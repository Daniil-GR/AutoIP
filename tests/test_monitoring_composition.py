from datetime import timedelta

from sqlalchemy import select

from commander.database import Agent, ControlTask, Integration, SystemSetting, utcnow
from commander.monitoring import atlas_fallback, rate_slot, record_cooldown
from commander.schemas import CommanderPolicy


def test_shared_rate_limit_survives_commits_and_honors_retry_after(db, monkeypatch):
    now = utcnow()
    monkeypatch.setattr("commander.monitoring.utcnow", lambda: now)
    for _ in range(25):
        assert rate_slot(db, "shared-key", now) == (True, 0)
        db.commit()
    assert rate_slot(db, "shared-key", now)[0] is False
    assert rate_slot(db, "other-key", now)[0] is True
    later = now + timedelta(minutes=1)
    assert rate_slot(db, "shared-key", later)[0] is True
    record_cooldown(db, "shared-key", 180)
    db.commit()
    db.expire_all()
    assert rate_slot(db, "shared-key", now + timedelta(seconds=60)) == (False, 120)
    assert rate_slot(db, "shared-key", now + timedelta(seconds=181))[0] is True


def setup_fallback(db):
    a = Agent(
        name="test",
        token_hash="fallback-test",
        proxy_port=9443,
        configuration={
            "proxy_ip": "8.8.8.8",
            "sni_domain": "sni.example.com",
            "ripe_atlas_integration_id": "atlas-test",
        },
        facts={},
    )
    db.add_all(
        [
            a,
            Integration(
                id="atlas-test",
                name="Atlas",
                kind="ripe_atlas",
                ciphertext="not-read",
                metadata_json={},
            ),
            SystemSetting(
                key="commander",
                value=CommanderPolicy(atlas_fallback_enabled=True).model_dump(),
            ),
        ]
    )
    db.commit()
    return a


def test_fallback_only_when_primary_unanswered_and_never_more_than_hourly(db):
    a = setup_fallback(db)
    assert (
        atlas_fallback(
            db, a.id, [{"source": "mtproto-checker", "provider_status": "RKN_BLOCK"}]
        )["status"]
        == "standby"
    )
    assert (
        atlas_fallback(
            db, a.id, [{"source": "mtproto-checker", "error": "not_configured"}]
        )["status"]
        == "standby"
    )
    assert db.scalar(select(ControlTask)) is None
    reports = [{"source": "mtproto-checker", "error": "service_unavailable"}]
    result = atlas_fallback(db, a.id, reports)
    db.commit()
    assert result["status"] == "queued"
    assert atlas_fallback(db, a.id, reports)["status"] == "cooldown"
    task = db.scalar(select(ControlTask))
    assert task.kind == "sni" and task.payload["port"] == 9443
    task.created_at = utcnow() - timedelta(minutes=61)
    task.status = "succeeded"
    db.commit()
    assert atlas_fallback(db, a.id, reports)["status"] == "queued"


def test_fallback_disabled_or_missing_key_or_paused_is_not_a_measurement(db):
    a = setup_fallback(db)
    reports = [{"source": "check-host", "error": "unavailable"}]
    a.paused = True
    db.commit()
    assert atlas_fallback(db, a.id, reports)["status"] == "paused"
    a.paused = False
    a.configuration = {**a.configuration, "ripe_atlas_integration_id": ""}
    db.commit()
    assert atlas_fallback(db, a.id, reports)["status"] == "not_configured"
    policy = db.get(SystemSetting, "commander")
    policy.value = CommanderPolicy(atlas_fallback_enabled=False).model_dump()
    db.commit()
    assert atlas_fallback(db, a.id, reports)["status"] == "disabled"
    assert db.scalar(select(ControlTask)) is None


def test_composition_sends_only_mtproto_port_to_protocol_checker(client, monkeypatch):
    import asyncio
    from commander import monitoring
    from commander.mtproto_checker import normalize
    from test_mtproto_checker import sample

    calls = []
    with client.factory() as db:
        a = Agent(
            name="Two protocols",
            token_hash="two-protocols",
            proxy_port=9443,
            configuration={
                "proxy_ip": "8.8.8.8",
                "web_proxy_host": "web.example.com",
                "web_proxy_port": 443,
            },
            facts={},
        )
        db.add(a)
        db.commit()
        identifier = a.id

    async def tcp(host, port, ip):
        calls.append(("tcp", port))
        return {
            "reports": [
                {"source": "check-host", "status": "observed", "observations": []}
            ],
            "observations": [],
            "ip": ip,
        }

    async def mtproto(agent_id, target, port):
        calls.append(("mtproto", port))
        return normalize(sample(), "8.8.8.8", 9443, "obf2")

    async def web(self, host, port, protocol="tcp"):
        calls.append((protocol, port))
        assert host == "web.example.com" and protocol == "https"
        return {
            "source": "check-host",
            "status": "observed",
            "target": host,
            "observations": [
                {
                    "source": "check-host",
                    "state": "reachable",
                    "country": "RU",
                    "protocol": "https",
                }
            ],
        }

    monkeypatch.setattr(monitoring, "SessionLocal", client.factory)
    monkeypatch.setattr(monitoring, "collect", tcp)
    monkeypatch.setattr(monitoring, "checker_report", mtproto)
    monkeypatch.setattr(monitoring.CheckHost, "check", web)
    result = asyncio.run(
        monitoring.collect_agent(identifier, "proxy.example.com", 9443, "8.8.8.8")
    )
    assert set(calls) == {("mtproto", 9443), ("https", 443)}
    assert result["mtproto_verified"] is True
    assert result["web_endpoint"]["webproxy_data_verified"] is False
    assert result["atlas_fallback"]["status"] == "standby"


def test_ambiguous_old_atlas_submission_is_never_requeued(db):
    a = setup_fallback(db)
    old = ControlTask(
        agent_id=a.id,
        kind="sni",
        dedup_key="ambiguous-atlas",
        status="submission_uncertain",
        payload={},
        created_at=utcnow() - timedelta(hours=2),
    )
    db.add(old)
    db.commit()
    result = atlas_fallback(
        db, a.id, [{"source": "check-host", "error": "unavailable"}]
    )
    assert result["status"] == "submission_uncertain" and result["task_id"] == old.id
    assert len(db.scalars(select(ControlTask)).all()) == 1
