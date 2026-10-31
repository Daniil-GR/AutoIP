import asyncio
from unittest.mock import AsyncMock

from sqlalchemy.orm import sessionmaker

from commander import atlas, monitoring
from commander.database import (
    Agent,
    Check,
    ControlTask,
    Incident,
    Integration,
    Recovery,
    SystemSetting,
    utcnow,
)
from commander.monitor import verdict
from commander.services import record_evidence, request_sni_check
from commander.paid_recovery import enabled
from commander.reserve_recovery import reserve_readiness


def setup_cdn(db, monkeypatch):
    a = Agent(
        id="cdn-node",
        name="CDN",
        token_hash="cdn-test",
        public_host="node.vetka.rest",
        proxy_port=9443,
        last_seen=utcnow(),
        facts={"telemt_service": "active"},
        configuration={
            "monitoring_mode": "cdn_web",
            "web_proxy_host": "node.vetka.rest",
            "dns_record": "node.vetka.rest",
            "floating_ip": "8.8.8.8",
            "ripe_atlas_integration_id": "atlas-test",
        },
    )
    db.add_all(
        [
            a,
            Integration(
                id="atlas-test",
                name="Atlas",
                kind="ripe_atlas",
                ciphertext="fixture-only",
            ),
            SystemSetting(key="commander", value={"atlas_fallback_enabled": True}),
            SystemSetting(key="paid-auto:cdn-node", value={"enabled": True}),
        ]
    )
    db.commit()
    factory = sessionmaker(db.bind, expire_on_commit=False)
    monkeypatch.setattr(monitoring, "SessionLocal", factory)
    monkeypatch.setattr(atlas, "SessionLocal", factory, raising=False)
    monkeypatch.setattr(
        "socket.getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", ("9.9.9.9", 443))]
    )
    return a, factory


def test_cdn_collect_only_checks_hostname_https_and_schedules_one_atlas(
    db, monkeypatch
):
    a, _ = setup_cdn(db, monkeypatch)
    check = AsyncMock(
        return_value={
            "source": "check-host",
            "status": "observed",
            "observations": [
                {
                    "country": "RU",
                    "asn": "AS1",
                    "state": "reachable",
                    "protocol": "https",
                }
            ],
        }
    )
    forbidden = AsyncMock(
        side_effect=AssertionError("Direct MTProto must not be checked")
    )
    monkeypatch.setattr(monitoring.CheckHost, "check", check)
    monkeypatch.setattr(monitoring, "checker_report", forbidden)
    monkeypatch.setattr(monitoring, "collect", forbidden)
    r = asyncio.run(monitoring.collect_agent(a.id, "node.vetka.rest", 9443, "8.8.8.8"))
    check.assert_awaited_once_with(
        "node.vetka.rest", 443, protocol="https", foreign_countries=("DE", "NL", "FR")
    )
    forbidden.assert_not_awaited()
    assert verdict(r, True, True) == "cdn_web_reachable"
    assert not r["webproxy_data_verified"] and not r["mtproto_verified"]
    assert r["ip"] is None and r["atlas_fallback"]["role"] == "scheduled"
    assert db.query(ControlTask).count() == 1
    db.expire_all()
    task = db.query(ControlTask).one()
    assert task.payload["target_ip"] == "9.9.9.9" and task.payload["port"] == 443
    assert task.payload["host"] == "node.vetka.rest"
    with monitoring.SessionLocal() as session:
        assert monitoring.schedule_atlas(session, a.id)["status"] == "cooldown"
        session.commit()
    assert db.query(ControlTask).count() == 1


def test_cdn_evidence_never_opens_direct_ip_incident_or_recovery(db, monkeypatch):
    a, _ = setup_cdn(db, monkeypatch)
    evidence = {
        "monitoring_mode": "cdn_web",
        "reports": [],
        "observations": [
            {"country": "RU", "asn": asn, "state": "failed"} for asn in ("AS1", "AS2")
        ]
        + [{"country": c, "state": "reachable"} for c in ("DE", "NL", "FR")],
    }
    result = verdict(evidence, True, True)
    assert result == "cdn_web_suspected"
    record_evidence(db, a.id, evidence, result)
    db.commit()
    assert db.query(Check).count() == 1
    assert db.query(Incident).count() == 0 and db.query(Recovery).count() == 0
    assert not enabled(db, a.id)
    assert not reserve_readiness(db, a)["checks"]["direct_dns_mode"]
    evidence["observations"][0]["state"] = "unknown"
    assert verdict(evidence, True, True) == "cdn_web_unknown"


def test_cdn_atlas_request_pins_edge_and_respects_existing_dedup(db, monkeypatch):
    a, _ = setup_cdn(db, monkeypatch)
    one = request_sni_check(db, a.id, "atlas-test", "owner")
    db.commit()
    two = request_sni_check(db, a.id, "atlas-test", "owner")
    assert one.id == two.id and one.payload["target_ip"] != "8.8.8.8"
    assert one.payload["monitoring_mode"] == "cdn_web" and one.payload["port"] == 443


def test_cdn_atlas_execution_keeps_edge_target_and_does_not_compare_to_origin(
    db, monkeypatch
):
    a, factory = setup_cdn(db, monkeypatch)
    task = request_sni_check(db, a.id, "atlas-test", "owner")
    task.payload = {**task.payload, "probe_plan": {"probes": [{"id": 1}]}}
    db.commit()
    monkeypatch.setattr("commander.database.SessionLocal", factory)
    monkeypatch.setattr("commander.vault.decrypt", lambda _: {"api_key": "fixture"})
    submit = AsyncMock(return_value=123)
    monkeypatch.setattr(atlas.Atlas, "submit", submit)
    monkeypatch.setattr(
        atlas.Atlas,
        "results",
        AsyncMock(return_value={"responded": 1, "outcome": "available"}),
    )
    asyncio.run(atlas.execute_task(task.id))
    submit.assert_awaited_once_with(
        "node.vetka.rest", {"probes": [{"id": 1}]}, "9.9.9.9", 443
    )
    db.expire_all()
    task = db.get(ControlTask, task.id)
    assert task.status == "succeeded"
    assert task.result["scope"] == "cdn-edge-tls-sni"
    assert task.result["resolution_scope"] == "single_cdn_edge"
    assert task.result["webproxy_data_verified"] is False


def test_old_origin_atlas_task_is_not_submitted_after_cdn_switch(db, monkeypatch):
    a, factory = setup_cdn(db, monkeypatch)
    task = ControlTask(
        agent_id=a.id,
        kind="sni",
        dedup_key="old-direct-atlas",
        payload={
            "integration_id": "atlas-test",
            "host": "old.example.com",
            "target_ip": "8.8.8.8",
            "port": 9443,
        },
    )
    db.add(task)
    db.commit()
    monkeypatch.setattr("commander.database.SessionLocal", factory)
    monkeypatch.setattr("commander.vault.decrypt", lambda _: {"api_key": "fixture"})
    submit = AsyncMock(
        side_effect=AssertionError("Stale task must never spend credits")
    )
    monkeypatch.setattr(atlas.Atlas, "submit", submit)
    asyncio.run(atlas.execute_task(task.id))
    db.expire_all()
    assert db.get(ControlTask, task.id).status == "failed"
    submit.assert_not_awaited()


def test_bot_cdn_card_does_not_report_mtproto_checker_as_active(db, monkeypatch):
    from commander.bot import agent_view
    from commander.config import settings

    a, _ = setup_cdn(db, monkeypatch)
    monkeypatch.setattr(settings, "telegram_admin_ids", [1])
    text, _ = agent_view(db, 1, a.id, "agents")
    assert "node.vetka.rest:443" in text
    assert "MTProto Checker: не используется для WEB через CDN" in text
