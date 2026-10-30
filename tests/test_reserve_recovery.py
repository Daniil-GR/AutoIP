import asyncio
import copy
from contextlib import contextmanager
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from commander import reserve_recovery as rr
from commander.database import (
    Agent,
    ControlTask,
    FloatingIP,
    Incident,
    Integration,
    Recovery,
    Sponsorship,
    SystemSetting,
    utcnow,
)
from commander.dns_pilot import DNSPilot, DNSPilotError
from commander.floating_pilot import known_blocked
from commander.services import incident_action, record_evidence

OLD = "8.8.8.8"
NEW = "1.1.1.1"
RESOURCE = str(uuid4())


def failed_evidence():
    return {
        "ip": OLD,
        "reports": [
            {
                "source": "mtproto-checker",
                "status": "observed",
                "provider_status": "RKN_BLOCK",
                "target": OLD,
            }
        ],
        "observations": [
            {
                "source": "check-host",
                "country": "RU",
                "asn": "AS1",
                "state": "failed",
                "target": OLD,
            },
            {
                "source": "check-host",
                "country": "RU",
                "asn": "AS2",
                "state": "failed",
                "target": OLD,
            },
            {
                "source": "mtproto-checker",
                "country": "RU",
                "asn": "",
                "state": "failed",
                "target": OLD,
            },
            {
                "source": "check-host",
                "country": "DE",
                "asn": "AS3",
                "state": "reachable",
                "target": OLD,
            },
        ],
    }


@pytest.fixture
def env(db, monkeypatch):
    factory = sessionmaker(db.bind, expire_on_commit=False)
    monkeypatch.setattr(rr, "SessionLocal", factory)
    monkeypatch.setattr(
        rr, "decrypt", lambda _: {"api_key": "test", "api_secret": "test"}
    )

    @contextmanager
    def exclusive():
        yield True

    monkeypatch.setattr(rr, "exclusive", exclusive)
    for kind in ["cherry", "dynadot", "mtproto_checker", "mtproto"]:
        db.add(
            Integration(
                id=kind, name=kind, kind=kind, status="verified", ciphertext="fake"
            )
        )
    a = Agent(
        id=str(uuid4()),
        name="node",
        token_hash="test",
        public_host="lt.vetka.rest",
        proxy_port=9443,
        last_seen=utcnow(),
        facts={
            "telemt_service": "active",
            "interfaces": [{"name": "eth0", "addresses": [{"ip": OLD}, {"ip": NEW}]}],
        },
        configuration={
            "management_ip": OLD,
            "proxy_ip": OLD,
            "dns_zone": "vetka.rest",
            "dns_record": "lt.vetka.rest",
            "cherry_integration_id": "cherry",
            "dns_integration_id": "dynadot",
            "mtproto_integration_id": "mtproto",
            "checker_integration_id": "mtproto_checker",
            "cherry_server_id": "123",
            "cherry_project_id": "55",
            "region": "LT-Siauliai",
        },
    )
    db.add(a)
    db.flush()
    db.add(
        FloatingIP(
            agent_id=a.id,
            integration_id="cherry",
            resource_id=RESOURCE,
            ipv4=NEW,
            managed=True,
            status="ready_standby",
        )
    )
    db.add(Sponsorship(agent_id=a.id, status="ACTIVE", ad_tag="a" * 32))
    db.add(
        SystemSetting(
            key="dns-pilot:" + str(uuid4()),
            value={
                "stage": "COMPLETED_RETURNED",
                "agent_id": a.id,
                "resource_id": RESOURCE,
                "old": OLD,
                "new": NEW,
                "host": a.public_host,
                "forward_check": {"verified": True},
                "return_check": {"verified": True},
            },
        )
    )
    db.commit()

    class Provider(DNSPilot):
        def __init__(self):
            super().__init__("test", "test")
            self.calls = []
            self.lose_add = False
            self.zone = {
                "glue_type": "DNS",
                "ttl": 300,
                "dns_sub_list": [
                    {"sub_host": "lt", "record_type": "a", "record_value1": OLD},
                    {
                        "sub_host": "admin",
                        "record_type": "txt",
                        "record_value1": "preserve",
                    },
                ],
            }

        async def records(self, zone):
            return {"glue_info": copy.deepcopy(self.zone)}

        async def mutate(self, method, record, ttl):
            assert record["sub_host"] == "lt" and record["record_type"] == "a"
            self.calls.append((method, record["record_value1"]))
            if method == "POST":
                self.zone["dns_sub_list"].append(copy.deepcopy(record))
                if self.lose_add:
                    self.lose_add = False
                    raise DNSPilotError("lost response")
            elif method == "DELETE":
                self.zone["dns_sub_list"].remove(record)
            else:
                pytest.fail("Forbidden mutation")

    provider = Provider()
    monkeypatch.setattr(rr, "dns_client", lambda _: provider)

    async def cherry(self, method, path, payload=None):
        assert method == "GET" and path == "/ips/" + RESOURCE
        return {"type": "floating-ip", "address": NEW, "targeted_to": {"id": 123}}

    monkeypatch.setattr(rr.CherryPilotAPI, "request", cherry)
    from commander import monitoring

    async def collect(*args):
        return failed_evidence()

    async def check(*args):
        return {"mtproto_verified": True, "provider_status": "OK"}

    monkeypatch.setattr(monitoring, "collect_agent", collect)
    monkeypatch.setattr(monitoring, "checker_report", check)
    monkeypatch.setattr(
        rr,
        "dns_observations",
        lambda _: {
            "authoritative": [{"aa": True, "ips": [NEW]}],
            "recursive": [{"ips": [NEW]}],
        },
    )
    return a, provider, factory


def activate(db, a):
    rr.prepare(db, a.id, RESOURCE)
    rr.set_enabled(db, a.id, True, approved=True)
    db.commit()


def queue(db, a):
    record_evidence(db, a.id, failed_evidence(), "suspected")
    db.commit()
    i = db.scalar(select(Incident))
    incident_action(db, i.id, "confirm", "admin")
    db.commit()
    record_evidence(db, a.id, failed_evidence(), "suspected", i.id)
    db.commit()
    return db.scalar(select(Recovery))


def drive(identifier, limit=12):
    for _ in range(limit):
        with rr.SessionLocal() as db:
            if db.get(Recovery, identifier).status not in rr.ACTIVE:
                return
        asyncio.run(rr.step(identifier))
    pytest.fail("Recovery did not terminate")


def test_preparation_is_disabled_and_needs_explicit_activation(db, env):
    a, p, _ = env
    report = rr.prepare(db, a.id, RESOURCE)
    db.commit()
    assert report["prepared"] and not report["enabled"]
    with pytest.raises(DNSPilotError):
        rr.set_enabled(db, a.id, True)
    assert p.calls == []


def test_disabled_mode_never_queues_real_work(db, env):
    a, p, _ = env
    rr.prepare(db, a.id, RESOURCE)
    db.commit()
    assert queue(db, a).status == "MANUAL_REQUIRED"
    assert p.calls == []


def test_complete_confirmed_recovery_is_single_use_and_preserves_management_tag(
    db, env
):
    a, p, factory = env
    activate(db, a)
    r = queue(db, a)
    assert r.status == "QUEUED"
    drive(r.id)
    with factory() as session:
        agent = session.get(Agent, a.id)
        assert session.get(Recovery, r.id).status == "SUCCEEDED"
        assert (
            agent.configuration["floating_ip"] == NEW
            and agent.configuration["management_ip"] == OLD
        )
        assert session.get(Incident, r.incident_id).status == "RECOVERED"
        assert not session.get(SystemSetting, rr.policy_key(a.id)).value["enabled"]
        assert session.get(Sponsorship, a.id).ad_tag == "a" * 32
        assert session.scalar(select(FloatingIP)).status == "active"
    assert p.calls == [("POST", NEW), ("DELETE", OLD)]
    assert p.zone["dns_sub_list"][0]["sub_host"] == "admin"


def test_lost_add_reply_reconciles_on_restart_without_second_post(db, env):
    a, p, factory = env
    activate(db, a)
    r = queue(db, a)
    asyncio.run(rr.step(r.id))
    asyncio.run(rr.step(r.id))
    p.lose_add = True
    with pytest.raises(DNSPilotError):
        asyncio.run(rr.step(r.id))
    with factory() as session:
        assert session.get(SystemSetting, rr.state_key(r.id)).value["add_submitted"]
    drive(r.id)
    assert p.calls.count(("POST", NEW)) == 1


def test_unsubmitted_after_reservation_is_not_blindly_resubmitted(db, env):
    a, p, _ = env
    activate(db, a)
    r = queue(db, a)
    asyncio.run(rr.step(r.id))
    asyncio.run(rr.step(r.id))
    rr.save(r.id, "DNS_ADD", add_submitted=True)
    asyncio.run(rr.step(r.id))
    assert p.calls == [] and rr.load(r.id)["stage"] == "DNS_ADD"


def test_pause_before_dns_prevents_mutation(db, env):
    a, p, factory = env
    activate(db, a)
    r = queue(db, a)
    with factory() as session:
        session.get(Agent, a.id).paused = True
        session.commit()
    asyncio.run(rr.step(r.id))
    with factory() as session:
        assert session.get(Recovery, r.id).status == "MANUAL_REQUIRED"
    assert p.calls == []


def test_pause_after_add_rolls_back_only_its_dns_record(db, env):
    a, p, factory = env
    activate(db, a)
    r = queue(db, a)
    for _ in range(3):
        asyncio.run(rr.step(r.id))
    with factory() as session:
        session.get(Agent, a.id).paused = True
        session.commit()
    drive(r.id)
    assert p.calls == [("POST", NEW), ("DELETE", NEW)]
    with factory() as session:
        assert session.get(Recovery, r.id).status == "ROLLED_BACK"
        assert session.get(Agent, a.id).configuration.get("floating_ip", "") == ""
        assert session.scalar(select(FloatingIP)).released_at is None


def test_original_recovers_final_check_cancels_without_dns(db, env, monkeypatch):
    from commander import monitoring

    a, p, factory = env
    activate(db, a)
    r = queue(db, a)

    async def reachable(*args):
        return {
            "reports": [
                {
                    "source": "mtproto-checker",
                    "status": "observed",
                    "provider_status": "OK",
                    "target": OLD,
                }
            ],
            "ip": OLD,
        }

    monkeypatch.setattr(monitoring, "collect_agent", reachable)
    asyncio.run(rr.step(r.id))
    with factory() as session:
        assert session.get(Recovery, r.id).status == "CANCELLED"
    assert p.calls == []


def test_candidate_unknown_is_not_replaced_by_a_purchase(db, env, monkeypatch):
    from commander import monitoring

    a, p, factory = env
    activate(db, a)
    r = queue(db, a)
    asyncio.run(rr.step(r.id))

    async def unknown(*args):
        return {"mtproto_verified": False, "error": "service_unavailable"}

    monkeypatch.setattr(monitoring, "checker_report", unknown)
    asyncio.run(rr.step(r.id))
    with factory() as session:
        assert session.get(Recovery, r.id).status == "MANUAL_REQUIRED"
    assert p.calls == []


def test_reissued_blocked_history_prevents_preparation(db, env):
    a, p, _ = env
    db.add(
        FloatingIP(
            agent_id=a.id,
            integration_id="cherry",
            resource_id=str(uuid4()),
            ipv4=NEW,
            managed=True,
            status="blocked",
            released_at=utcnow(),
        )
    )
    db.commit()
    with pytest.raises(DNSPilotError):
        rr.prepare(db, a.id, RESOURCE)
    assert p.calls == []


def test_pending_recovery_does_not_open_duplicate_incident(db, env):
    a, _, _ = env
    activate(db, a)
    queue(db, a)
    record_evidence(db, a.id, failed_evidence(), "suspected")
    db.commit()
    assert len(db.scalars(select(Incident)).all()) == 1


def test_automatic_confirmation_history_survives_success(db, env):
    a, _, factory = env
    activate(db, a)
    i = Incident(
        agent_id=a.id,
        observed_ip=OLD,
        status="BLOCK_CONFIRMED",
        evidence=failed_evidence(),
    )
    db.add(i)
    db.flush()
    from commander.services import recovery_plan

    r = recovery_plan(db, a.id, "scheduler", "incident:" + i.id, i.id)
    db.commit()
    drive(r.id)
    with factory() as session:
        assert session.get(Incident, i.id).decision == "auto_confirm"
        assert known_blocked(session, OLD)


def test_timeout_does_not_undo_a_potentially_working_dns_or_buy(db, env):
    a, p, factory = env
    activate(db, a)
    r = queue(db, a)
    for _ in range(6):
        asyncio.run(rr.step(r.id))
    rr.save(r.id, "DNS_VERIFY", deadline=(utcnow() - timedelta(seconds=1)).isoformat())
    asyncio.run(rr.step(r.id))
    with factory() as session:
        assert session.get(Recovery, r.id).status == "MANUAL_REQUIRED"
    assert p.calls == [("POST", NEW), ("DELETE", OLD)]


def test_mixed_domain_failures_do_not_count_as_ip_block_evidence():
    from commander.monitor import independent_failure

    data = failed_evidence()
    for x in data["observations"]:
        if x["source"] == "check-host":
            x["target"] = "lt.vetka.rest"
    assert not independent_failure(data)


def test_complete_step_is_idempotent_after_restart(db, env):
    a, p, factory = env
    activate(db, a)
    r = queue(db, a)
    drive(r.id)
    calls = copy.deepcopy(p.calls)
    asyncio.run(rr.step(r.id))
    with factory() as session:
        assert session.get(Recovery, r.id).status == "SUCCEEDED"
    assert p.calls == calls


def test_pause_during_dns_read_is_rechecked_before_write(db, env, monkeypatch):
    a, p, factory = env
    activate(db, a)
    r = queue(db, a)
    asyncio.run(rr.step(r.id))
    asyncio.run(rr.step(r.id))
    original = p.records

    async def changed(zone):
        with factory() as session:
            session.get(Agent, a.id).paused = True
            session.commit()
        return await original(zone)

    monkeypatch.setattr(p, "records", changed)
    with pytest.raises(DNSPilotError):
        asyncio.run(rr.step(r.id))
    assert p.calls == [] and not rr.load(r.id).get("add_submitted")


def test_auto_recheck_requires_three_independent_failures(db, env):
    a, p, _ = env
    activate(db, a)
    record_evidence(db, a.id, failed_evidence(), "suspected")
    db.commit()
    i = db.scalar(select(Incident))
    i.rechecks = 3
    for index in range(2):
        db.add(
            ControlTask(
                agent_id=a.id,
                dedup_key=str(uuid4()),
                status="succeeded",
                payload={"incident_id": i.id},
                result={**failed_evidence(), "status": "suspected"},
                created_at=utcnow() - timedelta(minutes=10 - index),
            )
        )
    db.commit()
    record_evidence(db, a.id, failed_evidence(), "suspected", i.id)
    db.commit()
    assert db.scalar(select(Recovery)).status == "QUEUED"
    assert i.status == "RECOVERING" and i.decision == "auto_confirm"
    assert p.calls == []


def test_commit_failure_rolls_back_config_incident_and_resource_together(db, env):
    from sqlalchemy import event
    from sqlalchemy.orm import Session

    a, p, factory = env
    activate(db, a)
    r = queue(db, a)
    for _ in range(7):
        asyncio.run(rr.step(r.id))
    assert rr.load(r.id)["stage"] == "COMMIT"

    def fail_commit(session):
        if any(
            isinstance(x, Agent) and x.configuration.get("floating_ip") == NEW
            for x in session.identity_map.values()
        ):
            raise RuntimeError("simulated commit crash")

    event.listen(Session, "before_commit", fail_commit)
    try:
        with pytest.raises(RuntimeError):
            asyncio.run(rr.step(r.id))
    finally:
        event.remove(Session, "before_commit", fail_commit)
    with factory() as session:
        assert session.get(Agent, a.id).configuration.get("floating_ip", "") == ""
        assert session.get(Incident, r.incident_id).status == "RECOVERING"
        assert session.scalar(select(FloatingIP)).status == "ready_standby"
        assert session.get(Recovery, r.id).status == "RUNNING"
    asyncio.run(rr.step(r.id))
    with factory() as session:
        assert session.get(Recovery, r.id).status == "SUCCEEDED"
    assert p.calls == [("POST", NEW), ("DELETE", OLD)]


def test_telemt_public_host_can_be_primary_ip_while_clients_use_dns(db, env):
    a, p, factory = env
    a.public_host = OLD
    db.commit()
    activate(db, a)
    r = queue(db, a)
    drive(r.id)
    with factory() as session:
        assert session.get(Recovery, r.id).status == "SUCCEEDED"
        assert session.get(Agent, a.id).public_host == OLD
    assert p.calls == [("POST", NEW), ("DELETE", OLD)]


def human_protocol_evidence(status="RKN_BLOCK"):
    return {
        "ip": OLD,
        "reports": [
            {
                "source": "mtproto-checker",
                "status": "observed",
                "target": OLD,
                "provider_status": status,
                "checked_at": utcnow().isoformat(),
                "points": {
                    "local": {"tcp": False, "handshake": False, "data": False},
                    "remote": {"tcp": True, "handshake": True, "data": True},
                },
            }
        ],
        "observations": [],
    }


def test_human_confirmation_accepts_fresh_protocol_block_only():
    data = human_protocol_evidence()
    assert rr.recovery_failure(data, "confirm")
    assert not rr.recovery_failure(data, "auto_confirm")
    assert not rr.recovery_failure(data, "")
    data["reports"][0]["target"] = NEW
    assert not rr.recovery_failure(data, "confirm")


@pytest.mark.parametrize(
    "change", ["stale", "external_dead", "unknown", "missing_time"]
)
def test_human_confirmation_cannot_bypass_protocol_proof(change):
    data = human_protocol_evidence()
    report = data["reports"][0]
    if change == "stale":
        report["checked_at"] = (utcnow() - timedelta(minutes=6)).isoformat()
    elif change == "external_dead":
        report["points"]["remote"]["data"] = False
    elif change == "unknown":
        report["provider_status"] = "UNKNOWN"
    else:
        del report["checked_at"]
    assert not rr.recovery_failure(data, "confirm")


def test_human_protocol_block_runs_final_check_and_cutover(db, env, monkeypatch):
    from commander import monitoring

    a, provider, _ = env
    activate(db, a)
    data = human_protocol_evidence()
    record_evidence(db, a.id, data, "suspected")
    db.commit()
    i = db.scalar(select(Incident))
    incident_action(db, i.id, "confirm", "admin")
    db.commit()
    record_evidence(db, a.id, data, "suspected", i.id)
    db.commit()
    r = db.scalar(select(Recovery))
    assert r.status == "QUEUED"

    async def collect(*args):
        return human_protocol_evidence()

    monkeypatch.setattr(monitoring, "collect_agent", collect)
    asyncio.run(rr.step(r.id))
    assert rr.load(r.id)["stage"] == "CANDIDATE_CHECK"
    assert not provider.calls
