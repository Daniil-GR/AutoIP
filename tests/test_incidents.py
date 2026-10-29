from datetime import timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from commander.database import (
    Agent,
    ControlTask,
    Incident,
    Notification,
    Recovery,
    utcnow,
)
from commander.monitor import independent_failure, verdict
from commander.security import aware
from commander.services import (
    incident_action,
    record_evidence,
    request_check,
    schedule,
    set_paused,
)


def evidence(state="failed", source="check-host"):
    return {
        "observations": [
            {"source": source, "country": "RU", "asn": "AS1", "state": state},
            {"source": source, "country": "RU", "asn": "AS2", "state": state},
            {"source": source, "country": "DE", "asn": "AS3", "state": "reachable"},
        ]
    }


def agent(db, name="one"):
    a = Agent(
        name=name,
        token_hash=name * 20,
        machine_id=name,
        public_host="proxy.example.com",
        facts={"telemt_service": "active"},
        last_seen=utcnow(),
        configuration={},
    )
    db.add(a)
    db.commit()
    return a


@pytest.mark.parametrize(
    "result,fresh,service,expected",
    [
        ("failed", True, True, "suspected"),
        ("unknown", True, True, "unknown"),
        ("failed", False, True, "local_fault"),
        ("failed", True, False, "local_fault"),
        ("reachable", True, True, "reachable"),
    ],
)
def test_conservative_verdict(result, fresh, service, expected):
    assert verdict(evidence(result), service, fresh) == expected
    assert not independent_failure(evidence(result))


def test_dns_success_cannot_hide_ip_failure():
    data = evidence()
    data["ip"] = "8.8.8.8"
    data["observations"] = [dict(o, target="8.8.8.8") for o in data["observations"]]
    data["observations"].append(
        {
            "source": "check-host",
            "target": "proxy.example.com",
            "country": "RU",
            "state": "reachable",
        }
    )
    assert verdict(data, True, True) == "suspected"


def test_single_asn_and_missing_foreign_are_inconclusive():
    data = evidence()
    data["observations"][1]["asn"] = "AS1"
    assert verdict(data, True, True) == "unknown"
    data = evidence()
    data["observations"] = data["observations"][:2]
    assert verdict(data, True, True) == "unknown"


def test_confirm_requires_final_check_and_is_not_purchase(db):
    a = agent(db)
    record_evidence(db, a.id, evidence(), "suspected")
    db.commit()
    i = db.scalar(select(Incident))
    incident_action(db, i.id, "confirm", "admin")
    db.commit()
    assert i.status == "RECHECKING"
    assert db.scalar(select(ControlTask)).payload["incident_id"] == i.id
    assert db.scalar(select(Recovery)) is None
    record_evidence(db, a.id, evidence(), "suspected", i.id)
    db.commit()
    assert i.status == "MANUAL_REQUIRED"
    assert db.scalar(select(Recovery)).status == "MANUAL_REQUIRED"
    with pytest.raises(HTTPException):
        incident_action(db, i.id, "confirm", "admin")


def test_final_unknown_never_advances_recovery(db):
    a = agent(db)
    record_evidence(db, a.id, evidence(), "suspected")
    db.commit()
    i = db.scalar(select(Incident))
    incident_action(db, i.id, "confirm", "admin")
    db.commit()
    record_evidence(db, a.id, {}, "unknown", i.id)
    db.commit()
    assert i.status == "MANUAL_REQUIRED"
    assert db.scalar(select(Recovery)) is None


def test_recovery_cancels_timer_and_stale_callback(db):
    a = agent(db)
    record_evidence(db, a.id, evidence(), "suspected")
    db.commit()
    i = db.scalar(select(Incident))
    record_evidence(db, a.id, evidence("reachable"), "reachable")
    db.commit()
    assert i.status == "RECOVERED" and i.next_check_at is None
    with pytest.raises(HTTPException):
        incident_action(db, i.id, "confirm", "admin")


def test_timers_persist_15_20_25_and_no_double_count(db):
    a = agent(db)
    record_evidence(db, a.id, evidence(), "suspected")
    db.commit()
    i = db.scalar(select(Incident))
    start = utcnow() - timedelta(minutes=16)
    i.created_at = start
    i.next_check_at = start + timedelta(minutes=15)
    db.commit()
    schedule(db)
    db.commit()
    assert i.rechecks == 1
    assert aware(i.next_check_at) == start + timedelta(minutes=20)
    first = db.scalar(select(ControlTask))
    first.status = "running"
    db.commit()
    i.next_check_at = utcnow() - timedelta(seconds=1)
    db.commit()
    schedule(db)
    db.commit()
    assert i.rechecks == 1  # previous check is still running
    first.status = "succeeded"
    db.commit()
    schedule(db)
    db.commit()
    assert i.rechecks == 2
    assert aware(i.next_check_at) == start + timedelta(minutes=25)
    for t in db.scalars(select(ControlTask)):
        t.status = "succeeded"
    i.next_check_at = utcnow() - timedelta(seconds=1)
    db.commit()
    schedule(db)
    db.commit()
    assert i.rechecks == 3 and i.next_check_at is None
    assert db.scalar(select(Recovery)) is None


def test_pause_and_agents_isolated(db):
    a, b = agent(db, "first"), agent(db, "second")
    record_evidence(db, a.id, evidence(), "suspected")
    db.commit()
    set_paused(db, a.id, True, "admin")
    db.commit()
    assert not b.paused
    i = db.scalar(select(Incident))
    assert i.status == "PAUSED"
    assert i.next_check_at is None
    record_evidence(db, b.id, evidence(), "suspected")
    db.commit()
    assert len(db.scalars(select(Incident)).all()) == 2


def test_check_requests_coalesce_and_dedup(db):
    a = agent(db)
    one = request_check(db, a.id, "web", key="same")
    db.commit()
    two = request_check(db, a.id, "bot", key="different")
    db.commit()
    assert one.id == two.id
    one.status = "succeeded"
    db.commit()
    three = request_check(db, a.id, "web", key="same")
    db.commit()
    assert three.id == one.id


def test_late_recheck_does_not_reopen_dismissed_incident(db):
    a = agent(db)
    record_evidence(db, a.id, evidence(), "suspected")
    db.commit()
    i = db.scalar(select(Incident))
    incident_action(db, i.id, "working", "admin")
    db.commit()
    record_evidence(db, a.id, evidence(), "suspected", i.id)
    db.commit()
    assert len(db.scalars(select(Incident)).all()) == 1
    assert i.status == "DISMISSED"


def test_health_alerts_only_on_transitions(db):
    from commander.services import record_agent_health

    a = agent(db)
    record_agent_health(db)
    db.commit()
    assert len(db.scalars(select(Notification)).all()) == 0
    a.last_seen = utcnow() - timedelta(minutes=2)
    db.commit()
    record_agent_health(db)
    db.commit()
    record_agent_health(db)
    db.commit()
    assert len(db.scalars(select(Notification)).all()) == 1
    a.last_seen = utcnow()
    db.commit()
    record_agent_health(db)
    db.commit()
    assert len(db.scalars(select(Notification)).all()) == 2
    a.facts = {"telemt_service": "failed"}
    db.commit()
    record_agent_health(db)
    db.commit()
    record_agent_health(db)
    db.commit()
    assert len(db.scalars(select(Notification)).all()) == 3


def test_protocol_degradation_alerts_once_and_is_not_a_block(db):
    a = agent(db)
    data = {"mtproto_status": "MT_DEAD", "reports": [], "observations": []}
    record_evidence(db, a.id, data, "proxy_degraded")
    db.commit()
    record_evidence(db, a.id, data, "proxy_degraded")
    db.commit()
    notices = db.scalars(
        select(Notification).where(Notification.topic == "proxy_health")
    ).all()
    assert len(notices) == 1 and "не подтверждение блокировки" in notices[0].text
    assert db.scalar(select(Incident)) is None
    record_evidence(db, a.id, {"reports": [], "observations": []}, "reachable")
    db.commit()
    assert (
        len(
            db.scalars(
                select(Notification).where(Notification.topic == "proxy_health")
            ).all()
        )
        == 2
    )


def test_recent_secondary_sni_does_not_delay_primary_monitoring(db):
    from commander.database import Check, SystemSetting
    from commander.schemas import CommanderPolicy

    a = agent(db)
    db.add(
        SystemSetting(
            key="commander",
            value=CommanderPolicy(
                monitor_enabled=True, monitor_interval_seconds=300
            ).model_dump(),
        )
    )
    db.add(
        Check(
            agent_id=a.id,
            result="reachable",
            details={},
            created_at=utcnow() - timedelta(seconds=301),
        )
    )
    db.add(
        Check(agent_id=a.id, result="sni_available", details={}, created_at=utcnow())
    )
    db.commit()
    schedule(db)
    db.commit()
    task = db.scalar(select(ControlTask))
    assert task is not None and task.kind == "check" and task.agent_id == a.id
