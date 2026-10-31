import asyncio
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select
from commander import paid_recovery as paid, reserve_recovery as rr
from commander.database import (
    FloatingIP,
    Incident,
    Job,
    Recovery,
    SystemSetting,
    utcnow,
)
from commander.services import record_evidence, incident_action
from test_reserve_recovery import (
    OLD,
    NEW,
    RESOURCE,
    human_protocol_evidence,
    env as reserve_fixture,  # noqa: F401 - pytest discovers imported fixtures
)


@pytest.fixture
def paid_env(db, request, monkeypatch):
    a, provider, factory = request.getfixturevalue("reserve_fixture")
    monkeypatch.setattr(paid, "SessionLocal", factory)
    from commander import floating_pilot

    monkeypatch.setattr(floating_pilot, "decrypt", lambda _: {"api_key": "test"})
    db.add(SystemSetting(key=paid.policy_key(a.id), value={"enabled": True}))
    db.commit()
    return a, provider


def test_primary_requires_valid_ru_block_and_live_external_data():
    data = human_protocol_evidence()
    assert paid.protocol_block(data)
    data["reports"][0]["points"]["remote"]["data"] = False
    assert not paid.protocol_block(data)
    data = human_protocol_evidence()
    data["reports"][0]["checked_at"] = (utcnow() - timedelta(minutes=11)).isoformat()
    assert not paid.protocol_block(data)
    assert paid.protocol_block(data, fresh=False)


def test_confirmation_queues_paid_recovery_without_tcp_consensus(db, paid_env):
    a, _ = paid_env
    data = human_protocol_evidence()
    record_evidence(db, a.id, data, "suspected")
    db.commit()
    i = db.scalar(select(Incident))
    incident_action(db, i.id, "confirm", "admin")
    db.commit()
    record_evidence(db, a.id, data, "suspected", i.id)
    db.commit()
    r = db.scalar(select(Recovery))
    assert r.status == "PAID_RUNNING"
    assert paid.load(r.id)["stage"] == "FINAL_CHECK"


def start(db, a):
    i = Incident(
        agent_id=a.id,
        observed_ip=OLD,
        status="BLOCK_CONFIRMED",
        decision="confirm",
        evidence=human_protocol_evidence(),
    )
    db.add(i)
    db.flush()
    r = Recovery(
        agent_id=a.id,
        incident_id=i.id,
        idempotency_key=str(uuid4()),
        status="MANUAL_REQUIRED",
    )
    db.add(r)
    db.flush()
    assert paid.queue_if_ready(db, r, i)
    db.commit()
    return r


def test_paid_pipeline_reuses_dns_engine(db, paid_env, monkeypatch):
    from commander import monitoring

    a, provider = paid_env
    r = start(db, a)

    async def collect(*args):
        return human_protocol_evidence()

    monkeypatch.setattr(monitoring, "collect_agent", collect)
    orders = []

    async def purchase(agent, operation, approved):
        orders.append(operation)
        return {"status": "ALLOCATED", "resource_id": RESOURCE, "ipv4": NEW}

    async def attach(*args, **kwargs):
        return {}

    monkeypatch.setattr(paid, "purchase_one", purchase)
    monkeypatch.setattr(paid, "attach_one", attach)
    for _ in range(15):
        asyncio.run(paid.step(r.id))
        db.expire_all()
        for j in db.scalars(select(Job)):
            j.status = "succeeded"
        db.commit()
        if paid.load(r.id)["stage"] == "HANDOFF":
            break
    assert len(orders) == 1
    db.expire_all()
    assert db.get(Recovery, r.id).status == "QUEUED"
    assert rr.load(r.id)["stage"] == "FINAL_CHECK"
    assert not provider.calls


def test_uncertain_purchase_never_reorders(db, paid_env, monkeypatch):
    a, _ = paid_env
    r = start(db, a)
    paid.save(r.id, "ORDER", order_id=str(uuid4()))
    calls = []

    async def purchase(*args, **kwargs):
        calls.append(1)
        return {"status": "SUBMISSION_UNCERTAIN"}

    monkeypatch.setattr(paid, "purchase_one", purchase)
    asyncio.run(paid.step(r.id))
    db.expire_all()
    assert db.get(Recovery, r.id).status == "MANUAL_REQUIRED"
    assert not paid.enabled(db, a.id)
    assert calls == [1]


def test_dns_handoff_refreshes_expired_incident_evidence(db, paid_env, monkeypatch):
    from commander import monitoring

    a, _ = paid_env
    r = start(db, a)
    incident = db.get(Incident, r.incident_id)
    old = human_protocol_evidence()
    old["reports"][0]["checked_at"] = (utcnow() - timedelta(minutes=20)).isoformat()
    incident.evidence = old
    db.commit()
    paid.save(r.id, "DNS_HANDOFF", resource_id=RESOURCE, new=NEW)

    async def collect(*args):
        return human_protocol_evidence()

    monkeypatch.setattr(monitoring, "collect_agent", collect)
    asyncio.run(paid.step(r.id))
    assert paid.load(r.id)["stage"] == "HANDOFF"
    db.expire_all()
    assert paid.protocol_block(db.get(Incident, r.incident_id).evidence)


@pytest.mark.parametrize("recovers", [False, True])
def test_candidate_requires_repeated_failure_before_another_purchase(
    db, paid_env, monkeypatch, recovers
):
    a, _ = paid_env
    r = start(db, a)
    paid.save(
        r.id, "CANDIDATE_VERIFY", resource_id=RESOURCE, new=NEW, order_id=str(uuid4())
    )
    now = utcnow()
    monkeypatch.setattr(paid, "utcnow", lambda: now)
    attempts = 0

    async def protocol(*args):
        nonlocal attempts
        attempts += 1
        return {
            "target": NEW,
            "provider_status": "OK" if recovers and attempts > 1 else "DATA_CUT",
            "mtproto_verified": recovers and attempts > 1,
        }

    monkeypatch.setattr(rr, "protocol_verification", protocol)
    asyncio.run(paid.step(r.id))
    assert paid.load(r.id)["stage"] == "CANDIDATE_VERIFY"
    db.expire_all()
    assert (
        db.scalar(select(FloatingIP).where(FloatingIP.resource_id == RESOURCE)).status
        != "rejected_blocked"
    )
    now += timedelta(seconds=61)
    asyncio.run(paid.step(r.id))
    if recovers:
        assert paid.load(r.id)["stage"] == "NETWORK_COMMIT"
    else:
        assert paid.load(r.id)["stage"] == "CANDIDATE_VERIFY"
        now += timedelta(seconds=61)
        asyncio.run(paid.step(r.id))
        assert (
            paid.load(r.id)["stage"] == "ORDER" and paid.load(r.id)["order_id"] is None
        )
        db.expire_all()
        assert (
            db.scalar(
                select(FloatingIP).where(FloatingIP.resource_id == RESOURCE)
            ).status
            == "rejected_blocked"
        )


def test_known_history_is_not_attached(db, paid_env, monkeypatch):
    a, _ = paid_env
    r = start(db, a)
    paid.save(r.id, "ORDER", order_id=str(uuid4()))

    async def purchase(*args, **kwargs):
        return {"status": "REJECTED_HISTORY", "resource_id": RESOURCE, "ipv4": NEW}

    monkeypatch.setattr(paid, "purchase_one", purchase)
    asyncio.run(paid.step(r.id))
    s = paid.load(r.id)
    assert s["stage"] == "ORDER" and s["order_id"] is None
    assert s["candidates"] == [RESOURCE]
    assert not list(db.scalars(select(Job)))


def test_delete_never_removes_current_or_management(db, paid_env):
    a, _ = paid_env
    r = start(db, a)
    s = paid.load(r.id)
    row = db.scalar(select(FloatingIP))
    row.ipv4 = OLD
    db.commit()
    with pytest.raises(Exception, match="management/active"):
        asyncio.run(paid.delete_owned(r.id, s, RESOURCE))


@pytest.mark.parametrize(
    "protected",
    [None, "dns", "other_server", "pending_network", "lost_response", "active"],
)
def test_detach_rejected_frees_slot_without_deleting_or_forgetting_history(
    db, paid_env, monkeypatch, protected
):
    a, dns = paid_env
    r = start(db, a)
    rid = str(uuid4())
    address = OLD if protected == "active" else "9.9.9.9"
    db.add(
        FloatingIP(
            agent_id=a.id,
            integration_id="cherry",
            resource_id=rid,
            ipv4=address,
            managed=True,
            status="rejected_blocked",
        )
    )
    db.commit()
    paid.save(r.id, "ATTACH", candidates=[rid], configured=[rid], new=NEW)
    s = paid.load(r.id)
    if protected == "dns":
        dns.zone["dns_sub_list"].append(
            {"sub_host": "other", "record_type": "a", "record_value1": address}
        )
    calls = []
    attached = True

    def raw():
        return {
            "id": rid,
            "address": address,
            "type": "floating-ip",
            "targeted_to": {"id": 999 if protected == "other_server" else 123}
            if attached
            else None,
            "routed_to": {"id": "primary", "address": OLD, "type": "primary-ip"}
            if attached
            else None,
        }

    async def request(self, method, path, payload=None):
        nonlocal attached
        calls.append((method, path, payload))
        if method == "PUT":
            assert payload == {"targeted_to": "0"}
            attached = False
            if protected == "lost_response":
                raise paid.PilotError("Response lost after successful detach")
            return {}
        assert method == "GET"  # No POST or DELETE under any outcome.
        return [raw()] if path.endswith("/ips") else raw()

    jobs = []

    def network(identifier, state, action, resource, address=""):
        jobs.append((action, resource))
        return protected != "pending_network"

    monkeypatch.setattr(rr.CherryPilotAPI, "request", request)
    monkeypatch.setattr(paid, "network_job", network)
    if protected in ("dns", "other_server", "active"):
        with pytest.raises(Exception, match="Detach"):
            asyncio.run(paid.detach_rejected(r.id, s))
        assert attached and not any(c[0] == "PUT" for c in calls)
    elif protected == "lost_response":
        with pytest.raises(paid.PilotError):
            asyncio.run(paid.detach_rejected(r.id, s))
        assert not attached
        assert asyncio.run(paid.detach_rejected(r.id, s))
        assert len([c for c in calls if c[0] == "PUT"]) == 1
    else:
        assert not asyncio.run(paid.detach_rejected(r.id, s))
        assert jobs == [("remove", rid)]
        if protected == "pending_network":
            assert attached and not any(c[0] == "PUT" for c in calls)
        else:
            assert not attached
            assert asyncio.run(paid.detach_rejected(r.id, paid.load(r.id)))
    db.expire_all()
    row = db.scalar(select(FloatingIP).where(FloatingIP.resource_id == rid))
    assert row.status == "rejected_blocked" and not row.released_at


def test_quota_is_shared_per_project_not_per_agent(db, paid_env):
    a, _ = paid_env
    s = paid.load(start(db, a).id)
    for n in range(24):
        db.add(
            SystemSetting(
                key="fip-pilot:" + str(uuid4()),
                value={
                    "integration_id": s["integration_id"],
                    "project_id": s["project"],
                    "created_at": (
                        utcnow() - timedelta(hours=1, minutes=n)
                    ).isoformat(),
                },
            )
        )
    db.commit()
    assert paid.project_order_delay(db, s) > 22 * 3600


def test_three_primary_failures_allow_unattended_replacement(db, paid_env):
    from commander.database import ControlTask

    a, _ = paid_env
    data = human_protocol_evidence()
    record_evidence(db, a.id, data, "suspected")
    db.commit()
    i = db.scalar(select(Incident))
    i.rechecks = 3
    for n in range(2):
        history = human_protocol_evidence()
        history["reports"][0]["checked_at"] = (
            utcnow() - timedelta(minutes=10 - n * 5)
        ).isoformat()
        db.add(
            ControlTask(
                agent_id=a.id,
                dedup_key=str(uuid4()),
                status="succeeded",
                payload={"incident_id": i.id},
                result={"status": "suspected", **history},
            )
        )
    db.commit()
    record_evidence(db, a.id, data, "suspected", i.id)
    db.commit()
    assert db.scalar(select(Recovery)).status == "PAID_RUNNING"
    assert db.get(Incident, i.id).decision == "auto_confirm"


def test_two_sources_start_recovery_without_owner_wait(db, paid_env):
    a, _ = paid_env
    data = human_protocol_evidence()
    data["observations"] = [
        {"source": src, "country": "RU", "state": "failed", "target": OLD, "asn": asn}
        for src, asn in [
            ("check-host", "AS1"),
            ("check-host", "AS2"),
            ("mtproto-checker", ""),
        ]
    ]
    record_evidence(db, a.id, data, "suspected")
    db.commit()
    assert db.scalar(select(Recovery)).status == "PAID_RUNNING"


def test_disagreement_only_notifies_before_three_rechecks(db, paid_env):
    a, _ = paid_env
    record_evidence(db, a.id, human_protocol_evidence(), "suspected")
    db.commit()
    assert db.scalar(select(Recovery)) is None
    assert db.scalar(select(Incident)).status == "WAITING_CONFIRMATION"


def test_cleanup_reconciles_delete_and_retains_history(db, paid_env, monkeypatch):
    from commander.floating_pilot import PilotError

    a, _ = paid_env
    r = start(db, a)
    s = paid.load(r.id)
    rid = str(uuid4())
    address = "9.9.9.9"
    db.add(
        FloatingIP(
            agent_id=a.id,
            integration_id="cherry",
            resource_id=rid,
            ipv4=address,
            managed=True,
            status="rejected_blocked",
        )
    )
    db.commit()
    calls = []
    deleted = False
    assigned = True

    async def request(self, method, path, payload=None):
        nonlocal deleted, assigned
        if method == "PUT":
            assert payload == {"targeted_to": "0"}
            assigned = False
            return {}
        calls.append((method, path))
        if method == "DELETE":
            deleted = True
            return None
        if path.endswith("/ips"):
            return [] if deleted else [{"id": rid}]
        if deleted:
            raise PilotError("not found", provider_status=404)
        return {
            "id": rid,
            "address": address,
            "type": "floating-ip",
            "targeted_to": {"id": 123} if assigned else None,
        }

    monkeypatch.setattr(rr.CherryPilotAPI, "request", request)
    assert asyncio.run(paid.delete_owned(r.id, s, rid))
    assert asyncio.run(paid.delete_owned(r.id, s, rid))
    db.expire_all()
    row = db.scalar(select(FloatingIP).where(FloatingIP.resource_id == rid))
    assert row.released_at and row.status == "rejected_blocked"
    assert len([c for c in calls if c[0] == "DELETE"]) == 1
    assert not assigned


def test_dns_engine_completes_paid_handoff_and_policy_stays_armed(
    db, paid_env, monkeypatch
):
    # Run the same acquisition test, then finish the integrated DNS engine.
    test_paid_pipeline_reuses_dns_engine(db, paid_env, monkeypatch)
    r = db.scalar(select(Recovery))
    a, _ = paid_env
    for _ in range(10):
        asyncio.run(rr.step(r.id))
        db.expire_all()
        if db.get(Recovery, r.id).status == "SUCCEEDED":
            break
    assert db.get(Recovery, r.id).status == "SUCCEEDED"
    assert paid.enabled(db, a.id)
    asyncio.run(paid.step(r.id))
    assert paid.load(r.id)["stage"] == "CLEANUP"


def test_bot_and_overview_report_enabled_paid_mode(db, paid_env, monkeypatch):
    from commander.app import overview, health
    from commander.bot import dispatch_action, agent_view
    from types import SimpleNamespace
    from commander.config import settings

    a, _ = paid_env
    assert overview(actor="test", db=db)["paid_agents"] == 1
    assert health(db=db)["writes_enabled"] is True
    monkeypatch.setattr(settings, "telegram_admin_ids", [123])
    text, _ = dispatch_action(db, 123, SimpleNamespace(action="status", target=""))
    assert "Автопокупки разрешены для агентов: 1" in text
    text, _ = agent_view(db, 123, a.id, "automation")
    assert "включены автопокупки" in text


def test_cleanup_failure_preserves_successful_recovery(db, paid_env):
    a, _ = paid_env
    r = start(db, a)
    db.add(SystemSetting(key=rr.state_key(r.id), value={"stage": "SUCCEEDED"}))
    db.commit()
    paid.stop(r.id, "cleanup failure")
    db.expire_all()
    assert db.get(Recovery, r.id).status == "SUCCEEDED"
    assert db.get(Incident, r.incident_id).status == "RECOVERED"
    assert not paid.enabled(db, a.id)


@pytest.mark.parametrize("foreign_route", [True, False])
def test_cleanup_requires_safe_route_and_verified_detach(
    db, paid_env, monkeypatch, foreign_route
):
    from commander.floating_pilot import PilotError

    a, _ = paid_env
    r = start(db, a)
    s = paid.load(r.id)
    rid = str(uuid4())
    db.add(
        FloatingIP(
            agent_id=a.id,
            integration_id="cherry",
            resource_id=rid,
            ipv4="9.9.9.9",
            managed=True,
            status="rejected_blocked",
        )
    )
    db.commit()
    calls = []

    async def request(self, method, path, payload=None):
        calls.append(method)
        if method == "PUT":
            return {}
        assert method == "GET"
        if path.endswith("/ips"):
            return [{"id": rid}]
        return {
            "id": rid,
            "type": "floating-ip",
            "address": "9.9.9.9",
            "targeted_to": {"id": 123},
            "routed_to": {"id": "foreign", "type": "subnet", "address": "8.8.4.4"}
            if foreign_route
            else None,
        }

    monkeypatch.setattr(rr.CherryPilotAPI, "request", request)
    if foreign_route:
        with pytest.raises(PilotError, match="другую сеть"):
            asyncio.run(paid.delete_owned(r.id, s, rid))
        assert "PUT" not in calls
    else:
        assert not asyncio.run(paid.delete_owned(r.id, s, rid))
        assert calls.count("PUT") == 1
    assert "DELETE" not in calls


def test_completed_network_job_does_not_expire_during_provider_retry(db, paid_env):
    a, _ = paid_env
    r = start(db, a)
    s = paid.load(r.id)
    assert not paid.network_job(r.id, s, "remove", RESOURCE)
    job = db.scalar(select(Job))
    job.status = "succeeded"
    job.created_at = utcnow() - timedelta(minutes=20)
    db.commit()
    assert paid.network_job(r.id, s, "remove", RESOURCE)


def test_recovered_proxy_cancels_purchase_without_disarming(db, paid_env, monkeypatch):
    from commander import monitoring

    a, _ = paid_env
    r = start(db, a)

    async def healthy(*args):
        return {"mtproto_verified": True, "reports": [], "observations": []}

    monkeypatch.setattr(monitoring, "collect_agent", healthy)
    asyncio.run(paid.step(r.id))
    db.expire_all()
    assert db.get(Recovery, r.id).status == "CANCELLED"
    assert paid.enabled(db, a.id)
    assert paid.load(r.id)["stage"] == "DONE"
    assert not list(db.scalars(select(Job)))


def test_quota_resume_rechecks_proxy_before_another_order(db, paid_env):
    a, _ = paid_env
    r = start(db, a)
    paid.save(
        r.id, "QUOTA_CLEANUP", resume_at=(utcnow() + timedelta(hours=1)).isoformat()
    )
    asyncio.run(paid.step(r.id))
    assert paid.load(r.id)["stage"] == "FINAL_CHECK"


@pytest.mark.parametrize("still_owned", [False, True])
def test_403_requires_complete_project_absence_proof(
    db, paid_env, monkeypatch, still_owned
):
    from commander.floating_pilot import PilotError

    a, _ = paid_env
    r = start(db, a)
    s = paid.load(r.id)
    rid = str(uuid4())
    db.add(
        FloatingIP(
            agent_id=a.id,
            integration_id="cherry",
            resource_id=rid,
            ipv4="9.9.9.9",
            managed=True,
            status="rejected_blocked",
        )
    )
    db.commit()

    async def request(self, method, path, payload=None):
        assert method == "GET"
        if path.endswith("/ips"):
            return [{"id": rid}] if still_owned else []
        raise PilotError("denied", provider_status=403)

    monkeypatch.setattr(rr.CherryPilotAPI, "request", request)
    if still_owned:
        with pytest.raises(PilotError):
            asyncio.run(paid.delete_owned(r.id, s, rid))
    else:
        assert asyncio.run(paid.delete_owned(r.id, s, rid))
    db.expire_all()
    row = db.scalar(select(FloatingIP).where(FloatingIP.resource_id == rid))
    assert bool(row.released_at) is (not still_owned)


def test_cleanup_waits_for_cached_deleted_resource_without_second_delete(
    db, paid_env, monkeypatch
):
    from commander.floating_pilot import PilotError

    a, _ = paid_env
    recovery = start(db, a)
    state = paid.load(recovery.id)
    rid = str(uuid4())
    db.add(
        FloatingIP(
            agent_id=a.id,
            integration_id="cherry",
            resource_id=rid,
            ipv4="9.9.9.9",
            managed=True,
            status="rejected_blocked",
        )
    )
    db.commit()
    deleted = False
    cache_expired = False
    deletes = []

    async def request(self, method, path, payload=None):
        nonlocal deleted
        if method == "DELETE":
            deletes.append(path)
            deleted = True
            return None
        assert method == "GET"
        if path.endswith("/ips"):
            return [] if deleted else [{"id": rid}]
        if cache_expired:
            raise PilotError("denied", provider_status=403)
        return {"id": rid, "address": "9.9.9.9", "type": "floating-ip"}

    monkeypatch.setattr(rr.CherryPilotAPI, "request", request)
    assert not asyncio.run(paid.delete_owned(recovery.id, state, rid))
    assert not asyncio.run(paid.delete_owned(recovery.id, state, rid))
    db.expire_all()
    assert (
        db.scalar(select(FloatingIP).where(FloatingIP.resource_id == rid)).released_at
        is None
    )
    assert len(deletes) == 1
    cache_expired = True
    assert asyncio.run(paid.delete_owned(recovery.id, state, rid))
    db.expire_all()
    assert db.scalar(
        select(FloatingIP).where(FloatingIP.resource_id == rid)
    ).released_at
    assert paid.load(recovery.id)["delete_requests"][rid]["status"] == "released"
    assert len(deletes) == 1


def test_unknown_candidate_is_retried_without_disarming_or_buying(
    db, paid_env, monkeypatch
):
    a, _ = paid_env
    recovery = start(db, a)
    paid.save(recovery.id, "CANDIDATE_VERIFY", resource_id=RESOURCE, new=NEW)
    replies = iter(
        [
            {
                "status": "unknown",
                "error": "inconsistent_response",
                "mtproto_verified": False,
            },
            {"status": "observed", "provider_status": "OK", "mtproto_verified": True},
        ]
    )

    async def protocol(*args):
        return next(replies)

    monkeypatch.setattr(rr, "protocol_verification", protocol)
    asyncio.run(paid.step(recovery.id))
    state = paid.load(recovery.id)
    assert state["stage"] == "CANDIDATE_VERIFY"
    assert state["candidate_last_report"]["error"] == "inconsistent_response"
    db.expire_all()
    assert paid.enabled(db, a.id)
    assert db.get(Recovery, recovery.id).status == "PAID_RUNNING"
    asyncio.run(paid.step(recovery.id))
    assert paid.load(recovery.id)["stage"] == "NETWORK_COMMIT"
    assert paid.load(recovery.id)["candidate_unknown_since"] is None


def test_prolonged_unknown_stops_before_network_rollback_deadline(
    db, paid_env, monkeypatch
):
    a, _ = paid_env
    recovery = start(db, a)
    now = utcnow()
    paid.save(
        recovery.id,
        "CANDIDATE_VERIFY",
        resource_id=RESOURCE,
        new=NEW,
        candidate_unknown_since=(now - timedelta(minutes=3)).isoformat(),
    )

    async def protocol(*args):
        return {
            "status": "unknown",
            "error": "provider_unavailable",
            "mtproto_verified": False,
        }

    monkeypatch.setattr(rr, "protocol_verification", protocol)
    asyncio.run(paid.step(recovery.id))
    state = paid.load(recovery.id)
    assert state["stage"] == "MANUAL_REQUIRED"
    assert state["candidate_last_report"]["error"] == "provider_unavailable"
    assert "order_id" not in state


def test_candidate_window_cannot_outlive_temporary_network(db, paid_env, monkeypatch):
    a, _ = paid_env
    recovery = start(db, a)
    paid.save(
        recovery.id,
        "CANDIDATE_VERIFY",
        resource_id=RESOURCE,
        new=NEW,
        candidate_verify_started_at=(utcnow() - timedelta(minutes=8)).isoformat(),
    )

    async def forbidden(*args):
        raise AssertionError("Expired staging must not be verified or committed")

    monkeypatch.setattr(rr, "protocol_verification", forbidden)
    asyncio.run(paid.step(recovery.id))
    assert paid.load(recovery.id)["stage"] == "MANUAL_REQUIRED"


@pytest.mark.parametrize(
    "stage,status",
    [
        ("PAUSED_FOR_CDN", "PAUSED"),
        ("PAUSED_FOR_CDN", "PAID_RUNNING"),
        ("PAUSED", "PAID_RUNNING"),
        ("FINAL_CHECK", "PAUSED"),
    ],
)
def test_paused_recovery_is_not_scheduled_or_treated_as_failure(
    db, paid_env, monkeypatch, stage, status
):
    from unittest.mock import AsyncMock

    a, _ = paid_env
    r = start(db, a)
    r.status = status
    state = db.get(SystemSetting, paid.state_key(r.id))
    state.value = {
        **state.value,
        "stage": stage,
        "next_at": (utcnow() - timedelta(minutes=10)).isoformat(),
    }
    db.commit()
    before = dict(state.value)
    scheduled = AsyncMock(
        side_effect=AssertionError("Paused work must not be selected")
    )
    monkeypatch.setattr(paid, "step", scheduled)
    assert asyncio.run(paid.tick()) is False
    scheduled.assert_not_awaited()
    db.refresh(state)
    assert state.value == before


def test_pause_saved_after_tick_selection_is_respected_by_step(
    db, paid_env, monkeypatch
):
    from unittest.mock import Mock

    a, _ = paid_env
    r = start(db, a)
    r.status = "PAUSED"
    db.commit()
    check = Mock(
        side_effect=AssertionError(
            "Pause must be checked before context or provider calls"
        )
    )
    monkeypatch.setattr(paid, "require_context", check)
    asyncio.run(paid.step(r.id))
    check.assert_not_called()
    db.refresh(r)
    assert r.status == "PAUSED"
