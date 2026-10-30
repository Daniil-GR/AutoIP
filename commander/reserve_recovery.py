"""Durable, opt-in cutover to a previously tested reserve; no purchase/delete/SSH."""

import asyncio
from contextlib import contextmanager
from datetime import datetime, timedelta

from sqlalchemy import select, text

from .database import (
    Agent,
    FloatingIP,
    Incident,
    Integration,
    Notification,
    Recovery,
    SessionLocal,
    SystemSetting,
    engine,
    utcnow,
)
from .diagnostics import record_failure
from .dns_pilot import (
    DNSPilot,
    DNSPilotError,
    assert_records,
    canonical,
    snapshot,
    target,
)
from .dns_roundtrip import dns_observations, dns_quorum
from .dns_scope import MANAGED_DNS_ZONE
from .floating_pilot import CherryPilotAPI, known_blocked, relation_id
from .security import audit, aware
from .vault import decrypt

ACTIVE = ("QUEUED", "RUNNING", "ROLLING_BACK", "PAID_RUNNING")


def policy_key(agent_id):
    return "auto-reserve:" + agent_id


def state_key(recovery_id):
    return "recovery:" + recovery_id


def reserve_readiness(db, agent):
    from .services import online, proxy_address

    setting = db.get(SystemSetting, policy_key(agent.id))
    policy = dict(setting.value) if setting else {}
    candidate = db.scalar(
        select(FloatingIP).where(
            FloatingIP.resource_id == policy.get("resource_id", "")
        )
    )
    cfg = agent.configuration or {}
    addresses = {
        a.get("ip")
        for link in agent.facts.get("interfaces", [])
        for a in link.get("addresses", [])
    }
    checks = {
        "reserve_selected": bool(
            candidate
            and candidate.agent_id == agent.id
            and candidate.integration_id == cfg.get("cherry_integration_id")
            and candidate.managed
            and not candidate.released_at
            and candidate.status == "ready_standby"
        ),
        "reserve_unblocked": bool(candidate and not known_blocked(db, candidate.ipv4)),
        "reserve_separate": bool(
            candidate
            and candidate.ipv4 not in (cfg.get("management_ip"), proxy_address(agent))
        ),
        "reserve_on_interface": bool(
            candidate
            and candidate.ipv4 in addresses
            and cfg.get("management_ip") in addresses
        ),
        "agent_online": online(agent) and not agent.revoked,
        "telemt_active": agent.facts.get("telemt_service") == "active",
        "agent_unpaused": not agent.paused,
        "tested_roundtrip": False,
        "dns_scoped": False,
        "stable_public_host": bool(agent.public_host)
        and agent.public_host
        in (
            cfg.get("dns_record"),
            cfg.get("proxy_ip"),
            cfg.get("management_ip"),
            cfg.get("floating_ip"),
        ),
    }
    for kind, field in [
        ("cherry", "cherry_integration_id"),
        ("dynadot", "dns_integration_id"),
        ("mtproto_checker", "checker_integration_id"),
        ("mtproto", "mtproto_integration_id"),
    ]:
        item = db.get(Integration, cfg.get(field, ""))
        checks[kind] = bool(
            item
            and item.kind == kind
            and (item.status == "verified" or kind == "mtproto")
        )
    try:
        target(cfg.get("dns_record", ""), proxy_address(agent))
        checks["dns_scoped"] = cfg.get("dns_zone") == MANAGED_DNS_ZONE
    except (ValueError, TypeError, DNSPilotError):
        pass
    proof = db.get(SystemSetting, policy.get("proof_key", ""))
    if proof and candidate:
        p = proof.value
        checks["tested_roundtrip"] = bool(
            p.get("stage") == "COMPLETED_RETURNED"
            and p.get("agent_id") == agent.id
            and (
                policy.get("mode") == "paid_candidate"
                or (
                    p.get("resource_id") == candidate.resource_id
                    and p.get("old") == proxy_address(agent)
                    and p.get("new") == candidate.ipv4
                )
            )
            and p.get("host") == cfg.get("dns_record")
            and p.get("forward_check", {}).get("verified")
            and p.get("return_check", {}).get("verified")
        )
    return {
        "checks": checks,
        "prepared": all(checks.values()),
        "enabled": policy.get("enabled") is True,
        "resource_id": policy.get("resource_id"),
        "policy": policy,
    }


def prepare(db, agent_id, resource_id):
    agent = db.get(Agent, agent_id)
    if not agent:
        raise DNSPilotError("Агент не найден")
    if db.scalar(
        select(Recovery.id).where(
            Recovery.agent_id == agent_id, Recovery.status.in_(ACTIVE)
        )
    ):
        raise DNSPilotError("У агента уже выполняется восстановление")
    proofs = db.scalars(
        select(SystemSetting).where(SystemSetting.key.like("dns-pilot:%"))
    ).all()
    proof = next(
        (
            p
            for p in proofs
            if p.value.get("stage") == "COMPLETED_RETURNED"
            and p.value.get("agent_id") == agent_id
            and p.value.get("resource_id") == resource_id
        ),
        None,
    )
    if not proof:
        raise DNSPilotError("Нет завершённого DNS-пилота для этого резерва")
    row = db.get(SystemSetting, policy_key(agent_id))
    value = {
        "enabled": False,
        "mode": "tested_reserve_only",
        "resource_id": resource_id,
        "proof_key": proof.key,
        "prepared_at": utcnow().isoformat(),
        "purchase_allowed": False,
        "delete_allowed": False,
    }
    if row and row.value.get("enabled"):
        raise DNSPilotError("Сначала явно отключите действующий режим")
    if row:
        row.value = value
    else:
        db.add(SystemSetting(key=policy_key(agent_id), value=value))
    db.flush()
    report = reserve_readiness(db, agent)
    if not report["prepared"]:
        raise DNSPilotError(
            "Не выполнены условия: "
            + ", ".join(k for k, v in report["checks"].items() if not v)
        )
    audit(
        db,
        "local-admin",
        "reserve_recovery_prepared_disabled",
        agent_id,
        resource_id=resource_id,
    )
    return report


def set_enabled(db, agent_id, enabled, *, approved=False):
    agent = db.scalar(select(Agent).where(Agent.id == agent_id).with_for_update())
    if not agent:
        raise DNSPilotError("Агент не найден")
    row = db.get(SystemSetting, policy_key(agent_id))
    if not row:
        raise DNSPilotError("Сначала подготовьте резерв")
    if enabled and (not approved or not reserve_readiness(db, agent)["prepared"]):
        raise DNSPilotError("Нужны согласование и готовый проверенный резерв")
    row.value = {**row.value, "enabled": enabled, "changed_at": utcnow().isoformat()}
    audit(
        db,
        "local-admin",
        "reserve_recovery_enabled" if enabled else "reserve_recovery_disabled",
        agent_id,
    )


def assert_authorized(db, state):
    from .services import online, proxy_address

    agent = db.get(Agent, state["agent_id"])
    policy = db.get(SystemSetting, policy_key(agent.id))
    cfg = agent.configuration or {}
    from .paid_recovery import enabled

    if (
        not policy
        or (policy.value.get("mode") == "paid_candidate" and not enabled(db, agent.id))
        or not policy.value.get("enabled")
        or policy.value.get("resource_id") != state["resource_id"]
        or agent.paused
        or agent.revoked
        or not online(agent)
        or agent.facts.get("telemt_service") != "active"
        or proxy_address(agent) != state["old"]
        or cfg.get("management_ip") != state["management_ip"]
        or cfg.get("dns_record") != state["host"]
        or cfg.get("dns_zone") != MANAGED_DNS_ZONE
        or agent.public_host != state["public_host_at_start"]
        or cfg.get("dns_integration_id") != state["dns_integration_id"]
        or cfg.get("cherry_integration_id") != state["cherry_integration_id"]
        or str(cfg.get("cherry_server_id")) != state["cherry_server_id"]
        or agent.proxy_port != state["port"]
    ):
        raise DNSPilotError("Разрешение или параметры изменились перед записью")


async def verify_assignment(state):
    with SessionLocal() as db:
        item = db.get(Integration, state["cherry_integration_id"])
        key = decrypt(item)["api_key"]
    raw = await CherryPilotAPI(key).request("GET", "/ips/" + state["resource_id"])
    if (
        raw.get("type") != "floating-ip"
        or raw.get("address") != state["new"]
        or relation_id(raw.get("targeted_to") or raw.get("assigned_to"))
        != state["cherry_server_id"]
    ):
        raise DNSPilotError("Cherry не подтвердил назначение резерва нужной ноде")


def recovery_failure(evidence, decision):
    """Human confirmation supports protocol blocks invisible to TCP probes."""
    from .monitor import independent_failure

    if independent_failure(evidence):
        return True
    if decision != "confirm" or not evidence.get("ip"):
        return False
    for report in evidence.get("reports", []):
        if (
            report.get("source") != "mtproto-checker"
            or report.get("status") != "observed"
            or report.get("target") != evidence["ip"]
            or report.get("provider_status") not in ("RKN_BLOCK", "DATA_CUT")
        ):
            continue
        try:
            checked = datetime.fromisoformat(
                report["checked_at"].replace("Z", "+00:00")
            )
            if (
                checked.tzinfo is None
                or not -60 <= (utcnow() - checked).total_seconds() <= 300
            ):
                continue
        except (KeyError, TypeError, ValueError, AttributeError):
            continue
        points = report.get("points", {})
        local, remote = points.get("local", {}), points.get("remote", {})
        if not all(remote.get(k) is True for k in ("tcp", "handshake", "data")):
            continue
        if report["provider_status"] == "RKN_BLOCK":
            return local.get("tcp") is False or local.get("handshake") is False
        return (
            local.get("tcp") is True
            and local.get("handshake") is True
            and local.get("data") is False
        )
    return False


def queue_if_ready(db, recovery, incident):
    from .services import proxy_address
    from .paid_recovery import authorization, enabled

    agent = db.get(Agent, recovery.agent_id)
    report = reserve_readiness(db, agent)
    if not (
        report["enabled"]
        and report["prepared"]
        and incident
        and incident.status == "BLOCK_CONFIRMED"
        and incident.observed_ip == proxy_address(agent)
        and (
            recovery_failure(incident.evidence, incident.decision)
            or (enabled(db, agent.id) and authorization(incident))
        )
    ):
        return False
    other = db.scalar(
        select(Recovery.id).where(
            Recovery.agent_id == agent.id,
            Recovery.id != recovery.id,
            Recovery.status.in_(ACTIVE),
        )
    )
    if other:
        return False
    candidate = db.scalar(
        select(FloatingIP).where(FloatingIP.resource_id == report["resource_id"])
    )
    cfg = agent.configuration
    state = {
        "stage": "FINAL_CHECK",
        "agent_id": agent.id,
        "incident_id": incident.id,
        "old": incident.observed_ip,
        "new": candidate.ipv4,
        "resource_id": candidate.resource_id,
        "host": cfg["dns_record"],
        "public_host_at_start": agent.public_host,
        "port": agent.proxy_port,
        "dns_integration_id": cfg["dns_integration_id"],
        "cherry_integration_id": cfg["cherry_integration_id"],
        "cherry_server_id": str(cfg["cherry_server_id"]),
        "management_ip": cfg["management_ip"],
        "created_at": utcnow().isoformat(),
        "deadline": (utcnow() + timedelta(minutes=30)).isoformat(),
    }
    db.add(SystemSetting(key=state_key(recovery.id), value=state))
    recovery.status = "QUEUED"
    recovery.stages = [
        *[x for x in recovery.stages if x["stage"] != "LIVE_EXECUTION"],
        {"stage": "FINAL_CHECK", "status": "queued"},
    ]
    incident.status = "RECOVERING"
    incident.next_check_at = None
    if not incident.decision:
        incident.decision = "auto_confirm"
    db.add(
        Notification(
            topic="recovery",
            target=recovery.id,
            text=(
                f"{agent.name}: подготовлено DNS-переключение на проверенный новый Floating IP."
                if report["policy"].get("mode") == "paid_candidate"
                else f"{agent.name}: подтверждена проблема в РФ. Подготовлено переключение на существующий резерв; новые IP не покупаются."
            ),
        )
    )
    return True


def load(identifier):
    with SessionLocal() as db:
        return dict(db.get(SystemSetting, state_key(identifier)).value)


def save(identifier, stage, **values):
    with SessionLocal() as db:
        r = db.get(Recovery, identifier)
        row = db.get(SystemSetting, state_key(identifier))
        row.value = {
            **row.value,
            **values,
            "stage": stage,
            "updated_at": utcnow().isoformat(),
        }
        if not r.stages or r.stages[-1]["stage"] != stage:
            r.stages = [
                *r.stages,
                {"stage": stage, "status": "running", "at": utcnow().isoformat()},
            ]
            audit(
                db,
                "worker",
                "reserve_recovery_" + stage.lower(),
                r.agent_id,
                recovery_id=identifier,
            )
        r.status = "ROLLING_BACK" if stage == "ROLLBACK" else "RUNNING"
        db.commit()


def finish(identifier, status, reason):
    with SessionLocal() as db:
        r = db.get(Recovery, identifier)
        row = db.get(SystemSetting, state_key(identifier))
        row.value = {
            **row.value,
            "stage": status,
            "reason": reason,
            "finished_at": utcnow().isoformat(),
        }
        r.status = status
        policy = db.get(SystemSetting, policy_key(r.agent_id))
        if policy and status != "CANCELLED":
            policy.value = {**policy.value, "enabled": False, "stopped_by": identifier}
        r.stages = [*r.stages, {"stage": status, "status": reason}]
        incident = db.get(Incident, r.incident_id)
        if incident:
            incident.status = (
                "RECOVERED"
                if status in ("SUCCEEDED", "CANCELLED")
                else "MANUAL_REQUIRED"
            )
            incident.next_check_at = None
            if status in ("SUCCEEDED", "CANCELLED"):
                incident.closed_at = utcnow()
        db.add(
            Notification(
                topic="recovery",
                target=r.id,
                text=f"Восстановление {r.id[:8]}: {reason}. Новые IP не покупались; ресурсы не удалялись.",
            )
        )
        audit(
            db,
            "worker",
            "reserve_recovery_" + status.lower(),
            r.agent_id,
            recovery_id=identifier,
        )
        db.commit()


def dns_client(state):
    with SessionLocal() as db:
        item = db.get(Integration, state["dns_integration_id"])
        c = decrypt(item)
    return DNSPilot(c["api_key"], c["api_secret"])


@contextmanager
def exclusive():
    with engine.connect() as conn:
        if conn.dialect.name != "postgresql":
            raise DNSPilotError("Живой worker требует PostgreSQL")
        locked = conn.execute(text("SELECT pg_try_advisory_lock(184042, 1)")).scalar()
        try:
            yield bool(locked)
        finally:
            if locked:
                conn.execute(text("SELECT pg_advisory_unlock(184042, 1)"))


async def protocol_verification(agent_id, host, port):
    """Retry one contradictory provider response, never hide a valid failure."""
    from .monitoring import checker_report

    for attempt in range(2):
        report = await checker_report(agent_id, host, port)
        if report.get("error") != "inconsistent_response" or attempt:
            return report
        await asyncio.sleep(1)


async def step(identifier):
    from .services import online, proxy_address
    from .monitor import verdict
    from .monitoring import checker_report, collect_agent

    s = load(identifier)
    with SessionLocal() as db:
        a = db.get(Agent, s["agent_id"])
        r = db.get(Recovery, identifier)
        if r.status not in ACTIVE:
            return
        i = db.get(Incident, s["incident_id"])
        cfg = a.configuration or {}
        policy = db.get(SystemSetting, policy_key(a.id))
        enabled = bool(policy and policy.value.get("enabled"))
        if policy and policy.value.get("mode") == "paid_candidate":
            from .paid_recovery import enabled as paid_enabled

            enabled = enabled and paid_enabled(db, a.id)
        resource = db.scalar(
            select(FloatingIP).where(FloatingIP.resource_id == s["resource_id"])
        )
        addresses = {
            x.get("ip")
            for link in a.facts.get("interfaces", [])
            for x in link.get("addresses", [])
        }
        stale = (
            not resource
            or not resource.managed
            or resource.released_at
            or resource.agent_id != a.id
            or resource.integration_id != s["cherry_integration_id"]
            or resource.ipv4 != s["new"]
            or known_blocked(db, s["new"])
            or s["new"] not in addresses
            or cfg.get("management_ip") != s["management_ip"]
            or cfg.get("cherry_integration_id") != s["cherry_integration_id"]
            or str(cfg.get("cherry_server_id")) != s["cherry_server_id"]
            or not policy
            or policy.value.get("resource_id") != s["resource_id"]
            or a.revoked
            or not online(a)
            or a.facts.get("telemt_service") != "active"
            or proxy_address(a) != s["old"]
            or cfg.get("dns_record") != s["host"]
            or cfg.get("dns_zone") != MANAGED_DNS_ZONE
            or a.public_host != s["public_host_at_start"]
            or cfg.get("dns_integration_id") != s["dns_integration_id"]
            or a.proxy_port != s["port"]
            or not i
            or i.status != "RECOVERING"
        )
        paused = a.paused or not enabled
    writes = s.get("add_submitted") or s.get("remove_submitted")
    if (stale or paused) and s["stage"] != "ROLLBACK":
        if writes:
            save(identifier, "ROLLBACK", reason="Условия или разрешение изменились")
        else:
            finish(identifier, "MANUAL_REQUIRED", "Условия или разрешение изменились")
        return
    if utcnow() >= aware(datetime.fromisoformat(s["deadline"])) and s["stage"] not in (
        "ROLLBACK",
        "COMMIT",
    ):
        finish(
            identifier,
            "MANUAL_REQUIRED",
            "Восстановление задержалось более 30 минут; оба IP и текущее DNS сохранены для проверки",
        )
        return
    stage = s["stage"]
    if stage == "FINAL_CHECK":
        evidence = await collect_agent(s["agent_id"], s["host"], s["port"], s["old"])
        result = verdict(evidence, True, True)
        if result == "reachable":
            finish(identifier, "CANCELLED", "Доступность исходного IP восстановилась")
            return
        from .paid_recovery import authorization, enabled

        with SessionLocal() as db:
            paid_confirmed = enabled(db, s["agent_id"]) and authorization(i, evidence)
        if result != "suspected" or not (
            recovery_failure(evidence, i.decision) or paid_confirmed
        ):
            finish(
                identifier,
                "MANUAL_REQUIRED",
                "Финальная проверка не дала достаточных подтверждений блокировки",
            )
            return
        save(identifier, "CANDIDATE_CHECK", final_evidence=evidence)
    elif stage == "CANDIDATE_CHECK":
        with SessionLocal() as db:
            agent = db.get(Agent, s["agent_id"])
            ready = reserve_readiness(db, agent)
        if not ready["prepared"]:
            finish(identifier, "MANUAL_REQUIRED", "Резерв больше не готов")
            return
        await verify_assignment(s)
        report = await checker_report(s["agent_id"], s["new"], s["port"])
        if not report.get("mtproto_verified"):
            finish(identifier, "MANUAL_REQUIRED", "Резерв не прошёл MTProto-проверку")
            return
        before = snapshot(await dns_client(s).records(MANAGED_DNS_ZONE))
        matches = [
            x
            for x in before.get("dns_sub_list", [])
            if x.get("sub_host") == target(s["host"], s["old"])["sub_host"]
        ]
        if canonical(matches) != canonical([target(s["host"], s["old"])]):
            finish(identifier, "MANUAL_REQUIRED", "DNS уже изменён или неоднозначен")
            return
        save(identifier, "DNS_ADD", before=before, candidate_check=report)
    elif stage in ("DNS_ADD", "DNS_REMOVE"):
        client = dns_client(s)
        current = snapshot(await client.records(MANAGED_DNS_ZONE))
        old, new = target(s["host"], s["old"]), target(s["host"], s["new"])
        added = {
            **s["before"],
            "dns_sub_list": [*s["before"].get("dns_sub_list", []), new],
        }
        final = {
            **s["before"],
            "dns_sub_list": [
                x
                for x in s["before"].get("dns_sub_list", [])
                if canonical([x]) != canonical([old])
            ]
            + [new],
        }
        expected = added if stage == "DNS_ADD" else final
        try:
            assert_records(current, expected)
            done = True
        except DNSPilotError:
            done = False
        if done:
            save(identifier, "DNS_REMOVE" if stage == "DNS_ADD" else "DNS_VERIFY")
            return
        assert_records(current, s["before"] if stage == "DNS_ADD" else added)
        marker = "add_submitted" if stage == "DNS_ADD" else "remove_submitted"
        if not s.get(marker):
            await verify_assignment(s)
            with SessionLocal() as db:
                assert_authorized(db, s)
            save(identifier, stage, **{marker: True})
            await client.mutate(
                "POST" if stage == "DNS_ADD" else "DELETE",
                new if stage == "DNS_ADD" else old,
                s["before"]["ttl"],
            )
        save(identifier, stage, next_at=(utcnow() + timedelta(seconds=30)).isoformat())
    elif stage == "DNS_VERIFY":
        observations = await asyncio.to_thread(dns_observations, s["host"])
        ready = dns_quorum(observations, s["new"])
        if not (ready["authoritative_ok"] and ready["recursive_ok"]):
            save(
                identifier,
                stage,
                dns=observations,
                next_at=(utcnow() + timedelta(seconds=30)).isoformat(),
            )
            return
        direct = await protocol_verification(s["agent_id"], s["new"], s["port"])
        domain = await protocol_verification(s["agent_id"], s["host"], s["port"])
        if not (direct.get("mtproto_verified") and domain.get("mtproto_verified")):
            save(
                identifier,
                stage,
                dns=observations,
                last_protocol_checks={"direct": direct, "domain": domain},
                next_at=(utcnow() + timedelta(seconds=30)).isoformat(),
            )
            return
        save(
            identifier,
            "COMMIT",
            verified={
                "dns": observations,
                "direct": direct,
                "domain": domain,
                "at": utcnow().isoformat(),
            },
        )
    elif stage == "COMMIT":
        verified_at = s.get("verified", {}).get("at")
        if not verified_at or utcnow() - aware(
            datetime.fromisoformat(verified_at)
        ) > timedelta(minutes=5):
            if utcnow() >= aware(datetime.fromisoformat(s["deadline"])):
                finish(
                    identifier,
                    "MANUAL_REQUIRED",
                    "Проверки устарели после остановки; оба IP сохранены",
                )
            else:
                save(identifier, "DNS_VERIFY")
            return
        await verify_assignment(s)
        current = snapshot(await dns_client(s).records(MANAGED_DNS_ZONE))
        old, new = target(s["host"], s["old"]), target(s["host"], s["new"])
        final = {
            **s["before"],
            "dns_sub_list": [
                x
                for x in s["before"].get("dns_sub_list", [])
                if canonical([x]) != canonical([old])
            ]
            + [new],
        }
        try:
            assert_records(current, final)
        except DNSPilotError:
            finish(
                identifier,
                "MANUAL_REQUIRED",
                "DNS изменился после проверки; адреса сохранены, нужна сверка",
            )
            return
        with SessionLocal() as db:
            a = db.scalar(
                select(Agent).where(Agent.id == s["agent_id"]).with_for_update()
            )
            assert_authorized(db, s)
            r = db.get(Recovery, identifier)
            resource = db.scalar(
                select(FloatingIP).where(FloatingIP.resource_id == s["resource_id"])
            )
            a.configuration = {**a.configuration, "floating_ip": s["new"]}
            resource.status = "active"
            if s["old"] != s["management_ip"]:
                for old_resource in db.scalars(
                    select(FloatingIP).where(
                        FloatingIP.agent_id == a.id,
                        FloatingIP.ipv4 == s["old"],
                        FloatingIP.managed.is_(True),
                        FloatingIP.released_at.is_(None),
                    )
                ):
                    old_resource.status = "blocked"
            policy = db.get(SystemSetting, policy_key(a.id))
            policy.value = {**policy.value, "enabled": False, "consumed_by": identifier}
            r.status = "SUCCEEDED"
            paid_mode = policy.value.get("mode") == "paid_candidate"
            reason = (
                "DNS и MTProto проверены; новый Floating IP активирован, ожидается безопасная очистка старых адресов"
                if paid_mode
                else "DNS и MTProto проверены; активирован существующий резерв, режим исчерпан и выключен"
            )
            row = db.get(SystemSetting, state_key(identifier))
            row.value = {
                **row.value,
                "stage": "SUCCEEDED",
                "finished_at": utcnow().isoformat(),
            }
            r.stages = [*r.stages, {"stage": "SUCCEEDED", "status": reason}]
            incident = db.get(Incident, r.incident_id)
            incident.status, incident.closed_at, incident.next_check_at = (
                "RECOVERED",
                utcnow(),
                None,
            )
            db.add(
                Notification(
                    topic="recovery",
                    target=r.id,
                    text=reason
                    if paid_mode
                    else reason + ". Новые IP не покупались; ресурсы не удалялись.",
                )
            )
            audit(
                db, "worker", "reserve_recovery_succeeded", a.id, recovery_id=identifier
            )
            db.commit()
    elif stage == "ROLLBACK":
        deadline = s.get("rollback_deadline")
        if deadline and utcnow() >= aware(datetime.fromisoformat(deadline)):
            finish(
                identifier,
                "MANUAL_REQUIRED",
                "Возврат DNS не подтверждён за 10 минут; оба IP сохранены",
            )
            return
        if not deadline:
            save(
                identifier,
                stage,
                rollback_deadline=(utcnow() + timedelta(minutes=10)).isoformat(),
            )
        await dns_client(s).restore_a(
            s["host"], s["old"], s["new"], s["before"], approved=True
        )
        finish(
            identifier,
            "ROLLED_BACK",
            "Возвращён исходный DNS, требуется ручная проверка; оба IP сохранены",
        )


async def tick():
    with SessionLocal() as db:
        candidates = db.scalars(
            select(Recovery)
            .where(Recovery.status.in_(ACTIVE))
            .order_by(Recovery.created_at)
            .limit(20)
        ).all()
        identifier = None
        for r in candidates:
            state = db.get(SystemSetting, state_key(r.id))
            if state and (
                not state.value.get("next_at")
                or utcnow() >= aware(datetime.fromisoformat(state.value["next_at"]))
            ):
                identifier = r.id
                break
    if not identifier:
        return False
    with exclusive() as locked:
        if not locked:
            return False
        with SessionLocal() as db:
            current = db.get(Recovery, identifier)
            if current.status not in ACTIVE:
                return False
            state = db.get(SystemSetting, state_key(identifier))
            if state.value.get("next_at") and utcnow() < aware(
                datetime.fromisoformat(state.value["next_at"])
            ):
                return False
        try:
            await step(identifier)
        except Exception as error:
            s = load(identifier)
            error_id = record_failure(
                "reserve_recovery",
                s["stage"],
                error,
                operation_id=identifier,
                agent_id=s["agent_id"],
            )
            save(
                identifier,
                s["stage"],
                error_id=error_id,
                next_at=(utcnow() + timedelta(seconds=30)).isoformat(),
            )
    return True


STAGE_LABELS = {
    "PAID_RUNNING": "Поиск нового Floating IP",
    "NETWORK_PREFLIGHT": "Проверка сетевого помощника",
    "ORDER": "Получение Floating IP",
    "ATTACH": "Назначение IP серверу",
    "NETWORK_PREPARE": "Добавление IP в Linux",
    "CANDIDATE_VERIFY": "Проверка кандидата из РФ",
    "NETWORK_COMMIT": "Сохранение IP после перезагрузки",
    "DNS_HANDOFF": "Подготовка DNS-переключения",
    "HANDOFF": "Выполняется DNS-переключение",
    "CLEANUP": "Освобождение старых адресов",
    "QUOTA_CLEANUP": "Квота исчерпана: очистка кандидатов",
    "DONE": "Завершено",
    "PREFLIGHT": "Подготовка",
    "LIVE_EXECUTION": "Живое выполнение",
    "FINAL_CHECK": "Финальная проверка блокировки",
    "CANDIDATE_CHECK": "Проверка резерва",
    "DNS_ADD": "Добавление нового A-адреса",
    "DNS_REMOVE": "Удаление старого A-адреса",
    "DNS_VERIFY": "Проверка DNS и MTProto",
    "COMMIT": "Сохранение активного IP",
    "ROLLBACK": "Возврат исходной DNS-записи",
    "QUEUED": "В очереди",
    "RUNNING": "Выполняется",
    "ROLLING_BACK": "Выполняется возврат DNS",
    "SUCCEEDED": "Завершено",
    "CANCELLED": "Отменено: доступность восстановилась",
    "ROLLED_BACK": "DNS возвращён",
    "MANUAL_REQUIRED": "Нужно вмешательство",
    "queued": "В очереди",
    "running": "Выполняется",
    "checked": "Проверено",
    "blocked": "Остановлено",
}
