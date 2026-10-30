"""Transactional control-plane actions shared by API, worker and Telegram bot."""

from datetime import timedelta
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import select

from .database import (
    Agent,
    Check,
    ControlTask,
    FloatingIP,
    Incident,
    Integration,
    Notification,
    Recovery,
    SystemSetting,
    utcnow,
)
from .monitor import independent_failure
from .security import audit, aware, display_time

ACTIVE_INCIDENTS = ("WAITING_CONFIRMATION", "RECHECKING", "BLOCK_CONFIRMED")


def proxy_address(agent):
    config = agent.configuration or {}
    return config.get("floating_ip") or config.get("proxy_ip") or ""


def require_agent(db, agent_id, lock=False):
    query = select(Agent).where(Agent.id == agent_id)
    item = db.scalar(query.with_for_update() if lock else query)
    if not item:
        raise HTTPException(404, "Агент не найден")
    return item


def online(agent):
    return bool(
        agent.last_seen and utcnow() - aware(agent.last_seen) < timedelta(seconds=90)
    )


def serialize_agent(a):
    return {
        "id": a.id,
        "name": a.name,
        "public_host": a.public_host,
        "proxy_port": a.proxy_port,
        "facts": a.facts,
        "last_seen": a.last_seen,
        "created_at": a.created_at,
        "configuration": a.configuration or {},
        "paused": a.paused,
        "online": online(a),
    }


def set_paused(db, agent_id, paused, actor):
    agent = require_agent(db, agent_id, lock=True)
    agent.paused = paused
    if paused:
        for incident in db.scalars(
            select(Incident).where(
                Incident.agent_id == agent_id, Incident.status.in_(ACTIVE_INCIDENTS)
            )
        ):
            incident.status = "PAUSED"
            incident.decision = "hold"
            incident.next_check_at = None
    audit(db, actor, "agent_paused" if paused else "agent_resumed", agent_id)
    return agent


def request_check(db, agent_id, actor, incident_id=None, key=None):
    require_agent(db, agent_id, lock=True)
    # One live check per agent across UI, bot and scheduled tasks.
    existing = db.scalar(
        select(ControlTask).where(
            ControlTask.agent_id == agent_id,
            ControlTask.status.in_(["queued", "running"]),
            ControlTask.kind == "check",
        )
    )
    if existing:
        return existing
    key = key or str(uuid4())
    existing = db.scalar(select(ControlTask).where(ControlTask.dedup_key == key))
    if existing:
        return existing
    task = ControlTask(
        agent_id=agent_id, dedup_key=key, payload={"incident_id": incident_id}
    )
    db.add(task)
    audit(db, actor, "check_requested", agent_id)
    db.flush()
    return task


def readiness(db, agent):
    from .reserve_recovery import reserve_readiness

    report = reserve_readiness(db, agent)
    blockers = []
    if not report["prepared"]:
        blockers.append(
            "Не завершена подготовка существующего резерва; проверьте условия ниже"
        )
    if not report["enabled"]:
        blockers.append(
            "Автоматическое DNS-переключение на резерв отдельно не включено"
        )
    return {
        "checks": report["checks"],
        "monitoring_ready": online(agent)
        and agent.facts.get("telemt_service") == "active",
        "reserve_prepared": report["prepared"],
        "recovery_ready": report["prepared"] and report["enabled"],
        "automation_enabled": report["enabled"],
        "live_blockers": blockers,
    }


def recovery_plan(db, agent_id, actor, key, incident_id=None):
    agent = require_agent(db, agent_id, lock=True)
    existing = db.scalar(select(Recovery).where(Recovery.idempotency_key == key))
    if existing:
        return existing
    report = readiness(db, agent)
    stages = [
        {"stage": "PREFLIGHT", "status": "checked", "readiness": report},
        {
            "stage": "LIVE_EXECUTION",
            "status": "blocked",
            "reason": "Нет достаточных подтверждений блокировки либо не выполнены условия восстановления",
        },
    ]
    recovery = Recovery(
        agent_id=agent_id,
        incident_id=incident_id,
        idempotency_key=key,
        status="MANUAL_REQUIRED",
        stages=stages,
    )
    db.add(recovery)
    db.flush()
    from .reserve_recovery import queue_if_ready

    incident = db.get(Incident, incident_id) if incident_id else None
    if queue_if_ready(db, recovery, incident):
        audit(db, actor, "reserve_recovery_queued", recovery.id, agent_id=agent_id)
        return recovery
    audit(db, actor, "recovery_preflight", recovery.id, agent_id=agent_id)
    db.add(
        Notification(
            topic="recovery",
            target=recovery.id,
            text=f"{agent.name}: предварительная проверка завершена. Живое восстановление не запущено: проверьте готовность и подтверждение инцидента. Новые IP не покупались.",
        )
    )
    return recovery


def incident_action(db, incident_id, action, actor):
    # Agent first, incident second: identical lock ordering to worker.
    item = db.get(Incident, incident_id)
    if not item:
        raise HTTPException(404, "Инцидент не найден")
    agent = require_agent(db, item.agent_id, lock=True)
    item = db.scalar(
        select(Incident)
        .where(Incident.id == incident_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if item.status not in ACTIVE_INCIDENTS:
        raise HTTPException(409, "Инцидент уже закрыт или приостановлен")
    if action == "working":
        item.status, item.decision, item.closed_at = "DISMISSED", "working", utcnow()
        item.next_check_at = None
    elif action == "hold":
        set_paused(db, agent.id, True, actor)
    elif action in ("confirm", "recheck"):
        if agent.paused:
            raise HTTPException(409, "Автоматизация приостановлена")
        if action == "confirm":
            item.decision = "confirm"
        item.status = "RECHECKING"
        request_check(db, agent.id, actor, incident_id=item.id)
    else:
        raise HTTPException(422, "Неизвестное действие")
    audit(db, actor, "incident_" + action, item.id)
    return item


def record_evidence(db, agent_id, evidence, result, incident_id=None):
    agent = require_agent(db, agent_id, lock=True)
    db.add(Check(agent_id=agent_id, result=result, details=evidence))
    record_monitor_health(db, agent, evidence)
    record_protocol_health(db, agent, evidence, result)
    active = db.scalar(
        select(Incident)
        .where(Incident.agent_id == agent_id, Incident.status.in_(ACTIVE_INCIDENTS))
        .with_for_update()
    )
    current_ip = proxy_address(agent)
    from .reserve_recovery import ACTIVE

    if db.scalar(
        select(Recovery.id).where(
            Recovery.agent_id == agent_id, Recovery.status.in_(ACTIVE)
        )
    ):
        return  # Existing recovery owns this incident; do not open a duplicate.
    if active and active.observed_ip != current_ip:
        active.status, active.closed_at, active.next_check_at = (
            "SUPERSEDED",
            utcnow(),
            None,
        )
        active = None
    if incident_id and (not active or active.id != incident_id):
        return  # stale result must never reopen a dismissed/superseded incident
    if result == "reachable":
        if active:
            active.status, active.closed_at, active.next_check_at = (
                "RECOVERED",
                utcnow(),
                None,
            )
            db.add(
                Notification(
                    topic="incident_closed",
                    target=active.id,
                    text=f"{agent.name}: доступность TCP из РФ восстановилась. Замена IP отменена.",
                )
            )
        return
    if result != "suspected" or agent.paused:
        if (
            active
            and incident_id == active.id
            and (active.decision == "confirm" or active.rechecks >= 3)
        ):
            active.status, active.next_check_at = "MANUAL_REQUIRED", None
            db.add(
                Notification(
                    topic="incident_attention",
                    target=active.id,
                    text=f"{agent.name}: заключительная проверка не дала достаточных подтверждений. Требуется ручная проверка.",
                )
            )
        return
    if not active:
        protocol_status = next(
            (
                r.get("provider_status")
                for r in evidence.get("reports", [])
                if r.get("source") == "mtproto-checker"
            ),
            None,
        )
        summary = (
            f"MTProto Checker: {protocol_status}; отдельная RU-точка и внешняя нода. Проверьте результаты других источников."
            if protocol_status
            else "Отказы TCP из нескольких RU ASN при доступности из других стран."
        )
        active = Incident(
            agent_id=agent_id,
            observed_ip=current_ip,
            evidence=evidence,
            next_check_at=utcnow() + timedelta(minutes=15),
        )
        db.add(active)
        db.flush()
        db.add(
            Notification(
                topic="incident",
                target=active.id,
                text=f"Вероятная недоступность: {agent.name}\n{agent.public_host}:{agent.proxy_port}\nIP: {current_ip or 'не настроен'}\nНачало: {display_time(utcnow())}\n{summary} Требуется проверка; блокировка не доказана.",
            )
        )
    else:
        active.evidence = evidence
    # Only a dedicated final recheck may advance to recovery.
    if incident_id == active.id and active.decision == "confirm":
        active.status, active.next_check_at = "BLOCK_CONFIRMED", None
        recovery = recovery_plan(
            db, agent_id, "incident", "incident:" + active.id, active.id
        )
        if recovery.status == "MANUAL_REQUIRED":
            active.status = "MANUAL_REQUIRED"
    elif incident_id == active.id and active.rechecks >= 3:
        prior = db.scalars(
            select(ControlTask)
            .where(ControlTask.agent_id == agent_id, ControlTask.status == "succeeded")
            .order_by(ControlTask.created_at, ControlTask.id)
        ).all()
        previous_rechecks = [
            t for t in prior if t.payload.get("incident_id") == active.id
        ]
        if (
            len(previous_rechecks) >= 2
            and independent_failure(evidence)
            and all(
                t.result.get("status") == "suspected" and independent_failure(t.result)
                for t in previous_rechecks[-2:]
            )
        ):
            active.status = "BLOCK_CONFIRMED"
            recovery = recovery_plan(
                db, agent_id, "scheduler", "incident:" + active.id, active.id
            )
            if recovery.status != "MANUAL_REQUIRED":
                return
        active.status, active.next_check_at = "MANUAL_REQUIRED", None
        db.add(
            Notification(
                topic="incident_attention",
                target=active.id,
                text=f"{agent.name}: отложенные проверки завершены. Для автоматического восстановления не хватает подтверждённых условий; нужна ручная проверка.",
            )
        )


def schedule(db):
    now = utcnow()
    record_agent_health(db)
    for incident in db.scalars(
        select(Incident).where(
            Incident.status.in_(ACTIVE_INCIDENTS), Incident.next_check_at <= now
        )
    ).all():
        agent = require_agent(db, incident.agent_id, lock=True)
        db.refresh(incident)
        if (
            incident.status not in ACTIVE_INCIDENTS
            or agent.paused
            or incident.next_check_at is None
            or aware(incident.next_check_at) > now
        ):
            continue
        key = f"incident:{incident.id}:{incident.rechecks}"
        task = request_check(db, agent.id, "scheduler", incident.id, key)
        # Do not count an unrelated running check as a scheduled recheck.
        if task.dedup_key != key:
            continue
        incident.rechecks += 1
        offsets = [15, 20, 25]
        incident.next_check_at = (
            aware(incident.created_at) + timedelta(minutes=offsets[incident.rechecks])
            if incident.rechecks < 3
            else None
        )
    from .policy import get_policy

    policy = get_policy(db)
    if not policy.monitor_enabled:
        return
    for agent in db.scalars(select(Agent).where(Agent.paused.is_(False))).all():
        last = db.scalar(
            select(Check)
            .where(Check.agent_id == agent.id, ~Check.result.startswith("sni_"))
            .order_by(Check.created_at.desc())
            .limit(1)
        )
        if agent.public_host and (
            not last
            or now - aware(last.created_at)
            >= timedelta(seconds=policy.monitor_interval_seconds)
        ):
            request_check(db, agent.id, "scheduler")


def cost_report(db):
    resources = db.scalars(select(FloatingIP)).all()
    known = sum(r.cost_cents or 0 for r in resources)
    unknown = sum(1 for r in resources if r.cost_cents is None)
    return {
        "recorded_cents": known,
        "unknown_cost_resources": unknown,
        "active_managed": sum(1 for r in resources if r.managed and not r.released_at),
        "billing_verified": False,
        "note": "Учёт AutoIP; не является подтверждённым счётом Cherry Servers",
    }


def record_agent_health(db):
    for agent in db.scalars(
        select(Agent).where(Agent.revoked.is_(False)).order_by(Agent.id)
    ):
        current = {
            "online": online(agent),
            "telemt": agent.facts.get("telemt_service", "unknown"),
        }
        key = "health:" + agent.id
        stored = db.get(SystemSetting, key)
        previous = stored.value if stored else {}
        if current != previous:
            if not current["online"] and previous.get("online") is not False:
                db.add(
                    Notification(
                        topic="agent_offline",
                        target=agent.id,
                        text=f"{agent.name}: нет heartbeat более 90 секунд. Автоматическое восстановление IP не запускается по потере связи с Agent.",
                    )
                )
            elif current["online"] and previous.get("online") is False:
                db.add(
                    Notification(
                        topic="agent_online",
                        target=agent.id,
                        text=f"{agent.name}: связь с Agent восстановлена.",
                    )
                )
            if (
                current["online"]
                and current["telemt"] in ("failed", "inactive")
                and previous.get("telemt") != current["telemt"]
            ):
                db.add(
                    Notification(
                        topic="telemt_error",
                        target=agent.id,
                        text=f"{agent.name}: Telemt сообщает состояние {current['telemt']}. Нужна проверка сервиса; это не доказательство блокировки IP.",
                    )
                )
            if stored:
                stored.value = current
            else:
                db.add(SystemSetting(key=key, value=current))


def record_monitor_health(db, agent, evidence):
    failed = any(report.get("error") for report in evidence.get("reports", []))
    key = "monitorhealth:" + agent.id
    stored = db.get(SystemSetting, key)
    previous = stored.value.get("failed", False) if stored else False
    if failed != previous:
        message = (
            f"{agent.name}: источник мониторинга недоступен или вернул неполные данные. Блокировка не подтверждается."
            if failed
            else f"{agent.name}: источник мониторинга снова отвечает."
        )
        db.add(Notification(topic="monitor_status", target=agent.id, text=message))
    if stored:
        stored.value = {"failed": failed}
    else:
        db.add(SystemSetting(key=key, value={"failed": failed}))


def record_protocol_health(db, agent, evidence, result):
    if result not in ("proxy_degraded", "reachable"):
        return
    key = "proxyhealth:" + agent.id
    stored = db.get(SystemSetting, key)
    previous = stored.value.get("degraded", False) if stored else False
    degraded = result == "proxy_degraded"
    if degraded != previous:
        state = evidence.get("mtproto_status", "UNKNOWN")
        text = (
            f"{agent.name}: MTProto недоступен или деградировал ({state}). Это не подтверждение блокировки в РФ; проверьте Telemt и связь с Telegram DC."
            if degraded
            else f"{agent.name}: доступность восстановилась после деградации MTProto."
        )
        db.add(Notification(topic="proxy_health", target=agent.id, text=text))
    if stored:
        stored.value = {"degraded": degraded}
    else:
        db.add(SystemSetting(key=key, value={"degraded": degraded}))


def request_sni_check(db, agent_id, integration_id, actor):
    from .monitor import PUBLIC_HOST

    agent = require_agent(db, agent_id, lock=True)
    if agent.revoked:
        raise HTTPException(409, "Агент отозван")
    integration = db.get(Integration, integration_id)
    host = (
        (agent.configuration or {}).get("sni_domain")
        or agent.facts.get("tls_domain")
        or ""
    )
    if (
        not integration
        or integration.kind != "ripe_atlas"
        or not PUBLIC_HOST.fullmatch(host)
        or not proxy_address(agent)
    ):
        raise HTTPException(
            422, "Укажите RIPE Atlas интеграцию, SNI-домен и IPv4 прокси"
        )
    existing = db.scalar(
        select(ControlTask).where(
            ControlTask.agent_id == agent_id,
            ControlTask.kind == "sni",
            ControlTask.status.in_(["queued", "running", "submission_uncertain"]),
        )
    )
    if existing:
        return existing
    task = ControlTask(
        agent_id=agent_id,
        kind="sni",
        dedup_key="sni:" + str(uuid4()),
        payload={
            "integration_id": integration.id,
            "host": host,
            "target_ip": proxy_address(agent),
            "port": agent.proxy_port,
        },
    )
    db.add(task)
    db.flush()
    audit(db, actor, "sni_check_credits_approved", task.id)
    return task
