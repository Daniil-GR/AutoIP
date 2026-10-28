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
from .schemas import AgentConfiguration
from .security import audit, aware, display_time

ACTIVE_INCIDENTS = ("WAITING_CONFIRMATION", "RECHECKING", "BLOCK_CONFIRMED")


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
    c = AgentConfiguration(**(agent.configuration or {}))
    requirements = {
        "agent_online": online(agent),
        "public_host": bool(agent.public_host),
        "telemt_active": agent.facts.get("telemt_service") == "active",
        "management_ip": bool(c.management_ip),
        "floating_ip": bool(c.floating_ip),
        "separate_management_ip": bool(
            c.management_ip and c.floating_ip and c.management_ip != c.floating_ip
        ),
        "cherry_project": bool(c.cherry_project_id),
        "cherry_server": bool(c.cherry_server_id),
        "dns_zone": bool(c.dns_zone and c.dns_record),
        "budget": c.monthly_budget_cents > 0,
    }
    for kind, identifier in [
        ("cherry", c.cherry_integration_id),
        ("dynadot", c.dns_integration_id),
    ]:
        integration = db.get(Integration, identifier) if identifier else None
        requirements[kind] = bool(
            integration
            and integration.kind == kind
            and integration.status == "verified"
        )
    return {
        "checks": requirements,
        "monitoring_ready": all(
            requirements[k] for k in ("agent_online", "public_host", "telemt_active")
        ),
        "recovery_ready": False,
        "live_blockers": [
            "Сетевой адаптер требует согласованного пилота",
            "Безопасность DNS-изменения не подтверждена",
            "Нет второго независимого источника мониторинга",
        ],
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
            "reason": "Реальные изменения требуют проверенных адаптеров и отдельного согласования",
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
    audit(db, actor, "recovery_preflight", recovery.id, agent_id=agent_id)
    db.add(
        Notification(
            topic="recovery",
            target=recovery.id,
            text=f"{agent.name}: предварительная проверка восстановления завершена. Нужна ручная настройка. Платные операции не выполнялись.",
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
    active = db.scalar(
        select(Incident)
        .where(Incident.agent_id == agent_id, Incident.status.in_(ACTIVE_INCIDENTS))
        .with_for_update()
    )
    current_ip = (agent.configuration or {}).get("floating_ip", "")
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
                text=f"Вероятная недоступность: {agent.name}\n{agent.public_host}:{agent.proxy_port}\nIP: {current_ip or 'не настроен'}\nНачало: {display_time(utcnow())}\nОтказы TCP из нескольких RU ASN при доступности из других стран. Требуется проверка; блокировка не доказана.",
            )
        )
    else:
        active.evidence = evidence
    # Only a dedicated final recheck may advance to recovery.
    if incident_id == active.id and active.decision == "confirm":
        active.status, active.next_check_at = "BLOCK_CONFIRMED", None
        recovery_plan(db, agent_id, "incident", "incident:" + active.id, active.id)
        active.status = "MANUAL_REQUIRED"
    elif incident_id == active.id and active.rechecks >= 3:
        prior = db.scalars(
            select(ControlTask).where(
                ControlTask.agent_id == agent_id, ControlTask.status == "succeeded"
            )
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
            recovery_plan(db, agent_id, "scheduler", "incident:" + active.id, active.id)
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
            .where(Check.agent_id == agent.id)
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
