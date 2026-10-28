"""Separate durable worker. Provider outages never advance recovery."""

import asyncio
import logging
from datetime import timedelta

from sqlalchemy import or_, select

from .database import Agent, ControlTask, SessionLocal, utcnow
from .monitor import collect, verdict
from .services import online, record_evidence, schedule

log = logging.getLogger(__name__)


async def tick():
    with SessionLocal() as db:
        schedule(db)
        db.commit()
        task = db.scalar(
            select(ControlTask)
            .where(
                or_(
                    ControlTask.status == "queued",
                    (ControlTask.status == "running")
                    & (ControlTask.leased_at < utcnow() - timedelta(minutes=5)),
                )
            )
            .order_by(ControlTask.created_at)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if not task:
            return False
        if task.attempts >= 4:
            task.status, task.result = (
                "failed",
                {"error": "Превышен лимит повторов проверки"},
            )
            db.commit()
            return True
        task.status, task.attempts, task.leased_at = (
            "running",
            task.attempts + 1,
            utcnow(),
        )
        agent = db.get(Agent, task.agent_id)
        task_id, agent_id, host, port = (
            task.id,
            agent.id,
            agent.public_host,
            agent.proxy_port,
        )
        observed_ip = (agent.configuration or {}).get("floating_ip", "")
        kind = task.kind
        db.commit()
    try:
        if kind == "sni":
            from .atlas import execute_task

            await execute_task(task_id)
            return True
        evidence = await collect(host or "", port, observed_ip)
        with SessionLocal() as db:
            task = db.scalar(
                select(ControlTask).where(ControlTask.id == task_id).with_for_update()
            )
            agent = db.get(Agent, agent_id)
            if observed_ip != (agent.configuration or {}).get("floating_ip", ""):
                task.status, task.result = (
                    "failed",
                    {"error": "IP изменился во время проверки"},
                )
            else:
                result = verdict(
                    evidence,
                    agent.facts.get("telemt_service") == "active",
                    online(agent),
                )
                record_evidence(
                    db, agent_id, evidence, result, task.payload.get("incident_id")
                )
                task.status, task.result = "succeeded", {"status": result, **evidence}
            db.commit()
    except Exception:
        log.error(
            "Check task failed; task_id=%s", task_id
        )  # no raw exception/secret URLs
        with SessionLocal() as db:
            task = db.get(ControlTask, task_id)
            task.status, task.result = "failed", {"error": "Ошибка обработки проверки"}
            db.commit()
    return True


async def run():
    while True:
        try:
            busy = await tick()
        except Exception:
            log.error("Worker iteration failed")
            busy = False
        await asyncio.sleep(1 if busy else 5)


if __name__ == "__main__":
    asyncio.run(run())
