"""Explicitly approved, single-IP Cherry pilot. No scheduler, DNS or deletion.

A durable reservation precedes the one non-idempotent POST. Re-running an
operation cannot place another order, including after a lost provider response.
"""

import asyncio
import ipaddress
import re
from uuid import UUID

import httpx
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from .database import (
    Agent,
    FloatingIP,
    Incident,
    Integration,
    SessionLocal,
    SystemSetting,
    utcnow,
)
from .security import audit
from .vault import decrypt


class PilotError(RuntimeError):
    def __init__(self, message, provider_status=None, retry_after=None):
        self.provider_status = provider_status
        self.retry_after = retry_after
        super().__init__(message)


class CherryPilotAPI:
    def __init__(self, api_key):
        self.api_key = api_key

    async def request(self, method, path, payload=None):
        permitted = (
            method == "GET"
            and re.fullmatch(
                r"/(?:servers/\d+|projects/\d+/ips|ips/[a-f0-9-]{36})", path
            )
            or method == "POST"
            and re.fullmatch(r"/projects/\d+/ips", path)
            or method in ("PUT", "DELETE")
            and re.fullmatch(r"/ips/[a-f0-9-]{36}", path)
        )
        if not permitted:
            raise PilotError("Недопустимая операция Cherry pilot")
        await asyncio.sleep(0.3)
        try:
            async with httpx.AsyncClient(
                base_url="https://api.cherryservers.com/v1",
                timeout=30,
                follow_redirects=False,
                headers={"Authorization": "Bearer " + self.api_key},
            ) as client:
                params = (
                    [("status", "available"), ("status", "assigned"), ("limit", "100")]
                    if method == "GET" and path.endswith("/ips")
                    else None
                )
                response = await client.request(
                    method, path, json=payload, params=params
                )
                response.raise_for_status()
                return (
                    None
                    if response.status_code == 204
                    or (method in ("PUT", "DELETE") and not response.content)
                    else response.json()
                )
        except httpx.HTTPStatusError as error:
            status = error.response.status_code
            raise PilotError(
                f"Cherry API: HTTP {status}; запрос не повторён",
                provider_status=status,
                retry_after=(
                    min(86400, max(1, int(error.response.headers["Retry-After"])))
                    if error.response.headers.get("Retry-After", "").isdigit()
                    else None
                ),
            ) from None
        except (httpx.HTTPError, ValueError):
            # Never propagate provider bodies, request headers or server passwords.
            raise PilotError(
                "Cherry не подтвердил операцию; требуется сверка состояния, повторный заказ запрещён"
            ) from None


def operation_key(operation_id):
    return "fip-pilot:" + str(UUID(operation_id))


def relation_id(value):
    return str(value.get("id", "")) if isinstance(value, dict) else str(value or "")


def known_blocked(db, address):
    return bool(
        db.scalar(
            select(FloatingIP.id)
            .where(
                FloatingIP.ipv4 == address,
                FloatingIP.status.in_(
                    ["blocked", "blocked_ru", "rejected_blocked", "rejected_history"]
                ),
            )
            .limit(1)
        )
        or db.scalar(
            select(Incident.id)
            .where(
                Incident.observed_ip == address,
                (Incident.status == "BLOCK_CONFIRMED")
                | (Incident.decision.in_(["confirm", "auto_confirm"])),
            )
            .limit(1)
        )
    )


def resource_summary(raw):
    if not isinstance(raw, dict) or raw.get("type") != "floating-ip":
        raise PilotError("Ответ не является Floating IP")
    try:
        resource_id = str(UUID(raw["id"]))
        address = ipaddress.IPv4Address(raw["address"])
    except (ValueError, KeyError, TypeError):
        raise PilotError("Неверный ответ Floating IP") from None
    if not address.is_global:
        raise PilotError("Floating IP не является публичным IPv4")
    return {"resource_id": resource_id, "ipv4": str(address)}


def save_state(key, status, **values):
    with SessionLocal() as db:
        row = db.get(SystemSetting, key)
        row.value = {
            **row.value,
            **values,
            "status": status,
            "updated_at": utcnow().isoformat(),
        }
        audit(
            db,
            "local-admin",
            "floating_pilot_" + status.lower(),
            row.value["agent_id"],
            operation_id=row.value["operation_id"],
        )
        db.commit()
        return dict(row.value)


def context(db, agent_id):
    agent = db.get(Agent, agent_id)
    if not agent or agent.revoked:
        raise PilotError("Агент отсутствует или отозван")
    cfg = agent.configuration or {}
    if cfg.get("provider", "cherry") != "cherry":
        raise PilotError("Cherry операции разрешены только агентам Cherry")
    account = db.get(Integration, cfg.get("cherry_integration_id", ""))
    if not account or account.kind != "cherry" or account.status != "verified":
        raise PilotError("Нужна проверенная Cherry интеграция")
    project, server = cfg.get("cherry_project_id", ""), cfg.get("cherry_server_id", "")
    if (
        not str(project).isdigit()
        or not str(server).isdigit()
        or not cfg.get("region")
        or not cfg.get("management_ip")
    ):
        raise PilotError("Не заполнены проект, сервер, регион или Management IP")
    return agent, account, cfg, CherryPilotAPI(decrypt(account)["api_key"])


def record_allocation(key):
    """Finish a saved POST atomically, retaining history if Cherry reuses its UUID."""
    with SessionLocal() as db:
        operation = db.scalar(
            select(SystemSetting).where(SystemSetting.key == key).with_for_update()
        )
        state = dict(operation.value)
        if state["status"] != "ALLOCATED_UNCHECKED":
            return state
        blocked = known_blocked(db, state["ipv4"])
        seen = (
            db.scalar(
                select(FloatingIP.id).where(FloatingIP.ipv4 == state["ipv4"]).limit(1)
            )
            is not None
        )
        owned = db.scalar(
            select(FloatingIP)
            .where(FloatingIP.resource_id == state["resource_id"])
            .with_for_update()
        )
        if owned:
            if (
                owned.agent_id != state["agent_id"]
                or owned.integration_id != state["integration_id"]
                or owned.ipv4 != state["ipv4"]
                or not owned.managed
                or (
                    not owned.released_at
                    and owned.status not in ("candidate", "rejected_history")
                )
            ):
                raise PilotError("Повторный ресурс не принадлежит этой операции")
            audit(
                db,
                "commander",
                "floating_resource_reissued",
                owned.resource_id,
                previous_status=owned.status,
                previous_released_at=owned.released_at.isoformat()
                if owned.released_at
                else None,
                operation_id=state["operation_id"],
            )
            owned.released_at = None
        else:
            owned = FloatingIP(
                agent_id=state["agent_id"],
                integration_id=state["integration_id"],
                resource_id=state["resource_id"],
                ipv4=state["ipv4"],
                managed=True,
            )
            db.add(owned)
        owned.status = "rejected_history" if blocked else "candidate"
        operation.value = {
            **state,
            "status": "REJECTED_HISTORY" if blocked else "ALLOCATED",
            "seen_before": seen,
            "known_blocked": blocked,
            "updated_at": utcnow().isoformat(),
        }
        audit(
            db,
            "commander",
            "floating_allocation_recorded",
            state["agent_id"],
            operation_id=state["operation_id"],
            known_blocked=blocked,
        )
        db.commit()
        return dict(operation.value)


async def purchase_one(agent_id, operation_id, *, approved=False):
    if not approved:
        raise PilotError("Нужно отдельное подтверждение покупки одного Floating IP")
    key = operation_key(operation_id)
    with SessionLocal() as db:
        previous = db.get(SystemSetting, key)
        if previous:
            if previous.value.get("agent_id") != agent_id:
                raise PilotError("Операция принадлежит другому агенту")
            saved = dict(previous.value)
            if saved.get("status") != "ALLOCATED_UNCHECKED":
                return saved
        else:
            saved = None
        agent, account, cfg, api = context(db, agent_id)
        project, region = str(cfg["cherry_project_id"]), cfg["region"]
        integration_id = account.id
    if saved:
        if (
            saved.get("integration_id") != integration_id
            or saved.get("project_id") != project
            or saved.get("region") != region
        ):
            raise PilotError("Конфигурация незавершённого заказа изменилась")
        resources = await api.request("GET", f"/projects/{project}/ips")
        matches = (
            [r for r in resources if str(r.get("id")) == saved["resource_id"]]
            if isinstance(resources, list)
            else []
        )
        if (
            len(matches) != 1
            or resource_summary(matches[0])["ipv4"] != saved["ipv4"]
            or relation_id(
                matches[0].get("targeted_to") or matches[0].get("assigned_to")
            )
        ):
            raise PilotError(
                "Незавершённый кандидат не подтверждён как свободный ресурс проекта"
            )
        return record_allocation(key)
    before = await api.request("GET", f"/projects/{project}/ips")
    if not isinstance(before, list):
        raise PilotError("Не удалось получить исходный список ресурсов")
    initial_ids = {str(item.get("id")) for item in before if isinstance(item, dict)}
    reservation = {
        "agent_id": agent_id,
        "operation_id": str(UUID(operation_id)),
        "project_id": project,
        "region": region,
        "integration_id": integration_id,
        "status": "SUBMITTING",
        "created_at": utcnow().isoformat(),
        "initial_resource_ids": sorted(initial_ids),
    }
    with SessionLocal() as db:
        db.add(SystemSetting(key=key, value=reservation))
        audit(
            db,
            "local-admin",
            "floating_pilot_purchase_approved",
            agent_id,
            operation_id=operation_id,
            quantity=1,
        )
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return dict(db.get(SystemSetting, key).value)
    try:
        # Deliberately omit routed_to/assigned_to: check history BEFORE Attach.
        raw = await api.request(
            "POST",
            f"/projects/{project}/ips",
            {"region": region},
        )
        summary = resource_summary(raw)
        if summary["resource_id"] in initial_ids:
            raise PilotError("Cherry вернул ранее существовавший ресурс")
        save_state(key, "ALLOCATED_UNCHECKED", **summary)
    except PilotError as error:
        declined = (
            error.provider_status is not None and 400 <= error.provider_status < 500
        )
        save_state(
            key,
            "ORDER_REJECTED" if declined else "SUBMISSION_UNCERTAIN",
            provider_status=error.provider_status,
        )
        raise
    return record_allocation(key)


async def attach_one(operation_id, *, approved=False):
    if not approved:
        raise PilotError("Нужно подтверждение Attach для пилота")
    key = operation_key(operation_id)
    with SessionLocal() as db:
        row = db.get(SystemSetting, key)
        if not row or row.value.get("status") not in (
            "ALLOCATED",
            "ATTACH_PENDING",
            "ATTACHED",
        ):
            raise PilotError(
                "Кандидат не готов к Attach; проверьте историю и состояние покупки"
            )
        state = dict(row.value)
        agent, account, cfg, api = context(db, state["agent_id"])
        owned = db.scalar(
            select(FloatingIP).where(FloatingIP.resource_id == state["resource_id"])
        )
        if (
            not owned
            or not owned.managed
            or owned.released_at
            or owned.agent_id != agent.id
            or owned.integration_id != account.id
            or known_blocked(db, owned.ipv4)
            or owned.ipv4 == cfg["management_ip"]
        ):
            raise PilotError("Attach запрещён: владение, история или Management IP")
        project, server, management = (
            str(cfg["cherry_project_id"]),
            str(cfg["cherry_server_id"]),
            cfg["management_ip"],
        )
        if project != state["project_id"] or cfg["region"] != state["region"]:
            raise PilotError("Конфигурация проекта изменилась")
    server_info = await api.request("GET", "/servers/" + server)
    if (
        relation_id(server_info.get("project")) != project
        or (server_info.get("region") or {}).get("slug") != state["region"]
    ):
        raise PilotError("Сервер не принадлежит согласованному проекту/региону")
    addresses = await api.request("GET", f"/projects/{project}/ips")
    primary = [
        ip
        for ip in addresses
        if ip.get("type") == "primary-ip" and ip.get("address") == management
    ]
    candidates = [ip for ip in addresses if str(ip.get("id")) == state["resource_id"]]
    if (
        len(primary) != 1
        or len(candidates) != 1
        or resource_summary(candidates[0])["ipv4"] != state["ipv4"]
    ):
        raise PilotError("Не подтверждены основной IP или кандидат в проекте")
    if (
        relation_id(primary[0].get("assigned_to") or primary[0].get("targeted_to"))
        != server
    ):
        raise PilotError("Management IP принадлежит другому серверу")
    candidate = candidates[0]
    target = relation_id(candidate.get("targeted_to") or candidate.get("assigned_to"))
    if target and target != server:
        raise PilotError("Floating IP уже привязан к другому серверу")
    # Recheck immediately before mutation; released history is retained.
    with SessionLocal() as db:
        if known_blocked(db, state["ipv4"]):
            raise PilotError("Attach запрещён: адрес появился в истории блокировок")
    save_state(key, "ATTACH_PENDING", server_id=server, management_ip=management)
    try:
        if target != server:
            await api.request(
                "PUT",
                "/ips/" + state["resource_id"],
                {"routed_to": str(primary[0]["id"])},
            )
        verified = await api.request("GET", "/ips/" + state["resource_id"])
        if (
            resource_summary(verified)["ipv4"] != state["ipv4"]
            or relation_id(verified.get("targeted_to") or verified.get("assigned_to"))
            != server
        ):
            raise PilotError("Cherry ещё не подтвердил Attach нужному серверу")
    except PilotError:
        # A retry may READ and reconcile the same resource; it never buys again.
        raise
    with SessionLocal() as db:
        owned = db.scalar(
            select(FloatingIP).where(FloatingIP.resource_id == state["resource_id"])
        )
        owned.status = "attached_pilot"
        db.commit()
    return save_state(key, "ATTACHED", dns_changed=False, linux_configured=False)
