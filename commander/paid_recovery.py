"""Opt-in durable acquisition and cleanup around the tested DNS recovery engine."""

from datetime import datetime, timedelta
from uuid import uuid4, uuid5, NAMESPACE_URL

from sqlalchemy import select
from .database import (
    Agent,
    FloatingIP,
    Incident,
    Job,
    Notification,
    Recovery,
    SessionLocal,
    SystemSetting,
    utcnow,
)
from .security import audit, aware
from .diagnostics import record_failure
from .floating_pilot import (
    purchase_one,
    attach_one,
    context,
    PilotError,
    resource_summary,
)
from . import reserve_recovery as rr


def policy_key(agent_id):
    return "paid-auto:" + agent_id


def state_key(identifier):
    return "paid-recovery:" + identifier


def enabled(db, agent_id):
    row = db.get(SystemSetting, policy_key(agent_id))
    return bool(row and row.value.get("enabled") is True)


def protocol_block(evidence, *, fresh=True):
    for r in evidence.get("reports", []):
        if (
            r.get("source") != "mtproto-checker"
            or r.get("status") != "observed"
            or r.get("target") != evidence.get("ip")
            or r.get("provider_status") not in ("RKN_BLOCK", "DATA_CUT")
        ):
            continue
        try:
            checked = datetime.fromisoformat(r["checked_at"].replace("Z", "+00:00"))
            if checked.tzinfo is None or (
                fresh and not -60 <= (utcnow() - checked).total_seconds() <= 300
            ):
                continue
        except (ValueError, KeyError, TypeError, AttributeError):
            continue
        p = r.get("points", {})
        local = p.get("local", {})
        remote = p.get("remote", {})
        if not all(remote.get(k) is True for k in ("tcp", "handshake", "data")):
            continue
        return (
            (local.get("tcp") is False or local.get("handshake") is False)
            if r["provider_status"] == "RKN_BLOCK"
            else (
                local.get("tcp") is True
                and local.get("handshake") is True
                and local.get("data") is False
            )
        )
    return False


def authorization(incident, evidence=None):
    data = evidence if evidence is not None else incident.evidence
    if not protocol_block(data):
        return False
    if incident.decision == "confirm":
        return True
    from .monitor import independent_failure

    return independent_failure(data) or (
        incident.decision == "auto_confirm" and incident.rechecks >= 3
    )


def queue_if_ready(db, recovery, incident):
    from .services import online, proxy_address

    a = db.get(Agent, recovery.agent_id)
    if (
        not enabled(db, a.id)
        or not incident
        or incident.status != "BLOCK_CONFIRMED"
        or incident.observed_ip != proxy_address(a)
        or not authorization(incident)
    ):
        return False
    if (
        a.paused
        or a.revoked
        or not online(a)
        or a.facts.get("telemt_service") != "active"
    ):
        return False
    context(db, a.id)
    if db.scalar(
        select(Recovery.id).where(
            Recovery.agent_id == a.id,
            Recovery.id != recovery.id,
            Recovery.status.in_(rr.ACTIVE),
        )
    ):
        return False
    cfg = a.configuration
    state = {
        "stage": "FINAL_CHECK",
        "agent_id": a.id,
        "incident_id": incident.id,
        "old": proxy_address(a),
        "host": cfg["dns_record"],
        "port": a.proxy_port,
        "management": cfg["management_ip"],
        "project": str(cfg["cherry_project_id"]),
        "server": str(cfg["cherry_server_id"]),
        "integration_id": cfg["cherry_integration_id"],
        "dns_integration_id": cfg["dns_integration_id"],
        "region": cfg["region"],
        "created_at": utcnow().isoformat(),
        "candidates": [],
    }
    db.add(SystemSetting(key=state_key(recovery.id), value=state))
    recovery.status = "PAID_RUNNING"
    recovery.stages = [{"stage": "FINAL_CHECK", "status": "queued"}]
    incident.status, incident.next_check_at = "RECOVERING", None
    db.add(
        Notification(
            topic="recovery",
            target=recovery.id,
            text=f"{a.name}: подтверждена недоступность из РФ. Начинается автоматическое получение и проверка Floating IP.",
        )
    )
    audit(db, "commander", "paid_recovery_queued", recovery.id, agent_id=a.id)
    return True


def load(identifier):
    with SessionLocal() as db:
        return dict(db.get(SystemSetting, state_key(identifier)).value)


def save(identifier, stage, **values):
    with SessionLocal() as db:
        row = db.get(SystemSetting, state_key(identifier))
        r = db.get(Recovery, identifier)
        row.value = {
            **row.value,
            **values,
            "stage": stage,
            "failures": values.get("failures", 0),
            "updated_at": utcnow().isoformat(),
        }
        if not r.stages or r.stages[-1]["stage"] != stage:
            r.stages = [
                *r.stages,
                {"stage": stage, "status": "checked" if stage == "DONE" else "running"},
            ]
            if stage == "DONE":
                db.add(
                    Notification(
                        topic="recovery",
                        target=identifier,
                        text="Очистка старых управляемых адресов завершена.",
                    )
                )
            audit(
                db,
                "worker",
                "paid_recovery_" + stage.lower(),
                identifier,
                agent_id=r.agent_id,
            )
        db.commit()


def stop(identifier, reason):
    with SessionLocal() as db:
        r = db.get(Recovery, identifier)
        dns_result = db.get(SystemSetting, rr.state_key(identifier))
        recovered = bool(dns_result and dns_result.value.get("stage") == "SUCCEEDED")
        r.status = "SUCCEEDED" if recovered else "MANUAL_REQUIRED"
        row = db.get(SystemSetting, state_key(identifier))
        row.value = {**row.value, "stage": "MANUAL_REQUIRED", "reason": reason}
        p = db.get(SystemSetting, policy_key(r.agent_id))
        if p:
            p.value = {**p.value, "enabled": False, "stopped_by": identifier}
        i = db.get(Incident, r.incident_id)
        i.status = "RECOVERED" if recovered else "MANUAL_REQUIRED"
        i.next_check_at = None
        if recovered:
            r.stages = [
                *r.stages,
                {"stage": "CLEANUP", "status": "failed", "reason": reason},
            ]
        db.add(
            Notification(
                topic="recovery",
                target=r.id,
                text=(
                    "Прокси восстановлен, требуется завершить очистку: "
                    if recovered
                    else "Восстановление остановлено: "
                )
                + reason
                + ". Ресурсы сохранены для сверки.",
            )
        )
        db.commit()


def require_context(db, s, *, cleanup=False):
    from .services import online, proxy_address

    a = db.get(Agent, s["agent_id"])
    cfg = a.configuration
    if (
        not enabled(db, a.id)
        or a.paused
        or a.revoked
        or not online(a)
        or cfg.get("management_ip") != s["management"]
        or str(cfg.get("cherry_project_id")) != s["project"]
        or str(cfg.get("cherry_server_id")) != s["server"]
        or cfg.get("cherry_integration_id") != s["integration_id"]
        or cfg.get("dns_integration_id") != s["dns_integration_id"]
        or cfg.get("dns_record") != s["host"]
        or cfg.get("region") != s["region"]
        or a.proxy_port != s["port"]
        or (not cleanup and proxy_address(a) != s["old"])
    ):
        raise PilotError("Разрешение, связь или параметры операции изменились")
    return a


def network_job(identifier, s, action, resource="", address=""):
    job_id = str(
        uuid5(
            NAMESPACE_URL,
            identifier
            + ":"
            + action
            + ":"
            + resource
            + ":"
            + str(s.get("network_retry", 0))
            + (
                ":" + str(int(utcnow().timestamp()) // 300)
                if action == "inspect"
                else ""
            ),
        )
    )
    with SessionLocal() as db:
        require_context(db, s, cleanup=action == "remove")
        job = db.get(Job, job_id)
        if not job:
            db.add(
                Job(
                    id=job_id,
                    agent_id=s["agent_id"],
                    kind="floating_network",
                    payload={
                        "action": action,
                        **({"resource_id": resource} if resource else {}),
                        **({"address": address} if address else {}),
                    },
                )
            )
            db.commit()
            return False
        if job.status == "failed":
            raise PilotError("Agent отклонил сетевое задание; требуется сверка")
        if job.status == "succeeded":
            return True
        if utcnow() - aware(job.created_at) > timedelta(minutes=5):
            raise PilotError("Agent не подтвердил сетевое задание вовремя")
        return False


def next_at(seconds):
    return (utcnow() + timedelta(seconds=seconds)).isoformat()


def project_order_delay(db, s):
    times = []
    for row in db.scalars(
        select(SystemSetting).where(SystemSetting.key.like("fip-pilot:%"))
    ):
        p = row.value
        if (
            p.get("integration_id") == s["integration_id"]
            and p.get("project_id") == s["project"]
            and p.get("status") != "ORDER_REJECTED"
        ):
            t = aware(datetime.fromisoformat(p["created_at"]))
            if utcnow() - t < timedelta(hours=24):
                times.append(t)
    return (
        max(0, (min(times) + timedelta(hours=24) - utcnow()).total_seconds()) + 30
        if len(times) >= 24
        else 0
    )


async def resource_absent(api, project, resource_id):
    inventory = await api.request("GET", "/projects/" + project + "/ips")
    if not isinstance(inventory, list) or len(inventory) >= 100:
        raise PilotError("Нельзя доказать отсутствие ресурса: неполный список проекта")
    return not any(str(x.get("id")) == resource_id for x in inventory)


async def detach_rejected(identifier, s):
    """Free attachment slots while retaining paid candidates and their history."""
    from .floating_pilot import relation_id
    from .services import proxy_address
    from .dns_pilot import snapshot
    from .dns_scope import MANAGED_DNS_ZONE

    with SessionLocal() as db:
        agent = require_context(db, s)
        _, _, _, api = context(db, agent.id)
        rejected = [
            (row.resource_id, row.ipv4)
            for row in db.scalars(
                select(FloatingIP).where(
                    FloatingIP.agent_id == agent.id,
                    FloatingIP.integration_id == s["integration_id"],
                    FloatingIP.managed.is_(True),
                    FloatingIP.released_at.is_(None),
                    FloatingIP.status.in_(("rejected_history", "rejected_blocked")),
                )
            )
            if row.resource_id in s.get("candidates", [])
        ]
        protected = {s["management"], proxy_address(agent), s.get("new")}
    if not rejected:
        return True
    zone = snapshot(await rr.dns_client(s).records(MANAGED_DNS_ZONE))
    dns_addresses = {
        str(value)
        for key in ("dns_main_list", "dns_sub_list")
        for record in zone.get(key, [])
        for value in record.values()
    }
    inventory = await api.request("GET", "/projects/" + s["project"] + "/ips")
    if not isinstance(inventory, list) or len(inventory) >= 100:
        raise PilotError("Неполный список проекта; Detach запрещён")
    for rid, address in rejected:
        if address in protected or address in dns_addresses:
            raise PilotError("Detach запрещён: адрес активен или используется DNS")
        matches = [item for item in inventory if str(item.get("id")) == rid]
        if len(matches) != 1 or resource_summary(matches[0])["ipv4"] != address:
            raise PilotError("Не подтверждено владение кандидатом для Detach")
        raw = matches[0]
        server = relation_id(raw.get("targeted_to") or raw.get("assigned_to"))
        routed = raw.get("routed_to")
        if server and server != s["server"]:
            raise PilotError("Detach запрещён: кандидат назначен другому серверу")
        if relation_id(routed) and (
            not isinstance(routed, dict)
            or routed.get("address") != s["management"]
            or routed.get("type") != "primary-ip"
        ):
            raise PilotError("Detach запрещён: другая сеть назначения")
        if not server and not relation_id(routed):
            continue
        if rid in s.get("configured", []) and not network_job(
            identifier, s, "remove", rid
        ):
            return False
        with SessionLocal() as db:
            require_context(db, s)
            current = db.scalar(select(FloatingIP).where(FloatingIP.resource_id == rid))
            if (
                not current
                or not current.managed
                or current.released_at
                or current.agent_id != s["agent_id"]
                or current.integration_id != s["integration_id"]
                or current.ipv4 != address
                or current.status not in ("rejected_history", "rejected_blocked")
            ):
                raise PilotError("Владение кандидатом изменилось; Detach запрещён")
        await api.request("PUT", "/ips/" + rid, {"targeted_to": "0"})
        detached = await api.request("GET", "/ips/" + rid)
        if resource_summary(detached)["ipv4"] != address:
            raise PilotError("Адрес изменился после Detach кандидата")
        if relation_id(
            detached.get("targeted_to") or detached.get("assigned_to")
        ) or relation_id(detached.get("routed_to")):
            return False
        with SessionLocal() as db:
            audit(
                db,
                "worker",
                "paid_rejected_candidate_detached",
                rid,
                agent_id=s["agent_id"],
            )
            db.commit()
        save(
            identifier,
            "ATTACH",
            detached_rejected=list(
                dict.fromkeys([*s.get("detached_rejected", []), rid])
            ),
        )
        return False
    return True


async def delete_owned(identifier, s, resource_id):
    """Delete a single recorded resource only after both DNS and ownership checks."""
    from .services import proxy_address
    from .dns_pilot import snapshot
    from .dns_scope import MANAGED_DNS_ZONE

    with SessionLocal() as db:
        a = require_context(db, s, cleanup=True)
        owned = db.scalar(
            select(FloatingIP).where(FloatingIP.resource_id == resource_id)
        )
        if (
            not owned
            or not owned.managed
            or owned.agent_id != a.id
            or owned.integration_id != s["integration_id"]
        ):
            raise PilotError("Удаление чужого ресурса запрещено")
        if owned.released_at:
            return True
        address = owned.ipv4
        if address in (s["management"], proxy_address(a)):
            raise PilotError("Удаление management/active IP запрещено")
        _, _, _, api = context(db, a.id)
        dns_state = {"dns_integration_id": s["dns_integration_id"]}
    zone = snapshot(await rr.dns_client(dns_state).records(MANAGED_DNS_ZONE))
    if any(
        address == str(v)
        for key in ("dns_sub_list", "dns_main_list")
        for record in zone.get(key, [])
        for v in record.values()
    ):
        raise PilotError("Удаляемый IP ещё используется DNS")
    try:
        raw = await api.request("GET", "/ips/" + resource_id)
    except PilotError as error:
        if error.provider_status not in (403, 404) or not await resource_absent(
            api, s["project"], resource_id
        ):
            raise
        raw = None
    if raw:
        summary = resource_summary(raw)
        if raw.get("type") != "floating-ip" or summary["ipv4"] != address:
            raise PilotError("Provider ownership mismatch")
        inventory = await api.request("GET", "/projects/" + s["project"] + "/ips")
        if not any(str(x.get("id")) == resource_id for x in inventory):
            raise PilotError("Ресурс не принадлежит проекту")
        from .floating_pilot import relation_id

        target = relation_id(raw.get("targeted_to") or raw.get("assigned_to"))
        if target and target != s["server"]:
            raise PilotError("Ресурс назначен другому серверу")
        if resource_id in s.get("configured", []) and not network_job(
            identifier, s, "remove", resource_id
        ):
            return False
        routed = raw.get("routed_to")
        if relation_id(routed):
            if (
                not isinstance(routed, dict)
                or routed.get("address") != s["management"]
                or routed.get("type") != "primary-ip"
            ):
                raise PilotError(
                    "Ресурс маршрутизирован в другую сеть; Detach запрещён"
                )
        if target or relation_id(routed):
            # Official cherrygo IPAddresses.Unassign uses targeted_to="0".
            await api.request("PUT", "/ips/" + resource_id, {"targeted_to": "0"})
            detached = await api.request("GET", "/ips/" + resource_id)
            if resource_summary(detached)["ipv4"] != address:
                raise PilotError("Адрес изменился после Detach")
            if relation_id(
                detached.get("targeted_to") or detached.get("assigned_to")
            ) or relation_id(detached.get("routed_to")):
                return False
        with SessionLocal() as db:
            require_context(db, s, cleanup=True)
            current = db.get(Agent, s["agent_id"])
            if address in (s["management"], proxy_address(current)):
                raise PilotError("Адрес стал активным перед удалением")
        latest = snapshot(await rr.dns_client(dns_state).records(MANAGED_DNS_ZONE))
        if any(
            address == str(v)
            for key in ("dns_sub_list", "dns_main_list")
            for record in latest.get(key, [])
            for v in record.values()
        ):
            raise PilotError("Адрес появился в DNS перед удалением")
        # DELETE is resource-specific and idempotently reconciled by subsequent GET.
        await api.request("DELETE", "/ips/" + resource_id)
        try:
            await api.request("GET", "/ips/" + resource_id)
            return False
        except PilotError as error:
            if error.provider_status != 404:
                raise
    if (
        not raw
        and resource_id in s.get("configured", [])
        and not network_job(identifier, s, "remove", resource_id)
    ):
        return False
    with SessionLocal() as db:
        row = db.scalar(select(FloatingIP).where(FloatingIP.resource_id == resource_id))
        row.released_at = utcnow()
        audit(
            db, "worker", "paid_resource_released", resource_id, agent_id=s["agent_id"]
        )
        db.commit()
    return True


async def step(identifier):
    from .monitoring import collect_agent

    s = load(identifier)
    stage = s["stage"]
    with SessionLocal() as db:
        r = db.get(Recovery, identifier)
        if stage == "HANDOFF":
            if r.status == "SUCCEEDED":
                # TTL grace plus final success has already verified all selected DNS.
                save(
                    identifier,
                    "CLEANUP",
                    next_at=next_at(max(600, int(s.get("ttl", 300)) * 2)),
                )
            elif r.status not in rr.ACTIVE:
                stop(
                    identifier,
                    "DNS-переход не завершился; автоматическая очистка остановлена",
                )
            return
        require_context(db, s, cleanup=stage in ("CLEANUP", "QUOTA_CLEANUP"))
    if stage == "FINAL_CHECK":
        evidence = await collect_agent(s["agent_id"], s["host"], s["port"], s["old"])
        with SessionLocal() as db:
            i = db.get(Incident, s["incident_id"])
            if evidence.get("mtproto_verified"):
                r = db.get(Recovery, identifier)
                r.status = "CANCELLED"
                i.status, i.closed_at, i.next_check_at = "RECOVERED", utcnow(), None
                row = db.get(SystemSetting, state_key(identifier))
                row.value = {
                    **row.value,
                    "stage": "DONE",
                    "reason": "Исходный прокси снова доступен; покупка отменена",
                }
                db.add(
                    Notification(
                        topic="recovery",
                        target=identifier,
                        text="Исходный прокси снова доступен; покупка отменена.",
                    )
                )
                db.commit()
                return
            if not authorization(i, evidence):
                stop(identifier, "Свежая проверка не подтверждает блокировку")
                return
        save(identifier, "NETWORK_PREFLIGHT", final_evidence=evidence)
    elif stage == "NETWORK_PREFLIGHT":
        if network_job(identifier, s, "inspect", address=s["management"]):
            save(identifier, "ORDER")
    elif stage == "ORDER":
        with SessionLocal() as db:
            delay = project_order_delay(db, s)
        if delay:
            save(identifier, "QUOTA_CLEANUP", resume_at=next_at(delay))
            return
        operation = s.get("order_id")
        if not operation:
            save(identifier, "ORDER", order_id=str(uuid4()))
            return
        try:
            result = await purchase_one(s["agent_id"], operation, approved=True)
        except PilotError as error:
            if error.provider_status == 429:
                save(
                    identifier,
                    "QUOTA_CLEANUP",
                    resume_at=next_at(error.retry_after or 3600),
                )
                return
            raise
        if result["status"] not in (
            "ALLOCATED",
            "REJECTED_HISTORY",
            "ATTACH_PENDING",
            "ATTACHED",
        ):
            stop(
                identifier,
                "Результат заказа неопределён или отклонён; повторная покупка запрещена",
            )
            return
        rid = result["resource_id"]
        candidates = list(dict.fromkeys([*s["candidates"], rid]))
        if result["status"] == "REJECTED_HISTORY":
            save(
                identifier,
                "ORDER",
                order_id=None,
                candidates=candidates,
                next_at=next_at(30),
            )
            return
        save(
            identifier,
            "ATTACH",
            resource_id=rid,
            new=result["ipv4"],
            candidates=candidates,
            candidate_failures=[],
        )
    elif stage == "ATTACH":
        if not await detach_rejected(identifier, s):
            return
        await attach_one(s["order_id"], approved=True)
        save(identifier, "NETWORK_PREPARE")
    elif stage == "NETWORK_PREPARE":
        if network_job(identifier, s, "prepare", s["resource_id"], s["new"]):
            save(
                identifier,
                "CANDIDATE_VERIFY",
                configured=list(
                    dict.fromkeys([*s.get("configured", []), s["resource_id"]])
                ),
            )
    elif stage == "CANDIDATE_VERIFY":
        report = await rr.protocol_verification(s["agent_id"], s["new"], s["port"])
        if report.get("mtproto_verified"):
            save(identifier, "NETWORK_COMMIT", candidate_proof=report)
        elif report.get("provider_status") in ("RKN_BLOCK", "DATA_CUT"):
            failures = [
                item
                for item in s.get("candidate_failures", [])
                if item.get("ipv4") == s["new"]
                and timedelta(0)
                <= utcnow() - aware(datetime.fromisoformat(item["at"]))
                < timedelta(minutes=10)
            ]
            if failures and utcnow() - aware(
                datetime.fromisoformat(failures[-1]["at"])
            ) < timedelta(minutes=1):
                save(identifier, stage, next_at=next_at(60))
                return
            failures.append(
                {"ipv4": s["new"], "at": utcnow().isoformat(), "report": report}
            )
            if len(failures) < 3:
                save(
                    identifier, stage, candidate_failures=failures, next_at=next_at(60)
                )
                return
            with SessionLocal() as db:
                row = db.scalar(
                    select(FloatingIP).where(FloatingIP.resource_id == s["resource_id"])
                )
                row.status = "rejected_blocked"
                db.commit()
            save(
                identifier,
                "ORDER",
                order_id=None,
                candidate_failures=failures,
                next_at=next_at(30),
            )
        else:
            # Do not purchase on inconclusive or externally degraded checks.
            stop(
                identifier,
                "Не удалось доказать работоспособность кандидата; требуется сверка",
            )
    elif stage == "NETWORK_COMMIT":
        if network_job(identifier, s, "commit", s["resource_id"]):
            save(identifier, "DNS_HANDOFF")
    elif stage == "DNS_HANDOFF":
        from .monitoring import collect_agent

        # Candidate search may outlast the original incident evidence's TTL.
        evidence = await collect_agent(s["agent_id"], s["host"], s["port"], s["old"])
        with SessionLocal() as db:
            a = require_context(db, s)
            incident = db.get(Incident, s["incident_id"])
            if not authorization(incident, evidence):
                raise PilotError("Свежая проверка перед DNS не подтверждает блокировку")
            incident.evidence = evidence
            row = db.scalar(
                select(FloatingIP).where(FloatingIP.resource_id == s["resource_id"])
            )
            row.status = "ready_standby"
            p = db.get(SystemSetting, rr.policy_key(a.id))
            # Proven adapter boundary, not a fabricated per-address DNS roundtrip.
            proofs = db.scalars(
                select(SystemSetting).where(SystemSetting.key.like("dns-pilot:%"))
            ).all()
            proof = next(
                (
                    x
                    for x in proofs
                    if x.value.get("agent_id") == a.id
                    and x.value.get("host") == s["host"]
                    and x.value.get("stage") == "COMPLETED_RETURNED"
                ),
                None,
            )
            if not proof:
                raise PilotError("Нет проверенного DNS-адаптера для агента")
            value = {
                "enabled": True,
                "mode": "paid_candidate",
                "resource_id": s["resource_id"],
                "proof_key": proof.key,
                "purchase_allowed": False,
                "delete_allowed": False,
            }
            if p:
                p.value = value
            else:
                db.add(SystemSetting(key=rr.policy_key(a.id), value=value))
            db.flush()
            r = db.get(Recovery, identifier)
            i = db.get(Incident, s["incident_id"])
            i.status = "BLOCK_CONFIRMED"
            if not rr.queue_if_ready(db, r, i):
                raise PilotError("DNS-переход не прошёл проверки готовности")
            paid_row = db.get(SystemSetting, state_key(identifier))
            paid_row.value = {
                **paid_row.value,
                "stage": "HANDOFF",
                "handoff_evidence": evidence,
                "updated_at": utcnow().isoformat(),
            }
            db.commit()
    elif stage in ("CLEANUP", "QUOTA_CLEANUP"):
        with SessionLocal() as db:
            a = db.get(Agent, s["agent_id"])
            targets = [
                x
                for x in s["candidates"]
                if x != s.get("resource_id") or stage == "QUOTA_CLEANUP"
            ]
            if stage == "CLEANUP" and s["old"] != s["management"]:
                old = db.scalar(
                    select(FloatingIP).where(
                        FloatingIP.agent_id == a.id,
                        FloatingIP.ipv4 == s["old"],
                        FloatingIP.managed.is_(True),
                        FloatingIP.released_at.is_(None),
                    )
                )
                if old:
                    targets.append(old.resource_id)
            configured = list(s.get("configured", []))
            if (
                stage == "CLEANUP"
                and s["old"] != s["management"]
                and old
                and old.resource_id not in configured
            ):
                configured.append(old.resource_id)
            s["configured"] = configured
        for rid in targets:
            if not await delete_owned(identifier, s, rid):
                return
        if stage == "QUOTA_CLEANUP":
            save(
                identifier,
                "FINAL_CHECK",
                order_id=None,
                resource_id=None,
                next_at=s["resume_at"],
            )
            with SessionLocal() as db:
                db.add(
                    Notification(
                        topic="recovery",
                        target=identifier,
                        text="Квота заказов исчерпана. Забракованные кандидаты освобождены; история сохранена. Поиск возобновится после восстановления квоты.",
                    )
                )
                db.commit()
        else:
            save(identifier, "DONE")


async def tick():
    with SessionLocal() as db:
        rows = db.scalars(
            select(SystemSetting).where(SystemSetting.key.like("paid-recovery:%"))
        ).all()
        identifiers = [
            x.key.split(":", 1)[1]
            for x in rows
            if not (
                x.value.get("stage") == "HANDOFF"
                and db.get(Recovery, x.key.split(":", 1)[1]).status in rr.ACTIVE
            )
            and x.value.get("stage") not in ("DONE", "MANUAL_REQUIRED")
            and (
                not x.value.get("next_at")
                or utcnow() >= aware(datetime.fromisoformat(x.value["next_at"]))
            )
        ]
    for identifier in identifiers:
        with rr.exclusive() as locked:
            if not locked:
                return False
            try:
                await step(identifier)
            except Exception as error:
                s = load(identifier)
                eid = record_failure(
                    "paid_recovery",
                    s["stage"],
                    error,
                    operation_id=identifier,
                    agent_id=s["agent_id"],
                )
                # Purchasing is reconciled by purchase_one; never blind POST retries.
                failures = s.get("failures", 0) + 1
                if failures >= 5:
                    stop(
                        identifier,
                        "Повторные ошибки шага " + s["stage"] + "; error_id=" + eid,
                    )
                else:
                    save(
                        identifier,
                        s["stage"],
                        error_id=eid,
                        failures=failures,
                        next_at=next_at(60),
                    )
        return True
    return False


def configure(db, agent_id, action, *, approved=False, probe_id=None):
    from .services import online
    from .dns_scope import managed_record

    a = db.get(Agent, agent_id)
    if not a:
        raise PilotError("Агент не найден")
    key = policy_key(agent_id)
    row = db.get(SystemSetting, key)
    if action == "status":
        return dict(row.value) if row else {"enabled": False}
    if action == "probe":
        job = Job(
            agent_id=agent_id,
            kind="floating_network",
            payload={"action": "inspect", "address": a.configuration["management_ip"]},
        )
        db.add(job)
        db.flush()
        audit(db, "local-admin", "paid_network_probe", job.id, agent_id=agent_id)
        return {"probe_job_id": job.id}
    if action == "enable":
        if not approved:
            raise PilotError("Нужно явное разрешение автопокупок")
        context(db, agent_id)
        if (
            not online(a)
            or a.paused
            or a.revoked
            or a.facts.get("telemt_service") != "active"
        ):
            raise PilotError("Нода не готова")
        if a.configuration.get("dns_zone") != "vetka.rest" or not managed_record(
            a.configuration.get("dns_record")
        ):
            raise PilotError("Неверная DNS-граница")
        probe = db.get(Job, probe_id or "")
        if (
            not probe
            or probe.agent_id != a.id
            or probe.kind != "floating_network"
            or probe.payload
            != {"action": "inspect", "address": a.configuration["management_ip"]}
            or probe.status != "succeeded"
            or utcnow() - aware(probe.created_at) > timedelta(minutes=10)
        ):
            raise PilotError("Нужна свежая успешная проверка сетевого помощника")
        proofs = db.scalars(
            select(SystemSetting).where(SystemSetting.key.like("dns-pilot:%"))
        ).all()
        if not any(
            x.value.get("stage") == "COMPLETED_RETURNED"
            and x.value.get("agent_id") == a.id
            and x.value.get("host") == a.configuration["dns_record"]
            and x.value.get("forward_check", {}).get("verified")
            and x.value.get("return_check", {}).get("verified")
            for x in proofs
        ):
            raise PilotError("Не проверен DNS-адаптер")
    elif action != "disable":
        raise PilotError("Неизвестная команда")
    value = {
        **(row.value if row else {}),
        "enabled": action == "enable",
        "mode": "mtproto_primary",
        "changed_at": utcnow().isoformat(),
    }
    if action == "enable":
        value.update(
            {
                "probe_job_id": probe_id,
                "approved_by": "owner",
                "rechecks_minutes": [15, 20, 25],
            }
        )
    if row:
        row.value = value
    else:
        db.add(SystemSetting(key=key, value=value))
    audit(db, "local-admin", "paid_automation_" + action, agent_id)
    return value


def enabled_count(db):
    return sum(
        enabled(db, a.id)
        for a in db.scalars(select(Agent).where(Agent.revoked.is_(False)))
    )
