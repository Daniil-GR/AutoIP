"""Audited, owner-approved DNS roundtrip CLI. Not automatic recovery."""

import asyncio
from contextlib import contextmanager
from uuid import UUID

import dns.flags
import dns.message
import dns.query
import dns.resolver
from sqlalchemy import select, text

from .database import (
    Agent,
    FloatingIP,
    Integration,
    SessionLocal,
    SystemSetting,
    engine,
    utcnow,
)
from .dns_pilot import (
    DNSPilot,
    DNSPilotError,
    assert_records,
    snapshot,
    target,
    canonical,
)
from .dns_scope import MANAGED_DNS_ZONE
from .security import audit
from .vault import decrypt


def key_for(operation_id):
    return "dns-pilot:" + str(UUID(operation_id))


def load(operation_id):
    with SessionLocal() as db:
        row = db.get(SystemSetting, key_for(operation_id))
        if not row:
            raise DNSPilotError("Операция не найдена")
        return dict(row.value)


def checkpoint(operation_id, stage, **values):
    with SessionLocal() as db:
        row = db.get(SystemSetting, key_for(operation_id))
        row.value = {
            **row.value,
            **values,
            "stage": stage,
            "updated_at": utcnow().isoformat(),
        }
        audit(
            db,
            "local-admin",
            "dns_pilot_" + stage.lower(),
            row.value["agent_id"],
            operation_id=operation_id,
        )
        db.commit()


@contextmanager
def serialized():
    # Across different pilot UUIDs too: all write operations share the zone lock.
    with engine.connect() as conn:
        if conn.dialect.name != "postgresql":
            raise DNSPilotError("Живой DNS-пилот требует PostgreSQL блокировку")
        locked = conn.execute(text("SELECT pg_try_advisory_lock(184042, 1)")).scalar()
        if not locked:
            raise DNSPilotError("Другой DNS-пилот уже выполняется")
        try:
            yield
        finally:
            conn.execute(text("SELECT pg_advisory_unlock(184042, 1)"))


def client_for(integration_id):
    with SessionLocal() as db:
        item = db.get(Integration, integration_id)
        if not item or item.kind != "dynadot" or item.status != "verified":
            raise DNSPilotError("Нужна проверенная Dynadot интеграция")
        c = decrypt(item)
    return DNSPilot(c["api_key"], c["api_secret"])


async def prepare(operation_id, agent_id, resource_id, *, approved=False):
    if not approved:
        raise DNSPilotError("Нужно согласование теста и возврата DNS")
    key = key_for(operation_id)
    with serialized():
        with SessionLocal() as db:
            if db.get(SystemSetting, key):
                return {"stage": load(operation_id)["stage"]}
            agent = db.get(Agent, agent_id)
            resource = db.scalar(
                select(FloatingIP).where(FloatingIP.resource_id == resource_id)
            )
            if (
                not agent
                or agent.revoked
                or not resource
                or resource.agent_id != agent_id
                or not resource.managed
                or resource.released_at
                or resource.status != "ready_standby"
            ):
                raise DNSPilotError("Не подтверждены агент и резервный IP")
            cfg = agent.configuration or {}
            old = cfg.get("floating_ip") or cfg.get("proxy_ip")
            host = cfg.get("dns_record")
            record = target(host, old)
            target(host, resource.ipv4)
            state = {
                "agent_id": agent_id,
                "operation_id": str(UUID(operation_id)),
                "host": host,
                "old": old,
                "new": resource.ipv4,
                "resource_id": resource_id,
                "integration_id": cfg.get("dns_integration_id"),
                "stage": "PREPARING",
                "return_authorized": True,
                "created_at": utcnow().isoformat(),
            }
            client = client_for(state["integration_id"])
            before = snapshot(await client.records(MANAGED_DNS_ZONE))
            matches = [
                r
                for r in before.get("dns_sub_list", [])
                if r.get("sub_host") == record["sub_host"]
            ]
            if canonical(matches) != canonical([record]):
                raise DNSPilotError("DNS не совпадает с текущим адресом агента")
            state.update(before=before, stage="PREPARED", ttl=before["ttl"])
            db.add(SystemSetting(key=key, value=state))
            audit(
                db,
                "owner",
                "dns_pilot_roundtrip_approved",
                agent_id,
                operation_id=operation_id,
            )
            db.commit()
    return {"stage": "PREPARED", "ttl": state["ttl"]}


async def change(operation_id, *, restore=False):
    with serialized():
        state = load(operation_id)
        client = client_for(state["integration_id"])

        def cb(stage, **values):
            # Keep the immutable original snapshot/old/new during reverse steps.
            checkpoint(operation_id, stage)

        if restore:
            if not state.get("return_authorized"):
                raise DNSPilotError("Возврат не согласован")
            result = await client.restore_a(
                state["host"],
                state["old"],
                state["new"],
                state["before"],
                approved=True,
                checkpoint=cb,
            )
            checkpoint(operation_id, "RESTORED_PROVIDER")
        else:
            if state["stage"] != "PREPARED":
                raise DNSPilotError(
                    "Повтор переключения запрещён; сверить состояние или вернуть DNS"
                )
            assert_records(
                snapshot(await client.records(MANAGED_DNS_ZONE)), state["before"]
            )
            result = await client.replace_a(
                state["host"], state["old"], state["new"], approved=True, checkpoint=cb
            )
        return result


def dns_observations(host):
    result = {"authoritative": [], "recursive": []}
    names = [
        str(x.target).rstrip(".")
        for x in dns.resolver.resolve(MANAGED_DNS_ZONE, "NS", lifetime=8)
    ]
    if not names or len(names) > 8:
        raise DNSPilotError("Не определены авторитетные NS")
    for name in names:
        try:
            addresses = sorted(
                {str(x) for x in dns.resolver.resolve(name, "A", lifetime=8)}
            )
            if not addresses or len(addresses) > 4:
                raise DNSPilotError("Неизвестный набор адресов NS")
        except Exception:
            result["authoritative"].append({"ns": name, "error": "dns_query_failed"})
            continue
        for address in addresses:
            try:
                response = dns.query.udp(
                    dns.message.make_query(host, "A"), address, timeout=5
                )
                if response.flags & dns.flags.TC:
                    response = dns.query.tcp(
                        dns.message.make_query(host, "A"), address, timeout=5
                    )
                ips = sorted(
                    {
                        str(item)
                        for rr in response.answer
                        if rr.rdtype == 1 and str(rr.name).rstrip(".") == host
                        for item in rr
                    }
                )
                result["authoritative"].append(
                    {
                        "ns": name,
                        "address": address,
                        "ips": ips,
                        "aa": bool(response.flags & dns.flags.AA),
                    }
                )
            except Exception:
                result["authoritative"].append(
                    {"ns": name, "address": address, "error": "dns_query_failed"}
                )
    for name in ["1.1.1.1", "8.8.8.8"]:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [name]
        try:
            result["recursive"].append(
                {
                    "resolver": name,
                    "ips": sorted(
                        str(x) for x in resolver.resolve(host, "A", lifetime=6)
                    ),
                }
            )
        except Exception:
            result["recursive"].append({"resolver": name, "error": "dns_query_failed"})
    return result


def dns_quorum(observations, expected):
    authorities = observations["authoritative"]
    recursive = observations["recursive"]
    a = sum(bool(r.get("aa")) and r.get("ips") == [expected] for r in authorities)
    r = sum(x.get("ips") == [expected] for x in recursive)
    return {
        "authoritative_ok": bool(authorities) and a > len(authorities) / 2,
        "recursive_ok": bool(recursive) and r > len(recursive) / 2,
        "all_authorities_updated": bool(authorities) and a == len(authorities),
        "dns_votes": {
            "authoritative": [a, len(authorities)],
            "recursive": [r, len(recursive)],
        },
    }


async def verify(operation_id, *, restored=False):
    from .monitoring import checker_report

    state = load(operation_id)
    expected = state["old"] if restored else state["new"]
    observations = await asyncio.to_thread(dns_observations, state["host"])
    readiness = dns_quorum(observations, expected)
    authoritative_ok = readiness["authoritative_ok"]
    recursive_ok = readiness["recursive_ok"]
    with SessionLocal() as db:
        port = db.get(Agent, state["agent_id"]).proxy_port
    direct = await checker_report(state["agent_id"], expected, port)
    domain = await checker_report(state["agent_id"], state["host"], port)
    report = {
        "expected": expected,
        "dns": observations,
        **readiness,
        "authoritative_ok": authoritative_ok,
        "recursive_ok": recursive_ok,
        "direct_mtproto": direct,
        "domain_mtproto": domain,
        "verified": authoritative_ok
        and recursive_ok
        and direct.get("mtproto_verified") is True
        and domain.get("mtproto_verified") is True,
    }
    # Verification does not overwrite the mutation checkpoint needed for recovery.
    checkpoint(
        operation_id,
        state["stage"],
        **{"return_check" if restored else "forward_check": report},
    )
    return report
