"""Opt-in DNS pilot using append and exact-record removal, never zone replacement."""

import ipaddress
import json
from collections import Counter
from uuid import uuid4

import httpx

from .dns_scope import MANAGED_DNS_ZONE, managed_record
from .dynadot import Dynadot, signature


class DNSPilotError(RuntimeError):
    pass


def snapshot(data):
    glue = data.get("glue_info", {})
    if glue.get("glue_type") != "DNS" or set(glue) - {
        "glue_type",
        "dns_main_list",
        "dns_sub_list",
        "ttl",
    }:
        raise DNSPilotError("Неизвестная конфигурация зоны; запись запрещена")
    ttl = glue.get("ttl")
    if isinstance(ttl, str) and ttl.isdigit():
        ttl = int(ttl)
    glue = {**glue, "ttl": ttl}
    if type(ttl) is not int or ttl not in [300, 600, 1800, 3600, 7200, 14400, 28800]:
        raise DNSPilotError("Неизвестный TTL")
    for key in ["dns_main_list", "dns_sub_list"]:
        rows = glue.get(key, [])
        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
            raise DNSPilotError("Неизвестный формат записей")
    return glue


def target(host, address):
    host = managed_record(host)
    if not host:
        raise DNSPilotError("Поддомен обязателен")
    if not ipaddress.IPv4Address(address).is_global:
        raise DNSPilotError("Требуется публичный IPv4")
    return {
        "sub_host": host[: -(len(MANAGED_DNS_ZONE) + 1)],
        "record_type": "a",
        "record_value1": address,
    }


def canonical(rows):
    # Dynadot may add empty optional record_value2 on readback.
    return Counter(
        json.dumps({k: v for k, v in r.items() if v != ""}, sort_keys=True)
        for r in rows
    )


def assert_records(actual, expected):
    if actual["ttl"] != expected["ttl"] or any(
        canonical(actual.get(k, [])) != canonical(expected.get(k, []))
        for k in ["dns_main_list", "dns_sub_list"]
    ):
        raise DNSPilotError(
            "Записи отличаются от ожидаемых; остановка и сверка, без перезаписи зоны"
        )


class DNSPilot(Dynadot):
    async def restore_a(
        self, host, old, new, before, *, approved=False, checkpoint=None
    ):
        """Reconcile an interrupted pilot, preserving unrelated records on restore."""
        if not approved:
            raise DNSPilotError("Нужно согласование возврата DNS")
        original, candidate = target(host, old), target(host, new)
        current = snapshot(await self.records(MANAGED_DNS_ZONE))
        rows = current.get("dns_sub_list", [])
        matches = [r for r in rows if r.get("sub_host") == original["sub_host"]]

        def without_target(zone):
            return {
                **zone,
                "dns_sub_list": [
                    r
                    for r in zone.get("dns_sub_list", [])
                    if r.get("sub_host") != original["sub_host"]
                ],
            }

        # Compare every other record with the original snapshot. Never restore a
        # whole old zone over somebody else's concurrent changes.
        assert_records(without_target(current), without_target(before))
        if canonical(matches) == canonical([original]):
            return {"restored": True, "already_original": True}
        if canonical(matches) == canonical([candidate]):
            return await self.replace_a(
                host, new, old, approved=True, checkpoint=checkpoint
            )
        if canonical(matches) != canonical([original, candidate]):
            raise DNSPilotError(
                "Неожиданный адрес поддомена; автоматический возврат запрещён"
            )
        if checkpoint:
            checkpoint("RESTORE_REMOVE_CANDIDATE_PENDING")
        await self.mutate("DELETE", candidate, before["ttl"])
        assert_records(snapshot(await self.records(MANAGED_DNS_ZONE)), before)
        if checkpoint:
            checkpoint("RESTORED_PROVIDER")
        return {"restored": True, "interrupted_append_reconciled": True}

    async def mutate(self, method, record, ttl):
        # No arbitrary payload, host, method, URL or zone can reach this boundary.
        if (
            method not in ("POST", "DELETE")
            or target(
                record["sub_host"] + "." + MANAGED_DNS_ZONE, record["record_value1"]
            )
            != record
        ):
            raise DNSPilotError("Недопустимая DNS-операция")
        payload = {"dns_sub_list": [record]}
        if method == "POST":
            payload.update(ttl=ttl, add_dns_to_current_setting=True)
        body = json.dumps(payload, separators=(",", ":"))
        path = "/restful/v2/domains/" + MANAGED_DNS_ZONE + "/records"
        rid = str(uuid4())
        headers = {
            "Authorization": "Bearer " + self.api_key,
            "X-Request-ID": rid,
            "X-Signature": signature(self.api_key, self.api_secret, path, rid, body),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        try:
            async with httpx.AsyncClient(timeout=20, follow_redirects=False) as client:
                r = await client.request(
                    method,
                    "https://api.dynadot.com" + path,
                    content=body.encode(),
                    headers=headers,
                )
                r.raise_for_status()
                data = r.json()
                if not isinstance(data, dict) or str(data.get("code")) != "200":
                    raise DNSPilotError(
                        "Dynadot не подтвердил DNS-запрос; требуется сверка"
                    )
        except (httpx.HTTPError, ValueError):
            raise DNSPilotError(
                "Ответ DNS-операции не получен; сверить записи до повтора"
            ) from None

    async def replace_a(self, host, old, new, *, approved=False, checkpoint=None):
        if not approved:
            raise DNSPilotError("Нужно согласование DNS-пилота")
        before_record, after_record = target(host, old), target(host, new)
        if old == new:
            raise DNSPilotError("Исходный и новый IP совпадают")
        before = snapshot(await self.records(MANAGED_DNS_ZONE))
        rows = before.get("dns_sub_list", [])
        matches = [r for r in rows if r.get("sub_host") == before_record["sub_host"]]
        if canonical(matches) != canonical([before_record]):
            raise DNSPilotError(
                "Поддомен неоднозначен, имеет другие записи или уже изменён"
            )
        expected_added = {**before, "dns_sub_list": [*rows, after_record]}
        expected_final = {
            **before,
            "dns_sub_list": [r for r in rows if r not in matches] + [after_record],
        }
        if checkpoint:
            checkpoint("ADD_PENDING", before=before, host=host, old=old, new=new)
        await self.mutate("POST", after_record, before["ttl"])
        assert_records(snapshot(await self.records(MANAGED_DNS_ZONE)), expected_added)
        if checkpoint:
            checkpoint("REMOVE_OLD_PENDING")
        await self.mutate("DELETE", before_record, before["ttl"])
        assert_records(snapshot(await self.records(MANAGED_DNS_ZONE)), expected_final)
        if checkpoint:
            checkpoint("PROVIDER_VERIFIED")
        return {
            "host": host,
            "old": old,
            "new": new,
            "ttl": before["ttl"],
            "provider_verified": True,
        }
