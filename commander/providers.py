"""Read-only integrations. No provider mutation is reachable from Commander."""

import asyncio
import hashlib
import json
import re

import httpx
from fastapi import HTTPException


class Cherry:
    def __init__(self, api_key):
        self.api_key = api_key

    async def get(self, path):
        if not re.fullmatch(
            r"/(?:projects|teams|servers|ips)(?:/[A-Za-z0-9_-]+){0,3}", path
        ):
            raise ValueError("Invalid Cherry inventory path")
        try:
            async with httpx.AsyncClient(
                base_url="https://api.cherryservers.com/v1",
                timeout=20,
                headers={"Authorization": "Bearer " + self.api_key},
            ) as client:
                response = await client.get(path, params={"limit": 100, "offset": 0})
                response.raise_for_status()
                return response.json()
        except (httpx.HTTPError, ValueError):
            raise HTTPException(
                502, "Cherry API недоступен или отклонил запрос"
            ) from None

    async def inventory(self):
        teams = await self.get("/teams")
        if not isinstance(teams, list):
            raise HTTPException(502, "Неизвестный формат Cherry API")
        projects = []
        for team in teams[:20]:
            identifier = str(team.get("id", ""))
            if not identifier.isdigit():
                continue
            await asyncio.sleep(0.3)  # official limit is 4 requests/second
            data = await self.get("/teams/" + identifier + "/projects")
            if isinstance(data, list):
                projects.extend(data)
        # Return only allowlisted non-secret inventory fields, never credentials/user_data.
        return {
            "teams": [{"id": x.get("id"), "name": x.get("name")} for x in teams],
            "projects": [{"id": x.get("id"), "name": x.get("name")} for x in projects],
            "truncated": len(teams) > 20 or len(teams) >= 100,
        }

    async def project_inventory(self, project_id):
        if not str(project_id).isdigit():
            raise ValueError("Invalid project ID")
        servers = await self.get(f"/projects/{project_id}/servers")
        await asyncio.sleep(0.3)
        ips = await self.get(f"/projects/{project_id}/ips")
        return {
            "servers": [
                {"id": s.get("id"), "name": s.get("name"), "region": s.get("region")}
                for s in servers
            ],
            "ips": [
                {"id": i.get("id"), "address": i.get("address"), "type": i.get("type")}
                for i in ips
            ],
            "truncated": len(servers) >= 100 or len(ips) >= 100,
        }


def dns_plan(snapshot, zone, host, old_ip, new_ip):
    """Lossless local plan only. Dynadot v2 exposes zone-wide writes without CAS.

    Refuse to invoke such a write automatically, even if the local diff is safe.
    """
    import copy
    import ipaddress

    from .dns_scope import managed_record, managed_zone

    zone, host = managed_zone(zone), managed_record(host)
    if not zone or not host:
        raise ValueError("Требуются зона vetka.rest и её поддомен")
    for address in (old_ip, new_ip):
        if not ipaddress.IPv4Address(address).is_global:
            raise ValueError("Требуется публичный IPv4")
    if host == zone or not host.endswith("." + zone):
        raise ValueError("Ожидался поддомен выбранной зоны")
    relative = host[: -(len(zone) + 1)]
    records = snapshot.get("dns_sub_list")
    if not isinstance(records, list):
        raise ValueError("Неизвестный формат снимка зоны")
    matches = [
        i
        for i, record in enumerate(records)
        if record.get("sub_host") == relative
        and str(record.get("record_type")).lower() == "a"
    ]
    if len(matches) != 1 or records[matches[0]].get("record_value1") != old_ip:
        raise ValueError("A-запись неоднозначна или уже изменена")
    planned = copy.deepcopy(snapshot)
    planned["dns_sub_list"][matches[0]]["record_value1"] = new_ip
    fingerprint = hashlib.sha256(
        json.dumps(snapshot, sort_keys=True).encode()
    ).hexdigest()
    return {
        "snapshot_hash": fingerprint,
        "planned": planned,
        "auto_apply_allowed": False,
        "reason": "Dynadot zone-wide update: отсутствует проверенный CAS для сохранения параллельных изменений",
    }


async def test_connection(kind, credentials):
    try:
        if kind == "gcore":
            async with httpx.AsyncClient(timeout=12, follow_redirects=False) as client:
                response = await client.get(
                    "https://api.gcore.com/iam/clients/me",
                    headers={"Authorization": "APIKey " + credentials["api_key"]},
                )
                response.raise_for_status()
                if not isinstance(response.json(), dict) or not response.json():
                    raise ValueError("Unexpected Gcore response")
            return {
                "ok": True,
                "scope": "iam_auth_only",
                "edge_proxy_tested": False,
                "message": "Gcore: токен принят IAM API. Права Edge Proxy и работа MTProto ещё не проверены. Платные ресурсы не создавались",
            }
        if kind in ("telemt_profile", "vps_access"):
            return {
                "ok": False,
                "status": "not_tested",
                "message": "Профиль сохранён зашифрованно. Проверка выбранного VPS выполняется в разделе VPS Node Host",
            }
        if kind == "mtproto_checker":
            from .mtproto_checker import test_key

            return await test_key(credentials["api_key"])
        if kind == "cherry":
            await Cherry(credentials["api_key"]).get("/teams")
            return {
                "ok": True,
                "message": "Cherry API: ключ принят, проверка только чтением",
            }
        if kind == "telegram_bot":
            async with httpx.AsyncClient(timeout=12) as client:
                response = await client.get(
                    "https://api.telegram.org/bot" + credentials["token"] + "/getMe"
                )
                response.raise_for_status()
                data = response.json()
                return {
                    "ok": bool(data.get("ok")),
                    "message": "Telegram Bot API: проверка getMe завершена",
                }
        if kind == "dynadot":
            from .dynadot import Dynadot, DynadotError

            try:
                await Dynadot(credentials["api_key"], credentials["api_secret"]).get(
                    "/accounts/info"
                )
                return {
                    "ok": True,
                    "message": "Dynadot v2: подписанный запрос чтения принят. Запись DNS отключена",
                }
            except DynadotError as error:
                return {
                    "ok": False,
                    "provider_status": error.status,
                    "message": "Dynadot отклонил проверку. Проверьте ключи и разрешённый IP Commander в Tools → API",
                }
        if kind == "telethon":
            if not credentials.get("session"):
                return {
                    "ok": False,
                    "status": "authorization_required",
                    "message": "Данные сохранены. Завершите авторизацию локальной командой; код и пароль 2FA в чат не отправляйте",
                }
            from telethon import TelegramClient
            from telethon.sessions import StringSession

            client = TelegramClient(
                StringSession(credentials["session"]),
                int(credentials["api_id"]),
                credentials["api_hash"],
            )
            try:
                await client.connect()
                return {
                    "ok": await client.is_user_authorized(),
                    "message": "Проверена авторизация отдельного Telegram-аккаунта",
                }
            finally:
                await client.disconnect()
        return {
            "ok": False,
            "message": "Проверка требует выбора домена или measurement ID. Ключ сохранён, внешние изменения не выполнялись",
        }
    except (httpx.HTTPError, HTTPException, ValueError, KeyError):
        return {
            "ok": False,
            "message": "Проверка не пройдена: проверьте ключ и доступность API",
        }
