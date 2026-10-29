"""Header-authenticated MTProto checks. Never persist raw responses or secrets."""

import math
import re
from datetime import datetime, timezone

import httpx

from .monitor import PUBLIC_HOST, valid_target

BASE_URL = "https://api.yazaebalsyadelatproxy.cc"
SOURCE = "mtproto-checker"
STATUSES = {"OK", "DATA_CUT", "RKN_BLOCK", "MT_DEAD", "DOWN", "UNKNOWN"}


def unavailable(code, retry_after=None):
    report = {
        "source": SOURCE,
        "status": "unknown",
        "error": code,
        "observations": [],
        "mtproto_verified": False,
    }
    if retry_after is not None:
        report["retry_after_seconds"] = retry_after
    return report


def fake_tls_secret(secret, sni):
    if not re.fullmatch(r"[a-fA-F0-9]{32}", secret) or not PUBLIC_HOST.fullmatch(sni):
        raise ValueError("A base MTProto secret and SNI domain are required")
    return "ee" + secret.lower() + sni.lower().encode("ascii").hex()


def normalize(payload, host, port, secret_type="faketls"):
    if not isinstance(payload, dict) or payload.get("status") not in STATUSES:
        return unavailable("malformed_response")
    if (
        payload.get("server") != host
        or payload.get("port") != port
        or payload.get("secret_type") != secret_type
    ):
        return unavailable("target_mismatch")
    try:
        checked = datetime.fromisoformat(payload["checked_at"].replace("Z", "+00:00"))
        if (
            checked.tzinfo is None
            or not -60 <= (datetime.now(timezone.utc) - checked).total_seconds() <= 300
        ):
            return unavailable("stale_response")
    except (KeyError, TypeError, ValueError, AttributeError):
        return unavailable("malformed_response")
    points = {}
    for name in ("local", "remote"):
        raw = payload.get(name)
        if not isinstance(raw, dict):
            return unavailable("malformed_response")
        fields = {}
        for field in ("handshake", "data", "tcp"):
            value = raw.get(field)
            if value is not None and type(value) is not bool:
                return unavailable("malformed_response")
            fields[field] = value
        for field in ("latency_ms", "duration_ms"):
            value = raw.get(field)
            fields[field] = (
                value
                if type(value) in (int, float)
                and math.isfinite(value)
                and 0 <= value <= 120000
                else None
            )
        points[name] = fields
    local, remote = points["local"], points["remote"]
    local_ok = all(local[k] is True for k in ("tcp", "handshake", "data"))
    remote_ok = all(remote[k] is True for k in ("tcp", "handshake", "data"))
    status = payload["status"]
    consistent = {
        "OK": local_ok and remote_ok,
        "DATA_CUT": remote_ok
        and local["tcp"] is True
        and local["handshake"] is True
        and local["data"] is False,
        "RKN_BLOCK": remote_ok
        and (local["tcp"] is False or local["handshake"] is False),
        "MT_DEAD": remote["tcp"] is True and remote["data"] is False,
        "DOWN": local["tcp"] is False and remote["tcp"] is False,
        "UNKNOWN": True,
    }[status]
    if not consistent:
        return unavailable("inconsistent_response")
    observations = []
    for name, country, good in (
        ("local", "RU", local_ok),
        ("remote", "EXTERNAL", remote_ok),
    ):
        failed = (
            status in ("DATA_CUT", "RKN_BLOCK")
            and name == "local"
            or status == "MT_DEAD"
            and name == "remote"
            or status == "DOWN"
        )
        observations.append(
            {
                "source": SOURCE,
                "node": name,
                "country": country,
                "asn": "",
                "protocol": "mtproto",
                "target": host,
                "state": "reachable" if good else "failed" if failed else "unknown",
                **points[name],
            }
        )
    return {
        "source": SOURCE,
        "status": "observed",
        "scope": "mtproto",
        "target": host,
        "port": port,
        "provider_status": status,
        "secret_type": secret_type,
        "checked_at": checked.isoformat(),
        "points": points,
        "mtproto_verified": status == "OK",
        "observations": observations,
        "note": "РФ — одна точка обзора сервиса, не все российские сети. Поля ответа и цель проверены; TCP не заменяет проверку данных MTProto.",
    }


class MTProtoChecker:
    def __init__(self, api_key, secret, sni="", secret_format="dd"):
        self.api_key = api_key
        if not re.fullmatch(r"[a-fA-F0-9]{32}", secret) or secret_format not in (
            "dd",
            "ee",
        ):
            raise ValueError("Unsupported MTProto secret format")
        self.secret = (
            fake_tls_secret(secret, sni)
            if secret_format == "ee"
            else "dd" + secret.lower()
        )
        self.secret_type = "faketls" if secret_format == "ee" else "obf2"

    async def check(self, host, port):
        if not valid_target(host, port):
            return unavailable("invalid_target")
        try:
            async with httpx.AsyncClient(timeout=35, follow_redirects=False) as client:
                response = await client.post(
                    BASE_URL + "/v1/check",
                    params={"mode": "sync", "timeout": 15},
                    headers={"X-API-Key": self.api_key},
                    json={"server": host, "port": port, "secret": self.secret},
                )
                if response.status_code == 429:
                    value = response.headers.get("Retry-After", "")
                    retry = (
                        min(3600, max(1, int(value)))
                        if value.isdigit() and len(value) < 8
                        else 60
                    )
                    return unavailable("rate_limited", retry)
                if response.status_code in (401, 403):
                    return unavailable("credentials_rejected", 300)
                response.raise_for_status()
                if len(response.content) > 65536:
                    return unavailable("malformed_response")
                return normalize(response.json(), host, port, self.secret_type)
        except (httpx.HTTPError, ValueError, TypeError):
            return unavailable("service_unavailable")


async def test_key(api_key):
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
            response = await client.get(
                BASE_URL + "/v1/me", headers={"X-API-Key": api_key}
            )
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict) or type(data.get("rate_limit")) is not int:
                raise ValueError()
            return {
                "ok": True,
                "rate_limit": data["rate_limit"],
                "message": "MTProto Checker: ключ принят. Проверка прокси не запускалась",
            }
    except (httpx.HTTPError, ValueError):
        return {"ok": False, "message": "MTProto Checker отклонил ключ или недоступен"}


def status_label(status):
    return {
        "OK": "работает: данные проходят из РФ и снаружи",
        "DATA_CUT": "из РФ хендшейк проходит, поток данных режется",
        "RKN_BLOCK": "из РФ нет TCP/хендшейка, снаружи работает",
        "MT_DEAD": "снаружи TCP открыт, данные до DC не проходят",
        "DOWN": "недоступен из обеих точек",
        "UNKNOWN": "недостаточно данных",
    }.get(status, "недостаточно данных")
