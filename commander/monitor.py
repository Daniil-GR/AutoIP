"""Provider-neutral evidence. TCP reachability is never proof of MTProto health."""

import asyncio
import ipaddress
import re
from typing import Protocol

import httpx

PUBLIC_HOST = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)


def valid_target(host, port):
    if not 1 <= port <= 65535:
        return False
    try:
        return ipaddress.IPv4Address(host).is_global
    except ValueError:
        return bool(PUBLIC_HOST.fullmatch(host)) and not host.lower().endswith(
            (".localhost", ".local", ".internal")
        )


class MonitorProvider(Protocol):
    name: str

    async def check(self, host: str, port: int) -> dict: ...


class CheckHost:
    name = "check-host"

    async def check(self, host, port, protocol="tcp"):
        if protocol not in ("tcp", "https"):
            raise ValueError("Unsupported check protocol")
        if not valid_target(host, port):
            return {
                "status": "unknown",
                "source": self.name,
                "error": "Invalid public host/port",
                "observations": [],
            }
        try:
            async with httpx.AsyncClient(timeout=12) as client:
                response = await client.get(
                    "https://check-host.net/nodes/hosts",
                    headers={"Accept": "application/json"},
                )
                response.raise_for_status()
                nodes = response.json().get("nodes", {})
                ru, foreign = {}, {}
                for name, info in nodes.items():
                    if not isinstance(info, dict) or not info.get("location"):
                        continue
                    country = str(info["location"][0]).upper()
                    pool = ru if country == "RU" else foreign
                    if len(pool) < (5 if country == "RU" else 3):
                        pool[name] = {
                            "country": country,
                            "asn": str(info.get("asn", "")),
                        }
                selected = {**ru, **foreign}
                if not ru:
                    return {
                        "status": "unknown",
                        "source": self.name,
                        "error": "No RU nodes",
                        "observations": [],
                    }
                response = await client.get(
                    "https://check-host.net/check-http"
                    if protocol == "https"
                    else "https://check-host.net/check-tcp",
                    params=[
                        (
                            "host",
                            f"https://{host}:{port}/"
                            if protocol == "https"
                            else f"{host}:{port}",
                        )
                    ]
                    + [("node", n) for n in selected],
                    headers={"Accept": "application/json"},
                )
                response.raise_for_status()
                request_id = response.json().get("request_id")
                if not isinstance(request_id, str) or not re.fullmatch(
                    r"[A-Za-z0-9_-]{1,128}", request_id
                ):
                    raise ValueError("Invalid request id")
                results = {}
                for _ in range(6):
                    await asyncio.sleep(2)
                    response = await client.get(
                        "https://check-host.net/check-result/" + request_id,
                        headers={"Accept": "application/json"},
                    )
                    response.raise_for_status()
                    results = response.json()
                    if all(results.get(node) is not None for node in selected):
                        break
                observations = []
                for node, info in selected.items():
                    raw = results.get(node)
                    item = raw[0] if isinstance(raw, list) and raw else None
                    # Timeouts, DNS failures and unknown response schemas are inconclusive.
                    state = "unknown"
                    if (
                        protocol == "https"
                        and isinstance(item, list)
                        and len(item) >= 4
                        and item[0] == 1
                    ):
                        code = str(item[3])
                        state = (
                            "reachable"
                            if code.isdigit() and 200 <= int(code) < 400
                            else "failed"
                        )
                    elif protocol == "tcp" and isinstance(item, dict):
                        if isinstance(item.get("time"), (int, float)) and item.get(
                            "address"
                        ):
                            state = "reachable"
                        elif "refused" in str(item.get("error", "")).lower():
                            state = "failed"
                    observations.append(
                        {
                            "source": self.name,
                            "node": node,
                            **info,
                            "state": state,
                            "protocol": protocol,
                            "raw": raw,
                        }
                    )
                return {
                    "status": "observed",
                    "source": self.name,
                    "target": host,
                    "port": port,
                    "request_id": request_id,
                    "observations": observations,
                }
        except (httpx.HTTPError, ValueError, TypeError, KeyError, AttributeError):
            # Exception URLs can contain credentials on other providers; never persist str(exc).
            return {
                "status": "unknown",
                "source": self.name,
                "error": "Monitoring provider unavailable or malformed response",
                "observations": [],
            }


async def checkhost_tcp(host, port):
    return await CheckHost().check(host, port)


PROVIDERS: dict[str, MonitorProvider] = {"check-host": CheckHost()}


async def collect(host, port, ip=""):
    targets = [host] + ([ip] if ip and ip != host else [])
    batches = await asyncio.gather(
        *(p.check(target, port) for target in targets for p in PROVIDERS.values()),
        return_exceptions=True,
    )
    observations = []
    reports = []
    for report in batches:
        if isinstance(report, BaseException):
            continue
        reports.append(report)
        observations.extend(
            [
                {**o, "target": report.get("target", host)}
                for o in report.get("observations", [])
            ]
        )
    return {
        "observations": observations,
        "reports": reports,
        "target": host,
        "ip": ip,
        "port": port,
    }


def verdict(evidence, telemt_ok, fresh):
    protocol = next(
        (
            r.get("provider_status")
            for r in evidence.get("reports", [])
            if r.get("source") == "mtproto-checker"
            and r.get("status") == "observed"
            and (not evidence.get("ip") or r.get("target") == evidence["ip"])
        ),
        None,
    )
    if protocol == "OK":
        return "reachable"
    if protocol in ("DATA_CUT", "RKN_BLOCK"):
        return "suspected" if telemt_ok and fresh else "local_fault"
    if protocol in ("MT_DEAD", "DOWN"):
        return "proxy_degraded" if telemt_ok and fresh else "local_fault"
    observations = [
        o for o in evidence.get("observations", []) if o.get("scope") != "web-endpoint"
    ]
    if evidence.get("ip"):
        observations = [o for o in observations if o.get("target") == evidence["ip"]]
    ru = [o for o in observations if o.get("country") == "RU"]
    if any(o.get("state") == "reachable" for o in ru):
        return (
            "tcp_only"
            if any(
                r.get("source") == "mtproto-checker"
                for r in evidence.get("reports", [])
            )
            else "reachable"
        )
    if not telemt_ok or not fresh:
        return "local_fault"
    foreign_ok = any(
        o.get("country") != "RU" and o.get("state") == "reachable" for o in observations
    )
    failures = [o for o in ru if o.get("state") == "failed" and o.get("asn")]
    if foreign_ok and len({o["asn"] for o in failures}) >= 2:
        return "suspected"
    return "unknown"


def independent_failure(evidence):
    if any(
        r.get("provider_status") in ("OK", "MT_DEAD", "DOWN")
        for r in evidence.get("reports", [])
        if r.get("source") == "mtproto-checker"
    ):
        return False
    failures = [
        o
        for o in evidence.get("observations", [])
        if o.get("country") == "RU"
        and o.get("state") == "failed"
        and o.get("scope") != "web-endpoint"
        and (not evidence.get("ip") or o.get("target") == evidence["ip"])
    ]
    return (
        len({o.get("source") for o in failures}) >= 2
        and len({o.get("asn") for o in failures if o.get("asn")}) >= 2
    )
