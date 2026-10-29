"""RIPE Atlas SNI diagnostics. This does NOT test an MTProto proxy.

Adapted from the owner's allowed domain-TLS check: RU probes, sslcert,
certificate hostname/time validation. No secrets/configuration reused.
"""

import asyncio
import ipaddress
import socket
import ssl
from datetime import datetime, timezone

import httpx
from cryptography import x509

from .monitor import PUBLIC_HOST


class AtlasError(RuntimeError):
    pass


class AmbiguousSubmission(AtlasError):
    """POST may have succeeded; never submit another measurement automatically."""


def summarize(rows, host, measurement_id, minimum=3):
    unique = {
        r["prb_id"]: r
        for r in rows
        if isinstance(r, dict) and isinstance(r.get("prb_id"), int)
    }
    good, bad = 0, 0
    now = datetime.now(timezone.utc)
    for row in unique.values():
        try:
            raw = row.get("cert", [])[0].replace("\\n", "\n").encode()
            cert = x509.load_pem_x509_certificate(raw)
            names = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
            target = host.lower().rstrip(".")

            def matches(name):
                candidate = name.lower().rstrip(".")
                return candidate == target or (
                    candidate.startswith("*.")
                    and candidate.count("*") == 1
                    and target.endswith(candidate[1:])
                    and len(target.split(".")) == len(candidate.split("."))
                )

            if not any(matches(name) for name in names):
                raise ValueError("Certificate hostname mismatch")
            if (
                row.get("error")
                or row.get("alert")
                or not cert.not_valid_before_utc <= now < cert.not_valid_after_utc
            ):
                bad += 1
            else:
                good += 1
        except (
            ValueError,
            IndexError,
            KeyError,
            TypeError,
            AttributeError,
            x509.ExtensionNotFound,
            ssl.CertificateError,
        ):
            if row.get("error") or row.get("alert") or row.get("cert"):
                bad += 1
    responded = len(unique)
    outcome = (
        "available"
        if responded >= minimum and good == responded
        else "unavailable"
        if responded >= minimum and bad == responded
        else "partial"
        if responded >= minimum and good and bad
        else "unknown"
    )
    return {
        "scope": "sni-domain-only",
        "source": "ripe-atlas",
        "measurement_id": measurement_id,
        "target": host,
        "outcome": outcome,
        "responded": responded,
        "successes": good,
        "failures": bad,
        "certificate_chain_verified": False,
        "mtproto_verified": False,
        "note": "TLS/SNI домена из RU probes; не проверяет передачу Telegram и не является доказательством блокировки IP прокси",
    }


def compare_regions(rows, host, measurement_id, plan, target_ip):
    probes = {p["id"]: p for p in plan["probes"]}
    # Ignore unsolicited probes and results for another target; absence stays UNKNOWN.
    rows = [
        r
        for r in rows
        if isinstance(r, dict)
        and r.get("prb_id") in probes
        and (not r.get("dst_addr") or r["dst_addr"] == target_ip)
    ]
    regions = []
    for coverage in plan["coverage"]:
        ids = {
            p["id"]
            for p in probes.values()
            if p["country"] == coverage["country"]
            and (
                coverage["country"] != "RU"
                or (p["city"] == coverage["city"] and p["asn"] == coverage["asn"])
            )
        }
        summary = summarize(
            [r for r in rows if r["prb_id"] in ids], host, measurement_id, minimum=2
        )
        regions.append(
            {
                **coverage,
                **{
                    k: summary[k]
                    for k in ("outcome", "responded", "successes", "failures")
                },
            }
        )
    ru_rows = [r for r in rows if probes[r["prb_id"]]["country"] == "RU"]
    ru = summarize(ru_rows, host, measurement_id)
    failed = [
        g for g in regions if g["country"] == "RU" and g["outcome"] == "unavailable"
    ]
    abroad = [g for g in regions if g["country"] != "RU"]
    comparison = "inconclusive"
    if (
        ru["outcome"] == "unavailable"
        and len({g["asn"] for g in failed}) >= 2
        and len({g["city"] for g in failed}) >= 2
        and len(abroad) == 3
        and all(g["outcome"] == "available" for g in abroad)
    ):
        comparison = "suspected_ru_filtering"
    elif ru["outcome"] == "available":
        comparison = "ru_accessible"
    report = summarize(rows, host, measurement_id)
    report.update(
        scope="proxy-ip-tls-sni",
        target_ipv4=target_ip,
        regions=regions,
        comparison=comparison,
        coverage=plan["coverage"],
        missing_groups=plan["missing_groups"],
        note="Один IPv4 и SNI сравниваются из РФ и трёх стран. Различие указывает на возможную фильтрацию или проблему маршрутизации, но не доказывает блокировку IP. Таймаут одного зонда и неполное покрытие не запускают покупку IP.",
    )
    return report


class Atlas:
    def __init__(self, api_key):
        self.api_key = api_key

    def client(self):
        return httpx.AsyncClient(
            base_url="https://atlas.ripe.net/api/v2/",
            timeout=15,
            headers={"Authorization": "Key " + self.api_key},
        )

    async def submit(self, host, plan=None, target_ip=None, port=443):
        if not PUBLIC_HOST.fullmatch(host):
            raise AtlasError("Требуется корректный SNI-домен")
        if type(port) is not int or not 1 <= port <= 65535:
            raise AtlasError("Некорректный порт прокси")
        if target_ip:
            ips = {target_ip}
        else:
            loop = asyncio.get_running_loop()
            addresses = await loop.getaddrinfo(
                host, 443, family=socket.AF_INET, type=socket.SOCK_STREAM
            )
            ips = {r[4][0] for r in addresses}
        if not ips or not all(ipaddress.IPv4Address(ip).is_global for ip in ips):
            raise AtlasError("SNI-домен должен разрешаться только в публичные IPv4")
        body = {
            "definitions": [
                {
                    "target": sorted(ips)[0],
                    "hostname": host,
                    "description": "AutoIP SNI domain diagnostics",
                    "type": "sslcert",
                    "af": 4,
                    "port": port,
                    "method": "TLS",
                    "version": "1.2",
                    "is_public": False,
                }
            ],
            "probes": [
                {
                    "requested": 5,
                    "type": "country",
                    "value": "RU",
                    "tags": {"include": ["system-ipv4-works"]},
                }
            ],
            "is_oneoff": True,
        }
        if plan is not None:
            identifiers = sorted({p["id"] for p in plan["probes"]})
            if not identifiers or len(identifiers) > 41:
                raise AtlasError("Нет подходящих зондов или превышен лимит 41 зонда")
            body["probes"] = [
                {
                    "requested": len(identifiers),
                    "type": "probes",
                    "value": ",".join(map(str, identifiers)),
                }
            ]
        try:
            async with self.client() as client:
                response = await client.post("measurements/", json=body)
                if response.status_code >= 500:
                    raise AmbiguousSubmission(
                        "RIPE Atlas: результат создания неизвестен; требуется ручная сверка"
                    )
                response.raise_for_status()
                identifier = response.json()["measurements"][0]
                if not isinstance(identifier, int):
                    raise AmbiguousSubmission(
                        "RIPE Atlas: неизвестный результат создания"
                    )
                return identifier
        except (httpx.TransportError, ValueError, KeyError, IndexError):
            raise AmbiguousSubmission(
                "RIPE Atlas: результат создания неизвестен; не повторяем автоматически"
            ) from None
        except httpx.HTTPStatusError:
            raise AtlasError("RIPE Atlas отклонил создание измерения") from None

    async def results(self, identifier, host, plan=None, target_ip=None):
        if not isinstance(identifier, int) or identifier <= 0:
            raise AtlasError("Некорректный measurement ID")
        try:
            async with self.client() as client:
                response = await client.get(f"measurements/{identifier}/results/")
                response.raise_for_status()
                data = response.json()
                if not isinstance(data, list):
                    raise ValueError()
                if plan is not None:
                    return compare_regions(data, host, identifier, plan, target_ip)
                return summarize(data, host, identifier)
        except (httpx.HTTPError, ValueError):
            raise AtlasError("Не удалось получить результаты RIPE Atlas") from None


async def execute_task(task_id):
    """Durable submit-once checkpoint. Crash before response => manual reconcile."""
    from .database import Check, ControlTask, Integration, SessionLocal
    from .database import Agent
    from .services import proxy_address
    from .vault import decrypt

    with SessionLocal() as db:
        task = db.get(ControlTask, task_id)
        integration = db.get(Integration, task.payload["integration_id"])
        host = task.payload["host"]
        client = Atlas(decrypt(integration)["api_key"])
        identifier = task.payload.get("measurement_id")
        plan = task.payload.get("probe_plan")
        target_ip = task.payload.get("target_ip")
        port = task.payload.get("port", 443)
        agent = db.get(Agent, task.agent_id)
        if target_ip != proxy_address(agent) or port != agent.proxy_port:
            task.status, task.result = (
                "failed",
                {"error": "Адрес или порт изменился; создайте новую проверку"},
            )
            db.commit()
            return
    try:
        if not target_ip:
            raise AtlasError("Требуется IPv4 прокси")
        if not identifier:
            if not plan:
                from .atlas_probes import discover_probes

                plan = await discover_probes()
            with SessionLocal() as db:
                task = db.get(ControlTask, task_id)
                task.payload = {**task.payload, "probe_plan": plan}
                task.status = "submission_uncertain"
                task.result = {
                    "error": "Начата отправка; при аварии требуется ручная сверка RIPE Atlas"
                }
                db.commit()
            identifier = await client.submit(host, plan, target_ip, port)
            with SessionLocal() as db:
                task = db.get(ControlTask, task_id)
                task.payload = {**task.payload, "measurement_id": identifier}
                task.status = "running"
                db.commit()
        report = await client.results(identifier, host, plan, target_ip)
        report["target_port"] = port
        with SessionLocal() as db:
            task = db.get(ControlTask, task_id)
            agent = db.get(Agent, task.agent_id)
            if target_ip != proxy_address(agent) or port != agent.proxy_port:
                task.status, task.result = (
                    "failed",
                    {"error": "Адрес или порт изменился во время измерения"},
                )
                db.commit()
                return
            if report["responded"] < len(plan["probes"]) and task.attempts < 4:
                # Leave running lease to delay safe GET retries; never repeat POST.
                task.status, task.result = "running", report
            else:
                task.status, task.result = "succeeded", report
                db.add(
                    Check(
                        agent_id=task.agent_id,
                        result="sni_" + report["outcome"],
                        details=report,
                    )
                )
            db.commit()
    except AmbiguousSubmission:
        return  # persistent submission_uncertain; no automatic paid retry
    except (AtlasError, httpx.HTTPError, ValueError):
        with SessionLocal() as db:
            task = db.get(ControlTask, task_id)
            task.status, task.result = (
                "failed",
                {"error": "Ошибка RIPE Atlas; проверьте интеграцию и measurement ID"},
            )
            db.commit()
