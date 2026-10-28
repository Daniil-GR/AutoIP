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


def summarize(rows, host, measurement_id):
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
        if responded >= 3 and good == responded
        else "unavailable"
        if responded >= 3 and bad == responded
        else "partial"
        if responded >= 3 and good and bad
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


class Atlas:
    def __init__(self, api_key):
        self.api_key = api_key

    def client(self):
        return httpx.AsyncClient(
            base_url="https://atlas.ripe.net/api/v2/",
            timeout=15,
            headers={"Authorization": "Key " + self.api_key},
        )

    async def submit(self, host):
        if not PUBLIC_HOST.fullmatch(host):
            raise AtlasError("Требуется корректный SNI-домен")
        loop = asyncio.get_running_loop()
        addresses = await loop.getaddrinfo(
            host, 443, family=socket.AF_INET, type=socket.SOCK_STREAM
        )
        ips = {r[4][0] for r in addresses}
        if not ips or not all(ipaddress.ip_address(ip).is_global for ip in ips):
            raise AtlasError("SNI-домен должен разрешаться только в публичные IPv4")
        body = {
            "definitions": [
                {
                    "target": sorted(ips)[0],
                    "hostname": host,
                    "description": "AutoIP SNI domain diagnostics",
                    "type": "sslcert",
                    "af": 4,
                    "port": 443,
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

    async def results(self, identifier, host):
        if not isinstance(identifier, int) or identifier <= 0:
            raise AtlasError("Некорректный measurement ID")
        try:
            async with self.client() as client:
                response = await client.get(f"measurements/{identifier}/results/")
                response.raise_for_status()
                data = response.json()
                if not isinstance(data, list):
                    raise ValueError()
                return summarize(data, host, identifier)
        except (httpx.HTTPError, ValueError):
            raise AtlasError("Не удалось получить результаты RIPE Atlas") from None


async def execute_task(task_id):
    """Durable submit-once checkpoint. Crash before response => manual reconcile."""
    from .database import Check, ControlTask, Integration, SessionLocal
    from .vault import decrypt

    with SessionLocal() as db:
        task = db.get(ControlTask, task_id)
        integration = db.get(Integration, task.payload["integration_id"])
        host = task.payload["host"]
        client = Atlas(decrypt(integration)["api_key"])
        identifier = task.payload.get("measurement_id")
        if not identifier:
            task.status = "submission_uncertain"
            task.result = {
                "error": "Начата отправка измерения; при аварии требуется ручная сверка RIPE Atlas"
            }
            db.commit()
    try:
        if not identifier:
            identifier = await client.submit(host)
            with SessionLocal() as db:
                task = db.get(ControlTask, task_id)
                task.payload = {**task.payload, "measurement_id": identifier}
                task.status = "running"
                db.commit()
        report = await client.results(identifier, host)
        with SessionLocal() as db:
            task = db.get(ControlTask, task_id)
            if report["responded"] < 3 and task.attempts < 4:
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
    except AtlasError:
        with SessionLocal() as db:
            task = db.get(ControlTask, task_id)
            task.status, task.result = (
                "failed",
                {"error": "Ошибка RIPE Atlas; проверьте интеграцию и measurement ID"},
            )
            db.commit()
