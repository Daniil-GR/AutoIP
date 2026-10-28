import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from commander.atlas import AmbiguousSubmission, Atlas, summarize


def certificate(host, expired=False):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now + timedelta(days=-1 if expired else 1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_sni_requires_multiple_distinct_probes_and_is_not_mtproto():
    cert = certificate("sni.example.com")
    row = {"prb_id": 1, "cert": [cert]}
    assert summarize([row] * 5, "sni.example.com", 10)["outcome"] == "unknown"
    result = summarize([dict(row, prb_id=n) for n in range(3)], "sni.example.com", 10)
    assert result["outcome"] == "available"
    assert (
        result["mtproto_verified"] is False
        and result["certificate_chain_verified"] is False
    )
    assert result["scope"] == "sni-domain-only"
    assert (
        summarize([dict(row, prb_id=n) for n in range(3)], "wrong.example.com", 10)[
            "outcome"
        ]
        == "unavailable"
    )


def test_sni_expired_and_missing_cert():
    cert = certificate("sni.example.com", expired=True)
    assert (
        summarize(
            [{"prb_id": n, "cert": [cert]} for n in range(3)], "sni.example.com", 10
        )["outcome"]
        == "unavailable"
    )
    assert (
        summarize([{"prb_id": n} for n in range(3)], "sni.example.com", 10)["outcome"]
        == "unknown"
    )


def test_ambiguous_measurement_is_not_retried(monkeypatch):
    requests = []

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def post(self, *args, **kwargs):
            requests.append(kwargs["json"])
            raise httpx.ReadTimeout("must-not-be-logged")

    async def resolver(*args, **kwargs):
        return [(None, None, None, None, ("8.8.8.8", 443))]

    async def execute():
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolver)
        monkeypatch.setattr(Atlas, "client", lambda self: Client())
        with pytest.raises(AmbiguousSubmission):
            await Atlas("fake-api-key").submit("sni.example.com")

    asyncio.run(execute())
    assert len(requests) == 1
    assert requests[0]["definitions"][0]["hostname"] == "sni.example.com"
    assert requests[0]["probes"][0]["value"] == "RU"
