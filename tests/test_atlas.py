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


def probe(identifier, country, asn, coordinates=(37.6173, 55.7558)):
    return {
        "id": identifier,
        "country_code": country,
        "asn_v4": asn,
        "is_public": True,
        "status": {"id": 1},
        "tags": [{"slug": "system-ipv4-works"}],
        "geometry": {"coordinates": list(coordinates)},
    }


def test_probe_selection_reports_missing_cells_and_never_fakes_mobile_coverage():
    from commander.atlas_probes import select_probes

    rows = [
        probe(1, "RU", 3216),
        probe(2, "RU", 3216),
        probe(3, "RU", 3216),
        probe(4, "RU", 99999),
    ]
    rows += [probe(10 + i, "DE", asn) for i, asn in enumerate((100, 100, 200, 300))]
    rows += [
        dict(probe(20, "RU", 8359), status={"id": 2}),
        probe(21, "RU", 8359, (0, 0)),
    ]
    plan = select_probes(rows)
    assert {p["id"] for p in plan["probes"]} == {1, 2, 10, 12, 13}
    assert len(plan["coverage"]) == 19
    assert any(
        g.get("city") == "Хабаровск" and g["probes"] == 0
        for g in plan["missing_groups"]
    )
    assert plan["geolocation_approximate"] and not plan["measurement_submitted"]


def test_comparison_requires_multiple_ru_networks_cities_and_all_foreign_controls():
    from commander.atlas import compare_regions
    from commander.atlas_probes import select_probes

    host = "sni.example.com"
    rows = [
        probe(1, "RU", 3216),
        probe(2, "RU", 3216),
        probe(3, "RU", 8359, (30.3351, 59.9343)),
        probe(4, "RU", 8359, (30.3351, 59.9343)),
    ]
    for offset, country in enumerate(("DE", "NL", "FI")):
        rows += [probe(10 + offset * 3 + i, country, 100 + i) for i in range(3)]
    plan = select_probes(rows)
    cert = certificate(host)
    results = [
        {
            "prb_id": p["id"],
            **({"error": "timeout"} if p["country"] == "RU" else {"cert": [cert]}),
        }
        for p in plan["probes"]
    ]
    report = compare_regions(results, host, 123, plan, "8.8.8.8")
    assert report["comparison"] == "suspected_ru_filtering"
    assert report["target_ipv4"] == "8.8.8.8" and not report["mtproto_verified"]
    assert (
        compare_regions(results[:1] + results[4:], host, 123, plan, "8.8.8.8")[
            "comparison"
        ]
        == "inconclusive"
    )
    assert (
        compare_regions(results[:-3], host, 123, plan, "8.8.8.8")["comparison"]
        == "inconclusive"
    )
    unexpected = [dict(r, dst_addr="1.1.1.1") for r in results]
    assert (
        compare_regions(unexpected, host, 123, plan, "8.8.8.8")["comparison"]
        == "inconclusive"
    )


def test_explicit_probe_submission_pins_proxy_ipv4_and_sni(monkeypatch):
    posted = []

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def post(self, path, **kwargs):
            posted.append(kwargs["json"])
            return httpx.Response(
                201,
                json={"measurements": [123]},
                request=httpx.Request(
                    "POST", "https://atlas.ripe.net/api/v2/measurements/"
                ),
            )

    monkeypatch.setattr(Atlas, "client", lambda self: Client())
    plan = {"probes": [{"id": 11}, {"id": 12}]}
    assert (
        asyncio.run(Atlas("fake").submit("sni.example.com", plan, "8.8.8.8", 9443))
        == 123
    )
    assert posted[0]["definitions"][0]["target"] == "8.8.8.8"
    assert posted[0]["definitions"][0]["hostname"] == "sni.example.com"
    assert posted[0]["definitions"][0]["port"] == 9443
    assert posted[0]["probes"] == [{"requested": 2, "type": "probes", "value": "11,12"}]
