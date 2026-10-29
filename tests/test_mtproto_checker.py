import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from commander.monitor import verdict, independent_failure
from commander.mtproto_checker import MTProtoChecker, normalize


def sample(status="OK"):
    point = {
        "tcp": True,
        "handshake": True,
        "data": True,
        "latency_ms": 60,
        "duration_ms": 500,
    }
    value = {
        "status": status,
        "server": "8.8.8.8",
        "port": 9443,
        "secret_type": "obf2",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "local": dict(point),
        "remote": dict(point),
    }
    if status == "DATA_CUT":
        value["local"]["data"] = False
    if status == "RKN_BLOCK":
        value["local"].update(tcp=False, handshake=False, data=False)
    if status == "MT_DEAD":
        value["remote"]["data"] = False
    if status == "DOWN":
        for name in ("local", "remote"):
            value[name].update(tcp=False, handshake=False, data=False)
    if status == "UNKNOWN":
        value["local"].update(tcp=None, handshake=None, data=None)
    return value


@pytest.mark.parametrize(
    "status,expected",
    [
        ("OK", "reachable"),
        ("DATA_CUT", "suspected"),
        ("RKN_BLOCK", "suspected"),
        ("MT_DEAD", "proxy_degraded"),
        ("DOWN", "proxy_degraded"),
        ("UNKNOWN", "tcp_only"),
    ],
)
def test_checker_status_and_tcp_do_not_hide_data_cut(status, expected):
    report = normalize(sample(status), "8.8.8.8", 9443, "obf2")
    assert report["provider_status"] == status
    assert report["mtproto_verified"] == (status == "OK")
    evidence = {
        "ip": "8.8.8.8",
        "reports": [report],
        "observations": report["observations"]
        + [
            {
                "source": "check-host",
                "country": "RU",
                "asn": "AS1",
                "state": "reachable",
                "target": "8.8.8.8",
            }
        ],
    }
    assert verdict(evidence, True, True) == expected
    assert not independent_failure(evidence)


def test_web_success_cannot_prove_mtproto_is_available():
    data = {
        "observations": [
            {
                "source": "check-host",
                "country": "RU",
                "state": "reachable",
                "scope": "web-endpoint",
            }
        ]
    }
    assert verdict(data, True, True) == "unknown"


@pytest.mark.parametrize(
    "mutation,error",
    [
        ({"server": "1.1.1.1"}, "target_mismatch"),
        ({"port": 443}, "target_mismatch"),
        ({"secret_type": "plain"}, "target_mismatch"),
        ({"status": "unexpected"}, "malformed_response"),
        (
            {
                "checked_at": (
                    datetime.now(timezone.utc) - timedelta(minutes=20)
                ).isoformat()
            },
            "stale_response",
        ),
    ],
)
def test_wrong_target_unknown_and_stale_data_are_not_proof(mutation, error):
    data = sample()
    data.update(mutation)
    assert normalize(data, "8.8.8.8", 9443, "obf2")["error"] == error


def test_inconsistent_ok_and_secret_echoes_are_rejected_or_removed():
    data = sample()
    data["local"]["data"] = False
    assert normalize(data, "8.8.8.8", 9443, "obf2")["error"] == "inconsistent_response"
    data = sample()
    data["secret"] = "private-secret"
    data["local"]["echo"] = "private-secret"
    assert "private-secret" not in str(normalize(data, "8.8.8.8", 9443, "obf2"))


@pytest.mark.parametrize(
    "code,error",
    [
        (429, "rate_limited"),
        (401, "credentials_rejected"),
        (403, "credentials_rejected"),
        (503, "service_unavailable"),
    ],
)
def test_header_only_secret_in_post_body_and_failures_unknown(monkeypatch, code, error):
    calls = []

    class Client:
        def __init__(self, **kwargs):
            assert kwargs["follow_redirects"] is False

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def post(self, url, **kwargs):
            calls.append((url, kwargs))
            return httpx.Response(
                code,
                headers={"Retry-After": "120"},
                json={"secret": "must-not-be-logged"},
                request=httpx.Request("POST", url),
            )

    monkeypatch.setattr("commander.mtproto_checker.httpx.AsyncClient", Client)
    report = asyncio.run(
        MTProtoChecker("private-api-key", "a" * 32, secret_format="dd").check(
            "8.8.8.8", 9443
        )
    )
    assert report["error"] == error and report["observations"] == []
    assert "private-api-key" not in str(report) and "must-not-be-logged" not in str(
        report
    )
    url, kwargs = calls[0]
    assert "private-api-key" not in url and kwargs["headers"] == {
        "X-API-Key": "private-api-key"
    }
    assert kwargs["json"]["secret"] == "dd" + "a" * 32
    assert "secret" not in kwargs["params"] and "api_key" not in kwargs["params"]
    if code == 429:
        assert report["retry_after_seconds"] == 120
