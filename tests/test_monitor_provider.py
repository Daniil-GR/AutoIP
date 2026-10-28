import asyncio

import httpx
import pytest

from commander.monitor import CheckHost


@pytest.mark.parametrize(
    "sample,expected",
    [
        ([{"time": 0.04, "address": "8.8.8.8"}], "reachable"),
        ([{"error": "Connection refused"}], "failed"),
        ([{"error": "Connection timed out"}], "unknown"),
        ([{"error": "Unable to resolve hostname"}], "unknown"),
        (None, "unknown"),
        ([], "unknown"),
        ([[1, 1]], "unknown"),
    ],
)
def test_official_checkhost_schema(monkeypatch, sample, expected):
    calls = []

    class Client:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def get(self, url, **kwargs):
            calls.append((url, kwargs))
            if url.endswith("/nodes/hosts"):
                data = {
                    "nodes": {
                        "ru1": {"asn": "AS1", "location": ["ru", "Russia", "Moscow"]},
                        "de1": {"asn": "AS2", "location": ["de", "Germany", "Berlin"]},
                    }
                }
            elif url.endswith("/check-tcp"):
                data = {"request_id": "abc123"}
            else:
                data = {"ru1": sample, "de1": [{"time": 0.02, "address": "8.8.8.8"}]}
            return httpx.Response(200, json=data, request=httpx.Request("GET", url))

    async def no_sleep(_):
        pass

    monkeypatch.setattr("commander.monitor.httpx.AsyncClient", Client)
    monkeypatch.setattr("commander.monitor.asyncio.sleep", no_sleep)
    report = asyncio.run(CheckHost().check("example.com", 443))
    assert report["observations"][0]["state"] == expected
    assert report["observations"][1]["country"] == "DE"
    assert report["observations"][0]["asn"] == "AS1"
    assert ("node", "ru1") in calls[1][1]["params"]


def test_provider_failure_is_unknown(monkeypatch):
    class Client:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def get(self, *args, **kwargs):
            raise httpx.ConnectError("sensitive-data")

    monkeypatch.setattr("commander.monitor.httpx.AsyncClient", Client)
    result = asyncio.run(CheckHost().check("example.com", 443))
    assert result["status"] == "unknown" and "sensitive-data" not in str(result)
