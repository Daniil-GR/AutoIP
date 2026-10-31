import asyncio

import httpx
import pytest

from commander import providers
from commander.database import Integration
from commander.vault import decrypt


TOKEN = "fixture_gcore$opaque-token-not-real"


def test_gcore_token_is_encrypted_and_never_echoed(client):
    response = client.post(
        "/api/integrations",
        auth=client.auth_pair,
        json={
            "name": "Gcore test",
            "kind": "gcore",
            "credentials": {"api_key": TOKEN},
        },
    )
    assert response.status_code == 200
    assert TOKEN not in response.text
    assert TOKEN not in client.get("/api/integrations", auth=client.auth_pair).text
    with client.factory() as db:
        item = db.get(Integration, response.json()["id"])
        assert TOKEN not in item.ciphertext
        assert decrypt(item) == {"api_key": TOKEN}


@pytest.mark.parametrize("status", [200, 401, 403, 302, 500])
def test_gcore_connection_is_read_only_and_discards_provider_body(monkeypatch, status):
    seen = []

    def handle(request):
        seen.append(request)
        assert request.method == "GET"
        assert str(request.url) == "https://api.gcore.com/iam/clients/me"
        assert request.headers["Authorization"] == "APIKey " + TOKEN
        return httpx.Response(
            status,
            json={"provider_echo": TOKEN},
            headers={"Location": "https://other.invalid/"},
        )

    real = httpx.AsyncClient
    monkeypatch.setattr(
        providers.httpx,
        "AsyncClient",
        lambda **kwargs: real(transport=httpx.MockTransport(handle), **kwargs),
    )
    result = asyncio.run(providers.test_connection("gcore", {"api_key": TOKEN}))
    assert len(seen) == 1
    assert result["ok"] is (status == 200)
    assert TOKEN not in str(result)
    if status == 200:
        assert result["scope"] == "iam_auth_only"
        assert result["edge_proxy_tested"] is False


def test_gcore_header_injection_rejected_without_echo(client):
    token = TOKEN + "\r\nInjected: value"
    response = client.post(
        "/api/integrations",
        auth=client.auth_pair,
        json={
            "name": "bad Gcore",
            "kind": "gcore",
            "credentials": {"api_key": token},
        },
    )
    assert response.status_code == 422
    assert TOKEN not in response.text
