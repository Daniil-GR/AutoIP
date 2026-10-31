import asyncio
import base64
import hashlib
import hmac

import httpx
import pytest

from commander.dynadot import Dynadot, DynadotError, signature


def test_signature_uses_exact_wire_query_and_no_body():
    expected = base64.b64encode(
        hmac.new(
            b"secret",
            b"key\n/restful/v2/domains?page=1&page_size=100\nrequest-id\n",
            hashlib.sha256,
        ).digest()
    ).decode()
    assert (
        signature(
            "key", "secret", "/restful/v2/domains?page=1&page_size=100", "request-id"
        )
        == expected
    )


def test_inventory_is_signed_and_returns_only_allowlisted_fields(monkeypatch):
    requests = []

    class Client:
        def __init__(self, **kwargs):
            assert kwargs["follow_redirects"] is False

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def send(self, request):
            requests.append(request)
            rid = request.headers["X-Request-ID"]
            assert request.headers["X-Signature"] == signature(
                "key", "secret", request.url.raw_path.decode(), rid
            )
            assert request.headers["Authorization"] == "Bearer key"
            assert request.method == "GET" and request.content == b""
            assert request.url.path == "/restful/v2/domains/vetka.rest/records"
            return httpx.Response(
                200,
                request=request,
                json={
                    "code": 200,
                    "data": {
                        "domain_info_list": [
                            {
                                "domain_name": "unrelated.example",
                                "status": "active",
                                "registrant_contact_id": "do-not-expose",
                            }
                        ],
                        "pagination_result": {"has_next_page": False},
                    },
                },
            )

    monkeypatch.setattr("commander.dynadot.httpx.AsyncClient", Client)
    result = asyncio.run(Dynadot("key", "secret").domains())
    assert result["domains"] == [{"domain_name": "vetka.rest", "status": "accessible"}]
    assert not result["writes_enabled"] and "do-not-expose" not in str(result)
    assert len(requests) == 1


@pytest.mark.parametrize(
    "status,body",
    [
        (401, {}),
        (200, {"code": 403, "message": "secret-private-provider-message"}),
        (200, {"code": 200, "data": None}),
    ],
)
def test_provider_errors_do_not_echo_account_or_secrets(monkeypatch, status, body):
    class Client:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def send(self, request):
            return httpx.Response(status, json=body, request=request)

    monkeypatch.setattr("commander.dynadot.httpx.AsyncClient", Client)
    with pytest.raises(DynadotError) as error:
        asyncio.run(Dynadot("private-key", "private-secret").get("/accounts/info"))
    assert "private" not in str(error.value)


@pytest.mark.parametrize(
    "path",
    [
        "/domains/example.com/transfer_auth_code",
        "/domains/../records",
        "//evil.example/accounts/info",
        "/orders",
        "/domains/example.com/records?x=1",
    ],
)
def test_inventory_rejects_other_paths(path):
    with pytest.raises(ValueError):
        asyncio.run(Dynadot("key", "secret").get(path))
