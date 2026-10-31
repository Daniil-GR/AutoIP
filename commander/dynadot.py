"""Signed Dynadot v2 inventory. Intentionally exposes GET operations only."""

import base64
import hashlib
import hmac
from uuid import uuid4

import httpx

from .dns_scope import MANAGED_DNS_ZONE, managed_zone


class DynadotError(RuntimeError):
    def __init__(self, status=None):
        self.status = (
            int(status) if str(status).isdigit() and 100 <= int(status) <= 599 else None
        )
        super().__init__("Dynadot API отклонил запрос или недоступен")


def signature(api_key, api_secret, path_and_query, request_id, body=""):
    message = f"{api_key}\n{path_and_query}\n{request_id}\n{body}"
    digest = hmac.new(api_secret.encode(), message.encode(), hashlib.sha256).digest()
    return base64.b64encode(digest).decode()


class Dynadot:
    def __init__(self, api_key, api_secret):
        self.api_key, self.api_secret = api_key, api_secret

    async def get(self, path, params=None):
        if params or path not in (
            "/accounts/info",
            f"/domains/{MANAGED_DNS_ZONE}/records",
        ):
            raise ValueError("Dynadot: доступ разрешён только к зоне vetka.rest")
        request_id = str(uuid4())
        request = httpx.Request(
            "GET", "https://api.dynadot.com/restful/v2" + path, params=params
        )
        request.headers.update(
            {
                "Accept": "application/json",
                "Authorization": "Bearer " + self.api_key,
                "X-Request-ID": request_id,
                "X-Signature": signature(
                    self.api_key,
                    self.api_secret,
                    request.url.raw_path.decode("ascii"),
                    request_id,
                ),
            }
        )
        try:
            async with httpx.AsyncClient(timeout=20, follow_redirects=False) as client:
                response = await client.send(request)
                response.raise_for_status()
                payload = response.json()
                if not isinstance(payload, dict) or str(payload.get("code")) != "200":
                    raise DynadotError(
                        payload.get("code") if isinstance(payload, dict) else None
                    )
                data = payload.get("data")
                if not isinstance(data, dict):
                    raise DynadotError()
                return data
        except httpx.HTTPStatusError as error:
            raise DynadotError(error.response.status_code) from None
        except (httpx.HTTPError, ValueError):
            # Do not log exception URLs/headers or provider account information.
            raise DynadotError() from None

    async def domains(self, page=1):
        if not 1 <= page <= 10000:
            raise ValueError("Некорректная страница")
        # Never enumerate the account: unrelated domains stay outside AutoIP.
        if page > 1:
            return {
                "domains": [],
                "pagination": {"has_next_page": False},
                "writes_enabled": False,
            }
        await self.records(MANAGED_DNS_ZONE)
        return {
            "domains": [{"domain_name": MANAGED_DNS_ZONE, "status": "accessible"}],
            "pagination": {"has_next_page": False},
            "writes_enabled": False,
        }

    async def records(self, domain):
        domain = managed_zone(domain)
        if not domain:
            raise ValueError("Требуется DNS-зона vetka.rest")
        return await self.get("/domains/" + domain + "/records")
