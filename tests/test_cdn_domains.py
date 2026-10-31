import asyncio
from datetime import timedelta
from unittest.mock import AsyncMock

import httpx
import pytest
from sqlalchemy import select

from commander import cdn_domains as cdn
from commander.database import Agent, ControlTask, Integration, SystemSetting, utcnow
from commander.vault import encrypt


def setup(db):
    agent = Agent(
        id="cdn",
        name="CDN",
        token_hash="cdn",
        configuration={"monitoring_mode": "cdn_web"},
    )
    db.add(agent)
    db.add(
        SystemSetting(
            key="cdn-bind:cdn",
            value={
                "source_host": "lt.vetka.rest",
                "resource_id": 42,
                "cname": "cl-example.gcdn.co",
                "gcore_id": "g",
                "dns_id": "d",
                "ssh_id": "ssh",
            },
        )
    )
    db.commit()
    return agent


@pytest.mark.parametrize(
    "name",
    [
        "vetka.rest",
        "admin",
        "other.example.org",
        "*.vetka.rest",
        "a.b.vetka.rest",
        "lt1;reboot",
        "https://lt1.vetka.rest",
        "",
    ],
)
def test_hostname_scope(name):
    with pytest.raises(ValueError):
        cdn.hostname(name)


def test_confirm_bound_to_user_and_single_use(db):
    setup(db)
    task = cdn.create(db, "cdn", "LT1", 1)
    db.commit()
    assert task.payload["hostname"] == "lt1.vetka.rest"
    with pytest.raises(cdn.AliasError):
        cdn.confirm(db, task.id, 2)
    cdn.confirm(db, task.id, 1)
    db.commit()
    with pytest.raises(cdn.AliasError):
        cdn.confirm(db, task.id, 1)
    assert cdn.create(db, "cdn", "lt1", 1).id == task.id
    with pytest.raises(cdn.AliasError):
        cdn.create(db, "cdn", "lt2", 1)


def test_expired_draft_and_revoked_agent(db):
    a = setup(db)
    t = cdn.create(db, "cdn", "lt1", 1)
    t.payload = {**t.payload, "expires": (utcnow() - timedelta(seconds=1)).isoformat()}
    db.commit()
    with pytest.raises(cdn.AliasError):
        cdn.confirm(db, t.id, 1)
    a.revoked = True
    db.commit()
    with pytest.raises(cdn.AliasError):
        cdn.create(db, "cdn", "lt2", 1)


ZONE = {
    "glue_info": {
        "glue_type": "DNS",
        "ttl": 300,
        "dns_main_list": [{"record_type": "txt", "record_value1": "keep"}],
        "dns_sub_list": [
            {
                "sub_host": "lt",
                "record_type": "cname",
                "record_value1": "cl-example.gcdn.co",
            }
        ],
    }
}


def test_cname_appends_only_one_record_and_reconciles(monkeypatch):
    import copy

    before = cdn.snapshot(ZONE)
    record = {
        "sub_host": "lt1",
        "record_type": "cname",
        "record_value1": "cl-example.gcdn.co",
    }
    after = copy.deepcopy(ZONE)
    after["glue_info"]["dns_sub_list"].append(record)
    dns = cdn.CnameDNS("private-key", "private-secret")
    dns.records = AsyncMock(side_effect=[ZONE, after, after])
    calls = []

    def handle(request):
        calls.append(request)
        assert request.method == "POST"
        # Dynadot returns HTTP 200 / envelope code 400 for the default Accept: */*.
        assert request.headers["Accept"] == "application/json"
        body = __import__("json").loads(request.content)
        assert body == {
            "dns_sub_list": [record],
            "ttl": 300,
            "add_dns_to_current_setting": True,
        }
        assert request.url.path == "/restful/v2/domains/vetka.rest/records"
        return httpx.Response(200, json={"code": "200"})

    original = httpx.AsyncClient
    monkeypatch.setattr(
        cdn.httpx,
        "AsyncClient",
        lambda **kw: original(transport=httpx.MockTransport(handle), **kw),
    )
    asyncio.run(dns.append("lt1", "cl-example.gcdn.co", before))
    asyncio.run(dns.append("lt1", "cl-example.gcdn.co", before))
    assert len(calls) == 1


def test_cname_conflict_never_writes():
    dns = cdn.CnameDNS("key", "secret")
    dns.records = AsyncMock(return_value=ZONE)
    with pytest.raises(cdn.AliasError):
        asyncio.run(dns.append("lt", "cl-other.gcdn.co", cdn.snapshot(ZONE)))


def test_task_restarts_from_checkpoint_and_waits_for_tls(client, monkeypatch):
    factory = client.factory
    monkeypatch.setattr(cdn, "SessionLocal", factory)
    monkeypatch.setattr(cdn, "node", AsyncMock())
    monkeypatch.setattr(cdn, "tls_ready", AsyncMock(return_value=False))
    with factory() as db:
        setup(db)
        for identifier, kind, credentials in [
            ("g", "gcore", {"api_key": "k"}),
            ("d", "dynadot", {"api_key": "k", "api_secret": "s"}),
        ]:
            db.add(
                Integration(
                    id=identifier,
                    kind=kind,
                    name=kind,
                    ciphertext=encrypt(identifier, kind, credentials),
                )
            )
        task = cdn.create(db, "cdn", "lt1", 1)
        db.flush()
        cdn.confirm(db, task.id, 1)
        task.payload = {**task.payload, "stage": "TLS"}
        db.commit()
        tid = task.id
    assert asyncio.run(cdn.tick())
    assert not asyncio.run(cdn.tick())  # durable next_at, no busy polling/reissue
    with factory() as db:
        task = db.get(ControlTask, tid)
        assert task.status == "queued" and task.payload["stage"] == "TLS"
        task.payload = {**task.payload, "next_at": None}
        db.commit()
    monkeypatch.setattr(cdn, "tls_ready", AsyncMock(return_value=True))
    for _ in range(3):
        assert asyncio.run(cdn.tick())
    with factory() as db:
        task = db.get(ControlTask, tid)
        assert task.status == "succeeded" and task.payload["stage"] == "DONE"
        assert "передачу данных" in task.result["message"]
    assert cdn.node.await_count == 2


def test_unknown_dns_write_is_not_repeated(client, monkeypatch):
    factory = client.factory
    monkeypatch.setattr(cdn, "SessionLocal", factory)
    monkeypatch.setattr(cdn.CnameDNS, "records", AsyncMock(return_value=ZONE))
    append = AsyncMock()
    monkeypatch.setattr(cdn.CnameDNS, "append", append)
    with factory() as db:
        setup(db)
        for identifier, kind, credentials in [
            ("g", "gcore", {"api_key": "k"}),
            ("d", "dynadot", {"api_key": "k", "api_secret": "s"}),
        ]:
            db.add(
                Integration(
                    id=identifier,
                    kind=kind,
                    name=kind,
                    ciphertext=encrypt(identifier, kind, credentials),
                )
            )
        t = cdn.create(db, "cdn", "lt1", 1)
        db.flush()
        cdn.confirm(db, t.id, 1)
        t.payload = {
            **t.payload,
            "stage": "DNS",
            "dns_pending": True,
            "dns_before": cdn.snapshot(ZONE),
        }
        db.commit()
    assert asyncio.run(cdn.tick())
    assert append.await_count == 0
    with factory() as db:
        assert db.scalar(select(ControlTask)).status == "manual"


def test_verification_program_uses_domain_bound_dd_capability(monkeypatch):
    import base64
    import hashlib
    import hmac
    import io
    import urllib.parse
    import urllib.request
    from pathlib import Path

    secret = "ab" * 16
    config = (
        '[access.users]\nhello="'
        + secret
        + '"\n[[web.vhosts]]\nhost="lt1.vetka.rest"\n[[web.vhosts.profiles]]\nuser="hello"\nsecret_mode="dd"\n'
    )
    monkeypatch.setattr(Path, "read_text", lambda self: config)
    expected = (
        base64.urlsafe_b64encode(
            hmac.new(
                bytes([221]) + bytes.fromhex(secret),
                b"tdesktop-web-proxy-bridge-v1\nlt1.vetka.rest",
                hashlib.sha256,
            ).digest()
        )
        .decode()
        .rstrip("=")
    )

    class Response(io.BytesIO):
        status = 200
        headers = {"Content-Security-Policy": "default-src 'none'"}

    def request(url, timeout):
        assert urllib.parse.urlparse(url).netloc == "lt1.vetka.rest"
        assert urllib.parse.parse_qs(urllib.parse.urlparse(url).query) == {
            "bridge": [expected]
        }
        return Response(b"bootstrap")

    monkeypatch.setattr(urllib.request, "urlopen", request)
    output = io.StringIO()
    monkeypatch.setattr("sys.stdout", output)
    exec(
        compile(
            cdn.VERIFY_PROGRAM.replace("__HOST__", repr("lt1.vetka.rest")),
            "verify",
            "exec",
        ),
        {},
    )
    assert output.getvalue() == "VERIFIED\n"


def test_bot_confirmation_and_stop_use_shared_service(db, monkeypatch):
    from commander import bot
    from commander.config import settings
    from types import SimpleNamespace

    monkeypatch.setattr(settings, "telegram_admin_ids", [1])
    setup(db)
    t = cdn.create(db, "cdn", "lt1", 1)
    db.flush()
    text, markup = bot.cdn_task_view(db, 1, t)
    assert "перерыв" in text
    token = markup.inline_keyboard[0][0].callback_data[2:]
    item = bot.consume_action(db, 1, token)
    bot.dispatch_action(db, 1, item)
    db.commit()
    assert t.status == "queued"
    with pytest.raises(__import__("fastapi").HTTPException):
        bot.consume_action(db, 1, token)
    bot.dispatch_action(db, 1, SimpleNamespace(action="cdn_stop", target=t.id))
    db.commit()
    assert t.status == "cancelled"


def test_gcore_reorders_aliases_without_losing_existing_names(client, monkeypatch):
    factory = client.factory
    monkeypatch.setattr(cdn, "SessionLocal", factory)
    resource = {
        "active": True,
        "sslEnabled": True,
        "sslData": 1,
        "cname": "lt.vetka.rest",
        "secondaryHostnames": ["test-lt.vetka.rest"],
        "options": {
            "forward_host_header": {"enabled": True, "value": True},
            "sni": {
                "enabled": True,
                "sni_type": "custom",
                "custom_hostname": "lt.vetka.rest",
            },
        },
    }
    sorted_readback = {
        **resource,
        "secondaryHostnames": ["lt1.vetka.rest", "test-lt.vetka.rest"],
    }
    call = AsyncMock(side_effect=[resource, {}, sorted_readback])
    monkeypatch.setattr(cdn.Gcore, "call", call)
    with factory() as db:
        setup(db)
        for identifier, kind, credentials in [
            ("g", "gcore", {"api_key": "k"}),
            ("d", "dynadot", {"api_key": "k", "api_secret": "s"}),
        ]:
            db.add(
                Integration(
                    id=identifier,
                    kind=kind,
                    name=kind,
                    ciphertext=encrypt(identifier, kind, credentials),
                )
            )
        t = cdn.create(db, "cdn", "lt1", 1)
        db.flush()
        cdn.confirm(db, t.id, 1)
        t.payload = {**t.payload, "stage": "GCORE", "aliases": ["test-lt.vetka.rest"]}
        db.commit()
        tid = t.id
    assert asyncio.run(cdn.tick())
    with factory() as db:
        t = db.get(ControlTask, tid)
        assert t.status == "queued" and t.payload["stage"] == "TLS"
    assert call.await_args_list[1].kwargs["json"] == {
        "secondaryHostnames": ["test-lt.vetka.rest", "lt1.vetka.rest"]
    }


def test_dns_wait_never_issues_certificate_while_unresolved(client, monkeypatch):
    factory = client.factory
    monkeypatch.setattr(cdn, "SessionLocal", factory)
    monkeypatch.setattr(cdn, "dns_ready", AsyncMock(return_value=False))
    call = AsyncMock()
    monkeypatch.setattr(cdn.Gcore, "call", call)
    with factory() as db:
        setup(db)
        for identifier, kind, credentials in [
            ("g", "gcore", {"api_key": "k"}),
            ("d", "dynadot", {"api_key": "k", "api_secret": "s"}),
        ]:
            db.add(
                Integration(
                    id=identifier,
                    kind=kind,
                    name=kind,
                    ciphertext=encrypt(identifier, kind, credentials),
                )
            )
        t = cdn.create(db, "cdn", "lt1", 1)
        db.flush()
        cdn.confirm(db, t.id, 1)
        t.payload = {**t.payload, "stage": "DNS_WAIT"}
        db.commit()
    assert asyncio.run(cdn.tick())
    assert call.await_count == 0
    with factory() as db:
        t = db.scalar(select(ControlTask))
        assert t.status == "queued" and t.payload["next_at"]
