import asyncio
import json
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy.orm import sessionmaker

from commander.database import Agent, Integration, SystemSetting, utcnow
from commander.schemas import AgentConfiguration
from commander import vps_bootstrap as bootstrap
from commander.nodehost import NodeHostError


def test_enrollment_persists_selected_mode_without_credentials(client):
    issued = client.post(
        "/api/enrollments",
        auth=client.auth_pair,
        json={"name": "FakeTLS node", "proxy_mode": "mtproto_faketls"},
    )
    assert issued.status_code == 200
    token = issued.json()["token"]
    enrolled = client.post(
        "/api/agent/enroll", json={"token": token, "machine_id": "mode-test-node"}
    )
    assert enrolled.status_code == 200
    config = client.get(
        "/api/agents/" + enrolled.json()["agent_id"] + "/configuration",
        auth=client.auth_pair,
    ).json()
    assert config["proxy_mode"] == "mtproto_faketls"
    assert config["mtproto_secret_format"] == "ee"
    assert config["sni_domain"] == "www.booking.com"
    assert not config["vps_profile_integration_id"]
    assert (
        client.post(
            "/api/agent/enroll", json={"token": token, "machine_id": "other-node"}
        ).status_code
        == 401
    )


def test_legacy_mode_and_active_node_are_preserved(client):
    with client.factory() as db:
        db.add(
            Agent(
                id="live",
                name="legacy",
                token_hash="legacy-hash",
                proxy_port=9443,
                configuration={},
                facts={"telemt_service": "active"},
            )
        )
        db.commit()
    response = client.get("/api/agents/live/configuration", auth=client.auth_pair)
    config = response.json()
    assert config["proxy_mode"] == "web_mtproto"
    config["proxy_mode"] = "mtproto_faketls"
    assert (
        client.put(
            "/api/agents/live/configuration", auth=client.auth_pair, json=config
        ).status_code
        == 409
    )
    with client.factory() as db:
        a = db.get(Agent, "live")
        assert a.configuration == {} and a.proxy_port == 9443


@pytest.mark.parametrize(
    "domain", ["vetka.rest", "outside.example", "x.vetka.rest.other.example", ""]
)
def test_profile_domain_scope(client, domain):
    response = client.post(
        "/api/integrations",
        auth=client.auth_pair,
        json={
            "name": "FakeTLS profile",
            "kind": "telemt_profile",
            "credentials": {
                "domain": domain,
                "proxy_mode": "mtproto_faketls",
                "secret": "a" * 32,
                "ad_tag": "b" * 32,
            },
        },
    )
    assert response.status_code == 422


def test_new_profile_is_encrypted_and_mode_must_match_node(client):
    secret, tag = "a" * 32, "b" * 32
    response = client.post(
        "/api/integrations",
        auth=client.auth_pair,
        json={
            "name": "new node profile",
            "kind": "telemt_profile",
            "credentials": {
                "domain": "new.vetka.rest",
                "proxy_mode": "mtproto_faketls",
                "secret": secret,
                "ad_tag": tag,
            },
        },
    )
    assert response.status_code == 200
    profile_id = response.json()["id"]
    assert secret not in response.text and tag not in response.text
    with client.factory() as db:
        p = db.get(Integration, profile_id)
        assert secret not in p.ciphertext and tag not in p.ciphertext
        db.add(
            Agent(
                id="new",
                name="new",
                token_hash="new-mode-hash",
                configuration={},
                facts={},
            )
        )
        db.commit()
    path = "/api/agents/new/configuration"
    config = {
        "provider": "nodehost",
        "vps_profile_integration_id": profile_id,
        "dns_record": "new.vetka.rest",
    }
    assert client.put(path, auth=client.auth_pair, json=config).status_code == 422
    config["proxy_mode"] = "mtproto_faketls"
    assert client.put(path, auth=client.auth_pair, json=config).status_code == 200
    config["dns_record"] = "different.vetka.rest"
    assert client.put(path, auth=client.auth_pair, json=config).status_code == 422
    assert secret not in client.get("/api/integrations", auth=client.auth_pair).text


def test_faketls_cannot_be_saved_with_web_or_different_sni():
    for extra in (
        {"web_proxy_host": "web.example.com"},
        {"sni_domain": "other.example.com"},
    ):
        with pytest.raises(ValueError):
            AgentConfiguration(proxy_mode="mtproto_faketls", **extra)


def preflight():
    return {
        "checked_at": utcnow().isoformat(),
        "report": {
            "source": "check-host",
            "status": "observed",
            "target": "8.8.8.8",
            "port": 22,
            "observations": [
                {"country": c, "asn": asn, "protocol": "tcp", "state": "reachable"}
                for c, asn in [
                    ("RU", "AS1"),
                    ("RU", "AS2"),
                    ("DE", "AS3"),
                    ("NL", "AS4"),
                    ("FR", "AS5"),
                ]
            ],
        },
    }


def seed_bootstrap(db, monkeypatch, mode):
    data = {"domain": "new.vetka.rest", "secret": "a" * 32, "ad_tag": "b" * 32}
    if mode:
        data["proxy_mode"] = mode
    for identifier, kind in [("access", "vps_access"), ("profile", "telemt_profile")]:
        db.add(
            Integration(
                id=identifier,
                name=identifier,
                kind=kind,
                ciphertext="encrypted",
                metadata_json={},
            )
        )
    db.add(
        SystemSetting(
            key="vps-receipt:1",
            value={
                "managed": True,
                "credential_id": "access",
                "created_at": (utcnow() - timedelta(minutes=6)).isoformat(),
                "ssh_rounds": [preflight()],
            },
        )
    )
    db.commit()
    monkeypatch.setattr(
        bootstrap, "SessionLocal", sessionmaker(db.bind, expire_on_commit=False)
    )
    monkeypatch.setattr(
        bootstrap,
        "decrypt",
        lambda i: {"ipv4": "8.8.8.8"} if i.id == "access" else dict(data),
    )
    return data


class Remote:
    def __init__(self, dirty=False):
        self.files = {}
        self.commands = []
        self.modes = {}
        self.dirty = dirty

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    def start_sftp_client(self):
        return self

    def open(self, name, mode):
        remote = self

        class File:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def write(self, content):
                remote.files[name] = content

        return File()

    async def chmod(self, name, mode):
        self.modes[name] = mode

    async def run(self, command, **kw):
        self.commands.append(command)
        return SimpleNamespace(exit_status=int(self.dirty))


@pytest.mark.parametrize("mode,port", [("mtproto_faketls", 443), (None, 9443)])
def test_bootstrap_uses_selected_installer_without_secret_arguments(
    db, monkeypatch, mode, port
):
    data = seed_bootstrap(db, monkeypatch, mode)
    remote = Remote()
    monkeypatch.setattr(bootstrap, "connect", AsyncMock(return_value=remote))
    fetched = AsyncMock(return_value=(b"#!/usr/bin/env bash\n", "test-digest"))
    monkeypatch.setattr(bootstrap, "installer", fetched)
    result = asyncio.run(
        bootstrap.start_install("access", "profile", str(uuid4()), approved=True)
    )
    assert result["port"] == port
    fetched.assert_awaited_once_with(mode or "web_mtproto")
    assert all(
        data["secret"] not in c and data["ad_tag"] not in c for c in remote.commands
    )
    assert "new.vetka.rest" in remote.commands[-1]
    assert "pl.vetka.rest" not in remote.commands[-1]
    assert set(remote.modes.values()) == {0o600}
    assert json.loads(remote.files["/var/lib/autoip-vps/profile.json"]) == data
    assert json.loads(remote.files["/var/lib/autoip-vps/mode.json"])["proxy_mode"] == (
        mode or "web_mtproto"
    )
    compile(remote.files["/var/lib/autoip-vps/apply.py"], "remote-apply", "exec")


def test_dirty_vps_and_stale_preflight_do_not_start_install(db, monkeypatch):
    seed_bootstrap(db, monkeypatch, "mtproto_faketls")
    remote = Remote(dirty=True)
    connect = AsyncMock(return_value=remote)
    monkeypatch.setattr(bootstrap, "connect", connect)
    monkeypatch.setattr(
        bootstrap,
        "installer",
        AsyncMock(return_value=(b"#!/usr/bin/env bash\n", "digest")),
    )
    with pytest.raises(NodeHostError, match="не чистый"):
        asyncio.run(
            bootstrap.start_install("access", "profile", str(uuid4()), approved=True)
        )
    assert not remote.files and len(remote.commands) == 1
    r = db.get(SystemSetting, "vps-receipt:1")
    r.value = {**r.value, "ssh_rounds": []}
    db.commit()
    connect.reset_mock()
    with pytest.raises(NodeHostError, match="свежая"):
        asyncio.run(
            bootstrap.start_install("access", "profile", str(uuid4()), approved=True)
        )
    connect.assert_not_awaited()


def test_fake_tls_installer_is_pinned_and_tampering_rejected(monkeypatch):
    urls = []

    class Client:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def get(self, url):
            urls.append(url)
            return SimpleNamespace(
                content=b"#!/usr/bin/env bash\nchanged", raise_for_status=lambda: None
            )

    monkeypatch.setattr(bootstrap.httpx, "AsyncClient", Client)
    with pytest.raises(NodeHostError, match="Неверный файл"):
        asyncio.run(bootstrap.installer("mtproto_faketls"))
    assert urls == [bootstrap.MTPROTO_INSTALLER_URL]
    assert bootstrap.MTPROTO_INSTALLER_COMMIT in urls[0]


def test_faketls_monitoring_uses_ee_443_and_skips_web_even_with_stale_settings(
    client, monkeypatch
):
    from commander import monitoring
    from commander.vault import encrypt

    with client.factory() as db:
        db.add_all(
            [
                Integration(
                    id="checker",
                    name="checker",
                    kind="mtproto_checker",
                    ciphertext=encrypt(
                        "checker", "mtproto_checker", {"api_key": "fixture-key"}
                    ),
                ),
                Integration(
                    id="profile",
                    name="profile",
                    kind="telemt_profile",
                    ciphertext=encrypt(
                        "profile",
                        "telemt_profile",
                        {
                            "domain": "new.vetka.rest",
                            "proxy_mode": "mtproto_faketls",
                            "secret": "a" * 32,
                            "ad_tag": "b" * 32,
                        },
                    ),
                ),
                Agent(
                    id="fake",
                    name="fake",
                    token_hash="fake-tls-monitor",
                    public_host="new.vetka.rest",
                    proxy_port=443,
                    facts={},
                    configuration={
                        "proxy_mode": "mtproto_faketls",
                        "checker_integration_id": "checker",
                        "vps_profile_integration_id": "profile",
                        "web_proxy_host": "stale.example.com",
                        "mtproto_secret_format": "dd",
                    },
                ),
            ]
        )
        db.commit()
    calls = []

    async def measured(self, target, port):
        assert self.secret == "ee" + "a" * 32 + "www.booking.com".encode().hex()
        calls.append((target, port))
        return {
            "source": "mtproto-checker",
            "provider_status": "OK",
            "mtproto_verified": True,
            "observations": [],
        }

    no_web = AsyncMock(side_effect=AssertionError("No Web request allowed"))
    monkeypatch.setattr(monitoring, "SessionLocal", client.factory)
    monkeypatch.setattr(monitoring.MTProtoChecker, "check", measured)
    monkeypatch.setattr(monitoring.CheckHost, "check", no_web)
    r = asyncio.run(monitoring.collect_agent("fake", "new.vetka.rest", 443, "8.8.8.8"))
    assert calls == [("8.8.8.8", 443)] and r["mtproto_verified"]
    assert "web_endpoint" not in r
    no_web.assert_not_awaited()
    calls.clear()
    r = asyncio.run(monitoring.checker_report("fake", "8.8.8.8", 9443))
    assert r["error"] == "configuration_error" and not calls
