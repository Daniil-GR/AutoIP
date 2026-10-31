import asyncio
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import select

from commander import nodehost
from commander.database import Integration, SystemSetting, utcnow
from commander.vps_bootstrap import patch_profile, remote_patch_program
from commander.vps_preflight import assess

RECEIPT = """🖥 Ваш сервер успешно создан
IP адрес: 8.8.8.8
ОС: Ubuntu 24.04
Логин: root
Пароль: fixture-password-only
"""


def test_receipt_is_strict_and_access_repr_hides_password():
    access = nodehost.parse_access(RECEIPT)
    assert access.ipv4 == "8.8.8.8"
    assert access.password == "fixture-password-only"
    assert access.password not in repr(access)
    for wrong in (
        RECEIPT.replace("8.8.8.8", "127.0.0.1"),
        RECEIPT + "Пароль: other\n",
        RECEIPT.replace("Ubuntu 24.04", "Debian 12"),
        RECEIPT.replace("root", "user"),
    ):
        with pytest.raises(nodehost.NodeHostError):
            nodehost.parse_access(wrong)


def test_receipt_deduplicates_and_keeps_password_out_of_resource(db, monkeypatch):
    monkeypatch.setattr(nodehost, "encrypt", lambda *args: "encrypted-test-envelope")
    access = nodehost.parse_access(RECEIPT)
    one = nodehost.remember_receipt(db, "telegram", 50, access)
    db.flush()
    two = nodehost.remember_receipt(db, "telegram", 50, access)
    assert one == two and one["managed"] is False
    assert "password" not in str(one) and access.password not in str(one)
    assert db.query(Integration).count() == 1
    assert db.scalar(select(Integration)).ciphertext == "encrypted-test-envelope"
    with pytest.raises(nodehost.NodeHostError):
        nodehost.remember_receipt(db, "other-account", 50, access)


def test_financial_click_can_only_be_checkpointed_once(db):
    operation = str(uuid4())
    with pytest.raises(nodehost.NodeHostError):
        nodehost.financial_checkpoint(db, operation, "order", "quote")
    assert db.query(SystemSetting).count() == 0
    nodehost.financial_checkpoint(db, operation, "order", "quote", approved=True)
    with pytest.raises(nodehost.NodeHostError):
        nodehost.financial_checkpoint(db, operation, "order", "quote", approved=True)
    assert db.scalar(select(SystemSetting)).value["status"] == "SUBMITTING"


def test_refund_is_actual_report_not_assumed_remaining_credit():
    result = nodehost.refund_result(
        "✅ Сервер успешно удален!\nНа ваш баланс возвращено: 0.11$\nОсталось возвратов: 2"
    )
    assert result == {"deleted": True, "refund_usd": "0.11", "refunds_remaining": 2}
    assert nodehost.refund_result("Сервер успешно удален!")["refund_usd"] is None
    with pytest.raises(nodehost.NodeHostError):
        nodehost.refund_result("Возврат недоступен")


def test_inventory_extracts_specific_provider_ids_not_other_controls():
    def button(label, data):
        return SimpleNamespace(text=label, data=data)

    message = SimpleNamespace(
        raw_text="🖥 Ваши серверы:",
        buttons=[
            [
                button("🇵🇱 | 8.8.8.8 | Истечёт через 23 часа", b"select_order;123;1"),
                button("Назад", b"back"),
            ]
        ],
    )
    assert nodehost.inventory(message) == [{"provider_id": "123", "ipv4": "8.8.8.8"}]


def test_dialog_does_not_consume_unrelated_newer_reply(monkeypatch):
    def msg(text):
        return SimpleNamespace(
            id=20,
            raw_text=text,
            buttons=[[SimpleNamespace(text="Poland", data=b"select")]],
        )

    original, edited = msg("Locations"), msg("Configurator")

    async def click(*, data):
        assert data == b"select"

    original.click = click

    class Client:
        async def get_messages(self, peer, *, ids):
            assert peer == nodehost.BOT_ID and ids == 20
            return edited

    async def no_wait(_):
        pass

    monkeypatch.setattr(nodehost.asyncio, "sleep", no_wait)
    assert (
        asyncio.run(nodehost.click_edit(Client(), original, b"select")).raw_text
        == "Configurator"
    )


def test_profile_changes_only_two_selected_fields_and_preserves_structure():
    import tomllib

    text = """[general]
ad_tag = ""
[general.links]
public_host = "proxy.vetka.rest"
[access.users]
hello = "11111111111111111111111111111111"
other = "22222222222222222222222222222222"
[[server.listeners]]
ip="0.0.0.0"
port=9443
"""
    result = patch_profile(text, "a" * 32, "b" * 32)
    expected = tomllib.loads(text)
    expected["access"]["users"]["hello"] = "a" * 32
    expected["general"]["ad_tag"] = "b" * 32
    assert tomllib.loads(result) == expected
    assert "22222222222222222222222222222222" in result
    with pytest.raises(nodehost.NodeHostError):
        patch_profile(text.replace('ad_tag = ""', ""), "a" * 32, "b" * 32)
    with pytest.raises(nodehost.NodeHostError):
        patch_profile(text, '"; rm -rf /', "b" * 32)
    compile(remote_patch_program(), "remote-profile-patch", "exec")


def report(state="reachable", foreign=True):
    observations = [
        {
            "country": "RU",
            "asn": str(i),
            "protocol": "tcp",
            "state": state,
            "raw": [{"error": "Connection timed out"}],
        }
        for i in (1, 2)
    ]
    observations += [
        {"country": c, "protocol": "tcp", "state": "reachable"}
        for c in (("DE", "NL", "FR") if foreign else ("DE",))
    ]
    return {
        "source": "check-host",
        "status": "observed",
        "target": "8.8.8.8",
        "port": 22,
        "observations": observations,
    }


def test_ssh_preflight_waits_four_minutes_and_checks_three_distinct_countries(db):
    now = utcnow()
    assert assess(db, "8.8.8.8", now, [], now)["status"] == "BOOT_WAIT"
    created = now - timedelta(minutes=10)
    rounds = [{"checked_at": now.isoformat(), "report": report()}]
    result = assess(db, "8.8.8.8", created, rounds, now)
    assert result["status"] == "SSH_READY" and result["mtproto_verified"] is False
    rounds[0]["report"] = report(foreign=False)
    assert assess(db, "8.8.8.8", created, rounds, now)["status"] == "RECHECK"


def test_one_timeout_or_replayed_round_cannot_reject_an_ip(db):
    now = utcnow()
    created = now - timedelta(minutes=10)
    one = {"checked_at": now.isoformat(), "report": report("unknown")}
    assert assess(db, "8.8.8.8", created, [one], now)["status"] == "RECHECK"
    assert assess(db, "8.8.8.8", created, [one] * 3, now)["status"] == "RECHECK"
    rounds = [
        {
            "checked_at": (now - timedelta(minutes=i)).isoformat(),
            "report": report("unknown"),
        }
        for i in (2, 1, 0)
    ]
    assert assess(db, "8.8.8.8", created, rounds, now)["status"] == "REJECT_RU_FILTER"
    nodehost.record_block(db, "8.8.8.8", "owner")
    assert assess(db, "8.8.8.8", created, [], now)["status"] == "REJECT_HISTORY"


def test_cherry_adapter_rejects_nodehost_agent(db, setup=None):
    from commander.database import Agent
    from commander.floating_pilot import context, PilotError

    db.add(
        Agent(
            id="vps",
            name="VPS",
            token_hash="unique",
            configuration={"provider": "nodehost"},
        )
    )
    db.flush()
    with pytest.raises(PilotError, match="Cherry"):
        context(db, "vps")


def test_vps_routes_require_admin_and_reject_private_discovery_targets(client):
    assert client.get("/api/nodehost/resources").status_code == 401
    response = client.post(
        "/api/nodehost/discover",
        auth=client.auth_pair,
        json={"integration_id": "test", "addresses": ["127.0.0.1"]},
    )
    assert response.status_code == 422
    response = client.get("/api/nodehost/resources", auth=client.auth_pair)
    assert (
        response.status_code == 200
        and response.json()["automatic_purchases_enabled"] is False
    )


def test_profile_integration_is_encrypted_and_never_echoes_values(client):
    secret, tag = "a" * 32, "b" * 32
    response = client.post(
        "/api/integrations",
        auth=client.auth_pair,
        json={
            "name": "PL profile",
            "kind": "telemt_profile",
            "credentials": {"domain": "pl.vetka.rest", "secret": secret, "ad_tag": tag},
        },
    )
    assert response.status_code == 200
    assert secret not in response.text and tag not in response.text
    assert secret not in client.get("/api/integrations", auth=client.auth_pair).text
    response = client.post(
        "/api/integrations",
        auth=client.auth_pair,
        json={
            "name": "Wrong domain",
            "kind": "telemt_profile",
            "credentials": {"domain": "lt.vetka.rest", "secret": secret, "ad_tag": tag},
        },
    )
    assert response.status_code == 422


def test_ssh_first_pin_uses_supported_sdk_arguments_and_never_disables_verification(
    db, monkeypatch
):
    from sqlalchemy.orm import sessionmaker
    from commander import vps_bootstrap as bootstrap
    import asyncssh

    db.add(
        Integration(id="access", kind="vps_access", name="test", ciphertext="encrypted")
    )
    db.commit()
    data = {"ipv4": "8.8.8.8", "username": "root", "password": "test-only-password"}
    monkeypatch.setattr(
        bootstrap, "SessionLocal", sessionmaker(db.bind, expire_on_commit=False)
    )
    monkeypatch.setattr(bootstrap, "decrypt", lambda _: dict(data))
    monkeypatch.setattr(
        bootstrap,
        "encrypt",
        lambda _id, _kind, value: "encrypted-with-pin"
        if value.get("host_key")
        else "bad",
    )
    key = asyncssh.generate_private_key("ssh-ed25519").convert_to_public()

    async def get_key(host, port, *, config):
        assert host == "8.8.8.8" and port == 22 and config is None
        return key

    async def connect(host, **kwargs):
        assert kwargs["known_hosts"] is not None
        assert kwargs["client_keys"] == [] and kwargs["agent_path"] is None
        assert kwargs["password"] == data["password"]
        return "connected"

    monkeypatch.setattr(bootstrap.asyncssh, "get_server_host_key", get_key)
    monkeypatch.setattr(bootstrap.asyncssh, "connect", connect)
    assert asyncio.run(bootstrap.connect("access", allow_first_pin=True)) == "connected"
    db.expire_all()
    assert db.get(Integration, "access").ciphertext == "encrypted-with-pin"


@pytest.mark.parametrize(
    "notice,expected",
    [
        (
            "❌ Покупка серверов в выбранной локации временно недоступна",
            "временно отключил",
        ),
        ("private-account-secret", "неизвестное уведомление"),
    ],
)
def test_menu_alert_stops_before_polling_without_leaking_private_notice(
    notice, expected
):
    from commander.nodehost import click_edit, NodeHostError
    from types import SimpleNamespace

    async def click(**kwargs):
        return SimpleNamespace(alert=True, message=notice)

    class Client:
        async def get_messages(self, *args, **kwargs):
            raise AssertionError(
                "Availability alert must not wait for a nonexistent edit"
            )

    msg = SimpleNamespace(
        raw_text="Choose location",
        buttons=[
            [SimpleNamespace(text="Germany", data=b"select_configuration;1;Germany")]
        ],
        click=click,
    )
    with pytest.raises(NodeHostError, match=expected) as error:
        asyncio.run(click_edit(Client(), msg, b"select_configuration;1;Germany"))
    assert "private-account-secret" not in str(error.value)
