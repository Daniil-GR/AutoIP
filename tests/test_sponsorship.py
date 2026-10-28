import asyncio
from types import SimpleNamespace

import pytest

from commander.sponsorship import (
    ManualRequired,
    expects,
    matching_button,
    parse_tag,
    register,
)


def test_tag_parser_does_not_treat_user_secret_as_ad_tag():
    secret = "1" * 32
    tag = "a" * 32
    assert (
        parse_tag("Here is your proxy tag: " + tag + "\nsecret=" + secret, secret)
        == tag
    )
    with pytest.raises(ManualRequired):
        parse_tag("secret=" + secret, secret)
    with pytest.raises(ManualRequired):
        parse_tag("tag: " + secret, secret)
    with pytest.raises(ManualRequired):
        parse_tag("tag: " + tag + "\ntag: " + "b" * 32, secret)


def test_expected_prompts_and_exact_proxy_selection():
    assert expects("Please send your IP address and port", "endpoint")
    assert expects("Send the secret", "secret")
    assert not expects("Invalid secret", "secret")
    message = SimpleNamespace(
        buttons=[
            [SimpleNamespace(text="1.1.1.1:443"), SimpleNamespace(text="11.1.1.1:443")]
        ]
    )
    assert matching_button(message, lambda label: label == "1.1.1.1:443") == (0, 0)
    with pytest.raises(ManualRequired):
        matching_button(message, lambda label: "1.1.1.1" in label)


def test_registration_stops_before_sending_secret_on_unknown_prompt():
    sent = []
    checkpoints = []

    class Conversation:
        async def send_message(self, value):
            sent.append(value)

        async def get_response(self):
            return SimpleNamespace(
                raw_text="Unexpected interface, please contact support"
            )

    async def checkpoint(*value):
        checkpoints.append(value)

    with pytest.raises(ManualRequired):
        asyncio.run(register(Conversation(), "1.1.1.1:443", "1" * 32, checkpoint))
    assert sent == ["/newproxy"]
    assert checkpoints == [("REGISTRATION_SUBMITTING",)]


def test_registration_flow_checkpoints_tag_without_persisting_secret():
    sent = []
    checkpoints = []

    class Conversation:
        def __init__(self):
            self.replies = iter(
                [
                    "Send IP address and port",
                    "Send the secret",
                    "Here is the proxy tag: " + "a" * 32,
                ]
            )

        async def send_message(self, value):
            sent.append(value)

        async def get_response(self):
            return SimpleNamespace(raw_text=next(self.replies))

    async def checkpoint(*value):
        checkpoints.append(value)

    result = asyncio.run(register(Conversation(), "1.1.1.1:443", "1" * 32, checkpoint))
    assert result == "a" * 32 and sent == ["/newproxy", "1.1.1.1:443", "1" * 32]
    assert "1" * 32 not in str(checkpoints)
    assert checkpoints[-1] == ("REGISTERED", "a" * 32)


@pytest.mark.parametrize("needs_2fa", [False, True])
def test_stored_pending_credentials_do_not_reprompt_or_create_duplicate(
    db, monkeypatch, tmp_path, needs_2fa
):
    from contextlib import nullcontext
    from types import SimpleNamespace
    from sqlalchemy.orm import sessionmaker
    from commander import sponsorship
    from commander.config import settings
    from commander.database import Integration
    from commander.vault import encrypt, decrypt, initialize

    key = tmp_path / "key"
    initialize(key)
    monkeypatch.setattr(settings, "vault_key_file", str(key))
    credentials = {"api_id": "12345", "api_hash": "a" * 32, "phone": "+15551234567"}
    item = Integration(
        id="pending-account",
        name="Dedicated",
        kind="telethon",
        ciphertext=encrypt("pending-account", "telethon", credentials),
        metadata_json={},
        status="authorization_required",
    )
    db.add(item)
    db.commit()
    prompts = []
    sent = []
    authorized = [False]

    class Client:
        def __init__(self, *args):
            self.session = SimpleNamespace(save=lambda: "fake-encrypted-session-input")

        async def connect(self):
            pass

        async def disconnect(self):
            pass

        async def is_user_authorized(self):
            return authorized[0]

        async def send_code_request(self, phone):
            sent.append(phone)
            return SimpleNamespace(phone_code_hash="transient-hash")

        async def sign_in(self, *args, **kwargs):
            if needs_2fa and "password" not in kwargs:
                from telethon.errors import SessionPasswordNeededError

                raise SessionPasswordNeededError(request=None)
            authorized[0] = True

    def hidden(prompt):
        prompts.append(prompt)
        return "12345"

    monkeypatch.setattr(
        sponsorship, "SessionLocal", sessionmaker(db.bind, expire_on_commit=False)
    )
    monkeypatch.setattr(sponsorship, "TelegramClient", Client)
    monkeypatch.setattr(sponsorship, "account_lock", lambda _: nullcontext())
    monkeypatch.setattr("getpass.getpass", hidden)
    monkeypatch.setattr("sys.stdin", SimpleNamespace(isatty=lambda: True))
    result = asyncio.run(sponsorship.authorize_local(integration_id="pending-account"))
    db.expire_all()
    stored = db.get(Integration, "pending-account")
    assert result == "pending-account" and stored.status == "verified"
    assert len(prompts) == 1 + int(needs_2fa) and "Код Telegram" in prompts[0]
    if needs_2fa:
        assert "Пароль 2FA" in prompts[1]
    assert sent == ["+15551234567"]
    assert decrypt(stored)["session"] == "fake-encrypted-session-input"
    assert db.query(Integration).count() == 1


def test_pending_telethon_connection_test_does_not_send_auth_code():
    from commander.providers import test_connection

    report = asyncio.run(
        test_connection(
            "telethon",
            {"api_id": "12345", "api_hash": "a" * 32, "phone": "+15551234567"},
        )
    )
    assert report["ok"] is False and report["status"] == "authorization_required"


def test_telethon_rejects_noninteractive_secret_input(monkeypatch):
    from commander.sponsorship import authorize_local

    monkeypatch.setattr("sys.stdin", SimpleNamespace(isatty=lambda: False))
    with pytest.raises(ManualRequired, match="интерактивный терминал"):
        asyncio.run(authorize_local(integration_id="no-network-call"))
