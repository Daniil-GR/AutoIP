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
@pytest.mark.parametrize(
    "qr,wrong_account", [(False, False), (True, False), (True, True)]
)
def test_stored_pending_credentials_do_not_reprompt_or_create_duplicate(
    db, monkeypatch, tmp_path, needs_2fa, qr, wrong_account
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
    logged_out = []

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
            from telethon.tl.types.auth import SentCode, SentCodeTypeApp

            sent.append(phone)
            return SentCode(SentCodeTypeApp(5), "transient-hash")

        async def sign_in(self, *args, **kwargs):
            if needs_2fa and "password" not in kwargs:
                from telethon.errors import SessionPasswordNeededError

                raise SessionPasswordNeededError(request=None)
            authorized[0] = True

        async def get_me(self):
            return SimpleNamespace(
                phone="15550000000" if wrong_account else "15551234567"
            )

        async def log_out(self):
            logged_out.append(True)
            authorized[0] = False

    async def scan(client):
        if needs_2fa:
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
    monkeypatch.setattr(sponsorship, "authorize_qr", scan)
    monkeypatch.setattr("getpass.getpass", hidden)
    monkeypatch.setattr("sys.stdin", SimpleNamespace(isatty=lambda: True))
    if wrong_account:
        with pytest.raises(ManualRequired, match="другим аккаунтом"):
            asyncio.run(
                sponsorship.authorize_local(integration_id="pending-account", qr=qr)
            )
        db.expire_all()
        stored = db.get(Integration, "pending-account")
        assert stored.status == "authorization_required"
        assert decrypt(stored) == credentials
        assert logged_out == [True]
        assert sent == []
        return
    result = asyncio.run(
        sponsorship.authorize_local(integration_id="pending-account", qr=qr)
    )
    db.expire_all()
    stored = db.get(Integration, "pending-account")
    assert result == "pending-account" and stored.status == "verified"
    assert len(prompts) == int(not qr) + int(needs_2fa)
    if not qr:
        assert "Код Telegram" in prompts[0]
    if needs_2fa:
        assert "Пароль 2FA" in prompts[-1]
    assert sent == ([] if qr else ["+15551234567"])
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


def test_sponsor_pending_account_stops_before_dialog_or_state_write(
    db, monkeypatch, tmp_path
):
    from sqlalchemy.orm import sessionmaker
    from commander import sponsorship
    from commander.config import settings
    from commander.database import Agent, Integration, Sponsorship
    from commander.vault import encrypt, initialize

    key = tmp_path / "key"
    initialize(key)
    monkeypatch.setattr(settings, "vault_key_file", str(key))
    for identifier, kind, credentials in [
        (
            "account",
            "telethon",
            {"api_id": "12345", "api_hash": "a" * 32, "phone": "+15551234567"},
        ),
        ("proxy-secret", "mtproto", {"secret": "b" * 32}),
    ]:
        db.add(
            Integration(
                id=identifier,
                kind=kind,
                name=identifier,
                ciphertext=encrypt(identifier, kind, credentials),
                metadata_json={},
            )
        )
    db.add(
        Agent(
            id="one",
            name="Test",
            token_hash="unused-token-hash",
            configuration={
                "telethon_integration_id": "account",
                "mtproto_integration_id": "proxy-secret",
                "floating_ip": "1.1.1.1",
                "sponsor_channel": "https://t.me/example",
            },
        )
    )
    db.commit()
    monkeypatch.setattr(
        sponsorship, "SessionLocal", sessionmaker(db.bind, expire_on_commit=False)
    )

    def forbidden_client(*args, **kwargs):
        raise AssertionError("Pending account must not contact Telegram")

    monkeypatch.setattr(sponsorship, "TelegramClient", forbidden_client)
    with pytest.raises(ManualRequired, match="ещё не авторизован"):
        asyncio.run(sponsorship.sponsor_agent("one", approve_new_registration=True))
    assert db.query(Sponsorship).count() == 0


def test_login_delivery_and_resend_respect_telegram_delay(monkeypatch, capsys):
    from commander import sponsorship
    from telethon.tl.types.auth import (
        SentCode,
        SentCodeTypeApp,
        SentCodeTypeSms,
        CodeTypeSms,
    )

    clock = [0.0]
    answers = iter(["", "", "54321"])
    requests = []
    initial = SentCode(
        SentCodeTypeApp(5), "first-private-hash", next_type=CodeTypeSms(), timeout=30
    )
    replacement = SentCode(SentCodeTypeSms(5), "replacement-private-hash")

    def hidden(_):
        value = next(answers)
        if len(requests) == 0 and clock[0] == 0:
            clock[0] = 10
        else:
            clock[0] = 31
        return value

    class Client:
        async def __call__(self, request):
            assert clock[0] >= 30
            requests.append(request)
            return replacement

    monkeypatch.setattr("getpass.getpass", hidden)
    monkeypatch.setattr(sponsorship.time, "monotonic", lambda: clock[0])
    result = asyncio.run(sponsorship.read_login_code(Client(), "+15551234567", initial))
    assert result == ("54321", "replacement-private-hash")
    assert len(requests) == 1 and requests[0].phone_code_hash == "first-private-hash"
    output = capsys.readouterr().out
    assert (
        "служебный чат Telegram" in output and "SMS" in output and "20 сек." in output
    )
    assert all(
        value not in output
        for value in (
            "54321",
            "first-private-hash",
            "replacement-private-hash",
            "+15551234567",
        )
    )


def test_login_never_resends_when_not_offered_or_already_resent(monkeypatch):
    from commander.sponsorship import read_login_code
    from telethon.tl.types.auth import SentCode, SentCodeTypeApp, CodeTypeSms

    monkeypatch.setattr("getpass.getpass", lambda _: "")
    requests = []

    class Client:
        async def __call__(self, request):
            requests.append(request)
            return SentCode(
                SentCodeTypeApp(5), "new", next_type=CodeTypeSms(), timeout=0
            )

    with pytest.raises(ManualRequired, match="отменён"):
        asyncio.run(
            read_login_code(
                Client(), "+15551234567", SentCode(SentCodeTypeApp(5), "old")
            )
        )
    assert not requests
    with pytest.raises(ManualRequired, match="отменён"):
        asyncio.run(
            read_login_code(
                Client(),
                "+15551234567",
                SentCode(SentCodeTypeApp(5), "old", next_type=CodeTypeSms(), timeout=0),
            )
        )
    assert len(requests) == 1


def test_login_unknown_delivery_does_not_prompt_or_dump_response(monkeypatch):
    from commander.sponsorship import read_login_code

    def no_prompt(_):
        pytest.fail("Unsupported delivery must not request a code")

    monkeypatch.setattr("getpass.getpass", no_prompt)
    with pytest.raises(ManualRequired, match="не поддерживает"):
        asyncio.run(
            read_login_code(
                None,
                "private-phone",
                SimpleNamespace(type=object(), phone_code_hash="private-hash"),
            )
        )


def test_qr_timeout_is_bounded_and_does_not_print_login_url(monkeypatch, capsys):
    import qrcode
    from commander.sponsorship import authorize_qr

    printed = []
    monkeypatch.setattr("builtins.input", lambda _: "")

    class QR:
        url = "tg://login?token=private-one-time-token"

        async def wait(self, timeout):
            assert timeout == 60
            raise asyncio.TimeoutError

    class Client:
        async def qr_login(self):
            return QR()

    monkeypatch.setattr(
        qrcode.QRCode, "print_ascii", lambda self, **kwargs: printed.append(True)
    )
    with pytest.raises(ManualRequired, match="QR истёк"):
        asyncio.run(authorize_qr(Client()))
    assert printed == [True]
    assert "private-one-time-token" not in capsys.readouterr().out
