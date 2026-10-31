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
    assert expects(
        "Registering a new proxy server. Please send me its address in the format host:port.",
        "endpoint",
    )
    assert expects("Send the secret", "secret")
    assert expects(
        "New promoted channel has been set. It may take some time (up to 1 hour) for Telegram clients to apply these settings.",
        "promotion_saved",
    )
    assert not expects("Invalid promotion: channel has not been set", "promotion_saved")
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


@pytest.mark.parametrize("address_field", ["floating_ip", "proxy_ip"])
def test_sponsor_pending_account_stops_before_dialog_or_state_write(
    db, monkeypatch, tmp_path, address_field
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
                address_field: "1.1.1.1",
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


def test_2fa_input_keeps_event_loop_running(monkeypatch):
    import threading
    from commander.sponsorship import authorize_2fa

    started, release = threading.Event(), threading.Event()
    submitted = []

    def hidden(_):
        started.set()
        assert release.wait(2), "Terminal input blocked the networking event loop"
        return "test-only-cloud-password"

    class Client:
        async def sign_in(self, **kwargs):
            submitted.append(kwargs["password"])

    monkeypatch.setattr("getpass.getpass", hidden)

    async def exercise():
        task = asyncio.create_task(authorize_2fa(Client()))
        try:
            assert await asyncio.wait_for(
                asyncio.to_thread(started.wait, 1), timeout=1.5
            )
        finally:
            release.set()
        await task

    asyncio.run(exercise())
    assert submitted == ["test-only-cloud-password"]


@pytest.mark.parametrize("invalid_attempts", [1, 3])
def test_2fa_invalid_password_retries_are_bounded(
    monkeypatch, capsys, invalid_attempts
):
    from commander.sponsorship import authorize_2fa
    from telethon.errors import PasswordHashInvalidError

    calls = []

    class Client:
        async def sign_in(self, **kwargs):
            calls.append(True)
            if len(calls) <= invalid_attempts:
                raise PasswordHashInvalidError(request=None)

    monkeypatch.setattr("getpass.getpass", lambda _: "private-password")
    if invalid_attempts == 3:
        with pytest.raises(ManualRequired, match="три раза"):
            asyncio.run(authorize_2fa(Client()))
    else:
        asyncio.run(authorize_2fa(Client()))
    assert len(calls) == min(invalid_attempts + 1, 3)
    assert "private-password" not in capsys.readouterr().out


def test_2fa_flood_never_retries_and_diagnostics_do_not_echo_exception(monkeypatch):
    from commander.sponsorship import authorize_2fa, login_failure
    from telethon.errors import FloodWaitError

    calls = []

    class Client:
        async def sign_in(self, **kwargs):
            calls.append(True)
            raise FloodWaitError(request=None, capture=120)

    monkeypatch.setattr("getpass.getpass", lambda _: "private-password")
    with pytest.raises(FloodWaitError):
        asyncio.run(authorize_2fa(Client()))
    assert len(calls) == 1
    diagnostic = login_failure(ValueError("private-password"), "пароль 2FA")
    assert "ValueError" in diagnostic and "пароль 2FA" in diagnostic
    assert "private-password" not in diagnostic


@pytest.mark.parametrize("change_during_dialog", [None, "proxy_ip", "proxy_port"])
def test_sponsor_primary_ip_and_stale_endpoint(
    db, monkeypatch, tmp_path, change_during_dialog
):
    from contextlib import nullcontext
    from sqlalchemy.orm import sessionmaker
    from commander import sponsorship
    from commander.config import settings
    from commander.database import Agent, Integration, Job, Sponsorship
    from commander.vault import encrypt, initialize

    key = tmp_path / "key"
    initialize(key)
    monkeypatch.setattr(settings, "vault_key_file", str(key))
    for identifier, kind, credentials in [
        (
            "account",
            "telethon",
            {"api_id": "12345", "api_hash": "a" * 32, "session": "fake-session"},
        ),
        ("secret", "mtproto", {"secret": "b" * 32}),
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
            id="primary",
            name="Primary",
            token_hash="unused",
            proxy_port=9443,
            configuration={
                "proxy_ip": "1.1.1.1",
                "telethon_integration_id": "account",
                "mtproto_integration_id": "secret",
                "sponsor_channel": "https://t.me/example",
            },
        )
    )
    db.commit()
    factory = sessionmaker(db.bind, expire_on_commit=False)
    monkeypatch.setattr(sponsorship, "SessionLocal", factory)
    monkeypatch.setattr(sponsorship, "account_lock", lambda _: nullcontext())
    monkeypatch.setattr(sponsorship, "StringSession", lambda _: "fake-session")

    class Conversation:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    class Client:
        def __init__(self, *args):
            pass

        async def connect(self):
            pass

        async def disconnect(self):
            pass

        async def is_user_authorized(self):
            return True

        def conversation(self, *args, **kwargs):
            return Conversation()

    async def register(conversation, endpoint, secret, checkpoint):
        assert endpoint == "1.1.1.1:9443"
        await checkpoint("REGISTERED", "c" * 32)
        return "c" * 32

    async def promote(conversation, endpoint, channel, tag=None):
        assert endpoint == "1.1.1.1:9443"
        assert channel == "https://t.me/example"
        if change_during_dialog:
            with factory() as session:
                agent = session.get(Agent, "primary")
                if change_during_dialog == "proxy_ip":
                    agent.configuration = {**agent.configuration, "proxy_ip": "8.8.8.8"}
                else:
                    agent.proxy_port = 443
                session.commit()

    monkeypatch.setattr(sponsorship, "TelegramClient", Client)
    monkeypatch.setattr(sponsorship, "register", register)
    monkeypatch.setattr(sponsorship, "promote", promote)
    if change_during_dialog:
        with pytest.raises(ManualRequired):
            asyncio.run(
                sponsorship.sponsor_agent("primary", approve_new_registration=True)
            )
    else:
        asyncio.run(sponsorship.sponsor_agent("primary", approve_new_registration=True))
    db.expire_all()
    state = db.get(Sponsorship, "primary")
    assert state.status == (
        "PROMOTION_MANUAL_REQUIRED" if change_during_dialog else "AD_TAG_PENDING"
    )
    assert db.query(Job).count() == (0 if change_during_dialog else 1)


def test_tag_result_keeps_registration_identity(db):
    from commander.app import JobResult, job_result
    from commander.database import Agent, Job, Sponsorship

    agent = Agent(id="tag-agent", name="Tag agent", token_hash="unused")
    job = Job(
        id="tag-job",
        agent_id=agent.id,
        kind="apply_ad_tag",
        status="leased",
        payload={"ad_tag": "c" * 32},
        attempts=1,
    )
    details = {"endpoint": "1.1.1.1:9443", "account_id": "account"}
    state = Sponsorship(agent_id=agent.id, status="AD_TAG_PENDING", details=details)
    db.add_all([agent, job, state])
    db.commit()
    job_result(
        job.id,
        JobResult(status="succeeded", attempt=1, result={"written": True}),
        agent=agent,
        db=db,
    )
    db.refresh(state)
    assert state.status == "TAG_WRITTEN_UNVERIFIED"
    assert state.details == {**details, "job_id": job.id, "reload_verified": False}


@pytest.mark.parametrize("variant", ["ip_tag", "endpoint", "wrong_tag", "wrong_port"])
def test_real_bot_promotion_labels_and_selected_endpoint(variant):
    from commander.sponsorship import promote

    sent, clicked = [], []
    tag = "a" * 32
    label = (
        "1.1.1.1:9443"
        if variant == "endpoint"
        else "1.1.1.1 " + ("b" * 32 if variant == "wrong_tag" else tag)
    )

    created = []

    async def get_messages(*args, **kwargs):
        return [next(replies)]

    class Message:
        def __init__(self, text, buttons=()):
            self.id = len(created) + 1
            created.append(self)
            self.chat_id, self.out = 123, False
            self.client = SimpleNamespace(get_messages=get_messages)
            self.raw_text = text
            self.buttons = [[SimpleNamespace(text=b) for b in row] for row in buttons]

        async def click(self, row, column):
            clicked.append(self.buttons[row][column].text)

    replies = iter(
        [
            Message("Here is the list of all proxies you created:", [[label]]),
            Message(
                f"Proxy 1.1.1.1:{443 if variant == 'wrong_port' else 9443} with the tag {tag}.",
                [["Set promotion", "Stats"], ["Delete proxy"]],
            ),
            Message(
                "Please send a public channel username in the format @channel or t.me/channel."
            ),
            Message(
                "New promoted channel has been set. It may take some time (up to 1 hour) for Telegram clients to apply these settings."
            ),
        ]
    )

    class Conversation:
        async def send_message(self, message):
            sent.append(message)

        async def get_response(self):
            return next(replies)

    operation = promote(Conversation(), "1.1.1.1:9443", "https://t.me/example", tag)
    if variant in ("wrong_tag", "wrong_port"):
        with pytest.raises(ManualRequired):
            asyncio.run(operation)
        assert sent == ["/myproxies"]
        assert "Set promotion" not in clicked
    else:
        asyncio.run(operation)
        assert sent == ["/myproxies", "https://t.me/example"]
        assert clicked == [label, "Set promotion"]


@pytest.mark.parametrize("edited", [False, True])
def test_callback_accepts_edited_or_new_bot_reply_and_ignores_outgoing(edited):
    from commander.sponsorship import click_reply

    clicked = []
    reply = SimpleNamespace(
        id=10 if edited else 11, out=False, raw_text="Proxy 1.1.1.1:9443", buttons=[]
    )

    async def get_messages(chat_id, limit):
        assert chat_id == 123 and limit == 5
        return [SimpleNamespace(id=12, out=True), reply]

    async def click(row, column):
        clicked.append((row, column))

    message = SimpleNamespace(
        id=10,
        chat_id=123,
        out=False,
        raw_text="Here is the list",
        buttons=[],
        client=SimpleNamespace(get_messages=get_messages),
        click=click,
    )
    assert asyncio.run(click_reply(message, 0, 0)) is reply
    assert clicked == [(0, 0)]
