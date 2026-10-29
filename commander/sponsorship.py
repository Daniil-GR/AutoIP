"""Conservative MTProxybot dialog adapter, isolated from proxy availability.

Only explicit local operator approval can start a new registration. The live
bot interface is unverified; any unexpected message stops the conversation.
"""

import asyncio
import hashlib
import re
import time
from contextlib import contextmanager

from sqlalchemy import text
from telethon import TelegramClient
from telethon.errors import (
    FloodWaitError,
    PasswordHashInvalidError,
    SessionPasswordNeededError,
)
from telethon.sessions import StringSession

from .database import (
    Integration,
    Job,
    Notification,
    SessionLocal,
    Sponsorship,
    engine,
    utcnow,
)
from .security import audit
from .services import proxy_address, require_agent
from .vault import decrypt, encrypt


class ManualRequired(RuntimeError):
    pass


def login_delivery(sent):
    """Describe only the delivery type; never print the auth response or hash."""
    descriptions = {
        "SentCodeTypeApp": "в служебный чат Telegram на уже авторизованных устройствах этого аккаунта",
        "SentCodeTypeSms": "по SMS на сохранённый номер",
        "SentCodeTypeCall": "голосовым звонком на сохранённый номер",
        "SentCodeTypeEmailCode": "на почту для входа, настроенную в Telegram",
        "SentCodeTypeSmsWord": "словом в SMS на сохранённый номер",
        "SentCodeTypeSmsPhrase": "фразой в SMS на сохранённый номер",
    }
    delivery = descriptions.get(type(getattr(sent, "type", None)).__name__)
    if not delivery:
        raise ManualRequired(
            "Telegram вернул способ входа, который эта команда не поддерживает. "
            "Проверьте вход в официальном приложении; частые повторные запросы не помогут."
        )
    return delivery


async def read_login_code(client, phone, sent):
    import getpass
    from telethon.tl.functions.auth import ResendCodeRequest

    deadline = time.monotonic() + max(0, getattr(sent, "timeout", 0) or 0)
    resent = False
    while True:
        print("Telegram указал доставку кода: " + login_delivery(sent) + ".")
        can_resend = getattr(sent, "next_type", None) is not None and not resent
        if can_resend:
            print(
                "Если кода нет, нажмите Enter без кода для одного повторного запроса. "
                "Команда проверит задержку Telegram; способ повторной доставки выбирает Telegram."
            )
        else:
            print("Повторная отправка сейчас недоступна. Пустой ввод отменяет вход.")
        value = (
            await asyncio.to_thread(getpass.getpass, "Код Telegram (скрытый ввод): ")
        ).strip()
        if value:
            return value, sent.phone_code_hash
        if not can_resend:
            raise ManualRequired(
                "Вход отменён: код не получен. Данные интеграции сохранены."
            )
        remaining = max(0, int(deadline - time.monotonic() + 0.999))
        if remaining:
            print(
                f"Повторный запрос разрешён через {remaining} сек. Подождите и снова нажмите Enter."
            )
            continue
        sent = await asyncio.wait_for(
            client(ResendCodeRequest(phone, sent.phone_code_hash)), timeout=30
        )
        resent = True


def parse_tag(message, secret):
    # Never mistake a user secret echoed in a proxy URL for the promotion tag.
    candidates = re.findall(
        r"(?:\btag\b|тег|ad_tag)[\s\S]{0,80}?\b([0-9a-fA-F]{32})\b", message, flags=re.I
    )
    candidates = {
        value.lower() for value in candidates if value.lower() != secret.lower()
    }
    if len(candidates) != 1:
        raise ManualRequired("MTProxybot: не найден однозначный рекламный тег")
    return candidates.pop()


def expects(message, kind):
    patterns = {
        "endpoint": r"(?:ip.?address|ip\s*:\s*port|ip.*port|адрес.*порт)",
        "secret": r"(?:\bsecret\b|секрет)",
        "channel": r"(?:channel|канал)",
        "promotion_saved": r"(?:promotion.*(?:set|updated)|(?:set|updated).*promotion|канал.*(?:установлен|назначен))",
    }
    lower = message.lower()
    return not re.search(r"\b(?:error|invalid|failed)\b|ошибк|неверн", lower) and bool(
        re.search(patterns[kind], lower)
    )


def matching_button(message, predicate):
    options = [
        (row, column)
        for row, buttons in enumerate(message.buttons or [])
        for column, button in enumerate(buttons)
        if predicate(button.text)
    ]
    if len(options) != 1:
        raise ManualRequired(
            "MTProxybot: интерфейс выбора изменился или результат неоднозначен"
        )
    return options[0]


async def register(conversation, endpoint, secret, checkpoint):
    await checkpoint("REGISTRATION_SUBMITTING")
    await conversation.send_message("/newproxy")
    prompt = await conversation.get_response()
    if not expects(prompt.raw_text, "endpoint"):
        raise ManualRequired("MTProxybot: неизвестный запрос IP:PORT")
    await conversation.send_message(endpoint)
    prompt = await conversation.get_response()
    if not expects(prompt.raw_text, "secret"):
        raise ManualRequired("MTProxybot: не получен ожидаемый запрос секрета")
    await conversation.send_message(secret)
    prompt = await conversation.get_response()
    tag = parse_tag(prompt.raw_text, secret)
    await checkpoint("REGISTERED", tag)
    return tag


async def promote(conversation, endpoint, channel):
    await conversation.send_message("/myproxies")
    proxies = await conversation.get_response()
    row, column = matching_button(
        proxies,
        lambda label: endpoint == label.strip()
        or label.strip().endswith(" " + endpoint),
    )
    await proxies.click(row, column)
    selected = await conversation.get_response()
    row, column = matching_button(
        selected,
        lambda label: label.strip().lower()
        in ("set promotion", "назначить канал", "установить спонсора"),
    )
    await selected.click(row, column)
    prompt = await conversation.get_response()
    if not expects(prompt.raw_text, "channel"):
        raise ManualRequired("MTProxybot: не получен ожидаемый запрос канала")
    await conversation.send_message(channel)
    response = await conversation.get_response()
    if not expects(response.raw_text, "promotion_saved"):
        raise ManualRequired("MTProxybot: сохранение канала требует ручной проверки")


@contextmanager
def account_lock(identifier):
    if engine.dialect.name != "postgresql":
        raise ManualRequired(
            "Реальная работа Telethon требует PostgreSQL для блокировки диалогов"
        )
    lock_id = int.from_bytes(
        hashlib.sha256(("telethon:" + identifier).encode()).digest()[:8],
        "big",
        signed=True,
    )
    with engine.connect() as connection:
        locked = connection.execute(
            text("SELECT pg_try_advisory_lock(:key)"), {"key": lock_id}
        ).scalar()
        if not locked:
            raise ManualRequired("Telegram-аккаунт уже используется другой операцией")
        try:
            yield
        finally:
            connection.execute(
                text("SELECT pg_advisory_unlock(:key)"), {"key": lock_id}
            )


async def authorize_qr(client):
    import sys
    import qrcode

    print("На телефоне: Telegram → Настройки → Устройства → Подключить устройство.")
    print("Сканируйте QR только своим аккаунтом. QR и ссылки входа не пересылайте.")
    await asyncio.to_thread(
        input, "Подготовьте сканер на телефоне и нажмите Enter для показа QR: "
    )
    login = await asyncio.wait_for(client.qr_login(), timeout=30)
    # Listen before displaying: scanning may complete immediately.
    waiter = asyncio.create_task(login.wait(timeout=60))
    try:
        await asyncio.sleep(0)
        image = qrcode.QRCode(border=4)
        image.add_data(login.url)
        image.make(fit=True)
        image.print_ascii(out=sys.stdout, invert=True)
        await waiter
    except asyncio.TimeoutError:
        raise ManualRequired("QR истёк. Запустите вход через QR ещё раз.") from None
    finally:
        if not waiter.done():
            waiter.cancel()
        await asyncio.gather(waiter, return_exceptions=True)


async def authorize_2fa(client):
    import getpass

    for attempt in range(3):
        password = await asyncio.to_thread(
            getpass.getpass, "Пароль 2FA Telegram (скрытый ввод): "
        )
        if not password:
            raise ManualRequired("Вход отменён: пароль 2FA не введён.")
        try:
            await asyncio.wait_for(client.sign_in(password=password), timeout=30)
            return
        except PasswordHashInvalidError:
            if attempt == 2:
                raise ManualRequired(
                    "Telegram отклонил пароль 2FA три раза. Вход остановлен."
                ) from None
            print(
                "Telegram отклонил пароль 2FA. Проверьте раскладку; это облачный пароль, а не код входа."
            )
        finally:
            password = None


def login_failure(error, stage):
    # Never include provider messages, request objects or arbitrary exception text.
    if isinstance(error, FloodWaitError):
        return f"Telegram ограничил попытки входа. Повторите не раньше чем через {error.seconds} сек."
    codes = {
        "AuthKeyDuplicatedError": "Telegram отклонил ключ сессии как дублирующийся",
        "AuthKeyUnregisteredError": "Telegram не признал ключ сессии",
        "SessionRevokedError": "Сессия отозвана в Telegram",
        "PhoneCodeInvalidError": "Telegram отклонил код входа",
        "PhoneCodeExpiredError": "Код входа истёк",
        "SecurityError": "Проверка безопасности ответа Telegram не пройдена",
        "EOFError": "Ввод в терминале закрыт",
        "KeyboardInterrupt": "Вход отменён оператором",
        "TimeoutError": "Истекло время ожидания ответа",
        "ConnectionError": "Соединение с Telegram прервано",
    }
    error_type = type(error).__name__
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", error_type):
        error_type = "UnknownError"
    reason = codes.get(
        error_type, f"Ошибка типа {error_type}; секретные подробности скрыты"
    )
    return f"Вход не завершён. Этап: {stage}. {reason}. Данные интеграции сохранены."


async def authorize_local(name="Telegram account", integration_id=None, qr=False):
    """Use stored credentials; codes and 2FA passwords are read only from local TTY."""
    import getpass
    import sys
    from uuid import uuid4
    from .schemas import IntegrationInput

    if not sys.stdin.isatty():
        raise ManualRequired(
            "Для входа нужен локальный интерактивный терминал; используйте docker compose run --rm -it"
        )

    if not integration_id:
        credentials = {
            "api_id": getpass.getpass("Telegram api_id (скрытый ввод): "),
            "api_hash": getpass.getpass("Telegram api_hash (скрытый ввод): "),
            "phone": getpass.getpass(
                "Телефон отдельного Telegram-аккаунта (скрытый ввод): "
            ),
        }
        body = IntegrationInput(name=name, kind="telethon", credentials=credentials)
        body.validate_keys()
        integration_id = str(uuid4())
        with SessionLocal() as db:
            db.add(
                Integration(
                    id=integration_id,
                    name=name,
                    kind="telethon",
                    ciphertext=encrypt(integration_id, "telethon", credentials),
                    metadata_json={},
                    status="authorization_required",
                )
            )
            audit(db, "local-admin", "telethon_credentials_saved", integration_id)
            db.commit()
    with account_lock(integration_id):
        with SessionLocal() as db:
            item = db.get(Integration, integration_id)
            if not item or item.kind != "telethon":
                raise ManualRequired("Telegram-интеграция не найдена")
            credentials = decrypt(item)
            IntegrationInput(
                name=item.name, kind="telethon", credentials=credentials
            ).validate_keys()
            item.status = "authorization_in_progress"
            db.commit()
        client = None
        stage = "соединение"
        try:
            client = TelegramClient(
                StringSession(credentials.get("session", "")),
                int(credentials["api_id"]),
                credentials["api_hash"],
            )
            await asyncio.wait_for(client.connect(), timeout=30)
            if not await asyncio.wait_for(client.is_user_authorized(), timeout=30):
                try:
                    if qr:
                        stage = "QR"
                        await authorize_qr(client)
                    else:
                        stage = "код входа"
                        phone = credentials.get("phone")
                        if not phone:
                            raise ManualRequired(
                                "Для повторной авторизации укажите телефон в защищённой интеграции"
                            )
                        code = await asyncio.wait_for(
                            client.send_code_request(phone), timeout=30
                        )
                        print(
                            "Telegram запросил подтверждение входа. Код и пароль вводите только здесь; ввод скрыт."
                        )
                        value, phone_code_hash = await read_login_code(
                            client, phone, code
                        )
                        await client.sign_in(
                            phone, value, phone_code_hash=phone_code_hash
                        )
                except SessionPasswordNeededError:
                    stage = "пароль 2FA"
                    await authorize_2fa(client)
                if qr:
                    stage = "проверка аккаунта"
                    me = await asyncio.wait_for(client.get_me(), timeout=30)
                    expected_phone = credentials.get("phone", "").lstrip("+")
                    if (
                        not expected_phone
                        or getattr(me, "phone", None) != expected_phone
                    ):
                        await asyncio.wait_for(client.log_out(), timeout=30)
                        raise ManualRequired(
                            "QR подтверждён другим аккаунтом. Новая сессия закрыта; "
                            "выберите в Telegram аккаунт с сохранённым номером."
                        )
            if not await client.is_user_authorized():
                raise ManualRequired("Авторизация Telegram не завершена")
            stage = "сохранение зашифрованной сессии"
            credentials = {**credentials, "session": client.session.save()}
            with SessionLocal() as db:
                item = db.get(Integration, integration_id)
                item.ciphertext = encrypt(integration_id, "telethon", credentials)
                item.status = "verified"
                audit(db, "local-admin", "telethon_authorized", integration_id)
                db.commit()
            print(
                "Telegram-аккаунт авторизован; зашифрованная интеграция ID:",
                integration_id,
            )
            return integration_id
        except (Exception, KeyboardInterrupt) as error:
            with SessionLocal() as db:
                item = db.get(Integration, integration_id)
                item.status = "authorization_required"
                db.commit()
            if isinstance(error, ManualRequired):
                raise
            raise ManualRequired(login_failure(error, stage)) from None
        finally:
            try:
                if client is not None:
                    await asyncio.wait_for(client.disconnect(), timeout=10)
            except Exception:
                pass


async def sponsor_agent(agent_id, approve_new_registration=False):
    with SessionLocal() as db:
        agent = require_agent(db, agent_id)
        config = agent.configuration or {}
        account = db.get(Integration, config.get("telethon_integration_id", ""))
        user_secret = db.get(Integration, config.get("mtproto_integration_id", ""))
        if (
            not account
            or account.kind != "telethon"
            or not user_secret
            or user_secret.kind != "mtproto"
        ):
            raise ManualRequired("Нужны отдельные Telethon и MTProto secret интеграции")
        ip, channel = proxy_address(agent), config.get("sponsor_channel")
        if not ip or not channel:
            raise ManualRequired("Не настроены публичный IP прокси и спонсорский канал")
        endpoint = f"{ip}:{agent.proxy_port}"
        account_id, credentials = account.id, decrypt(account)
        if not credentials.get("session"):
            raise ManualRequired(
                "Telegram-аккаунт ещё не авторизован. Завершите локальный вход перед работой с MTProxybot"
            )
        secret = decrypt(user_secret)["secret"]
    with account_lock(account_id):
        with SessionLocal() as db:
            state = db.get(Sponsorship, agent_id)
            if state and state.status in (
                "REGISTERING",
                "REGISTRATION_SUBMITTING",
                "REGISTRATION_UNCERTAIN",
            ):
                raise ManualRequired(
                    "Результат предыдущей регистрации неизвестен: проверьте MTProxybot вручную"
                )
            existing_tag = (
                state.ad_tag
                if state and state.details.get("endpoint") == endpoint
                else None
            )
            if not existing_tag and not approve_new_registration:
                raise ManualRequired(
                    "Требуется отдельное подтверждение новой регистрации"
                )
            if not state:
                state = Sponsorship(agent_id=agent_id)
                db.add(state)
            state.ad_tag = existing_tag
            state.status = "REGISTERED" if existing_tag else "REGISTERING"
            state.details = {"endpoint": endpoint, "account_id": account_id}
            db.commit()

        async def checkpoint(status, tag=None):
            with SessionLocal() as db:
                state = db.get(Sponsorship, agent_id)
                state.status, state.updated_at = status, utcnow()
                if tag:
                    state.ad_tag = tag
                db.commit()

        client = TelegramClient(
            StringSession(credentials["session"]),
            int(credentials["api_id"]),
            credentials["api_hash"],
        )
        try:
            await client.connect()
            if not await client.is_user_authorized():
                raise ManualRequired("Telegram-аккаунт требует повторной авторизации")
            async with client.conversation(
                "MTProxybot", timeout=30, exclusive=True
            ) as conversation:
                tag = existing_tag or await register(
                    conversation, endpoint, secret, checkpoint
                )
                await promote(conversation, endpoint, channel)
            with SessionLocal() as db:
                current = require_agent(db, agent_id, lock=True)
                if f"{proxy_address(current)}:{current.proxy_port}" != endpoint:
                    raise ManualRequired(
                        "IP или порт агента изменился во время диалога"
                    )
                state = db.get(Sponsorship, agent_id)
                state.status, state.updated_at = "AD_TAG_PENDING", utcnow()
                db.add(
                    Job(agent_id=agent_id, kind="apply_ad_tag", payload={"ad_tag": tag})
                )
                audit(db, "local-admin", "sponsorship_tag_queued", agent_id)
                db.add(
                    Notification(
                        topic="sponsorship",
                        target=agent_id,
                        text=f"{current.name}: MTProxybot подтвердил регистрацию и канал. ad_tag поставлен в очередь; применение ещё не проверено.",
                    )
                )
                db.commit()
        except (ManualRequired, asyncio.TimeoutError, FloodWaitError) as error:
            with SessionLocal() as db:
                state = db.get(Sponsorship, agent_id)
                state.status = (
                    "PROMOTION_MANUAL_REQUIRED"
                    if state.ad_tag
                    else "REGISTRATION_UNCERTAIN"
                )
                state.details = {
                    **state.details,
                    "retry_after_seconds": error.seconds
                    if isinstance(error, FloodWaitError)
                    else None,
                }
                state.updated_at = utcnow()
                db.add(
                    Notification(
                        topic="sponsorship_error",
                        target=agent_id,
                        text="Спонсорство требует ручной проверки MTProxybot. Работа прокси не остановлена.",
                    )
                )
                db.commit()
            raise ManualRequired(
                "Спонсорство не завершено. Проверьте MTProxybot вручную; повторная регистрация заблокирована"
            ) from None
        except Exception:
            # Connection may have failed after a message was sent. Preserve uncertainty.
            with SessionLocal() as db:
                state = db.get(Sponsorship, agent_id)
                state.status = (
                    "PROMOTION_MANUAL_REQUIRED"
                    if state.ad_tag
                    else "REGISTRATION_UNCERTAIN"
                )
                db.commit()
            raise ManualRequired(
                "Неизвестный результат диалога: требуется ручная сверка MTProxybot"
            ) from None
        finally:
            await client.disconnect()
