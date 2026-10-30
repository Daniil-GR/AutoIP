"""Node Host dialog primitives: no unrecorded financial clicks or raw transcripts."""

import asyncio
import ipaddress
import re
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from uuid import uuid4

from sqlalchemy import select
from telethon import TelegramClient
from telethon.sessions import StringSession

from .database import Integration, SessionLocal, SystemSetting, utcnow
from .security import audit
from .sponsorship import account_lock
from .vault import decrypt, encrypt

BOT_ID = 8323960409
BOT_NAME = "nodehost_bot"


class NodeHostError(RuntimeError):
    pass


def public_ip(value):
    try:
        address = ipaddress.IPv4Address(value)
    except (ValueError, TypeError):
        raise NodeHostError("Ожидался публичный IPv4") from None
    if not address.is_global:
        raise NodeHostError("Ожидался публичный IPv4")
    return str(address)


@dataclass(repr=False)
class Access:
    ipv4: str
    username: str = field(repr=False)
    password: str = field(repr=False)


def parse_access(text):
    if "Ваш сервер успешно создан" not in text:
        raise NodeHostError("Не получено подтверждение создания VPS")
    fields = {}
    for key, pattern in {
        "ipv4": r"(?mi)^\s*IP\s*адрес\s*:\s*(\S+)\s*$",
        "username": r"(?mi)^\s*Логин\s*:\s*(\S+)\s*$",
        "password": r"(?mi)^\s*Пароль\s*:\s*(\S+)\s*$",
    }.items():
        values = re.findall(pattern, text)
        if len(values) != 1:
            raise NodeHostError("Неоднозначный формат данных нового VPS")
        fields[key] = values[0]
    if not re.search(r"(?mi)^ОС\s*:\s*Ubuntu 24\.04\s*$", text):
        raise NodeHostError("Нужна Ubuntu 24.04")
    if fields["username"] != "root" or len(fields["password"]) > 512:
        raise NodeHostError("Не поддерживается формат входа VPS")
    fields["ipv4"] = public_ip(fields["ipv4"])
    return Access(**fields)


def inventory(message):
    if "Ваши серверы" not in message.raw_text:
        raise NodeHostError("Неизвестный список серверов Node Host")
    result = []
    for row in message.buttons or []:
        for button in row:
            data = button.data.decode("ascii") if button.data else ""
            match = re.fullmatch(r"select_order;(\d+);1", data)
            if not match:
                continue
            addresses = re.findall(r"(?<![\d.])\d+(?:\.\d+){3}(?![\d.])", button.text)
            if len(addresses) != 1:
                raise NodeHostError("Неоднозначный адрес в списке серверов")
            result.append({"provider_id": match[1], "ipv4": public_ip(addresses[0])})
    if len({r["provider_id"] for r in result}) != len(result):
        raise NodeHostError("Повторные ID в списке серверов")
    return result


def refund_result(text):
    if "Сервер успешно удален" not in text:
        raise NodeHostError("Node Host не подтвердил удаление")
    amount = re.findall(r"возвращено:\s*([0-9]+(?:[.,][0-9]+)?)\s*\$", text, re.I)
    remaining = re.findall(r"Осталось возвратов:\s*(\d+)", text)
    return {
        "deleted": True,
        "refund_usd": amount[0].replace(",", ".") if len(amount) == 1 else None,
        "refunds_remaining": int(remaining[0]) if len(remaining) == 1 else None,
    }


def signature(message):
    return message.raw_text, tuple(
        tuple((b.text, b.data) for b in row) for row in message.buttons or []
    )


async def click_edit(client, message, data, *, timeout=25):
    """Only accept this message's edit; unrelated old replies cannot advance us."""
    choices = [
        (r, c)
        for r, row in enumerate(message.buttons or [])
        for c, b in enumerate(row)
        if b.data == data
    ]
    if len(choices) != 1:
        raise NodeHostError("Интерфейс Node Host изменился; действие не выполнено")
    before = signature(message)
    await asyncio.wait_for(message.click(*choices[0]), timeout=timeout)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        after = await client.get_messages(BOT_ID, ids=message.id)
        if after and signature(after) != before:
            return after
        await asyncio.sleep(0.5)
    raise NodeHostError("Нет ожидаемого изменения меню; повторять нажатие нельзя")


@asynccontextmanager
async def session(identifier):
    with SessionLocal() as db:
        item = db.get(Integration, identifier)
        if not item or item.kind != "telethon":
            raise NodeHostError("Нужна существующая Telegram-интеграция")
        credentials = decrypt(item)
        if not credentials.get("session"):
            raise NodeHostError("Telegram-аккаунт не авторизован")
    with account_lock(identifier):
        client = TelegramClient(
            StringSession(credentials["session"]),
            int(credentials["api_id"]),
            credentials["api_hash"],
            connection_retries=1,
            request_retries=1,
            timeout=10,
        )
        await asyncio.wait_for(client.connect(), timeout=20)
        try:
            if not await client.is_user_authorized():
                raise NodeHostError("Нужна локальная авторизация Telegram")
            entity = await client.get_entity(BOT_NAME)
            if entity.id != BOT_ID or not entity.bot:
                raise NodeHostError("Не подтверждена личность Node Host")
            yield client
        finally:
            await client.disconnect()


def remember_receipt(
    db, telegram_id, message_id, access, *, managed=False, created_at=None
):
    """Receipt IDs deduplicate imports; credentials never enter resource JSON."""
    key = f"vps-receipt:{message_id}"
    previous = db.get(SystemSetting, key)
    if previous:
        if previous.value["telegram_integration_id"] != telegram_id:
            raise NodeHostError("Квитанция принадлежит другому аккаунту")
        return dict(previous.value)
    identifier = str(uuid4())
    secret = Integration(
        id=identifier,
        kind="vps_access",
        name="Node Host SSH",
        ciphertext=encrypt(
            identifier,
            "vps_access",
            {
                "ipv4": access.ipv4,
                "username": access.username,
                "password": access.password,
            },
        ),
        status="not_tested",
    )
    db.add(secret)
    value = {
        "ipv4": access.ipv4,
        "telegram_integration_id": telegram_id,
        "source_message_id": message_id,
        "credential_id": identifier,
        "managed": managed,
        "status": "discovered",
        "created_at": (created_at or utcnow()).isoformat(),
    }
    db.add(SystemSetting(key=key, value=value))
    audit(
        db, "commander", "nodehost_receipt_imported", str(message_id), ipv4=access.ipv4
    )
    return value


async def discover(identifier, addresses):
    """Read-only history import for explicitly selected IPs; no server adoption."""
    selected = {public_ip(ip) for ip in addresses}
    found = []
    async with session(identifier) as client:
        async for message in client.iter_messages(BOT_ID, limit=500):
            if message.out or "Ваш сервер успешно создан" not in message.raw_text:
                continue
            addresses_in_message = re.findall(
                r"(?mi)^\s*IP\s*адрес\s*:\s*(\S+)\s*$", message.raw_text
            )
            if (
                len(addresses_in_message) != 1
                or addresses_in_message[0] not in selected
            ):
                continue
            access = parse_access(message.raw_text)
            if access.ipv4 not in selected:
                continue
            with SessionLocal() as db:
                result = remember_receipt(
                    db, identifier, message.id, access, created_at=message.date
                )
                db.commit()
                found.append(
                    {
                        "ipv4": access.ipv4,
                        "source_message_id": message.id,
                        "credential_id": result["credential_id"],
                    }
                )
            selected.remove(access.ipv4)
            if not selected:
                break
    return {"found": found, "missing": sorted(selected)}


def financial_checkpoint(db, operation_id, action, target, *, approved=False):
    """Commit before the one irreversible click; retries must reconcile history."""
    if not approved or action not in ("order", "delete"):
        raise NodeHostError("Нужно подтверждение конкретного платного действия")
    key = "nodehost-op:" + str(operation_id)
    if len(key) > 50:
        raise NodeHostError("Слишком длинный ID операции")
    existing = db.get(SystemSetting, key)
    if existing:
        raise NodeHostError("Действие уже отправлялось; требуется сверка, без повтора")
    db.add(
        SystemSetting(
            key=key,
            value={
                "action": action,
                "target": target,
                "status": "SUBMITTING",
                "created_at": utcnow().isoformat(),
            },
        )
    )
    audit(db, "local-admin", "nodehost_" + action + "_submitting", operation_id)
    db.commit()


def known_blocked(db, ipv4):
    row = db.get(SystemSetting, "vps-block:" + public_ip(ipv4))
    return bool(row and row.value.get("blocked"))


def record_block(db, ipv4, reason):
    key = "vps-block:" + public_ip(ipv4)
    row = db.get(SystemSetting, key)
    value = {"blocked": True, "reason": reason, "recorded_at": utcnow().isoformat()}
    if row:
        row.value = {**row.value, **value}
    else:
        db.add(SystemSetting(key=key, value=value))
    audit(db, "local-admin", "vps_ip_blocked", ipv4)


def resources(db):
    return [
        {
            k: r.value.get(k)
            for k in ("ipv4", "source_message_id", "status", "managed", "created_at")
        }
        for r in db.scalars(
            select(SystemSetting).where(SystemSetting.key.like("vps-receipt:%"))
        )
    ]
