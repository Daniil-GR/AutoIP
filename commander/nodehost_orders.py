"""Verified Node Host Poland purchase flow; payment requires a persisted quote."""

import asyncio
import hashlib
import re
from datetime import datetime, timedelta
from decimal import Decimal
from uuid import UUID, uuid4
from sqlalchemy import select

from .database import SessionLocal, SystemSetting, utcnow
from .nodehost import (
    BOT_ID,
    NodeHostError,
    click_edit,
    financial_checkpoint,
    parse_access,
    remember_receipt,
    session,
    signature,
)
from .security import aware, audit


def buttons(message):
    return [b for row in message.buttons or [] for b in row]


def exact_data(message, pattern):
    matches = [
        b.data
        for b in buttons(message)
        if b.data and re.fullmatch(pattern, b.data.decode())
    ]
    if len(matches) != 1:
        raise NodeHostError("Ожидаемая кнопка Node Host отсутствует или неоднозначна")
    return matches[0]


def quote_data(message):
    text = message.raw_text
    for pattern in (
        r"CPU:\s*1\b",
        r"RAM:\s*3\b",
        r"Диск:\s*25 GB\b",
        r"ОС:\s*Ubuntu 24\.04\b",
        r"Локация:\s*Poland",
        r"Срок аренды:\s*1 день\b",
        r"Скорость порта:\s*10GBps\b",
    ):
        if not re.search(pattern, text):
            raise NodeHostError("Итоговая конфигурация VPS отличается от согласованной")
    callback = exact_data(message, r"buy;10;Poland;\d+;1;Ubuntu;23;1;[0-9]+\.[0-9]+;₽")
    rubles = re.findall(r"Стоимость:\s*([0-9]+(?:[.,][0-9]+)?)\s*₽", text)
    if len(rubles) != 1:
        raise NodeHostError("Не определена итоговая цена VPS")
    usd = callback.decode().split(";")[-2]
    if not Decimal(usd) > 0 or not Decimal(rubles[0].replace(",", ".")) > 0:
        raise NodeHostError("Некорректная стоимость VPS")
    fingerprint = hashlib.sha256(text.encode() + b"\0" + callback).hexdigest()
    return {
        "callback": callback.decode(),
        "price_usd": usd,
        "price_rub": rubles[0].replace(",", "."),
        "days": 1,
        "fingerprint": fingerprint,
        "message_id": message.id,
    }


def funds_decline(text):
    match = re.fullmatch(
        r"❌ На вашем балансе не хватает ([0-9]+(?:[.,][0-9]+)?) ₽", text.strip()
    )
    return match[1].replace(",", ".") if match else None


async def root_menu(client):
    async with client.conversation(BOT_ID, timeout=25, exclusive=True) as conversation:
        await conversation.send_message("🛒 Купить")
        result = await conversation.get_response()
    # Read the actual stored message, rather than clicking an update snapshot.
    result = await client.get_messages(BOT_ID, ids=result.id)
    if not result or result.out:
        raise NodeHostError("Не получено меню покупки Node Host")
    exact_data(result, r"select_geo;10")
    return result


async def open_locations(client, message):
    """One retry for the unpaid speed selector, only if its menu is unchanged.

    Node Host sometimes ignores the first callback on a newly sent root menu.
    This exception is deliberately limited to select_geo, never payment.
    """
    data = exact_data(message, r"select_geo;10")
    before = signature(message)
    try:
        return await click_edit(client, message, data)
    except NodeHostError:
        current = await client.get_messages(BOT_ID, ids=message.id)
        if not current or signature(current) != before:
            raise
        return await click_edit(client, current, data)


async def prepare(telegram_id):
    """Browse only. The final buy callback is not sent by this function."""
    async with session(telegram_id) as client:
        m = await root_menu(client)
        m = await open_locations(client, m)
        for pattern in (
            r"select_configuration;10;Poland",
            r"configurator;10;Poland",
        ):
            m = await click_edit(client, m, exact_data(m, pattern))
        for action, target, index in (
            ("plusc", 1, 3),
            ("plusr", 3, 4),
            ("plusd", 25, 5),
        ):
            for _ in range(20):
                data = exact_data(m, action + r";10;Poland;\d+;\d+;\d+")
                current = int(data.decode().split(";")[index])
                if current == target:
                    break
                if current > target:
                    raise NodeHostError("Невозможно безопасно выбрать конфигурацию VPS")
                m = await click_edit(client, m, data)
            else:
                raise NodeHostError("Конфигуратор не достиг выбранной конфигурации")
        m = await click_edit(client, m, exact_data(m, r"conf_buy;10;Poland;1;3;25"))
        for pattern in (
            r"select_os_version;10;Poland;\d+;1;Ubuntu",
            r"select_duration;10;Poland;\d+;1;Ubuntu;23",
            r"accept;10;Poland;\d+;1;Ubuntu;23;1;[0-9]+\.[0-9]+;₽",
        ):
            m = await click_edit(client, m, exact_data(m, pattern))
        result = quote_data(m)
    identifier = str(uuid4())
    with SessionLocal() as db:
        db.add(
            SystemSetting(
                key="nh-quote:" + identifier,
                value={
                    **result,
                    "telegram_id": telegram_id,
                    "expires_at": (utcnow() + timedelta(minutes=10)).isoformat(),
                },
            )
        )
        audit(
            db,
            "local-admin",
            "nodehost_quote_prepared",
            identifier,
            days=1,
            price_usd=result["price_usd"],
        )
        db.commit()
    return {
        "quote_id": identifier,
        **{k: result[k] for k in ("price_usd", "price_rub", "days")},
    }


async def purchase(quote_id, operation_id, *, approved=False):
    if not approved:
        raise NodeHostError(
            "Нужно подтверждение покупки VPS на сутки по конкретной цене"
        )
    quote_id, operation_id = str(UUID(quote_id)), str(UUID(operation_id))
    with SessionLocal() as db:
        previous = db.get(SystemSetting, "nodehost-op:" + operation_id)
        if previous:
            if previous.value.get("target") != quote_id:
                raise NodeHostError("ID операции уже относится к другому предложению")
            return {k: previous.value.get(k) for k in ("status", "receipt_id")}
        row = db.get(SystemSetting, "nh-quote:" + quote_id)
        if not row or aware(datetime.fromisoformat(row.value["expires_at"])) < utcnow():
            raise NodeHostError("Предложение устарело; подготовьте новое без оплаты")
        quote = dict(row.value)
    async with session(quote["telegram_id"]) as client:
        with SessionLocal() as db:
            if db.get(SystemSetting, "nh-consumed:" + quote_id):
                raise NodeHostError(
                    "Это предложение уже использовано; нужна сверка заказа"
                )
            for op in db.scalars(
                select(SystemSetting).where(SystemSetting.key.like("nodehost-op:%"))
            ):
                if op.value.get("status") != "SUBMITTING":
                    continue
                prior_quote = db.get(
                    SystemSetting, "nh-quote:" + str(op.value.get("target", ""))
                )
                if (
                    prior_quote
                    and prior_quote.value.get("telegram_id") == quote["telegram_id"]
                ):
                    raise NodeHostError(
                        "Есть неопределённый заказ; новая покупка запрещена до сверки"
                    )
        m = await client.get_messages(BOT_ID, ids=quote["message_id"])
        if not m or quote_data(m)["fingerprint"] != quote["fingerprint"]:
            raise NodeHostError("Параметры или цена перед оплатой изменились")
        latest = await client.get_messages(BOT_ID, limit=1)
        baseline = latest[0].id if latest else 0
        with SessionLocal() as db:
            db.add(
                SystemSetting(
                    key="nh-consumed:" + quote_id, value={"operation_id": operation_id}
                )
            )
            financial_checkpoint(db, operation_id, "order", quote_id, approved=True)
            row = db.get(SystemSetting, "nodehost-op:" + operation_id)
            row.value = {
                **row.value,
                "telegram_id": quote["telegram_id"],
                "baseline_id": baseline,
                "price_usd": quote["price_usd"],
                "price_rub": quote["price_rub"],
            }
            db.commit()
        # Do not use click_edit: a successful payment sends separate receipt messages.
        data = quote["callback"].encode()
        positions = [
            (r, c)
            for r, row in enumerate(m.buttons or [])
            for c, b in enumerate(row)
            if b.data == data
        ]
        if len(positions) != 1:
            raise NodeHostError("Кнопка оплаты изменилась; нужна сверка операции")
        await asyncio.wait_for(m.click(data=data), timeout=25)
        for _ in range(25):
            await asyncio.sleep(2)
            replies = await client.get_messages(BOT_ID, min_id=baseline, limit=30)
            if any(reply.out for reply in replies):
                raise NodeHostError(
                    "Обнаружен параллельный диалог; заказ требует сверки"
                )
            receipts = [r for r in replies if "Ваш сервер успешно создан" in r.raw_text]
            if len(receipts) > 1:
                raise NodeHostError(
                    "Получено несколько VPS; требуется сверка владельца"
                )
            if len(replies) == 1 and not receipts:
                missing = funds_decline(replies[0].raw_text)
                if missing is not None:
                    with SessionLocal() as db:
                        op = db.get(SystemSetting, "nodehost-op:" + operation_id)
                        op.value = {
                            **op.value,
                            "status": "DECLINED_FUNDS",
                            "missing_rub": missing,
                            "response_message_id": replies[0].id,
                        }
                        audit(
                            db,
                            "commander",
                            "nodehost_order_declined_funds",
                            operation_id,
                        )
                        db.commit()
                    return {
                        "status": "DECLINED_FUNDS",
                        "receipt_id": None,
                        "missing_rub": missing,
                    }
            if not receipts:
                continue
            receipt = receipts[0]
            access = parse_access(receipt.raw_text)
            with SessionLocal() as db:
                remember_receipt(
                    db,
                    quote["telegram_id"],
                    receipt.id,
                    access,
                    managed=True,
                    created_at=receipt.date,
                )
                op = db.get(SystemSetting, "nodehost-op:" + operation_id)
                op.value = {
                    **op.value,
                    "status": "ALLOCATED",
                    "receipt_id": receipt.id,
                    "ipv4": access.ipv4,
                }
                audit(
                    db,
                    "commander",
                    "nodehost_order_allocated",
                    operation_id,
                    receipt_id=receipt.id,
                )
                db.commit()
            return {
                "status": "ALLOCATED",
                "receipt_id": receipt.id,
                "ipv4": access.ipv4,
            }
    # Unknown outcome stays SUBMITTING forever until explicit reconciliation, never another click.
    return {"status": "SUBMITTING", "receipt_id": None}
