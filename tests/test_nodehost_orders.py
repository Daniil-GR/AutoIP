import asyncio
from contextlib import asynccontextmanager
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy.orm import sessionmaker

from commander import nodehost_orders as orders, nodehost
from commander.database import SystemSetting, utcnow

TEXT = """⚡️ Информация о сервере
CPU: 1
RAM: 3
Диск: 25 GB
ОС: Ubuntu 24.04
Скорость порта: 10GBps
Локация: Poland 🇵🇱
Стоимость: 20.95 ₽
Срок аренды: 1 день
"""
DATA = "buy;10;Poland;123;1;Ubuntu;23;1;0.26;₽"


def message(text=TEXT, callback=DATA):
    return SimpleNamespace(
        id=10, raw_text=text, buttons=[[SimpleNamespace(data=callback.encode())]]
    )


def test_quote_checks_real_config_period_and_both_price_units():
    q = orders.quote_data(message())
    assert q["price_usd"] == "0.26" and q["price_rub"] == "20.95" and q["days"] == 1
    for text in (
        TEXT.replace("CPU: 1", "CPU: 2"),
        TEXT.replace("25 GB", "45 GB"),
        TEXT.replace("1 день", "1 месяц"),
    ):
        with pytest.raises(nodehost.NodeHostError):
            orders.quote_data(message(text))
    with pytest.raises(nodehost.NodeHostError):
        orders.quote_data(message(callback=DATA.replace(";1;0.26;", ";30;7.79;")))


@pytest.fixture
def purchase_setup(db, monkeypatch):
    factory = sessionmaker(db.bind, expire_on_commit=False)
    monkeypatch.setattr(orders, "SessionLocal", factory)
    monkeypatch.setattr(nodehost, "encrypt", lambda *_: "encrypted-test-envelope")
    m = message()

    class Client:
        clicks = 0

        async def get_messages(self, peer, *, ids=None, limit=None, min_id=None):
            assert peer == nodehost.BOT_ID
            if ids:
                return m
            if min_id is None:
                return [SimpleNamespace(id=15)]
            return [
                SimpleNamespace(
                    id=20,
                    out=False,
                    date=utcnow(),
                    raw_text="Ваш сервер успешно создан\nIP адрес: 8.8.8.8\nОС: Ubuntu 24.04\nЛогин: root\nПароль: test-only-password\n",
                )
            ]

    client = Client()

    async def click(*, data):
        assert data == DATA.encode()
        client.clicks += 1

    m.click = click

    @asynccontextmanager
    async def session(_):
        yield client

    async def skip(_):
        pass

    monkeypatch.setattr(orders, "session", session)
    monkeypatch.setattr(orders.asyncio, "sleep", skip)
    quote_id = str(uuid4())
    db.add(
        SystemSetting(
            key="nh-quote:" + quote_id,
            value={
                **orders.quote_data(m),
                "telegram_id": "telegram",
                "expires_at": (utcnow() + timedelta(minutes=10)).isoformat(),
            },
        )
    )
    db.commit()
    return quote_id, client, m


def test_purchase_is_single_click_and_receipt_is_encrypted(db, purchase_setup):
    quote_id, client, _ = purchase_setup
    op = str(uuid4())
    with pytest.raises(nodehost.NodeHostError):
        asyncio.run(orders.purchase(quote_id, op))
    result = asyncio.run(orders.purchase(quote_id, op, approved=True))
    assert result["status"] == "ALLOCATED" and result["ipv4"] == "8.8.8.8"
    assert (
        asyncio.run(orders.purchase(quote_id, op, approved=True))["status"]
        == "ALLOCATED"
    )
    with pytest.raises(nodehost.NodeHostError):
        asyncio.run(orders.purchase(quote_id, str(uuid4()), approved=True))
    assert client.clicks == 1
    row = db.get(SystemSetting, "vps-receipt:20")
    assert row.value["managed"] and "password" not in str(row.value)


def test_changed_price_prevents_financial_checkpoint(db, purchase_setup):
    quote_id, client, m = purchase_setup
    m.raw_text = TEXT.replace("20.95", "21.95")
    with pytest.raises(nodehost.NodeHostError):
        asyncio.run(orders.purchase(quote_id, str(uuid4()), approved=True))
    assert client.clicks == 0


def test_unknown_purchase_prevents_new_purchase_in_same_account(db, purchase_setup):
    quote_id, client, _ = purchase_setup
    old_quote = str(uuid4())
    db.add(
        SystemSetting(key="nh-quote:" + old_quote, value={"telegram_id": "telegram"})
    )
    db.add(
        SystemSetting(
            key="nodehost-op:" + str(uuid4()),
            value={"target": old_quote, "status": "SUBMITTING"},
        )
    )
    db.commit()
    with pytest.raises(nodehost.NodeHostError, match="неопределённый"):
        asyncio.run(orders.purchase(quote_id, str(uuid4()), approved=True))
    assert client.clicks == 0


def test_root_menu_rejects_changed_stored_message():
    class Conversation:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def send_message(self, text):
            assert text == "🛒 Купить"

        async def get_response(self):
            return message(callback="select_geo;10")

    class Client:
        def conversation(self, peer, **kwargs):
            return Conversation()

        async def get_messages(self, peer, *, ids):
            assert ids == 10
            current = message(callback="unexpected")
            current.out = False
            return current

    with pytest.raises(nodehost.NodeHostError):
        asyncio.run(orders.root_menu(Client()))


@pytest.mark.parametrize("changed", [False, True])
def test_only_unchanged_unpaid_speed_menu_can_retry(monkeypatch, changed):
    initial = message(callback="select_geo;10")
    initial.buttons[0][0].text = "10GBps"
    current = message(callback="other" if changed else "select_geo;10")
    current.buttons[0][0].text = "10GBps"
    calls = []

    class Client:
        async def get_messages(self, peer, *, ids):
            assert ids == initial.id and peer == nodehost.BOT_ID
            return current

    async def click(client, menu, data):
        calls.append(data)
        if len(calls) == 1:
            raise nodehost.NodeHostError("Ignored callback")
        return "locations"

    monkeypatch.setattr(orders, "click_edit", click)
    if changed:
        with pytest.raises(nodehost.NodeHostError):
            asyncio.run(orders.open_locations(Client(), initial))
        assert len(calls) == 1
    else:
        assert asyncio.run(orders.open_locations(Client(), initial)) == "locations"
        assert calls == [b"select_geo;10", b"select_geo;10"]

    with pytest.raises(nodehost.NodeHostError):
        asyncio.run(orders.open_locations(Client(), message()))
    assert len(calls) == (1 if changed else 2)
