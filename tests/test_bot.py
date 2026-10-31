from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from commander.bot import AccessGuard, button, consume_action, dispatch_action, menu
from commander.config import settings
from commander.database import Agent, BotAction, ControlTask, Recovery, utcnow


def action(db, user, label, kind, target=""):
    b = button(db, user, label, kind, target)
    db.commit()
    return consume_action(db, user, b.callback_data[2:])


def test_callbacks_user_bound_expiring_single_use(db, monkeypatch):
    monkeypatch.setattr(settings, "telegram_admin_ids", [1, 2])
    b = button(db, 1, "Подтвердить", "confirm_recovery")
    db.commit()
    token = b.callback_data[2:]
    with pytest.raises(HTTPException):
        consume_action(db, 2, token)
    with pytest.raises(HTTPException):
        consume_action(db, 3, token)
    item = consume_action(db, 1, token)
    db.commit()
    assert item.used_at
    with pytest.raises(HTTPException):
        consume_action(db, 1, token)
    b = button(db, 1, "Подтвердить", "confirm_recovery")
    db.commit()
    item = db.get(
        BotAction,
        __import__("commander.security", fromlist=["digest"]).digest(
            b.callback_data[2:]
        ),
    )
    item.expires_at = utcnow() - timedelta(seconds=1)
    db.commit()
    with pytest.raises(HTTPException):
        consume_action(db, 1, b.callback_data[2:])


def test_menu_and_shared_services(db, monkeypatch):
    monkeypatch.setattr(settings, "telegram_admin_ids", [1])
    a = Agent(
        name="Test", token_hash="test", facts={}, configuration={}, last_seen=utcnow()
    )
    db.add(a)
    db.commit()
    assert sum(len(row) for row in menu(db, 1).inline_keyboard) == 10
    for kind in [
        "status",
        "agents",
        "checks",
        "recovery",
        "automation",
        "ips",
        "costs",
        "history",
    ]:
        item = action(db, 1, "x", kind)
        text, markup = dispatch_action(db, 1, item)
        db.commit()
        assert text and markup
    item = action(db, 1, "x", "check", a.id)
    dispatch_action(db, 1, item)
    db.commit()
    assert db.scalar(select(ControlTask)).agent_id == a.id
    item = action(db, 1, "x", "pause", a.id)
    dispatch_action(db, 1, item)
    db.commit()
    assert a.paused
    item = action(db, 1, "x", "resume", a.id)
    dispatch_action(db, 1, item)
    db.commit()
    assert not a.paused
    item = action(db, 1, "x", "prepare_recovery", a.id)
    text, _ = dispatch_action(db, 1, item)
    db.commit()
    assert "Подготовить" in text and db.scalar(select(Recovery)) is None
    item = action(db, 1, "x", "confirm_recovery", a.id)
    text, _ = dispatch_action(db, 1, item)
    db.commit()
    assert db.scalar(select(Recovery)).status == "MANUAL_REQUIRED"


def test_access_guard_rejects_groups_and_unknown_users(monkeypatch):
    import asyncio

    monkeypatch.setattr(settings, "telegram_admin_ids", [1])
    called = []

    async def handler(event, data):
        called.append(True)

    guard = AccessGuard()
    for user, chatid, kind in [(2, 2, "private"), (1, -100, "group")]:
        event = SimpleNamespace(
            from_user=SimpleNamespace(id=user),
            chat=SimpleNamespace(id=chatid, type=kind),
        )
        asyncio.run(guard(handler, event, {}))
    assert not called
    event = SimpleNamespace(
        from_user=SimpleNamespace(id=1), chat=SimpleNamespace(id=1, type="private")
    )
    asyncio.run(guard(handler, event, {}))
    assert called == [True]


def test_sni_bot_requires_confirmation_and_uses_shared_deduped_task(db, monkeypatch):
    from commander.database import Integration, FloatingIP
    from commander.services import proxy_address, request_sni_check

    monkeypatch.setattr(settings, "telegram_admin_ids", [1])
    a = Agent(
        name="Primary only",
        token_hash="primary-only",
        facts={},
        configuration={
            "management_ip": "8.8.8.8",
            "proxy_ip": "8.8.8.8",
            "sni_domain": "sni.example.com",
        },
    )
    integration = Integration(
        id="atlas-test",
        kind="ripe_atlas",
        name="Atlas",
        ciphertext="not-used",
        metadata_json={},
    )
    db.add_all([a, integration])
    db.commit()
    text, _ = dispatch_action(db, 1, action(db, 1, "x", "prepare_sni", a.id))
    db.commit()
    assert "кредиты" in text and db.scalar(select(ControlTask)) is None
    assert proxy_address(a) == "8.8.8.8"
    text, _ = dispatch_action(
        db, 1, action(db, 1, "x", "confirm_sni", a.id + ":atlas-test")
    )
    db.commit()
    task = db.scalar(select(ControlTask))
    assert task.kind == "sni" and task.payload["target_ip"] == "8.8.8.8"
    assert request_sni_check(db, a.id, "atlas-test", "web").id == task.id
    assert db.scalar(select(FloatingIP)) is None
    a.configuration = {**a.configuration, "floating_ip": "1.1.1.1"}
    assert proxy_address(a) == "1.1.1.1"


@pytest.mark.parametrize(
    "kind",
    [
        "menu",
        "status",
        "agents",
        "agent:agents",
        "page:checks",
        "recovery_status",
        "prepare_sni",
    ],
)
def test_navigation_reusable_after_expiry_and_previous_use(db, monkeypatch, kind):
    from commander.security import digest

    monkeypatch.setattr(settings, "telegram_admin_ids", [1, 2])
    b = button(db, 1, "Открыть", kind, "target")
    db.commit()
    stored = db.get(BotAction, digest(b.callback_data[2:]))
    stored.expires_at = utcnow() - timedelta(days=2)
    stored.used_at = utcnow() - timedelta(days=3)
    db.commit()
    for _ in range(2):
        assert consume_action(db, 1, b.callback_data[2:]).action == kind
        db.commit()
    with pytest.raises(HTTPException):
        consume_action(db, 2, b.callback_data[2:])


@pytest.mark.parametrize(
    "kind",
    [
        "check",
        "pause",
        "resume",
        "confirm_sni",
        "confirm_recovery",
        "incident:confirm",
        "incident:working",
    ],
)
def test_mutations_remain_single_use(db, monkeypatch, kind):
    monkeypatch.setattr(settings, "telegram_admin_ids", [1])
    b = button(db, 1, "Действие", kind, "target")
    db.commit()
    assert consume_action(db, 1, b.callback_data[2:]).used_at
    db.commit()
    with pytest.raises(HTTPException):
        consume_action(db, 1, b.callback_data[2:])


def test_expired_mutation_opens_menu_without_executing(db, monkeypatch):
    import asyncio
    from unittest.mock import AsyncMock, Mock
    from contextlib import nullcontext
    from commander import bot
    from commander.security import digest

    monkeypatch.setattr(settings, "telegram_admin_ids", [1])
    b = button(db, 1, "Подтвердить", "confirm_recovery", "missing-agent")
    db.commit()
    stored = db.get(BotAction, digest(b.callback_data[2:]))
    stored.expires_at = utcnow() - timedelta(seconds=1)
    db.commit()
    monkeypatch.setattr(bot, "SessionLocal", lambda: nullcontext(db))
    dispatch = Mock(side_effect=AssertionError("Expired action must never execute"))
    monkeypatch.setattr(bot, "dispatch_action", dispatch)
    query = SimpleNamespace(
        from_user=SimpleNamespace(id=1),
        data=b.callback_data,
        answer=AsyncMock(),
        message=SimpleNamespace(answer=AsyncMock(), edit_text=AsyncMock()),
    )
    asyncio.run(bot.callback(query))
    dispatch.assert_not_called()
    query.message.answer.assert_awaited_once()
    assert "reply_markup" in query.message.answer.call_args.kwargs
    assert db.scalar(select(Recovery)) is None


def test_cdn_card_hides_direct_recovery_and_old_confirmation_is_rejected(
    db, monkeypatch
):
    from commander.bot import agent_view

    monkeypatch.setattr(settings, "telegram_admin_ids", [1])
    a = Agent(
        name="CDN",
        token_hash="cdn-bot",
        public_host="node.vetka.rest",
        facts={},
        configuration={"monitoring_mode": "cdn_web"},
    )
    db.add(a)
    db.commit()
    text, markup = agent_view(db, 1, a.id, "agents")
    db.commit()
    assert "Режим: Web через CDN" in text
    assert "смена IP и DNS выключена" in text
    assert not any(
        "Подготовить восстановление" in b.text
        for row in markup.inline_keyboard
        for b in row
    )
    assert any("К списку" in b.text for row in markup.inline_keyboard for b in row)
    with pytest.raises(HTTPException):
        dispatch_action(db, 1, action(db, 1, "Подтвердить", "confirm_recovery", a.id))
    assert db.scalar(select(Recovery)) is None


def test_persistent_menu_and_sections_have_return_navigation(db, monkeypatch):
    from commander.bot import persistent_menu

    monkeypatch.setattr(settings, "telegram_admin_ids", [1])
    assert persistent_menu().is_persistent
    assert persistent_menu().keyboard[0][0].text == "🏠 Главное меню"
    for kind in ("status", "ips", "costs", "history"):
        _, markup = dispatch_action(db, 1, action(db, 1, "Открыть", kind))
        labels = [b.text for row in markup.inline_keyboard for b in row]
        assert "🔄 Обновить" in labels and "🏠 Главное меню" in labels


def test_repeated_navigation_callbacks_refresh_same_message(db, monkeypatch):
    import asyncio
    from contextlib import nullcontext
    from unittest.mock import AsyncMock
    from commander import bot

    monkeypatch.setattr(settings, "telegram_admin_ids", [1])
    b = button(db, 1, "Статус", "status")
    db.commit()
    monkeypatch.setattr(bot, "SessionLocal", lambda: nullcontext(db))
    query = SimpleNamespace(
        from_user=SimpleNamespace(id=1),
        data=b.callback_data,
        answer=AsyncMock(),
        message=SimpleNamespace(answer=AsyncMock(), edit_text=AsyncMock()),
    )
    for _ in range(2):
        db.expire_all()
        asyncio.run(bot.callback(query))
    assert query.message.edit_text.await_count == 2
    query.message.answer.assert_not_awaited()
    assert db.scalar(select(ControlTask)) is None


@pytest.mark.parametrize(
    "config, port, label",
    [
        ({}, 9443, "Web + MTProto"),
        ({"proxy_mode": "mtproto_faketls"}, 443, "MTProto FakeTLS"),
        ({"monitoring_mode": "cdn_web"}, 9443, "Web через CDN"),
    ],
)
def test_agent_card_setup_modes(db, config, port, label):
    from commander.bot import agent_view

    a = Agent(
        name="Test mode",
        token_hash="mode-bot",
        public_host="node.vetka.rest",
        proxy_port=port,
        configuration=config,
        facts={},
    )
    db.add(a)
    db.commit()
    text, _ = agent_view(db, 1, a.id, "agents")
    assert f"Режим: {label}" in text
    assert "Последняя проверка:" in text
