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
    b = button(db, 1, "Статус", "status")
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
    b = button(db, 1, "Статус", "status")
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
    assert len(menu(db, 1).inline_keyboard) == 8
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
