"""aiogram 3 administrator service. All mutations use Commander services."""

import asyncio
import logging
import secrets
from datetime import timedelta

from aiogram import BaseMiddleware, Bot, Dispatcher, F, Router
from aiogram.exceptions import TelegramAPIError, TelegramBadRequest
from aiogram.filters import CommandStart
from aiogram.types import (
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)
from fastapi import HTTPException
from sqlalchemy import select

from .config import settings
from .database import (
    Agent,
    Audit,
    BotAction,
    Check,
    Delivery,
    FloatingIP,
    Incident,
    Integration,
    Notification,
    Recovery,
    SessionLocal,
    Sponsorship,
    utcnow,
)
from .security import aware, digest, display_time
from .services import (
    ACTIVE_INCIDENTS,
    cost_report,
    incident_action,
    online,
    recovery_plan,
    request_check,
    require_agent,
    set_paused,
)
from .vault import decrypt
from .policy import get_policy

router = Router()
log = logging.getLogger(__name__)


def admin_ids():
    with SessionLocal() as db:
        return get_policy(db).telegram_admin_ids


def authorized(user_id):
    return user_id in admin_ids()


class AccessGuard(BaseMiddleware):
    async def __call__(self, handler, event, data):
        user = event.from_user
        chat = (
            event.message.chat
            if isinstance(event, CallbackQuery) and event.message
            else getattr(event, "chat", None)
        )
        if (
            not user
            or not authorized(user.id)
            or not chat
            or chat.type != "private"
            or chat.id != user.id
        ):
            if isinstance(event, CallbackQuery):
                await event.answer("Доступ запрещён", show_alert=True)
            return
        return await handler(event, data)


router.message.outer_middleware(AccessGuard())
router.callback_query.outer_middleware(AccessGuard())


def button(db, user_id, label, action, target="", minutes=60):
    token = secrets.token_urlsafe(18)
    db.add(
        BotAction(
            token_hash=digest(token),
            user_id=str(user_id),
            action=action,
            target=target,
            expires_at=utcnow() + timedelta(minutes=minutes),
        )
    )
    return InlineKeyboardButton(text=label, callback_data="a:" + token)


def consume_action(db, user_id, token):
    if not authorized(user_id):
        raise HTTPException(403, "Доступ запрещён")
    action = db.scalar(
        select(BotAction).where(BotAction.token_hash == digest(token)).with_for_update()
    )
    if (
        not action
        or action.user_id != str(user_id)
        or action.used_at
        or aware(action.expires_at) <= utcnow()
    ):
        raise HTTPException(
            409, "Кнопка устарела или уже использована. Откройте меню заново"
        )
    action.used_at = utcnow()
    return action


def keyboard(rows):
    return InlineKeyboardMarkup(inline_keyboard=rows)


def menu(db, user_id):
    entries = [
        ("📊 Статус инфраструктуры", "status"),
        ("🖥 Агенты", "agents"),
        ("🔍 Проверить доступность", "checks"),
        ("🔄 Восстановление прокси", "recovery"),
        ("🌐 Floating IP", "ips"),
        ("💰 Расходы", "costs"),
        ("📜 История операций", "history"),
        ("⚙️ Настройки автоматизации", "automation"),
    ]
    return keyboard([[button(db, user_id, label, action)] for label, action in entries])


def agent_buttons(db, user_id, mode, offset=0):
    agents = db.scalars(
        select(Agent)
        .where(Agent.revoked.is_(False))
        .order_by(Agent.created_at, Agent.id)
        .offset(offset)
        .limit(11)
    ).all()
    rows = [
        [
            button(
                db,
                user_id,
                ("🟢 " if online(a) else "🔴 ") + a.name[:60],
                "agent:" + mode,
                a.id,
            )
        ]
        for a in agents[:10]
    ]
    if offset:
        rows.append(
            [button(db, user_id, "← Назад", "page:" + mode, str(max(0, offset - 10)))]
        )
    if len(agents) > 10:
        rows.append([button(db, user_id, "Далее →", "page:" + mode, str(offset + 10))])
    rows.append([button(db, user_id, "Главное меню", "menu")])
    return keyboard(rows)


def agent_view(db, user_id, agent_id, mode):
    agent = require_agent(db, agent_id)
    check = db.scalar(
        select(Check)
        .where(Check.agent_id == agent.id)
        .order_by(Check.created_at.desc())
        .limit(1)
    )
    sponsor = db.get(Sponsorship, agent.id)
    config = agent.configuration or {}
    text = (
        f"🖥 {agent.name}\n{agent.public_host or 'Домен не определён'}:{agent.proxy_port}\n"
        f"Floating IP: {config.get('floating_ip') or 'не настроен'}\n"
        f"Связь: {'онлайн' if online(agent) else 'нет heartbeat'}\n"
        f"Telemt: {agent.facts.get('telemt_service', 'неизвестно')}\n"
        f"Мониторинг: {check.result if check else 'нет проверок'}\n"
        f"Спонсорство: {sponsor.status if sponsor else 'не настроено'}\n"
        f"Автоматизация: {'приостановлена' if agent.paused else 'ручной безопасный режим'}"
    )
    rows = [
        [button(db, user_id, "🔍 Проверить из РФ", "check", agent.id)],
        [
            button(
                db,
                user_id,
                "Возобновить" if agent.paused else "Приостановить",
                "resume" if agent.paused else "pause",
                agent.id,
            )
        ],
        [
            button(
                db,
                user_id,
                "🔄 Подготовить восстановление",
                "prepare_recovery",
                agent.id,
            )
        ],
        [button(db, user_id, "История IP", "agent_ips", agent.id)],
        [button(db, user_id, "Обновить", "agent:" + mode, agent.id)],
        [button(db, user_id, "Главное меню", "menu")],
    ]
    return text, keyboard(rows)


@router.message(CommandStart())
@router.message(F.text == "Меню")
async def start(message: Message):
    with SessionLocal() as db:
        markup = menu(db, message.from_user.id)
        db.commit()
    await message.answer(
        "AutoIP Commander\nВыберите раздел. Платные операции отключены.",
        reply_markup=markup,
    )


@router.callback_query(F.data.startswith("a:"))
async def callback(query: CallbackQuery):
    try:
        with SessionLocal() as db:
            action = consume_action(db, query.from_user.id, query.data[2:])
            text, markup = dispatch_action(db, query.from_user.id, action)
            db.commit()
        await query.answer()
        try:
            await query.message.edit_text(text[:4000], reply_markup=markup)
        except TelegramBadRequest:
            # The action was already committed. Do not execute it a second time.
            await query.message.answer(text[:4000], reply_markup=markup)
    except HTTPException as exc:
        await query.answer(str(exc.detail), show_alert=True)


def dispatch_action(db, user_id, item):
    actor = "telegram:" + str(user_id)
    action, target = item.action, item.target
    text = "AutoIP Commander"
    markup = None
    if action == "menu":
        markup = menu(db, user_id)
    elif action == "status":
        agents = db.scalars(select(Agent).where(Agent.revoked.is_(False))).all()
        count = sum(online(a) for a in agents)
        text = f"📊 Всего агентов: {len(agents)}\nОнлайн: {count}\nОфлайн: {len(agents) - count}\nПлатные операции отключены."
    elif action in ("agents", "checks", "recovery", "automation"):
        text = "Выберите агента"
        markup = agent_buttons(db, user_id, action)
    elif action.startswith("page:"):
        text = "Выберите агента"
        markup = agent_buttons(db, user_id, action.split(":", 1)[1], int(target))
    elif action.startswith("agent:"):
        return agent_view(db, user_id, target, action.split(":", 1)[1])
    elif action == "check":
        task = request_check(db, target, actor)
        text = f"Проверка поставлена в очередь.\nЗадание: {task.id}\nРезультат появится в карточке агента и панели."
        markup = keyboard(
            [[button(db, user_id, "Обновить статус агента", "agent:checks", target)]]
        )
    elif action in ("pause", "resume"):
        set_paused(db, target, action == "pause", actor)
        return agent_view(db, user_id, target, "automation")
    elif action == "prepare_recovery":
        agent = require_agent(db, target)
        text = f"Подготовить план восстановления для {agent.name}?\nПроверим настройки и сохраним результат. Покупки и изменения DNS отключены."
        markup = keyboard(
            [
                [
                    button(
                        db,
                        user_id,
                        "Подтвердить проверку",
                        "confirm_recovery",
                        target,
                        5,
                    )
                ],
                [button(db, user_id, "Отмена", "menu")],
            ]
        )
    elif action == "confirm_recovery":
        recovery = recovery_plan(db, target, actor, "bot:" + item.token_hash)
        return recovery_view(db, user_id, recovery)
    elif action == "recovery_status":
        recovery = db.get(Recovery, target)
        if not recovery:
            raise HTTPException(404, "Операция не найдена")
        return recovery_view(db, user_id, recovery)
    elif action.startswith("incident:"):
        incident_action(db, target, action.split(":", 1)[1], actor)
        text = "Решение сохранено. Для подтверждённой блокировки сначала выполняется заключительная проверка."
    elif action in ("ips", "agent_ips"):
        query = select(FloatingIP).order_by(FloatingIP.created_at.desc()).limit(20)
        if action == "agent_ips":
            query = query.where(FloatingIP.agent_id == target)
        ips = db.scalars(query).all()
        text = "🌐 Последние IP\n" + (
            "\n".join(
                f"{i.ipv4} · {i.status} · {'управляемый' if i.managed else 'наблюдение'}"
                for i in ips
            )
            or "Учтённых ресурсов пока нет"
        )
    elif action == "costs":
        report = cost_report(db)
        agents = db.scalars(
            select(Agent).where(Agent.revoked.is_(False)).limit(20)
        ).all()
        text = (
            f"💰 Учтено: {report['recorded_cents'] / 100:.2f} EUR\nРесурсов с неизвестной стоимостью: {report['unknown_cost_resources']}\n"
            "Реальный счёт Cherry не сверялся.\nЛимиты агентов (EUR/месяц):\n"
            + "\n".join(
                f"{a.name}: {(a.configuration or {}).get('monthly_budget_cents', 0) / 100:.2f}"
                for a in agents
            )
        )
    elif action == "history":
        events = db.scalars(
            select(Audit).order_by(Audit.created_at.desc()).limit(15)
        ).all()
        text = "📜 Последние операции\n" + (
            "\n".join(f"{display_time(e.created_at)} · {e.action}" for e in events)
            or "История пуста"
        )
    else:
        raise HTTPException(422, "Неизвестное действие")
    return text, markup or keyboard([[button(db, user_id, "Главное меню", "menu")]])


def recovery_view(db, user_id, recovery):
    text = f"🔄 Восстановление {recovery.id[:8]}\nСтатус: {recovery.status}\n"
    text += "\n".join(f"{s['stage']}: {s['status']}" for s in recovery.stages)
    text += "\nПлатные действия не выполнялись. Для недостающих настроек используйте защищённую панель."
    return text, keyboard(
        [
            [button(db, user_id, "Обновить этапы", "recovery_status", recovery.id)],
            [button(db, user_id, "Главное меню", "menu")],
        ]
    )


def incident_keyboard(db, user_id, identifier):
    incident = db.get(Incident, identifier)
    if not incident or incident.status not in ACTIVE_INCIDENTS:
        return None
    labels = [
        ("Подтвердить блокировку", "confirm"),
        ("Прокси работает", "working"),
        ("Повторить проверку", "recheck"),
        ("Отложить автоматизацию", "hold"),
    ]
    return keyboard(
        [
            [button(db, user_id, label, "incident:" + action, identifier, 30)]
            for label, action in labels
        ]
    )


async def deliver(bot):
    # One dedicated bot process; Telegram updates and deliveries are separate from API.
    while True:
        try:
            for user_id in admin_ids():
                with SessionLocal() as db:
                    existing = select(Delivery.notification_id).where(
                        Delivery.user_id == str(user_id),
                        Delivery.delivered_at.is_not(None),
                    )
                    notices = db.scalars(
                        select(Notification)
                        .where(Notification.id.not_in(existing))
                        .order_by(Notification.created_at)
                        .limit(10)
                    ).all()
                    pending = [(n.id, n.text, n.topic, n.target) for n in notices]
                for identifier, text, topic, target in pending:
                    with SessionLocal() as db:
                        markup = (
                            incident_keyboard(db, user_id, target)
                            if topic == "incident"
                            else None
                        )
                        db.commit()
                    try:
                        sent = await bot.send_message(
                            user_id, text[:4000], reply_markup=markup
                        )
                    except TelegramAPIError:
                        log.warning(
                            "Notification delivery deferred; user_id=%s", user_id
                        )
                        continue
                    with SessionLocal() as db:
                        db.add(
                            Delivery(
                                notification_id=identifier,
                                user_id=str(user_id),
                                message_id=sent.message_id,
                                delivered_at=utcnow(),
                            )
                        )
                        db.commit()
        except Exception:
            log.error("Notification iteration failed")
        await asyncio.sleep(5)


async def main():
    if not admin_ids():
        raise RuntimeError(
            "Задайте AUTOIP_TELEGRAM_ADMIN_IDS: список разрешённых Telegram User ID"
        )
    with SessionLocal() as db:
        integrations = db.scalars(
            select(Integration)
            .where(Integration.kind == "telegram_bot")
            .order_by(Integration.created_at)
        ).all()
        if len(integrations) > 1:
            raise RuntimeError(
                "Для сервиса бота выберите единственную интеграцию telegram_bot"
            )
        token = (
            decrypt(integrations[0])["token"]
            if integrations
            else settings.telegram_bot_token
        )
    if not token:
        raise RuntimeError(
            "Добавьте токен локальной командой commander.manage integration telegram_bot"
        )
    bot = Bot(token=token)
    dispatcher = Dispatcher(disable_fsm=True)
    dispatcher.include_router(router)
    delivery = asyncio.create_task(deliver(bot))
    try:
        await dispatcher.start_polling(
            bot, allowed_updates=["message", "callback_query"]
        )
    finally:
        delivery.cancel()
        try:
            await delivery
        except asyncio.CancelledError:
            pass
        await bot.session.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    asyncio.run(main())
