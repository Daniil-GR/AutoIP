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
    KeyboardButton,
    Message,
    ReplyKeyboardMarkup,
)
from fastapi import HTTPException
from sqlalchemy import select

from .config import settings
from .database import (
    Agent,
    Audit,
    BotAction,
    Check,
    ControlTask,
    Delivery,
    FloatingIP,
    Incident,
    Integration,
    Notification,
    Recovery,
    SessionLocal,
    SystemSetting,
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
    request_sni_check,
    require_agent,
    set_paused,
)
from .vault import decrypt
from .policy import get_policy
from .sponsorship import status_label as sponsorship_label

router = Router()
log = logging.getLogger(__name__)

# Only navigation is reusable. Checks, confirmations and incident decisions
# retain their expiry and transactional single-use guard, including old tokens.
NAVIGATION_ACTIONS = frozenset(
    {
        "menu",
        "status",
        "agents",
        "checks",
        "recovery",
        "automation",
        "ips",
        "vps",
        "costs",
        "history",
        "agent_ips",
        "recovery_status",
        "prepare_sni",
        "prepare_recovery",
        "cdn_domains",
        "cdn_status",
    }
    | {"agent:" + mode for mode in ("agents", "checks", "recovery", "automation")}
    | {"page:" + mode for mode in ("agents", "checks", "recovery", "automation")}
)


def persistent_menu():
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="🏠 Главное меню"), KeyboardButton(text="🖥 Агенты")]
        ],
        resize_keyboard=True,
        is_persistent=True,
    )


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
    if not action or action.user_id != str(user_id):
        raise HTTPException(409, "Кнопка недоступна. Открыто новое меню.")
    if action.action in NAVIGATION_ACTIONS:
        return action
    if action.used_at or aware(action.expires_at) <= utcnow():
        raise HTTPException(
            409, "Подтверждение устарело или уже использовано. Действие не выполнено."
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
        ("▣ VPS Node Host", "vps"),
        ("🌐 Поддомены CDN", "cdn_domains"),
        ("💰 Расходы", "costs"),
        ("📜 История операций", "history"),
        ("⚙️ Настройки автоматизации", "automation"),
    ]
    buttons = [button(db, user_id, label, action) for label, action in entries]
    rows = [buttons[:1]] + [buttons[i : i + 2] for i in range(1, len(buttons), 2)]
    if settings.public_url.startswith("https://"):
        rows.append(
            [
                InlineKeyboardButton(
                    text="🌐 Открыть веб-панель", url=settings.public_url
                )
            ]
        )
    return keyboard(rows)


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
        .where(Check.agent_id == agent.id, ~Check.result.startswith("sni_"))
        .order_by(Check.created_at.desc())
        .limit(1)
    )
    sponsor = db.get(Sponsorship, agent.id)
    config = agent.configuration or {}
    from .mtproto_checker import status_label

    evidence = (check.details or {}) if check else {}
    monitor_state = (
        {
            "reachable": "доступен",
            "tcp_only": "TCP доступен; MTProto не подтверждён",
            "suspected": "вероятная недоступность из РФ",
            "proxy_degraded": "прокси недоступен или деградировал",
            "local_fault": "проблема агента или Telemt",
            "unknown": "недостаточно данных",
            "cdn_web_reachable": "HTTPS CDN: доступ из РФ обнаружен; данные прокси не проверены",
            "cdn_web_suspected": "возможна недоступность HTTPS CDN из РФ",
            "cdn_web_unknown": "недостаточно данных о CDN",
        }.get(check.result, check.result)
        if check
        else "нет проверок"
    )
    web = evidence.get("web_endpoint", {})
    web_state = (
        "HTTPS-адрес доступен (данные веб-прокси не проверены)"
        if web.get("status") == "reachable"
        else "нет подтверждённого результата"
    )
    sni = db.scalar(
        select(Check)
        .where(Check.agent_id == agent.id, Check.result.startswith("sni_"))
        .order_by(Check.created_at.desc())
        .limit(1)
    )
    sni_state = (
        {
            "suspected_ru_filtering": "возможна фильтрация в РФ; нужна перепроверка",
            "ru_accessible": "доступен на выбранных зондах РФ",
            "inconclusive": "недостаточно данных",
        }.get((sni.details or {}).get("comparison"), "нет сравнительных проверок")
        if sni
        else "нет проверок"
    )
    cdn = config.get("monitoring_mode") == "cdn_web"
    if cdn and check and (check.details or {}).get("monitoring_mode") != "cdn_web":
        monitor_state = "проверок CDN ещё нет"
    if cdn and check and check.result == "cdn_web_reachable":
        web_state = "HTTPS CDN доступен; передача данных прокси отдельно не проверялась"
    if config.get("proxy_mode") == "mtproto_faketls":
        web_state = "не используется в режиме MTProto FakeTLS"
    if cdn and sni and (sni.details or {}).get("scope") != "cdn-edge-tls-sni":
        sni_state = "проверок CDN ещё нет"
    protocol_state = (
        "не используется для WEB через CDN"
        if cdn
        else status_label(evidence.get("mtproto_status", "UNKNOWN"))
    )
    client_host = (
        config.get("web_proxy_host") or config.get("dns_record") or agent.public_host
        if cdn
        else agent.public_host
    )
    client_port = 443 if cdn else agent.proxy_port
    from .reserve_recovery import reserve_readiness

    reserve = reserve_readiness(db, agent)
    from .paid_recovery import enabled as paid_enabled

    automation = (
        "приостановлена"
        if agent.paused
        else "включены автопокупки и замена IP"
        if paid_enabled(db, agent.id)
        else "включено переключение на подготовленный резерв"
        if reserve["enabled"]
        else "резерв подготовлен; переключение выключено"
        if reserve["prepared"]
        else "резерв использован; переключение выключено"
        if reserve["policy"].get("consumed_by")
        else "ручной безопасный режим"
    )
    if cdn:
        automation = (
            "мониторинг приостановлен"
            if agent.paused
            else "мониторинг включён; смена IP и DNS выключена для CDN"
        )
    setup_mode = (
        "Web через CDN"
        if cdn
        else "MTProto FakeTLS · 443"
        if config.get("proxy_mode") == "mtproto_faketls"
        else "Web + MTProto"
    )
    text = (
        f"🖥 {agent.name}\n{client_host or 'Домен не определён'}:{client_port}\n"
        f"Режим: {setup_mode}\n"
        f"DNS: {config.get('dns_record') or 'не задан'}\n"
        f"{'Origin CDN' if cdn else 'Floating IP'}: {config.get('floating_ip') or 'не настроен'}\n"
        f"Management IPv4: {config.get('management_ip') or config.get('proxy_ip') or 'не указан'}\n"
        f"Связь: {'онлайн' if online(agent) else 'нет heartbeat'}\n"
        f"Telemt: {agent.facts.get('telemt_service', 'неизвестно')}\n"
        f"Мониторинг: {monitor_state}\n"
        f"Последняя проверка: {display_time(check.created_at) if check else 'ещё не выполнялась'}\n"
        f"MTProto Checker: {protocol_state}\n"
        f"Веб-прокси: {web_state}\n"
        f"SNI РФ / зарубежье: {sni_state}\n"
        f"Спонсорство: {sponsorship_label(sponsor.status if sponsor else None)}\n"
        f"Автоматизация: {automation}"
    )
    rows = [
        [button(db, user_id, "🔍 Проверить из РФ", "check", agent.id)],
        [
            button(
                db, user_id, "Дополнительно: SNI / RIPE Atlas", "prepare_sni", agent.id
            )
        ],
        [
            button(
                db,
                user_id,
                (
                    "▶️ Возобновить мониторинг"
                    if agent.paused
                    else "⏸ Приостановить мониторинг"
                )
                if cdn
                else (
                    "▶️ Возобновить работу"
                    if agent.paused
                    else "⏸ Пауза мониторинга и автоматики"
                ),
                "resume" if agent.paused else "pause",
                agent.id,
            )
        ],
        [button(db, user_id, "История IP", "agent_ips", agent.id)],
        [button(db, user_id, "🔄 Обновить карточку", "agent:" + mode, agent.id)],
        [
            button(db, user_id, "← К списку агентов", "agents"),
            button(db, user_id, "🏠 Меню", "menu"),
        ],
    ]
    if not cdn:
        rows.insert(
            3,
            [
                button(
                    db,
                    user_id,
                    "🔄 Подготовить восстановление",
                    "prepare_recovery",
                    agent.id,
                )
            ],
        )
    return text, keyboard(rows)


@router.message(CommandStart())
@router.message(F.text.in_({"Меню", "🏠 Главное меню"}))
async def start(message: Message):
    with SessionLocal() as db:
        markup = menu(db, message.from_user.id)
        from .paid_recovery import enabled_count

        paid_count = enabled_count(db)
        db.commit()
    await message.answer("Управление AutoIP", reply_markup=persistent_menu())
    await message.answer(
        f"AutoIP Commander\nВыберите раздел. Автопокупки разрешены для агентов: {paid_count}.",
        reply_markup=markup,
    )


@router.message(F.text == "🖥 Агенты")
async def open_agents(message: Message):
    with SessionLocal() as db:
        markup = agent_buttons(db, message.from_user.id, "agents")
        db.commit()
    await message.answer("Выберите агента", reply_markup=markup)


def cdn_task_view(db, user_id, task):
    from .cdn_domains import status_text

    text = status_text(task)
    rows = []
    if task.status == "draft":
        text += "\n\nСоздать CNAME, добавить имя в Gcore, дождаться сертификата и применить Nginx/Telemt? Возможен краткий перерыв при перезапуске Telemt. Новые платные ресурсы не создаются."
        rows.append(
            [button(db, user_id, "✅ Создать и настроить", "cdn_confirm", task.id, 15)]
        )
    if task.status == "manual":
        rows.append([button(db, user_id, "Повторить сверку", "cdn_retry", task.id, 15)])
    if task.status in ("draft", "queued", "manual"):
        rows.append(
            [
                button(
                    db,
                    user_id,
                    "Остановить; сохранить настройки",
                    "cdn_stop",
                    task.id,
                    15,
                )
            ]
        )
    rows += [
        [button(db, user_id, "🔄 Обновить", "cdn_status", task.id)],
        [button(db, user_id, "← Поддомены CDN", "cdn_domains")],
    ]
    return text, keyboard(rows)


@router.message(F.text)
async def cdn_name_input(message: Message):
    from datetime import datetime
    from .cdn_domains import AliasError, create

    user_id = message.from_user.id
    with SessionLocal() as db:
        pending = db.get(
            SystemSetting, "cdn-input:" + str(user_id), with_for_update=True
        )
        if not pending:
            return
        if (
            message.text == "/cancel"
            or aware(datetime.fromisoformat(pending.value["expires"])) <= utcnow()
        ):
            db.delete(pending)
            db.commit()
            await message.answer("Ввод поддомена отменён.")
            return
        try:
            task = create(db, pending.value["agent_id"], message.text, user_id)
            db.flush()
            text, markup = cdn_task_view(db, user_id, task)
        except (AliasError, ValueError) as exc:
            await message.answer(str(exc))
            return
        db.delete(pending)
        db.commit()
    await message.answer(text, reply_markup=markup)


@router.callback_query(F.data.startswith("a:"))
async def callback(query: CallbackQuery):
    try:
        with SessionLocal() as db:
            action = consume_action(db, query.from_user.id, query.data[2:])
            from .cdn_domains import AliasError

            try:
                text, markup = dispatch_action(db, query.from_user.id, action)
            except (AliasError, ValueError) as exc:
                raise HTTPException(409, str(exc)) from None
            db.commit()
        await query.answer()
        try:
            await query.message.edit_text(text[:4000], reply_markup=markup)
        except TelegramBadRequest:
            # The action was already committed. Do not execute it a second time.
            await query.message.answer(text[:4000], reply_markup=markup)
    except HTTPException as exc:
        if exc.status_code != 409:
            await query.answer(str(exc.detail), show_alert=True)
            return
        with SessionLocal() as db:
            markup = menu(db, query.from_user.id)
            db.commit()
        await query.answer("Открыто актуальное меню. Действие не повторялось.")
        await query.message.answer(str(exc.detail), reply_markup=markup)


def dispatch_action(db, user_id, item):
    actor = "telegram:" + str(user_id)
    action, target = item.action, item.target
    text = "AutoIP Commander"
    markup = None
    if action == "cdn_domains":
        from .cdn_domains import KIND

        rows = []
        for agent in db.scalars(select(Agent).where(Agent.revoked.is_(False))):
            if db.get(SystemSetting, "cdn-bind:" + agent.id):
                rows.append(
                    [button(db, user_id, "➕ " + agent.name, "cdn_input", agent.id)]
                )
        for task in db.scalars(
            select(ControlTask)
            .where(ControlTask.kind == KIND)
            .order_by(ControlTask.created_at.desc())
            .limit(8)
        ):
            rows.append(
                [button(db, user_id, task.payload["hostname"], "cdn_status", task.id)]
            )
        rows.append([button(db, user_id, "🏠 Меню", "menu")])
        return (
            "🌐 Поддомены CDN\nВыберите ноду, чтобы добавить свободное имя. Существующие DNS-записи не заменяются.",
            keyboard(rows),
        )
    elif action == "cdn_input":
        from .cdn_domains import binding

        binding(db, target)
        key = "cdn-input:" + str(user_id)
        pending = db.get(SystemSetting, key)
        value = {
            "agent_id": target,
            "expires": (utcnow() + timedelta(minutes=15)).isoformat(),
        }
        if pending:
            pending.value = value
        else:
            db.add(SystemSetting(key=key, value=value))
        return (
            "Отправьте новое имя, например lt1.vetka.rest. Можно написать только lt1. Для отмены отправьте /cancel. Ключи и пароли сюда не отправляйте.",
            None,
        )
    elif action == "cdn_confirm":
        from .cdn_domains import confirm

        task = confirm(db, target, user_id)
        return cdn_task_view(db, user_id, task)
    elif action == "cdn_status":
        return cdn_task_view(db, user_id, db.get(ControlTask, target))
    elif action in ("cdn_retry", "cdn_stop"):
        from .cdn_domains import AliasError, KIND

        task = db.get(ControlTask, target, with_for_update=True)
        if not task or task.kind != KIND or task.payload["user_id"] != str(user_id):
            raise AliasError("Операция недоступна")
        if action == "cdn_retry":
            if task.status != "manual":
                raise AliasError("Операция уже выполняется или завершена")
            task.status = "queued"
            task.payload = {
                **task.payload,
                "next_at": None,
                "deadline": (utcnow() + timedelta(hours=1)).isoformat(),
            }
            task.result = {}
        else:
            if task.status not in ("draft", "queued", "manual"):
                raise AliasError(
                    "Этап выполняется; обновите статус после его завершения"
                )
            task.status = "cancelled"
            task.result = {
                "message": "Остановка подтверждена. Уже добавленные DNS/CDN-имена сохранены; автоматического удаления нет."
            }
        from .security import audit

        audit(db, actor, action, target)
        return cdn_task_view(db, user_id, task)
    elif action == "menu":
        pending = db.get(SystemSetting, "cdn-input:" + str(user_id))
        if pending:
            db.delete(pending)
        markup = menu(db, user_id)
    elif action == "status":
        agents = db.scalars(select(Agent).where(Agent.revoked.is_(False))).all()
        count = sum(online(a) for a in agents)
        interval = get_policy(db).monitor_interval_seconds
        from .paid_recovery import enabled_count

        paid_count = enabled_count(db)
        text = f"📊 Всего агентов: {len(agents)}\nОнлайн: {count}\nОфлайн: {len(agents) - count}\nИнтервал проверок: {interval} сек.\nИсточники задаются для каждой ноды. WEB через CDN: Check-Host и RIPE Atlas; прямой MTProto: MTProto Checker и Check-Host.\nАвтопокупки разрешены для агентов: {paid_count}."
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
            [
                [button(db, user_id, "Обновить статус агента", "agent:checks", target)],
                [button(db, user_id, "🏠 Меню", "menu")],
            ]
        )
    elif action == "prepare_sni":
        agent = require_agent(db, target)
        integrations = db.scalars(
            select(Integration).where(Integration.kind == "ripe_atlas").limit(10)
        ).all()
        text = f"RIPE Atlas · {agent.name}\nОдин IPv4 и SNI: РФ, Германия, Нидерланды, Финляндия. Измерение расходует кредиты RIPE Atlas. Неполное покрытие и таймаут не доказывают блокировку."
        if not integrations:
            text += "\nСначала сохраните ключ RIPE Atlas в защищённой веб-панели. Секреты в Telegram не вводите."
        markup = keyboard(
            [
                [
                    button(
                        db,
                        user_id,
                        "Подтвердить расход кредитов: " + i.name[:40],
                        "confirm_sni",
                        target + ":" + i.id,
                        5,
                    )
                ]
                for i in integrations
            ]
            + [[button(db, user_id, "← К агенту", "agent:checks", target)]]
        )
    elif action == "confirm_sni":
        agent_id, integration_id = target.split(":", 1)
        task = request_sni_check(db, agent_id, integration_id, actor)
        text = (
            "Проверка SNI поставлена в очередь: "
            + task.id
            + ". Результат появится в мониторинге панели и карточке агента."
        )
        markup = keyboard(
            [
                [button(db, user_id, "Обновить агента", "agent:checks", agent_id)],
                [button(db, user_id, "🏠 Меню", "menu")],
            ]
        )
    elif action in ("pause", "resume"):
        set_paused(db, target, action == "pause", actor)
        return agent_view(db, user_id, target, "automation")
    elif action == "prepare_recovery":
        agent = require_agent(db, target)
        if (agent.configuration or {}).get("monitoring_mode") == "cdn_web":
            text, markup = agent_view(db, user_id, target, "recovery")
            return (
                text
                + "\n\nВосстановление через CDN пока недоступно: требуется управление origin. CNAME сохранён.",
                markup,
            )
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
        agent = require_agent(db, target)
        if (agent.configuration or {}).get("monitoring_mode") == "cdn_web":
            raise HTTPException(
                409, "Режим агента изменён на CDN. Восстановление не запускалось."
            )
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
    elif action == "vps":
        from .nodehost import resources

        items = resources(db)
        text = (
            "▣ VPS Node Host\nАвтопокупки VPS выключены; готовится отдельный пилот.\n"
        )
        text += (
            "\n".join(
                r["ipv4"]
                + " · "
                + ("Найден в истории" if r["status"] == "discovered" else r["status"])
                for r in items[:20]
            )
            or "Нет импортированных VPS"
        )
        text += "\nПроверка SSH и ОС доступна в разделе VPS Node Host веб-панели. Секреты в Telegram не отправляйте."
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
    if markup is None:
        rows = []
        if action in NAVIGATION_ACTIONS and action != "menu":
            rows.append([button(db, user_id, "🔄 Обновить", action, target)])
        if action == "agent_ips":
            rows.append([button(db, user_id, "← К агенту", "agent:agents", target)])
        rows.append([button(db, user_id, "🏠 Главное меню", "menu")])
        markup = keyboard(rows)
    return text, markup


def recovery_view(db, user_id, recovery):
    from .reserve_recovery import STAGE_LABELS

    def label(value):
        return STAGE_LABELS.get(value, value)

    text = f"🔄 Восстановление {recovery.id[:8]}\nСтатус: {label(recovery.status)}\n"
    text += "\n".join(
        f"{label(s['stage'])}: {label(s['status'])}"
        + (f" — {s['reason']}" if s.get("reason") else "")
        for s in recovery.stages
    )
    paid = db.get(SystemSetting, "paid-recovery:" + recovery.id)
    if paid:
        text += f"\nАвтоматическая замена. Получено адресов: {len(paid.value.get('candidates', []))}. Расходы доступны в разделе «Расходы»."
    else:
        text += "\nПлатные действия не выполнялись. Для недостающих настроек используйте защищённую панель."
    return text, keyboard(
        [
            [button(db, user_id, "Обновить этапы", "recovery_status", recovery.id)],
            [button(db, user_id, "← К агенту", "agent:recovery", recovery.agent_id)],
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
                        if topic == "recovery" and db.get(Recovery, target):
                            markup = keyboard(
                                [
                                    [
                                        button(
                                            db,
                                            user_id,
                                            "Этапы восстановления",
                                            "recovery_status",
                                            target,
                                        )
                                    ]
                                ]
                            )
                        if topic == "cdn_alias" and db.get(ControlTask, target):
                            _, markup = cdn_task_view(
                                db, user_id, db.get(ControlTask, target)
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
        except Exception as error:
            from .diagnostics import record_failure

            record_failure("bot", "notification_iteration", error)
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
