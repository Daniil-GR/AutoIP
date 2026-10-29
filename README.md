# AutoIP — Commander + Agent

Централизованное управление несколькими серверами Telemt. Русская панель, aiogram 3 бот администратора, защищённые интеграции, регистрация агентов, мониторинг и постоянные инциденты.

**v0.2, этап разработки. Платные операции, сеть и запись DNS заблокированы. Автоматическое восстановление ещё не готово к production.** Подробный проверенный статус и ограничения: [docs/IMPLEMENTATION_STATUS_RU.md](docs/IMPLEMENTATION_STATUS_RU.md).

## Развёртывание

Читайте [docs/deployment.md](docs/deployment.md). Не запускайте установщик Agent на действующем прокси без согласования. Commander по умолчанию слушает только `127.0.0.1:18080`, использует отдельный Compose project `autoip`; PostgreSQL не публикуется на хосте.

1. Создайте закрытую `.env` и мастер-ключ по инструкции.
2. `docker compose up -d --build` запускает только PostgreSQL, миграции, API и worker.
3. Подключите HTTPS на выделенном домене после проверки существующего reverse proxy.
4. Добавьте ключи через защищённую форму или `python -m commander.manage integration cherry`. Ввод секретов скрыт.
5. Для бота сохраните интеграцию `telegram_bot` и разрешённые User ID. Затем отдельно запускайте `docker compose --profile telegram up -d bot`.

Никогда не коммитьте `.env`, `secrets/`, Telethon session или резервные копии. Мастер-ключ хранится отдельно от PostgreSQL; без него восстановление ключей интеграций невозможно.

## Агенты

Мастер «Добавить агента» создаёт одноразовый код на 15 минут и показывает команду. Код вводится локально скрытым запросом `enroll-local`; его не требуется вставлять в командную строку. У агента исходящее HTTPS-соединение. Основной IP и маршруты AutoIP при подключении не меняет. См. [docs/agent-installation.md](docs/agent-installation.md).

В настройках Commander можно сохранить DNS-зону по умолчанию. Она копируется в настройки нового агента при регистрации; смена значения не затрагивает существующих агентов. Полное имя поддомена задаётся отдельно. Эти настройки не выполняют запись в DNS.

## Мониторинг

Обычный интервал — 5 минут. Check-Host проверяет TCP MTProto и отдельно HTTPS веб-адреса; MTProto Checker проверяет хендшейк и данные MTProto из RU и внешней точки. RIPE Atlas — дополнительная TLS/SNI-диагностика при недоступном или неопределённом ответе основного источника, с отдельным разрешением кредитов и часовым ограничением. Секреты вводятся только через защищённую панель или локально.

## Проверки

Python 3.12+. В отдельном virtualenv:

```sh
pip install -r commander/requirements.txt -r agent/requirements.txt -r requirements-dev.txt
python -m pytest -q
python -m compileall -q commander agent migrations
node --check commander/static/app.js
```

Тесты сами создают временные SQLite БД. Настоящий PostgreSQL проверяется отдельно на пустой БД `autoip_test` через `AUTOIP_TEST_POSTGRES_URL`. Браузер: `playwright install chromium`, затем `python scripts/browser-smoke.py`; он поднимает и удаляет собственный Commander на случайном loopback-порту, не вызывает провайдеров.

Обновление v0.1: сначала backup, затем `python -m commander.manage adopt-v01` на копии БД. Обычный старт больше не использует `create_all`.
