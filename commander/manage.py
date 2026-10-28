"""Local interactive setup. No credentials on command line or in shell history."""

import argparse
import getpass
from pathlib import Path
from uuid import uuid4

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect

from .database import Integration, SessionLocal, engine
from .schemas import IntegrationInput
from .security import audit
from .vault import encrypt, initialize


def main():
    parser = argparse.ArgumentParser(description="Локальная настройка AutoIP")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("migrate")
    sub.add_parser("adopt-v01")
    sub.add_parser("policy-init")
    telethon = sub.add_parser("telethon-login")
    telethon.add_argument("name", nargs="?", default="Telegram account")
    telethon.add_argument("--integration-id")
    sponsor = sub.add_parser("sponsor-agent")
    sponsor.add_argument("agent_id")
    sponsor.add_argument("--approve-new-registration", action="store_true")
    bootstrap = sub.add_parser("import-bootstrap")
    bootstrap.add_argument("path")
    key = sub.add_parser("vault-init")
    key.add_argument("path")
    integration = sub.add_parser("integration")
    integration.add_argument(
        "kind",
        choices=[
            "cherry",
            "dynadot",
            "telegram_bot",
            "telethon",
            "ripe_atlas",
            "mtproto",
        ],
    )
    args = parser.parse_args()
    if args.command == "telethon-login":
        import asyncio
        from .sponsorship import authorize_local

        asyncio.run(authorize_local(args.name, args.integration_id))
    elif args.command == "sponsor-agent":
        import asyncio
        from .sponsorship import sponsor_agent
        from .services import require_agent

        with SessionLocal() as db:
            agent = require_agent(db, args.agent_id)
            endpoint = f"{(agent.configuration or {}).get('floating_ip', '')}:{agent.proxy_port}"
        expected = f"REGISTER {args.agent_id} {endpoint}"
        print(
            "Реальное взаимодействие с MTProxybot может изменить регистрацию. Для подтверждения введите:",
            expected,
        )
        if input().strip() != expected:
            raise SystemExit("Отменено")
        asyncio.run(sponsor_agent(args.agent_id, args.approve_new_registration))
    elif args.command == "policy-init":
        from .database import SystemSetting
        from .policy import get_policy

        with SessionLocal() as db:
            if not db.get(SystemSetting, "commander"):
                db.add(
                    SystemSetting(key="commander", value=get_policy(db).model_dump())
                )
                audit(db, "local-admin", "policy_initialized")
                db.commit()
        print("Настройки Commander сохранены в БД")
    elif args.command == "import-bootstrap":
        import json
        from .vault import decrypt

        entries = json.loads(Path(args.path).read_text())
        with SessionLocal() as db:
            for entry in entries:
                if db.get(Integration, entry["id"]):
                    continue
                item = Integration(**entry, metadata_json={})
                credentials = decrypt(item)
                body = IntegrationInput(
                    name=item.name, kind=item.kind, credentials=credentials
                )
                body.validate_keys()
                if item.kind == "telethon" and not credentials.get("session"):
                    item.status = "authorization_required"
                db.add(item)
                audit(
                    db, "local-admin", "integration_imported", item.id, kind=item.kind
                )
            db.commit()
        print("Зашифрованные интеграции импортированы; повторный импорт безопасен")
    elif args.command == "vault-init":
        initialize(args.path)
        print("Мастер-ключ создан. Сохраните отдельную защищённую резервную копию.")
    elif args.command in ("migrate", "adopt-v01"):
        cfg = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
        if args.command == "adopt-v01":
            tables = set(inspect(engine).get_table_names())
            if tables != {"agents", "enrollments", "checks", "jobs"}:
                raise SystemExit(
                    "Ожидалась исходная БД v0.1. Перед обновлением сделайте резервную копию."
                )
            # Validate every legacy column before assigning the baseline revision.
            import importlib.util
            from sqlalchemy import create_engine
            from alembic.migration import MigrationContext
            from alembic.operations import Operations

            spec = importlib.util.spec_from_file_location(
                "baseline",
                Path(cfg.get_main_option("script_location"))
                / "versions/0001_baseline.py",
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            tmp = create_engine("sqlite://")
            with tmp.begin() as conn:
                with Operations.context(MigrationContext.configure(conn)):
                    module.upgrade()
                for table in tables:
                    expected = {c["name"] for c in inspect(conn).get_columns(table)}
                    if expected != {
                        c["name"] for c in inspect(engine).get_columns(table)
                    }:
                        raise SystemExit("Неизвестная схема v0.1: " + table)
            command.stamp(cfg, "0001_baseline")
        command.upgrade(cfg, "head")
        print("Миграции применены")
    else:
        fields = {
            "cherry": ["api_key"],
            "dynadot": ["api_key", "api_secret"],
            "telegram_bot": ["token"],
            "telethon": ["api_id", "api_hash", "session"],
            "ripe_atlas": ["api_key"],
            "mtproto": ["secret"],
        }[args.kind]
        name = input("Название интеграции: ").strip()
        credentials = {
            field: getpass.getpass(field + " (ввод скрыт): ") for field in fields
        }
        body = IntegrationInput(name=name, kind=args.kind, credentials=credentials)
        body.validate_keys()
        identifier = str(uuid4())
        with SessionLocal() as db:
            db.add(
                Integration(
                    id=identifier,
                    name=name,
                    kind=args.kind,
                    ciphertext=encrypt(identifier, args.kind, credentials),
                    metadata_json={},
                )
            )
            audit(db, "local-admin", "integration_created", identifier, kind=args.kind)
            db.commit()
        print("Интеграция сохранена, ID:", identifier)


if __name__ == "__main__":
    main()
