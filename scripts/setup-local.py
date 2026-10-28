#!/usr/bin/env python3
"""Create isolated local configuration; optionally stage already supplied credentials."""

import argparse
import getpass
import json
import os
import secrets
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from cryptography.fernet import Fernet


def exclusive(path, value, mode=0o600):
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-url", required=True)
    parser.add_argument("--telegram-admin", type=int, required=True)
    parser.add_argument("--stage-credentials", action="store_true")
    args = parser.parse_args()
    parsed = urlsplit(args.public_url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.path not in ("", "/")
        or parsed.username
        or parsed.query
        or parsed.fragment
    ):
        raise SystemExit("Требуется HTTPS-адрес Commander")
    root = Path(__file__).resolve().parents[1]
    folder = root / "secrets"
    folder.mkdir(mode=0o700, exist_ok=True)
    key_path = folder / "master.key"
    env_path = root / ".env"
    if not env_path.exists() and not key_path.exists():
        key = Fernet.generate_key()
        exclusive(key_path, key.decode() + "\n")
        # Container services run under uid 10001. Parent folder stays root-only.
        if os.geteuid() == 0:
            os.chown(key_path, 10001, 10001)
        values = {
            "AUTOIP_ADMIN_USER": "admin",
            "AUTOIP_ADMIN_PASSWORD": secrets.token_urlsafe(36),
            "POSTGRES_PASSWORD": secrets.token_urlsafe(36),
            "AUTOIP_PUBLIC_URL": args.public_url.rstrip("/"),
            "AUTOIP_TELEGRAM_ADMIN_IDS": json.dumps([args.telegram_admin]),
            "AUTOIP_VAULT_KEY_FILE": str(key_path),
            "AUTOIP_MONITOR_ENABLED": "false",
            "AUTOIP_MONITOR_INTERVAL_SECONDS": "180",
            "AUTOIP_BIND_PORT": "18080",
        }
        exclusive(env_path, "".join(f"{k}={v}\n" for k, v in values.items()))
    elif not (env_path.exists() and key_path.exists()):
        raise SystemExit(
            "Неполная конфигурация: проверьте .env и мастер-ключ. Файлы не перезаписаны."
        )
    if args.stage_credentials:
        cipher = Fernet(key_path.read_bytes().strip())
        entries = []
        for kind, name, field in [
            ("telegram_bot", "AutoIP Commander", "token"),
            ("cherry", "Cherry Servers", "api_key"),
        ]:
            value = getpass.getpass(f"{name}, {field} (ввод скрыт): ")
            if not value:
                continue
            identifier = str(uuid4())
            envelope = {"id": identifier, "kind": kind, "credentials": {field: value}}
            ciphertext = cipher.encrypt(json.dumps(envelope).encode()).decode()
            entries.append(
                {"id": identifier, "kind": kind, "name": name, "ciphertext": ciphertext}
            )
        staged = folder / "bootstrap-integrations.json"
        exclusive(staged, json.dumps(entries))
        if os.geteuid() == 0:
            os.chown(staged, 10001, 10001)
    print(
        "Закрытая конфигурация AutoIP создана. Сервисы не запущены; секреты не выводились."
    )


if __name__ == "__main__":
    main()
