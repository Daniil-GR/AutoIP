#!/usr/bin/env python3
"""Show local panel credentials only to an administrator's interactive terminal."""

import os
import stat
import sys
from pathlib import Path

from dotenv import dotenv_values


def main():
    if os.geteuid() != 0 or not sys.stdin.isatty() or not sys.stdout.isatty():
        raise SystemExit(
            "Запустите от root в своём интерактивном терминале. Вывод в файл или канал запрещён."
        )
    path = Path(__file__).resolve().parents[1] / ".env"
    if path.is_symlink() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise SystemExit(
            "Файл .env должен быть обычным закрытым файлом с правами 0600."
        )
    values = dotenv_values(path)
    password = values.get("AUTOIP_ADMIN_PASSWORD")
    if not password:
        raise SystemExit("Пароль администратора не настроен.")
    print("Панель:", values.get("AUTOIP_PUBLIC_URL", ""))
    print("Логин:", values.get("AUTOIP_ADMIN_USER", "admin"))
    print("Пароль:", password)
    print("Не отправляйте этот вывод в чат или снимках экрана.")


if __name__ == "__main__":
    main()
