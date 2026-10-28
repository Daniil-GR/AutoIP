"""Encrypted credential envelopes. The master key never lives in the database."""

import json
import os
import stat
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .config import settings


class VaultError(ValueError):
    pass


def cipher():
    if not settings.vault_key_file:
        raise VaultError("Хранилище не настроено: задайте AUTOIP_VAULT_KEY_FILE")
    path = Path(settings.vault_key_file)
    if path.is_symlink() or not path.is_file():
        raise VaultError("Недопустимый файл мастер-ключа")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise VaultError("Мастер-ключ должен иметь права 0600")
    try:
        return Fernet(path.read_bytes().strip())
    except (ValueError, OSError):
        raise VaultError("Не удалось прочитать мастер-ключ") from None


def encrypt(identifier, kind, credentials):
    envelope = {"id": identifier, "kind": kind, "credentials": credentials}
    return cipher().encrypt(json.dumps(envelope).encode()).decode()


def decrypt(item):
    try:
        envelope = json.loads(cipher().decrypt(item.ciphertext.encode()))
        if envelope["id"] != item.id or envelope["kind"] != item.kind:
            raise VaultError("Несовпадение владельца секрета")
        return envelope["credentials"]
    except (InvalidToken, KeyError, ValueError):
        raise VaultError("Не удалось расшифровать интеграцию") from None


def initialize(path):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(Fernet.generate_key() + b"\n")
        f.flush()
        os.fsync(f.fileno())
