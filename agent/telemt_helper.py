#!/usr/bin/env python3
"""Restricted root-side TOML update. Never accepts a path or shell command from network."""

import fcntl
import json
import socket
import struct
import pwd
import os
import re
import sys
import tempfile
from pathlib import Path

import tomlkit

CONFIG = Path("/etc/telemt/telemt.toml")


def _apply_ad_tag_locked(tag: str):
    if os.geteuid() != 0:
        raise RuntimeError("Root required")
    if not re.fullmatch(r"[a-fA-F0-9]{32}", tag):
        raise ValueError("ad_tag must be 32 hex characters")
    if CONFIG.is_symlink() or not CONFIG.is_file():
        raise RuntimeError("Unexpected Telemt config path")
    st = CONFIG.stat()
    current = CONFIG.read_text()
    doc = tomlkit.parse(current)
    if "general" not in doc:
        raise RuntimeError("Telemt [general] section missing")
    if doc["general"].get("ad_tag") == tag.lower():
        return "ad_tag already applied"
    doc["general"]["ad_tag"] = tag.lower()
    rendered = tomlkit.dumps(doc)
    tomlkit.parse(rendered)
    backup = CONFIG.with_name(CONFIG.name + ".autoip.bak")
    if backup.is_symlink():
        raise RuntimeError("Unsafe backup path")
    backup_fd = os.open(
        backup, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(backup_fd, "w") as saved:
        saved.write(current)
        saved.flush()
        os.fsync(saved.fileno())
    os.chmod(backup, 0o600)
    fd, temp = tempfile.mkstemp(prefix=".autoip-", dir=str(CONFIG.parent))
    try:
        os.fchmod(fd, st.st_mode & 0o777)
        os.fchown(fd, st.st_uid, st.st_gid)
        with os.fdopen(fd, "w") as f:
            f.write(rendered)
            f.flush()
            os.fsync(f.fileno())
        if CONFIG.read_text() != current:
            raise RuntimeError("Telemt config changed concurrently")
        os.replace(temp, CONFIG)
        directory = os.open(CONFIG.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    return "ad_tag written; check Telemt hot-reload logs before marking fully applied"


def apply_ad_tag(tag: str):
    lock_path = CONFIG.parent / ".autoip-config.lock"
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _apply_ad_tag_locked(tag)


def serve_one():
    from .main import config_facts

    # systemd socket activation supplies the connected Unix socket as stdin.
    channel = socket.socket(fileno=os.dup(0))
    _, uid, _ = struct.unpack(
        "3i",
        channel.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        ),
    )
    if uid != pwd.getpwnam("autoip-agent").pw_uid:
        raise RuntimeError("Unauthorized local peer")
    channel.settimeout(10)
    stream = channel.makefile("rwb")
    raw = stream.readline(4097)
    if len(raw) > 4096 or not raw.endswith(b"\n"):
        raise RuntimeError("Invalid request length")
    request = json.loads(raw)
    operation = request.get("operation")
    if operation == "inspect" and set(request) == {"operation"}:
        import tomllib

        if CONFIG.is_symlink():
            raise RuntimeError("Unsafe config path")
        result = config_facts(tomllib.loads(CONFIG.read_text()))
    elif operation == "apply-ad-tag" and set(request) == {"operation", "ad_tag"}:
        flag = Path("/etc/autoip-agent/allow-ad-tag-write")
        if (
            not flag.is_file()
            or flag.is_symlink()
            or flag.stat().st_uid != 0
            or flag.stat().st_mode & 0o022
        ):
            raise RuntimeError("Local writes not explicitly enabled")
        apply_ad_tag(request["ad_tag"])
        result = {
            "written": True,
            "reload_verified": False,
            "message": "Config saved. Telemt hot reload requires independent verification",
        }
    else:
        raise ValueError("Operation not allowed")
    stream.write(json.dumps({"ok": True, "result": result}).encode() + b"\n")
    stream.flush()


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["serve-one"]:
            serve_one()
        elif sys.argv[1:] == ["apply-ad-tag"]:
            print(apply_ad_tag(sys.stdin.readline().strip()))
        else:
            sys.exit("Only inspect socket and apply-ad-tag are supported")
    except (OSError, ValueError, RuntimeError):
        # Never log a TOML parse exception: its context may contain a user secret.
        print("Restricted Telemt helper rejected operation", file=sys.stderr)
        sys.exit(1)
