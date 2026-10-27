#!/usr/bin/env python3
"""Restricted root-side TOML update. Never accepts a path or shell command from network."""
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

import tomlkit

CONFIG = Path("/etc/telemt/telemt.toml")


def apply_ad_tag(tag: str):
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
    backup = CONFIG.with_name(CONFIG.name + ".autoip.bak")
    shutil.copy2(CONFIG, backup)
    fd, temp = tempfile.mkstemp(prefix=".autoip-", dir=str(CONFIG.parent))
    try:
        os.fchmod(fd, st.st_mode & 0o777)
        os.fchown(fd, st.st_uid, st.st_gid)
        with os.fdopen(fd, "w") as f:
            f.write(rendered)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, CONFIG)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    return "ad_tag written; check Telemt hot-reload logs before marking fully applied"


if __name__ == "__main__":
    if sys.argv[1:] != ["apply-ad-tag"]:
        sys.exit("Only apply-ad-tag is supported")
    try:
        print(apply_ad_tag(sys.stdin.readline().strip()))
    except (OSError, ValueError, RuntimeError) as exc:
        print("Failed:", str(exc), file=sys.stderr)
        sys.exit(1)
