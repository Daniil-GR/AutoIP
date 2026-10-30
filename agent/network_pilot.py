"""Root-local additive Floating IP pilot, never a remote shell/Agent job.

Adds one /32 via its own systemd unit. No default routes, primary addresses,
firewall, DNS or Telemt settings are modified. Commit only after external tests.
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import time
from pathlib import Path
from uuid import UUID

STATE_DIR = Path("/var/lib/autoip-floating-pilot")
UNIT_DIR = Path("/etc/systemd/system")


def command(*args):
    result = subprocess.run(list(args), capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError("Local pilot command failed: " + args[0])
    return result.stdout


def snapshot():
    return {
        "addresses": json.loads(command("/usr/sbin/ip", "-j", "-4", "address", "show")),
        "defaults": json.loads(
            command("/usr/sbin/ip", "-j", "-4", "route", "show", "default")
        ),
        "egress": json.loads(
            command("/usr/sbin/ip", "-j", "-4", "route", "get", "1.1.1.1")
        ),
        "telemt_hash": hashlib.sha256(
            Path("/etc/telemt/telemt.toml").read_bytes()
        ).hexdigest(),
    }


def device_for_management(before, management):
    devices = [
        link["ifname"]
        for link in before["addresses"]
        if any(a.get("local") == management for a in link.get("addr_info", []))
    ]
    if len(devices) != 1 or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", devices[0]):
        raise ValueError("Cannot identify management interface")
    return devices[0]


def validate_plan(address, management, resource_id, before):
    address, management = (
        str(ipaddress.IPv4Address(address)),
        str(ipaddress.IPv4Address(management)),
    )
    if (
        not ipaddress.IPv4Address(address).is_global
        or not ipaddress.IPv4Address(management).is_global
        or address == management
    ):
        raise ValueError("Floating IP must be public and different from management")
    resource_id = str(UUID(resource_id))
    if any(
        a.get("local") == address
        for link in before["addresses"]
        for a in link.get("addr_info", [])
    ):
        raise ValueError("Address already exists; inspect previous pilot")
    device = device_for_management(before, management)
    if not before["egress"] or before["egress"][0].get("prefsrc") != management:
        raise ValueError("Unexpected existing outbound source; manual plan required")
    return address, management, resource_id, device


def verify_invariants(before, after, management):
    if (
        before["defaults"] != after["defaults"]
        or before["telemt_hash"] != after["telemt_hash"]
    ):
        raise RuntimeError("Default route or Telemt configuration changed")
    if device_for_management(after, management) != device_for_management(
        before, management
    ):
        raise RuntimeError("Management interface changed")
    if not after["egress"] or after["egress"][0].get("prefsrc") != management:
        raise RuntimeError("Outbound management source changed")


def state_file(resource_id):
    if os.geteuid() != 0:
        raise RuntimeError("Run only as root after explicit approval")
    if STATE_DIR.is_symlink():
        raise RuntimeError("Unsafe state path")
    STATE_DIR.mkdir(mode=0o700, exist_ok=True)
    if STATE_DIR.stat().st_uid != 0 or STATE_DIR.stat().st_mode & 0o077:
        raise RuntimeError("Unsafe state permissions")
    path = STATE_DIR / (str(UUID(resource_id)) + ".json")
    if path.is_symlink():
        raise RuntimeError("Unsafe state file")
    return path


def save(path, data, exclusive=False):
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_NOFOLLOW
        | (os.O_EXCL if exclusive else os.O_TRUNC)
    )
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(data, stream)
        stream.flush()
        os.fsync(stream.fileno())


def prepare(address, management, resource_id):
    path = state_file(resource_id)
    if path.exists():
        raise RuntimeError(
            "Pilot already recorded; inspect or commit without re-applying"
        )
    before = snapshot()
    address, management, resource_id, device = validate_plan(
        address, management, resource_id, before
    )
    unit = "autoip-floating-" + resource_id + ".service"
    rollback = "autoip-floating-rollback-" + resource_id
    unit_path = UNIT_DIR / unit
    if unit_path.exists() or unit_path.is_symlink():
        raise RuntimeError("Unit already exists; no overwrite permitted")
    text = f"""[Unit]
Description=AutoIP approved Floating IP pilot {address}
After=network-online.target
Wants=network-online.target
Before=telemt.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/ip address add {address}/32 dev {device} label {device}:aip
ExecStop=/usr/sbin/ip address del {address}/32 dev {device}
TimeoutStartSec=15
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
CapabilityBoundingSet=CAP_NET_ADMIN
[Install]
WantedBy=multi-user.target
"""
    state = {
        "status": "PREPARING",
        "address": address,
        "management": management,
        "resource_id": resource_id,
        "device": device,
        "unit": unit,
        "rollback": rollback,
        "rollback_deadline": time.time() + 600,
        "before": before,
    }
    save(path, state, exclusive=True)
    descriptor = os.open(
        unit_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644
    )
    with os.fdopen(descriptor, "w") as stream:
        stream.write(text)
    command("/usr/bin/systemctl", "daemon-reload")
    command(
        "/usr/bin/systemd-run",
        "--unit=" + rollback,
        "--on-active=10m",
        "--",
        "/usr/bin/systemctl",
        "stop",
        unit,
    )
    try:
        command("/usr/bin/systemctl", "start", unit)
        after = snapshot()
        verify_invariants(before, after, management)
        if not any(
            a.get("local") == address
            for link in after["addresses"]
            for a in link.get("addr_info", [])
        ):
            raise RuntimeError("New address missing")
        command("/usr/bin/systemctl", "is-active", "telemt")
    except Exception:
        subprocess.run(
            ["/usr/bin/systemctl", "stop", unit], capture_output=True, timeout=30
        )
        state["status"] = "ROLLED_BACK"
        save(path, state)
        raise
    state["status"] = "STAGED"
    save(path, state)
    return {
        k: state[k]
        for k in ("status", "address", "device", "unit", "rollback_deadline")
    }


def commit(resource_id):
    path = state_file(resource_id)
    state = json.loads(path.read_text())
    if state["status"] not in ("STAGED", "COMMITTED"):
        raise RuntimeError("Pilot not staged")
    if state["status"] == "STAGED" and time.time() > state["rollback_deadline"] - 30:
        raise RuntimeError("Rollback deadline too close or expired; inspect first")
    verify_invariants(state["before"], snapshot(), state["management"])
    command("/usr/bin/systemctl", "is-active", state["unit"])
    command("/usr/bin/systemctl", "enable", state["unit"])
    command("/usr/bin/systemctl", "stop", state["rollback"] + ".timer")
    state["status"] = "COMMITTED"
    save(path, state)
    return {
        "status": "COMMITTED",
        "address": state["address"],
        "persistent": True,
        "default_route_changed": False,
        "telemt_changed": False,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Approved root-local single-address pilot"
    )
    parser.add_argument("action", choices=["prepare", "commit"])
    parser.add_argument("--resource-id", required=True)
    parser.add_argument("--address")
    parser.add_argument("--management")
    args = parser.parse_args()
    try:
        result = (
            prepare(args.address, args.management, args.resource_id)
            if args.action == "prepare"
            else commit(args.resource_id)
        )
        print(json.dumps(result))
    except (RuntimeError, ValueError, OSError, KeyError, subprocess.SubprocessError):
        raise SystemExit(
            "Floating IP network pilot stopped; inspect its journal and rollback unit"
        ) from None


if __name__ == "__main__":
    main()
