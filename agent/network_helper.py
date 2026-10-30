"""Locally opted-in, UID-bound additive network operations; no remote shell."""

import fcntl
import json
import os
import pwd
import socket
import struct
import sys
import time
from uuid import uuid4
from pathlib import Path
from uuid import UUID
from . import network_pilot as net

POLICY = Path("/etc/autoip-agent/floating-policy.json")
ACTIVE = Path("/var/lib/autoip-floating-pilot/active.json")


def policy():
    st = POLICY.lstat()
    if (
        not POLICY.is_file()
        or POLICY.is_symlink()
        or st.st_uid != 0
        or st.st_mode & 0o077
    ):
        raise RuntimeError("Invalid local network policy")
    p = json.loads(POLICY.read_text())
    if p.get("enabled") is not True:
        raise RuntimeError("Local network operations disabled")
    return p


def operate(request):
    p = policy()
    if set(request) - {"action", "resource_id", "address"}:
        raise ValueError("Unexpected fields")
    before = net.snapshot()
    net.device_for_management(before, p["management"])
    action = request.get("action")
    if action == "inspect":
        if request.get("address") != p["management"]:
            raise ValueError("Management mismatch")
        return {"ready": True, "management": p["management"]}
    resource = str(UUID(request["resource_id"]))
    path = net.state_file(resource)
    state = json.loads(path.read_text()) if path.exists() else None
    if state and state["management"] != p["management"]:
        raise RuntimeError("Management policy mismatch")
    if action == "prepare":
        address = request["address"]
        if state:
            if state["address"] != address or state["status"] not in (
                "STAGED",
                "COMMITTED",
            ):
                raise RuntimeError("Existing operation requires inspection")
            net.verify_invariants(state["before"], before, p["management"])
            net.command("/usr/bin/systemctl", "is-active", state["unit"])
            return {"status": state["status"]}
        return net.prepare(address, p["management"], resource)
    if action == "commit":
        result = net.commit(resource)
        net.save(ACTIVE, {"resource_id": resource, "address": result["address"]})
        return result
    if action == "remove":
        if not state or state["status"] == "REMOVED":
            return {"status": "REMOVED"}
        active = json.loads(ACTIVE.read_text())
        if state["address"] == p["management"] or active["address"] == state["address"]:
            raise RuntimeError("Cannot remove management or active address")
        if state["status"] not in ("STAGED", "COMMITTED", "ROLLED_BACK", "REMOVING"):
            raise RuntimeError("Unrecognized managed network state")
        addresses = {
            a.get("local")
            for link in before["addresses"]
            for a in link.get("addr_info", [])
        }
        if active["address"] not in addresses:
            raise RuntimeError("Active address missing; preserve old resource")
        # Compare the cleanup action against its own snapshot. The owner may
        # legitimately have edited Telemt since this IP was originally added.
        state["removal_before"] = before
        state["status"] = "REMOVING"
        net.save(path, state)
        unit = net.UNIT_DIR / state["unit"]
        if unit.is_symlink():
            raise RuntimeError("Unsafe unit")
        if unit.exists():
            net.command("/usr/bin/systemctl", "disable", "--now", state["unit"])
            unit.unlink()
            net.command("/usr/bin/systemctl", "daemon-reload")
        after = net.snapshot()
        if any(
            a.get("local") == state["address"]
            for link in after["addresses"]
            for a in link.get("addr_info", [])
        ):
            raise RuntimeError("Managed address still present; cleanup not confirmed")
        net.verify_invariants(state["removal_before"], after, p["management"])
        state["status"] = "REMOVED"
        net.save(path, state)
        return {"status": "REMOVED"}
    raise ValueError("Unsupported network action")


def serve():
    channel = socket.socket(fileno=os.dup(0))
    _, uid, _ = struct.unpack(
        "3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    )
    if uid != pwd.getpwnam("autoip-agent").pw_uid:
        raise RuntimeError("Unauthorized local peer")
    channel.settimeout(90)
    stream = channel.makefile("rwb")
    raw = stream.readline(4097)
    if len(raw) > 4096 or not raw.endswith(b"\n"):
        raise ValueError("Invalid request length")
    fd = os.open(
        "/var/lib/autoip-floating-pilot/network.lock",
        os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
        0o600,
    )
    with os.fdopen(fd, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            result = {"ok": True, "result": operate(json.loads(raw))}
        except Exception as error:
            failure = {
                "error_id": str(uuid4()),
                "component": "network_helper",
                "error_type": type(error).__name__,
                "time": time.time(),
            }
            print(json.dumps(failure), file=sys.stderr, flush=True)
            result = {"ok": False, **failure}
        stream.write(json.dumps(result).encode() + b"\n")
        stream.flush()


if __name__ == "__main__":
    serve()
