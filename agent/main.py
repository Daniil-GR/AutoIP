"""AutoIP Agent: outbound polling, no remote shell and no destructive commands."""

import getpass
import pwd
import socket
import sqlite3
import json
import os
import platform
import re
import secrets
import subprocess
import sys
import time
import tomllib
from pathlib import Path
from uuid import uuid4

import httpx

COMMANDER = os.environ.get("AUTOIP_COMMANDER_URL", "").rstrip("/")
STATE_PATH = Path(
    os.environ.get("AUTOIP_STATE_PATH", "/var/lib/autoip-agent/identity.json")
)
TELEMT_PATH = Path(os.environ.get("AUTOIP_TELEMT_CONFIG", "/etc/telemt/telemt.toml"))
ALLOW_AD_TAG_WRITE = (
    os.environ.get("AUTOIP_ALLOW_AD_TAG_WRITE", "false").lower() == "true"
)


def check_transport():
    from urllib.parse import urlsplit

    try:
        parsed = urlsplit(COMMANDER)
        _ = parsed.port
    except ValueError:
        raise RuntimeError("Invalid Commander URL") from None
    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise RuntimeError("Invalid Commander URL")
    if parsed.scheme != "https" and not (
        parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1")
    ):
        raise RuntimeError("Commander URL must use HTTPS outside localhost")


def run(args, timeout=5):
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, check=False
        )
        return result.stdout.strip()[:180] or result.stderr.strip()[:180]
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"


def helper_request(operation, **payload):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(15)
        client.connect("/run/autoip-telemt-helper.sock")
        client.sendall(json.dumps({"operation": operation, **payload}).encode() + b"\n")
        data = b""
        while not data.endswith(b"\n") and len(data) < 65536:
            chunk = client.recv(4096)
            if not chunk:
                break
            data += chunk
        result = json.loads(data)
        if not result.get("ok"):
            raise RuntimeError("Privileged helper rejected request")
        return result["result"]


def read_config_facts():
    try:
        cfg = tomllib.loads(TELEMT_PATH.read_text())
        return config_facts(cfg)
    except (OSError, ValueError):
        try:
            return helper_request("inspect")
        except (OSError, ValueError, RuntimeError):
            return {"config_readable": False}


def config_facts(cfg):
    general = cfg.get("general", {})
    listeners = cfg.get("server", {}).get("listeners", [])
    return {
        "tls_domain": cfg.get("censorship", {}).get("tls_domain"),
        "config_readable": True,
        "public_host": general.get("links", {}).get("public_host"),
        "proxy_port": cfg.get("server", {}).get("port", 443),
        "ad_tag_present": bool(general.get("ad_tag")),
        "middle_proxy_nat_ip_set": bool(general.get("middle_proxy_nat_ip")),
        "middle_proxy_nat_ip": general.get("middle_proxy_nat_ip"),
        "listeners": [
            {k: x[k] for k in ("ip", "port") if k in x}
            for x in listeners
            if isinstance(x, dict)
        ]
        if isinstance(listeners, list)
        else [],
        "outbound_bind_configured": bool(
            cfg.get("network", {}).get("outbound_bind_addr")
        ),
    }


def network_facts():
    result = {}
    for name, args in [
        ("interfaces", ["ip", "-j", "address", "show"]),
        ("routes", ["ip", "-j", "route", "show"]),
    ]:
        try:
            output = subprocess.run(
                args, capture_output=True, text=True, timeout=5, check=True
            )
            values = json.loads(output.stdout)
            if name == "interfaces":
                result[name] = [
                    {
                        "name": v.get("ifname"),
                        "state": v.get("operstate"),
                        "addresses": [
                            {
                                "ip": a.get("local"),
                                "prefix": a.get("prefixlen"),
                                "scope": a.get("scope"),
                            }
                            for a in v.get("addr_info", [])
                        ],
                    }
                    for v in values[:16]
                ]
            else:
                result[name] = [
                    {k: v[k] for k in ("dst", "gateway", "dev", "prefsrc") if k in v}
                    for v in values[:32]
                ]
        except (OSError, ValueError, subprocess.SubprocessError):
            result[name] = []
    return result


def facts():
    result = {
        "hostname": platform.node(),
        "os": platform.platform(),
        "telemt_version": run(["telemt", "--version"]),
        "telemt_service": run(["systemctl", "is-active", "telemt"]),
        "config_found": TELEMT_PATH.is_file(),
    }
    discovered = read_config_facts()
    result.update(
        {k: v for k, v in discovered.items() if k not in ("public_host", "proxy_port")}
    )
    result.update(network_facts())
    return result


def proxy_endpoint():
    # Explicit non-secret override for installations where Telemt config is root-readable only.
    override_host = os.environ.get("AUTOIP_PUBLIC_HOST", "").strip() or None
    override_port = os.environ.get("AUTOIP_PROXY_PORT")
    if override_host:
        return override_host, int(override_port) if override_port else 443
    detected = read_config_facts()
    return detected.get("public_host"), detected.get("proxy_port", 443)


def save_identity(data):
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    temp = STATE_PATH.with_name(STATE_PATH.name + "." + secrets.token_hex(4))
    fd = os.open(temp, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, STATE_PATH)
    finally:
        if temp.exists():
            temp.unlink()


def identity():
    return json.loads(STATE_PATH.read_text())


def enroll():
    check_transport()
    token = os.environ.get("AUTOIP_ENROLL_TOKEN", "")
    if not token:
        raise RuntimeError("AUTOIP_ENROLL_TOKEN is missing")
    if STATE_PATH.exists():
        raise RuntimeError(
            "Agent is already enrolled; revoke first before re-enrolling"
        )
    machine_id_path = STATE_PATH.with_name("machine-id")
    if machine_id_path.exists():
        machine_id = machine_id_path.read_text().strip()
    else:
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        machine_id = str(uuid4())
        machine_id_path.write_text(machine_id)
        machine_id_path.chmod(0o600)
    with httpx.Client(timeout=20) as client:
        r = client.post(
            COMMANDER + "/api/agent/enroll",
            json={"token": token, "machine_id": machine_id, "facts": facts()},
        )
        r.raise_for_status()
        data = r.json()
    save_identity(data)
    print("Enrolled Agent ID:", data["agent_id"])


def execute(job):
    kind = job.get("kind")
    if kind == "status":
        return {"status": "succeeded", "result": {"facts": facts()}}
    if kind == "apply_ad_tag":
        tag = job.get("payload", {}).get("ad_tag", "")
        if not re.fullmatch(r"[0-9a-f]{32}", tag):
            return {"status": "failed", "result": {"error": "Invalid ad_tag"}}
        if not ALLOW_AD_TAG_WRITE:
            return {
                "status": "failed",
                "result": {
                    "error": "Local ad_tag writes disabled; set AUTOIP_ALLOW_AD_TAG_WRITE after audit"
                },
            }
        try:
            outcome = helper_request("apply-ad-tag", ad_tag=tag)
            return {"status": "succeeded", "result": outcome}
        except (OSError, ValueError, RuntimeError):
            return {
                "status": "failed",
                "result": {
                    "error": "Restricted Telemt helper unavailable or operation disabled"
                },
            }
    return {"status": "failed", "result": {"error": "Unsupported job"}}


def execute_durable(job):
    # Persist before acknowledgement; the only write operation is itself idempotent.
    ledger = STATE_PATH.with_name("jobs.sqlite3")
    fd = os.open(ledger, os.O_CREAT | os.O_WRONLY, 0o600)
    os.close(fd)
    with sqlite3.connect(ledger) as db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS results (id TEXT PRIMARY KEY, result TEXT)"
        )
        previous = db.execute(
            "SELECT result FROM results WHERE id=?", (job["id"],)
        ).fetchone()
        if previous:
            return json.loads(previous[0])
        result = execute(job)
        db.execute("INSERT INTO results VALUES (?, ?)", (job["id"], json.dumps(result)))
        db.commit()
        return result


def enroll_local(url):
    # Root reads a hidden token, then permanently drops privileges before enrollment.
    global COMMANDER
    if os.geteuid() != 0:
        raise RuntimeError("Run enroll-local using sudo")
    account = pwd.getpwnam("autoip-agent")
    token = getpass.getpass("Одноразовый код регистрации (ввод скрыт): ")
    COMMANDER = url.rstrip("/")
    os.environ["AUTOIP_ENROLL_TOKEN"] = token
    os.initgroups(account.pw_name, account.pw_gid)
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)
    os.chdir("/opt/AutoIP")
    enroll()


def serve():
    check_transport()
    if not STATE_PATH.exists():
        raise RuntimeError("Enroll this agent first")
    agent = identity()
    headers = {"Authorization": "Bearer " + agent["agent_token"]}
    with httpx.Client(timeout=25, headers=headers) as client:
        while True:
            try:
                host, port = proxy_endpoint()
                hb = client.post(
                    COMMANDER + "/api/agent/heartbeat",
                    json={"facts": facts(), "public_host": host, "proxy_port": port},
                )
                hb.raise_for_status()
                jobs = client.get(COMMANDER + "/api/agent/jobs")
                jobs.raise_for_status()
                for job in jobs.json().get("jobs", []):
                    result = execute_durable(job)
                    result = {**result, "attempt": job.get("attempt")}
                    response = client.post(
                        COMMANDER + "/api/agent/jobs/" + job["id"] + "/result",
                        json=result,
                    )
                    response.raise_for_status()
            except (httpx.HTTPError, KeyError, ValueError):
                print("Commander unavailable or invalid response; retrying", flush=True)
            time.sleep(20)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "enroll-local":
        enroll_local(sys.argv[2])
        sys.exit(0)
    if len(sys.argv) != 2 or sys.argv[1] not in ("enroll", "run", "status"):
        sys.exit("Usage: python -m agent.main enroll|run|status")
    if sys.argv[1] == "enroll":
        enroll()
    elif sys.argv[1] == "status":
        print(json.dumps(facts(), ensure_ascii=False, indent=2))
    else:
        serve()
