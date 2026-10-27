"""AutoIP Agent: outbound polling, no remote shell and no destructive commands."""
import hashlib
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
STATE_PATH = Path(os.environ.get("AUTOIP_STATE_PATH", "/var/lib/autoip-agent/identity.json"))
TELEMT_PATH = Path(os.environ.get("AUTOIP_TELEMT_CONFIG", "/etc/telemt/telemt.toml"))
ALLOW_AD_TAG_WRITE = os.environ.get("AUTOIP_ALLOW_AD_TAG_WRITE", "false").lower() == "true"


def check_transport():
    if not (COMMANDER.startswith("https://") or COMMANDER.startswith("http://127.0.0.1:") or COMMANDER.startswith("http://localhost:")):
        raise RuntimeError("Commander URL must use HTTPS outside localhost")


def run(args, timeout=5):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return result.stdout.strip()[:180] or result.stderr.strip()[:180]
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"


def facts():
    result = {"hostname": platform.node(), "os": platform.platform(),
              "telemt_version": run(["telemt", "--version"]),
              "telemt_service": run(["systemctl", "is-active", "telemt"]),
              "config_found": TELEMT_PATH.is_file()}
    try:
        cfg = tomllib.loads(TELEMT_PATH.read_text())
        result["ad_tag_present"] = bool(cfg.get("general", {}).get("ad_tag"))
        result["middle_proxy_nat_ip_set"] = bool(cfg.get("general", {}).get("middle_proxy_nat_ip"))
    except (OSError, ValueError):
        pass
    return result


def proxy_endpoint():
    # Explicit non-secret override for installations where Telemt config is root-readable only.
    override_host = os.environ.get("AUTOIP_PUBLIC_HOST", "").strip() or None
    override_port = os.environ.get("AUTOIP_PROXY_PORT")
    if override_host:
        return override_host, int(override_port) if override_port else 443
    try:
        cfg = tomllib.loads(TELEMT_PATH.read_text())
        return (cfg.get("general", {}).get("links", {}).get("public_host"),
                cfg.get("server", {}).get("port", 443))
    except (OSError, ValueError):
        return None, 443


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
        raise RuntimeError("Agent is already enrolled; revoke first before re-enrolling")
    machine_id_path = STATE_PATH.with_name("machine-id")
    if machine_id_path.exists():
        machine_id = machine_id_path.read_text().strip()
    else:
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        machine_id = str(uuid4())
        machine_id_path.write_text(machine_id)
        machine_id_path.chmod(0o600)
    with httpx.Client(timeout=20) as client:
        r = client.post(COMMANDER + "/api/agent/enroll", json={"token": token, "machine_id": machine_id, "facts": facts()})
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
            return {"status": "failed", "result": {"error": "Local ad_tag writes disabled; set AUTOIP_ALLOW_AD_TAG_WRITE after audit"}}
        try:
            r = subprocess.run(
                ["sudo", "-n", "/usr/local/libexec/autoip-telemt-helper", "apply-ad-tag"],
                input=tag + "\n", text=True, capture_output=True, timeout=20, check=False
            )
            if r.returncode:
                return {"status": "failed", "result": {"error": r.stderr.strip()[:240]}}
            return {"status": "succeeded", "result": {"message": r.stdout.strip()[:240]}}
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"status": "failed", "result": {"error": str(exc)[:240]}}
    return {"status": "failed", "result": {"error": "Unsupported job"}}


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
                hb = client.post(COMMANDER + "/api/agent/heartbeat",
                                 json={"facts": facts(), "public_host": host, "proxy_port": port})
                hb.raise_for_status()
                jobs = client.get(COMMANDER + "/api/agent/jobs")
                jobs.raise_for_status()
                for job in jobs.json().get("jobs", []):
                    result = execute(job)
                    response = client.post(COMMANDER + "/api/agent/jobs/" + job["id"] + "/result", json=result)
                    response.raise_for_status()
            except (httpx.HTTPError, KeyError, ValueError) as exc:
                print("Commander unavailable or invalid response:", str(exc)[:200], flush=True)
            time.sleep(20)


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("enroll", "run", "status"):
        sys.exit("Usage: python -m agent.main enroll|run|status")
    if sys.argv[1] == "enroll":
        enroll()
    elif sys.argv[1] == "status":
        print(json.dumps(facts(), ensure_ascii=False, indent=2))
    else:
        serve()
