"""Compose primary checks and bounded, explicitly enabled Atlas fallback."""

import asyncio
import hashlib
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException

from .database import (
    Agent,
    ControlTask,
    Integration,
    SessionLocal,
    SystemSetting,
    utcnow,
)
from .monitor import CheckHost, collect
from .mtproto_checker import MTProtoChecker, unavailable
from .policy import get_policy
from .services import request_sni_check
from .vault import decrypt
from .proxy_modes import DEFAULT_MODE, FAKETLS_MODE, FAKETLS_SNI


def rate_slot(db, identifier, now=None):
    """Per-key persistent quota. Reserve 5 of the service's 30/min for manual use."""
    now = now or utcnow()
    timestamp = int(now.timestamp())
    key = "checker-rate:" + identifier
    row = db.scalar(
        select(SystemSetting).where(SystemSetting.key == key).with_for_update()
    )
    if row is None:
        try:
            with db.begin_nested():
                db.add(SystemSetting(key=key, value={}))
                db.flush()
        except IntegrityError:
            pass
        row = db.scalar(
            select(SystemSetting).where(SystemSetting.key == key).with_for_update()
        )
    state = dict(row.value)
    cooldown = state.get("cooldown_until", 0)
    if cooldown > timestamp:
        return False, cooldown - timestamp
    minute = timestamp // 60
    count = state.get("count", 0) if state.get("minute") == minute else 0
    if count >= 25:
        return False, 60 - timestamp % 60
    row.value = {**state, "minute": minute, "count": count + 1}
    return True, 0


def record_cooldown(db, identifier, seconds):
    key = "checker-rate:" + identifier
    row = db.scalar(
        select(SystemSetting).where(SystemSetting.key == key).with_for_update()
    )
    if row:
        row.value = {
            **row.value,
            "cooldown_until": int(utcnow().timestamp()) + min(3600, max(1, seconds)),
        }


async def checker_report(agent_id, target, port):
    identifier = None
    try:
        with SessionLocal() as db:
            agent = db.get(Agent, agent_id)
            config = agent.configuration or {}
            identifier = config.get("checker_integration_id")
            integration = db.get(Integration, identifier) if identifier else None
            secret_id = config.get("mtproto_integration_id")
            if not secret_id:
                secret_id = config.get("vps_profile_integration_id")
            secret = db.get(Integration, secret_id) if secret_id else None
            if (
                not integration
                or integration.kind != "mtproto_checker"
                or not secret
                or secret.kind not in ("mtproto", "telemt_profile")
            ):
                return unavailable("not_configured")
            api_key = decrypt(integration)["api_key"]
            secret_data = decrypt(secret)
            mode = config.get("proxy_mode", DEFAULT_MODE)
            if secret.kind == "telemt_profile" and (
                secret_data.get("proxy_mode", DEFAULT_MODE) != mode
                or secret_data.get("domain")
                != (config.get("dns_record") or agent.public_host)
            ):
                return unavailable("configuration_error")
            if mode == FAKETLS_MODE and port != 443:
                return unavailable("configuration_error")
            quota_id = hashlib.sha256(api_key.encode()).hexdigest()[:32]
            checker = MTProtoChecker(
                api_key,
                secret_data["secret"],
                FAKETLS_SNI
                if mode == FAKETLS_MODE
                else config.get("sni_domain") or agent.facts.get("tls_domain", ""),
                "ee"
                if mode == FAKETLS_MODE
                else config.get("mtproto_secret_format", "dd"),
            )
            allowed, seconds = rate_slot(db, quota_id)
            db.commit()
            if not allowed:
                return unavailable("local_rate_limit", seconds)
        report = await checker.check(target, port)
        if report.get("retry_after_seconds"):
            with SessionLocal() as db:
                record_cooldown(db, quota_id, report["retry_after_seconds"])
                db.commit()
        return report
    except (ValueError, KeyError):
        return unavailable("configuration_error")


def primary_unanswered(report):
    if report.get("error"):
        return report["error"] not in ("not_configured", "configuration_error")
    ru = [o for o in report.get("observations", []) if o.get("country") == "RU"]
    return report.get("provider_status") == "UNKNOWN" or bool(
        ru and all(o.get("state") == "unknown" for o in ru)
    )


def atlas_fallback(db, agent_id, reports):
    failed = sorted({r["source"] for r in reports if primary_unanswered(r)})
    if not failed:
        return {"status": "standby", "role": "fallback"}
    return schedule_atlas(db, agent_id, failed)


def schedule_atlas(db, agent_id, failed=None):
    failed = failed or []
    if not get_policy(db).atlas_fallback_enabled:
        return {"status": "disabled", "role": "fallback", "failed_sources": failed}
    # Serialize cooldown/dedup across Commander workers and UI checks.
    agent = db.scalar(select(Agent).where(Agent.id == agent_id).with_for_update())
    if agent.paused or agent.revoked:
        return {"status": "paused", "role": "fallback", "failed_sources": failed}
    identifier = (agent.configuration or {}).get("ripe_atlas_integration_id")
    if not identifier:
        return {
            "status": "not_configured",
            "role": "fallback",
            "failed_sources": failed,
        }
    latest = db.scalar(
        select(ControlTask)
        .where(
            ControlTask.agent_id == agent_id,
            ControlTask.kind == "sni",
            ControlTask.created_at >= utcnow() - timedelta(hours=1),
        )
        .order_by(ControlTask.created_at.desc())
        .limit(1)
    )
    if latest:
        return {
            "status": "cooldown",
            "role": "fallback",
            "task_id": latest.id,
            "failed_sources": failed,
        }
    try:
        task = request_sni_check(db, agent_id, identifier, "atlas-fallback")
    except HTTPException:
        # No provider request is made by queueing; never persist exception details.
        return {
            "status": "configuration_error",
            "role": "fallback",
            "failed_sources": failed,
        }
    return {
        "status": task.status,
        "role": "fallback",
        "task_id": task.id,
        "failed_sources": failed,
    }


async def collect_agent(agent_id, host, port, ip):
    with SessionLocal() as db:
        config = dict(db.get(Agent, agent_id).configuration or {})
    if config.get("monitoring_mode") == "cdn_web":
        host = config.get("web_proxy_host") or config.get("dns_record") or host
        report = await CheckHost().check(
            host, 443, protocol="https", foreign_countries=("DE", "NL", "FR")
        )
        report = {
            **report,
            "scope": "cdn-web-endpoint",
            "webproxy_data_verified": False,
        }
        with SessionLocal() as db:
            atlas = schedule_atlas(db, agent_id)
            db.commit()
        return {
            "monitoring_mode": "cdn_web",
            "target": host,
            "ip": None,
            "port": 443,
            "reports": [report],
            "observations": [
                {**o, "target": host, "scope": "cdn-web-endpoint"}
                for o in report.get("observations", [])
            ],
            "web_endpoint": {
                "target": host,
                "port": 443,
                "status": "reachable"
                if any(
                    o.get("country") == "RU" and o.get("state") == "reachable"
                    for o in report.get("observations", [])
                )
                else "unknown",
                "webproxy_data_verified": False,
            },
            "atlas_fallback": {
                **atlas,
                "role": "scheduled",
                "resolution_scope": "single_cdn_edge",
            },
            "mtproto_verified": False,
            "webproxy_data_verified": False,
        }

    async def web_check():
        if config.get("proxy_mode") == FAKETLS_MODE or not config.get("web_proxy_host"):
            return None
        return await CheckHost().check(
            config["web_proxy_host"],
            config.get("web_proxy_port", 443),
            protocol="https",
        )

    protocol = await checker_report(agent_id, ip or host, port)

    async def transport_check():
        if protocol.get("mtproto_verified"):
            return {
                "reports": [],
                "observations": [],
                "target": host,
                "ip": ip,
                "port": port,
            }
        return await collect(host, port, ip)

    tcp, web = await asyncio.gather(transport_check(), web_check())
    tcp["reports"] = [{**r, "scope": "mtproto-tcp"} for r in tcp["reports"]]
    tcp["observations"] = [{**o, "scope": "mtproto-tcp"} for o in tcp["observations"]]
    primary = [*tcp["reports"], protocol]
    tcp["reports"].append(protocol)
    tcp["observations"].extend(
        [{**o, "scope": "mtproto"} for o in protocol.get("observations", [])]
    )
    tcp["mtproto_status"] = protocol.get("provider_status", "UNKNOWN")
    tcp["mtproto_verified"] = protocol.get("mtproto_verified", False)
    if web is not None:
        web = {**web, "scope": "web-endpoint", "webproxy_data_verified": False}
        tcp["reports"].append(web)
        tcp["observations"].extend(
            [
                {
                    **o,
                    "target": web.get("target", config["web_proxy_host"]),
                    "scope": "web-endpoint",
                }
                for o in web.get("observations", [])
            ]
        )
        tcp["web_endpoint"] = {
            "target": config["web_proxy_host"],
            "port": config.get("web_proxy_port", 443),
            "status": "reachable"
            if any(
                o["state"] == "reachable" and o["country"] == "RU"
                for o in web.get("observations", [])
            )
            else "unknown",
            "webproxy_data_verified": False,
        }
    with SessionLocal() as db:
        tcp["atlas_fallback"] = atlas_fallback(db, agent_id, primary)
        db.commit()
    return tcp
