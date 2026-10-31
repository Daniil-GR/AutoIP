import json
import re
import secrets
import httpx
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, select
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from .config import settings
from .diagnostics import record_failure
from .database import (
    AdminSession,
    Agent,
    Audit,
    Check,
    ControlTask,
    Enrollment,
    FloatingIP,
    Incident,
    Integration,
    Job,
    Recovery,
    Notification,
    Sponsorship,
    SystemSetting,
    get_db,
    init_db,
    utcnow,
)
from .schemas import AgentConfiguration, CommanderPolicy, IntegrationInput, safe_facts
from .policy import get_policy
from .security import admin, audit, aware, digest, login
from .services import (
    cost_report,
    incident_action,
    readiness,
    recovery_plan,
    request_check,
    require_agent,
    serialize_agent,
    set_paused,
)
from .vault import VaultError, cipher, decrypt, encrypt
from .proxy_modes import ProxyMode, DEFAULT_MODE

bearer = HTTPBearer()
STATIC = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app):
    init_db()
    yield


app = FastAPI(title="AutoIP Commander", version="0.2.0", lifespan=lifespan)


@app.middleware("http")
async def unexpected_errors(request, call_next):
    try:
        return await call_next(request)
    except Exception as error:
        # No URL/query, headers, request body or raw exception in diagnostics.
        error_id = record_failure("api", "request", error)
        return JSONResponse(
            status_code=500,
            content={
                "detail": "Внутренняя ошибка. Идентификатор сохранён в журнале.",
                "error_id": error_id,
            },
        )


@app.exception_handler(RequestValidationError)
async def validation_error(request, exc):
    # Pydantic errors include the submitted input by default; never echo secrets.
    errors = [
        {"loc": e["loc"], "type": e["type"], "msg": "Некорректное значение"}
        for e in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": errors})


@app.exception_handler(VaultError)
async def vault_error(request, exc):
    return JSONResponse(status_code=503, content={"detail": str(exc)})


@app.middleware("http")
async def security_headers(request, call_next):
    length = request.headers.get("content-length", "0")
    if not length.isdigit() or int(length) > 65536:
        return JSONResponse(
            status_code=413, content={"detail": "Слишком большой запрос"}
        )
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        origin = request.headers.get("origin")
        expected = settings.public_url.rstrip("/") or str(request.base_url).rstrip("/")
        if origin and origin.rstrip("/") != expected:
            return JSONResponse(
                status_code=403, content={"detail": "Запрос с другого сайта запрещён"}
            )
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        chunks, size = [], 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > 65536:
                return JSONResponse(
                    status_code=413, content={"detail": "Слишком большой запрос"}
                )
            chunks.append(chunk)
        request._body = b"".join(chunks)
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )
    return response


@app.get("/")
def panel():
    return FileResponse(STATIC / "index.html")


@app.get("/static/{name}")
def static_file(name: Literal["app.js", "style.css"]):
    return FileResponse(STATIC / name)


class LoginInput(BaseModel):
    username: str = Field(max_length=100)
    password: str = Field(max_length=1024, repr=False)
    otp: str = Field(default="", max_length=6, repr=False)


@app.post("/api/session")
def create_session(body: LoginInput, request: Request, db: Session = Depends(get_db)):
    token, csrf = login(db, request, body.username, body.password, body.otp)
    response = JSONResponse({"csrf": csrf, "user": settings.admin_user})
    response.set_cookie(
        "autoip_session",
        token,
        httponly=True,
        samesite="strict",
        secure=request.url.hostname not in ("localhost", "127.0.0.1", "testserver"),
        max_age=settings.session_hours * 3600,
    )
    return response


@app.get("/api/session")
def get_session(request: Request, actor=Depends(admin), db: Session = Depends(get_db)):
    session = db.get(AdminSession, digest(request.cookies.get("autoip_session", "")))
    return {"user": actor, "csrf": session.csrf if session else ""}


@app.delete("/api/session")
def logout(request: Request, actor=Depends(admin), db: Session = Depends(get_db)):
    db.execute(
        delete(AdminSession).where(
            AdminSession.token_hash == digest(request.cookies.get("autoip_session", ""))
        )
    )
    audit(db, actor, "logout")
    db.commit()
    response = JSONResponse({"ok": True})
    response.delete_cookie("autoip_session")
    return response


@app.get("/health")
def health(db: Session = Depends(get_db)):
    from .paid_recovery import enabled_count

    paid = enabled_count(db)
    reserve = any(
        x.value.get("enabled")
        for x in db.scalars(
            select(SystemSetting).where(SystemSetting.key.like("auto-reserve:%"))
        )
    )
    return {
        "status": "ok",
        "mode": "approved_automation" if paid or reserve else "safe",
        "writes_enabled": bool(paid or reserve),
    }


@app.get("/api/overview")
def overview(actor=Depends(admin), db: Session = Depends(get_db)):
    agents = db.scalars(select(Agent).where(Agent.revoked.is_(False))).all()
    online = sum(serialize_agent(a)["online"] for a in agents)
    from .paid_recovery import enabled_count

    paid = enabled_count(db)
    return {
        "total": len(agents),
        "online": online,
        "offline": len(agents) - online,
        "incidents": len(
            db.scalars(select(Incident).where(Incident.closed_at.is_(None))).all()
        ),
        "mode": "approved_automation" if paid else "safe",
        "real_ip_purchases": bool(paid),
        "paid_agents": paid,
        "costs": cost_report(db),
    }


@app.get("/api/agents")
def list_agents(actor=Depends(admin), db: Session = Depends(get_db)):
    return [
        serialize_agent(a) | {"revoked": a.revoked}
        for a in db.scalars(select(Agent).order_by(Agent.created_at.desc()))
    ]


class TicketRequest(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    proxy_mode: ProxyMode = DEFAULT_MODE


class AgentEnroll(BaseModel):
    token: str = Field(max_length=200, repr=False)
    machine_id: str = Field(min_length=3, max_length=128)
    facts: dict = Field(default_factory=dict)

    @field_validator("facts")
    @classmethod
    def sanitize(cls, value):
        return safe_facts(value)


class Heartbeat(BaseModel):
    facts: dict = Field(default_factory=dict)
    public_host: str | None = Field(default=None, max_length=253)
    proxy_port: int = Field(default=443, ge=1, le=65535)

    @field_validator("public_host")
    @classmethod
    def valid_host(cls, value):
        from .monitor import valid_target

        if value and not valid_target(value, 443):
            raise ValueError("Недопустимый адрес прокси")
        return value

    @field_validator("facts")
    @classmethod
    def sanitize(cls, value):
        return safe_facts(value)


def authenticated_agent(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
    db: Session = Depends(get_db),
):
    agent = db.scalar(
        select(Agent).where(
            Agent.token_hash == digest(credentials.credentials),
            Agent.revoked.is_(False),
        )
    )
    if not agent:
        raise HTTPException(401, "Недействительный ключ агента")
    return agent


@app.post("/api/enrollments")
def issue_ticket(
    body: TicketRequest, actor=Depends(admin), db: Session = Depends(get_db)
):
    token = secrets.token_urlsafe(32)
    ticket = Enrollment(
        name=body.name,
        token_hash=digest(token),
        expires_at=utcnow() + timedelta(minutes=15),
    )
    db.add(ticket)
    db.flush()
    db.add(
        SystemSetting(
            key="enroll-mode:" + ticket.id, value={"proxy_mode": body.proxy_mode}
        )
    )
    audit(db, actor, "enrollment_created", body.name)
    db.commit()
    return {
        "id": ticket.id,
        "token": token,
        "expires_in_seconds": 900,
        "name": body.name,
        "proxy_mode": body.proxy_mode,
        "commander_url": settings.public_url,
        "repository": "https://github.com/Daniil-GR/AutoIP.git",
        "agent_git_ref": settings.agent_git_ref,
    }


@app.get("/api/enrollments/{ticket_id}")
def enrollment_status(
    ticket_id: str, actor=Depends(admin), db: Session = Depends(get_db)
):
    item = db.get(Enrollment, ticket_id)
    if not item:
        raise HTTPException(404, "Код не найден")
    agent = db.get(Agent, item.agent_id) if item.agent_id else None
    return {
        "used": item.used_at is not None,
        "expired": aware(item.expires_at) <= utcnow(),
        "agent_id": agent.id if agent else None,
    }


@app.post("/api/agent/enroll")
def enroll(body: AgentEnroll, db: Session = Depends(get_db)):
    ticket = db.scalar(
        select(Enrollment)
        .where(Enrollment.token_hash == digest(body.token))
        .with_for_update()
    )
    if not ticket or ticket.used_at or aware(ticket.expires_at) <= utcnow():
        raise HTTPException(401, "Код использован или истёк")
    if db.scalar(select(Agent).where(Agent.machine_id == body.machine_id)):
        raise HTTPException(409, "Сервер уже зарегистрирован")
    token = secrets.token_urlsafe(48)
    mode_row = db.get(SystemSetting, "enroll-mode:" + ticket.id)
    config = AgentConfiguration(
        dns_zone=get_policy(db).default_dns_zone,
        proxy_mode=mode_row.value["proxy_mode"] if mode_row else DEFAULT_MODE,
    ).model_dump()
    agent = Agent(
        name=ticket.name,
        token_hash=digest(token),
        machine_id=body.machine_id,
        facts=body.facts,
        last_seen=utcnow(),
        configuration=config,
    )
    ticket.used_at = utcnow()
    db.add(agent)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Сервер уже зарегистрирован") from None
    ticket.agent_id = agent.id
    if mode_row:
        db.delete(mode_row)
    audit(db, "agent", "enrolled", agent.id)
    db.commit()
    return {"agent_id": agent.id, "agent_token": token}


@app.post("/api/agent/heartbeat")
def heartbeat(
    body: Heartbeat, agent=Depends(authenticated_agent), db: Session = Depends(get_db)
):
    agent.facts, agent.public_host, agent.proxy_port = (
        body.facts,
        body.public_host,
        body.proxy_port,
    )
    agent.last_seen = utcnow()
    db.commit()
    return {"status": "ok"}


@app.post("/api/agents/{agent_id}/revoke")
def revoke_agent(agent_id: str, actor=Depends(admin), db: Session = Depends(get_db)):
    agent = set_paused(db, agent_id, True, actor)
    agent.revoked = True
    for job in db.scalars(
        select(Job).where(
            Job.agent_id == agent_id, Job.status.in_(["queued", "leased"])
        )
    ):
        job.status, job.result = "failed", {"error": "Доступ агента отозван"}
    audit(db, actor, "agent_revoked", agent_id)
    db.commit()
    return {"revoked": True}


class AgentRename(BaseModel):
    name: str = Field(min_length=2, max_length=100)


@app.patch("/api/agents/{agent_id}")
def rename_agent(
    agent_id: str,
    body: AgentRename,
    actor=Depends(admin),
    db: Session = Depends(get_db),
):
    require_agent(db, agent_id).name = body.name
    audit(db, actor, "agent_renamed", agent_id)
    db.commit()
    return {"saved": True}


class JobCreate(BaseModel):
    kind: Literal["status", "apply_ad_tag"]
    ad_tag: str | None = None


class JobResult(BaseModel):
    status: Literal["succeeded", "failed"]
    result: dict = Field(default_factory=dict)
    attempt: int | None = None


@app.get("/api/agent/jobs")
def get_agent_jobs(agent=Depends(authenticated_agent), db: Session = Depends(get_db)):
    if agent.paused:
        return {"jobs": []}
    old = utcnow() - timedelta(minutes=2)
    jobs = db.scalars(
        select(Job)
        .where(Job.agent_id == agent.id, Job.status.in_(["queued", "leased"]))
        .order_by(Job.created_at)
        .with_for_update(skip_locked=True)
    ).all()
    available = []
    for job in jobs:
        if job.status == "leased" and job.leased_at and aware(job.leased_at) > old:
            continue
        if job.attempts >= 4 or utcnow() - aware(job.created_at) > timedelta(
            minutes=15
        ):
            job.status, job.result = (
                "failed",
                {"error": "Истёк срок задания или лимит повторов"},
            )
            continue
        job.status, job.leased_at, job.attempts = "leased", utcnow(), job.attempts + 1
        available.append(
            {
                "id": job.id,
                "kind": job.kind,
                "payload": job.payload,
                "attempt": job.attempts,
            }
        )
        break
    db.commit()
    return {"jobs": available}


@app.post("/api/agent/jobs/{job_id}/result")
def job_result(
    job_id: str,
    body: JobResult,
    agent=Depends(authenticated_agent),
    db: Session = Depends(get_db),
):
    job = db.scalar(
        select(Job).where(Job.id == job_id, Job.agent_id == agent.id).with_for_update()
    )
    if not job:
        raise HTTPException(404, "Задание не найдено")
    if job.status in ("succeeded", "failed"):
        return {"status": job.status}
    if job.status != "leased" or (
        body.attempt is not None and body.attempt != job.attempts
    ):
        raise HTTPException(409, "Устаревший результат задания")
    # Do not persist arbitrary stderr/config strings from an agent.
    result = {
        k: v
        for k, v in body.result.items()
        if k in {"facts", "message", "error", "written", "reload_verified"}
    }
    if "facts" in result:
        result["facts"] = safe_facts(result["facts"])
    if len(json.dumps(result)) > 32768:
        raise HTTPException(422, "Слишком большой результат")
    job.status, job.result = body.status, result
    if job.kind == "apply_ad_tag":
        sponsorship = db.get(Sponsorship, agent.id)
        if not sponsorship:
            sponsorship = Sponsorship(agent_id=agent.id)
            db.add(sponsorship)
        sponsorship.status = (
            "TAG_WRITTEN_UNVERIFIED"
            if body.status == "succeeded" and result.get("written")
            else "TAG_APPLY_FAILED"
        )
        sponsorship.ad_tag = job.payload.get("ad_tag")
        sponsorship.details = {
            **(sponsorship.details or {}),
            "job_id": job.id,
            "reload_verified": False,
        }
        sponsorship.updated_at = utcnow()
        db.add(
            Notification(
                topic="sponsorship_status",
                target=agent.id,
                text=f"{agent.name}: статус ad_tag — {sponsorship.status}. Работа сети и спонсорство учитываются отдельно.",
            )
        )
    audit(db, "agent:" + agent.id, "job_" + body.status, job.id)
    db.commit()
    return {"status": job.status}


@app.get("/api/agents/{agent_id}/jobs")
def agent_jobs(agent_id: str, actor=Depends(admin), db: Session = Depends(get_db)):
    require_agent(db, agent_id)
    return [
        {
            "id": j.id,
            "kind": j.kind,
            "status": j.status,
            "created_at": j.created_at,
            "result": j.result,
        }
        for j in db.scalars(
            select(Job)
            .where(Job.agent_id == agent_id)
            .order_by(Job.created_at.desc())
            .limit(50)
        )
    ]


@app.post("/api/agents/{agent_id}/jobs")
def new_job(
    agent_id: str, body: JobCreate, actor=Depends(admin), db: Session = Depends(get_db)
):
    agent = require_agent(db, agent_id, lock=True)
    if agent.paused or agent.revoked:
        raise HTTPException(409, "Агент приостановлен или отозван")
    payload = {}
    if body.kind == "apply_ad_tag":
        if not body.ad_tag or not re.fullmatch("[a-fA-F0-9]{32}", body.ad_tag):
            raise HTTPException(422, "ad_tag должен содержать 32 hex-символа")
        payload["ad_tag"] = body.ad_tag.lower()
    job = Job(agent_id=agent_id, kind=body.kind, payload=payload)
    db.add(job)
    db.flush()
    audit(db, actor, "job_created", job.id, kind=body.kind)
    db.commit()
    return {"job_id": job.id, "status": job.status}


@app.get("/api/agents/{agent_id}/configuration")
def get_configuration(
    agent_id: str, actor=Depends(admin), db: Session = Depends(get_db)
):
    return AgentConfiguration(**(require_agent(db, agent_id).configuration or {}))


@app.put("/api/agents/{agent_id}/configuration")
def set_configuration(
    agent_id: str,
    body: AgentConfiguration,
    actor=Depends(admin),
    db: Session = Depends(get_db),
):
    agent = require_agent(db, agent_id, lock=True)
    if body.proxy_mode != (agent.configuration or {}).get(
        "proxy_mode", DEFAULT_MODE
    ) and (
        agent.facts.get("config_found") or agent.facts.get("telemt_service") == "active"
    ):
        raise HTTPException(
            409,
            "Режим действующей ноды нельзя изменить настройкой Commander. Выберите режим для новой ноды.",
        )
    for identifier, kind in [
        (body.cherry_integration_id, "cherry"),
        (body.dns_integration_id, "dynadot"),
        (body.telethon_integration_id, "telethon"),
        (body.mtproto_integration_id, "mtproto"),
        (body.checker_integration_id, "mtproto_checker"),
        (body.ripe_atlas_integration_id, "ripe_atlas"),
        (body.vps_profile_integration_id, "telemt_profile"),
    ]:
        integration = db.get(Integration, identifier) if identifier else None
        if identifier and (not integration or integration.kind != kind):
            raise HTTPException(422, "Неверная привязка интеграции")
        if identifier and kind == "telemt_profile":
            profile = decrypt(integration)
            if profile.get("proxy_mode", DEFAULT_MODE) != body.proxy_mode:
                raise HTTPException(
                    422, "Режим профиля Telemt не совпадает с режимом ноды"
                )
            if body.dns_record and profile["domain"] != body.dns_record:
                raise HTTPException(
                    422, "Поддомен профиля Telemt не совпадает с DNS-записью ноды"
                )
    if body.management_ip and body.management_ip == body.floating_ip:
        raise HTTPException(422, "Management IP должен отличаться от Floating IP")
    if (
        body.dns_zone
        and body.dns_record
        and body.dns_record != body.dns_zone
        and not body.dns_record.endswith("." + body.dns_zone)
    ):
        raise HTTPException(422, "Запись не принадлежит выбранной DNS-зоне")
    agent.configuration = body.model_dump()
    audit(db, actor, "configuration_saved", agent_id)
    db.commit()
    return {"saved": True, "configuration": agent.configuration}


@app.get("/api/agents/{agent_id}/readiness")
def agent_readiness(agent_id: str, actor=Depends(admin), db: Session = Depends(get_db)):
    return readiness(db, require_agent(db, agent_id))


class PauseRequest(BaseModel):
    paused: bool


@app.put("/api/agents/{agent_id}/pause")
def explicit_pause(
    agent_id: str,
    body: PauseRequest,
    actor=Depends(admin),
    db: Session = Depends(get_db),
):
    agent = set_paused(db, agent_id, body.paused, actor)
    db.commit()
    return {"paused": agent.paused}


@app.post("/api/agents/{agent_id}/pause")
def pause_agent(agent_id: str, actor=Depends(admin), db: Session = Depends(get_db)):
    agent = require_agent(db, agent_id, lock=True)
    agent = set_paused(db, agent_id, not agent.paused, actor)
    db.commit()
    return {"paused": agent.paused}


@app.post("/api/agents/{agent_id}/check", status_code=202)
def run_check(agent_id: str, actor=Depends(admin), db: Session = Depends(get_db)):
    if not require_agent(db, agent_id).public_host:
        raise HTTPException(409, "Агент ещё не сообщил public_host")
    task = request_check(db, agent_id, actor)
    db.commit()
    return {"task_id": task.id, "status": task.status}


@app.get("/api/tasks/{task_id}")
def task_status(task_id: str, actor=Depends(admin), db: Session = Depends(get_db)):
    task = db.get(ControlTask, task_id)
    if not task:
        raise HTTPException(404, "Проверка не найдена")
    return {"id": task.id, "status": task.status, "result": task.result}


@app.get("/api/agents/{agent_id}/checks")
def agent_checks(agent_id: str, actor=Depends(admin), db: Session = Depends(get_db)):
    require_agent(db, agent_id)
    return [
        {"result": c.result, "details": c.details, "created_at": c.created_at}
        for c in db.scalars(
            select(Check)
            .where(Check.agent_id == agent_id)
            .order_by(Check.created_at.desc())
            .limit(100)
        )
    ]


def rows(db, model, limit=100):
    items = db.scalars(select(model).order_by(model.created_at.desc()).limit(limit))
    return [
        {c.name: getattr(item, c.name) for c in model.__table__.columns}
        for item in items
    ]


@app.get("/api/incidents")
def incidents(actor=Depends(admin), db: Session = Depends(get_db)):
    return rows(db, Incident)


class IncidentInput(BaseModel):
    action: Literal["confirm", "working", "recheck", "hold"]


@app.post("/api/incidents/{incident_id}/action")
def act_on_incident(
    incident_id: str,
    body: IncidentInput,
    actor=Depends(admin),
    db: Session = Depends(get_db),
):
    item = incident_action(db, incident_id, body.action, actor)
    db.commit()
    return {"status": item.status}


class RecoveryInput(BaseModel):
    idempotency_key: str = Field(min_length=8, max_length=100)


@app.post("/api/agents/{agent_id}/recovery-plan")
def plan_recovery(
    agent_id: str,
    body: RecoveryInput,
    actor=Depends(admin),
    db: Session = Depends(get_db),
):
    item = recovery_plan(db, agent_id, actor, agent_id + ":" + body.idempotency_key)
    db.commit()
    return {"id": item.id, "status": item.status, "stages": item.stages}


@app.get("/api/recoveries")
def recoveries(actor=Depends(admin), db: Session = Depends(get_db)):
    return rows(db, Recovery)


@app.get("/api/floating-ips")
def floating_ips(actor=Depends(admin), db: Session = Depends(get_db)):
    return rows(db, FloatingIP)


@app.get("/api/costs")
def costs(actor=Depends(admin), db: Session = Depends(get_db)):
    return cost_report(db)


@app.get("/api/audit")
def audit_history(actor=Depends(admin), db: Session = Depends(get_db)):
    return rows(db, Audit)


@app.get("/api/sponsorship")
def sponsorship(actor=Depends(admin), db: Session = Depends(get_db)):
    return [
        {
            "agent_id": s.agent_id,
            "status": s.status,
            "details": s.details,
            "updated_at": s.updated_at,
        }
        for s in db.scalars(select(Sponsorship))
    ]


@app.get("/api/settings")
def global_settings(actor=Depends(admin), db: Session = Depends(get_db)):
    try:
        cipher()
        vault_ready = True
    except VaultError:
        vault_ready = False
    return {
        "public_url": settings.public_url,
        "vault_ready": vault_ready,
        "totp_enabled": bool(settings.totp_secret_file),
        **get_policy(db).model_dump(),
        "paid_actions_enabled": False,
    }


@app.get("/api/integrations")
def integrations(actor=Depends(admin), db: Session = Depends(get_db)):
    return [
        {
            "id": i.id,
            "name": i.name,
            "kind": i.kind,
            "status": i.status,
            "configured": True,
        }
        for i in db.scalars(select(Integration).order_by(Integration.created_at))
    ]


@app.post("/api/integrations")
def save_integration(
    body: IntegrationInput,
    request: Request,
    actor=Depends(admin),
    db: Session = Depends(get_db),
):
    if request.url.scheme != "https" and request.url.hostname not in (
        "localhost",
        "127.0.0.1",
        "testserver",
    ):
        raise HTTPException(403, "Ключи принимаются только по HTTPS или локально")
    try:
        body.validate_keys()
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    identifier = str(uuid4())
    item = Integration(
        id=identifier,
        name=body.name,
        kind=body.kind,
        ciphertext=encrypt(identifier, body.kind, body.credentials),
        metadata_json={},
    )
    if body.kind == "telethon" and not body.credentials.get("session"):
        item.status = "authorization_required"
    db.add(item)
    audit(db, actor, "integration_created", identifier, kind=body.kind)
    db.commit()
    return {"id": item.id, "configured": True}


@app.post("/api/integrations/{identifier}/test")
async def test_integration(
    identifier: str, actor=Depends(admin), db: Session = Depends(get_db)
):
    from .providers import test_connection

    item = db.get(Integration, identifier)
    if not item:
        raise HTTPException(404, "Интеграция не найдена")
    report = await test_connection(item.kind, decrypt(item))
    item.status = report.get("status") or ("verified" if report["ok"] else "failed")
    audit(db, actor, "integration_tested", identifier, ok=report["ok"])
    db.commit()
    return report


@app.get("/api/integrations/{identifier}/inventory")
async def integration_inventory(
    identifier: str, actor=Depends(admin), db: Session = Depends(get_db)
):
    from .providers import Cherry

    item = db.get(Integration, identifier)
    if not item or item.kind != "cherry":
        raise HTTPException(404, "Интеграция Cherry не найдена")
    return await Cherry(decrypt(item)["api_key"]).inventory()


@app.put("/api/settings")
def save_settings(
    body: CommanderPolicy, actor=Depends(admin), db: Session = Depends(get_db)
):
    item = db.get(SystemSetting, "commander")
    if item:
        item.value = body.model_dump()
    else:
        db.add(SystemSetting(key="commander", value=body.model_dump()))
    audit(db, actor, "policy_saved")
    db.commit()
    return {"saved": True}


@app.get("/api/integrations/{identifier}/projects/{project_id}")
async def project_inventory(
    identifier: str,
    project_id: str,
    actor=Depends(admin),
    db: Session = Depends(get_db),
):
    from .providers import Cherry

    item = db.get(Integration, identifier)
    if not item or item.kind != "cherry" or not project_id.isdigit():
        raise HTTPException(404, "Проект или интеграция не найдены")
    return await Cherry(decrypt(item)["api_key"]).project_inventory(project_id)


class SniCheckInput(BaseModel):
    integration_id: str
    approve_atlas_credits: Literal[True]


@app.post("/api/agents/{agent_id}/sni-check", status_code=202)
def check_sni(
    agent_id: str,
    body: SniCheckInput,
    actor=Depends(admin),
    db: Session = Depends(get_db),
):
    from .services import request_sni_check

    task = request_sni_check(db, agent_id, body.integration_id, actor)
    db.commit()
    return {"task_id": task.id, "status": task.status}


@app.get("/api/integrations/{identifier}/dns-domains")
async def dns_domains(
    identifier: str, page: int = 1, actor=Depends(admin), db: Session = Depends(get_db)
):
    from .dynadot import Dynadot, DynadotError

    item = db.get(Integration, identifier)
    if not item or item.kind != "dynadot":
        raise HTTPException(404, "Интеграция Dynadot не найдена")
    credentials = decrypt(item)
    try:
        return await Dynadot(credentials["api_key"], credentials["api_secret"]).domains(
            page
        )
    except (DynadotError, ValueError):
        raise HTTPException(502, "Не удалось получить список доменов Dynadot") from None


@app.get("/api/atlas/probe-plan")
async def atlas_probe_plan(actor=Depends(admin)):
    from .atlas_probes import discover_probes

    try:
        return await discover_probes()
    except (httpx.HTTPError, ValueError):
        raise HTTPException(
            502, "Не удалось получить актуальное покрытие RIPE Atlas"
        ) from None


class NodeHostDiscovery(BaseModel):
    integration_id: str
    addresses: list[str] = Field(min_length=1, max_length=10)

    @field_validator("addresses")
    @classmethod
    def public_addresses(cls, addresses):
        from .nodehost import public_ip
        from .nodehost import NodeHostError

        try:
            return [public_ip(value) for value in addresses]
        except NodeHostError:
            raise ValueError("Нужны публичные IPv4") from None


@app.get("/api/nodehost/resources")
def nodehost_resources(actor=Depends(admin), db: Session = Depends(get_db)):
    from .nodehost import resources

    return {"resources": resources(db), "automatic_purchases_enabled": False}


@app.post("/api/nodehost/discover")
async def nodehost_discover(body: NodeHostDiscovery, actor=Depends(admin)):
    from .nodehost import discover, NodeHostError

    try:
        result = await discover(body.integration_id, body.addresses)
    except NodeHostError as error:
        raise HTTPException(409, str(error)) from None
    # Credential IDs are internal; use only receipt IDs in the web interface.
    return {
        "found": [
            {k: r[k] for k in ("ipv4", "source_message_id")} for r in result["found"]
        ],
        "missing": result["missing"],
    }


@app.post("/api/nodehost/resources/{receipt_id}/inspect")
async def nodehost_inspect(
    receipt_id: int, actor=Depends(admin), db: Session = Depends(get_db)
):
    from .vps_bootstrap import inspect as inspect_vps

    item = db.get(SystemSetting, "vps-receipt:" + str(receipt_id))
    if not item:
        raise HTTPException(404, "VPS не найден")
    report = await inspect_vps(item.value["credential_id"], allow_first_pin=True)
    item.value = {
        **item.value,
        "inspection": report,
        "inspected_at": utcnow().isoformat(),
    }
    audit(db, actor, "nodehost_inspected", str(receipt_id))
    db.commit()
    return report


@app.post("/api/nodehost/resources/{receipt_id}/preflight")
async def nodehost_preflight(
    receipt_id: int, actor=Depends(admin), db: Session = Depends(get_db)
):
    from .vps_preflight import check, assess

    item = db.get(SystemSetting, "vps-receipt:" + str(receipt_id))
    if not item:
        raise HTTPException(404, "VPS не найден")
    before = dict(item.value)
    rounds = list(before.get("ssh_rounds", []))[-9:]
    result = assess(
        db,
        before["ipv4"],
        datetime.fromisoformat(before["created_at"]),
        rounds,
        utcnow(),
    )
    if result["status"] not in ("BOOT_WAIT", "REJECT_HISTORY"):
        report = await check(before["ipv4"])
        rounds.append({"checked_at": utcnow().isoformat(), "report": report})
        result = assess(
            db,
            before["ipv4"],
            datetime.fromisoformat(before["created_at"]),
            rounds,
            utcnow(),
        )
    # Do not lose a concurrent inspection or other metadata update.
    db.refresh(item, with_for_update=True)
    item.value = {**item.value, "ssh_rounds": rounds[-10:], "ssh_preflight": result}
    audit(db, actor, "nodehost_ssh_preflight", str(receipt_id), status=result["status"])
    db.commit()
    return result


class NodeHostQuote(BaseModel):
    integration_id: str


@app.post("/api/nodehost/quote")
async def nodehost_quote(body: NodeHostQuote, actor=Depends(admin)):
    from .nodehost_orders import prepare
    from .nodehost import NodeHostError

    try:
        return await prepare(body.integration_id)
    except NodeHostError as error:
        raise HTTPException(409, str(error)) from None


class NodeHostOrder(BaseModel):
    quote_id: str
    operation_id: str
    approved: bool = False


@app.post("/api/nodehost/order")
async def nodehost_order(body: NodeHostOrder, actor=Depends(admin)):
    from .nodehost_orders import purchase
    from .nodehost import NodeHostError

    try:
        return await purchase(body.quote_id, body.operation_id, approved=body.approved)
    except (NodeHostError, ValueError) as error:
        raise HTTPException(
            409,
            str(error) if isinstance(error, NodeHostError) else "Неверный ID операции",
        ) from None
