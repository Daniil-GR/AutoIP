import asyncio
import hashlib
import os
import re
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .database import Agent, Check, Enrollment, Job, SessionLocal, get_db, init_db, utcnow
from .monitor import checkhost_tcp

basic = HTTPBasic()
bearer = HTTPBearer()
UI_FILE = Path(__file__).parent / "static" / "index.html"


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def admin(credentials: HTTPBasicCredentials = Depends(basic)):
    valid = secrets.compare_digest(credentials.username, settings.admin_user)
    valid &= secrets.compare_digest(credentials.password, settings.admin_password)
    if not valid:
        raise HTTPException(status_code=401, detail="Invalid credentials", headers={"WWW-Authenticate": "Basic"})
    return credentials.username


def authenticated_agent(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
    db: Session = Depends(get_db),
) -> Agent:
    if credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Bearer required")
    item = db.scalar(select(Agent).where(Agent.token_hash == digest(credentials.credentials)))
    if not item:
        raise HTTPException(status_code=401, detail="Unknown agent token")
    return item


class TicketRequest(BaseModel):
    name: str = Field(min_length=2, max_length=100)


class AgentEnroll(BaseModel):
    token: str
    machine_id: str = Field(min_length=3, max_length=128)
    facts: dict = Field(default_factory=dict)


class Heartbeat(BaseModel):
    facts: dict = Field(default_factory=dict)
    public_host: str | None = Field(default=None, max_length=253)
    proxy_port: int = Field(default=443, ge=1, le=65535)


class JobCreate(BaseModel):
    kind: Literal["status", "apply_ad_tag"]
    ad_tag: str | None = None


class JobResult(BaseModel):
    status: Literal["succeeded", "failed"]
    result: dict = Field(default_factory=dict)


def serialize_agent(a: Agent):
    return {
        "id": a.id, "name": a.name, "public_host": a.public_host,
        "proxy_port": a.proxy_port, "facts": a.facts,
        "last_seen": a.last_seen, "created_at": a.created_at,
        "paused": a.paused, "online": bool(a.last_seen and (utcnow() - aware(a.last_seen)).total_seconds() < 90),
    }


def aware(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


async def send_notice(message: str):
    if not settings.telegram_bot_token or not settings.telegram_chat_id:
        return
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            await client.post(
                "https://api.telegram.org/bot" + settings.telegram_bot_token + "/sendMessage",
                json={"chat_id": settings.telegram_chat_id, "text": message},
            )
        except httpx.HTTPError:
            pass


async def monitoring_loop():
    while True:
        try:
            with SessionLocal() as db:
                targets = [(a.id, a.name, a.public_host, a.proxy_port) for a in db.scalars(select(Agent).where(Agent.paused == False)).all() if a.public_host]
            for agent_id, name, host, port in targets:
                result = await checkhost_tcp(host, port)
                with SessionLocal() as db:
                    db.add(Check(agent_id=agent_id, result=result["status"], details=result))
                    db.commit()
                if result["status"] == "unknown":
                    continue
        except Exception:
            # An isolated monitoring failure must never crash API or trigger purchases.
            pass
        await asyncio.sleep(max(settings.monitor_interval_seconds, 30))


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    task = asyncio.create_task(monitoring_loop()) if settings.monitor_enabled else None
    yield
    if task:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="AutoIP Commander", version="0.1.0", lifespan=lifespan)


@app.get("/")
def panel(_: str = Depends(admin)):
    return FileResponse(UI_FILE)


@app.get("/health")
def health():
    return {"status": "ok", "mode": "monitoring-only", "writes_enabled": False}


@app.get("/api/overview")
def overview(_: str = Depends(admin), db: Session = Depends(get_db)):
    agents = db.scalars(select(Agent)).all()
    online = sum(1 for a in agents if serialize_agent(a)["online"])
    return {"total": len(agents), "online": online, "offline": len(agents) - online,
            "mode": "monitoring-only", "real_ip_purchases": False}


@app.get("/api/agents")
def list_agents(_: str = Depends(admin), db: Session = Depends(get_db)):
    return [serialize_agent(a) for a in db.scalars(select(Agent).order_by(Agent.created_at.desc())).all()]


@app.post("/api/enrollments")
def issue_ticket(body: TicketRequest, _: str = Depends(admin), db: Session = Depends(get_db)):
    token = secrets.token_urlsafe(32)
    ticket = Enrollment(name=body.name, token_hash=digest(token), expires_at=utcnow() + timedelta(minutes=15))
    db.add(ticket)
    db.commit()
    return {"token": token, "expires_in_seconds": 900, "name": body.name}


@app.post("/api/agent/enroll")
def enroll(body: AgentEnroll, db: Session = Depends(get_db)):
    ticket = db.scalar(select(Enrollment).where(Enrollment.token_hash == digest(body.token)).with_for_update())
    if not ticket or ticket.used_at is not None or aware(ticket.expires_at) < utcnow():
        raise HTTPException(status_code=401, detail="Invalid or expired enrollment token")
    if db.scalar(select(Agent).where(Agent.machine_id == body.machine_id)):
        raise HTTPException(status_code=409, detail="Machine already enrolled")
    agent_token = secrets.token_urlsafe(48)
    agent = Agent(name=ticket.name, token_hash=digest(agent_token), machine_id=body.machine_id,
                  facts=body.facts, last_seen=utcnow())
    ticket.used_at = utcnow()
    db.add(agent)
    db.commit()
    return {"agent_id": agent.id, "agent_token": agent_token}


@app.post("/api/agent/heartbeat")
def heartbeat(body: Heartbeat, agent: Agent = Depends(authenticated_agent), db: Session = Depends(get_db)):
    agent.facts = body.facts
    agent.public_host = body.public_host
    agent.proxy_port = body.proxy_port
    agent.last_seen = utcnow()
    db.commit()
    return {"status": "ok"}


@app.get("/api/agent/jobs")
def get_agent_jobs(agent: Agent = Depends(authenticated_agent), db: Session = Depends(get_db)):
    # At-least-once leasing. Executions must be idempotent on the agent.
    old = utcnow() - timedelta(minutes=2)
    jobs = db.scalars(select(Job).where(Job.agent_id == agent.id, Job.status.in_(["queued", "leased"]))
                      .order_by(Job.created_at).with_for_update()).all()
    available = []
    for job in jobs:
        if job.status == "leased" and job.leased_at and aware(job.leased_at) > old:
            continue
        if job.attempts >= 4:
            job.status = "failed"
            job.result = {"error": "Retry limit exceeded"}
            continue
        job.status = "leased"
        job.leased_at = utcnow()
        job.attempts += 1
        available.append({"id": job.id, "kind": job.kind, "payload": job.payload})
        if len(available) >= 1:
            break
    db.commit()
    return {"jobs": available}


@app.post("/api/agent/jobs/{job_id}/result")
def job_result(job_id: str, body: JobResult, agent: Agent = Depends(authenticated_agent), db: Session = Depends(get_db)):
    job = db.scalar(select(Job).where(Job.id == job_id, Job.agent_id == agent.id))
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status in ("succeeded", "failed"):
        return {"status": job.status}
    job.status = body.status
    job.result = body.result
    db.commit()
    return {"status": job.status}


@app.get("/api/agents/{agent_id}/jobs")
def agent_jobs(agent_id: str, _: str = Depends(admin), db: Session = Depends(get_db)):
    return [{"id": j.id, "kind": j.kind, "status": j.status, "created_at": j.created_at, "result": j.result}
            for j in db.scalars(select(Job).where(Job.agent_id == agent_id).order_by(Job.created_at.desc()).limit(50)).all()]


@app.get("/api/agents/{agent_id}/checks")
def agent_checks(agent_id: str, _: str = Depends(admin), db: Session = Depends(get_db)):
    return [{"result": c.result, "details": c.details, "created_at": c.created_at}
            for c in db.scalars(select(Check).where(Check.agent_id == agent_id).order_by(Check.created_at.desc()).limit(20)).all()]


@app.post("/api/agents/{agent_id}/jobs")
def new_job(agent_id: str, body: JobCreate, _: str = Depends(admin), db: Session = Depends(get_db)):
    agent = db.get(Agent, agent_id)
    if not agent or agent.paused:
        raise HTTPException(status_code=404, detail="Agent not found or paused")
    payload = {}
    if body.kind == "apply_ad_tag":
        if not body.ad_tag or not re.fullmatch("[a-fA-F0-9]{32}", body.ad_tag):
            raise HTTPException(status_code=422, detail="ad_tag must be exactly 32 hex characters")
        payload["ad_tag"] = body.ad_tag.lower()
    job = Job(agent_id=agent_id, kind=body.kind, payload=payload)
    db.add(job)
    db.commit()
    return {"job_id": job.id, "status": job.status}


@app.post("/api/agents/{agent_id}/pause")
def pause_agent(agent_id: str, _: str = Depends(admin), db: Session = Depends(get_db)):
    agent = db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent.paused = not agent.paused
    db.commit()
    return {"paused": agent.paused}


@app.post("/api/agents/{agent_id}/check")
async def run_check(agent_id: str, _: str = Depends(admin), db: Session = Depends(get_db)):
    agent = db.get(Agent, agent_id)
    if not agent or not agent.public_host:
        raise HTTPException(status_code=404, detail="Agent missing public_host")
    result = await checkhost_tcp(agent.public_host, agent.proxy_port)
    db.add(Check(agent_id=agent_id, result=result["status"], details=result))
    db.commit()
    return result
