"""Durable, additive CDN aliases. No resource creation, zone replacement or deletion."""

import hashlib
import json
import re
import shlex
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

import asyncssh
import httpx
from sqlalchemy import select

from .database import (
    Agent,
    ControlTask,
    Integration,
    Notification,
    SessionLocal,
    SystemSetting,
    utcnow,
)
from .dns_pilot import DNSPilot, DNSPilotError, assert_records, canonical, snapshot
from .dns_scope import MANAGED_DNS_ZONE, managed_record
from .dynadot import signature
from .security import audit, aware
from .vault import decrypt

KIND = "cdn_alias"
HELPER_SHA256 = "81c9d5d50d0fefea6e6f113d4624a3b955114644bbdd147b40f80307c65fe752"
LABELS = {
    "PREFLIGHT": "Проверка настроек и свободного имени",
    "DNS": "Добавление CNAME",
    "DNS_WAIT": "Ожидание распространения DNS",
    "GCORE": "Добавление имени в CDN",
    "TLS": "Ожидание DNS и сертификата CDN",
    "NODE": "Настройка Nginx и Telemt",
    "VERIFY": "Проверка авторизации через CDN",
    "DONE": "Готово к проверке в Telegram",
}


class AliasError(RuntimeError):
    def __init__(self, message, provider_status=None):
        self.provider_status = provider_status
        super().__init__(message)


def hostname(value):
    value = value.strip().lower().rstrip(".")
    if "." not in value:
        value += "." + MANAGED_DNS_ZONE
    value = managed_record(value)
    # One label only: avoid affecting delegated subzones, ACME and panel names.
    label = value.removesuffix("." + MANAGED_DNS_ZONE)
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) or label in {
        "admin",
        "www",
        "mail",
        "ftp",
        "api",
        "ns1",
        "ns2",
    }:
        raise ValueError(
            "Нужен свободный поддомен вида lt1.vetka.rest; служебные имена запрещены"
        )
    return value


def binding(db, agent_id):
    agent = db.get(Agent, agent_id)
    item = db.get(SystemSetting, "cdn-bind:" + agent_id)
    if (
        not agent
        or agent.revoked
        or (agent.configuration or {}).get("monitoring_mode") != "cdn_web"
        or not item
    ):
        raise AliasError("Для агента не настроено управление CDN-поддоменами")
    return dict(item.value)


def create(db, agent_id, name, user_id):
    name = hostname(name)
    binding(db, agent_id)
    # Serialize all aliases on a resource via its owning agent, including confirmations.
    db.get(Agent, agent_id, with_for_update=True)
    existing = db.scalar(
        select(ControlTask).where(ControlTask.dedup_key == KIND + ":" + name)
    )
    if existing:
        if existing.payload["user_id"] != str(user_id):
            raise AliasError("Имя уже находится в другой операции")
        return existing
    if db.scalar(
        select(ControlTask).where(
            ControlTask.agent_id == agent_id,
            ControlTask.kind == KIND,
            ControlTask.status.in_(["queued", "running", "manual"]),
        )
    ):
        raise AliasError("Сначала завершите предыдущую операцию добавления имени")
    task = ControlTask(
        id=str(uuid4()),
        agent_id=agent_id,
        kind=KIND,
        dedup_key=KIND + ":" + name,
        status="draft",
        payload={
            "hostname": name,
            "user_id": str(user_id),
            "stage": "PREFLIGHT",
            "expires": (utcnow() + timedelta(minutes=15)).isoformat(),
        },
    )
    db.add(task)
    audit(db, "telegram:" + str(user_id), "cdn_alias_prepared", agent_id, hostname=name)
    return task


def confirm(db, task_id, user_id):
    task = db.get(ControlTask, task_id, with_for_update=True)
    if not task or task.kind != KIND or task.payload["user_id"] != str(user_id):
        raise AliasError("Операция недоступна")
    binding(db, task.agent_id)
    db.get(Agent, task.agent_id, with_for_update=True)
    if db.scalar(
        select(ControlTask).where(
            ControlTask.agent_id == task.agent_id,
            ControlTask.kind == KIND,
            ControlTask.id != task.id,
            ControlTask.status.in_(["queued", "running", "manual"]),
        )
    ):
        raise AliasError("Другой поддомен уже обрабатывается; дождитесь результата")
    if (
        task.status != "draft"
        or aware(datetime.fromisoformat(task.payload["expires"])) <= utcnow()
    ):
        raise AliasError("Подтверждение устарело или уже использовано")
    task.status = "queued"
    task.payload = {
        **task.payload,
        "approved_at": utcnow().isoformat(),
        "deadline": (utcnow() + timedelta(hours=1)).isoformat(),
    }
    audit(
        db,
        "telegram:" + str(user_id),
        "cdn_alias_approved",
        task.agent_id,
        hostname=task.payload["hostname"],
    )
    return task


def status_text(task):
    if not task or task.kind != KIND:
        raise AliasError("Операция не найдена")
    states = {
        "draft": "Ожидает подтверждения",
        "queued": "В работе",
        "running": "В работе",
        "manual": "Нужно вмешательство",
        "succeeded": "Готово к проверке",
        "cancelled": "Остановлено",
    }
    return (
        f"🌐 {task.payload['hostname']}\nСтатус: {states.get(task.status, task.status)}\n"
        f"Этап: {LABELS[task.payload['stage']]}\n" + task.result.get("message", "")
    )


class Gcore:
    def __init__(self, key):
        self.key = key

    async def call(self, method, path, **kwargs):
        try:
            async with httpx.AsyncClient(timeout=20, follow_redirects=False) as client:
                response = await client.request(
                    method,
                    "https://api.gcore.com" + path,
                    headers={"Authorization": "APIKey " + self.key},
                    **kwargs,
                )
                response.raise_for_status()
                return response.json()
        except (httpx.HTTPError, ValueError):
            raise AliasError(
                "Gcore не подтвердил запрос; состояние нужно сверить"
            ) from None


def resource_ok(resource, cfg):
    opts = resource.get("options") or {}
    if (
        not resource.get("active")
        or not resource.get("sslEnabled")
        or not resource.get("sslData")
    ):
        raise AliasError("Нужен активный CDN-ресурс с действующим сертификатом")
    if opts.get("forward_host_header") != {"enabled": True, "value": True} or opts.get(
        "hostHeader"
    ):
        raise AliasError("CDN должен передавать исходный Host без подмены")
    sni = opts.get("sni") or {}
    if (
        not sni.get("enabled")
        or sni.get("sni_type") != "custom"
        or sni.get("custom_hostname") != cfg["source_host"]
    ):
        raise AliasError("SNI origin не соответствует сохранённому имени")
    if resource.get("cname") != cfg["source_host"]:
        raise AliasError("Основное имя CDN изменилось; нужна сверка привязки")


class CnameDNS(DNSPilot):
    async def append(self, name, destination, before):
        name = hostname(name)
        if not re.fullmatch(r"cl-[a-z0-9-]+\.gcdn\.co", destination):
            raise AliasError("Недопустимый CNAME назначения")
        record = {
            "sub_host": name.removesuffix("." + MANAGED_DNS_ZONE),
            "record_type": "cname",
            "record_value1": destination,
        }
        current = snapshot(await self.records(MANAGED_DNS_ZONE))
        matches = [
            r
            for r in current.get("dns_sub_list", [])
            if r.get("sub_host") == record["sub_host"]
        ]
        if matches:
            if canonical(matches) != canonical([record]):
                raise AliasError("Поддомен занят; существующие записи не изменены")
            assert_records(
                current,
                {**before, "dns_sub_list": [*before.get("dns_sub_list", []), record]},
            )
            return
        assert_records(current, before)
        path = "/restful/v2/domains/" + MANAGED_DNS_ZONE + "/records"
        body = json.dumps(
            {
                "dns_sub_list": [record],
                "ttl": before["ttl"],
                "add_dns_to_current_setting": True,
            },
            separators=(",", ":"),
        )
        rid = str(uuid4())
        try:
            async with httpx.AsyncClient(timeout=20, follow_redirects=False) as client:
                r = await client.post(
                    "https://api.dynadot.com" + path,
                    content=body.encode(),
                    headers={
                        "Authorization": "Bearer " + self.api_key,
                        "X-Request-ID": rid,
                        "X-Signature": signature(
                            self.api_key, self.api_secret, path, rid, body
                        ),
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                )
                r.raise_for_status()
                code = r.json().get("code")
                if str(code) != "200":
                    status = (
                        int(code)
                        if str(code).isdigit() and 100 <= int(code) <= 599
                        else None
                    )
                    raise AliasError(
                        "Dynadot не подтвердил добавление CNAME"
                        + (f"; код {status}" if status else ""),
                        status,
                    )
        except (httpx.HTTPError, ValueError):
            raise AliasError(
                "Результат добавления CNAME неопределён; повтор запрещён до сверки"
            ) from None
        assert_records(
            snapshot(await self.records(MANAGED_DNS_ZONE)),
            {**before, "dns_sub_list": [*before.get("dns_sub_list", []), record]},
        )


async def node(cfg, name, apply=False, verify=False):
    with SessionLocal() as db:
        item = db.get(Integration, cfg["ssh_id"])
        if not item or item.kind != "cdn_access":
            raise AliasError("Нет закреплённого SSH-доступа CDN")
        data = decrypt(item)
    key = asyncssh.import_private_key(data["private_key"])
    known = asyncssh.import_known_hosts(f"{data['ipv4']} {data['host_key']}\n")
    async with await asyncssh.connect(
        data["ipv4"],
        username="root",
        client_keys=[key],
        known_hosts=known,
        config=None,
        agent_path=None,
        connect_timeout=15,
    ) as conn:
        if verify:
            program = VERIFY_PROGRAM.replace("__HOST__", repr(hostname(name)))
            result = await conn.run("python3 -", input=program, timeout=30, check=False)
            if result.exit_status or result.stdout.strip() != "VERIFIED":
                raise AliasError(
                    "CDN пока не передаёт авторизацию нового имени; существующий прокси сохранён"
                )
            return
        helper = Path(__file__).with_name("remote_cdn_domain.py").read_bytes()
        if hashlib.sha256(helper).hexdigest() != HELPER_SHA256:
            raise AliasError("Контрольная сумма помощника не совпала")
        command = (
            "python3 - "
            + shlex.quote(cfg["source_host"])
            + " "
            + shlex.quote(hostname(name))
            + (" --apply" if apply else "")
        )
        result = await conn.run(
            command, input=helper.decode(), timeout=120, check=False
        )
        if result.exit_status:
            raise AliasError(
                "Помощник VPS завершился ошибкой; проверьте журнал отката на ноде"
            )
        backup = re.search(
            r"/var/backups/telemtproxy/cdn-[A-Za-z0-9_-]+", result.stdout
        )
        return {"backup_path": backup[0] if backup else None}


VERIFY_PROGRAM = """import base64,hashlib,hmac,tomllib,urllib.request
from pathlib import Path
h=__HOST__
c=tomllib.loads(Path('/etc/telemt/telemt.toml').read_text())
v=next(v for v in c['web']['vhosts'] if v['host']==h)
p=v['profiles'][0]
k=bytes.fromhex(c['access']['users'][p['user']])
if p.get('secret_mode')=='dd':k=bytes([221])+k
t=base64.urlsafe_b64encode(hmac.new(k,b'tdesktop-web-proxy-bridge-v1'+bytes([10])+h.encode(),hashlib.sha256).digest()).decode().rstrip('=')
with urllib.request.urlopen('https://'+h+'/?bridge='+t,timeout=15) as r:
 body=r.read(200000)
 if r.status==200 and b'bootstrap' in body and r.headers.get('Content-Security-Policy'):print('VERIFIED')
"""


async def tls_ready(name, destination):
    import dns.asyncresolver

    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    try:
        answer = await resolver.resolve(name, "CNAME", lifetime=8)
        if {str(r.target).rstrip(".").lower() for r in answer} != {destination}:
            return False
        async with httpx.AsyncClient(timeout=12, follow_redirects=False) as client:
            r = await client.get("https://" + name + "/")
            # The request's validated TLS handshake is what matters here.
            return r.status_code < 500
    except Exception:
        return False


async def dns_ready(name, destination):
    """Avoid triggering certificate issuance while recursive DNS is still negative."""
    import ipaddress
    import dns.asyncresolver

    try:
        for server in ("1.1.1.1", "8.8.8.8"):
            resolver = dns.asyncresolver.Resolver(configure=False)
            resolver.nameservers = [server]
            cname = await resolver.resolve(name, "CNAME", lifetime=8)
            if {str(r.target).rstrip(".").lower() for r in cname} != {destination}:
                return False
            addresses = await resolver.resolve(name, "A", lifetime=8)
            if not addresses or not all(
                ipaddress.ip_address(str(r)).is_global for r in addresses
            ):
                return False
        return True
    except Exception:
        return False


def credentials(db, identifier, kind):
    item = db.get(Integration, identifier)
    if not item or item.kind != kind:
        raise AliasError("Интеграция отсутствует или её тип изменился")
    return decrypt(item)


async def advance(db, task):
    cfg = binding(db, task.agent_id)
    p = dict(task.payload)
    name, stage = hostname(p["hostname"]), p["stage"]
    if p.get("binding") and p["binding"] != cfg:
        raise AliasError("Привязка ноды изменилась во время операции")
    gcore = Gcore(credentials(db, cfg["gcore_id"], "gcore")["api_key"])
    dns = CnameDNS(**credentials(db, cfg["dns_id"], "dynadot"))
    path = "/cdn/resources/" + str(int(cfg["resource_id"]))
    if stage == "PREFLIGHT":
        resource = await gcore.call("GET", path)
        resource_ok(resource, cfg)
        origins = await gcore.call(
            "GET", "/cdn/origin_groups/" + str(resource["originGroup"])
        )
        if any(s.get("host_header_override") for s in origins.get("sources", [])):
            raise AliasError(
                "В группе источников задан Host override; сначала устраните подмену"
            )
        aliases = resource.get("secondaryHostnames") or []
        if name in aliases or name == resource.get("cname"):
            raise AliasError(
                "Имя уже есть в CDN; автоматическое принятие чужой настройки запрещено"
            )
        limits = await gcore.call("GET", "/cdn/clients/me")
        if len(aliases) >= int(limits["max_aliases_count"]):
            raise AliasError("Достигнут лимит имён CDN-ресурса")
        zone = snapshot(await dns.records(MANAGED_DNS_ZONE))
        if any(
            r.get("sub_host") == name.split(".")[0]
            for r in zone.get("dns_sub_list", [])
        ):
            raise AliasError("Поддомен занят в DNS; выберите новое имя")
        await node(cfg, name)
        p.update(aliases=aliases, dns_before=zone, binding=cfg, stage="DNS")
    elif stage == "DNS":
        if p.get("dns_pending"):
            # A timed-out write is never repeated automatically.
            zone = snapshot(await dns.records(MANAGED_DNS_ZONE))
            desired = {
                "sub_host": name.split(".")[0],
                "record_type": "cname",
                "record_value1": cfg["cname"],
            }
            assert_records(
                zone,
                {
                    **p["dns_before"],
                    "dns_sub_list": [*p["dns_before"].get("dns_sub_list", []), desired],
                },
            )
        else:
            task.payload = {**p, "dns_pending": True}
            db.commit()
            await dns.append(name, cfg["cname"], p["dns_before"])
        p.update(stage="DNS_WAIT", dns_pending=True)
    elif stage == "DNS_WAIT":
        if not await dns_ready(name, cfg["cname"]):
            task.payload = {
                **p,
                "next_at": (utcnow() + timedelta(seconds=45)).isoformat(),
            }
            return
        p["stage"] = "GCORE"
    elif stage == "GCORE":
        resource = await gcore.call("GET", path)
        resource_ok(resource, cfg)
        aliases = resource.get("secondaryHostnames") or []
        expected = [*p["aliases"], name]
        if sorted(aliases) != sorted(expected):
            if sorted(aliases) != sorted(p["aliases"]) or p.get("gcore_pending"):
                raise AliasError(
                    "CDN изменился или результат записи неопределён; нужна сверка"
                )
            task.payload = {**p, "gcore_pending": True}
            db.commit()
            await gcore.call("PATCH", path, json={"secondaryHostnames": expected})
            readback = await gcore.call("GET", path)
            if sorted(readback.get("secondaryHostnames") or []) != sorted(expected):
                raise AliasError("Добавление имени в CDN не подтверждено")
        p.update(stage="TLS", gcore_pending=True)
    elif stage == "TLS":
        if not await tls_ready(name, cfg["cname"]):
            task.payload = {
                **p,
                "next_at": (utcnow() + timedelta(seconds=45)).isoformat(),
            }
            return
        p["stage"] = "NODE"
    elif stage == "NODE":
        receipt = await node(cfg, name, apply=True)
        if isinstance(receipt, dict):
            task.result = {**task.result, **receipt}
        p["stage"] = "VERIFY"
    elif stage == "VERIFY":
        try:
            await node(cfg, name, verify=True)
        except AliasError:
            task.payload = {
                **p,
                "next_at": (utcnow() + timedelta(seconds=45)).isoformat(),
            }
            return
        p["stage"] = "DONE"
        task.status = "succeeded"
        task.result = {
            **task.result,
            "message": "DNS, TLS и авторизация WEB через CDN проверены. Проверьте передачу данных в Telegram; используйте прежний секрет. Доступность из всех сетей РФ не подтверждена.",
        }
    task.payload = {**p, "next_at": None}
    db.add(Notification(topic="cdn_alias", target=task.id, text=status_text(task)))
    audit(
        db, "system", "cdn_alias_stage", task.agent_id, hostname=name, stage=p["stage"]
    )


async def tick():
    # Hold a row lock throughout the bounded stage; SKIP LOCKED prevents a second worker.
    with SessionLocal() as db:
        tasks = db.scalars(
            select(ControlTask)
            .where(
                ControlTask.kind == KIND,
                (ControlTask.status == "queued")
                | (
                    (ControlTask.status == "running")
                    & (ControlTask.leased_at < utcnow() - timedelta(minutes=5))
                ),
            )
            .order_by(ControlTask.created_at)
            .with_for_update(skip_locked=True)
        ).all()
        for task in tasks:
            p = task.payload
            if (
                p.get("next_at")
                and aware(datetime.fromisoformat(p["next_at"])) > utcnow()
            ):
                continue
            if aware(datetime.fromisoformat(p["deadline"])) <= utcnow():
                task.status, task.result = (
                    "manual",
                    {
                        "message": "Истекло время ожидания. Добавленные DNS/CDN-настройки сохранены для сверки; повторные изменения не выполнялись."
                    },
                )
                db.add(
                    Notification(
                        topic="cdn_alias", target=task.id, text=status_text(task)
                    )
                )
                db.commit()
                return True
            task.status = "running"
            task.leased_at = utcnow()
            db.commit()
            try:
                await advance(db, task)
                if task.status == "running":
                    task.status = "queued"
            except Exception as error:
                from .diagnostics import record_failure

                error_id = record_failure(
                    "cdn_alias",
                    p["stage"],
                    error,
                    agent_id=task.agent_id,
                    task_id=task.id,
                )
                task.status = "manual"
                message = (
                    str(error)
                    if isinstance(error, (AliasError, DNSPilotError))
                    else "Ошибка операции; проверьте журнал Commander"
                )
                task.result = {"message": message + "; error_id=" + error_id}
                db.add(
                    Notification(
                        topic="cdn_alias", target=task.id, text=status_text(task)
                    )
                )
            db.commit()
            return True
    return False
