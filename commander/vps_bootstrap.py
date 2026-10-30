"""Pinned, password-authenticated provisioning for explicitly adopted fresh VPSs."""

import hashlib
import asyncio
import ipaddress
import json
import re
from copy import deepcopy

import asyncssh
import httpx
from sqlalchemy import select

from .database import Integration, SessionLocal, SystemSetting
from .nodehost import NodeHostError, known_blocked
from .vault import decrypt, encrypt

INSTALLER_COMMIT = "00c671745d64b171d81cd6b55c62d211bbfac180"
INSTALLER_SHA256 = "343b5843030be7e7f720cf5dcb8b0d6767a3c18864a863a55d634a196ff089dd"
INSTALLER_URL = (
    "https://raw.githubusercontent.com/Daniil-GR/TelemtProxy/"
    + INSTALLER_COMMIT
    + "/deploy.sh"
)


def patch_profile(text, secret, ad_tag):
    """Change only hello and ad_tag; reject unknown/duplicate TOML sections."""
    import tomllib

    if not all(re.fullmatch(r"[0-9a-f]{32}", v) for v in (secret, ad_tag)):
        raise NodeHostError("Нужны 32 hex-символа профиля")
    original = tomllib.loads(text)
    expected = deepcopy(original)
    if "hello" not in expected.get("access", {}).get("users", {}):
        raise NodeHostError("Пользователь hello отсутствует")
    if "ad_tag" not in expected.get("general", {}):
        raise NodeHostError("Поле ad_tag отсутствует")
    expected["access"]["users"]["hello"] = secret
    expected["general"]["ad_tag"] = ad_tag
    for section, key, value in (
        ("general", "ad_tag", ad_tag),
        ("access.users", "hello", secret),
    ):
        block = re.compile(
            r"(?ms)(^\[" + re.escape(section) + r"\][^\S\n]*\n)(.*?)(?=^\[|\Z)"
        )
        matches = list(block.finditer(text))
        if len(matches) != 1:
            raise NodeHostError("Неоднозначная секция профиля")
        match = matches[0]
        body, count = re.subn(
            r"(?m)^([ \t]*" + re.escape(key) + r"[ \t]*=[ \t]*)[^\n]*$",
            lambda m: m[1] + json.dumps(value),
            match[2],
        )
        if count != 1:
            raise NodeHostError("Неоднозначное поле профиля")
        text = text[: match.start(2)] + body + text[match.end(2) :]
    if tomllib.loads(text) != expected:
        raise NodeHostError("Изменились посторонние настройки Telemt")
    return text


async def connect(credential_id, *, allow_first_pin=False):
    """TOFU is opt-in once; later connections always verify the saved host key."""
    with SessionLocal() as db:
        item = db.get(Integration, credential_id)
        if not item or item.kind != "vps_access":
            raise NodeHostError("Нет зашифрованных данных VPS")
        data = decrypt(item)
    host = str(ipaddress.IPv4Address(data["ipv4"]))
    if not ipaddress.IPv4Address(host).is_global or data["username"] != "root":
        raise NodeHostError("Недопустимый адрес или пользователь VPS")
    pinned = data.get("host_key")
    if not pinned:
        if not allow_first_pin:
            raise NodeHostError("Сначала нужно закрепить SSH host key выбранного VPS")
        key = await asyncio.wait_for(
            asyncssh.get_server_host_key(host, port=22, config=None), timeout=15
        )
        if key is None:
            raise NodeHostError("SSH не предоставил ключ сервера")
        pinned = key.export_public_key().decode().strip()
        with SessionLocal() as db:
            item = db.get(Integration, credential_id, with_for_update=True)
            current = decrypt(item)
            if current.get("host_key") and current["host_key"] != pinned:
                raise NodeHostError("SSH host key изменился во время закрепления")
            current["host_key"] = pinned
            item.ciphertext = encrypt(item.id, item.kind, current)
            db.commit()
    known = asyncssh.import_known_hosts(f"{host} {pinned}\n")
    return await asyncssh.connect(
        host,
        port=22,
        username=data["username"],
        password=data["password"],
        known_hosts=known,
        config=None,
        client_keys=[],
        agent_path=None,
        connect_timeout=20,
        login_timeout=15,
    )


async def inspect(credential_id, *, allow_first_pin=False):
    async with await connect(
        credential_id, allow_first_pin=allow_first_pin
    ) as connection:
        # Intentionally no config dump: user secrets must never reach normal logs.
        program = """import json, pathlib, tomllib, subprocess
osinfo=dict(line.split('=',1) for line in pathlib.Path('/etc/os-release').read_text().splitlines() if '=' in line)
p=pathlib.Path('/etc/telemt/telemt.toml')
c=tomllib.loads(p.read_text()) if p.is_file() else {}
print(json.dumps({'os':osinfo.get('ID','').strip(chr(34)),'version':osinfo.get('VERSION_ID','').strip(chr(34)),
'installed':bool(c),'public_host':c.get('general',{}).get('links',{}).get('public_host',''),
'port':c.get('server',{}).get('port'),'has_hello':bool(c.get('access',{}).get('users',{}).get('hello')),
'has_ad_tag':bool(c.get('general',{}).get('ad_tag')),
'active':subprocess.run(['systemctl','is-active','--quiet','telemt']).returncode==0}))
"""
        result = await connection.run(
            "python3 -", input=program, timeout=20, check=False
        )
        if result.exit_status or len(result.stdout) > 4096:
            raise NodeHostError("Не удалось прочитать состояние VPS")
        return json.loads(result.stdout)


async def installer():
    async with httpx.AsyncClient(timeout=30, follow_redirects=False) as client:
        response = await client.get(INSTALLER_URL)
        response.raise_for_status()
        source = response.content
    # The reviewed commit is immutable; reject HTML/error pages or unexpected files.
    if (
        not source.startswith(b"#!/usr/bin/env bash\n")
        or len(source) > 2_000_000
        or hashlib.sha256(source).hexdigest() != INSTALLER_SHA256
    ):
        raise NodeHostError("Неверный файл установщика")
    return source, hashlib.sha256(source).hexdigest()


def remote_patch_program():
    # Ship only this small pure function, with no server passwords embedded.
    import inspect as python_inspect

    return (
        """import json,re,tomllib,os,tempfile,subprocess
from copy import deepcopy
from pathlib import Path
class NodeHostError(RuntimeError): pass
"""
        + python_inspect.getsource(patch_profile)
        + """
p=Path('/etc/telemt/telemt.toml')
profile=json.loads(Path('/var/lib/autoip-vps/profile.json').read_text())
old=p.read_text(); new=patch_profile(old,profile['secret'],profile['ad_tag'])
stat=p.stat(); backup=p.with_name('telemt.toml.autoip-before-profile')
if not backup.exists():
 fd=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as f:f.write(old)
fd,name=tempfile.mkstemp(dir=p.parent,prefix='.autoip-profile-')
try:
 os.fchmod(fd,stat.st_mode & 0o777); os.fchown(fd,stat.st_uid,stat.st_gid)
 with os.fdopen(fd,'w') as f:f.write(new); f.flush();os.fsync(f.fileno())
 os.replace(name,p)
finally:
 if os.path.exists(name):os.unlink(name)
if subprocess.run(['systemctl','restart','telemt']).returncode:
 p.write_text(old); os.chmod(p,stat.st_mode & 0o777); os.chown(p,stat.st_uid,stat.st_gid)
 subprocess.run(['systemctl','restart','telemt'])
 raise NodeHostError('Telemt restart failed; original profile restored')
Path('/var/lib/autoip-vps/profile.json').unlink()
"""
    )


async def start_install(credential_id, profile_id, operation_id, *, approved=False):
    """Start one durable remote unit. Existing installations are never overwritten."""
    from uuid import UUID

    if not approved:
        raise NodeHostError("Нужно подтверждение установки на выбранный новый VPS")
    operation_id = str(UUID(operation_id))
    with SessionLocal() as db:
        credential = db.get(Integration, credential_id)
        if not credential or credential.kind != "vps_access":
            raise NodeHostError("Нет данных выбранного VPS")
        access = decrypt(credential)
        if known_blocked(db, access["ipv4"]):
            raise NodeHostError("Установка на заблокированный IPv4 запрещена")
        receipts = db.scalars(
            select(SystemSetting).where(SystemSetting.key.like("vps-receipt:%"))
        ).all()
        if not any(
            r.value.get("credential_id") == credential_id and r.value.get("managed")
            for r in receipts
        ):
            raise NodeHostError("VPS не передан под управление AutoIP")
        profile = db.get(Integration, profile_id)
        if not profile or profile.kind != "telemt_profile":
            raise NodeHostError("Нет зашифрованного профиля Telemt")
        data = decrypt(profile)
        tls_lineage_id = profile.metadata_json.get("tls_lineage_id")
    if data.get("domain") != "pl.vetka.rest":
        raise NodeHostError("Для этой версии разрешён только pl.vetka.rest")
    patch_profile(
        '[general]\nad_tag=""\n[access.users]\nhello=""\n',
        data["secret"],
        data["ad_tag"],
    )
    source, digest = await installer()
    unit = "autoip-vps-" + operation_id
    async with await connect(credential_id) as connection:
        # DNS must already point at the candidate before running Let's Encrypt.
        checked = await connection.run(
            "test ! -e /etc/telemt/telemt.toml && test ! -e /opt/mtpr-simple/main.sh && "
            "test ! -e /var/lib/autoip-vps && install -d -m 0700 /var/lib/autoip-vps",
            timeout=15,
            check=False,
        )
        if checked.exit_status:
            raise NodeHostError(
                "VPS не чистый или установка уже запускалась; нужна сверка"
            )
        if tls_lineage_id:
            from .vps_certificates import restore

            await restore(connection, tls_lineage_id)
        async with connection.start_sftp_client() as sftp:
            for name, content in {
                "deploy.sh": source,
                "profile.json": json.dumps(data).encode(),
                "apply.py": remote_patch_program().encode(),
            }.items():
                async with sftp.open("/var/lib/autoip-vps/" + name, "wb") as file:
                    await file.write(content)
                await sftp.chmod("/var/lib/autoip-vps/" + name, 0o600)
        command = (
            "umask 077; systemd-run --unit="
            + unit
            + " --property=Type=exec /bin/bash -c "
            "'umask 077; exec > /var/lib/autoip-vps/install.log 2>&1; "
            "bash /var/lib/autoip-vps/deploy.sh pl.vetka.rest && "
            "python3 /var/lib/autoip-vps/apply.py && "
            "touch /var/lib/autoip-vps/succeeded'"
        )
        result = await connection.run(command, timeout=20, check=False)
        if result.exit_status:
            raise NodeHostError(
                "Запуск установщика не подтверждён; не повторяйте его автоматически"
            )
    return {
        "unit": unit,
        "installer_commit": INSTALLER_COMMIT,
        "installer_sha256": digest,
    }


async def install_status(credential_id):
    async with await connect(credential_id) as connection:
        result = await connection.run(
            "test -f /var/lib/autoip-vps/succeeded && systemctl is-active --quiet telemt && "
            "systemctl is-active --quiet nginx",
            timeout=15,
            check=False,
        )
        return {"succeeded": result.exit_status == 0}
