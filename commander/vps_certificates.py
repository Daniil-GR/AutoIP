"""Copy only the selected Certbot lineage, encrypted at rest, never into logs."""

import base64
import json
import re
import posixpath
from datetime import timedelta
from pathlib import PurePosixPath
from uuid import uuid4
from asyncssh import SFTPAttrs

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .database import Integration, SessionLocal, utcnow
from .nodehost import NodeHostError
from .vault import decrypt, encrypt

DOMAIN = "pl.vetka.rest"


def allowed(path):
    return bool(
        re.fullmatch(
            r"(?:(?:live|archive)/pl\.vetka\.rest/[a-zA-Z0-9_.-]+\.pem|renewal/pl\.vetka\.rest\.conf|"
            r"accounts/acme-v02\.api\.letsencrypt\.org/directory/[a-f0-9]+/(?:meta|private_key|regr)\.json)",
            path,
        )
    )


def validate(files):
    if (
        not isinstance(files, dict)
        or not 4 <= len(files) <= 80
        or len(json.dumps(files)) > 350000
    ):
        raise NodeHostError("Неверный размер набора TLS")
    decoded = {}
    for path, value in files.items():
        if not allowed(path):
            raise NodeHostError("Посторонний путь в наборе TLS")
        if isinstance(value, dict):
            if set(value) != {"symlink"} or not path.startswith("live/" + DOMAIN + "/"):
                raise NodeHostError("Неизвестная ссылка в наборе TLS")
            target = posixpath.normpath(
                posixpath.join(posixpath.dirname(path), value["symlink"])
            )
            if (
                not target.startswith("archive/" + DOMAIN + "/")
                or not allowed(target)
                or target not in files
                or not isinstance(files[target], str)
            ):
                raise NodeHostError(
                    "Ссылка TLS выходит за пределы выбранного сертификата"
                )
            decoded[path] = value
            continue
        decoded[path] = base64.b64decode(value, validate=True)
        if len(decoded[path]) > 65536:
            raise NodeHostError("Слишком большой файл TLS")
    try:

        def content(path):
            value = decoded[path]
            return (
                decoded[
                    posixpath.normpath(
                        posixpath.join(posixpath.dirname(path), value["symlink"])
                    )
                ]
                if isinstance(value, dict)
                else value
            )

        certificate = x509.load_pem_x509_certificate(
            content("live/" + DOMAIN + "/fullchain.pem")
        )
        key = serialization.load_pem_private_key(
            content("live/" + DOMAIN + "/privkey.pem"), password=None
        )
        names = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
        if names != [DOMAIN] or certificate.not_valid_after_utc < utcnow() + timedelta(
            days=7
        ):
            raise NodeHostError("Нужен действующий сертификат только для pl.vetka.rest")
        encoding = serialization.Encoding.DER
        form = serialization.PublicFormat.SubjectPublicKeyInfo
        if certificate.public_key().public_bytes(
            encoding, form
        ) != key.public_key().public_bytes(encoding, form):
            raise NodeHostError("Ключ не соответствует сертификату")
        if "renewal/" + DOMAIN + ".conf" not in decoded:
            raise NodeHostError("Нет настроек продления Certbot")
    except (ValueError, KeyError, x509.ExtensionNotFound):
        raise NodeHostError("Неверный сертификат или ключ TLS") from None
    return decoded


def export_program():
    return """import base64,json,pathlib,re
root=pathlib.Path('/etc/letsencrypt'); domain='pl.vetka.rest'
renewal=root/'renewal'/(domain+'.conf')
text=renewal.read_text()
account=re.findall(r'(?m)^account\\s*=\\s*([a-f0-9]+)\\s*$',text)
server=re.findall(r'(?m)^server\\s*=\\s*(https://acme-v02.api.letsencrypt.org/directory)\\s*$',text)
assert len(account)==len(server)==1
roots=[root/'live'/domain,root/'archive'/domain,renewal,root/'accounts'/'acme-v02.api.letsencrypt.org'/'directory'/account[0]]
files={}
for prefix in roots:
 paths=sorted(prefix.rglob('*')) if prefix.is_dir() else [prefix]
 for path in paths:
  if not path.is_file():continue
  if path.suffix not in ('.pem','.json','.conf'):continue
  assert path.resolve().is_relative_to(root)
  data=path.read_bytes();assert len(data)<=65536
  files[str(path.relative_to(root))]={'symlink':str(path.readlink())} if path.is_symlink() else base64.b64encode(data).decode()
assert len(files)<=80
print(json.dumps(files))
"""


async def export(credential_id):
    from .vps_bootstrap import connect

    async with await connect(credential_id) as connection:
        result = await connection.run(
            "python3 -", input=export_program(), timeout=20, check=False
        )
    if result.exit_status or len(result.stdout) > 350000:
        raise NodeHostError("Не удалось прочитать выбранный набор Certbot")
    files = json.loads(result.stdout)
    validate(files)
    identifier = str(uuid4())
    with SessionLocal() as db:
        db.add(
            Integration(
                id=identifier,
                name="PL Certbot lineage",
                kind="tls_lineage",
                ciphertext=encrypt(
                    identifier, "tls_lineage", {"files": files, "domain": DOMAIN}
                ),
                status="verified",
            )
        )
        db.commit()
    return {"integration_id": identifier, "domain": DOMAIN, "file_count": len(files)}


async def restore(connection, identifier):
    with SessionLocal() as db:
        item = db.get(Integration, identifier)
        if not item or item.kind != "tls_lineage":
            raise NodeHostError("Нет сохранённого набора TLS")
        data = decrypt(item)
    if data.get("domain") != DOMAIN:
        raise NodeHostError("Посторонний домен TLS")
    decoded = validate(data["files"])
    async with connection.start_sftp_client() as sftp:
        for path, content in sorted(
            decoded.items(), key=lambda item: isinstance(item[1], dict)
        ):
            target = PurePosixPath("/etc/letsencrypt") / path
            await sftp.makedirs(str(target.parent), exist_ok=True)
            if await sftp.lexists(str(target)):
                raise NodeHostError(
                    "TLS файл уже существует; автоматическая перезапись запрещена"
                )
            # Exclusive creation, no following symlinks in the final filename.
            if isinstance(content, dict):
                await sftp.symlink(content["symlink"], str(target))
            else:
                async with sftp.open(
                    str(target), "xb", attrs=SFTPAttrs(permissions=0o600)
                ) as file:
                    await file.write(content)
                await sftp.chmod(str(target), 0o600)
