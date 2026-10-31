#!/usr/bin/env python3
"""Import the existing pinned node key into Vault; never copy it into Compose mounts."""

import argparse
import json
import os
from pathlib import Path
import stat
import subprocess

import asyncssh


parser = argparse.ArgumentParser()
parser.add_argument("agent_id")
parser.add_argument("--ipv4", required=True)
parser.add_argument("--source-host", required=True)
parser.add_argument("--resource-id", type=int, required=True)
parser.add_argument("--cname", required=True)
parser.add_argument("--gcore-id", required=True)
parser.add_argument("--dns-id", required=True)
parser.add_argument("--ssh-key-file", type=Path, required=True)
parser.add_argument(
    "--known-hosts", type=Path, default=Path.home() / ".ssh/known_hosts"
)
args = parser.parse_args()
fd = os.open(args.ssh_key_file, os.O_RDONLY | os.O_NOFOLLOW)
with os.fdopen(fd) as source:
    info = os.fstat(source.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise SystemExit("SSH key must be a regular private file with mode 0600")
    key = source.read()
pins = asyncssh.import_known_hosts(args.known_hosts.read_text()).match(
    args.ipv4, args.ipv4, 22
)[0]
if not pins:
    raise SystemExit("A previously trusted SSH host key is required")
pin = next((key for key in pins if key.get_algorithm() == "ssh-ed25519"), pins[0])
payload = {
    "agent_id": args.agent_id,
    "binding": {
        "source_host": args.source_host,
        "resource_id": args.resource_id,
        "cname": args.cname,
        "gcore_id": args.gcore_id,
        "dns_id": args.dns_id,
    },
    "ssh": {
        "ipv4": args.ipv4,
        "host_key": pin.export_public_key().decode().strip(),
        "private_key": key,
    },
}
program = """import asyncio,json,sys
from uuid import uuid4
from sqlalchemy import select
from commander.cdn_domains import Gcore,credentials,hostname,resource_ok
from commander.database import Agent,Integration,SessionLocal,SystemSetting
from commander.security import audit
from commander.vault import encrypt
p=json.load(sys.stdin)
b=p['binding']; b['source_host']=hostname(b['source_host'])
with SessionLocal() as db:
 a=db.get(Agent,p['agent_id'])
 if not a or a.revoked or (a.configuration or {}).get('monitoring_mode')!='cdn_web':raise SystemExit('Agent must use CDN WEB')
 if (a.configuration or {}).get('management_ip')!=p['ssh']['ipv4']:raise SystemExit('Management IP differs')
 credentials(db,b['dns_id'],'dynadot')
 g=Gcore(credentials(db,b['gcore_id'],'gcore')['api_key'])
 r=asyncio.run(g.call('GET','/cdn/resources/'+str(b['resource_id'])))
 resource_ok(r,b)
 if db.get(SystemSetting,'cdn-bind:'+a.id):raise SystemExit('Binding exists; explicit review required before replacement')
 for other in db.scalars(select(SystemSetting).where(SystemSetting.key.like('cdn-bind:%'))):
  if other.value.get('gcore_id')==b['gcore_id'] and other.value.get('resource_id')==b['resource_id']:raise SystemExit('Resource already belongs to another agent binding')
 i=str(uuid4());b['ssh_id']=i
 db.add(Integration(id=i,name='CDN node access',kind='cdn_access',ciphertext=encrypt(i,'cdn_access',p['ssh']),status='configured'))
 db.add(SystemSetting(key='cdn-bind:'+a.id,value=b))
 audit(db,'local','cdn_binding_configured',a.id,resource_id=b['resource_id'])
 db.commit()
print('CDN binding saved; SSH key encrypted. No DNS, CDN or node settings changed.')
"""
result = subprocess.run(
    ["docker", "compose", "exec", "-T", "commander", "python", "-c", program],
    cwd=Path(__file__).resolve().parents[1],
    input=json.dumps(payload),
    text=True,
    capture_output=True,
    timeout=60,
)
if result.returncode:
    # Do not echo stderr/locals/tracebacks of credential import.
    raise SystemExit(
        "Binding failed; no credentials printed. Check the selected agent and integration IDs."
    )
print(result.stdout.strip())
