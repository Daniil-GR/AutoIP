#!/usr/bin/env bash
set -euo pipefail
umask 077
cd "$(dirname "${BASH_SOURCE[0]}")/.."
mkdir -p backups
backup_file="backups/autoip-$(date -u +%Y%m%dT%H%M%SZ).dump"
docker compose exec -T db pg_dump -U autoip -d autoip -Fc > "$backup_file"
if [[ ! -s "$backup_file" ]]; then rm -f "$backup_file"; exit 1; fi
printf 'Database backup: %s\nMaster key must be backed up separately using encrypted storage.\n' "$backup_file"
