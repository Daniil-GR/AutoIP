#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" != 2 || "$1" != '--confirm-replace-autoip-database' || ! -f "$2" ]]; then
  echo 'Usage: restore.sh --confirm-replace-autoip-database /absolute/path/backup.dump' >&2
  exit 1
fi
backup_file="$(realpath "$2")"
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# Explicitly stop only this Compose project. This is a maintenance operation.
docker compose --profile telegram stop commander worker bot
docker compose exec -T db pg_restore -U autoip -d autoip --clean --if-exists --single-transaction < "$backup_file"
docker compose run --rm migrate
echo 'AutoIP restored. Start the required Commander services after reviewing restore output.'
