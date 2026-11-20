#!/bin/sh
# Destructive ONLY to this deployment's isolated E-chat database and media volume.
set -eu
umask 077
cd "$(dirname "$0")/.."
if [ "$#" -ne 2 ] || [ "$2" != '--yes-replace-echat' ]; then
    echo 'Usage: bash scripts/restore.sh backups/TIMESTAMP --yes-replace-echat' >&2; exit 2
fi
SOURCE=$(realpath "$1")
(cd "$SOURCE" && sha256sum -c SHA256SUMS)
test -s "$SOURCE/database.dump" && test -s "$SOURCE/media.tar.gz" && test -s "$SOURCE/config.env"
# Restoring config also restores the data key. Require the same project and DB credentials.
# For migration to a fresh host, copy config.env to .env, then run up.sh before restoring.
test -f .env || { echo 'Copy backup config.env to .env and initialize a NEW deployment first' >&2; exit 1; }
python3 - "$SOURCE/config.env" <<'PY'
import sys
from pathlib import Path
def read(p):return dict(line.split('=',1) for line in Path(p).read_text().splitlines() if line and not line.startswith('#'))
a,b=read('.env'),read(sys.argv[1])
for k in ('COMPOSE_PROJECT_NAME','POSTGRES_PASSWORD','ECHAT_DB_PASSWORD','ECHAT_DATA_KEY'):
 if a.get(k)!=b.get(k):raise SystemExit('Configuration mismatch: '+k+'. Restore into a separate empty deployment with the backup config.')
PY
docker compose stop api
# If a restore fails, intentionally leave API stopped; do not serve inconsistent data.
docker compose exec -T db sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" pg_restore -h 127.0.0.1 -U postgres -d echat --clean --if-exists --no-owner --role=echat --exit-on-error' < "$SOURCE/database.dump"
docker compose run --rm --no-deps -T --entrypoint sh api -c 'find /app/data -mindepth 1 -maxdepth 1 -exec rm -rf {} \;'
docker compose run --rm --no-deps -T --entrypoint tar api -xzf - -C /app/data < "$SOURCE/media.tar.gz"
docker compose run --rm --no-deps api python -m echat check
docker compose up -d --wait api
echo 'E-chat restored. Re-enable other API nodes only after confirming the restored database and shared storage.'