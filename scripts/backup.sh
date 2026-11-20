#!/bin/sh
# Briefly stops only E-chat API so PostgreSQL + blobs form one consistent recovery point.
set -eu
umask 077
cd "$(dirname "$0")/.."
test -f .env
DEST="backups/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$DEST"
# If multiple API nodes exist, stop ALL writers before this command; see docs/DEPLOY.md.
docker compose stop api
trap 'docker compose start api >/dev/null 2>&1 || true' EXIT HUP INT TERM
docker compose exec -T db sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -h 127.0.0.1 -U postgres -d echat -Fc' > "$DEST/database.dump"
docker compose run --rm --no-deps -T --entrypoint tar api -czf - -C /app/data . > "$DEST/media.tar.gz"
cp .env "$DEST/config.env"
(cd "$DEST" && sha256sum database.dump media.tar.gz config.env > SHA256SUMS)
echo "Backup created: $DEST (contains secrets; encrypt before off-site storage)"