#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
test -f .env || { echo 'Run python3 scripts/init.py YOUR_DOMAIN first' >&2; exit 1; }
docker compose config --quiet
docker compose build api
docker compose up -d --wait db
docker compose run --rm --no-deps api python -m echat migrate
docker compose up -d --wait api
docker compose ps
echo 'API ready on the loopback port from .env. Configure HTTPS on a separate hostname.'