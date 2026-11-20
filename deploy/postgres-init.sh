#!/bin/sh
set -eu
# Runs once, on a new PostgreSQL volume. API never receives the superuser password.
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set=ON_ERROR_STOP=1 --set=app_password="$ECHAT_DB_PASSWORD" <<'SQL'
CREATE ROLE echat LOGIN PASSWORD :'app_password';
GRANT CONNECT ON DATABASE echat TO echat;
ALTER SCHEMA public OWNER TO echat;
ALTER ROLE echat SET statement_timeout = '30s';
ALTER ROLE echat SET idle_in_transaction_session_timeout = '30s';
SQL