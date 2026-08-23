#!/bin/sh
set -eu
HOST="${HR_HOST:-0.0.0.0}"
APP_PORT="${PORT:-${HR_PORT:-8765}}"
DB_PATH="${HR_DB_PATH:-/var/data/hr.sqlite3}"
exec python3 /app/server.py --host "$HOST" --port "$APP_PORT" --db "$DB_PATH"
