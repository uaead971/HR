#!/bin/zsh

set -e

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_PORT=8765
APP_URL="http://localhost:${APP_PORT}/"
APP_HEALTH="${APP_URL}api/health"

cd "$APP_DIR"

if curl -fsS --max-time 2 "$APP_HEALTH" >/dev/null 2>&1; then
  open "$APP_URL"
  echo "التطبيق يعمل بالفعل: $APP_URL"
  exit 0
fi

# قد يبقى خادم http.server القديم على 8765؛ لا نقتل عملية لا نملكها، بل ننتقل لمنفذ حر.
if curl -fsS --max-time 1 "$APP_URL" >/dev/null 2>&1; then
  APP_PORT=8766
  APP_URL="http://localhost:${APP_PORT}/"
  APP_HEALTH="${APP_URL}api/health"
fi

python3 server.py --host 127.0.0.1 --port "$APP_PORT" &
SERVER_PID=$!

cleanup() {
  kill "$SERVER_PID" >/dev/null 2>&1 || true
}

trap cleanup EXIT INT TERM
for _ in {1..20}; do
  curl -fsS --max-time 1 "$APP_HEALTH" >/dev/null 2>&1 && break
  sleep 0.2
done

if ! curl -fsS --max-time 2 "$APP_HEALTH" >/dev/null 2>&1; then
  echo "تعذر بدء خادم منصة موارد. راجع الرسالة أعلاه."
  exit 1
fi

open "$APP_URL"

echo "تم تشغيل التطبيق: $APP_URL"
echo "اترك هذه النافذة مفتوحة، واضغط Control+C لإيقاف الخادم."

wait "$SERVER_PID"
