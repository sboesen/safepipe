#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PORT="${1:-8877}"
PID_FILE="/tmp/safepipe-template-server.pid"
LOG_FILE="/tmp/safepipe-template-server.log"

if [[ -f "$PID_FILE" ]]; then
  PID="$(cat "$PID_FILE" || true)"
  if [[ -n "${PID:-}" ]] && kill -0 "$PID" 2>/dev/null; then
    echo "template server already running on PID $PID"
    echo "url: http://127.0.0.1:$PORT/"
    exit 0
  fi
fi

cd "$SCRIPT_DIR"
nohup python3 -m http.server "$PORT" --bind 127.0.0.1 >"$LOG_FILE" 2>&1 &
PID="$!"
echo "$PID" > "$PID_FILE"
sleep 0.5

if ! kill -0 "$PID" 2>/dev/null; then
  echo "failed to start template server; check $LOG_FILE" >&2
  exit 1
fi

echo "template server started"
echo "pid: $PID"
echo "url: http://127.0.0.1:$PORT/"
echo "log: $LOG_FILE"
