#!/usr/bin/env bash
set -euo pipefail

PID_FILE="/tmp/safepipe-template-server.pid"

if [[ ! -f "$PID_FILE" ]]; then
  echo "template server not running (no pid file)"
  exit 0
fi

PID="$(cat "$PID_FILE" || true)"
if [[ -z "${PID:-}" ]]; then
  rm -f "$PID_FILE"
  echo "template server not running (empty pid file)"
  exit 0
fi

if kill -0 "$PID" 2>/dev/null; then
  kill "$PID"
  echo "stopped template server pid $PID"
else
  echo "template server pid $PID not alive"
fi

rm -f "$PID_FILE"
