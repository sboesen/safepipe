#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SAFEPIPE_BIN="${SAFEPIPE_BIN:-safepipe}"
DEMO_ROOT="/tmp/safepipe-awk-demo"

if ! command -v "$SAFEPIPE_BIN" >/dev/null 2>&1; then
  SAFEPIPE_BIN="$HOME/.cargo/bin/safepipe"
fi

mkdir -p "$DEMO_ROOT"
cat > "$DEMO_ROOT/app.log" <<'LOG'
2026-02-21 INFO auth login_ok user=alice
2026-02-21 ERROR db timeout user=bob
2026-02-21 ERROR api quota_exceeded user=charlie
LOG

"$SAFEPIPE_BIN" template run \
  --template "$SCRIPT_DIR/safe_awk_extract.spt" \
  --root "$DEMO_ROOT" \
  --terminal-policy strict_printable
