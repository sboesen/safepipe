#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SAFEPIPE_BIN="${SAFEPIPE_BIN:-safepipe}"
DEMO_ROOT="/tmp/safepipe-demo"

if ! command -v "$SAFEPIPE_BIN" >/dev/null 2>&1; then
  SAFEPIPE_BIN="$HOME/.cargo/bin/safepipe"
fi

mkdir -p "$DEMO_ROOT/rules" "$DEMO_ROOT/notes"
printf 'Rule A\nRule B\n' > "$DEMO_ROOT/rules/agent_rules.md"
printf 'Remember to test' > "$DEMO_ROOT/notes/today.txt"

"$SAFEPIPE_BIN" template run \
  --template "$SCRIPT_DIR/system_context.spt" \
  --root "$DEMO_ROOT" \
  --terminal-policy strict_printable
