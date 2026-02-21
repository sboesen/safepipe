#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SAFEPIPE_BIN="${SAFEPIPE_BIN:-safepipe}"

if ! command -v "$SAFEPIPE_BIN" >/dev/null 2>&1; then
  SAFEPIPE_BIN="$HOME/.cargo/bin/safepipe"
fi

echo '   summarize this text for me and keep it compact   ' \
  | "$SAFEPIPE_BIN" template run \
      --template "$SCRIPT_DIR/stdin_prompt.spt" \
      --root /tmp \
      --terminal-policy strict_printable
