#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SAFEPIPE_BIN="${SAFEPIPE_BIN:-safepipe}"

if ! command -v "$SAFEPIPE_BIN" >/dev/null 2>&1; then
  SAFEPIPE_BIN="$HOME/.cargo/bin/safepipe"
fi

printf '  Loves concise answers.  \n' > /tmp/profile.txt

echo '   this is a long input line that should be wrapped and normalized   ' \
  | "$SAFEPIPE_BIN" template run \
      --template "$SCRIPT_DIR/file_and_stdin_demo.spt" \
      --root /tmp \
      --terminal-policy strict_printable
