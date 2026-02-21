# safepipe

`safepipe` is a local-first, memory-safe CLI for deterministic text shaping in agent and shell pipelines.

It is designed to be safe when used like:

```bash
curl https://example.com/untrusted.txt | safepipe run --op trim --op collapse_whitespace
```

The binary does not execute subprocesses, does not load plugins, and does not evaluate code.

## What It Does

- Prompt-safe text shaping: normalize, wrap, redact, quote, truncate.
- Terminal-safe formatting: allow safe style ANSI (balanced mode) while blocking control payloads.
- Data munging: literal/regex replace, sorting, delimiter-aligned tables.

## Install

```bash
cargo install --path crates/cli
```

## Quick Start

### 1) Prompt-safe shaping

```bash
cat notes.txt | safepipe run \
  --op normalize_unicode:nfkc \
  --op collapse_whitespace:preserve_newlines=true \
  --op wrap:width=88
```

### 2) Terminal formatting with safe ANSI boundary

```bash
printf '\033[2J\033[31mhello\033[0m\n' | safepipe run --op trim
```

In default `balanced` mode, dangerous sequences (like clear-screen/cursor movement) are removed, while safe style SGR codes are preserved.

### 3) Data munging

```bash
cat values.txt | safepipe run --op sort_lines:numeric=true,reverse=true --op truncate:max_chars=2000
```

## Spec Modes

Two interfaces are supported in v1:

- Repeated `--op` mini expressions.
- JSON spec via `--spec` (inline JSON or `@path/to/spec.json`).

Example JSON spec:

```json
{
  "version": "v1",
  "input": { "encoding": "utf8" },
  "ops": [
    { "op": "trim", "mode": "both" },
    { "op": "redact", "patterns": ["email", "api_key_like"], "replacement": "[REDACTED]" },
    { "op": "wrap", "width": 80, "break_long_words": false }
  ],
  "output": { "terminal_policy": "balanced", "newline": "ensure_trailing" }
}
```

Then run:

```bash
cat input.txt | safepipe run --spec @spec.json
```

## Commands

- `safepipe run`: execute transforms against stdin.
- `safepipe validate --spec ...`: validate spec and semantics.
- `safepipe explain --spec ...`: print normalized spec JSON.

## Exit Codes

- `0`: success
- `2`: spec/validation error
- `3`: limits exceeded or timeout
- `4`: internal/runtime error

## Safety Notes

- No shell execution, no eval, no dynamic extension loading.
- Resource boundaries: max input bytes, max output bytes, max lines, optional timeout.
- Terminal sanitizer is always applied unless output policy is `raw`.

For details, see `SECURITY.md`.
