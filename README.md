# safepipe

`safepipe` is a local-first, memory-safe CLI for safe text pipelines and shareable prompt templates.

Primary workflow:

1. Trust one binary (`safepipe`).
2. Share template files (`.spt`) from GitHub or local files.
3. Let templates read local data in a constrained way and render terminal output safely.

The runtime does not execute shell commands, does not load plugins, and does not eval user code.

## Install

```bash
cargo install --path crates/cli
```

## Template DSL (Primary Use Case)

A template can be local, installed, or fetched from a URL.

Template syntax (v1):

- `template v1`
- `set terminal_policy = balanced|strict_printable|raw`
- `set newline = preserve|ensure_trailing`
- `source <name> = file("...") | <op> | <op> ...`
- `source <name> = stdin() | <op> ...`
- `source <name> = now("%Y-%m-%d %H:%M:%S %Z")`
- `source <name> = literal("...")`
- `emit """ ... {{name}} ... """`

Example:

```text
template v1
set terminal_policy = balanced
set newline = ensure_trailing

source now = now("%Y-%m-%d %H:%M:%S %Z")
source profile = file("profile.txt") | trim:both
source prompt = stdin() | trim:both | wrap:width=88

emit """
Current time: {{now}}

Profile:
{{profile}}

User prompt:
{{prompt}}
"""
```

Run it:

```bash
cat user.txt | safepipe template run --template ./template.spt --root .
```

### Sharing / Installing templates

```bash
# Install from GitHub raw URL
safepipe template install \
  --name daily_context \
  --from https://raw.githubusercontent.com/ORG/REPO/main/templates/daily_context.spt

# List installed templates
safepipe template list

# Show installed template
safepipe template show --name daily_context

# Run installed template
cat input.txt | safepipe template run --template @daily_context --root .
```

## Transform Mode (Direct)

You can still run direct transforms without templates:

```bash
cat notes.txt | safepipe run --op trim:both --op collapse_whitespace:preserve_newlines=true
```

Supported interfaces:

- repeated `--op` expressions
- JSON `--spec` (inline or `@file`)

## Commands

- `safepipe run`
- `safepipe validate --spec ...`
- `safepipe explain --spec ...`
- `safepipe template run --template ... --root ...`
- `safepipe template install --name ... --from ...`
- `safepipe template list`
- `safepipe template show --name ...`

## Example Templates

- `examples/system_context.spt`
- `examples/stdin_prompt.spt`

## Exit Codes

- `0`: success
- `2`: spec/template/validation error
- `3`: limits exceeded or timeout
- `4`: internal/runtime error

## Safety Notes

- No shell execution, eval, or dynamic extension loading.
- Template `file(...)` reads are rooted by `--root` and must remain under that directory.
- URL templates are treated as untrusted text and parsed declaratively.
- Terminal sanitizer is applied unless output policy is `raw`.
- Resource bounds: template bytes, source bytes, output bytes, line count, optional timeout.

For details, see `SECURITY.md`.
