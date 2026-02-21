# safepipe

`safepipe` is a local-first Rust CLI for running untrusted text templates safely.

Primary goal: trust one binary, then share templates (`.spt`) from GitHub or files without giving templates control over runtime safety policy.

## Agent-Oriented Safety Properties

These are implemented design properties, not formal proofs:

- No shell execution, no eval, no dynamic plugin loading.
- Templates are declarative text only.
- Template scripts cannot set terminal safety policy.
- Caller must choose safety policy at runtime via CLI flag.
- `file("...")` reads are constrained under `--root`.
- Output passes terminal sanitization unless `--terminal-policy raw` is explicitly chosen.
- Input/output/template/source sizes are bounded by limits.

## Install

```bash
cargo install --path crates/cli
```

## Template DSL (Untrusted Input)

Template syntax (`v1`):

- `template v1`
- `source <name> = file("...") | <op> | <op> ...`
- `source <name> = stdin() | <op> ...`
- `source <name> = now("%Y-%m-%d %H:%M:%S %Z")`
- `source <name> = literal("...")`
- `emit """ ... {{name}} ... """`

`set ...` directives are rejected.

Example template:

```text
template v1

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

Run with explicit runtime safety policy:

```bash
cat user.txt | safepipe template run \
  --template ./template.spt \
  --root . \
  --terminal-policy strict_printable
```

## Sharing and Installation

```bash
# Install from URL
safepipe template install \
  --name daily_context \
  --from https://raw.githubusercontent.com/ORG/REPO/main/templates/daily_context.spt

# List installed
safepipe template list

# Show installed template source
safepipe template show --name daily_context

# Run installed template
cat input.txt | safepipe template run \
  --template @daily_context \
  --root . \
  --terminal-policy strict_printable
```

## Commands

- `safepipe run`
- `safepipe validate --spec ...`
- `safepipe explain --spec ...`
- `safepipe template run --template ... --root ... --terminal-policy ...`
- `safepipe template install --name ... --from ...`
- `safepipe template list`
- `safepipe template show --name ...`

## Terminal Policies

- `strict_printable`: strips/escapes all control sequences.
- `balanced`: allows safe SGR styles, strips dangerous control/OSC sequences.
- `raw`: no sanitizer (explicit opt-in).

## Exit Codes

- `0`: success
- `2`: spec/template/validation error
- `3`: limits exceeded or timeout
- `4`: internal/runtime error

## Examples

- `examples/system_context.spt`
- `examples/stdin_prompt.spt`

See `SECURITY.md` for threat model and boundaries.
