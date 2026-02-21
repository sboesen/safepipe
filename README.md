# safepipe

Safe, local-first text/template runtime for agents.

Core model: trust one binary, treat templates as untrusted data, force runtime safety policy at execution flags.

## LLM Quickstart

```bash
# install
cargo install --path crates/cli

# run untrusted template with explicit safety policy
cat input.txt | safepipe template run \
  --template https://raw.githubusercontent.com/ORG/REPO/main/template.spt \
  --root . \
  --terminal-policy strict_printable
```

## Security Properties (Implemented, Not Formal Proof)

- no shell exec
- no eval
- no plugin loading
- template cannot set runtime terminal policy
- caller must pass `--terminal-policy` for `template run`
- `file("...")` reads are constrained to `--root` (path escape blocked)
- bounds on template/source/output sizes and line count

See `SECURITY.md` for threat model and limitations.

## Commands

- `safepipe run`
- `safepipe validate --spec ...`
- `safepipe explain --spec ...`
- `safepipe template run --template ... --root ... --terminal-policy ...`
- `safepipe template install --name ... --from ...`
- `safepipe template list`
- `safepipe template show --name ...`

## Template DSL (v1)

Supported lines:

- `template v1`
- `source <name> = file("...") | <op>...`
- `source <name> = stdin() | <op>...`
- `source <name> = now("...")`
- `source <name> = literal("...")`
- `emit """ ... {{name}} ... """`

Rejected by design:

- `set ...` directives

## Safe awk-like subset

New awk-style declarative ops:

- `select_columns`
- `filter_contains`
- `filter_regex`

Example direct usage:

```bash
cat app.log | safepipe run \
  --op 'filter_contains:needle=ERROR' \
  --op 'select_columns:fields=1;3;4,delimiter=whitespace,output_delimiter=|'
```

Equivalent template usage:

```text
template v1
source rows = file("app.log") | filter_contains:needle=ERROR | select_columns:fields=1;3;4,delimiter=whitespace,output_delimiter=:
emit """
{{rows}}
"""
```

## Dense LLM Reference

Use this for compact, machine-friendly docs:

- `docs/LLM_DSL_REFERENCE.md`

It includes:

- grammar
- op syntax
- dense examples
- failure hints
- safe agent execution pattern

## Runnable Examples

- `examples/run_file_and_stdin_demo.sh`
- `examples/run_system_context_demo.sh`
- `examples/run_stdin_prompt_demo.sh`
- `examples/run_safe_awk_extract_demo.sh`

## Exit Codes

- `0`: success
- `2`: spec/template/validation error
- `3`: limits exceeded or timeout
- `4`: internal/runtime error
