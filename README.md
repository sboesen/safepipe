# safepipe

Canonical docs are in this README (LLM-first, dense, standalone).

`safepipe` = safe local text runtime for untrusted templates and deterministic text transforms.

## 1) Security Model (Operational)

Status: implemented behavior summary, not formal verification.

Trust boundary:

- Trust the `safepipe` binary.
- Treat template/spec/input text as untrusted.

Enforced properties:

- no shell execution
- no eval
- no plugin loading
- template cannot set runtime terminal policy
- `run` terminal policy is caller-selected; untrusted spec policy is ignored
- caller must pass `--terminal-policy` for `template run`
- `file("...")` reads are rooted under `--root` and blocked on path escape
- optional `--allow-read` capability fence for `file(...)` paths
- template URL defaults: HTTPS-only, no redirects, private-host block (override flags exist)
- optional template content pinning via `--template-sha256`
- runtime bounds on template/source/output bytes and output lines
- optional timeout

## 2) Install

```bash
cargo install --path crates/cli
```

If needed for shell path:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

## 3) CLI Surface

```bash
safepipe run [OPTIONS]
safepipe validate --spec <SPEC>
safepipe explain --spec <SPEC>

safepipe template run [OPTIONS] --template <TEMPLATE> --terminal-policy <POLICY>
safepipe template install --name <NAME> --from <PATH_OR_URL> [--max-template-bytes <N>]
safepipe template list
safepipe template show --name <NAME>
```

### 3.1 `run` options

- `--spec <SPEC>` JSON string or `@path`
- `--op <OPS>` repeatable mini op expression
- `--max-bytes <N>` stdin byte cap (default `8388608`)
- `--max-output-bytes <N>` output byte cap (default `8388608`)
- `--max-lines <N>` output line cap (default `200000`)
- `--timeout-ms <N>` optional timeout
- `--terminal-policy <balanced|strict_printable|raw>` caller policy (spec value ignored)
- `--allow-style` compatibility no-op

### 3.2 `template run` options

- `--template <path|url|@installed_name>`
- `--root <DIR>` root for `file(...)` reads (default `.`)
- `--max-source-bytes <N>` per-source cap (default `8388608`)
- `--max-template-bytes <N>` template cap (default `131072`)
- `--max-output-bytes <N>` output cap (default `8388608`)
- `--max-lines <N>` output line cap (default `200000`)
- `--timeout-ms <N>` optional timeout
- `--terminal-policy <balanced|strict_printable|raw>` required
- `--newline <preserve|ensure_trailing>` default `preserve`
- `--template-sha256 <HEX64>` optional template integrity pin
- `--allow-insecure-http` allow `http://` template URLs
- `--allow-private-hosts` allow localhost/private IP template hosts
- `--allow-read <REL_PATH>` repeatable file read allowlist under `--root` (`.` means whole root)
  - required when template source is URL or `@installed` and template uses `file(...)`.

### 3.3 `template install` options

- `--name <NAME>`
- `--from <PATH_OR_URL>`
- `--max-template-bytes <N>`
- `--template-sha256 <HEX64>` optional template integrity pin
- `--allow-insecure-http` allow `http://` template URLs
- `--allow-private-hosts` allow localhost/private IP template hosts

## 4) Terminal Policies

- `strict_printable`: strips/escapes control sequences; safest for agent ingestion.
- `balanced`: allows safe SGR styles; strips dangerous controls/OSC.
- `raw`: no sanitizer (explicit opt-in).

## 5) Template DSL (`v1`)

### 5.1 Grammar

```ebnf
template      := header? line* emit_block
header        := "template v1"
line          := source_decl | comment | blank
source_decl   := "source" NAME "=" source_expr ("|" OP_EXPR)*
source_expr   := file_call | stdin_call | now_call | literal_call
file_call     := "file(" JSON_STRING ")"
stdin_call    := "stdin()"
now_call      := "now(" JSON_STRING ")"
literal_call  := "literal(" JSON_STRING ")"
emit_block    := "emit \"\"\"" NEWLINE body "\"\"\""
placeholder   := "{{" NAME "}}"
NAME          := [A-Za-z_][A-Za-z0-9_]*
```

### 5.2 Rules

- `set ...` directives are rejected.
- `source` names must match `[A-Za-z_][A-Za-z0-9_]*`.
- placeholders must match existing source names.
- template pipeline separator is `|`.
- if op arg values need list-like separators inside a template source line, prefer `;` (example: `fields=1;3;4`).

### 5.3 Source functions

- `file("relative/path")`
- `stdin()`
- `now("%Y-%m-%d %H:%M:%S %Z")`
- `literal("text")`

## 6) OP DSL

Syntax:

- key/value: `op:key=value,key2=value2`
- positional: `op:value1,value2`

Supported ops:

- `normalize_unicode` / `normalize`
- `trim`
- `collapse_whitespace` / `collapse`
- `wrap`
- `truncate`
- `extract_between` / `extract`
- `replace_literal` / `replace`
- `regex_replace` / `regex`
- `redact`
- `quote`
- `table`
- `sort_lines` / `sort`
- `select_columns` / `select_fields` / `awk_select` (safe awk-like)
- `filter_contains`
- `filter_regex`

### 6.1 Op reference

`normalize_unicode`

- `normalize_unicode:form=nfc`
- `normalize_unicode:form=nfkc`

`trim`

- `trim:mode=left|right|both`
- shorthand: `trim:left`

`collapse_whitespace`

- `collapse_whitespace:preserve_newlines=true|false`

`wrap`

- `wrap:width=88,break_long_words=false`

`truncate`

- `truncate:max_chars=2000,ellipsis=...`

`extract_between`

- `extract_between:start=<A>,end=<B>,mode=first|all`

`replace_literal`

- `replace_literal:from=foo,to=bar,max_replacements=2`

`regex_replace`

- `regex_replace:pattern=\\d+,to=[NUM],max_replacements=3`

`redact`

- `redact:patterns=email|ipv4|api_key_like|url,replacement=[REDACTED]`

`quote`

- `quote:style=json|shell_single|markdown_code`

`table`

- `table:delimiter=comma|tab|pipe,align=left|right|center`

`sort_lines`

- `sort_lines:unique=true,numeric=true,reverse=true`

`select_columns` (safe awk-like field projection)

- `select_columns:fields=1;3;4,delimiter=whitespace,output_delimiter=:,skip_missing=true`
- fields are 1-based.
- field separators accepted inside value: `;` or `|`.
- delimiter accepts `whitespace`, `tab`, literal text.

`filter_contains`

- `filter_contains:needle=ERROR,invert=false`

`filter_regex`

- `filter_regex:pattern=timeout|quota,invert=false`

## 7) JSON Spec (`run --spec`)

Minimal:

```json
{
  "version": "v1",
  "ops": [
    { "op": "trim", "mode": "both" }
  ]
}
```

Shape:

- `version`: must be `"v1"`
- `input.encoding`: `utf8|bytes_lossy`
- `ops`: ordered op array (same operations as CLI `--op`)
- `output.terminal_policy`: `balanced|strict_printable|raw`
- `output.newline`: `preserve|ensure_trailing`

Helper commands:

```bash
safepipe validate --spec @spec.json
safepipe explain --spec @spec.json
```

## 8) Safe awk-like vs awk

What it is:

- declarative line/field filtering/projection ops with bounded runtime.

What it is not:

- no user program blocks
- no variable state
- no loops/conditionals authored by template author
- no command execution

## 9) Dense Examples

### 9.1 direct transform

```bash
echo '   hello   world   ' \
| safepipe run --op trim:both --op collapse_whitespace
```

### 9.2 untrusted remote template

```bash
cat input.txt | safepipe template run \
  --template https://raw.githubusercontent.com/ORG/REPO/main/template.spt \
  --root . \
  --allow-read prompts/profile.txt \
  --template-sha256 <HEX64> \
  --terminal-policy strict_printable
```

### 9.3 install + run template

```bash
safepipe template install --name daily_context --from https://raw.githubusercontent.com/ORG/REPO/main/daily_context.spt --template-sha256 <HEX64>
cat input.txt | safepipe template run --template @daily_context --root . --terminal-policy strict_printable
```

### 9.4 safe awk-like direct

```bash
cat app.log | safepipe run \
  --op 'filter_contains:needle=ERROR' \
  --op 'select_columns:fields=1;3;4,delimiter=whitespace,output_delimiter=:'
```

### 9.5 safe awk-like template

```text
template v1
source rows = file("app.log") | filter_contains:needle=ERROR | select_columns:fields=1;3;4,delimiter=whitespace,output_delimiter=:
emit """
{{rows}}
"""
```

Run:

```bash
safepipe template run --template ./safe_awk_extract.spt --root . --terminal-policy strict_printable
```

### 9.6 file + stdin composition

```text
template v1
source profile = file("profile.txt") | trim:both
source prompt = stdin() | trim:both | wrap:width=72
emit """
[PROFILE]
{{profile}}

[PROMPT]
{{prompt}}
"""
```

Run:

```bash
echo '  summarize this safely  ' | safepipe template run --template ./file_and_stdin_demo.spt --root . --terminal-policy strict_printable
```

## 10) Agent Execution Pattern

1. pin `--terminal-policy strict_printable` unless raw output is explicitly needed.
2. set conservative bounds (`--max-source-bytes`, `--max-output-bytes`).
3. for remote templates, pin `--template-sha256` and keep HTTPS.
4. for URL/`@installed` templates using `file(...)`, provide minimal `--allow-read` scope.
5. keep template source untrusted; never assume it can change runtime safety.
6. consume stdout only.

## 11) Failure Hints

- `set directives are not allowed`: template attempted policy/config mutation.
- `required arguments were not provided: --terminal-policy`: policy must be caller-chosen.
- `absolute paths are not allowed`: `file(...)` used absolute path.
- `escapes root`: `file(...)` path traversal blocked.
- `not allowed by --allow-read policy`: `file(...)` outside declared capability.
- `refusing insecure HTTP template URL`: pass `--allow-insecure-http` if truly needed.
- `is private/local`: host blocked unless `--allow-private-hosts`.
- `template SHA-256 mismatch`: fetched bytes != `--template-sha256`.
- `missing placeholder value`: placeholder has no source.
- `unknown op '3'` in template: `|` inside op args split pipeline; use `fields=1;3;4`.

## 12) Exit Codes

- `0` success
- `2` validation/template/spec error
- `3` limits or timeout
- `4` internal/runtime error

## 13) Local Runnable Assets

- `examples/run_file_and_stdin_demo.sh`
- `examples/run_system_context_demo.sh`
- `examples/run_stdin_prompt_demo.sh`
- `examples/run_safe_awk_extract_demo.sh`
