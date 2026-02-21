# safepipe LLM DSL Reference (Dense)

Status: implemented behavior summary, not formal proof.

## 1) Trust Boundary (Critical)

- Treat template text as untrusted input.
- Template cannot set terminal safety policy.
- Caller sets policy via CLI flag at execution time.
- No shell execution/eval/plugin loading in template runtime.

## 2) Runtime Contract

Required call shape:

```bash
safepipe template run \
  --template <path|url|@installed_name> \
  --root <directory> \
  --terminal-policy <strict_printable|balanced|raw>
```

Optional runtime controls:

- `--newline <preserve|ensure_trailing>`
- `--max-template-bytes <n>`
- `--max-source-bytes <n>`
- `--max-output-bytes <n>`
- `--max-lines <n>`
- `--timeout-ms <n>`

## 3) DSL Grammar (Implemented)

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

Notes:

- `set ...` lines are rejected.
- `JSON_STRING` means quoted JSON string syntax, e.g. `"profile.txt"`.
- Source values are transformed independently, then injected into emit body via placeholders.
- In template `source` lines, `|` is the pipeline separator. Use `;` inside op values when you need a list (for example `fields=1;3;4`).

## 4) Source Functions

- `file("relative/path")`
- `stdin()`
- `now("%Y-%m-%d %H:%M:%S %Z")` (chrono formatting)
- `literal("text")`

`file(...)` safety:

- path must be relative
- path must resolve under `--root`
- path escape is blocked

## 5) OP_EXPR Reference (Mini Parser)

Two forms:

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
- `select_columns` / `select_fields` / `awk_select`
- `filter_contains`
- `filter_regex`

### op: normalize_unicode

- `normalize_unicode:form=nfc`
- `normalize_unicode:form=nfkc`
- positional shorthand: `normalize:nfkc`

### op: trim

- `trim:mode=both`
- `trim:left` / `trim:right` / `trim:both`

### op: collapse_whitespace

- `collapse_whitespace:preserve_newlines=true`
- `collapse:true` is interpreted positionally for `preserve_newlines`

### op: wrap

- `wrap:width=88,break_long_words=false`
- positional: `wrap:88,true`

### op: truncate

- `truncate:max_chars=2000,ellipsis=...`
- positional: `truncate:2000,...`

### op: extract_between

- `extract_between:start=<BEGIN>,end=<END>,mode=first`
- `mode=all` returns newline-joined matches

### op: replace_literal

- `replace_literal:from=foo,to=bar,max_replacements=2`
- positional: `replace:foo,bar,2`

### op: regex_replace

- `regex_replace:pattern=\\d+,to=[NUM]`
- positional: `regex:\\d+,[NUM]`

### op: redact

- `redact:patterns=email|ipv4|api_key_like|url,replacement=[REDACTED]`
- defaults to `email` if no pattern parsed

### op: quote

- `quote:style=json`
- `quote:shell_single`
- `quote:markdown_code`

### op: table

- `table:delimiter=comma,align=left`
- delimiter: `comma|tab|pipe`
- align: `left|right|center`

### op: sort_lines

- `sort_lines:unique=true,numeric=true,reverse=true`
- positional flags: `sort:unique,numeric,reverse`

### op: select_columns (safe awk-like field select)

- `select_columns:fields=1;3;4,delimiter=whitespace,output_delimiter=:,skip_missing=true`
- aliases: `select_fields`, `awk_select`
- `fields` are 1-based
- accepted field separators in value: `;` or `|`
- `delimiter` values:
  - `whitespace` (default if omitted)
  - `tab`
  - any literal delimiter string

### op: filter_contains

- `filter_contains:needle=ERROR`
- `filter_contains:needle=ERROR,invert=true`

### op: filter_regex

- `filter_regex:pattern=timeout|quota`
- `filter_regex:pattern=^WARN,invert=true`

## 6) Dense Examples

### A) profile file + stdin prompt

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
echo '  user input that may be messy  ' \
| safepipe template run \
    --template ./prompt.spt \
    --root . \
    --terminal-policy strict_printable
```

### B) system context template

```text
template v1
source now = now("%Y-%m-%d %H:%M:%S %Z")
source policy = file("rules/policy.md") | trim:both
source notes = file("notes/today.txt") | trim:both | truncate:max_chars=4000
emit """
Time: {{now}}

Policy:
{{policy}}

Notes:
{{notes}}
"""
```

### C) safe log extraction for agent input

```text
template v1
source log = file("logs/app.log") | filter_contains:needle=ERROR | select_columns:fields=1;3;4,delimiter=whitespace,output_delimiter=:
emit """
Filtered log fields:
{{log}}
"""
```

### D) redact before injection

```text
template v1
source txt = stdin() | redact:patterns=email|api_key_like|url,replacement=[X]
emit """
Sanitized:
{{txt}}
"""
```

### E) template install (local file only)

```bash
# fetch/store template outside safepipe, then install locally
safepipe template install \
  --name daily_context \
  --from ./daily_context.spt

cat input.txt \
| safepipe template run \
    --template @daily_context \
    --root . \
    --terminal-policy strict_printable
```

## 7) Agent Usage Pattern (Copy/Paste)

Use this sequence when operating safely with untrusted templates:

1. Validate root directory scope and required files.
2. Prefer `--terminal-policy strict_printable`.
3. Keep `--max-source-bytes` and `--max-output-bytes` conservative.
4. Run template and consume stdout only.
5. Do not rely on template-set runtime policy (unsupported by design).

## 8) Failure Mode Hints

- `set directives are not allowed`: template attempted to configure runtime policy.
- `absolute paths are not allowed`: `file(...)` used an absolute path.
- `escapes root`: `file(...)` path traversal blocked.
- `missing placeholder value`: `{{name}}` has no source with that name.
- `required arguments were not provided: --terminal-policy`: caller must set safety mode.
- `unknown op '3'` in template: `|` inside op args was parsed as pipeline split; prefer `fields=1;3;4` in templates.
