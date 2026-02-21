# Security Policy

## Threat Model

`safepipe` is intended for safe local processing of untrusted text, including remotely hosted template files.

Security objectives:

- No remote code execution path from template/input text.
- No shell-out/eval/plugin loading from runtime specs/templates.
- Prevent unsafe terminal control payloads from reaching stdout by default.
- Bound CPU/memory impact via explicit limits.
- Constrain template local file reads under an explicit root directory.

Non-goals:

- Sandboxing other programs.
- Deep semantic malware detection.
- Perfect data-loss prevention.

## Hardening Guarantees

- Rust implementation (memory-safe by default).
- Declarative transform set (no user-defined executable code).
- Regex engine is Rust `regex` (non-backtracking engine class).
- No subprocess execution in runtime pipeline.
- URL templates are fetched as data only, then parsed by DSL parser.

## Template Security Model

- `template run --template <url|path|@name>` loads text templates only.
- `file("...")` reads are relative to `--root` and blocked if they escape root.
- Source, template, and output sizes are bounded by CLI limits.
- Remote template content must be UTF-8 and within max byte limits.

## Output Safety Modes

- `balanced` (default): allows safe SGR styling, strips dangerous escape/control sequences.
- `strict_printable`: strips/escapes all control sequences.
- `raw`: disables sanitizer (explicit opt-in).

## Reporting

Please open a private security report on GitHub if you discover a vulnerability.
