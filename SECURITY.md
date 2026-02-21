# Security Policy

## Threat Model

`safepipe` is intended for **safe local processing of untrusted text input**.

Security objectives:

- No remote code execution path from input text.
- No shell-out/eval/plugin loading from transform specs.
- Prevent unsafe terminal control payloads from reaching stdout by default.
- Bound CPU/memory impact via explicit limits.

Non-goals:

- Sandboxing other programs.
- Deep semantic malware detection.
- Perfect data-loss prevention.

## Hardening Guarantees

- Rust implementation (memory-safe by default).
- Declarative, enum-based transform set (no user-defined code).
- Regex engine is Rust `regex` (no catastrophic backtracking engine class).
- No network access paths in normal operation.
- No subprocess execution in runtime pipeline.

## Output Safety Modes

- `balanced` (default): allows safe SGR styling, strips dangerous escape/control sequences.
- `strict_printable`: strips/escapes all control sequences.
- `raw`: disables sanitizer (explicit opt-in).

## Reporting

Please open a private security report on GitHub if you discover a vulnerability.
