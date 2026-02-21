# Security Policy

## Scope

`safepipe` is for safe local processing of untrusted text, including remotely hosted template files.

## Important Note

This document describes intended security properties and implemented safeguards.
It is not a formal proof or legal guarantee.

## Threat Model

Security objectives:

- No remote code execution path from template/input text.
- No shell-out/eval/plugin loading from runtime templates/specs.
- Prevent unsafe terminal control payloads from reaching stdout by default.
- Bound CPU/memory usage via explicit limits.
- Constrain template local file reads under an explicit root directory.

Non-goals:

- Sandboxing other programs.
- Perfect data-loss prevention.
- Formal verification of the full runtime.

## Implemented Safeguards

- Rust implementation (memory-safe by default).
- Declarative template and transform model (no executable user code).
- No subprocess execution in runtime pipeline.
- URL templates are fetched as text only, then parsed by DSL parser.
- Template `set ...` directives are rejected.
- Runtime safety policy is caller-selected via CLI flags.
- `file("...")` is rooted under `--root` and path escape is blocked.
- Source/template/output size limits are enforced.

## Output Safety Modes

- `balanced` (default in direct run mode): allows safe SGR styling, strips dangerous control sequences.
- `strict_printable`: strips/escapes all control sequences.
- `raw`: disables sanitizer (explicit opt-in).

## Reporting

Please open a private security report on GitHub if you discover a vulnerability.
