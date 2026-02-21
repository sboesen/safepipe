# Contributing

## Setup

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Development Principles

- Keep transforms deterministic.
- Keep runtime bounded.
- Prefer explicit typed options over dynamic behavior.
- Do not introduce shell execution, plugin loading, or eval features.
