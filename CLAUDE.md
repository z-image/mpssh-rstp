# mpssh-rstp

Mass parallel SSH in Rust. Executes commands simultaneously on many hosts.

## Architecture

- `src/main.rs` - CLI, progress tracking, output formatting, async orchestration
- `src/ssh.rs` - Two SSH backends: russh (pure Rust) and libssh2

## Code Review Checklist

1. `cargo clippy` - Fix warnings before proceeding
2. `cargo test` - All tests must pass
3. Review for: Clarity, KISS, DRY, POLA, EIBTI (in that order)
