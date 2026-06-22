# Implementation Plan: Delete the Dead async-opcua-safety CLI Module

**Branch**: `028-drop-dead-safety-cli` | **Date**: 2026-06-22 | **Spec**: [spec.md](./spec.md)

## Summary
Delete `async-opcua-safety/src/cli.rs` (dead `clap` CLI, no `[[bin]]`, no workspace references) and
remove the `clap` + `hex` dependencies it solely uses. Behavior-preserving; net-negative lines + deps.

## Technical Context
- **Language**: Rust. **Crate**: `async-opcua-safety`.
- **Verified before planning**: `pub mod cli;` is the only reference; no `[[bin]]`; no
  `safety::cli`/`opcua_safety::cli` anywhere; `clap`/`hex` used only by `cli.rs`.
- **Constraints**: crate + workspace build/test green; clippy `-D warnings` clean; no new dep.

## Constitution Check
- **II Do It Right Once / V Leave It Better**: removes dead code + a heavy dep tree. PASS.
- **I Correctness**: behavior-preserving (no live consumer); verified-dead before acting. PASS.
- **IV Security**: smaller dependency surface on a safety-relevant crate. PASS.
No violations.

## Project Structure
```
async-opcua-safety/
├── Cargo.toml   # remove clap + hex
└── src/
    ├── cli.rs   # DELETE
    └── lib.rs   # remove `pub mod cli;`
```

## Verification Division
Pure deletion — no logic to author, so no codex dispatch. Claude deletes + verifies via
build/test/clippy + grep (the verification division exists to prevent self-verified *authored logic*;
a deletion has none). Existing safety tests are the behavior baseline.

## Phasing
Single user story: delete + drop deps + verify + merge.
