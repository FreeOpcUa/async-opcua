# Tasks: Delete the Dead async-opcua-safety CLI Module

- [X] T001 Confirm baseline: `cargo test -p async-opcua-safety` green on current code.
- [X] T002 Delete `async-opcua-safety/src/cli.rs`; remove `pub mod cli;` from `async-opcua-safety/src/lib.rs`.
- [X] T003 Remove the `clap` and `hex` dependencies from `async-opcua-safety/Cargo.toml` (sole-use by cli.rs, verified).
- [X] T004 Verify: `cargo test -p async-opcua-safety` green; `cargo tree -p async-opcua-safety` no longer lists clap/hex; workspace `cargo clippy --all-targets --all-features -- -D warnings` clean; `cargo fmt --check`.
- [ ] T005 Commit, push, PR to fork, merge when CI green; sync master.

## Analyze
Coverage: FR-001→T002; FR-002→T003; FR-003→T001/T004 (API unchanged, tests green); FR-004→T004;
FR-005→T003. SC-001→T004; SC-002→T004; SC-003→T005. No [NEEDS CLARIFICATION]; no constitution
violations; 0 critical/high findings. Deletion verified dead before the workflow.
