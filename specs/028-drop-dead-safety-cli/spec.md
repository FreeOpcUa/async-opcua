# Feature Specification: Delete the Dead async-opcua-safety CLI Module

**Feature Branch**: `028-drop-dead-safety-cli`
**Created**: 2026-06-22
**Status**: Draft
**Input**: complexity-cuts backlog (ponytail-audit) — `async-opcua-safety/src/cli.rs` is a `clap`-based
CLI declared `pub mod cli;` inside the safety **library** crate, wired to no `[[bin]]` and referenced
nowhere in the workspace. Delete it and the dependencies it solely pulls in.

## Background & Problem Statement

`async-opcua-safety` is a library crate. Its `Spdu`/`SpduBuilder`/`SafetyValidator` types are used by
the server (`node_access.rs`). The `cli` submodule, however, is dead weight: `pub mod cli;` in
`lib.rs`, a `clap`-derived argument parser with no binary target to run it and no caller anywhere in
the workspace. It is the sole user of the crate's `clap` and `hex` dependencies, so every consumer of
`async-opcua-safety` compiles `clap` (a large dependency tree) for code that can never execute.

Deleting it removes 135 lines of dead code and two dependencies, with no effect on any real consumer.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Remove dead code and its dependencies (Priority: P1)

A maintainer building `async-opcua-safety` (or anything depending on it) no longer compiles a dead
CLI module or its `clap`/`hex` dependency trees; the live SPDU/validator API is unchanged.

**Why this priority**: It is the whole feature — a behavior-preserving deletion that shrinks the
build and the dead-code surface (Constitution V: leave it better).

**Independent test**: The crate and the workspace build and test green after the deletion; no
remaining reference to the `cli` module or to `clap`/`hex` in the crate; the public SPDU/validator
API is unchanged.

**Acceptance Scenarios**:

1. **Given** the safety crate, **When** `cli.rs` and `pub mod cli;` are removed, **Then**
   `cargo build`/`test -p async-opcua-safety` pass and the crate exposes the same SPDU/validator API.
2. **Given** the crate manifest, **When** the `clap` and `hex` dependencies (used only by `cli.rs`)
   are removed, **Then** the crate still builds (nothing else referenced them) and they no longer
   appear in the crate's dependency set.
3. **Given** the whole workspace, **When** built with `--all-features`, **Then** it compiles and
   clippy is clean (nothing in the workspace referenced `opcua_safety::cli`).

### Edge Cases
- Any hidden re-export of `cli` (none found) → build would fail and reveal it; the deletion is
  reverted if so.
- `hex`/`clap` used by a test or example in the crate (none found) → would fail to build and be caught.

## Requirements *(mandatory)*

### Functional Requirements
- **FR-001**: `async-opcua-safety/src/cli.rs` MUST be deleted and `pub mod cli;` removed from `lib.rs`.
- **FR-002**: The `clap` and `hex` dependencies MUST be removed from `async-opcua-safety/Cargo.toml`
  (verified to be used only by `cli.rs`).
- **FR-003**: The crate's public SPDU/validator API (`Spdu`, `SpduBuilder`, `SafetyValidator`,
  `SafetyError`, `crc`) MUST be unchanged.
- **FR-004**: The crate and the full workspace MUST build and test green; clippy clean under
  `-D warnings`.
- **FR-005**: No new dependency is added; the change is net-negative lines and dependencies.

## Success Criteria *(mandatory)*

### Measurable Outcomes
- **SC-001**: `cli.rs` (135 lines) and the `clap` + `hex` dependencies are gone; `cargo tree -p
  async-opcua-safety` no longer lists them.
- **SC-002**: `cargo test -p async-opcua-safety` and the workspace `--all-features` build pass;
  clippy clean.
- **SC-003**: The fork's full Actions CI is green.

## Assumptions
- The `cli` module has no consumers (verified: no `[[bin]]`, no `safety::cli`/`opcua_safety::cli`
  references in the workspace; `clap`/`hex` used only by `cli.rs`).
- PRs target the fork `occamsshavingkit/async-opcua`.

## Out of Scope
- The other ponytail-audit items (feature-gating pubsub/history; cutting the typed-method context
  variant) — those change the crate feature/public-API surface and are product/decision calls.
