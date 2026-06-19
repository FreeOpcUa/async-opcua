# Implementation Plan: Embedded Hardening & Allocation Follow-ups

**Branch**: `010-embedded-hardening-allocation` | **Date**: 2026-06-19 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/010-embedded-hardening-allocation/spec.md`

## Summary

Close the remaining hardening and allocation gaps documented in the 009 embedded audit (§5/§6) and the 2026-06-19 sweep, across three prioritized stories: (P1) make every remote-reachable path panic-free and bounded (panic-surface sweep, codec `max_message_size` enforcement, decode-recursion depth bound, GDS registry caps); (P2) cut steady-state allocation churn (pool the event-notification Vec; reduce per-request dispatch allocation); (P3) ship embedded deployment guidance and copy-free decode. Each change preserves wire behavior for well-behaved peers (byte-identical), is verified by the existing 98-test integration suite, and — where it claims an allocation reduction — carries a before/after measurement from the counting-allocator harness established in the publish-path work.

## Technical Context

**Language/Version**: Rust (edition 2021, MSRV per workspace; toolchain 1.96 in CI)
**Primary Dependencies**: tokio, bytes, the async-opcua workspace crates (`-types`, `-core`, `-crypto`, `-server`, `-client`, `-nodes`, `-pubsub`); fuzz via `cargo-fuzz`/libfuzzer; clippy lints
**Storage**: N/A (protocol library; in-memory state only)
**Testing**: `cargo test` (unit + the `async-opcua` integration suite), `#[ignore]` allocation-baseline harness (counting global allocator), `cargo fuzz` targets, `cargo clippy -D warnings`
**Target Platform**: embedded **Linux** incl. musl (aarch64), and general Linux/Windows; `no_std`/bare-metal explicitly out of scope
**Project Type**: library workspace (single repo, multiple crates)
**Performance Goals**: reduce steady-state per-publish and per-request allocation count/bytes vs the pre-feature baseline; constant (pooled) per-tick allocation on the event path; copy-free string/bytestring/array decode where the buffer permits
**Constraints**: no panic/abort on any remote-reachable path; all attacker-influenced allocations and recursion bounded; encoded responses/notifications/republished notifications byte-for-byte unchanged for well-behaved peers; `verify-clean-codegen` must stay green (no edits to generated code)
**Scale/Scope**: ~482k LOC workspace (~138k hand-written); 8 enumerated backlog items mapped to FR-001..010

## Constitution Check

*This feature is a direct expression of the constitution; gates pass.*

- **I. Correctness Over Completion** — PASS. Each change is verified (regression tests, byte-equality proofs, full integration suite) before being called done; architectural items (M2/M4) are measure-first and may be staged rather than rushed.
- **II. Do It Right Once** — PASS. The panic sweep fixes root causes (Result, not `#[allow]` blanket); pooling reuses the proven 2b pattern; no scaffolding left behind.
- **III. Individual Task Discipline** — PASS. tasks.md keeps one task per line; production code is dispatched to codex **one task per dispatch**; commit cadence is one commit per user story.
- **IV. Security Is Paramount** — PASS (this feature's core). It removes remote-reachable panics, bounds attacker-influenced allocation/recursion, and caps server-side growth; fail-closed/no-secret-logging unaffected.
- **V. Leave It Better Than You Found It** — PASS. In-scope adjacent cleanup (misleading comments, weak tests) is encouraged; no degradation of structure/coverage/docs.

**No violations. No Complexity Tracking entries required.**

## Project Structure

### Documentation (this feature)

```
specs/010-embedded-hardening-allocation/
├── spec.md
├── plan.md            # this file
├── research.md        # Phase 0 — decided approach per item
├── data-model.md      # Phase 1 — entities (limits, registries, pools, buffer ownership)
├── contracts/         # Phase 1 — public-API surface changes (library "contracts")
│   └── api-surface.md
├── quickstart.md      # Phase 1 — how to verify (harness, fuzz, integration)
└── checklists/
    └── requirements.md
```

### Source Code (repository root) — crates touched per story

```
async-opcua-types/        # FR-003 recursion depth in DecodingOptions; FR-007 zero-copy decode; FR-001 panic sweep
async-opcua-core/         # FR-002 codec max_message_size; FR-001 panic sweep; allocation harness reuse
async-opcua-crypto/       # FR-001 panic sweep
async-opcua-server/       # FR-004 GDS caps; FR-005 event-Vec pool; FR-006 per-request dispatch
async-opcua-client/       # FR-001 panic sweep (decode/transport)
fuzz/                     # FR-001 panic-hunting fuzz targets/corpus
docs/setup.md             # FR-008 embedded runtime + size-optimized build profile
Cargo.toml (workspace)    # FR-008 size-optimized profile; clippy lint config
```

**Structure Decision**: Existing single library workspace; no new crates. Changes are localized per crate as mapped above.

## Phase 0: Research

See [research.md](./research.md). Most approaches are pre-decided by the audit/sweep; research focuses on the two architectural items (M2 dispatch, M4 zero-copy decode) and on the panic-sweep mechanics (lint scoping + fuzz). No unresolved `NEEDS CLARIFICATION`.

## Phase 1: Design & Contracts

- [data-model.md](./data-model.md) — the configurable limits, the bounded registry, the notification pools, and the shared receive-buffer ownership, with their validation/overflow rules.
- [contracts/api-surface.md](./contracts/api-surface.md) — the public-API-visible changes (new `DecodingOptions` depth field + default; GDS cap config; any signature changes), each constrained to additive/non-breaking where possible and byte-compatible on the wire.
- [quickstart.md](./quickstart.md) — verification recipe: run the allocation baseline harness, the fuzz pass, the integration suite, and the byte-equality checks.

## Phase 2: Implementation Approach (preview; tasks generated by /speckit-tasks)

Per-story, smallest-blast-radius first; production code via codex one task at a time, verified directly:
- **US1 (P1)**: FR-002 codec guard (small) → FR-003 recursion bound → FR-004 GDS caps → FR-001 panic sweep (largest; lint + fuzz). Each with regression tests; SC-001 fuzz pass gates the story.
- **US2 (P2)**: FR-005 event-Vec pool (extends 2b) → FR-006 per-request dispatch (measure-first, may stage). Each with before/after allocation numbers (SC-003/SC-004) and byte-equality (SC-005).
- **US3 (P3)**: FR-008 docs → FR-007 zero-copy decode (measure-first, `-types`-wide; may stage). SC-006/SC-007.
