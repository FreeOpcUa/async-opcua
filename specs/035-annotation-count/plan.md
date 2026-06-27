# Implementation Plan: AnnotationCount aggregate + Annotations Property

**Branch**: `035-annotation-count` | **Date**: 2026-06-27 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `specs/035-annotation-count/spec.md`

## Summary

Implement the **AnnotationCount** aggregate (Part 13 §5.4.3.20, i=2351) — the last standard aggregate
the engine deliberately omits — by feeding the already-stored annotation history into the aggregate
engine, plus an opt-in **Annotations Property** (Part 11 §5.1.2) for discoverability. AnnotationCount
returns, per processing interval, the `Int32` count of annotations whose timestamp falls in
`[interval_start, interval_end)`. The annotation data is loaded through the existing
`read_annotations` backend method (which returns all annotations for a node when called with empty
`req_times`); no new store. The 34 existing aggregates are untouched.

## Technical Context

**Language/Version**: Rust (edition 2021), workspace MSRV
**Primary Dependencies**: `async-opcua-server` (aggregate engine + in-memory history),
`async-opcua-history-sqlite` (sqlite backend, behind the `sqlite` feature), `async-opcua-types`
(`DataValue`, `Annotation`, `DateTime`, `Variant`); no new dependencies
**Storage**: existing annotation stores — in-memory `InMemoryDataHistory.annotation_values` and the
SQLite `historical_annotations` table; reused, not extended
**Testing**: `cargo test` — `async-opcua-server` aggregate unit/integration tests + sqlite parity tests
**Target Platform**: Linux/any (library)
**Project Type**: Rust library/server (single workspace)
**Performance Goals**: No regression for the 34 other aggregates — annotations are loaded ONLY when the
requested aggregate is AnnotationCount
**Constraints**: No panic on any input (Constitution IV); builds under `--no-default-features` and
`--all-features`; other aggregates' results unchanged
**Scale/Scope**: `aggregates/engine.rs` (the aggregate + AggregateInput field + compute signature),
TWO `read_processed` impls (server trait default + sqlite override), `monitored_item.rs` (one
AggregateInput construction site), + an Annotations-Property helper; ~3 aggregate/engine functions and
2 backend wirings

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **I. Correctness Over Completion (NON-NEGOTIABLE)**: PASS — AnnotationCount semantics grounded in
  Part 13 §5.4.3.20 (count of annotations in interval, Int32, Good/Calculated, StartTime, no bounds/
  interpolation) via the OPC UA reference.
- **II. Do It Right Once**: PASS — reuses the annotation stores, `read_annotations`, the
  `AggregateInput` engine, and `compute_processed_intervals`; the only structural change is one additive
  `AggregateInput` field + an `annotation_times` parameter threaded through the two `read_processed`
  impls. No second annotation store, no parallel engine.
- **III. Individual Task Discipline**: PASS — tasks.md will be one atomic task per line, each citing the
  Part 13 / Part 11 §; codex implements one per dispatch.
- **IV. Security Is Paramount**: PASS — annotation data is attacker-influenced (written via HistoryUpdate
  by clients). The count path is total and panic-free: a missing/unsupported annotation read yields an
  empty set → count 0 (FR-007); the field is a plain timestamp slice; no unwrap on remote data.
- **V. Leave It Better Than You Found It**: PASS — completes the standard aggregate set and removes the
  "intentionally unsupported" carve-out + its negative tests, replacing them with positive coverage.

**Result**: No violations. Proceed.

## Project Structure

### Documentation (this feature)

```text
specs/035-annotation-count/
├── plan.md              # This file
├── research.md          # Phase 0 — decisions D1–D6
├── data-model.md        # Phase 1 — AggregateInput.annotations / annotation timestamps
├── quickstart.md        # Phase 1 — reading AnnotationCount + the Annotations Property
├── contracts/
│   └── annotation-count.md  # Phase 1 — the aggregate + load-path contract
└── tasks.md             # Phase 2 (/speckit-tasks)
```

### Source Code (repository root)

```text
async-opcua-server/src/aggregates/engine.rs
  - AggregateInput (L271): add `annotations: &'a [DateTime]`
  - compute_processed_intervals (L1450): add `annotation_times: &[DateTime]` param; slice per interval
  - agg_annotation_count + const AGG_ANNOTATION_COUNT=2351 + dispatch case (L~1417) + SUPPORTED_AGGREGATE_IDS (L45)
async-opcua-server/src/history/backend.rs
  - read_processed (trait default, L84/L117): load annotations when aggregate == AnnotationCount, pass timestamps
async-opcua-history-sqlite/src/backend.rs
  - read_processed (OVERRIDE, L647/L680): same annotation load + pass-through  ← do not miss this second impl
async-opcua-server/src/subscriptions/monitored_item.rs (L605)
  - AggregateInput construction: pass `annotations: &[]` (monitored-item aggregates have no annotation history)
async-opcua-server/tests/aggregates_tests.rs
  - flip the "AnnotationCount unsupported" assertions (L45-68 / L700-705 / L1135-1140) to supported + counts
async-opcua-server/src/<address space helper> + tests
  - US2: opt-in Annotations Property (HasProperty → Annotations Variable, DataType Annotation i=891)
```

## Complexity Tracking

No constitution deviations. The only cross-cutting concern is that `read_processed` exists in TWO
places (the trait default and the sqlite override) — both must load annotations for AnnotationCount,
and the sqlite path is exercised only under the `sqlite` feature. This is called out explicitly so the
second impl is not missed (the likely source of a silent "works in-memory, 0 on sqlite" bug).
