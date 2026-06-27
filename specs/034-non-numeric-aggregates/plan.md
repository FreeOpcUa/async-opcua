# Implementation Plan: Non-numeric (any-value-type) HistoryRead aggregates

**Branch**: `034-non-numeric-aggregates` | **Date**: 2026-06-27 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `specs/034-non-numeric-aggregates/spec.md`

## Summary

Make the OPC UA Part 13 aggregates whose definition depends on status / presence / value-equality —
**Count** (§5.4.3.21), **NumberOfTransitions** (§5.4.3.24), the status/quality set
(DurationGood/Bad, PercentGood/Bad, WorstQuality/2), and the state-duration pair
(DurationInStateZero/NonZero, §5.4.3.22/23) — work for ANY `Variant` value type, not just numeric.
Today they route through `variant_to_f64()` (`aggregates/engine.rs:111`), so a Boolean/String/Enum
source reports Count 0 and NumberOfTransitions 0. Technical approach: split the type-independent
aggregates off the numeric filter, reusing the existing `AggregateInput` engine, `state_regions`
machinery, and Part-13 status helpers — no new engine, no change to the numeric-magnitude aggregates.
NumberOfTransitions is additionally **corrected**: its current zero-crossing logic is wrong even for
numeric sources (Part 13 defines a transition as any value differing from the previous non-Bad value).

## Technical Context

**Language/Version**: Rust (edition 2021), workspace MSRV per repo
**Primary Dependencies**: `async-opcua-server` (aggregates engine), `async-opcua-types` (`Variant`,
`DataValue`, `StatusCode`); no new dependencies
**Storage**: N/A — operates on in-memory `AggregateInput` slices fed from any history backend
**Testing**: `cargo test` — `async-opcua-server` unit tests in `aggregates/` + the
`async-opcua-server/tests/` aggregate suites; existing oracle-grounded vectors
**Target Platform**: Linux/any (library)
**Project Type**: Rust library/server (single workspace)
**Performance Goals**: No regression; the type-independent paths are O(n) over interval points, same
as today
**Constraints**: No panic on any `Variant`/null/Bad input (Constitution IV); builds under
`--no-default-features` and `--all-features`; numeric results unchanged except the corrected
NumberOfTransitions
**Scale/Scope**: One module (`async-opcua-server/src/aggregates/engine.rs`) + its tests; ~6 aggregate
functions touched, ~2 new helpers

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **I. Correctness Over Completion (NON-NEGOTIABLE)**: PASS — this feature is itself a correctness fix
  (Count/NumberOfTransitions return wrong answers today). Grounded against Part 13 §5.4.3.21/22/24 via
  the OPC UA reference; the NumberOfTransitions numeric bug is fixed, not papered over.
- **II. Do It Right Once**: PASS — reuses the engine + `state_regions` + status helpers; the only
  structural change is extending `StateRegion` with a value-type-aware zero-state classification (US4)
  and a type-independent "good point" path (US1). No parallel evaluation engine.
- **III. Individual Task Discipline**: PASS — tasks.md will be one atomic task per line, each citing
  the Part 13 §; codex implements one per dispatch.
- **IV. Security Is Paramount**: PASS — aggregate inputs come from historized values that can be
  attacker-influenced; every path is made type-total (no `unwrap`/panic on non-numeric, null, or Bad).
  FR-008 + SC-006 enforce no-panic across all `Variant` types.
- **V. Leave It Better Than You Found It**: PASS — US3 adds lock-in coverage for the already-working
  status aggregates so a future refactor can't silently re-break them; the NumberOfTransitions fix
  removes a latent numeric bug.

**Result**: No violations. Proceed.

## Project Structure

### Documentation (this feature)

```text
specs/034-non-numeric-aggregates/
├── plan.md              # This file
├── research.md          # Phase 0 — decisions D1–D6
├── data-model.md        # Phase 1 — AggregatePoint / ZeroState / classification
├── quickstart.md        # Phase 1 — reading aggregates of a Boolean source
├── contracts/
│   └── aggregates.md    # Phase 1 — per-aggregate type-independence contract
└── tasks.md             # Phase 2 (/speckit-tasks)
```

### Source Code (repository root)

```text
async-opcua-server/src/aggregates/
└── engine.rs            # variant_to_f64 (111), good_numeric_points (325), state_regions (358),
                         # agg_count (1022), agg_number_of_transitions (1153),
                         # agg_duration_in_state_zero/non_zero (1143), agg_duration_good/bad,
                         # agg_percent_good/bad, agg_worst_quality/2 — the functions this feature touches

async-opcua-server/tests/
└── <aggregate test binaries>   # numeric oracle vectors (must stay green except NumberOfTransitions)

async-opcua/tests/integration/  # optional e2e HistoryRead aggregate over a non-numeric historized var
```

## Complexity Tracking

No constitution deviations. The single added concept is a `ZeroState` classification on `StateRegion`
(replacing the numeric-only `Option<f64>` zero check) — justified because Part 13 DurationInState* is
defined on a value-state, not a magnitude, and the Boolean case has no f64 representation.
