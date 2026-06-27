# Phase 0 Research: Non-numeric (any-value-type) HistoryRead aggregates

All decisions grounded against the OPC UA Part 13 reference (verified via the reference MCP /
reference.opcfoundation.org) and the current engine in `async-opcua-server/src/aggregates/engine.rs`.

## D1 — Count: count Good-status points, not Good-numeric points

**Decision**: `agg_count` (engine.rs:1022) currently returns `good_numeric_points(input).len()`, which
filters BOTH status-good AND `variant_to_f64`-convertible. Replace the count with the number of points
whose StatusCode is Good (`status.is_none_or(is_good)`), regardless of value type. Add a small helper
(e.g. `good_status_point_count(input)`) rather than touching `good_numeric_points` (still used by the
numeric aggregates). The StatusCode-of-result computation (`percent_values_status`) is unchanged.

**Rationale**: Part 13 §5.4.3.21 — "Count retrieves a count of all the raw values within an interval.
If one or more raw values are non-Good, they are not included in the count." Nothing about value type.
For a numeric source, good-status points == good-numeric points, so numeric results are unchanged
(FR-007). A Good-status point with a null/Empty value is a degenerate raw value and is counted as a
raw point (documented edge case).

**Alternatives rejected**: making `variant_to_f64` return `Some` for non-numeric (pollutes the numeric
aggregates); a brand-new counting pass per type (unnecessary — status is the only filter).

## D2 — NumberOfTransitions: value-change vs previous non-Bad (CORRECTS numeric)

**Decision**: Rewrite `agg_number_of_transitions` (engine.rs:1153). Today it converts to f64 and counts
`(w0 == 0.0) != (w1 == 0.0)` — i.e. zero↔non-zero crossings. Replace with: order the in-interval
non-Bad points (plus the prior non-Bad value as the leading comparison point) by timestamp, and count
the number of consecutive pairs whose `Variant` VALUE differs (`!=`). `Variant` implements `PartialEq`,
so this is well-defined for Boolean, Enumeration, String, numeric, etc.

**Rationale**: Part 13 §5.4.3.24 — "returns a count of the number of transitions … a transition
occurred if … the earliest non-Bad value is different." A transition is ANY value change, not a
zero-crossing. The current logic is therefore **wrong even for numeric** (1→2→3 yields 0, should be 2).
This decision fixes both the non-numeric gap and the numeric bug. **Consequence**: existing numeric
NumberOfTransitions test vectors must be re-derived to the spec-correct values and the PR must call out
the behavior change (FR-007 carve-out, SC-004). Use `Variant` equality directly (no f64 round-trip),
which also avoids float-equality pitfalls.

**Alternatives rejected**: keeping zero-crossing semantics (non-conformant); comparing via f64 only
(loses non-numeric, keeps the float-equality smell).

## D3 — Status/quality aggregates are ALREADY type-agnostic → verify + lock in

**Decision**: DurationGood/DurationBad (`state_duration` on `region.status`), PercentGood/PercentBad
(`percent_values_status` / status counts), and WorstQuality/WorstQuality2 (iterate `value.status`) do
NOT depend on `variant_to_f64`. `state_regions` (engine.rs:358) builds each knot from EVERY point,
keeping `status` and only the *value* as `Option<f64>` — so the status-based aggregates already include
non-numeric points correctly. No code change; add integration/unit coverage that a non-numeric source
and a numeric source with the same per-point status pattern return equal results (Constitution V
lock-in).

**Rationale**: confirmed by reading `agg_duration_good/bad`, `agg_percent_good/bad`,
`agg_worst_quality/2` — all key on StatusCode. The risk is silent regression in a future refactor;
tests pin it.

## D4 — DurationInStateZero/NonZero: value-type-aware ZeroState on StateRegion

**Decision**: `StateRegion` (engine.rs:271) carries `value: Option<f64>`, and
`agg_duration_in_state_zero/non_zero` test `region.value == Some(0.0)` / `!= 0.0`. For a Boolean source
`value` is `None`, so both durations come out empty. Add a `ZeroState { Zero, NonZero, Unknown }`
classification computed from the original `Variant` at knot-construction time and store it on
`StateRegion` (alongside or instead of the `Option<f64>`):
- Boolean `false` → Zero; `true` → NonZero.
- Numeric `== 0` → Zero; `!= 0` → NonZero (preserves current numeric behavior exactly).
- Null / `Variant::Empty` → Zero (a "no value" state maps to zero-state).
- Other types (Guid, ByteString, String, DateTime, …) → Unknown → excluded from BOTH durations
  (documented: no natural zero; never panics).
`agg_duration_in_state_zero` includes `ZeroState::Zero` regions; `non_zero` includes
`ZeroState::NonZero`.

**Rationale**: Part 13 §5.4.3.22/23 define the aggregate on a "zero state" but do NOT define zero-state
for non-numeric — so this is a documented, defensible reasonable extension (spec is silent; we pick the
natural Boolean/numeric/null mapping and leave exotic types Unknown). Keeping the numeric `==0` rule
identical preserves numeric results (FR-007). `Unknown` excluded-from-both is the safe, panic-free
default.

**Alternatives rejected**: mapping every non-numeric to NonZero (would wrongly count Boolean `false`
time as non-zero); erroring on non-numeric (DurationInStateZero of a Boolean is a legitimate request).

## D5 — No panic on any value type (Constitution IV)

**Decision**: Every touched path is total over `Variant`: Count uses status only; NumberOfTransitions
uses `Variant: PartialEq` (no conversion); ZeroState classification is an exhaustive `match` with a
catch-all `Unknown`. No `unwrap`/`expect`/indexing on attacker-influenced data; empty intervals return
the existing empty-interval `DataValue` (Count 0 / Good, durations BadNoData) unchanged.

**Rationale**: aggregate inputs are historized values that can be attacker-influenced; SC-006 lists the
type matrix (Boolean/String/Enum/Guid/ByteString/DateTime/null/Bad) that must not panic.

## D6 — Backwards compatibility & feature gating

**Decision**: `variant_to_f64`, `good_numeric_points`, `simple_bounded_points`, and all numeric
aggregates are untouched, so numeric-magnitude results are byte-identical. The ONLY intended numeric
behavior change is the corrected NumberOfTransitions (D2). All changes are plain `Variant`/`StatusCode`
logic with no feature-gated types, so `--no-default-features` and `--all-features` both build (FR-010).

**Rationale**: the spec's backwards-compat requirement (FR-007) with the single, documented
NumberOfTransitions carve-out; no new dependencies or cfg gates introduced.
