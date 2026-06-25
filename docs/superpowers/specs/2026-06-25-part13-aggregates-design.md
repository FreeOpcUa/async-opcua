# Full Part-13 Aggregate Set — Design

Date: 2026-06-25
Status: draft (awaiting user review)

## Purpose

async-opcua's HistoryRead `ReadProcessed` engine implements only **4** of Part 13's ~37 standard
aggregates: TimeAverage (2343), Minimum (2346), Maximum (2347), StandardDeviationSample (11426).
A conformant HA client requesting any other standard aggregate gets `BadAggregateNotSupported`.
This design extends coverage to the full practical Part-13 set, grounded in OPC 10000-13 §5.4 and
validated against an independent oracle (the MIT `AggregateTester` dataset + the per-aggregate
§5.4.3 worked-example tables).

This is the "go broad" scope chosen 2026-06-25: includes the interpolation/bounding family and the
"2" (SimpleBounds) variants, not just the easy in-interval math. It is therefore a **multi-PR**
effort, architecture-first.

## The blocker today: the engine can't see bounds or config

Current data flow (`aggregates/middleware.rs` → `history/backend.rs::read_processed` →
`aggregates/engine.rs::calculate_aggregate`):

- `read_processed` reads raw values **only within `[start, end]`** (`read_raw_modified(..., return_bounds=false)`),
  partitions into intervals, and hands each interval's strictly-inside `&[&DataValue]` to
  `calculate_aggregate(values_in_interval, aggregate_type, interval_start, interval_end)`.
- `calculate_aggregate` has **no access to** (a) the raw point just before an interval / just after it
  (the *bounding values*), or (b) the `AggregateConfiguration`.

Most Part-13 aggregates beyond the current 4 need one or both:
- **Interpolated/Simple bounding values** — Interpolative, Total, TimeAverage's start bound, the whole
  "2" family, Start/EndBound, Delta-at-bounds. Per §5.4.2 an aggregate's region is bounded by the value
  *at* the interval start (interpolated or simple) and the next interval's start.
- **`AggregateConfiguration`** (§4.2.1.2 / passed in `ReadProcessedDetails.aggregateConfiguration`):
  `TreatUncertainAsBad` (Bool), `PercentDataBad` (Byte), `PercentDataGood` (Byte),
  `UseSlopedExtrapolation` (Bool). These drive the StatusCode calculus and bound interpolation.

So the foundation is a **data-flow + engine refactor**; new aggregates layer on top.

## Architecture

### 1. Carry bounds + config to the engine

- `read_processed` (default backend impl) reads raw with **`return_bounds = true`** so the result
  includes the value immediately before `start` and after `end`. Keep the existing
  read-all-then-partition shape; partitioning gains access to the out-of-interval bounding points.
- Thread `AggregateConfiguration` from `ReadProcessedDetails` through
  `read_processed_aggregates` → `HistoryStorageBackend::read_processed` → the engine. This adds a
  parameter to the `read_processed` trait method (the only signature break; all impls updated). When
  `useServerDefaults` is set, resolve against a server-default `AggregateConfiguration`.

### 2. Engine: one calculator per aggregate, uniform contract

Replace the single `calculate_aggregate` match with a dispatch over an `AggregateInput`:

```rust
pub struct AggregateInput<'a> {
    pub values: &'a [&'a DataValue],   // raw points inside the interval, time-sorted
    pub prior: Option<&'a DataValue>,  // last raw point at/before interval_start (the start bound source)
    pub next: Option<&'a DataValue>,   // first raw point after interval_end (for interpolation/extrapolation)
    pub interval_start: DateTime,
    pub interval_end: DateTime,
    pub config: &'a AggregateConfiguration,
}
```

Each aggregate is a function `fn(&AggregateInput) -> DataValue` returning value **and** the correct
StatusCode and timestamp, because Part-13 specifies these *per aggregate* (each §5.4.3.x "summary
table" gives Data Type, **Use Bounds** = None/Simple/Interpolated, **Timestamp** = StartTime or
ActualTime, and a **StatusCode Calculation** method). Dispatch by the aggregate NodeId numeric id
(named consts, sourced from the vendored `NodeIds.csv` — the same authoritative source that fixed the
earlier NodeId bug). Unknown id → `BadAggregateNotSupported` (unchanged).

### 3. Shared primitives (built once, reused across aggregates)

- **Interpolated bound** at a time `t`: interpolate between `prior` and the first in-interval point (or
  use `UseSlopedExtrapolation` / hold-last per §5.4.2.6 when there's no following point). Quality of an
  interpolated bound is `Uncertain` per §5.4.2.
- **Simple bound** at `t`: the `prior` raw value held constant (no interpolation) — used by the "2"
  family.
- **Status calculus** (§5.4.2.4): compute the % of the interval covered by Good vs Bad/Uncertain data
  (honoring `TreatUncertainAsBad`), compare against `PercentDataGood`/`PercentDataBad`, and emit
  `Good`/`Uncertain`/`Bad` plus the aggregate "Calculated"/"Interpolated"/"Partial"/"Raw" info bits the
  per-aggregate tables require. This is the single most error-prone piece → its own well-tested module.

## Phased roadmap (one PR per phase; subscription/HA + alarms suites green each step)

- **Phase A — refactor foundation (no new client-visible aggregates).** Introduce `AggregateInput`,
  the per-aggregate dispatch, `return_bounds=true`, and `AggregateConfiguration` threading + the
  status-calculus + bound primitives modules. Re-implement the existing 4 aggregates on the new
  structure with **no behavior regression** (the `aggregates_tests.rs` lock-in tests stay green).
- **Phase B — simple in-interval aggregates** (no bounds): Count 2352, Average 2342, Range 2350,
  Delta 2359, MinimumActualTime 2348, MaximumActualTime 2349, VarianceSample 11428,
  StandardDeviationPopulation 11427, VariancePopulation 11429, WorstQuality 2364.
  (AnnotationCount 2351 → `BadAggregateNotSupported` until annotation history exists; documented.)
- **Phase C — interpolated/bounded base** : Interpolative 2341, Total 2344, StartBound 11505,
  EndBound 11506, DeltaBounds 11507; sloped-extrapolation path. Exercises the interpolation primitive.
- **Phase D — the "2" (SimpleBounds) family**: TimeAverage2 11285, Minimum2 11286, Maximum2 11287,
  Range2, Total2, MinimumActualTime2 11305, MaximumActualTime2 11306, WorstQuality2 11292.
- **Phase E — status/duration aggregates**: DurationGood 2360, DurationBad 2361, PercentGood 2362,
  PercentBad 2363, DurationInStateZero 11307, DurationInStateNonZero 11308, NumberOfTransitions 2355.

Each phase registers its aggregates so the server advertises them (HistoryServerCapabilities
`AggregateFunctions` folder) — clients can discover what's supported.

## Testing (Claude authors; independent of the implementation)

- **Oracle:** the per-aggregate §5.4.3 worked examples (the spec gives canonical input series + expected
  outputs) transcribed as vectors, cross-checked against the MIT `AggregateTester` dataset
  (OPCFoundation Misc-Tools, "creates the Part-13 examples") where it covers the aggregate. Vendor any
  used data under `.../vectors/opcfoundation/` with PROVENANCE, per the conformance-tester convention.
- **Per aggregate:** value, StatusCode, and timestamp asserted against the oracle for: a normal
  interval, an interval with a Bad/Uncertain raw value (status calculus + `TreatUncertainAsBad`), an
  empty interval (`BadNoData`), and a boundary case (bound interpolation vs SimpleBounds for the "2"
  twin).
- **No regression:** existing `aggregates_tests.rs` + `hda.rs` + HistoryRead interop stay green every
  phase. The 4 original aggregates keep identical outputs after Phase A.
- **Grounding policy:** every aggregate's semantics confirmed via the `opc-ua-reference` MCP before
  implementing (the earlier aggregate NodeId bug was self-consistent and slipped own-tests — independent
  oracle + spec grounding is the guard). codex implements; Claude authors the oracle tests.

## Out of scope

- Annotation history (AnnotationCount stays `BadAggregateNotSupported`).
- Aggregates over non-numeric/complex data beyond what the current `variant_to_f64` supports.
- HistoryUpdate of aggregates; aggregate subscriptions (MonitoredItem AggregateFilter) — read-only HA.

## Provenance

Part-13 §4.2.1.2 (AggregateConfiguration), §5.2.2/5.2.3 (ReadProcessedDetails/AggregateFilter),
§5.4.2 (bounding/status calculus), §5.4.3.x (per-aggregate tables) grounded via the `opc-ua-reference`
MCP 2026-06-25. NodeIds from vendored `schemas/1.05/NodeIds.csv`. Builds on the conformance-tester
effort ([[conformance-tester-effort]]) where Phase 5 (#131) fixed the original aggregate NodeId bug.
