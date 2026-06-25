# Part-13 Aggregates — Phase E Plan (status/duration aggregates) — FINAL PHASE

> codex implements; Claude authors oracle tests. Scope-escape + `cargo fmt`; no-git guardrail.
> I run `cargo fmt --all` after each dispatch. Grounding: §5.4.3.22-24 (DurationInState*, NumberOfTransitions),
> §5.4.3.31-34 (DurationGood/Bad, PercentGood/Bad), §4.2.2.2; `scratchpad/phaseCDE-grounding.md`.
> Goal: the time-in-state aggregates, all built on one "segment the interval by held value/status
> (simple bounds)" helper. These complete the practical standard Part-13 set.

## Concept

Using SIMPLE bounds (stepped/held), the interval [interval_start, interval_end] is partitioned into
contiguous regions: the `prior` value/status is held from interval_start to the first in-interval raw
point; each raw point's value/status is held until the next; the last is held to interval_end. Each
region has a duration, a held StatusCode, and a held numeric value. The Phase-E aggregates sum/count
over these regions.

## Ids + value (grounded)

| Fn | Id | Result | Value |
|---|---|---|---|
| `agg_duration_good` | 2360 | Double (ms) | total region time whose held status is Good |
| `agg_duration_bad` | 2361 | Double (ms) | total region time whose held status is Bad |
| `agg_percent_good` | 2362 | Double (0..100) | DurationGood / interval_duration × 100 |
| `agg_percent_bad` | 2363 | Double (0..100) | DurationBad / interval_duration × 100 |
| `agg_duration_in_state_zero` | 11307 | Double (ms) | total region time whose held value == 0 |
| `agg_duration_in_state_non_zero` | 11308 | Double (ms) | total region time whose held value != 0 |
| `agg_number_of_transitions` | 2355 | Int32 | count of zero↔non-zero changes across the in-interval (+prior) values |

Result StatusCode for all: Good, Calculated (use `aggregate_quality`/`Good`; the full §5.3
PercentDataGood/Bad → Good/Uncertain/Bad result-status calculus is documented-deferred — `// ponytail:`).
Duration unit = milliseconds (matches `processing_interval`); confirm vs §5.4.3.31.

---

### Task E1 (codex): the segment helper + 7 aggregates

**File:** `async-opcua-server/src/aggregates/engine.rs`.

Ground via the public reference (§5.4.3.22 DurationInStateZero, §5.4.3.23 DurationInStateNonZero,
§5.4.3.24 NumberOfTransitions, §5.4.3.31 DurationGood, §5.4.3.32 DurationBad, §5.4.3.33 PercentGood,
§5.4.3.34 PercentBad) before coding. Add const ids (AGG_DURATION_GOOD=2360, AGG_DURATION_BAD=2361,
AGG_PERCENT_GOOD=2362, AGG_PERCENT_BAD=2363, AGG_NUMBER_OF_TRANSITIONS=2355,
AGG_DURATION_IN_STATE_ZERO=11307, AGG_DURATION_IN_STATE_NON_ZERO=11308).

1. Segment helper (private):
   ```rust
   struct StateRegion { duration_ms: f64, status: StatusCode, value: Option<f64> }
   /// Partition [interval_start, interval_end] into held regions via simple bounds.
   fn state_regions(input: &AggregateInput) -> Vec<StateRegion>
   ```
   Build "knots" in time order: start at `interval_start` holding the `prior` (its status + numeric
   value) if present; then each in-interval raw value (use `input.values`, NOT only good — we need
   status per region, so map each to (timestamp, status = v.status.unwrap_or(Good), value =
   variant_to_f64(v))); a final boundary at `interval_end`. Each consecutive knot pair → a region with
   `duration_ms = (next_time - this_time) in ms` (ticks/1e4), the held knot's status + value. Clamp
   times to [interval_start, interval_end]; skip in-interval points outside it; if `prior` is None the
   leading region before the first point has no defined state → omit it (its time is uncounted; that is
   the "No Start Bound" reading — `// ponytail:` note). Return empty for zero/backward interval.
2. Aggregates:
   - `agg_duration_good` = sum region.duration_ms where `region.status.is_good()` → Double (ms).
   - `agg_duration_bad` = sum where `region.status.is_bad()` → Double.
   - `agg_percent_good` = duration_good / total_interval_ms × 100 (total = (interval_end-interval_start)
     in ms); if total <= 0 → bad_no_data. Double.
   - `agg_percent_bad` = duration_bad / total_interval_ms × 100.
   - `agg_duration_in_state_zero` = sum region.duration_ms where `region.value == Some(0.0)` → Double.
   - `agg_duration_in_state_non_zero` = sum where `region.value` is Some and != 0.0 → Double.
   - `agg_number_of_transitions` = walk the in-interval (+prior) numeric values in time order; count
     adjacent pairs where `(a == 0.0) != (b == 0.0)` (a zero↔non-zero change). Result Variant::Int32.
     Empty/one value → 0. (Ground §5.4.3.24 — non-Good values are excluded from the count.)
   Each: result timestamp = interval_start, status Good (Calculated). Empty regions / no data →
   bad_no_data for the duration/percent ones; NumberOfTransitions → Int32(0).
3. Dispatch arms per id.

**Acceptance:** `cargo build -p async-opcua-server` clean (no warnings); `cargo test -p async-opcua-server --lib` + `aggregates_tests` green (unedited). `cargo fmt`. No git. SCOPE-ESCAPE: stay in engine.rs; if duration units or the "No Start Bound" region handling is ambiguous, implement the reading above, `// ponytail:`, report. One concern only.

---

### Task E.T (Claude): oracle tests

Through `compute_processed_intervals`. Interval [12:00:00, 12:00:10) (10000 ms). Series chosen so the
regions are exact:
- Status mix: prior Good@(-)=1.0, then a Bad value at 12:00:04, then Good at 12:00:07. Regions:
  [0,4) Good (4000ms), [4,7) Bad (3000ms), [7,10) Good (3000ms). DurationGood=7000, DurationBad=3000,
  PercentGood=70, PercentBad=30.
- Zero/non-zero: values 0@start-region, 5@12:00:04, 0@12:00:08 → DurationInStateZero/NonZero exact ms;
  NumberOfTransitions = count of 0↔non-0 changes (e.g. 0→5→0 = 2).
- Empty interval → duration/percent BadNoData; NumberOfTransitions Int32(0).
Hand-computed, cross-checked vs §5.4.3.22-24/31-34 (MCP). Full gate: lib + aggregates_tests +
hda/history; clippy default + no-default; no-default build; fmt.

---

## After Phase E (final follow-up, separate small PR)

Advertise the supported aggregate set in `HistoryServerCapabilities/AggregateFunctions` (discovery) —
now that the full set exists. Document the remaining deferrals: the §5.3 PercentDataGood/Bad result-
status calculus, sloped interpolation + per-variable `Stepped`, Bad-region reduction in TimeAverage,
AnnotationCount (needs annotation history).

## Self-review

- **Coverage:** 7 status/duration aggregates on one segment helper (E1) + oracle tests (E.T). Completes
  the practical Part-13 set (~37 standard aggregates: AnnotationCount deferred; the rest implemented).
- **Risk:** duration unit (ms — E.T pins it); "No Start Bound" leading-region omission (documented);
  NumberOfTransitions zero-definition (E.T's 0→5→0 = 2 case is the guard). codex grounds via reference;
  Claude's MCP-grounded oracle tests are the independent check.
