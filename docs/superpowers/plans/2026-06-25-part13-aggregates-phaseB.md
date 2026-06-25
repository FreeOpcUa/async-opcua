# Part-13 Aggregates — Phase B Plan (simple in-interval aggregates)

> codex implements; Claude authors the oracle tests. Scope-escape + `cargo fmt` in every brief;
> no-git guardrail. I run `cargo fmt --all` after each codex dispatch.
> Design: `docs/superpowers/specs/2026-06-25-part13-aggregates-design.md`.
> Grounding table: `docs/superpowers/specs/2026-06-25-part13-phaseB-grounding.md` (per-aggregate
> Data Type / Use Bounds / Timestamp / Status from OPC 10000-13 §5.4.3, via the opc-ua-reference MCP).
> Goal: add the 10 "simple" aggregates that need only the Good raw values inside an interval (Use
> Bounds = None → `prior`/`next` stay unused). Each builds its OWN `DataValue` (result type + timestamp
> vary per the grounding table). The 4 Phase-A aggregates are untouched.

## Foundation in place (Phase A)

`engine.rs` has `AggregateInput { values, prior, next, interval_start, interval_end, config }`,
`dispatch_aggregate(aggregate_type, input)` (unknown id → `bad_aggregate_not_supported`),
`aggregate_preamble(input) -> Result<AggregatePreamble{quality, numeric_points}, DataValue>` (returns
the BadNoData DataValue on empty), and `aggregate_result(Option<f64>, quality, interval_start)` (Double
result helper). `compute_processed_intervals` drives per-interval dispatch.

## Aggregates to add (id → value; see grounding table for exact spec wording)

All operate on the interval's raw values; "Good raw value" = a value whose status severity is Good.
Quality of the result comes from `compute_aggregate_quality` over the interval's statuses (as the
existing 4 do) — the precise PercentGood/Bad calculus is Phase E.

| Fn | Id | Result Variant | Timestamp | Value |
|---|---|---|---|---|
| `agg_count` | 2352 | `Int32` | interval_start | number of Good raw values (0 allowed; **not** BadNoData when empty — Count of an empty interval is 0 with Good_Calculated unless before-start/after-end, see §5.4.3.21) |
| `agg_average` | 2342 | `Double` | interval_start | arithmetic mean of Good raw numeric values |
| `agg_range` | 2350 | `Double` | interval_start | max − min of Good raw numeric values |
| `agg_delta` | 2359 | `Double` | interval_start | last − first Good raw numeric value (time order) |
| `agg_minimum_actual_time` | 2348 | same as source value's Variant | **timestamp of the min value** | min Good raw value |
| `agg_maximum_actual_time` | 2349 | same as source value's Variant | **timestamp of the max value** | max Good raw value |
| `agg_variance_sample` | 11428 | `Double` | interval_start | sample variance (÷ n−1; needs ≥2) |
| `agg_std_dev_population` | 11427 | `Double` | interval_start | population std dev (÷ n; needs ≥1) |
| `agg_variance_population` | 11429 | `Double` | interval_start | population variance (÷ n; needs ≥1) |
| `agg_worst_quality` | 2364 | `StatusCode` | interval_start | worst-severity StatusCode among raw values in interval |

`AnnotationCount` (2351) is intentionally NOT added → falls through to `BadAggregateNotSupported`
(no annotation history). Document in a code comment.

---

### Task B1 (codex): implement the 10 aggregates + dispatch

**Files:** `async-opcua-server/src/aggregates/engine.rs` only.

1. Add `const` ids: `AGG_COUNT=2352, AGG_AVERAGE=2342, AGG_RANGE=2350, AGG_DELTA=2359,
   AGG_MINIMUM_ACTUAL_TIME=2348, AGG_MAXIMUM_ACTUAL_TIME=2349, AGG_VARIANCE_SAMPLE=11428,
   AGG_STANDARD_DEVIATION_POPULATION=11427, AGG_VARIANCE_POPULATION=11429, AGG_WORST_QUALITY=2364`.
2. Helpers (private):
   - `good_numeric_points(input) -> Vec<(DateTime, f64, &DataValue)>` — the interval values that are
     BOTH numeric (`variant_to_f64`) AND Good status (status severity Good; treat `None` status as Good,
     matching how `compute_aggregate_quality` treats `None`). Time-sorted (values arrive sorted; keep order).
   - reuse `aggregate_preamble`/`aggregate_result` for the Double aggregates where they fit.
3. One fn per aggregate (signatures `fn(&AggregateInput) -> DataValue`), per the table above:
   - **Count**: count Good raw values; result `Variant::Int32(n as i32)`, status `Good` (Calculated),
     `source_timestamp = interval_start`. An empty interval → `Int32(0)` Good (NOT BadNoData). Confirm
     the §5.4.3.21 "before start of data / after end of data" nuance via the MCP; if you can't determine
     before/after-data cheaply from the inputs available, return `Int32(0)` Good and add a `// ponytail:`
     comment noting the before/after-data refinement is deferred.
   - **Average/Range/Delta/VarianceSample/StdDevPopulation/VariancePopulation**: compute from
     `good_numeric_points`; on too-few-points return the BadNoData DataValue (reuse `bad_no_data`);
     wrap via `aggregate_result(Some(v), quality, interval_start)`.
   - **Min/MaximumActualTime**: pick the Good point with the min/max value; result = that point's
     ORIGINAL value Variant (clone the source `DataValue.value`), `source_timestamp =` that point's
     timestamp (`get_value_timestamp`), status = quality. On no Good points → `bad_no_data`. Ties:
     earliest timestamp; you may set the aggregate-bits MultipleValues if straightforward, else add a
     `// ponytail:` deferring the info bit.
   - **WorstQuality**: the worst-severity StatusCode among the interval's raw values; result
     `Variant::StatusCode(worst)`, status `Good` (Calculated), `source_timestamp = interval_start`.
     Empty interval → ground the spec (likely `Bad_NoData`); if unclear, `bad_no_data`.
4. Add a match arm per new id in `dispatch_aggregate`. Reuse existing const-id arms unchanged.

**Acceptance:** `cargo build -p async-opcua-server` clean (no warnings); `cargo test -p async-opcua-server --lib` green; the existing `aggregates_tests.rs` still passes (the 4 originals unchanged). SCOPE-ESCAPE: stay in `engine.rs`; if `Variant::StatusCode`/`Int32` construction or status-severity access differs from expectation, STOP + report. Run `cargo fmt`. **Ground each aggregate's exact semantics via the opc-ua-reference MCP (search_text OPC-10000-13 §5.4.3.x) before coding — do not infer from the table alone.**

---

### Task B.T (Claude): oracle-backed tests

**Files:** `async-opcua-server/tests/aggregates_tests.rs` (extend).

For a fixed canonical raw series (Good values at known timestamps within one interval, plus a variant
series including a non-Good value), assert each aggregate's **value, result Variant type, status, and
source_timestamp** against hand-computed expected results cross-checked against the §5.4.3 worked
examples (and the MIT AggregateTester dataset where it covers the aggregate):
- Count = N (Int32); empty interval → Int32(0) Good.
- Average = arithmetic mean; Range = max−min; Delta = last−first (incl. a negative case).
- Min/MaxActualTime: value AND that the source_timestamp equals the extreme's actual time (distinct
  from interval_start) — the test must prove the timestamp is the value's, not the interval's.
- VarianceSample / VariancePopulation / StdDevPopulation against hand-computed numbers; <2 points →
  BadNoData for the sample variant.
- WorstQuality returns the worst StatusCode (Variant::StatusCode) for a mixed-status interval.
- An empty interval → BadNoData for the value-bearing aggregates (Count/WorstQuality per spec).

**Acceptance:** new tests green; existing aggregates_tests + `hda.rs`/history integration green; clippy
`--all-targets -D warnings` (default + `--no-default-features`); `--no-default-features` build; fmt.

---

## Deferred (cross-phase, do ONCE at the end)

Advertising the supported set in the `HistoryServerCapabilities/AggregateFunctions` folder (discovery)
— do after all aggregate phases land, with the complete list, not incrementally.

## Self-review

- **Coverage:** 10 aggregates (grounding table) in B1; oracle tests in B.T. AnnotationCount deferred.
- **Type consistency:** Count→Int32, WorstQuality→StatusCode, ActualTime→source Variant+actual time,
  rest→Double — each fn builds its own DataValue (Phase A's dispatch allows this); `agg_*` naming + const
  ids consistent with Phase A.
- **Risk:** (1) "Good raw value" filtering (new `good_numeric_points` — B.T asserts a mixed-status case);
  (2) ActualTime timestamp must be the value's not the interval's (B.T asserts distinctness);
  (3) Count/WorstQuality empty-interval semantics (grounded in B1, asserted in B.T). codex grounds each
  via MCP; Claude's independent oracle tests are the guard (per [[codex-no-self-authored-tests]]).
