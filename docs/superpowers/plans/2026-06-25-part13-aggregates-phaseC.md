# Part-13 Aggregates — Phase C Plan (interpolated/simple bounds + bounded aggregates)

> codex implements; Claude authors oracle tests. Scope-escape + `cargo fmt` per brief; no-git guardrail.
> I run `cargo fmt --all` after each codex dispatch. Grounding (MCP, OPC 10000-13):
> `scratchpad/phaseC-grounding.md` + §5.4.3.4 (Interpolative), §5.4.3.6 (TimeAverage), §5.4.3.8 (Total),
> §5.4.3.30 (DeltaBounds), §5.4.3.2.2/2.3 (Simple-sloped / Interpolated-stepped worked examples), §3.1.8.
> Goal: build the bounding-value infrastructure deferred from Phase A and the aggregates that need it,
> and CORRECT TimeAverage(2343) to use interpolated bounds (currently it uses none — a conformance gap).

## Concepts (grounded)

- **prior / next bounds**: `prior` = last raw value at/before `interval_start`; `next` = first raw value
  after `interval_end`. Source: `read_raw_modified(return_bounds=true)`. Phase A left
  `AggregateInput.prior/next = None`; Phase C populates them.
- **Interpolated Bounding Value** (§3.1.8): value at a boundary via straight-line interpolation between
  the raw points bracketing it. For the END boundary with no following point → extrapolate: SLOPED
  (extend last slope) if `AggregateConfiguration.use_sloped_extrapolation`, else STEPPED (hold last).
  Interpolated bounds are flagged `Interpolated` (an info bit / quality nuance).
- **Simple Bounding Value**: the `prior` raw value held constant (no interpolation).
- **Stepped property**: TimeAverage's *interpolation* (between points) is stepped vs sloped per the
  Variable's `Stepped` attribute. We do not track per-variable Stepped → **default sloped (Stepped=false)**,
  the analog/DCS norm; documented as a future knob. (`use_sloped_extrapolation` is a separate knob, for
  the no-following-point case.)

## Aggregates added/corrected

| Fn | Id | Result | Bounds | Value |
|---|---|---|---|---|
| `agg_interpolative` | 2341 | same as source | Interpolated | interpolated value AT interval_start; before-data → Bad_NoData; after-data → extrapolated |
| `agg_total` | 2344 | Double | Interpolated | area under the interpolated curve over the interval (= TimeAverage × duration_ms/1000? — ground exact units; spec: "area") |
| `agg_start_bound` | 11505 | same as source | Simple | value at interval_start using simple bounds |
| `agg_end_bound` | 11506 | same as source | Simple | value at interval_end using simple bounds |
| `agg_delta_bounds` | 11507 | Double | Simple | EndBound − StartBound (both must be Good; signed; 0 if equal) |
| `agg_time_average` (CORRECT) | 2343 | Double | Interpolated | area under interpolated curve / interval duration (uses start+end interpolated bounds) |

---

### Task C1 (codex): bounding-value infrastructure (no new aggregate behavior)

**Files:** `async-opcua-server/src/aggregates/engine.rs`, `async-opcua-server/src/history/backend.rs`,
`async-opcua-history-sqlite/src/backend.rs`.

1. In BOTH `read_processed` impls, flip the raw read to `return_bounds = true` (currently `false`).
   This adds the at/before-start and after-end bounding raw values to `raw_values`; the existing
   per-interval filter (`ts >= interval_start && ts < interval_end`) still EXCLUDES them, so no existing
   aggregate changes. (Confirm: a value exactly at interval_start is in-range either way.)
2. In `compute_processed_intervals` (engine.rs), for each interval locate from the full sorted
   `raw_values`: `prior` = last value with `ts <= interval_start`; `next` = first value with
   `ts > interval_end`. Pass them into `AggregateInput { prior, next, .. }` (replace the `None`s).
   Keep all existing aggregates byte-identical (they ignore prior/next).
3. Add interpolation primitives (private, engine.rs or a new `aggregates/bounds.rs` module):
   - `interpolated_bound_at(boundary: DateTime, before: Option<&DataValue>, after: Option<&DataValue>, use_sloped: bool) -> Option<(f64, bool /*is_interpolated*/)>` — linear interpolation between
     before/after; if only `before` (no after): sloped needs two priors (return None/stepped if not
     available) else stepped = before's value; ground §3.1.8 for the exact no-after rule.
   - `simple_bound_at(boundary, before: Option<&DataValue>) -> Option<f64>` — before's value held.

**Acceptance:** `cargo build -p async-opcua-server -p async-opcua-history-sqlite` clean; existing
`aggregates_tests` (Phase A+B) + lib + sqlite green — NO behavior change (prior/next populated but only
the new aggregates in C2 read them). SCOPE-ESCAPE: stay in these 3 files; if `return_bounds=true` shifts
any existing aggregate result (it must not), STOP + report. `cargo fmt`.

---

### Task C2 (codex): the bounded aggregates + TimeAverage correction

**File:** `async-opcua-server/src/aggregates/engine.rs`.

Ground each via the public reference (§5.4.3.4/6/8/29/30) before coding. Add const ids
(AGG_INTERPOLATIVE=2341, AGG_TOTAL=2344, AGG_START_BOUND=11505, AGG_END_BOUND=11506,
AGG_DELTA_BOUNDS=11507) + a fn each + dispatch arms:
- **StartBound/EndBound**: `simple_bound_at(interval_start | interval_end, prior | last-in-interval-or-prior)`;
  result is the bound value as the source Variant; status Good/Calculated; no bound available → Bad_NoData.
- **DeltaBounds**: EndBound − StartBound as Double; both must be Good else Bad; signed.
- **Interpolative**: `interpolated_bound_at(interval_start, prior, first-in-interval-or-next, use_sloped)`;
  Same-as-Source; before-data (no prior, no in-interval) → Bad_NoData; status Good if no Bad skipped.
- **Total**: area under the interpolated line over the interval; Double; ground the exact unit/definition
  in §5.4.3.8 (relationship to TimeAverage × duration) and implement accordingly.
- **CORRECT TimeAverage(2343)**: replace `agg_time_average`'s body to integrate the area under the
  interpolated curve using the start interpolated bound, the in-interval points, and the end interpolated
  bound, divided by the interval duration (sloped interpolation default; Bad in-interval values reduce
  the region per §5.4.3.6). Keep returning Double at interval_start. This CHANGES results when bounds
  exist — that is the intended conformance fix.

**Acceptance:** builds clean; lib green. The Phase-A TimeAverage lock-in test will need new expected
values (Claude updates it in C.T — do NOT edit tests). SCOPE-ESCAPE: if the Total definition or the
TimeAverage region-reduction-on-Bad is ambiguous, STOP + report the spec wording you found. `cargo fmt`.

---

### Task C.T (Claude): oracle tests

- **Bounds primitives**: unit-test `interpolated_bound_at` / `simple_bound_at` against hand cases
  (interpolation midpoint, no-after sloped vs stepped, no-before → None).
- **StartBound/EndBound/DeltaBounds**: with a `prior` before the interval, assert the held value + the
  signed delta (incl. negative + zero).
- **Interpolative**: a `prior` at t<start and a point at t>start → interpolated value AT start matches the
  hand-computed line; before-data → Bad_NoData.
- **Total**: hand-computed area for a simple series.
- **TimeAverage CORRECTION**: build the §5.4.3.6 (or §5.4.3.2.2) worked-example series; assert the
  conformant interpolated-bounds result; UPDATE the Phase-A `test_calculate_aggregate_average`
  expectation to the conformant value (document the old vs new number + why). Ground the example numbers
  via the opc-ua-reference MCP.
- Full gate: lib + aggregates_tests + hda/history integration; clippy `--all-targets -D warnings`
  (default + no-default); no-default build; fmt.

---

## Self-review

- **Coverage:** bounds infra (C1), 5 new + 1 corrected aggregate (C2), oracle tests + TimeAverage
  lock-in update (C.T). The "2"/SimpleBounds family is Phase D; status/duration is Phase E.
- **Risk:** (1) `return_bounds=true` must not perturb existing aggregates (C1 scope-escape + Phase A/B
  tests guard); (2) TimeAverage behavior change — isolated to its fn, validated against the spec example,
  lock-in test updated with rationale; (3) Stepped/sloped default — documented assumption (sloped);
  (4) extrapolation no-after rule — grounded in §3.1.8.
- **codex grounds via the public reference; Claude's MCP-grounded oracle tests are the independent guard.**
