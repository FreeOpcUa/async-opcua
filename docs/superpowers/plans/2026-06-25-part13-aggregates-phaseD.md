# Part-13 Aggregates — Phase D Plan (the "2" / SimpleBounds family)

> codex implements; Claude authors oracle tests. Scope-escape + `cargo fmt`; no-git guardrail.
> I run `cargo fmt --all` after each dispatch. Grounding: §4.2.2.2 + §5.4.3.7/15/16/17/18 +
> `scratchpad/phaseCDE-grounding.md`. The "2" aggregates are the base aggregates that INCLUDE the
> Simple Bounding Values (the prior value projected to interval_start, held).

## Ids + value (grounded)

| Fn | Id | Result | Value vs base |
|---|---|---|---|
| `agg_time_average2` | 11285 | Double | = `stepped_area_seconds` area / duration (simple bounds, stepped) — identical to our Phase-C TimeAverage |
| `agg_total2` | 11304 | Double | = `stepped_area_seconds` area |
| `agg_minimum2` | 11286 | Double | min over { simple start bound (prior held), in-interval Good values } |
| `agg_maximum2` | 11287 | Double | max over the same candidate set |
| `agg_range2` | 11288 | Double | Maximum2 − Minimum2 |
| `agg_minimum_actual_time2` | 11305 | source Variant | the Minimum2 value with its timestamp (interval_start if the bound is the min) |
| `agg_maximum_actual_time2` | 11306 | source Variant | the Maximum2 value with its timestamp |
| `agg_worst_quality2` | 11292 | StatusCode | worst status over { prior, in-interval raw values } |

"No Start Bound" (no prior): treat the start bound as absent and compute from in-interval values only
(degrades to the base aggregate's candidate set). No data at all → Bad_NoData. (The finer Partial/
Interpolated status bits per §5.4.3.x are deferred — `// ponytail:`.)

---

### Task D1 (codex): implement the 8 "2" aggregates

**File:** `async-opcua-server/src/aggregates/engine.rs`.

Ground via the public reference (§5.4.3.7 TimeAverage2, §5.4.3.15/16 Minimum2/Maximum2, §5.4.3.17/18
Min/MaximumActualTime2, Range2, Total2, WorstQuality2) before coding. Add const ids:
AGG_TIME_AVERAGE2=11285, AGG_MINIMUM2=11286, AGG_MAXIMUM2=11287, AGG_RANGE2=11288,
AGG_WORST_QUALITY2=11292, AGG_TOTAL2=11304, AGG_MINIMUM_ACTUAL_TIME2=11305,
AGG_MAXIMUM_ACTUAL_TIME2=11306.

Use existing helpers: `stepped_area_seconds`, `good_numeric_points`, `simple_bound_at`,
`aggregate_result`, `aggregate_quality`, `bad_no_data`, `get_value_timestamp`, `variant_to_f64`.

- **agg_time_average2 / agg_total2**: delegate to the SAME `stepped_area_seconds` logic as the corrected
  TimeAverage / Total (factor a shared helper if `agg_time_average`/`agg_total` aren't already reusable;
  prefer calling a shared private fn over duplicating). time_average2 = area/seconds; total2 = area.
- **Candidate set** for Min2/Max2/ActualTime2: build a `Vec<(DateTime, f64)>` = the simple start bound
  (if `input.prior` numeric: `(interval_start, prior_value)`) PLUS `good_numeric_points` (time, value).
  If empty → bad_no_data.
- **agg_minimum2 / agg_maximum2**: min/max of the candidate values → Double via aggregate_result.
- **agg_range2**: max − min of candidates (Double); empty → bad_no_data.
- **agg_minimum_actual_time2 / agg_maximum_actual_time2**: the candidate with min/max value (ties:
  earliest time); result = that value as Double (the bound's source Variant isn't retained for the
  synthetic start point — use Double for consistency; `// ponytail:` note source-Variant retention),
  source_timestamp = the candidate's timestamp (interval_start when the bound wins).
- **agg_worst_quality2**: worst-severity status over `input.values` statuses PLUS `input.prior`'s status
  (if Some). Reuse the `quality_rank` ordering from agg_worst_quality. Result Variant::StatusCode,
  timestamp interval_start, status Good. No values and no prior → bad_no_data.

Add a dispatch arm per id. Do not change existing aggregates.

**Acceptance:** `cargo build -p async-opcua-server` clean (no warnings); `cargo test -p async-opcua-server --lib` + existing `aggregates_tests` green (unedited). `cargo fmt`. No git. SCOPE-ESCAPE: stay in engine.rs; if the §5.4.3.x "No Start Bound" treatment is ambiguous, implement the candidate-set reading above, `// ponytail:` the assumption, report.

---

### Task D.T (Claude): oracle tests

Through `compute_processed_intervals` with a raw series whose **prior** (before the interval) is the
extreme — proving the "2" variants include the simple bound where the base ones don't:
- Series prior = 5@(before), in-interval = [10, 20]. Minimum2 = 5 (vs base Minimum = 10); Maximum2 = 20;
  Range2 = 15; MinimumActualTime2 value 5 at interval_start; WorstQuality2 includes prior's status.
- TimeAverage2 == the corrected TimeAverage for the same series (both stepped/simple); Total2 == Total.
- No prior → Minimum2 degrades to the in-interval min; no data at all → BadNoData.
Grounded via the opc-ua-reference MCP. Full gate: lib + aggregates_tests + hda/history; clippy
default + no-default; no-default build; fmt.

## Self-review

- **Coverage:** 8 "2" aggregates (D1) + oracle tests (D.T). Status/duration set is Phase E.
- **Type consistency:** reuses Phase-C `stepped_area_seconds`/`simple_bound_at`/`quality_rank`; ids from
  NodeIds.csv. **Risk:** the simple-bound candidate inclusion is the crux — D.T's prior-is-extreme case
  is the guard; codex grounds via the reference, Claude's MCP-grounded tests are independent.
