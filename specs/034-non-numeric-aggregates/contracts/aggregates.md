# Contract: type-independence of HistoryRead aggregates

All functions live in `async-opcua-server/src/aggregates/engine.rs`. Behaviour is specified per
aggregate; numeric inputs keep their current results except where noted.

## Count (§5.4.3.21) — US1

```text
agg_count(input) -> DataValue {
    value  = Int32(number of points with Good StatusCode in the interval, ANY value type)
    status = percent_values_status(input)   // unchanged
}
```
- Good-status points are counted regardless of `Variant` type (Boolean, String, Enum, …).
- Non-Good points are excluded (unchanged).
- Empty interval → Count 0, status Good (unchanged).
- Numeric source → identical to today (good-numeric == good-status when all values numeric).

## NumberOfTransitions (§5.4.3.24) — US2 (CORRECTS numeric)

```text
agg_number_of_transitions(input) -> DataValue {
    points = [prior non-Bad value (if any)] ++ in-interval non-Bad points, ordered by timestamp
    value  = Int32(count of consecutive pairs where points[i].Variant != points[i+1].Variant)
    status = percent_values_status(input)   // unchanged
}
```
- A transition = value differs from the previous non-Bad value (`Variant` `!=`), ANY value type.
- Numeric results CHANGE (zero-crossing → value-change); existing numeric vectors are re-derived.
- Empty interval → 0, status Good.

## DurationGood / DurationBad (§5.4.3.16/17), PercentGood / PercentBad (§5.4.3.18/19), WorstQuality / WorstQuality2 (§5.4.3.20/26) — US3

```text
// No behavioural change — these already key on StatusCode, not value.
agg_duration_good/bad      = sum of state_regions where region.status is Good / Bad
agg_percent_good/bad       = status-count ratio
agg_worst_quality(2)       = worst StatusCode over input.values
```
- Contract: for a non-numeric source and a numeric source with the SAME per-point StatusCode pattern
  over the same interval, these return EQUAL results. Locked in by tests (Constitution V).

## DurationInStateZero / DurationInStateNonZero (§5.4.3.22/23) — US4

```text
agg_duration_in_state_zero(input)     = sum of state_regions where zero_state == Zero
agg_duration_in_state_non_zero(input) = sum of state_regions where zero_state == NonZero
// zero_state = classify(region's Variant)  (see data-model.md)
```
- Boolean `false` / numeric `0` / null → Zero; Boolean `true` / numeric `!= 0` → NonZero.
- Types with no natural zero (Guid, ByteString, String, DateTime) → Unknown → excluded from BOTH.
- Numeric source → identical to today.

## Numeric-magnitude aggregates — UNCHANGED (FR-006)

Average, TimeAverage, Total, Minimum, Maximum, Min/MaxActualTime, Range, Delta, StandardDeviation*,
Variance, interpolation — continue to use `variant_to_f64`; a non-numeric source yields the existing
no-numeric-data / Bad result. This feature does NOT change them.

## Invariants

- No aggregate path panics on any `Variant` type, null, or Bad status (FR-008 / SC-006).
- `variant_to_f64`, `good_numeric_points`, `simple_bounded_points` and the numeric aggregates are not
  modified (backwards compat, FR-007).
- Builds under `--no-default-features` and `--all-features` (FR-010).
