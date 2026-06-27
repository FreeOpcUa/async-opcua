# Data Model: Non-numeric (any-value-type) HistoryRead aggregates

This feature adds no persisted entities. It refines two in-memory concepts in
`async-opcua-server/src/aggregates/engine.rs`.

## AggregatePoint (existing — `&DataValue` in `AggregateInput.values`)

A stored raw point: `(value: Variant, status: StatusCode, source_timestamp)`. The type-independent
aggregates consume:
- **status** — Good/Uncertain/Bad (Count inclusion, Duration/Percent/WorstQuality).
- **presence + value (by equality)** — NumberOfTransitions compares consecutive `Variant`s with `!=`.
- **value (by zero-state class)** — DurationInStateZero/NonZero classify the `Variant` into a ZeroState.

No magnitude (`f64`) is required for any of these. The numeric-magnitude aggregates continue to use
`variant_to_f64` and are unaffected.

## ZeroState (new — classification enum on `StateRegion`)

```text
enum ZeroState { Zero, NonZero, Unknown }

classify(value: Option<&Variant>) -> ZeroState:
    None | Some(Variant::Empty)            -> Zero        // null = zero state
    Some(Variant::Boolean(false))          -> Zero
    Some(Variant::Boolean(true))           -> NonZero
    Some(numeric) where variant_to_f64==0  -> Zero        // preserves current numeric == 0.0 rule
    Some(numeric) where variant_to_f64!=0  -> NonZero
    Some(other)                            -> Unknown     // Guid/ByteString/String/DateTime/… (out of scope)
```

- `StateRegion` gains a `zero_state: ZeroState` field (computed at knot construction in `state_regions`)
  in place of (or alongside) the current `value: Option<f64>` used only by the in-state durations.
- `agg_duration_in_state_zero` sums regions where `zero_state == Zero`.
- `agg_duration_in_state_non_zero` sums regions where `zero_state == NonZero`.
- `Unknown` regions are excluded from BOTH (documented; no natural zero; never panics).

**Invariant**: for numeric inputs, `classify` reproduces the existing `region.value == Some(0.0)` /
`!= 0.0` partition exactly, so numeric DurationInState* results are unchanged.

## Aggregate classification (conceptual)

| Class | Aggregates | Value dependency |
|---|---|---|
| Type-independent — status | Count, DurationGood/Bad, PercentGood/Bad, WorstQuality/2 | StatusCode only |
| Type-independent — equality | NumberOfTransitions | `Variant` `!=` |
| Type-independent — zero-state | DurationInStateZero/NonZero | `ZeroState` classification |
| Numeric-magnitude (unchanged) | Average, TimeAverage, Total, Min, Max, Min/MaxActualTime, Range, Delta, StdDev*, Variance, interpolation | `variant_to_f64` (Bad on non-numeric) |
| Out of scope | AnnotationCount | needs annotation modeling |
