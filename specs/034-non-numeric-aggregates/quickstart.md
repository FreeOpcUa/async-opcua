# Quickstart: aggregates over a non-numeric historized variable

## Before (the bug)

A historian stores a Boolean alarm flag. A client reads the Count aggregate:

```text
HistoryRead(Count, node=BoolAlarm, start=T0, end=T1)
→ Value = 0      // WRONG: there were 5 stored points in [T0, T1]
HistoryRead(NumberOfTransitions, node=BoolAlarm, …)
→ Value = 0      // WRONG: the flag flipped 4 times
```

## After

```text
HistoryRead(Count, node=BoolAlarm, start=T0, end=T1)
→ Value = 5      // number of Good-status raw points, any value type (Part 13 §5.4.3.21)
HistoryRead(NumberOfTransitions, node=BoolAlarm, …)
→ Value = 4      // value changes vs the previous non-Bad value (Part 13 §5.4.3.24)
```

NumberOfTransitions is also corrected for numeric sources: a `1.0 → 2.0 → 3.0` series now reports `2`
(it previously reported `0` because only zero↔non-zero crossings were counted).

## Status & state-duration aggregates work on any type too

```text
DurationGood / DurationBad / PercentGood / PercentBad / WorstQuality   // already type-agnostic (status-based)
DurationInStateZero(BoolAlarm)     → time the flag was false           // Part 13 §5.4.3.22
DurationInStateNonZero(BoolAlarm)  → time the flag was true            // Part 13 §5.4.3.23
```

Zero-state mapping: Boolean `false` / numeric `0` / null = zero state; Boolean `true` / numeric `≠ 0`
= non-zero state; types with no natural zero (Guid, ByteString, String, DateTime) are excluded from
both in-state durations.

## Unchanged

```text
HistoryRead(Average, node=BoolAlarm, …)   → Bad_* / no-numeric-data   // numeric-magnitude aggregates
                                                                      // stay numeric-only by definition
```
Numeric sources return identical results to before for every aggregate except the corrected
NumberOfTransitions.
