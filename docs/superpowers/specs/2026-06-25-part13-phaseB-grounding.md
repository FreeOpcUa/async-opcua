# Phase B aggregate grounding (OPC 10000-13 §5.4.3, via opc-ua-reference MCP 2026-06-25)

Each Phase-B aggregate's spec table (Type / Data Type / Use Bounds / Timestamp / StatusCode):

| Aggregate | Id | Data Type | Use Bounds | Timestamp | Value definition | Status notes |
|---|---|---|---|---|---|---|
| Count | 2352 | **Int32** (>=0) | None | StartTime | number of Good raw values in interval | Good, Calculated |
| Average | 2342 | Double | None | StartTime | arithmetic mean of Good raw values (NOT time-weighted) | Calculated; Uncertain if any non-Good per status calculus |
| Range | 2350 | Double | None | StartTime | Maximum − Minimum of Good raw values | Calculated |
| Delta | 2359 | (source/Double) | None | StartTime | last Good − first Good raw value (signed) | Uncertain if non-Good skipped finding first/last; Bad_NoData if none |
| MinimumActualTime | 2348 | Same as Source | None | **Time (actual)** | min Good raw value | returned w/ timestamp of that value; ties → MultipleValues bit |
| MaximumActualTime | 2349 | Same as Source | None | **Time (actual)** | max Good raw value | ditto |
| VarianceSample | 11428 | Double | None | StartTime | sample variance = stddev_sample^2 (÷ n-1) | needs >=2 points else Bad_NoData |
| StandardDeviationPopulation | 11427 | Double | None | StartTime | population stddev (÷ n) | >=1 point |
| VariancePopulation | 11429 | Double | None | StartTime | population variance (÷ n) | >=1 point |
| WorstQuality | 2364 | **StatusCode** | None (Simple in WorstQuality2) | StartTime | worst StatusCode severity among raw in interval | Custom |
| AnnotationCount | 2351 | Int32 | None | StartTime | DEFER → BadAggregateNotSupported (no annotation history) |

Engine implication: Phase-B aggregate fns must build their OWN DataValue (result type + timestamp vary)
— do NOT route through the Double+interval_start `aggregate_result` helper for Count (Int32),
Min/MaxActualTime (Same-as-Source + actual time), WorstQuality (StatusCode). Average/Range/Delta/Variance
trio CAN reuse a Double helper. All Phase-B = Use Bounds None (no prior/next needed → prior/next stay None).
