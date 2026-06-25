# Phase C/D grounding (OPC 10000-13, via opc-ua-reference MCP 2026-06-25)

## Bounding values (the core new infrastructure)
- **Interpolated Bounding Value** (§3.1.8): value at interval boundary via straight-line interpolation
  between the raw point before and after the boundary. If no following point: UseSlopedExtrapolation
  → sloped (extend last slope) vs stepped (hold last value). Interpolated bounds carry Uncertain-ish bits.
- **Simple Bounding Value**: the last raw value at/before the boundary, held constant (no interpolation).
- Need `prior` (last raw <= interval_start) and `next` (first raw > interval_end) → requires
  read_raw_modified(return_bounds=true) wired into AggregateInput.prior/next (deferred from Phase A).

## Phase C aggregates
- **TimeAverage (2343, EXISTING — needs correction)**: §5.4.3.6 uses INTERPOLATED bounds; line from start
  bound through each value to end bound; area under lines / total time. OUR CURRENT impl uses NO bounds
  (interval-internal time-weighting only) → simplified / not fully conformant. Phase C should correct it.
- **Interpolative (2341)**: interpolated value at the START of the interval (ground exact §5.4.3.x).
- **Total (2344)**: time integral (area) = TimeAverage * interval duration; uses interpolated bounds.
- **StartBound (11505)**: value at interval start using SIMPLE bounds.
- **EndBound (11506)**: value at interval end using SIMPLE bounds.
- **DeltaBounds (11507)** §5.4.3.30: EndBound - StartBound, both must be Good; signed (0 if equal).

## Aggregate StatusCode info bits (needed for full conformance, can phase in)
Calculated / Interpolated / Raw / Partial / MultipleValues — set per-aggregate per §5.4.3.x tables.
"No Start Bound → treat beginning value as Bad_NoData and compute"; "Before/After data → Bad_NoData".

## Phase D "2" family (SimpleBounds)
TimeAverage2 (11285, §5.4.3.7), Minimum2/Maximum2 (11286/11287, §5.4.3.15/16),
Min/MaxActualTime2 (11305/11306, §5.4.3.17/18), Range2, Total2, WorstQuality2 (11292) — same as the
base but include Simple Bounding Values. "No Start/End Bound → treat as Bad_NoData".

## Phase E status/duration (§5.4.3.31-34, 22-24)
DurationGood/Bad (2360/2361), PercentGood/Bad (2362/2363, Double percent, Good/Calculated; use Simple
bounds via DurationGood/Bad), DurationInStateZero/NonZero (11307/11308), NumberOfTransitions (2355,
custom bounds: a non-Bad value prior to interval). Need the §5.3 StatusCode time-weighted calculus.
