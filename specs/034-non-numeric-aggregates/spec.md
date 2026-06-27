# Feature Specification: Non-numeric (any-value-type) HistoryRead aggregates

**Feature Branch**: `034-non-numeric-aggregates`
**Created**: 2026-06-27
**Status**: Draft
**Input**: User description: "Non-numeric (any-value-type) HistoryRead aggregates — OPC UA Part 13 §A.1. Count / NumberOfTransitions / status-based aggregates currently route through a numeric-only filter and silently ignore Boolean/String/Enumeration sources."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Count works for non-numeric sources (Priority: P1)

A historian stores a Boolean alarm flag (or a String/Enumeration state). A client performs a
HistoryRead with the **Count** aggregate over an interval that contains several stored raw points.
Today the client gets `Count = 0` because the engine only counts values it can convert to a number.
The client expects `Count = N`, the number of good raw points actually present — exactly as it would
for a numeric source.

**Why this priority**: This is the core conformance defect. Count is the most widely used
type-independent aggregate, and returning 0 for a non-numeric source is a silent, wrong answer that
breaks Part 13 §A.1. Fixing Count alone delivers a viable, demonstrable correctness improvement.

**Independent Test**: Store a Boolean series, HistoryRead with Count over an interval, assert the
returned count equals the number of good raw points (not 0), and that a numeric series still returns
the same count it did before.

**Acceptance Scenarios**:

1. **Given** a Boolean source with 5 good raw points in an interval, **When** a client reads the
   Count aggregate over that interval, **Then** the result Value is 5 (not 0).
2. **Given** a String source with 3 good points and 1 Bad-status point in an interval, **When** the
   Count aggregate is read, **Then** the result reflects the Part 13 Count treatment of status
   (the same rule applied to numeric sources today), independent of the value type.
3. **Given** a numeric (Double) source, **When** the Count aggregate is read, **Then** the result is
   identical to the value returned before this feature (no regression).

---

### User Story 2 - NumberOfTransitions works for any comparable value (Priority: P2)

A client reads the **NumberOfTransitions** aggregate of a Boolean alarm flag (or an Enumeration
state) to learn how many times it changed state in an interval. Today it returns 0 because the engine
computes transitions through the numeric filter. The client expects the count of value *changes*,
determined by value equality — which is well-defined for Boolean, Enumeration, String, etc.

**Why this priority**: NumberOfTransitions on Boolean/Enumeration sources is a primary use case
(counting alarm flips, state changes). It is meaningless to restrict it to numeric values, since a
"transition" is a change of value, not a change of magnitude.

**Independent Test**: Store a Boolean series that flips K times in an interval, read
NumberOfTransitions, assert the result equals K; confirm a numeric series is unchanged.

**Acceptance Scenarios**:

1. **Given** a Boolean source whose value changes 4 times within an interval, **When**
   NumberOfTransitions is read, **Then** the result is 4.
2. **Given** an Enumeration/String source with no value changes in the interval, **When**
   NumberOfTransitions is read, **Then** the result is 0 (no transitions, not an error).
3. **Given** a numeric source, **When** NumberOfTransitions is read, **Then** the result is identical
   to before this feature.

---

### User Story 3 - Status-based aggregates are value-type-agnostic (Priority: P2)

A client reads quality/duration aggregates — **PercentGood, PercentBad, DurationGood, DurationBad,
WorstQuality, WorstQuality2** — of a non-numeric source. These aggregates are defined entirely on the
*StatusCode* of the stored points, never on the value, so they must return the same result for a
Boolean source as for a numeric source with the same status pattern.

**Why this priority**: These aggregates are conceptually already type-independent; the priority is to
confirm they do not pass through the numeric filter and to lock that in with coverage, so a future
refactor cannot silently re-break them.

**Independent Test**: Build a numeric series and a Boolean series with the *same* per-point status
pattern over the same interval; read each status aggregate against both; assert the results are equal.

**Acceptance Scenarios**:

1. **Given** a Boolean source and a numeric source with the same Good/Bad status pattern in an
   interval, **When** PercentGood / PercentBad / DurationGood / DurationBad are read, **Then** the
   results are equal for both sources.
2. **Given** a non-numeric source, **When** WorstQuality / WorstQuality2 is read, **Then** the result
   is the worst StatusCode in the interval, independent of value type.

---

### User Story 4 - State-based duration aggregates generalize to Boolean (Priority: P3)

A client reads **DurationInStateZero / DurationInStateNonZero** of a Boolean source. Part 13 defines a
"zero state" and a "non-zero state"; for these to be useful on a Boolean alarm, the zero state must
map cleanly to `false` (and numeric `0` / null), with everything else being non-zero. The client
expects the time-in-state to be computed for Boolean and numeric sources alike.

**Why this priority**: Lower priority because it requires a defensible cross-type definition of
"zero state". It generalizes cleanly for Boolean and numeric; exotic types (Guid, ByteString) have no
natural zero and are explicitly out of scope (treated as non-zero / unsupported) and documented.

**Independent Test**: Store a Boolean series that is `false` for part of the interval and `true` for
the rest; read DurationInStateZero and DurationInStateNonZero; assert the durations match the
false/true spans; confirm a numeric 0/non-0 series gives the same numbers as before.

**Acceptance Scenarios**:

1. **Given** a Boolean source that is `false` for the first half of an interval and `true` for the
   second, **When** DurationInStateZero is read, **Then** it reports the first-half duration.
2. **Given** a numeric source, **When** DurationInStateZero / DurationInStateNonZero are read,
   **Then** the results are identical to before this feature.
3. **Given** a value type with no natural zero (e.g. ByteString), **When** a state-based duration is
   read, **Then** the engine returns the documented behavior (treated as non-zero / unsupported) and
   never panics.

### Edge Cases

- **Empty interval** (no raw points): Count = 0, NumberOfTransitions = 0, with the same StatusCode the
  engine returns today for an empty numeric interval (no change in empty-interval semantics).
- **All-Bad-status interval**: counts/durations apply the existing Part 13 status treatment uniformly,
  independent of value type.
- **Mixed value types within one interval** (a source that changed DataType mid-stream): the
  type-independent aggregates still operate on presence/status/equality and never panic.
- **Null values** (`Variant::Empty` with Good status): handled per Part 13 without panicking; the
  zero-state definition (US4) treats null as zero-state.
- **Numeric-magnitude aggregate on a non-numeric source** (Average, Minimum, …): unchanged — returns
  the existing no-numeric-data / Bad behavior; this feature does NOT make them succeed.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The Count aggregate MUST return the number of **Good-status** raw data points in the
  interval regardless of the points' value type (Boolean, String, Enumeration, Guid, ByteString,
  DateTime, numeric, …); non-Good points (including Uncertain) are excluded, exactly as for numeric
  sources today (Part 13 §5.4.3.21).
- **FR-002**: The NumberOfTransitions aggregate MUST count the number of value *changes* between
  consecutive **non-Bad** points (Good OR Uncertain — a wider status set than Count's Good-only)
  using value equality, for any value type — a transition occurs when a value differs from the
  previous non-Bad value (Part 13 §5.4.3.24). NOTE: the current implementation
  counts only zero↔non-zero crossings, which is incorrect even for numeric sources (e.g. 1→2→3
  reports 0 transitions instead of 2); this requirement CORRECTS that, so numeric NumberOfTransitions
  results change where they were previously wrong (see FR-007).
- **FR-003**: PercentGood, PercentBad, DurationGood, and DurationBad MUST compute identically for a
  non-numeric source and a numeric source that share the same per-point StatusCode pattern (these
  aggregates are defined on status, not value).
- **FR-004**: WorstQuality and WorstQuality2 MUST return the worst StatusCode in the interval
  independent of the points' value type.
- **FR-005**: DurationInStateZero and DurationInStateNonZero MUST use a value-type-aware zero-state
  definition: `false` (Boolean), numeric `0`, and null are "zero state"; any other value is
  "non-zero state". Value types with no natural zero are treated as non-zero and documented; the
  engine MUST NOT panic on any value type.
- **FR-006**: The numeric-magnitude aggregates (Average, TimeAverage, Total, Minimum, Maximum,
  MinimumActualTime, MaximumActualTime, Range, Delta, StandardDeviation/Population variants, Variance,
  and interpolation-based aggregates) MUST retain their current numeric-only behavior unchanged: a
  non-numeric source yields the existing no-numeric-data / type-mismatch result, NOT a new value.
- **FR-007**: For every aggregate EXCEPT NumberOfTransitions, a numeric source MUST produce results
  identical to the prior release (the change is additive for non-numeric inputs only). For
  NumberOfTransitions, the numeric result is CORRECTED per FR-002 (Part 13 §5.4.3.24); the existing
  numeric NumberOfTransitions tests MUST be updated to the spec-correct expected values, and the
  correction MUST be called out in the PR.
- **FR-008**: No source value (any Variant type, null, or Bad status) MAY cause a panic in any
  aggregate path.
- **FR-009**: AnnotationCount remains explicitly unsupported and out of scope (it requires annotation
  modeling); its current behavior is unchanged.
- **FR-010**: All new and changed code MUST build and pass tests under `--no-default-features` and
  `--all-features`.

### Key Entities

- **Aggregate point**: a stored raw `DataValue` — a (value, StatusCode, source timestamp) triple. The
  type-independent aggregates consume the StatusCode/timestamp/presence and, for transitions and
  state-duration, the value via equality / zero-state classification — never via numeric conversion.
- **Aggregate classification**: each supported aggregate is either *numeric-magnitude* (operates on a
  converted f64) or *type-independent* (operates on status / presence / equality / zero-state). This
  feature moves Count and NumberOfTransitions (and confirms the status/duration set) into the
  type-independent class.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A Boolean source with N good raw points in an interval returns Count = N (previously 0)
  for N spanning at least the cases N ∈ {0, 1, 5}.
- **SC-002**: A Boolean/Enumeration source that changes value K times in an interval returns
  NumberOfTransitions = K (previously 0).
- **SC-003**: For a numeric source and a non-numeric source with an identical per-point status
  pattern, PercentGood, PercentBad, DurationGood, DurationBad, WorstQuality, and WorstQuality2 return
  equal results.
- **SC-004**: Every aggregate result for a numeric source is unchanged from the prior release across
  the existing aggregate test suite (zero regressions), EXCEPT NumberOfTransitions, whose numeric
  results are corrected to the Part 13 §5.4.3.24 value-change definition.
- **SC-005**: The crate builds and the aggregate tests pass under default features,
  `--no-default-features`, and `--all-features`.
- **SC-006**: No aggregate path panics for any of: Boolean, String, Enumeration, Guid, ByteString,
  DateTime, null, and Bad-status inputs.

## Spec Traceability

| Aggregate(s) | Part 13 § | This feature |
|---|---|---|
| Count | §5.4.3.21 | US1 — count Good-status raw points, any value type (FR-001) |
| NumberOfTransitions | §5.4.3.24 | US2 — value-change transitions vs previous non-Bad, any type; **corrects numeric** (FR-002) |
| PercentGood / PercentBad | §5.4.3.33 / §5.4.3.34 | US3 — status-based, confirm type-agnostic (FR-003) |
| DurationGood / DurationBad | §5.4.3.31 / §5.4.3.32 | US3 — status-based (FR-003) |
| WorstQuality / WorstQuality2 | §5.4.3.35 / §5.4.3.36 | US3 — status-based (FR-004) |
| DurationInStateZero / NonZero | §5.4.3.22 / §5.4.3.23 | US4 — cross-type zero-state (FR-005) |
| Average/Min/Max/Range/Delta/StdDev/Variance/Total/TimeAverage/interpolation | §5.4.3.x | unchanged, numeric-only (FR-006) |
| AnnotationCount | §5.4.3.25 | out of scope (FR-009) |

## Assumptions

- The existing AggregateInput engine, interval/bounds machinery, and Part-13 status/quality helpers in
  `async-opcua-server/src/aggregates/engine.rs` are reused; only the Count-family / transition /
  state-duration paths are split off the numeric (`variant_to_f64`) filter.
- "Users" = OPC UA clients reading history aggregates + server integrators exposing non-numeric
  historized variables. Outcomes are framed as observable HistoryRead aggregate results.
- The standard interval/bounding/`TreatUncertainAsBad`/status-code treatment of Part 13 is already
  implemented and correct for numeric sources; this feature does not alter that machinery, only the
  value-type gate in front of the type-independent aggregates.
- StandardDeviation/Variance and all interpolation aggregates are numeric by definition and remain so.
- Value types with no natural zero (Guid, ByteString, structured types) are out of scope for the
  zero-state aggregates and are documented as treated non-zero / unsupported rather than erroring.
