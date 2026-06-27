# Feature Specification: AnnotationCount aggregate + Annotations Property

**Feature Branch**: `035-annotation-count`
**Created**: 2026-06-27
**Status**: Draft
**Input**: User description: "AnnotationCount aggregate (Part 13 §5.4.3.20) — the last standard aggregate still unsupported — plus the Part 11 §5.1.2 Annotations Property for discoverability. Consumes the annotation history that HistoryUpdate already writes."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - AnnotationCount aggregate (Priority: P1)

A client has annotated a historized variable (added Annotation entries via HistoryUpdate). It now reads
the **AnnotationCount** aggregate over a time range, partitioned into processing intervals, to learn how
many annotations fall in each interval. Today the server rejects the request with
`Bad_AggregateNotSupported` — AnnotationCount is the one standard Part 13 aggregate the engine
deliberately omits. The client expects a per-interval count of the annotations in that range.

**Why this priority**: AnnotationCount is the **last** unimplemented standard Part 13 aggregate;
implementing it completes the aggregate set. The annotation history it counts is already stored and
updatable, so this is the natural closing piece. It is independently valuable and testable on its own.

**Independent Test**: Store N annotations on a node across a time range, HistoryRead the AnnotationCount
aggregate with a processing interval, and assert each interval's value equals the number of annotations
whose timestamp falls in that interval; an interval with no annotations returns 0.

**Acceptance Scenarios**:

1. **Given** a node with 3 annotations whose timestamps fall in a single processing interval, **When** a
   client reads the AnnotationCount aggregate over that interval, **Then** the result Value is 3 with a
   Good status (previously `Bad_AggregateNotSupported`).
2. **Given** a range partitioned into several intervals with annotations spread across them, **When**
   AnnotationCount is read, **Then** each interval reports the count of annotations in its own
   `[start, end)` window, and an interval with no annotations reports 0 (Good).
3. **Given** the server's advertised aggregate set, **When** a client enumerates supported aggregates,
   **Then** AnnotationCount (i=2351) now appears and a request for it is computed (not rejected).

---

### User Story 2 - Annotations Property discoverability (Priority: P2)

A client browsing a historized variable wants to find its annotation collection through the standard
address-space model. Per Part 11 §5.1.2 a HistoricalDataNode may expose an **Annotations** Property (a
Variable of DataType `Annotation`, reached by a `HasProperty` reference). Today annotations are reachable
only through HistoryRead/HistoryUpdate, not by browsing. The client expects to Browse the variable, find
its Annotations Property, and read it.

**Why this priority**: Lower priority because annotations are already fully usable via
HistoryRead/HistoryUpdate; this story adds standards-conformant discoverability. It is opt-in (a helper
that an integrator calls on the variables that should expose it) rather than auto-added everywhere.

**Independent Test**: Attach the Annotations Property to a historized variable via the helper, Browse the
variable's `HasProperty` references, and confirm the Annotations Property is reachable and readable.

**Acceptance Scenarios**:

1. **Given** a historized variable with the Annotations Property attached, **When** a client browses the
   variable's `HasProperty` references, **Then** the Annotations Property Variable (BrowseName
   "Annotations") is among them.
2. **Given** that Annotations Property, **When** the client reads its node attributes, **Then** it
   resolves as a Variable of DataType `Annotation` without error.

### Edge Cases

- **No annotations on the node**: every interval's AnnotationCount is 0 with Good status (not an error).
- **Annotation timestamp exactly on an interval boundary**: counted in `[interval_start, interval_end)`
  (start-inclusive, end-exclusive) — the same convention the Count aggregate uses.
- **Empty time range / zero-width interval**: handled like the other count aggregates (no panic).
- **Backend without annotation support**: a backend whose annotation read is unsupported yields an empty
  annotation set, so AnnotationCount returns 0 rather than erroring or panicking.
- **A node that is annotated but has no raw values in an interval**: AnnotationCount still reports the
  annotation count (it does not require raw values in the interval).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The server MUST support the AnnotationCount aggregate (Part 13 §5.4.3.20, NodeId i=2351):
  for each processing interval it MUST return an `Int32` count (≥ 0) of the annotations whose source
  timestamp falls within that interval, with a Good (Calculated) StatusCode and the interval's start time
  as the result timestamp.
- **FR-002**: An interval containing no annotations MUST return AnnotationCount = 0 with Good status, not
  an error.
- **FR-003**: AnnotationCount MUST count annotations whose timestamp is in `[interval_start,
  interval_end)` (start-inclusive, end-exclusive), consistent with the Count aggregate's convention.
- **FR-004**: AnnotationCount MUST appear in the server's advertised set of supported aggregates, and a
  request for it MUST be computed rather than rejected with `Bad_AggregateNotSupported`.
- **FR-005**: The annotation data consumed by AnnotationCount MUST come from the existing annotation
  history store (the same annotations written by HistoryUpdate `UpdateStructureData` and returned by the
  annotation HistoryRead) — the feature MUST NOT introduce a second annotation store.
- **FR-006**: AnnotationCount MUST NOT change the result of any other aggregate; the 34 existing
  aggregates MUST return identical results for all sources (the annotation data is additive to the
  aggregate input).
- **FR-007**: A backend that does not support annotations MUST cause AnnotationCount to return 0 (empty
  annotation set), never an error or panic.
- **FR-008**: A historized variable MAY expose the standard Annotations Property (Part 11 §5.1.2 — a
  `HasProperty` reference to an `Annotations` Variable of DataType `Annotation`); the server MUST provide
  a way to attach it, and once attached it MUST be browsable and readable. It MUST NOT be forced onto
  every variable.
- **FR-009**: All new and changed code MUST build and pass tests under `--no-default-features` and
  `--all-features` (the SQLite annotation parity is exercised under the sqlite feature).

### Key Entities

- **Annotation**: a Part 11 §5.1.2 record (message, user name, annotation time) stored against a node at
  a source timestamp; written via HistoryUpdate `UpdateStructureData`, read via annotation HistoryRead.
  AnnotationCount counts these by timestamp; it does not inspect their content.
- **AnnotationCount aggregate**: a Part 13 calculated aggregate (i=2351) returning the per-interval count
  of Annotations. Type-independent of the node's value type (it operates on annotation timestamps).
- **Annotations Property**: the standard address-space Property (DataType `Annotation`) that makes a
  node's annotation collection discoverable by browsing (Part 11 §5.1.2).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A node with N annotations in an interval returns AnnotationCount = N (for N covering at
  least {0, 1, 3}); previously the request returned `Bad_AggregateNotSupported`.
- **SC-002**: Across a multi-interval range, each interval's AnnotationCount equals the number of
  annotations in its own `[start, end)` window.
- **SC-003**: AnnotationCount (i=2351) is present in the advertised supported-aggregate set and is
  computed (not rejected); the count of advertised aggregates increases by exactly one.
- **SC-004**: Every other aggregate returns results identical to the prior release across the existing
  aggregate test suite (zero regressions).
- **SC-005**: A historized variable with the Annotations Property attached exposes a browsable,
  readable `Annotations` Variable of DataType `Annotation`.
- **SC-006**: The crate builds and the aggregate + annotation tests pass under default features,
  `--no-default-features`, and `--all-features`.

## Assumptions

- The existing annotation stores (in-memory `InMemoryDataHistory` and the SQLite
  `historical_annotations` table), the `read_annotations` backend method, the `AggregateInput` engine,
  and the interval/partition machinery are reused; only the annotation-count path is added.
- "Users" = OPC UA clients reading history aggregates / browsing historized nodes + server integrators
  exposing annotated historical variables. Outcomes are framed as observable HistoryRead aggregate
  results and browse results.
- Part 13 §5.4.3.20 specifies "Use Bounds: None" and "no interpolation" for AnnotationCount, so the
  count is a simple per-interval tally of annotation timestamps — no bounding/holding logic.
- The "Bad_NoData before-start / after-end-of-data" nuance in §5.4.3.20 needs historian range metadata
  the engine does not currently track (the same documented limitation as the Count aggregate); within
  the requested range the aggregate returns Good + count. This is recorded as a known limitation, not a
  gap in this feature.
- The Annotations Property is opt-in per variable; auto-attaching it to every historized variable is out
  of scope (it would bloat the address space and is not required by the spec).
