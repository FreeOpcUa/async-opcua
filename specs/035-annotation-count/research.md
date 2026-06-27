# Phase 0 Research: AnnotationCount aggregate + Annotations Property

Grounded against the OPC UA reference (Part 13 §5.4.3.20, Part 11 §5.1.2) and the current code
(`aggregates/engine.rs`, `history/backend.rs`, `async-opcua-history-sqlite/src/backend.rs`,
`history/data_history.rs`, `subscriptions/monitored_item.rs`).

## D1 — `AggregateInput` gains an additive `annotations: &'a [DateTime]` field

**Decision**: Add `pub annotations: &'a [DateTime]` to `AggregateInput` (engine.rs:271) — the annotation
source-timestamps that fall in THIS interval. Non-annotation aggregates ignore it; it is `&[]` for them.
Update the THREE construction sites: `compute_processed_intervals` (engine.rs:1484, populates it),
`subscriptions/monitored_item.rs:605` (live monitored-item aggregation — pass `&[]`, no annotation
history), and the `aggregates_tests.rs` `calculate_aggregate` helper (pass `&[]`; AnnotationCount tests
set it explicitly).

**Rationale**: AnnotationCount is the only aggregate that needs annotations; a single additive slice
field keeps the change minimal and leaves every other aggregate's computation byte-identical (FR-006).
`DateTime` timestamps (not full `DataValue`s) are sufficient — the count does not inspect annotation
content.

**Alternatives rejected**: a separate annotation-aware engine entry point (duplicates partitioning);
passing full annotation `DataValue`s (carries content the count never uses).

## D2 — `compute_processed_intervals` threads `annotation_times` and slices per interval

**Decision**: Add an `annotation_times: &[DateTime]` parameter to `compute_processed_intervals`
(engine.rs:1450) — all annotation timestamps in `[start_time, end_time]`, sorted. Inside the per-interval
map, slice the timestamps in `[min_t, max_t)` (the same interval predicate used for `values_in_interval`)
and set them on `AggregateInput.annotations`. Update BOTH callers (D3).

**Rationale**: mirrors how `values_in_interval` is already computed, so AnnotationCount honors the exact
same `[interval_start, interval_end)` convention as Count (FR-003). The parameter is `&[]` for all
non-AnnotationCount reads, so existing behavior is unchanged.

## D3 — Load annotations in BOTH `read_processed` impls, only for AnnotationCount

**Decision**: `read_processed` exists twice — the trait default (`history/backend.rs:84`, used by the
in-memory backend) AND a sqlite override (`async-opcua-history-sqlite/src/backend.rs:647`). BOTH call
`compute_processed_intervals` (backend.rs:117 / sqlite:680). In each, when `aggregate_type` is
AnnotationCount (i=2351): call `self.read_annotations(node_id, &[], None)` (empty `req_times` returns ALL
annotations for the node), map each returned `DataValue` to its `get_value_timestamp`, filter to
`[start_time, end_time]`, sort, and pass as `annotation_times`. For every other aggregate, pass `&[]`
(no annotation load → no overhead). If `read_annotations` returns `Err`/Unsupported, treat it as an empty
set (count 0) — never propagate an error (FR-007).

**Rationale**: one consistent behavior across both backends; loading is gated on the aggregate id so the
34 numeric/status aggregates pay nothing. The sqlite override is the easy-to-miss second site — the plan
and tasks call it out explicitly. SQLite parity is exercised under the `sqlite` feature.

**Alternatives rejected**: always loading annotations (overhead on every processed read); loading only in
the trait default (silently wrong on sqlite — the exact bug to avoid).

## D4 — `agg_annotation_count` + dispatch + advertise

**Decision**: Add `const AGG_ANNOTATION_COUNT: u32 = 2351;`, a dispatch arm
`Identifier::Numeric(AGG_ANNOTATION_COUNT) => agg_annotation_count(input)`, and add `2351` to
`SUPPORTED_AGGREGATE_IDS`. `agg_annotation_count(input)` returns
`DataValue { value: Int32(input.annotations.len() as i32), status: Good, source_timestamp:
interval_start, server_timestamp: now }`. Remove the engine comment that marks it unsupported.

**Rationale**: Part 13 §5.4.3.20 — Int32 count, Good/Calculated, StartTime timestamp, Use Bounds = None,
no interpolation. The count is simply the number of in-interval annotation timestamps. Empty interval →
`Int32(0)` Good (FR-002). The "Bad_NoData before/after available data" nuance needs historian range
metadata the engine does not track — the same documented limitation as Count; within the requested range
it returns Good + count.

## D5 — Flip the "unsupported" tests to positive coverage

**Decision**: The existing tests assert AnnotationCount is NOT advertised and returns
`Bad_AggregateNotSupported` (aggregates_tests.rs ~L45-68, L700-705, L1135-1140). Update them: 2351 IS in
the advertised set, the advertised count increases by one (was 34 → 35), and a request returns Good +
the count. Claude rewrites these as part of the US1 test tasks (they are verification, not codex's to
self-author).

**Rationale**: Constitution V — the negative carve-out is replaced by positive coverage; the
advertised-count assertion (`assert_eq!(ids.len(), 34)`) must move to 35.

## D6 — Opt-in Annotations Property (US2)

**Decision**: Add a helper that, given a historized variable, creates an `Annotations` Property — a
Variable with BrowseName `Annotations`, `PropertyType` type definition, DataType `Annotation` (i=891) —
and a `HasProperty` reference from the variable to it (Part 11 §5.1.2). Opt-in per variable; not
auto-attached. Reuse the existing `VariableBuilder`/address-space reference API (as the alarm InputNode
property binding did in feature 033).

**Rationale**: standards-conformant discoverability without bloating every node. Minimal: the property
makes the annotation collection browsable; the annotation values themselves remain served by
HistoryRead/HistoryUpdate (unchanged). Backwards compatible (purely additive).
