# Tasks: AnnotationCount aggregate + Annotations Property

**Feature**: `specs/035-annotation-count` | **Branch**: `035-annotation-count`
**Spec**: [spec.md](spec.md) · **Plan**: [plan.md](plan.md) · **Contract**: [contracts/annotation-count.md](contracts/annotation-count.md)

Format: `[ID] [P?] [Story?] Description (Spec: Part/§)`. Tasks are **atomic** (one concern each) and
**cite the OPC UA Part/§** they touch so the implementer grounds them via the reference MCP. [P] =
parallelizable. Engine work is in `async-opcua-server/src/aggregates/engine.rs`; backend wiring in
`async-opcua-server/src/history/backend.rs` AND `async-opcua-history-sqlite/src/backend.rs` (TWO
`read_processed` impls). Claude authors the `[Claude]` test tasks and runs the suite.

---

## Phase 1: Setup

- [X] T001 [P] Confirm the aggregate + history suites are green at baseline: `cargo test -p async-opcua-server` and `cargo test -p async-opcua-history-sqlite` (Spec: SC-004)
- [X] T002 Inventory the touch points: `AggregateInput` (engine.rs:271), `compute_processed_intervals` (engine.rs:1450), the dispatch arm + "unsupported" comment (engine.rs:~1417), `SUPPORTED_AGGREGATE_IDS` (engine.rs:45); the TWO `read_processed` impls (`history/backend.rs:84/117` trait default AND `async-opcua-history-sqlite/src/backend.rs:647/680` override); `read_annotations` (backend.rs:144); the other `AggregateInput` sites (`subscriptions/monitored_item.rs:605`, `tests/aggregates_tests.rs` `calculate_aggregate`); and the "AnnotationCount unsupported" tests (aggregates_tests.rs ~L45-68/L700-705/L1135-1140) (Spec: Part 13 §5.4.3.20)

## Phase 2: Foundational (BLOCKING — additive plumbing; no behavior change yet)

- [X] T003 Add `pub annotations: &'a [DateTime]` to `AggregateInput` (engine.rs:271); set it to `&[]` at the `monitored_item.rs:605` construction site and in the `aggregates_tests.rs` `calculate_aggregate` helper (no behavior change — every existing aggregate ignores the empty slice) (Spec: Part 13 §5.4.3.20)
- [X] T004 Add an `annotation_times: &[DateTime]` parameter to `compute_processed_intervals` (engine.rs:1450); per interval, slice the timestamps in `[min_t, max_t)` into `AggregateInput.annotations`; update BOTH callers (`history/backend.rs:117` and `async-opcua-history-sqlite/src/backend.rs:680`) to pass `&[]` for now (Spec: Part 13 §5.4.3.20; FR-003)

**Checkpoint**: the annotation slice is plumbed through the engine; all aggregates still identical (annotations always empty).

---

## Phase 3: User Story 1 — AnnotationCount aggregate (P1) 🎯 MVP

**Goal**: AnnotationCount returns the per-interval count of annotations.
**Independent test**: store 3 annotations in an interval, read AnnotationCount → 3 (was Bad_AggregateNotSupported).

- [X] T005 [US1] Implement `agg_annotation_count(input)` in engine.rs returning `Int32(input.annotations.len())`, status Good, source_timestamp = interval_start; add `const AGG_ANNOTATION_COUNT: u32 = 2351`, a dispatch arm for it, add `2351` to `SUPPORTED_AGGREGATE_IDS`, and remove the "intentionally unsupported" comment (Spec: Part 13 §5.4.3.20)
- [X] T006 [US1] In the trait-default `read_processed` (`history/backend.rs`), when `aggregate_type` is AnnotationCount (i=2351) call `self.read_annotations(node_id, &[], None)`, map each `DataValue` to `get_value_timestamp`, filter to `[start_time, end_time]`, sort, and pass as `annotation_times`; for other aggregates pass `&[]`; on `Err`/unsupported use an empty set (Spec: Part 13 §5.4.3.20; FR-007)
- [X] T007 [US1] Apply the SAME annotation-load logic in the sqlite `read_processed` OVERRIDE (`async-opcua-history-sqlite/src/backend.rs:647`) — the second impl that must not be missed (Spec: Part 13 §5.4.3.20; FR-005)
- [X] T008 [P] [US1] [Claude] Unit test (engine): an `AggregateInput` with N annotation timestamps in the interval → AnnotationCount = N for N ∈ {0, 1, 3} (Spec: SC-001; §5.4.3.20)
- [X] T009 [P] [US1] [Claude] Unit test: a multi-interval range with annotations spread across intervals → each interval counts its own `[start, end)` window; a boundary timestamp falls in the start-inclusive interval; empty interval → 0 (Spec: SC-002; FR-003)
- [X] T010 [US1] [Claude] Flip the "AnnotationCount unsupported" tests (aggregates_tests.rs): assert 2351 IS advertised (advertised count 34 → 35) and a request is computed (Good), not `Bad_AggregateNotSupported` (Spec: SC-003; SC-004)
- [X] T011 [P] [US1] [Claude] Integration test (in-memory backend, e2e): HistoryUpdate `UpdateStructureData` to add annotations, then HistoryRead the AnnotationCount aggregate → the per-interval counts (the full write→count loop) (Spec: SC-001; §5.4.3.20)
- [X] T011a [P] [US1] [Claude] sqlite parity test (`async-opcua-history-sqlite/tests/`, under the `sqlite` feature): same annotations + AnnotationCount read returns the same counts as the in-memory backend (Spec: SC-006; FR-005)
- [X] T012 [P] [US1] [Claude] Test: a backend whose `read_annotations` is unsupported → AnnotationCount returns 0 (Good), no error/panic (Spec: FR-007; SC-006)

**Checkpoint**: AnnotationCount works end-to-end on both backends; the standard aggregate set is complete.

---

## Phase 4: User Story 2 — Annotations Property discoverability (P2)

**Goal**: a historized variable can expose a browsable Annotations Property.
**Independent test**: attach the property, browse HasProperty → the Annotations Variable is reachable.

- [X] T013 [US2] Add a helper (e.g. `attach_annotations_property(address_space, &source_var) -> NodeId`) that creates an `Annotations` Variable (BrowseName `Annotations`, `PropertyType`, DataType `Annotation` i=891) and a forward `HasProperty` reference from the source variable to it (Spec: Part 11 §5.1.2)
- [X] T014 [P] [US2] [Claude] Integration test: after attaching, browse the source variable's `HasProperty` references → the `Annotations` property is present and reads back as a Variable of DataType `Annotation` (Spec: SC-005; Part 11 §5.1.2)

**Checkpoint**: annotations are discoverable via the address space, not only via HistoryRead/Update.

---

## Phase 5: Polish & cross-cutting

- [X] T015 [P] Run the FULL `cargo test -p async-opcua-server` + `cargo test -p async-opcua-history-sqlite` — all green; confirm no other aggregate result changed (Spec: SC-004)
- [X] T016 [P] [Claude] No-panic test: AnnotationCount with an empty range, a zero-width interval, and a node with no annotations — all return Good/0 with no panic (Spec: FR-002; FR-007; Constitution IV)
- [X] T017 [P] Build + `cargo clippy` under `--no-default-features` and `--all-features` (the latter pulls in sqlite); `cargo fmt --all --check` clean (Spec: FR-009; SC-006; Constitution V)
- [X] T018 Update `specs/completeness-backlog.md` (AnnotationCount done → the standard Part 13 aggregate set is COMPLETE; only HistoryUpdate-of-aggregates remains, which is a non-operation) + memory (Spec: project process)

---

## Dependencies & MVP

- **Setup (T001–T002)** → **Foundational (T003–T004)** → user stories.
- **US1 (P1, T005–T012)** is the MVP and independently shippable: it makes AnnotationCount work on both
  backends. T006 (in-memory) and T007 (sqlite) are the two `read_processed` impls — both required for
  parity. **US2 (P2)** is independent (address-space only). Recommended order US1 → US2; one PR per user
  story, Polish (T015–T018) folded into the final PR.
- Each `[Claude]` test task is authored independently of the codex implementation it verifies; T010 must
  bump the advertised-aggregate-count assertion from 34 to 35.
