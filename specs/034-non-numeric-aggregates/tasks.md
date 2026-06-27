# Tasks: Non-numeric (any-value-type) HistoryRead aggregates

**Feature**: `specs/034-non-numeric-aggregates` | **Branch**: `034-non-numeric-aggregates`
**Spec**: [spec.md](spec.md) · **Plan**: [plan.md](plan.md) · **Contract**: [contracts/aggregates.md](contracts/aggregates.md)

Format: `[ID] [P?] [Story?] Description (Spec: Part/§)`. Tasks are **atomic** (one concern each) and
**cite the OPC UA Part 13 §** they touch so the implementer grounds them via the reference MCP. [P] =
parallelizable (different concern, no incomplete deps). All engine work is in
`async-opcua-server/src/aggregates/engine.rs`; Claude authors the `[Claude]` test tasks (in
`async-opcua-server/tests/aggregates_tests.rs` and/or engine.rs `#[cfg(test)]`) and runs the suite.

---

## Phase 1: Setup

- [X] T001 [P] Confirm the aggregate suite is green at baseline: `cargo test -p async-opcua-server` (engine unit tests + `tests/aggregates_tests.rs`) (Spec: SC-004)
- [X] T002 Inventory the touch points in `aggregates/engine.rs`: `variant_to_f64` (L111), `good_numeric_points` (L325), `state_regions`/`StateRegion` (L271/L358), `agg_count` (L1022), `agg_number_of_transitions` (L1153), `agg_duration_in_state_zero/non_zero` (L1143), `agg_duration_good/bad`, `agg_percent_good/bad`, `agg_worst_quality/2`; and the existing numeric Count/NumberOfTransitions vectors in `tests/aggregates_tests.rs` (Spec: Part 13 §5.4.3.21 / §5.4.3.24)

## Phase 2: Foundational (BLOCKING — shared test fixtures)

- [X] T003 [Claude] Add non-numeric `DataValue` test fixtures in `tests/aggregates_tests.rs` — e.g. `bool_dv(value, sec, status)`, `string_dv(value, sec)` mirroring the existing `good(value, sec)` numeric helper — reused by US1–US4 tests (Spec: Part 13 §5.4.3)

**Checkpoint**: baseline known-green; typed fixtures available. No engine behavior changed yet.

---

## Phase 3: User Story 1 — Count works for non-numeric sources (P1) 🎯 MVP

**Goal**: Count returns the number of Good-status raw points regardless of value type.
**Independent test**: a Boolean series with 5 good points reads Count = 5 (was 0); numeric unchanged.

- [X] T004 [US1] Add a `good_status_point_count(input)` helper in `engine.rs` that counts points whose StatusCode is Good (`status.is_none_or(is_good)`, i.e. Good-only — Uncertain is NOT counted, per §5.4.3.21), independent of value type — do NOT touch `good_numeric_points` (Spec: Part 13 §5.4.3.21 Count)
- [X] T005 [US1] Rewrite `agg_count` to use `good_status_point_count` instead of `good_numeric_points(input).len()`; leave the result StatusCode (`percent_values_status`) and timestamps unchanged (Spec: Part 13 §5.4.3.21)
- [X] T006 [P] [US1] [Claude] Test: a Boolean source with N good raw points in an interval reads Count = N for N ∈ {0, 1, 5} (Spec: SC-001; §5.4.3.21)
- [X] T007 [P] [US1] [Claude] Test: a String source with good points + one Bad-status point reads Count = (good count only), independent of value type (Spec: §5.4.3.21)
- [X] T008 [P] [US1] [Claude] Test: a numeric (Double) source returns the SAME Count as before this change (regression) (Spec: FR-007; SC-004)

**Checkpoint**: Count is value-type-independent; numeric Count unchanged.

---

## Phase 4: User Story 2 — NumberOfTransitions value-change semantics (P2) — CORRECTS numeric

**Goal**: NumberOfTransitions counts value changes vs the previous non-Bad value, for any value type.
**Independent test**: a Boolean flipping 4× reads 4; a numeric 1→2→3 reads 2 (previously 0).

- [X] T009 [US2] Rewrite `agg_number_of_transitions` in `engine.rs`: order the prior **non-Bad** value + in-interval **non-Bad** points (Good OR Uncertain — wider than Count's Good-only, per §5.4.3.24) by timestamp and count consecutive pairs whose `Variant` value differs (`!=`); remove the `variant_to_f64` + zero-crossing `(w0==0.0)!=(w1==0.0)` logic; keep the result StatusCode (`percent_values_status`) and timestamps (Spec: Part 13 §5.4.3.24 NumberOfTransitions)
- [X] T010 [US2] Update the existing numeric NumberOfTransitions expected values in `tests/aggregates_tests.rs` to the spec-correct value-change counts and add an inline comment citing §5.4.3.24 (the prior values counted zero-crossings and were wrong) (Spec: FR-007; §5.4.3.24)
- [X] T011 [P] [US2] [Claude] Test: a Boolean source that changes value 4× within the interval reads NumberOfTransitions = 4 (Spec: SC-002; §5.4.3.24)
- [X] T012 [P] [US2] [Claude] Test: an Enumeration/String source with no value change reads 0; a numeric 1.0→2.0→3.0 source reads 2 (the corrected value) (Spec: §5.4.3.24; FR-007)
- [X] T012a [P] [US2] [Claude] Test: the Good-vs-non-Bad distinction — an interval with an Uncertain-status point that changes value contributes a transition for NumberOfTransitions (non-Bad) but is excluded from Count (Good-only); pins the §5.4.3.21-vs-§5.4.3.24 status difference (Spec: §5.4.3.21 / §5.4.3.24)

**Checkpoint**: NumberOfTransitions is value-change based and correct for numeric and non-numeric.

---

## Phase 5: User Story 3 — Status/quality aggregates are value-type-agnostic (P2) — verify + lock in

**Goal**: confirm DurationGood/Bad, PercentGood/Bad, WorstQuality/2 ignore value type and lock it in.
**Independent test**: numeric vs Boolean source with the same status pattern → equal results.

- [X] T013 [US3] Confirm (read-only) that `agg_duration_good/bad`, `agg_percent_good/bad`, `agg_worst_quality/2` key only on StatusCode and that `state_regions` keeps every point's status regardless of value type; record the finding (no code change expected — if any of them is found to filter on `variant_to_f64`, fix it to be status-only) (Spec: Part 13 §5.4.3.31/§5.4.3.32 DurationGood/Bad, §5.4.3.33/§5.4.3.34 PercentGood/Bad, §5.4.3.35/§5.4.3.36 WorstQuality/2)
- [X] T014 [P] [US3] [Claude] Test: a numeric source and a non-numeric source with an identical per-point Good/Bad status pattern return EQUAL DurationGood, DurationBad, PercentGood, PercentBad (Spec: SC-003; §5.4.3.31–§5.4.3.34)
- [X] T015 [P] [US3] [Claude] Test: WorstQuality and WorstQuality2 on a non-numeric source return the worst StatusCode in the interval, independent of value type (Spec: §5.4.3.35 / §5.4.3.36)

**Checkpoint**: status aggregates proven type-agnostic and pinned by tests.

---

## Phase 6: User Story 4 — DurationInStateZero/NonZero generalize to Boolean (P3)

**Goal**: in-state durations classify a value's zero/non-zero state across types.
**Independent test**: a Boolean false-then-true series splits the interval into Zero/NonZero durations.

- [X] T016 [US4] Add a `ZeroState { Zero, NonZero, Unknown }` enum + `classify(value: Option<&Variant>) -> ZeroState` in `engine.rs`: null/`Empty` → Zero, Boolean false → Zero / true → NonZero, numeric `==0` → Zero / `!=0` → NonZero (reuse `variant_to_f64`), any other type → Unknown (Spec: Part 13 §5.4.3.22 / §5.4.3.23; data-model.md)
- [X] T017 [US4] Add a `zero_state: ZeroState` field to `StateRegion`, computed via `classify` at knot construction in `state_regions`; keep the existing numeric `== 0.0` partition byte-identical for numeric sources (Spec: FR-007; §5.4.3.22/23)
- [X] T018 [US4] Rewrite `agg_duration_in_state_zero` to sum regions with `zero_state == Zero` and `agg_duration_in_state_non_zero` to sum `zero_state == NonZero` (Unknown excluded from both); drop the `region.value == Some(0.0)` checks (Spec: Part 13 §5.4.3.22 / §5.4.3.23)
- [X] T019 [P] [US4] [Claude] Test: a Boolean source that is `false` for the first span and `true` for the second reads DurationInStateZero = first span and DurationInStateNonZero = second (Spec: §5.4.3.22 / §5.4.3.23)
- [X] T020 [P] [US4] [Claude] Test: a numeric 0/non-0 series returns the SAME in-state durations as before (regression); a ByteString source is excluded from both and does not panic (Spec: FR-007; SC-006)

**Checkpoint**: in-state durations work for Boolean and numeric; exotic types are safely excluded.

---

## Phase 7: Polish & cross-cutting

- [X] T021 [P] [Claude] No-panic matrix test: feed Boolean, String, Enumeration, Guid, ByteString, DateTime, null (`Variant::Empty`), and Bad-status values through Count / NumberOfTransitions / DurationGood / DurationInStateZero and assert no panic (Spec: FR-008; SC-006; Constitution IV)
- [X] T021a [P] [Claude] Test: AnnotationCount (`i=2351`) still reports `Bad_AggregateNotSupported` (confirms it stays out of scope and this feature did not accidentally enable it) (Spec: FR-009; §5.4.3.25)
- [X] T022 [P] Run the FULL `cargo test -p async-opcua-server` — all green except the intentionally-updated numeric NumberOfTransitions vectors (T010); confirm no other numeric aggregate result changed (Spec: SC-004)
- [X] T023 [P] Build + `cargo clippy` under `--no-default-features` and `--all-features`; `cargo fmt --all --check` clean (Spec: FR-010; SC-005; Constitution V)
- [X] T024 Update `specs/completeness-backlog.md` (aggregates follow-on: non-numeric aggregates done; note the NumberOfTransitions numeric correction) + memory (Spec: project process)

---

## Dependencies & MVP

- **Setup (T001–T002)** → **Foundational (T003)** → user stories.
- **US1 (P1, T004–T008)** is the MVP: it fixes the headline Count = 0 bug and is independently shippable.
- **US2/US3/US4** are independent of each other (different aggregate functions); US4 adds a field to
  `StateRegion` but does not alter the status handling US3 relies on. Recommended order US1 → US2 → US3
  → US4 (priority order); one PR per user story, Polish (T021–T024) folded into the final PR.
- Each `[Claude]` test task is written independently of the codex implementation it verifies.
