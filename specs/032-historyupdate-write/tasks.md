# Tasks: Historical Access write — full HistoryUpdate service

**Feature**: `specs/032-historyupdate-write` | **Branch**: `032-historyupdate-write`
**Spec**: [spec.md](spec.md) · **Plan**: [plan.md](plan.md) · **Contract**: [contracts/history-update.md](contracts/history-update.md)

Format: `[ID] [P?] [Story] Description (Spec: Part/§)`. [P] = parallelizable (different files, no
incomplete deps). Every implementation task cites the OPC UA Part/§ so the implementer can ground it
via the reference MCP. Codex implements one task per dispatch (no-git); Claude writes the independent
tests and runs the full suite (codex sandbox cannot bind sockets).

---

## Phase 1: Setup

- [ ] T001 Confirm the existing HistoryUpdate surface compiles and inventory the gap: `HistoryUpdateDetails` variants + dispatch in `async-opcua-server/src/node_manager/history.rs`, the `HistoryStorageBackend` trait in `async-opcua-server/src/history/backend.rs`, and the sqlite `update_data` in `async-opcua-history-sqlite/src/backend.rs` (Spec: Part 11 §6; Part 4 §11.7)
- [ ] T002 [P] Confirm `cargo test -p async-opcua-server --lib`, `-p async-opcua-history-sqlite`, and the integration suite are green at baseline before changes (Spec: SC-005)

## Phase 2: Foundational (BLOCKING — all stories depend on this)

- [X] T003 Extend the `HistoryStorageBackend` trait (`async-opcua-server/src/history/backend.rs`) with `update_structure_data`, `update_event`, `delete_raw_modified`, `delete_at_time`, `delete_event` as `async` methods, each defaulting to `Err(StatusCode::BadHistoryOperationUnsupported)` (Spec: Part 11 §6.8–6.9; contracts/history-update.md)
- [X] T004 Add a `Remove` arm to the `HistoryStorageBackend::update_data` contract/signature note + the trait doc so backends implement all four `PerformUpdateType` modes (Spec: Part 11 §6.8.2; Part 4 §11.7.2)
- [X] T005 Implement `history_update` on `SimpleNodeManager` (`node_manager/memory/simple.rs:574`, and the `InMemoryNodeManager` equivalent) to fetch `self.history_backend` (the existing `RwLock<Option<Arc<dyn HistoryStorageBackend>>>` used by the read path) and route each `HistoryUpdateDetails` variant to the matching backend method, setting node `statusCode` from the result; return `Bad_HistoryOperationUnsupported` when no backend is set (Spec: Part 4 §11.7; mirrors the existing read path)
- [X] T006 In the dispatch, size and set `HistoryUpdateNode::set_operation_results` to the per-entry result vector for per-entry ops; set the operation `statusCode` directly for `DeleteRawModified` (Spec: Part 4 §11.7 result tables)
- [X] T007 [P] Reuse the existing `ModificationInfo { modification_time, update_type: HistoryUpdateType, user_name }` (async-opcua-types) as the modified-history record carried by both backends; define any small internal wrapper in `async-opcua-server/src/history/` (Spec: Part 11 §6.5 / §A.2 ModificationInfo; §3.1 HistoryUpdateType)
- [X] T007a Extend `HistoryStorageBackend::read_raw_modified` to ALSO return `Vec<ModificationInfo>` (e.g. `-> (Vec<DataValue>, Vec<ModificationInfo>, Option<Vec<u8>>)`). Update: (a) the trait def + both existing implementors `async-opcua-history-sqlite/src/backend.rs:270` and `history/event_history.rs:102` (return an empty `ModificationInfo` vec for now); (b) the internal aggregate-path callers `history/backend.rs:92` and sqlite `backend.rs:348` to destructure/ignore the new vec; (c) the two `HistoryModifiedData` construction sites `history/read.rs:19` and `node_manager/memory/simple.rs:371` to populate `modification_infos` from it instead of the hardcoded `None` (Spec: Part 11 §6.5; Part 4 §11.6 ReadRawModifiedDetails) — BLOCKS US4
- [X] T008 [P] Keep the node-manager trait default `history_update` returning `Bad_HistoryOperationUnsupported` and add a regression test asserting an unhistorized manager is unchanged (Spec: FR-011; SC-005)
- [X] T009 [P] [Claude] Unit test: the extended trait's default methods return `Bad_HistoryOperationUnsupported` (no override) (Spec: FR-011)

**Checkpoint**: trait extended + dispatch routes every variant; backends still report unsupported.

---

## Phase 3: User Story 1 — UpdateData all modes on the sqlite backend (P1) 🎯 MVP

**Goal**: sqlite `update_data` implements Insert/Replace/Update/**Remove** with the correct per-value
result codes, recording a modified-history entry on Replace/Update-overwrite.
**Independent test**: drive the Insert/Replace/Update/Remove matrix against the sqlite backend.

- [X] T010 [US1] Add the `Remove` arm to sqlite `update_data` (`async-opcua-history-sqlite/src/backend.rs`): delete the raw row at the timestamp; `Good` if present, `Bad_NoEntryExists` if absent (Spec: Part 11 §6.8.2 Remove; Part 4 §11.7.2)
- [X] T011 [US1] Verify/fix sqlite `update_data` Insert: `Good_EntryInserted` when absent, `Bad_EntryExists` when present (Spec: Part 11 §6.8.2; Part 4 §11.7.2)
- [X] T012 [US1] Verify/fix sqlite `update_data` Replace: `Good_EntryReplaced` when present, `Bad_NoEntryExists` when absent (Spec: Part 11 §6.8.2; Part 4 §11.7.2)
- [X] T013 [US1] Verify/fix sqlite `update_data` Update: insert-or-replace → `Good_EntryInserted` (new) or `Good_EntryReplaced` (overwrite) (Spec: Part 11 §6.8.2; Part 4 §11.7.2)
- [X] T014 [US1] Create the `modified_historical_data` table (migration/DDL) in the sqlite backend keyed by `(node_id, source_timestamp, modification_time)` with an `update_type` column (Spec: Part 11 §6.5)
- [X] T015 [US1] On sqlite Replace and Update-overwrite, append the superseded value to `modified_historical_data` with `update_type` and modification time/user (Spec: Part 11 §6.5)
- [X] T016 [US1] Ensure sqlite `update_data` bounds work to the input vector and never panics on empty values / duplicate timestamps within a batch (Spec: FR-013; Constitution IV)
- [X] T017 [P] [US1] [Claude] sqlite test: Insert into empty → `Good_EntryInserted`; Insert over existing → `Bad_EntryExists`; read-back confirms unchanged (Spec: Part 11 §6.8.2)
- [X] T018 [P] [US1] [Claude] sqlite test: Replace present → `Good_EntryReplaced`; Replace absent → `Bad_NoEntryExists` (Spec: Part 11 §6.8.2)
- [X] T019 [P] [US1] [Claude] sqlite test: Update new vs overwrite → `Good_EntryInserted` / `Good_EntryReplaced` (Spec: Part 11 §6.8.2)
- [X] T020 [P] [US1] [Claude] sqlite test: Remove present → `Good`; Remove absent → `Bad_NoEntryExists`; read-back confirms deletion (Spec: Part 11 §6.8.2)
- [X] T021 [P] [US1] [Claude] sqlite test: empty value array and duplicate-timestamp batch handled without panic (Spec: FR-013)

**Checkpoint**: sqlite UpdateData complete and tested for all four modes.

---

## Phase 4: User Story 2 — In-memory historical-data store (P1)

**Goal**: `InMemoryDataHistory` implements `HistoryStorageBackend` (read_raw_modified + update_data all
modes + modified recording) so the default `InMemoryNodeManager`/`SimpleNodeManager` has history
without sqlite.
**Independent test**: UpdateData matrix + HistoryRead raw against the in-memory store, no sqlite.

- [X] T022 [US2] Create `async-opcua-server/src/history/data_history.rs` with `InMemoryDataHistory` (per-node `BTreeMap<source-ticks, DataValue>` raw store + parallel modified store), `new()`/`with_capacity()` (Spec: Part 11 §5.5; mirror `InMemoryEventHistory`)
- [X] T023 [US2] Implement `HistoryStorageBackend::read_raw_modified` (raw branch) on `InMemoryDataHistory` per the T007a signature: ordered values within [start, end), an empty `ModificationInfo` vec for the raw branch, bounded, continuation consistent with the existing backend (Spec: Part 11 §6.4; Part 4 §11.6)
- [X] T024 [US2] Implement `update_data` Insert/Replace/Update/Remove on `InMemoryDataHistory` with the same result-code matrix as sqlite (Spec: Part 11 §6.8.2; Part 4 §11.7.2)
- [X] T025 [US2] Record a modified-history entry on `InMemoryDataHistory` Replace/Update-overwrite (parallel modified map) (Spec: Part 11 §6.5)
- [X] T026 [US2] Export `InMemoryDataHistory` from `async-opcua-server/src/history/mod.rs` + crate root, mirroring `InMemoryEventHistory` (Spec: FR-009)
- [X] T027 [US2] Bound per-node store size (optional capacity) and ensure no panic on empty/duplicate input (Spec: FR-013; Constitution IV)
- [X] T028 [P] [US2] [Claude] in-memory test: Insert N values → read_raw returns them in time order (Spec: Part 11 §6.4/§6.8.2)
- [X] T029 [P] [US2] [Claude] in-memory test: full Insert/Replace/Update/Remove result matrix matches sqlite/US1 (Spec: Part 11 §6.8.2)
- [X] T030 [P] [US2] [Claude] in-memory test: a manager with no history backend still returns `Bad_HistoryOperationUnsupported` (Spec: FR-011; SC-005)
- [X] T031 [P] [US2] [Claude] in-memory test: empty value array / `start > end` read handled without panic (Spec: FR-013)

**Checkpoint**: default in-memory data history works for UpdateData + raw read.

---

## Phase 5: User Story 3 — Delete by range and by timestamp (P2)

**Goal**: `DeleteRawModified` and `DeleteAtTime` on both backends, recording modified entries on raw
deletion.
**Independent test**: populate, delete by range and by timestamp, assert deletions + per-entry results.

- [X] T032 [US3] Implement sqlite `delete_raw_modified`: delete raw OR modified rows in [start, end) per `is_delete_modified`; operation `Good`, `Bad_NoData` if range empty (Spec: Part 11 §6.9.2; Part 4 §11.7.6)
- [X] T033 [US3] Implement in-memory `delete_raw_modified` with identical semantics (Spec: Part 11 §6.9.2; Part 4 §11.7.6)
- [X] T034 [US3] On raw delete (both backends), record a modified-history entry (`update_type = Delete`) for each removed value (Spec: Part 11 §6.5)
- [X] T035 [US3] Implement sqlite `delete_at_time`: per-timestamp delete; `Good` present, `Bad_NoEntryExists` absent; operationResults sized to req_times (Spec: Part 11 §6.9.3; Part 4 §11.7.7)
- [X] T036 [US3] Implement in-memory `delete_at_time` with identical semantics (Spec: Part 11 §6.9.3; Part 4 §11.7.7)
- [X] T037 [US3] Ensure both delete paths bound work to inputs and never panic on empty lists / inverted ranges (Spec: FR-013; Constitution IV)
- [X] T038 [P] [US3] [Claude] test (both backends): DeleteRawModified non-empty range removes raw values → `Good`; empty range → `Bad_NoData` (Spec: Part 11 §6.9.2)
- [X] T039 [P] [US3] [Claude] test (both backends): DeleteRawModified(is_delete_modified=true) removes modified entries, raw untouched (Spec: Part 11 §6.9.2)
- [X] T040 [P] [US3] [Claude] test (both backends): DeleteAtTime([present, present, absent]) → `[Good, Good, Bad_NoEntryExists]` and read-back confirms (Spec: Part 11 §6.9.3)
- [X] T041 [P] [US3] [Claude] test: empty timestamp list / inverted range handled without panic (Spec: FR-013)

**Checkpoint**: data deletes complete on both backends.

---

## Phase 6: User Story 4 — Modified-history read surface (P2)

**Goal**: `read_raw_modified(is_read_modified=true)` returns the modified entries recorded by US1/US3
with correct `HistoryUpdateType` and modification metadata, on both backends.
**Independent test**: replace + delete, then HistoryRead modified, assert prior values + update type.

- [X] T042 [US4] Implement the modified branch of sqlite `read_raw_modified` (per T007a): read from `modified_historical_data`, returning the superseded `DataValue`s AND a parallel `Vec<ModificationInfo>` (update_type + modification_time + user_name) (Spec: Part 11 §6.5; Part 4 §11.6 ReadRawModifiedDetails)
- [X] T043 [US4] Implement the modified branch of in-memory `read_raw_modified` with identical (DataValues, ModificationInfo) output (Spec: Part 11 §6.5)
- [X] T044 [US4] Capture modification metadata (`modification_time` = server time of the update, `user_name` from the request context, `update_type`) at WRITE time (US1/US3 record paths) so the read branch returns it; confirm `HistoryModifiedData.modification_infos` is populated end-to-end (no longer `None`) (Spec: Part 11 §6.5; §A.2 ModificationInfo)
- [X] T045 [US4] Confirm raw reads (is_read_modified=false) are unaffected by modified entries (Spec: Part 11 §6.4)
- [X] T046 [P] [US4] [Claude] test (both backends): replace V1→V2 at T, read modified at T returns V1 tagged Replace with metadata (Spec: Part 11 §6.5)
- [X] T047 [P] [US4] [Claude] test (both backends): delete value at T, read modified returns it tagged Delete (Spec: Part 11 §6.5)
- [X] T048 [P] [US4] [Claude] test (both backends): never-modified value yields no modified entry; raw read unchanged (Spec: Part 11 §6.4/§6.5)

**Checkpoint**: modified-history readable end-to-end on both backends.

---

## Phase 7: User Story 5 — Annotation history write (P2)

**Goal**: `UpdateStructureData` writes `Annotation` history (Insert/Replace/Update/Remove) on both
backends; read via the existing annotation path.
**Independent test**: write annotations, read them back.

- [X] T049 [US5] Implement sqlite `update_structure_data` for `Annotation` values: Insert/Replace/Update/Remove with the UpdateData result matrix, into the annotation store read by `read_annotations` (Spec: Part 11 §6.8.3; Part 4 §11.7.3)
- [X] T050 [US5] Add an in-memory annotation store + `update_structure_data` on `InMemoryDataHistory`, plus `read_annotations` (Spec: Part 11 §6.8.3)
- [X] T051 [US5] Validate that non-`Annotation` structure payloads return a per-entry error rather than panicking (Spec: FR-013; Part 11 §6.8.3)
- [X] T052 [P] [US5] [Claude] test (both backends): Insert annotation → `Good_EntryInserted`, read_annotations returns it (Spec: Part 11 §6.8.3)
- [X] T053 [P] [US5] [Claude] test (both backends): Replace + Remove annotation at T behave per the result matrix (Spec: Part 11 §6.8.3)

**Checkpoint**: annotation write complete on both backends.

---

## Phase 8: User Story 6 — Event history write (P3)

**Goal**: `UpdateEvent` (Insert/Replace/Update) and `DeleteEvent` (by EventId) on both backends.
**Independent test**: insert events, read via event path, delete by EventId.

- [X] T054 [US6] Implement in-memory `update_event` on `InMemoryEventHistory` (`event_history.rs`): store events keyed by EventId per the supplied EventFilter select clauses; Insert/Replace/Update matrix (Spec: Part 11 §6.8.4; Part 4 §11.7.4)
- [X] T055 [US6] Implement in-memory `delete_event` on `InMemoryEventHistory`: delete by EventId list; per-id `Good`/`Bad_NoEntryExists` (Spec: Part 11 §6.9.4; Part 4 §11.7.8)
- [X] T056 [US6] Implement sqlite `update_event`: persist events keyed by EventId, Insert/Replace/Update matrix, read via `read_events` (Spec: Part 11 §6.8.4; Part 4 §11.7.4)
- [X] T057 [US6] Implement sqlite `delete_event`: delete by EventId list with per-id results (Spec: Part 11 §6.9.4; Part 4 §11.7.8)
- [X] T058 [US6] Bound event-write work to the input list and reject malformed event field lists per-entry without panic (Spec: FR-013; Constitution IV)
- [X] T059 [P] [US6] [Claude] test (both backends): UpdateEvent(Insert) then read_events returns the event → `Good_EntryInserted` (Spec: Part 11 §6.8.4)
- [X] T060 [P] [US6] [Claude] test (both backends): UpdateEvent(Replace) replaces an existing event (Spec: Part 11 §6.8.4)
- [X] T061 [P] [US6] [Claude] test (both backends): DeleteEvent([present, absent]) → `[Good, Bad_NoEntryExists]`, read-back confirms (Spec: Part 11 §6.9.4)

**Checkpoint**: event-history write complete on both backends.

---

## Phase 9: User Story 7 — End-to-end server + client wiring (P3)

**Goal**: a server exposes a historized variable + event source accepting HistoryUpdate; a client
drives the full surface; integration tests cover it.
**Independent test**: run the integration server, issue each operation from the client, read back.

- [ ] T062 [US7] Wire `InMemoryDataHistory` into a node manager via the existing `set_history_backend(Arc::new(InMemoryDataHistory::new()))` so a historized variable accepts HistoryUpdate + HistoryRead on the default path (Spec: Part 11 §5.5; FR-009)
- [ ] T063 [US7] The client `Session::history_update` + `history_update_data` already exist (async-opcua-client/src/session/services/attributes.rs); confirm they accept every `HistoryUpdateDetails` variant and add per-operation convenience helpers (delete/event/annotation) only where missing (Spec: Part 4 §11.7)
- [ ] T064 [US7] Expose a historized variable + event source in the demo server (`samples/demo-server`) accepting HistoryUpdate (Spec: FR-012)
- [ ] T065 [P] [US7] [Claude] integration test `async-opcua/tests/integration/history_update.rs`: client UpdateData → HistoryRead raw round-trip on the default in-memory path (Spec: SC-004)
- [ ] T066 [P] [US7] [Claude] integration test: client Replace then HistoryRead modified returns the superseded value (Spec: SC-003)
- [ ] T067 [P] [US7] [Claude] integration test: client DeleteAtTime + DeleteRawModified per-entry results round-trip (Spec: SC-002)
- [ ] T068 [P] [US7] [Claude] integration test: a session lacking InsertHistory/ModifyHistory/DeleteHistory is denied (existing RBAC, enforced) (Spec: Part 3 §8.55; FR-010)
- [ ] T069 [P] [US7] [Claude] integration test: HistoryUpdate on an unhistorized node returns `Bad_HistoryOperationUnsupported` per node (Spec: FR-011)

**Checkpoint**: full write surface usable and demonstrated end-to-end.

---

## Phase 10: Polish & cross-cutting

- [ ] T070 [P] Run the FULL `cargo test -p async-opcua-server` (all binaries) + `-p async-opcua-history-sqlite` + the integration suite — zero regressions (Spec: SC-005)
- [ ] T071 [P] Build + test under `--no-default-features` and `--all-features`; fix any feature-gating gaps (Spec: SC-006; FR-014)
- [ ] T072 [P] `cargo clippy --workspace --all-targets` (default + no-default legs) + `cargo fmt --all --check` clean (Spec: Constitution V)
- [ ] T073 [P] Security review of the write path: per-entry results, bounded allocations, no panic on empty/inverted/duplicate input, RBAC gate intact (Spec: Constitution IV)
- [ ] T074 [P] Confirm per-operation result codes match Part 4 §11.7 tables (not whole-request failure) across all six operations (Spec: Part 4 §11.7; SC-002)
- [ ] T075 [P] Add a docs section (e.g. `docs/server.md` or `docs/advanced_server.md`) on HistoryUpdate + the in-memory data history backend, mirroring quickstart.md (Spec: FR-012)
- [ ] T076 Update `specs/SESSION-HANDOFF.md` + memory with the HistoryUpdate feature outcome (Spec: project process)

---

## Dependencies & order

- **Phase 2 (Foundational) blocks everything** — the trait extension + dispatch must land first.
- **T007a (extend `read_raw_modified` to return `Vec<ModificationInfo>`) is foundational and BLOCKS US4** — it changes the shared trait signature, so US1/US2 implementors must adopt the final signature up front (Constitution II, no rework).
- **US1 + US2 (P1)** establish UpdateData + the modified-recording on both backends; **US4** reads what
  US1/US3 record (so US4 follows US3).
- **US3** (deletes) depends on US1/US2 storage. **US5** (annotations) and **US6** (events) are
  independent of US3/US4 and of each other. **US7** depends on US1–US2 (needs a working backend).
- One PR per user story (squash-merged on the fork). Codex one task per dispatch; Claude authors the
  `[Claude]` test tasks independently and runs the full suite each story.

## Implementation strategy

MVP = Phase 2 + US1 + US2 (UpdateData on both backends). Each subsequent story is an independently
shippable increment that supersedes more `Bad_HistoryOperationUnsupported` stubs.
