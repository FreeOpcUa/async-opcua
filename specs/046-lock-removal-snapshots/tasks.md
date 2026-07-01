# Tasks: Lock Removal and Snapshot Concurrency

**Input**: Design documents from `/specs/046-lock-removal-snapshots/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/
**Tests**: Required by FR-003, FR-006, FR-010, and each slice contract.

## Format: `[ID] [P?] [Story?] Description`

- **[P]**: Can run in parallel because it touches different files and has no dependency on an incomplete task.
- **[Story]**: Required only for user-story phase tasks.
- **Atomicity rule**: Each task is one coherent, indivisible job with one primary artifact or one command to run.
- **OPC UA grounding rule**: Protocol-facing tests and gate decisions cite the controlling OPC UA Part and clause in the named artifact.

## Phase 1: Setup (Shared Baselines)

**Purpose**: Establish one baseline artifact with separate, independently reviewable entries.

- [X] T001 Add the TypeTree lock-audit baseline section to `specs/046-lock-removal-snapshots/baseline.md`
- [X] T002 Add the response-size global-state baseline section to `specs/046-lock-removal-snapshots/baseline.md`
- [X] T003 Add the subscription route lock baseline section to `specs/046-lock-removal-snapshots/baseline.md`
- [X] T004 Add the PubSub config/cache lock baseline section to `specs/046-lock-removal-snapshots/baseline.md`
- [X] T005 Add the SQLite history lock baseline section to `specs/046-lock-removal-snapshots/baseline.md`
- [X] T006 Add the SecureChannel renewal lock baseline section to `specs/046-lock-removal-snapshots/baseline.md`
- [X] T007 Add the current clippy await-holding-lock result to `specs/046-lock-removal-snapshots/baseline.md`
- [X] T008 Add the controlled Read benchmark baseline placeholder to `specs/046-lock-removal-snapshots/baseline.md`
- [X] T009 Add the controlled Write benchmark baseline placeholder to `specs/046-lock-removal-snapshots/baseline.md`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Create shared documentation scaffolding before implementation tasks begin.

- [X] T010 Add the slice-note template to `specs/046-lock-removal-snapshots/slice-notes.md`
- [X] T011 Add the TypeTree snapshot dependency decision for existing workspace primitives versus `arc-swap` to `specs/046-lock-removal-snapshots/baseline.md`
- [X] T012 Add the TypeTree focused test command list to `specs/046-lock-removal-snapshots/baseline.md`
- [X] T013 Add the Browse/Query/Read/Write/subscription regression command list to `specs/046-lock-removal-snapshots/baseline.md`
- [X] T014 Add the response-size focused test command list to `specs/046-lock-removal-snapshots/baseline.md`
- [X] T015 Add the subscription route contention measurement command/source to `specs/046-lock-removal-snapshots/baseline.md`
- [X] T016 Add the PubSub config/cache contention measurement command/source to `specs/046-lock-removal-snapshots/baseline.md`
- [X] T017 Add the SQLite history contention measurement command/source to `specs/046-lock-removal-snapshots/baseline.md`
- [X] T018 Add the SecureChannel renewal contention measurement command/source to `specs/046-lock-removal-snapshots/baseline.md`
- [X] T019 Add the controlled benchmark comparison rule from SC-004 to `specs/046-lock-removal-snapshots/baseline.md`
- [X] T020 Create the OPC UA clause matrix header in `specs/046-lock-removal-snapshots/opcua-clause-matrix.md`
- [X] T021 Add TypeTree slice rows for OPC-10000-4 Browse, Query, Read, Write, and Subscription clauses to `specs/046-lock-removal-snapshots/opcua-clause-matrix.md`
- [X] T022 Add response-size and P3 gate rows for OPC-10000-4, OPC-10000-6, OPC-10000-11, and OPC-10000-14 clauses to `specs/046-lock-removal-snapshots/opcua-clause-matrix.md`

**Checkpoint**: Baseline, slice-note, and OPC UA clause-matrix artifacts exist before any code change.

---

## Phase 3: User Story 1 - Type Metadata Reads Avoid Hot Locks (Priority: P1) MVP

**Goal**: Publish immutable TypeTree snapshots and update service hot paths to read snapshots without acquiring the global TypeTree `RwLock`.

**Independent Test**: TypeTree snapshot tests fail before implementation, then pass with existing OPC UA service regression tests unchanged.

### Tests for User Story 1

- [X] T023 [US1] Add `hot_path_reads_use_type_tree_snapshot` to `async-opcua-server/tests/type_tree_snapshot.rs`
- [X] T024 [US1] Add `browse_reference_description_preserves_part4_5_9_2_2_and_7_29` to `async-opcua-server/tests/type_tree_snapshot.rs`
- [X] T025 [US1] Add `query_type_path_preserves_part4_b_2_3` to `async-opcua-server/tests/type_tree_snapshot.rs`
- [X] T026 [US1] Add `published_snapshot_is_complete_after_startup` to `async-opcua-server/tests/type_tree_snapshot.rs`
- [X] T027 [US1] Add `custom_type_tree_getter_remains_compatible` to `async-opcua-server/tests/type_tree_snapshot.rs`
- [X] T028 [US1] Run `cargo test -p async-opcua-server type_tree_snapshot -- --nocapture` before implementation for `async-opcua-server/tests/type_tree_snapshot.rs`
- [X] T029 [US1] Record the TypeTree expected-red test result in `specs/046-lock-removal-snapshots/slice-notes.md`

### Implementation for User Story 1

- [X] T030 [US1] Add the immutable `TypeTreeSnapshot` wrapper in `async-opcua-server/src/info.rs`
- [X] T031 [US1] Add TypeTree snapshot storage to `async-opcua-server/src/info.rs`
- [X] T032 [US1] Add the TypeTree snapshot publication method to `async-opcua-server/src/info.rs`
- [X] T033 [US1] Add the TypeTree snapshot read accessor to `async-opcua-server/src/info.rs`
- [X] T034 [US1] Update default TypeTree-for-user access to use snapshots in `async-opcua-server/src/node_manager/context.rs`
- [X] T035 [US1] Publish the startup TypeTree snapshot from `async-opcua-server/src/node_manager/memory/mod.rs`
- [X] T036 [US1] Wire TypeTree snapshot publication through server startup in `async-opcua-server/src/server.rs`
- [X] T037 [US1] Preserve the public TypeTree accessor compatibility path in `async-opcua-server/src/server_handle.rs`
- [X] T038 [US1] Update the server namespace-index helper to use snapshot reads in `async-opcua-server/src/server_handle.rs`
- [X] T039 [US1] Update request-context construction in `async-opcua-server/src/session/message_handler.rs`
- [X] T040 [US1] Update session actor context construction in `async-opcua-server/src/session/actor.rs`
- [X] T041 [US1] Update view-service direct TypeTree reads in `async-opcua-server/src/session/services/view.rs`
- [X] T042 [US1] Update query-service TypeTree access in `async-opcua-server/src/session/services/query.rs`
- [X] T043 [US1] Update monitored-item TypeTree access in `async-opcua-server/src/session/services/monitored_items.rs`
- [X] T044 [US1] Update subscription actor TypeTree storage in `async-opcua-server/src/subscriptions/actor.rs`
- [X] T045 [US1] Publish TypeTree snapshots after namespace TypeTree mutations in `async-opcua-server/src/address_space/utils.rs`
- [X] T046 [US1] Update diagnostics TypeTree reads in `async-opcua-server/src/diagnostics/node_manager.rs`

### Verification for User Story 1

- [X] T047 [US1] Run `cargo test -p async-opcua-server type_tree_snapshot -- --nocapture` after implementation for `async-opcua-server/tests/type_tree_snapshot.rs`
- [X] T048 [US1] Record the TypeTree snapshot test result in `specs/046-lock-removal-snapshots/slice-notes.md`
- [X] T049 [US1] Run the focused Browse regression command recorded in `specs/046-lock-removal-snapshots/baseline.md`
- [X] T050 [US1] Record the Browse regression result with OPC-10000-4 5.9.2.2 and 7.29 references in `specs/046-lock-removal-snapshots/slice-notes.md`
- [X] T051 [US1] Run the focused Query regression command recorded in `specs/046-lock-removal-snapshots/baseline.md`
- [X] T052 [US1] Record the Query regression result with OPC-10000-4 B.2.3 references in `specs/046-lock-removal-snapshots/slice-notes.md`
- [X] T053 [US1] Run the focused Read regression command recorded in `specs/046-lock-removal-snapshots/baseline.md`
- [X] T054 [US1] Record the Read regression result with OPC-10000-4 5.11.2.2 references in `specs/046-lock-removal-snapshots/slice-notes.md`
- [X] T055 [US1] Run the focused Write regression command recorded in `specs/046-lock-removal-snapshots/baseline.md`
- [X] T056 [US1] Record the Write regression result with OPC-10000-4 5.11.4.2 references in `specs/046-lock-removal-snapshots/slice-notes.md`
- [X] T057 [US1] Run the focused subscription regression command recorded in `specs/046-lock-removal-snapshots/baseline.md`
- [X] T058 [US1] Record the subscription regression result with OPC-10000-4 5.13 and 5.14 references in `specs/046-lock-removal-snapshots/slice-notes.md`
- [X] T059 [US1] Run the controlled Read benchmark command recorded in `specs/046-lock-removal-snapshots/baseline.md`
- [X] T060 [US1] Record the TypeTree Read benchmark result in `specs/046-lock-removal-snapshots/slice-notes.md`
- [X] T061 [US1] Run the controlled Write benchmark command recorded in `specs/046-lock-removal-snapshots/baseline.md`
- [X] T062 [US1] Record the TypeTree Write benchmark result in `specs/046-lock-removal-snapshots/slice-notes.md`
- [X] T063 [US1] Record the SC-004 benchmark comparison conclusion in `specs/046-lock-removal-snapshots/slice-notes.md`

**Checkpoint**: TypeTree hot-path reads are snapshot-based, focused OPC UA service tests pass, and benchmark samples are recorded.

---

## Phase 4: User Story 2 - Response Size Enforcement Avoids Global Contention (Priority: P2)

**Goal**: Move response-size limit enforcement away from global hot-path lock state while preserving protocol behavior.

**Independent Test**: Response-size tests cover zero limit, nonzero limit, oversized response, concurrent channels, and cleanup.

### Tests for User Story 2

- [X] T064 [US2] Add `zero_limit_preserves_part4_5_7_2_2_unbounded_response_size` to `async-opcua-core/tests/response_limit_state.rs`
- [X] T065 [US2] Add `nonzero_limit_applies_part4_5_7_2_2_response_body_limit` to `async-opcua-core/tests/response_limit_state.rs`
- [X] T066 [US2] Add `oversized_response_returns_part4_5_3_bad_response_too_large` to `async-opcua-core/tests/response_limit_state.rs`
- [X] T067 [US2] Add `bad_response_too_large_matches_part4_7_38_2_status` to `async-opcua-core/tests/response_limit_state.rs`
- [X] T068 [US2] Add `concurrent_channels_use_independent_response_limits` to `async-opcua-core/tests/response_limit_state.rs`
- [X] T069 [US2] Add `closed_channel_drops_response_limit_state` to `async-opcua-core/tests/response_limit_state.rs`
- [X] T070 [US2] Run `cargo test -p async-opcua-core response_limit_state -- --nocapture` before implementation for `async-opcua-core/tests/response_limit_state.rs`
- [X] T071 [US2] Record the response-limit expected-red test result in `specs/046-lock-removal-snapshots/slice-notes.md`

### Implementation for User Story 2

- [X] T072 [US2] Add per-channel response-limit storage to `async-opcua-core/src/comms/secure_channel.rs`
- [X] T073 [US2] Add the response-limit setter to `async-opcua-core/src/comms/secure_channel.rs`
- [X] T074 [US2] Add the response-limit getter to `async-opcua-core/src/comms/secure_channel.rs`
- [X] T075 [US2] Replace response-limit reads with the SecureChannel getter in `async-opcua-core/src/comms/buffer.rs`
- [X] T076 [US2] Remove the global response-limit map from `async-opcua-core/src/comms/buffer.rs`
- [X] T077 [US2] Update response-limit refresh in `async-opcua-server/src/session/manager.rs`
- [X] T078 [US2] Update response-limit propagation in `async-opcua-server/src/session/controller.rs`
- [X] T079 [US2] Record the security-focused review for response-size transport changes in `specs/046-lock-removal-snapshots/slice-notes.md`

### Verification for User Story 2

- [X] T080 [US2] Run `cargo test -p async-opcua-core response_limit_state -- --nocapture` after implementation for `async-opcua-core/tests/response_limit_state.rs`
- [X] T081 [US2] Record the response-limit unit test result with OPC-10000-4 5.7.2.2, 5.3, and 7.38.2 references in `specs/046-lock-removal-snapshots/slice-notes.md`
- [X] T082 [US2] Run `cargo test -p async-opcua-server max_response_message_size -- --nocapture` for `async-opcua-server/tests/security_tests.rs`
- [X] T083 [US2] Record the maxResponseMessageSize integration result with OPC-10000-4 5.7.2.2 references in `specs/046-lock-removal-snapshots/slice-notes.md`
- [X] T084 [US2] Run the clippy await-holding-lock command recorded in `specs/046-lock-removal-snapshots/baseline.md`
- [X] T085 [US2] Record the response-size clippy result in `specs/046-lock-removal-snapshots/slice-notes.md`

**Checkpoint**: Response-size enforcement is channel-owned or hot-path lock-free with unchanged OPC UA Part 4 behavior.

---

## Phase 5: User Story 3 - Riskier Lock Removals Are Measurement-Gated (Priority: P3)

**Goal**: Produce evidence and focused tests for higher-risk lock boundaries before any follow-up implementation feature is created.

**Independent Test**: Each boundary has a baseline/proof gate and a written gate decision tied to OPC UA clauses.

### Subscription Route Gate

- [X] T086 [US3] Record subscription route contention evidence using the command/source in `specs/046-lock-removal-snapshots/baseline.md`
- [X] T087 [US3] Add OPC-10000-4 5.13.2.1 monitored-item create route test to `async-opcua-server/tests/subscription_route_snapshot.rs`
- [X] T088 [US3] Add OPC-10000-4 5.13.2.1 monitored-item delete route test to `async-opcua-server/tests/subscription_route_snapshot.rs`
- [X] T089 [US3] Add OPC-10000-4 5.13.3.1 monitored-item modify route test to `async-opcua-server/tests/subscription_route_snapshot.rs`
- [X] T090 [US3] Add OPC-10000-4 6.7 subscription transfer route test to `async-opcua-server/tests/subscription_route_snapshot.rs`
- [X] T091 [US3] Add OPC-10000-4 5.14.1.2 republish route test to `async-opcua-server/tests/subscription_route_snapshot.rs`
- [X] T092 [US3] Add OPC-10000-4 5.14.1.2 Publish notification route test to `async-opcua-server/tests/subscription_route_snapshot.rs`
- [X] T093 [US3] Run `cargo test -p async-opcua-server subscription_route_snapshot -- --nocapture` for `async-opcua-server/tests/subscription_route_snapshot.rs`
- [X] T094 [US3] Record the subscription route gate test result in `specs/046-lock-removal-snapshots/slice-notes.md`
- [X] T095 [US3] Write the subscription route gate decision with OPC-10000-4 5.13, 5.14, and 6.7 references in `specs/046-lock-removal-snapshots/slice-notes.md`

### PubSub Gate

- [X] T096 [US3] Record PubSub config/cache contention evidence using the command/source in `specs/046-lock-removal-snapshots/baseline.md`
- [X] T097 [US3] Add OPC-10000-14 9.1.5.2 PubSubConnection configuration test to `async-opcua-pubsub/tests/config_snapshot_consistency.rs`
- [X] T098 [US3] Add OPC-10000-14 9.1.7.2 DataSetWriter configuration test to `async-opcua-pubsub/tests/config_snapshot_consistency.rs`
- [X] T099 [US3] Add OPC-10000-14 9.1.10.1 PubSubStatus consistency test to `async-opcua-pubsub/tests/config_snapshot_consistency.rs`
- [X] T100 [US3] Add OPC-10000-14 5.4.1.2 transport message sending cache test to `async-opcua-pubsub/tests/config_snapshot_consistency.rs`
- [X] T101 [US3] Run `cargo test -p async-opcua-pubsub config_snapshot_consistency -- --nocapture` for `async-opcua-pubsub/tests/config_snapshot_consistency.rs`
- [X] T102 [US3] Record the PubSub gate test result in `specs/046-lock-removal-snapshots/slice-notes.md`
- [X] T103 [US3] Write the PubSub gate decision with OPC-10000-14 5.4.1.2, 9.1.5.2, 9.1.7.2, and 9.1.10.1 references in `specs/046-lock-removal-snapshots/slice-notes.md`

### SQLite History Gate

- [X] T104 [US3] Record SQLite history contention evidence using the command/source in `specs/046-lock-removal-snapshots/baseline.md`
- [X] T105 [US3] Add OPC-10000-11 6.3 continuation-point test to `async-opcua-history-sqlite/tests/history_lock_scaling.rs`
- [X] T106 [US3] Add OPC-10000-4 5.11.3.2 HistoryRead nodesToRead test to `async-opcua-history-sqlite/tests/history_lock_scaling.rs`
- [X] T107 [US3] Add SQLite concurrent-read test to `async-opcua-history-sqlite/tests/history_lock_scaling.rs`
- [X] T108 [US3] Add SQLite write-during-read test to `async-opcua-history-sqlite/tests/history_lock_scaling.rs`
- [X] T109 [US3] Run `cargo test -p async-opcua-history-sqlite history_lock_scaling -- --nocapture` for `async-opcua-history-sqlite/tests/history_lock_scaling.rs`
- [X] T110 [US3] Record the SQLite history gate test result in `specs/046-lock-removal-snapshots/slice-notes.md`
- [X] T111 [US3] Write the SQLite history gate decision with OPC-10000-11 6.3 and OPC-10000-4 5.11.3.2 references in `specs/046-lock-removal-snapshots/slice-notes.md`

### SecureChannel Renewal Gate

- [X] T112 [US3] Record SecureChannel renewal contention evidence using the command/source in `specs/046-lock-removal-snapshots/baseline.md`
- [X] T113 [US3] Add OPC-10000-6 6.7.4 concurrent-renewal-waiters test to `async-opcua-client/tests/secure_channel_renewal_singleflight.rs`
- [X] T114 [US3] Add OPC-10000-6 6.7.4 renewal-cancellation test to `async-opcua-client/tests/secure_channel_renewal_singleflight.rs`
- [X] T115 [US3] Add OPC-10000-6 6.7.4 renewal-failure test to `async-opcua-client/tests/secure_channel_renewal_singleflight.rs`
- [X] T116 [US3] Add OPC-10000-6 6.7.2.4 renewal-request-ordering test to `async-opcua-client/tests/secure_channel_renewal_singleflight.rs`
- [X] T117 [US3] Run `cargo test -p async-opcua-client secure_channel_renewal_singleflight -- --nocapture` for `async-opcua-client/tests/secure_channel_renewal_singleflight.rs`
- [X] T118 [US3] Record the SecureChannel renewal gate test result in `specs/046-lock-removal-snapshots/slice-notes.md`
- [X] T119 [US3] Write the SecureChannel renewal gate decision with OPC-10000-6 6.7.4 and 6.7.2.4 references in `specs/046-lock-removal-snapshots/slice-notes.md`

**Checkpoint**: P3 boundaries have evidence, focused OPC UA clause-grounded tests, test results, and gate decisions; implementation is deferred to a follow-up feature when a gate passes.

---

## Phase 6: Polish and Cross-Cutting Verification

**Purpose**: Confirm the completed slices preserve performance, functionality, and protocol fidelity.

- [X] T120 Update completed-slice links in `docs/HOT_PATH_LOCK_AUDIT_2026-06-30.md`
- [X] T121 Update the final TypeTree test command in `specs/046-lock-removal-snapshots/quickstart.md`
- [X] T122 Update the final response-size test command in `specs/046-lock-removal-snapshots/quickstart.md`
- [X] T123 Add the TypeTree slice rollback scope to `specs/046-lock-removal-snapshots/slice-notes.md`
- [X] T124 Add the response-size slice rollback scope to `specs/046-lock-removal-snapshots/slice-notes.md`
- [X] T125 Add the no-raw-seqlock/no-custom-unsafe-lock-free/relaxed-memory-ordering audit result to `specs/046-lock-removal-snapshots/slice-notes.md`
- [X] T126 Add the excluded-lock-boundary diff audit result to `specs/046-lock-removal-snapshots/slice-notes.md`
- [X] T127 Add the final OPC UA clause-matrix completion check to `specs/046-lock-removal-snapshots/opcua-clause-matrix.md`
- [X] T128 Run `cargo fmt --check` from the repository root for workspace `Cargo.toml`
- [X] T129 Record the formatting result in `specs/046-lock-removal-snapshots/slice-notes.md`
- [X] T130 Run `cargo clippy --workspace --all-targets --all-features --locked -- -W clippy::await_holding_lock -W clippy::await_holding_refcell_ref` from the repository root for workspace `Cargo.toml`
- [X] T131 Record the final clippy lock-check result in `specs/046-lock-removal-snapshots/slice-notes.md`
- [X] T132 Run `cargo test --workspace --all-targets --all-features --locked` from the repository root for workspace `Cargo.toml`
- [X] T133 Record the workspace test result in `specs/046-lock-removal-snapshots/slice-notes.md`
- [X] T134 Add the final review checkpoint summary to `specs/046-lock-removal-snapshots/slice-notes.md`

---

## Dependencies and Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies; complete before Foundational.
- **Foundational (Phase 2)**: Depends on Setup; blocks all implementation slices.
- **US1 TypeTree MVP (Phase 3)**: Depends on Foundational; complete before US2 implementation.
- **US2 Response Size (Phase 4)**: Depends on Foundational and should start after US1 establishes the snapshot pattern.
- **US3 Riskier Boundaries (Phase 5)**: Depends on Foundational; produces gates, tests, results, and follow-up decisions only.
- **Polish (Phase 6)**: Depends on all selected implementation and gate tasks.

### User Story Dependencies

- **US1 (P1)**: No dependency on US2 or US3 after Foundational.
- **US2 (P2)**: No dependency on US3; implementation should follow US1 review.
- **US3 (P3)**: Each gate is independent after Foundational, but implementation work is intentionally outside this task list until a gate passes.

### Within-Story Dependencies

- **US1 tests**: T023-T027 must be written before T028.
- **US1 expected-red proof**: T028-T029 must complete before T030-T046.
- **US1 implementation**: T030-T033 must land before T034-T046.
- **US1 verification**: T047-T063 must run after T030-T046.
- **US2 tests**: T064-T069 must be written before T070.
- **US2 expected-red proof**: T070-T071 must complete before T072-T079.
- **US2 implementation**: T072-T074 must land before T075-T078.
- **US2 security review**: T079 must complete before T080-T085.
- **US2 verification**: T080-T085 must run after T079.
- **US3 gates**: Evidence tasks, clause-grounded tests, and test-result tasks must precede the gate-decision task for the same boundary.

## Implementation Strategy

### MVP First

1. Complete Phase 1 and Phase 2.
2. Complete US1 tests T023-T027 and confirm they fail via T028-T029.
3. Implement US1 tasks T030-T046.
4. Validate US1 with T047-T063.
5. Stop for review before US2 implementation.

### Incremental Delivery

1. Review the TypeTree snapshot MVP.
2. Implement the response-size slice with T064-T085.
3. Run P3 measurement gates T086-T119.
4. Create a follow-up Spec Kit feature only for P3 boundaries whose gate decision approves implementation.

## Notes

- Do not remove locks from security/session/certificate ownership paths as part of this feature.
- Do not introduce raw seqlocks, custom unsafe lock-free structures, or relaxed memory ordering without a documented correctness proof.
- Keep every task small enough to review, verify, and revert independently.
