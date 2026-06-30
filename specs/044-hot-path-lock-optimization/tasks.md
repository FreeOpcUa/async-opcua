# Tasks: Hot Path Lock Optimization

**Input**: Design documents from `/specs/044-hot-path-lock-optimization/`
**Prerequisites**: [plan.md](./plan.md), [spec.md](./spec.md), [research.md](./research.md), [data-model.md](./data-model.md), [contracts/](./contracts/), [quickstart.md](./quickstart.md)

**Tests**: Included because FR-017 requires a regression/proof test for every behavior-changing task.
**Organization**: Tasks are grouped by user story and ordered so each implementation slice is atomic.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel with other marked tasks because it touches different files and has no dependency on an incomplete task.
- **[Story]**: User story label from `spec.md`.
- Every OPC UA behavior-changing task names the relevant OPC-10000 section.

## Phase 1: Setup

**Purpose**: Confirm active Spec Kit context and create the verification ledger used by later atomic tasks.

- [X] T001a Confirm `AGENTS.md` points to `specs/044-hot-path-lock-optimization/plan.md`
- [X] T001b Confirm `.specify/feature.json` points to `specs/044-hot-path-lock-optimization`
- [X] T002 Create `specs/044-hot-path-lock-optimization/verification.md` with columns for task id, HPL slice, OPC UA reference, focused command, expected-red evidence, final result, and notes
- [X] T003 Seed the HPL slice checklist from `specs/044-hot-path-lock-optimization/contracts/implementation-slices.md` into `specs/044-hot-path-lock-optimization/verification.md`

---

## Phase 2: Foundational

**Purpose**: Establish task-local proof and baseline expectations before user-story work starts.

**Critical**: No lock-boundary implementation should begin until this phase is complete.

- [X] T004 Record the proof strategy for guard-release tests in `specs/044-hot-path-lock-optimization/verification.md`, choosing reentrant-callback tests before lock-trace-only assertions
- [X] T005a Run `cargo test -p async-opcua-server node_manager -- --list` and record the baseline command output summary in `specs/044-hot-path-lock-optimization/verification.md`; Spec: OPC-10000-4 5.11.2, 5.11.4.2, and 5.12.2.2
- [X] T005b Run `cargo test -p async-opcua-client subscription -- --list` and record the baseline command output summary in `specs/044-hot-path-lock-optimization/verification.md`; Spec: OPC-10000-4 5.14.1, 5.14.5, and 7.26
- [X] T005c Run `cargo test -p async-opcua-server subscription -- --list` and record the baseline command output summary in `specs/044-hot-path-lock-optimization/verification.md`; Spec: OPC-10000-4 5.13.1.2, 5.13.2 through 5.13.6, 5.14.1, and 5.14.5

**Checkpoint**: Proof strategy and test baselines are documented.

---

## Phase 3: User Story 1 - Invoke Server Extension Callbacks Outside Internal Locks (Priority: P1)

**Goal**: Read, Write, and Call callbacks execute after internal address-space, type-tree, and callback-registry guards are released.

**Independent Test**: Register callbacks that re-enter safe node-manager operations or otherwise prove callback execution occurs after the relevant guard is released; verify public Read, Write, and Call behavior remains unchanged.

### Tests for User Story 1

- [X] T006 [P] [US1] Add expected-red `read_callback_runs_after_internal_guards_are_released` in `async-opcua-server/tests/hot_path_read_callback_locks.rs` proving a Read callback can re-enter a safe node-manager operation without deadlock; Spec: OPC-10000-4 5.11.2 and 5.11.2.3
- [X] T007 [P] [US1] Add expected-red `write_callback_runs_after_internal_guards_are_released` in `async-opcua-server/tests/hot_path_write_callback_locks.rs` proving a Write callback runs outside address-space, type-tree, and write-callback guards while preserving status mapping; Spec: OPC-10000-4 5.11.4.2 and 5.11.4.4
- [X] T008a [P] [US1] Add expected-red `plain_method_callback_runs_after_registry_guard_is_released` in `async-opcua-server/tests/hot_path_plain_method_callback_locks.rs` covering the simple in-memory manager path; Spec: OPC-10000-4 5.12.2.2 and 5.12.2.4
- [X] T008b [P] [US1] Add expected-red `context_method_callback_runs_after_registry_guard_is_released` in `async-opcua-server/tests/hot_path_context_method_callback_locks.rs` covering the context-aware in-memory manager path; Spec: OPC-10000-4 5.12.2.2 and 5.12.2.4

### Implementation for User Story 1

- [X] T009 [US1] Refactor `read_values` in `async-opcua-server/src/node_manager/memory/simple.rs` to capture read callback handles and immutable node/request metadata under lock, release guards, then invoke callbacks; Spec: OPC-10000-4 5.11.2 and 5.11.2.3
- [X] T010 [US1] Run `cargo test -p async-opcua-server read_callback_runs_after_internal_guards_are_released -- --exact --nocapture` and record the result in `specs/044-hot-path-lock-optimization/verification.md`; Spec: OPC-10000-4 5.11.2 and 5.11.2.3
- [X] T011 [US1] Refactor Write callback handling in `async-opcua-server/src/node_manager/memory/simple.rs` to capture callback handles and required type metadata under lock, release guards, then invoke callbacks while preserving per-node results; Spec: OPC-10000-4 5.11.4.2 and 5.11.4.4
- [X] T012 [US1] Run `cargo test -p async-opcua-server write_callback_runs_after_internal_guards_are_released -- --exact --nocapture` and record the result in `specs/044-hot-path-lock-optimization/verification.md`; Spec: OPC-10000-4 5.11.4.2 and 5.11.4.4
- [X] T013 [US1] Refactor plain method callback lookup in `async-opcua-server/src/node_manager/memory/simple.rs` to clone the callback handle under the registry guard and invoke after unlock; Spec: OPC-10000-4 5.12.2.2 and 5.12.2.4
- [X] T014 [US1] Refactor context-aware method callback lookup in `async-opcua-server/src/node_manager/memory/core.rs` to clone the callback handle under the registry guard and invoke after unlock; Spec: OPC-10000-4 5.12.2.2 and 5.12.2.4
- [X] T015a [US1] Run `cargo test -p async-opcua-server plain_method_callback_runs_after_registry_guard_is_released -- --exact --nocapture` and record the result in `specs/044-hot-path-lock-optimization/verification.md`; Spec: OPC-10000-4 5.12.2.2 and 5.12.2.4
- [X] T015b [US1] Run `cargo test -p async-opcua-server context_method_callback_runs_after_registry_guard_is_released -- --exact --nocapture` and record the result in `specs/044-hot-path-lock-optimization/verification.md`; Spec: OPC-10000-4 5.12.2.2 and 5.12.2.4
- [X] T015c [US1] Run `cargo test -p async-opcua-server method_call_tests -- --nocapture` and record the result in `specs/044-hot-path-lock-optimization/verification.md`; Spec: OPC-10000-4 5.12.2.2 and 5.12.2.4

**Checkpoint**: Server callback lock-boundary fixes are testable independently.

---

## Phase 4: User Story 2 - Deliver Client Subscription Callbacks Outside `subscription_state` (Priority: P1)

**Goal**: Client subscription callbacks execute after `subscription_state` is released while Publish acknowledgements and monitored-item views remain correct.

**Independent Test**: A Publish response with notification data queues acknowledgements under the mutex, then delivers user callbacks outside the mutex using an owned or immutable monitored-item view.

### Tests for User Story 2

- [X] T016 [P] [US2] Add expected-red `publish_notification_callback_runs_outside_subscription_state` in `async-opcua-client/tests/subscription_delivery_locks.rs` proving callback re-entry does not deadlock and acknowledgements are queued first; Spec: OPC-10000-4 5.14.1 and 5.14.5

### Implementation for User Story 2

- [X] T017 [US2] Introduce an owned `ClientDeliveryPacket` notification view in `async-opcua-client/src/session/services/subscriptions/state.rs` so callback delivery does not borrow guarded state after unlock; Spec: OPC-10000-4 5.14.1 and 5.14.5
- [X] T018 [US2] Add `Subscription::deliver_notification_packet` in `async-opcua-client/src/session/services/subscriptions/mod.rs` to accept `ClientDeliveryPacket` without taking `subscription_state`; Spec: OPC-10000-4 5.14.1 and 7.26
- [X] T019 [US2] Change Publish response handling in `async-opcua-client/src/session/services/subscriptions/service.rs` to mutate acknowledgements and subscription state under `subscription_state`, return delivery packets, drop the mutex, then call `Subscription::deliver_notification_packet`; Spec: OPC-10000-4 5.14.5
- [X] T020a [US2] Run `cargo test -p async-opcua-client publish_notification_callback_runs_outside_subscription_state -- --exact --nocapture` and record the result in `specs/044-hot-path-lock-optimization/verification.md`; Spec: OPC-10000-4 5.14.1, 5.14.5, and 7.26
- [X] T020b [US2] Run `cargo test -p async-opcua-client subscription -- --nocapture` and record the result in `specs/044-hot-path-lock-optimization/verification.md`; Spec: OPC-10000-4 5.14.1, 5.14.5, and 7.26

**Checkpoint**: Client subscription callback delivery is independent and testable.

---

## Phase 5: User Story 3 - Decouple Sampling And Notification Fanout From Global Guards (Priority: P1)

**Goal**: `SyncSampler` and subscription fanout stop running sampler callbacks, sampling closures, and actor queue pushes while global guards are live.

**Independent Test**: Slow sampler and fanout tests prove concurrent sampler management or route changes can proceed while callback/fanout work runs, without changing MonitoredItem queue or Subscription notification semantics.

### Tests for User Story 3

- [X] T021 [P] [US3] Add expected-red `sync_sampler_does_not_hold_sampler_mutex_while_sampling` in `async-opcua-server/tests/sync_sampler_lock_scope.rs` proving a slow sampler does not block sampler add/update/remove on the map mutex; Spec: OPC-10000-4 5.13.1.2 and 5.13.1.5
- [X] T022a [P] [US3] Add expected-red `subscription_route_lookup_releases_cache_guard_before_sampling` in `async-opcua-server/tests/subscription_route_snapshot_sampling.rs` proving route lookup is snapped before sampling closures; Spec: OPC-10000-4 5.13.2 through 5.13.6 and 5.14.1
- [X] T022b [P] [US3] Add expected-red `subscription_route_snapshot_releases_cache_guard_before_actor_enqueue` in `async-opcua-server/tests/subscription_route_snapshot_enqueue.rs` proving actor queue pushes happen after the cache guard is released; Spec: OPC-10000-4 5.13.2 through 5.13.6 and 5.14.1
- [X] T022c [P] [US3] Add expected-red `subscription_route_snapshot_no_match_path_is_allocation_light` in `async-opcua-server/tests/subscription_route_snapshot_no_match.rs` proving a no-match data-change route lookup produces no sampling closures, no actor enqueue, and only an empty route batch; Spec: OPC-10000-4 5.13.2 through 5.13.6 and 5.14.1

### Implementation for User Story 3

- [X] T023 [US3] Refactor due-sampler selection in `async-opcua-server/src/node_manager/utils/sync_sampler.rs` to collect `SamplerWorkItem` data and update scheduling state under the sampler mutex without invoking sampler callbacks; Spec: OPC-10000-4 5.13.1.2
- [X] T023a [US3] Run `cargo check -p async-opcua-server --all-targets` and record the behavior-preserving due-sampler selection result in `specs/044-hot-path-lock-optimization/verification.md`; Spec: OPC-10000-4 5.13.1.2
- [X] T024 [US3] Refactor notification emission in `async-opcua-server/src/node_manager/utils/sync_sampler.rs` so sampler callbacks and `notify_data_change` run after the sampler mutex is released; Spec: OPC-10000-4 5.13.1.5 and 5.14.1
- [X] T025 [US3] Run `cargo test -p async-opcua-server sync_sampler_does_not_hold_sampler_mutex_while_sampling -- --exact --nocapture` and record the result in `specs/044-hot-path-lock-optimization/verification.md`; Spec: OPC-10000-4 5.13.1.2, 5.13.1.5, and 5.14.1
- [X] T026 [US3] Add `NotificationRouteSnapshot` and owned route batch structures in `async-opcua-server/src/subscriptions/notify.rs` that preserve session/subscription/monitored-item routing without carrying the global cache guard; Spec: OPC-10000-4 5.13.2 through 5.13.6
- [X] T027a [US3] Change `data_notifier` in `async-opcua-server/src/subscriptions/mod.rs` to snapshot matching routes under the cache guard and release the guard before sampling closures; Spec: OPC-10000-4 5.13.1.5 and 5.14.1
- [X] T027b [US3] Change `notify_data_change` in `async-opcua-server/src/subscriptions/mod.rs` to consume snapped route data without extending the cache guard lifetime; Spec: OPC-10000-4 5.13.1.5 and 5.14.1
- [X] T027c [US3] Change `maybe_notify` in `async-opcua-server/src/subscriptions/mod.rs` to consume snapped route data without extending the cache guard lifetime; Spec: OPC-10000-4 5.13.1.5 and 5.14.1
- [X] T027d [US3] Change no-match route handling in `async-opcua-server/src/subscriptions/mod.rs` to return an empty route batch without running sampling closures or actor enqueue work; Spec: OPC-10000-4 5.13.2 through 5.13.6 and 5.14.1
- [X] T028 [US3] Change notifier dispatch in `async-opcua-server/src/subscriptions/notify.rs` so actor queue pushes happen after the cache guard is released while preserving route targets; Spec: OPC-10000-4 5.14.1 and 5.14.5
- [X] T029a [US3] Run `cargo test -p async-opcua-server subscription_route_lookup_releases_cache_guard_before_sampling -- --exact --nocapture` and record the result in `specs/044-hot-path-lock-optimization/verification.md`; Spec: OPC-10000-4 5.13.2 through 5.13.6 and 5.14.1
- [X] T029b [US3] Run `cargo test -p async-opcua-server subscription_route_snapshot_releases_cache_guard_before_actor_enqueue -- --exact --nocapture` and record the result in `specs/044-hot-path-lock-optimization/verification.md`; Spec: OPC-10000-4 5.13.2 through 5.13.6, 5.14.1, and 5.14.5
- [X] T029c [US3] Run `cargo test -p async-opcua-server subscription -- --nocapture` and record the result in `specs/044-hot-path-lock-optimization/verification.md`; Spec: OPC-10000-4 5.13.2 through 5.13.6, 5.14.1, and 5.14.5
- [X] T029d [US3] Run `cargo test -p async-opcua-server subscription_route_snapshot_no_match_path_is_allocation_light -- --exact --nocapture` and record the result in `specs/044-hot-path-lock-optimization/verification.md`; Spec: OPC-10000-4 5.13.2 through 5.13.6 and 5.14.1

**Checkpoint**: Sampler and fanout guard lifetimes are independently testable.

---

## Phase 6: User Story 4 - Narrow Session And Connection Control Locks Safely (Priority: P2)

**Goal**: Narrow `SessionManager`, CreateSession, and renewal-related locks without weakening Session or SecureChannel protocol invariants.

**Independent Test**: Request dispatch and CreateSession tests preserve invalid-session, closed-session, activation, endpoint, certificate, and limit status behavior while showing narrower guard lifetimes.

### Tests for User Story 4

- [X] T030 [P] [US4] Add expected-red `normal_request_dispatch_drops_session_manager_guard_before_validation` in `async-opcua-server/tests/session_dispatch_lock_scope.rs`; Spec: OPC-10000-4 7.32 and 7.35
- [X] T031a [P] [US4] Add expected-red `create_session_rechecks_session_limits_at_short_commit` in `async-opcua-server/tests/create_session_limit_lock_scope.rs`; Spec: OPC-10000-4 5.7.2
- [X] T031b [P] [US4] Add expected-red `create_session_preserves_endpoint_error_after_preflight_split` in `async-opcua-server/tests/create_session_endpoint_lock_scope.rs`; Spec: OPC-10000-4 5.7.2
- [X] T031c [P] [US4] Add expected-red `create_session_preserves_certificate_error_after_preflight_split` in `async-opcua-server/tests/create_session_certificate_lock_scope.rs`; Spec: OPC-10000-4 5.7.2
- [X] T031d [P] [US4] Add expected-red `create_session_preserves_allocation_error_after_preflight_split` in `async-opcua-server/tests/create_session_allocation_lock_scope.rs`; Spec: OPC-10000-4 5.7.2

### Implementation for User Story 4

- [X] T032 [US4] Refactor normal request dispatch in `async-opcua-server/src/session/controller.rs` to collect `SessionDispatchLookup` under the `SessionManager` read guard and drop the guard before validation, audit-context setup, and dispatch; Spec: OPC-10000-4 7.32 and 7.35
- [X] T033 [US4] Run `cargo test -p async-opcua-server normal_request_dispatch_drops_session_manager_guard_before_validation -- --exact --nocapture` and record the result in `specs/044-hot-path-lock-optimization/verification.md`; Spec: OPC-10000-4 7.32 and 7.35
- [X] T033a [US4] Record a normal request dispatch lock-scope measurement or documented correctness-risk rationale in `specs/044-hot-path-lock-optimization/verification.md` before starting CreateSession work; Spec: OPC-10000-4 7.32 and 7.35
- [X] T034a [US4] Add `CreateSessionDraft` scaffolding and endpoint-selection preflight in `async-opcua-server/src/session/manager.rs` without changing the active CreateSession path; Spec: OPC-10000-4 5.7.2
- [X] T034b [US4] Move certificate-validation preparation into the unused `CreateSessionDraft` builder in `async-opcua-server/src/session/manager.rs`; Spec: OPC-10000-4 5.7.2
- [X] T034c [US4] Move server-signature preparation into the unused `CreateSessionDraft` builder in `async-opcua-server/src/session/manager.rs`; Spec: OPC-10000-4 5.7.2
- [X] T034d [US4] Move actor-construction preparation into the unused `CreateSessionDraft` builder in `async-opcua-server/src/session/manager.rs` without publishing a session; Spec: OPC-10000-4 5.7.2
- [X] T034e [US4] Move session-allocation preparation into the unused `CreateSessionDraft` builder in `async-opcua-server/src/session/manager.rs` without publishing a session; Spec: OPC-10000-4 5.7.2
- [X] T035a [US4] Add a short CreateSession commit helper in `async-opcua-server/src/session/manager.rs` that re-checks session limits before publishing the draft; Spec: OPC-10000-4 5.7.2
- [X] T035b [US4] Add the unactivated-session recheck to the short CreateSession commit helper in `async-opcua-server/src/session/manager.rs`; Spec: OPC-10000-4 5.7.2
- [X] T035c [US4] Add the channel-association recheck to the short CreateSession commit helper in `async-opcua-server/src/session/manager.rs`; Spec: OPC-10000-4 5.7.2
- [X] T036 [US4] Update CreateSession dispatch in `async-opcua-server/src/session/controller.rs` to run safe preflight work before taking the `SessionManager` write guard and call the checked short commit path afterward; Spec: OPC-10000-4 5.7.2
- [X] T037a [US4] Run `cargo test -p async-opcua-server create_session_rechecks_session_limits_at_short_commit -- --exact --nocapture` and record the result in `specs/044-hot-path-lock-optimization/verification.md`; Spec: OPC-10000-4 5.7.2
- [X] T037b [US4] Run `cargo test -p async-opcua-server create_session_preserves_endpoint_error_after_preflight_split -- --exact --nocapture` and record the result in `specs/044-hot-path-lock-optimization/verification.md`; Spec: OPC-10000-4 5.7.2
- [X] T037c [US4] Run `cargo test -p async-opcua-server create_session_preserves_certificate_error_after_preflight_split -- --exact --nocapture` and record the result in `specs/044-hot-path-lock-optimization/verification.md`; Spec: OPC-10000-4 5.7.2
- [X] T037d [US4] Run `cargo test -p async-opcua-server create_session_preserves_allocation_error_after_preflight_split -- --exact --nocapture` and record the result in `specs/044-hot-path-lock-optimization/verification.md`; Spec: OPC-10000-4 5.7.2
- [X] T037e [US4] Run `cargo test -p async-opcua-server session -- --nocapture` and record the result in `specs/044-hot-path-lock-optimization/verification.md`; Spec: OPC-10000-4 5.7.2, 7.32, and 7.35
- [X] T037f [US4] Record a CreateSession lock-scope measurement or documented correctness-risk rationale in `specs/044-hot-path-lock-optimization/verification.md` before the secure-channel renewal baseline; Spec: OPC-10000-4 5.7.2
- [X] T038 [US4] Record a secure-channel renewal baseline and no-change decision for `async-opcua-client/src/transport/channel.rs` in `specs/044-hot-path-lock-optimization/verification.md`; Spec: OPC-10000-6 6.7.2.4 and 6.7.7

**Checkpoint**: Session and CreateSession lock narrowing is testable without weakening protocol security boundaries.

---

## Phase 7: User Story 5 - Prepare Measured Snapshot And Queue Follow-Ups (Priority: P3)

**Goal**: Gate larger snapshot/SPSC work behind measurements and clean up small lock-mode mistakes where code evidence proves no mutation.

**Independent Test**: Baselines exist before larger designs; read/write lock mode cleanups preserve SecureChannel and PubSub behavior.

### Tests for User Story 5

- [X] T039 [P] [US5] Add `certificate_store_connect_path_uses_read_access_for_cert_and_key_reads` in `async-opcua-client/tests/channel_certificate_store_lock.rs` proving the connect path only reads certificate material; Spec: OPC-10000-6 6.7.7
- [X] T040 [P] [US5] Add `pubsub_subscriber_validation_uses_read_access_before_mutation` in `async-opcua-pubsub/tests/subscriber_lock_modes.rs` proving read-only subscriber validation does not require an address-space write lock; Spec: OPC-10000-14 5.4.1.2 and 6.3.2.1.1

### Implementation for User Story 5

- [X] T041a [US5] Replace the certificate-store write guard with a read guard for `read_own_cert` in `async-opcua-client/src/transport/channel.rs`; Spec: OPC-10000-6 6.7.7
- [X] T041b [US5] Replace the certificate-store write guard with a read guard for `read_own_pkey` in `async-opcua-client/src/transport/channel.rs`; Spec: OPC-10000-6 6.7.7
- [X] T042 [US5] Run `cargo test -p async-opcua-client certificate_store_connect_path_uses_read_access_for_cert_and_key_reads -- --exact --nocapture` and record the result in `specs/044-hot-path-lock-optimization/verification.md`; Spec: OPC-10000-6 6.7.7
- [X] T043 [US5] Replace read-only subscriber address-space write access with read access before the mutation phase in `async-opcua-pubsub/src/subscriber.rs`; Spec: OPC-10000-14 5.4.1.2 and 6.3.2.1.1
- [X] T044 [US5] Run `cargo test -p async-opcua-pubsub pubsub_subscriber_validation_uses_read_access_before_mutation -- --exact --nocapture` and record the result in `specs/044-hot-path-lock-optimization/verification.md`; Spec: OPC-10000-14 5.4.1.2 and 6.3.2.1.1
- [X] T045 [US5] Create `specs/044-hot-path-lock-optimization/snapshot-queue-baseline.md` for the subscription route index candidate, run the selected baseline command, and record the baseline result before any snapshot/SPSC implementation; Spec: OPC-10000-4 5.13 and 5.14

**Checkpoint**: P3 cleanup is complete and larger concurrency work remains measurement gated.

---

## Final Phase: Polish & Cross-Cutting Concerns

**Purpose**: Validate the generated task work and keep documentation consistent.

- [X] T046 Update `docs/HOT_PATH_LOCK_AUDIT_2026-06-30.md` with completed task outcomes and deferred subscription-route snapshot/SPSC decisions; Spec: OPC-10000-4 5.13 and 5.14
- [X] T047 Run `cargo fmt --check` and record the result in `specs/044-hot-path-lock-optimization/verification.md`
- [X] T048 Run `cargo test --workspace --all-targets --all-features --locked` and record the result in `specs/044-hot-path-lock-optimization/verification.md`; Spec: OPC-10000-4 5.7.2, 5.11.2, 5.11.4.2, 5.12.2.2, 5.13, 5.14, 7.26, 7.32, and 7.35; OPC-10000-6 6.7.7; OPC-10000-14 5.4.1.2 and 6.3.2.1.1
- [X] T049 Run `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` and record the result in `specs/044-hot-path-lock-optimization/verification.md`
- [X] T050 Run `rg -n "OPC-10000|Spec:" specs/044-hot-path-lock-optimization/tasks.md specs/044-hot-path-lock-optimization/verification.md` and record the traceability check in `specs/044-hot-path-lock-optimization/verification.md`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies.
- **Foundational (Phase 2)**: Depends on Setup; blocks all user-story implementation.
- **US1, US2, US3 (P1)**: Depend on Foundational; may be planned in parallel by separate workers, but within each story the expected-red test precedes implementation.
- **US4 (P2)**: Depends on Foundational; can start after P1 if minimizing risk, or in parallel if a separate worker owns only session/controller files.
- **US5 (P3)**: Depends on Foundational; snapshot/SPSC baseline task depends on P1 route/sampler findings being understood.
- **Final Phase**: Depends on all selected implementation stories.

### User Story Dependencies

- **US1**: Independent after Foundational; touches server node-manager callback paths.
- **US2**: Independent after Foundational; touches client subscription paths.
- **US3**: Independent after Foundational; sampler and fanout tasks are sequential within the story because they share subscription notification behavior.
- **US4**: Independent after Foundational but should follow P1 in priority order unless staffed separately.
- **US5**: Cleanup tasks can run after Foundational; snapshot/SPSC baseline should wait until P1 results are known.

### Within Each User Story

- Expected-red tests must be added and observed before implementation.
- Implementation tasks must change one guard boundary at a time.
- Focused verification must be recorded before starting the next boundary in that story.

---

## Parallel Opportunities

- T006, T007, T008a, and T008b can be created in parallel because they are separate test files, but T009 through T015c should run in order.
- T016 can run in parallel with US1 tests because it touches only client test files.
- T021, T022a, T022b, and T022c can be created in parallel because they are separate server test files, but T023 through T029d should run in order.
- T030, T031a, T031b, T031c, and T031d can be created in parallel because they are separate server test files, but T032 through T038 should run in order.
- T039 and T040 can be created in parallel because they are separate client/pubsub test files.

## Parallel Example: P1 Tests

```bash
Task: "T006 add async-opcua-server/tests/hot_path_read_callback_locks.rs"
Task: "T016 add async-opcua-client/tests/subscription_delivery_locks.rs"
Task: "T021 add async-opcua-server/tests/sync_sampler_lock_scope.rs"
```

## Implementation Strategy

### MVP First

1. Complete Phase 1 and Phase 2.
2. Complete US1 server callback lock-boundary fixes.
3. Stop and validate with the US1 focused commands before any broader concurrency work.

### Incremental Delivery

1. US1 removes server callback-under-lock risk.
2. US2 removes client callback-under-mutex risk.
3. US3 removes sampler and subscription fanout guard lifetime risk.
4. US4 narrows session and CreateSession lock scopes while preserving protocol security boundaries.
5. US5 performs small cleanup and records the measurement gate for future snapshot/SPSC work.

### Guardrails

- Do not introduce raw seqlocks.
- Do not add unbounded queues.
- Do not hold new lock guards across `.await`.
- Do not change public OPC UA statuses unless a later spec-grounded conformance task explicitly requires it.
