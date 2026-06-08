# Tasks: Implement Future Performance Optimizations

**Input**: Design documents from `/specs/006-implement-future-optimizations/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: Test tasks are included as requested by the specification/quickstart verification criteria.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3, US4)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization and basic validation

- [ ] T001 Configure workspace dependencies in `async-opcua-server/Cargo.toml` and `async-opcua-core/Cargo.toml`
- [ ] T002 Verify all workspace projects compile clean before starting modifications by running `cargo check`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can be implemented

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [ ] T003 Create metrics instrumentation definitions in `async-opcua-server/src/metrics.rs`
- [ ] T004 Define custom error types for session actor failure paths in `async-opcua-server/src/session/errors.rs`

**Checkpoint**: Foundation ready - user story implementation can now begin

---

## Phase 3: User Story 1 - Fast Session Authentication / O(1) Lookup (Priority: P1) 🎯 MVP

**Goal**: Replace the linear session scanner with an O(1) DashMap registry.

**Independent Test**: Spawning 10,000 concurrent client sessions and verifying constant-time session lookup latency under 10 microseconds.

### Implementation for User Story 1

- [ ] T005 [P] [US1] Add `dashmap = "5.5"` to dependencies in `async-opcua-server/Cargo.toml`
- [ ] T006 [P] [US1] Add `use dashmap::DashMap;` import to `async-opcua-server/src/session/manager.rs`
- [ ] T007 [US1] Define concurrent lookup mapping registry `auth_tokens` in `async-opcua-server/src/session/manager.rs`
- [ ] T008 [US1] Update session registration in `SessionManager::register_token` in `async-opcua-server/src/session/manager.rs` to insert tokens into `auth_tokens`
- [ ] T009 [US1] Update session deregistration in `SessionManager::deregister_token` in `async-opcua-server/src/session/manager.rs` to remove tokens from `auth_tokens`
- [ ] T010 [US1] Refactor `SessionManager::find_by_token` in `async-opcua-server/src/session/manager.rs` to query `auth_tokens` in O(1) time
- [ ] T011 [US1] Instrument `find_by_token` lookup latency and registry size gauges using metrics in `async-opcua-server/src/session/manager.rs`
- [ ] T012 [US1] Write unit test verifying O(1) lookup performance and registry consistency in `async-opcua-server/tests/session_lookup.rs`

**Checkpoint**: User Story 1 is fully functional and testable independently.

---

## Phase 4: User Story 2 - High-Throughput Outbound Data Transmission / Zero-Copy Serialization (Priority: P1)

**Goal**: Write directly to connection-local write buffers using BytesMut.

**Independent Test**: Outbound packet preparation has zero new heap allocations per message frame.

### Implementation for User Story 2

- [ ] T013 [P] [US2] Add `bytes = "1.5"` to dependencies in `async-opcua-core/Cargo.toml`
- [ ] T014 [US2] Refactor connection write loop to hold a connection-local `BytesMut` buffer in `async-opcua-core/src/comms/tcp_codec.rs`
- [ ] T015 [US2] Implement write buffer reset helper to clear and reset the connection-local write buffer in `async-opcua-core/src/comms/tcp_codec.rs`
- [ ] T016 [US2] Refactor `BinaryEncodable::encode` serialization path to write directly to the mutable `BytesMut` buffer in `async-opcua-core/src/comms/tcp_codec.rs`
- [ ] T017 [US2] Update socket writing pipeline to utilize vectored write operations in `async-opcua-core/src/comms/tcp_codec.rs`
- [ ] T018 [US2] Implement bounds check validation to resize the connection-local buffer in `async-opcua-core/src/comms/tcp_codec.rs`
- [ ] T019 [US2] Instrument serialization metrics (counters for errors, bytes written) in `async-opcua-core/src/comms/tcp_codec.rs`
- [ ] T020 [US2] Write unit test simulating outbound message stream writes in `async-opcua-core/tests/serialization_alloc.rs`

**Checkpoint**: User Story 2 is fully functional and testable independently.

---

## Phase 5: User Story 3 - Lock-Free Session Operations / Actor-Based Sessions (Priority: P2)

**Goal**: Transition session to an actor model with an mpsc channel.

**Independent Test**: Multiple tasks read/write to the same session actor concurrently without lock contention.

### Implementation for User Story 3

- [ ] T021 [P] [US3] Define the `SessionMessage` enum for actor command routing in `async-opcua-server/src/session/actor.rs`
- [ ] T022 [P] [US3] Implement `SessionActor` structure managing thread-isolated state in `async-opcua-server/src/session/actor.rs`
- [ ] T023 [US3] Implement the main async message loop `SessionActor::run` in `async-opcua-server/src/session/actor.rs`
- [ ] T024 [US3] Implement immediate connection abort and token registry cleanup logic in `SessionActor::run` in `async-opcua-server/src/session/actor.rs`
- [ ] T025 [US3] Implement client notification callback dispatch within the actor in `async-opcua-server/src/session/actor.rs`
- [ ] T026 [US3] Update `SessionManager` to spawn `SessionActor` in a tokio task in `async-opcua-server/src/session/manager.rs`
- [ ] T027 [US3] Refactor connection request handlers to send messages through the actor's `mpsc` sender in `async-opcua-server/src/session/manager.rs`
- [ ] T028 [US3] Instrument actor message queue size gauges and processing times in `async-opcua-server/src/session/actor.rs`
- [ ] T029 [US3] Write concurrent load test verifying session state updates under high request volume in `async-opcua-server/tests/session_actor_load.rs`

**Checkpoint**: User Story 3 is fully functional and testable independently.

---

## Phase 6: User Story 4 - Low-Garbage Subscription Notifications / Pooling (Priority: P2)

**Goal**: Pool subscription notification allocations and block/wait on exhaustion.

**Independent Test**: Heap allocation profiling shows zero allocations for notification message structures during continuous subscription updates.

### Implementation for User Story 4

- [ ] T030 [P] [US4] Add `lockfree-object-pool = "0.1"` to dependencies in `async-opcua-server/Cargo.toml`
- [ ] T031 [P] [US4] Create `NotificationPool` using `lockfree_object_pool::LinearObjectPool` in `async-opcua-server/src/subscriptions/pool.rs`
- [ ] T032 [US4] Implement reuse/reset functions to clear notification structures in `async-opcua-server/src/subscriptions/pool.rs`
- [ ] T033 [US4] Refactor subscription scanning to acquire notifications from the pool in `async-opcua-server/src/subscriptions/subscription.rs`
- [ ] T034 [US4] Implement block/wait behavior in the pool acquire path if exhausted in `async-opcua-server/src/subscriptions/pool.rs`
- [ ] T035 [US4] Release notification structures back to the pool after transmission in `async-opcua-server/src/subscriptions/subscription.rs`
- [ ] T036 [US4] Instrument pool statistics (active/inactive counts) in `async-opcua-server/src/subscriptions/pool.rs`
- [ ] T037 [US4] Write unit test running high-frequency updates and asserting memory stability in `async-opcua-server/tests/subscription_pooling.rs`

**Checkpoint**: User Story 4 is fully functional and testable independently.

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: Cleanup, validation, and final integration checks

- [ ] T038 Verify all workspace unit and integration tests pass successfully by running `cargo test --workspace --all-features`
- [ ] T039 Verify the quickstart benchmarking and load tests compile and run in `async-opcua-server/tests/address_space_concurrency.rs`
- [ ] T040 Perform code cleanup, document the optimized structures in comments, and check for any leftover locks or wrappers across the codebase

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - starts immediately.
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories.
- **User Stories (Phase 3+)**: All depend on Foundational phase completion.
  - User Story 1 (O(1) Session Lookup) and User Story 2 (Zero-Copy Serialization) can run in parallel once Foundation is complete.
  - User Story 3 (Actor-Based Sessions) and User Story 4 (Notification Pooling) can run in parallel once Foundation is complete.
- **Polish (Phase 7)**: Depends on all desired user stories being complete.

### Parallel Opportunities

- Setup tasks `T001` and `T002` can run in parallel.
- User Story 1 setup tasks `T005` and `T006` can run in parallel.
- User Story 3 setup tasks `T021` and `T022` can run in parallel.
- User Story 4 setup tasks `T030` and `T031` can run in parallel.

---

## Parallel Example: User Story 1

```bash
# Launch models/setup tasks for User Story 1 together:
Task: "Add dashmap to dependencies in async-opcua-server/Cargo.toml"
Task: "Add dashmap import to async-opcua-server/src/session/manager.rs"
```

---

## Implementation Strategy

### MVP First (User Story 1 & 2 Only)

1. Complete Phase 1: Setup.
2. Complete Phase 2: Foundational.
3. Complete Phase 3: User Story 1 (O(1) Lookup).
4. Complete Phase 4: User Story 2 (Zero-Copy Serialization).
5. **STOP and VALIDATE**: Verify lookup latency and allocation metrics.
6. Deploy/demo if ready.
