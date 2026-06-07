# Tasks: Complete OPC UA Compliance

**Input**: Design documents from `/specs/002-complete-opcua-compliance/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization and basic workspace structure

- [X] T001 Configure new library crate `async-opcua-pubsub` in cargo workspace `Cargo.toml`
- [X] T002 Create `async-opcua-pubsub/Cargo.toml` with tokio, serde, rumqttc, lapin, and tokio-tungstenite dependencies
- [X] T003 [P] Create directory structure for `async-opcua-pubsub` under `async-opcua-pubsub/src/`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can be implemented

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T004 Implement `HistoryStorageBackend` trait definition in `async-opcua-server/src/history/mod.rs`
- [X] T005 [P] Define OAuth2 identity validator traits in `async-opcua-crypto/src/identity/mod.rs`
- [X] T006 [P] Add legacy security profiles configuration flags in `async-opcua-crypto/src/security.rs`
- [X] T007 Define base state machine types for stateful server resources in `async-opcua-server/src/programs/mod.rs`

**Checkpoint**: Foundation ready - user story implementation can now begin

---

## Phase 3: User Story 1 - PubSub Interoperability (Priority: P1) 🎯 MVP

**Goal**: Publish and subscribe to OPC UA PubSub data over MQTT, AMQP, WebSockets, and UDP multicast.

**Independent Test**: Verify compliant subscribers receive ordered binary/structured messages over UDP multicast and broker connections.

- [X] T008 [P] [US1] Implement `PubSubConnection` and address configuration structures in `async-opcua-pubsub/src/config.rs`
- [X] T009 [P] [US1] Implement UADP binary parser/writer in `async-opcua-pubsub/src/encoding/uadp.rs`
- [X] T010 [P] [US1] Implement JSON message serializer/deserializer in `async-opcua-pubsub/src/encoding/json.rs`
- [X] T011 [US1] Implement UDP Multicast socket client and server logic in `async-opcua-pubsub/src/transport/udp.rs`
- [X] T012 [US1] Implement MQTT broker publisher/subscriber driver using rumqttc in `async-opcua-pubsub/src/transport/mqtt.rs`
- [X] T013 [US1] Implement AMQP client publisher/subscriber driver using lapin in `async-opcua-pubsub/src/transport/amqp.rs`
- [X] T014 [US1] Implement WebSocket transport driver in `async-opcua-pubsub/src/transport/websocket.rs`
- [X] T015 [US1] Implement PubSub cyclical publishing engine loop in `async-opcua-pubsub/src/engine.rs`
- [X] T016 [US1] Add PubSub transport validation and integration tests in `async-opcua-pubsub/tests/pubsub_tests.rs`

**Checkpoint**: PubSub is fully functional and testable independently.

---

## Phase 4: User Story 2 - Harden Discovery & Cert Lifecycle (Priority: P1)

**Goal**: Global Discovery Server (GDS) registration, certificate request, and zero-downtime rotation.

**Independent Test**: Run GDS certificate renewal method, confirm client sessions remain active, and cached credentials fall back.

- [X] T017 [P] [US2] Implement GdsEnrollment structs and registration states in `async-opcua-client/src/gds/gds_state.rs`
- [X] T018 [US2] Implement GDS push methods CreateSigningRequest/StartSigningRequest in `async-opcua-server/src/gds/push_methods.rs`
- [X] T019 [US2] Implement GDS pull methods GetRejectedList/UpdateCertificate in `async-opcua-server/src/gds/pull_methods.rs`
- [X] T020 [US2] Implement GDS client signing request helpers in `async-opcua-client/src/gds/gds_client.rs`
- [X] T021 [US2] Implement zero-downtime dynamic key/cert reloading logic in `async-opcua-crypto/src/security.rs`
- [X] T022 [US2] Implement cached credentials storage and recovery on startup in `async-opcua-server/src/gds/cache.rs`
- [X] T023 [US2] Add integration tests for GDS push/pull certificate rotation in `async-opcua-server/tests/gds_integration.rs`

**Checkpoint**: Discovery enrollment and GDS certificate management are functional and testable.

---

## Phase 5: User Story 3 - Modern Security & Identity (Priority: P1)

**Goal**: Reject deprecated profiles by default, validate OAuth2 tokens, and enforce role authorization.

**Independent Test**: Reject weak channel security, validate signed JWT, and restrict node access based on claims.

- [X] T024 [P] [US3] Isolate deprecated security profiles behind legacy-crypto feature flags in `async-opcua-crypto/Cargo.toml`
- [X] T025 [US3] Update secure endpoint initialization to reject deprecated profiles by default in `async-opcua-server/src/session/negotiate.rs`
- [X] T026 [US3] Implement OAuth2 JWT signature validator using local trust store in `async-opcua-crypto/src/identity/jwt_validator.rs`
- [X] T027 [US3] Map JWT role claims to session authorization profiles in `async-opcua-server/src/session/identity.rs`
- [X] T028 [US3] Integrate role checks into server Read/Write node access methods in `async-opcua-server/src/services/node_access.rs`
- [X] T029 [US3] Implement password/token redaction filter for logging in `async-opcua-core/src/logging/redact.rs`
- [X] T030 [US3] Add security profile rejection and OAuth2 validation tests in `async-opcua-server/tests/security_tests.rs`

**Checkpoint**: Modern security policy and OAuth2 token authorization are fully enforced.

---

## Phase 6: User Story 4 - Companion Spec Coverage (Priority: P2)

**Goal**: Load complex companion NodeSet XML schemas and generate Rust structures with cyclic references.

**Independent Test**: Load AutoID and DI nodesets with cross-dependencies, and verify generated structures.

- [X] T031 [P] [US4] Harden the XML nodeset parser to support deeply nested companion tags in `async-opcua-xml/src/parser.rs`
- [X] T032 [US4] Update codegen compiler to derive Clone, Send, Sync, Debug, and PartialEq on generated structs in `async-opcua-codegen/src/generator.rs`
- [X] T033 [US4] Implement encoding/decoding traits code generation for companion types in `async-opcua-codegen/src/derives.rs`
- [X] T034 [US4] Implement dependency topological sorting for imported NodeSets in `async-opcua-xml/src/dependency_sort.rs`
- [X] T035 [US4] Add diagnostic reporting for unresolved external companion references in `async-opcua-xml/src/diagnostics.rs`
- [X] T036 [US4] Add unit tests for loading complex AutoID companion models in `async-opcua-xml/tests/import_tests.rs`

**Checkpoint**: Deep companion specification XML import and codegen are functional.

---

## Phase 7: User Story 5 - Complete Historical Data Access (HDA) & Aggregates (Priority: P2)

**Goal**: Historical database reads, continuation paging, and historical aggregate calculations.

**Independent Test**: SQLite paging retrieval (100k records) and interval aggregate calculations.

- [X] T037 [US5] Implement SQLite connection manager and migrations setup in `async-opcua-history-sqlite/src/migration.rs`
- [X] T038 [US5] Implement `HistoryStorageBackend` SQLite query wrapper in `async-opcua-history-sqlite/src/backend.rs`
- [X] T039 [US5] Implement microsecond timestamp sorting, half-open boundary queries, and reversed time-range query intervals in `async-opcua-history-sqlite/src/query.rs`
- [X] T040 [US5] Implement ContinuationPoint cache with TTL eviction in `async-opcua-server/src/history/continuation.rs`
- [X] T041 [US5] Integrate continuation logic into server HistoryRead service in `async-opcua-server/src/services/history_read.rs`
- [X] T042 [US5] Implement time-weighted average, min, and max aggregate logic in `async-opcua-server/src/history/aggregates.rs`
- [X] T043 [US5] Implement aggregate status code quality rules in `async-opcua-server/src/history/quality.rs`
- [X] T044 [US5] Add conformance and performance tests for 100k page reads, reversed query intervals, and aggregates in `async-opcua-server/tests/history_tests.rs`

**Checkpoint**: HDA storage engine, paging, and aggregates are functional.

---

## Phase 8: User Story 6 - Stateful Server Features (Priority: P2)

**Goal**: Alarms & Conditions event state engine, Program State Machine methods, and temporary file transfers.

**Independent Test**: Alarm transitions, Program Start/Halt task controls, and file deletion on session timeout.

- [X] T045 [P] [US6] Implement event filtering and `EventNotificationList` routing in `async-opcua-server/src/alarms/notification.rs`
- [X] T046 [US6] Implement ConditionStateMachine transitions (Acked, Confirmed, Enabled) in `async-opcua-server/src/alarms/state_machine.rs`
- [X] T047 [US6] Bind Acknowledge and Confirm method handlers in `async-opcua-server/src/alarms/methods.rs`
- [X] T048 [US6] Implement ProgramStateMachineType transitions in `async-opcua-server/src/programs/state_machine.rs`
- [X] T049 [US6] Implement Program control methods (Start, Suspend, Resume, Halt) spawning async tasks in `async-opcua-server/src/programs/methods.rs`
- [X] T050 [US6] Implement temporary file transfer node and file stream write limits in `async-opcua-server/src/files/transfer.rs`
- [X] T051 [US6] Implement session cleanup hooks to delete temporary files and reset states in `async-opcua-server/src/session/cleanup.rs`
- [X] T052 [US6] Add integration tests for stateful resource lifecycle and file cleanup on disconnect in `async-opcua-server/tests/stateful_tests.rs`

**Checkpoint**: Stateful server resources (Alarms, Programs, File transfers) are functional and secure.

---

## Phase 9: Polish & Cross-Cutting Concerns

**Purpose**: Cleanup, documentation, and final validation

- [X] T053 [P] Document PubSub and GDS configuration usage in `docs/pubsub.md` and `docs/gds.md`
- [X] T054 Run quickstart.md validation code to confirm correct API compilation

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: Can start immediately.
- **Foundational (Phase 2)**: Depends on Setup completion. Blocks all user stories.
- **User Stories (Phases 3 to 8)**: Depend on Foundational completion.
- **Polish (Phase 9)**: Depends on all user stories being complete.

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Phase 2. No other story dependencies.
- **User Story 2 (P2)**: Can start after Phase 2. No other story dependencies.
- **User Story 3 (P3)**: Can start after Phase 2. No other story dependencies.
- **User Stories 4, 5, 6**: Independent of each other, can run in parallel after Foundation.

### Parallel Opportunities

- Phase 1: Setup tasks T003 can run in parallel.
- Phase 2: Foundational tasks T005, T006 can run in parallel.
- Phase 3: T008, T009, T010 can run in parallel.
- Phase 4: T017 can run in parallel.
- Phase 5: T024 can run in parallel.
- Phase 6: T031 can run in parallel.
- Phase 8: T045 can run in parallel.

---

## Parallel Example: User Story 1

```bash
# Launch models and data configurations in parallel:
Task: "Implement PubSubConnection and address configuration structures in async-opcua-pubsub/src/config.rs"
Task: "Implement UADP binary parser/writer in async-opcua-pubsub/src/encoding/uadp.rs"
Task: "Implement JSON message serializer/deserializer in async-opcua-pubsub/src/encoding/json.rs"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup.
2. Complete Phase 2: Foundational (CRITICAL - blocks all stories).
3. Complete Phase 3: User Story 1.
4. **STOP and VALIDATE**: Test PubSub interoperability independently.

### Incremental Delivery

1. Setup + Foundation.
2. Add User Story 1 (PubSub) -> Test -> Deliver MVP.
3. Add User Story 2 (GDS / Certs) -> Test -> Deliver.
4. Add User Story 3 (Modern Security / OAuth2) -> Test -> Deliver.
5. Add User Story 4 (Companion Specs) -> Test -> Deliver.
6. Add User Story 5 (Historical Access / Aggregates) -> Test -> Deliver.
7. Add User Story 6 (Stateful Alarms / Programs / Files) -> Test -> Deliver.
