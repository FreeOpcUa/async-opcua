# Tasks: Implement OPC-UA Standard Support Plan

**Input**: Design documents from `/specs/001-implement-opc-ua-spec/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- Paths are relative to the repository root.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization and basic workspace structure

- [X] T001 Initialize the branch workspace environment and check Rust compile targets
- [X] T002 Update cargo workspace configurations to declare new crate directories in Cargo.toml
- [X] T003 [P] Configure linting and format constraints in workspace Cargo.toml

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can be implemented

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T004 Define shared protocol traits and common types for Alarms, HDA, and Programs in async-opcua-core/src/lib.rs
- [X] T005 [P] Setup logging, masking, and JWT SHA-256 tracing helpers in async-opcua-core/src/logging.rs
- [X] T006 [P] Implement modern default security profiles (disabling legacy profiles by default) and legacy-crypto opt-in feature-flag in async-opcua-crypto/src/security_policy.rs

**Checkpoint**: Foundation ready - user story implementation can now begin in parallel

---

## Phase 3: User Story 1 - Real-Time Alarm & Event Management (Priority: P1) 🎯 MVP

**Goal**: Enable real-time alarm monitoring, state machine transitions, event dispatch, and Method acknowledgment.

**Independent Test**: Trigger out-of-bounds telemetry value, verify Alarm transitions state, receive event, and acknowledge.

### Implementation for User Story 1

- [X] T007 [US1] Create A&C event types structures in async-opcua-core/src/events.rs
- [X] T008 [P] [US1] Implement ConditionStateMachine structure and EnabledState/ActiveState/AckedState variables in async-opcua-server/src/alarms/state_machine.rs
- [X] T009 [US1] Implement alarm transition logic and verification rules in async-opcua-server/src/alarms/transitions.rs (depends on T008)
- [X] T010 [US1] Implement event routing and dispatch to MonitoredItem subscription buffers in async-opcua-server/src/alarms/dispatch.rs
- [X] T011 [US1] Implement client acknowledgment method callbacks and identity validation in async-opcua-server/src/alarms/methods.rs
- [X] T012 [US1] Implement client-side alarm event parsing and dynamic subscription routing in async-opcua-client/src/alarms/client.rs
- [X] T013 [US1] Add alarm registration methods to the Server namespace initializer in async-opcua-server/src/namespace/init.rs
- [X] T014 [US1] Write integration tests for Alarm triggering and acknowledgment in async-opcua-server/tests/alarms_integration.rs

**Checkpoint**: At this point, User Story 1 should be fully functional and testable independently

---

## Phase 4: User Story 2 - Historical Telemetry Access & Auditing (Priority: P1)

**Goal**: Retrieve and modify historical telemetry using pagination continuation tokens.

**Independent Test**: Write data, read in pages using continuation points, verify ordering.

### Implementation for User Story 2

- [X] T015 [US2] Define HistoryStorageBackend trait in async-opcua-server/src/history/backend.rs
- [X] T016 [US2] Implement continuation point in-memory caching and token eviction policy in async-opcua-server/src/history/continuation.rs
- [X] T017 [US2] Implement history read raw/modified response formatting and chronological ordering middleware in async-opcua-server/src/history/read.rs
- [X] T018 [US2] Implement user permission and history update bitflag validation in async-opcua-server/src/history/permissions.rs
- [X] T019 [US2] Implement SQLite historical storage backend database operations in async-opcua-history-sqlite/src/lib.rs
- [X] T020 [US2] Implement client-side history read request builder wrapper methods on Session struct in async-opcua-client/src/session.rs
- [X] T021 [US2] Write integration tests for historical read pagination and continuation points in dotnet-tests/external-tests/src/hda_tests.rs

**Checkpoint**: At this point, User Stories 1 AND 2 should both work independently

---

## Phase 5: User Story 3 - Decoupled PubSub Telemetry Publishing (Priority: P1)

**Goal**: Distribute telemetry data via JSON MQTT and UADP binary multicast groups.

**Independent Test**: Broker publishes changes on topic, multicast listener receives raw frames.

### Implementation for User Story 3

- [X] T022 [US3] Create connection, WriterGroup, PublishedDataSet structures in async-opcua-pubsub/src/config.rs
- [X] T023 [US3] Implement UADP network message serialization/deserialization in async-opcua-pubsub/src/codec/uadp.rs
- [X] T024 [US3] Implement JSON payload encoders/decoders in async-opcua-pubsub/src/codec/json.rs
- [X] T025 [US3] Implement MQTT client connection loop, exponential backoff reconnection policy, local cache bounds, and topic routing in async-opcua-pubsub/src/transport/mqtt.rs
- [X] T026 [US3] Implement UDP multicast socket binding and datagram fragmentation in async-opcua-pubsub/src/transport/udp.rs
- [X] T027 [US3] Implement server Address Space listener to automatically publish variable changes in async-opcua-pubsub/src/bridge.rs
- [X] T028 [US3] Write integration tests for PubSub MQTT and UDP multicast in dotnet-tests/external-tests/src/pubsub_tests.rs

**Checkpoint**: All user stories should now be independently functional

---

## Phase 6: User Story 4 - Managed Program Execution (Priority: P2)

**Goal**: Asynchronous task execution controllable via standard Program methods.

**Independent Test**: Start/Halt execution and verify correct state transitions.

### Implementation for User Story 4

- [X] T029 [US4] Define ProgramStateMachineType state variables and traits in async-opcua-server/src/programs/state.rs
- [X] T030 [US4] Implement asynchronous Program execution engine utilizing Tokio tasks in async-opcua-server/src/programs/engine.rs
- [X] T031 [US4] Register Start, Suspend, Resume, Halt methods in the Address Space in async-opcua-server/src/programs/methods.rs
- [X] T032 [US4] Implement client-side program control helper functions in async-opcua-client/src/program_client.rs
- [X] T033 [US4] Write integration tests for dynamic program execution cycles in async-opcua-server/tests/programs_integration.rs

---

## Phase 7: User Story 5 - On-Demand Mathematical Aggregates (Priority: P2)

**Goal**: On-demand mathematical aggregate processing middleware on historical data.

**Independent Test**: Query average over 1h intervals, check returned calculated aggregates and quality codes.

### Implementation for User Story 5

- [X] T034 [US5] Implement aggregate calculations (time-weighted average, min, max, std dev) in async-opcua-server/src/aggregates/engine.rs
- [X] T035 [US5] Implement aggregate quality code computation logic (interpreting bad/uncertain points) in async-opcua-server/src/aggregates/quality.rs
- [X] T036 [US5] Implement read processed details service interceptor in async-opcua-server/src/aggregates/middleware.rs
- [X] T037 [US5] Write unit tests for aggregate functions and quality rules in async-opcua-server/tests/aggregates_tests.rs

---

## Phase 8: User Story 6 - Global Discovery & Certificate Management (Priority: P2)

**Goal**: Register and renew certificates dynamically with a central GDS.

**Independent Test**: Call certificate renewal, verify server applies new certificate without restart.

### Implementation for User Story 6

- [X] T038 [US6] Implement dynamic GDS registration client, including GDS unreachable offline cached cert fallback warning logic, in async-opcua-client/src/gds/registration.rs
- [X] T039 [US6] Implement secure certificate signing request (CSR) exchange in async-opcua-client/src/gds/csr.rs
- [X] T040 [US6] Implement dynamic TLS/X.509 context reloading in the cryptos module in async-opcua-crypto/src/gds_reload.rs
- [X] T041 [US6] Write integration tests for zero-downtime certificate rotation in async-opcua-server/tests/gds_integration.rs

---

## Phase 9: User Story 7 - Custom Companion Specification Integration (Priority: P3)

**Goal**: Hardening NodeSet XML parser for importing DI/AutoID companion specs.

**Independent Test**: Import external companion NodeSet and confirm types reside in Address Space.

### Implementation for User Story 7

- [X] T042 [US7] Harden XML parser to handle custom structured types and XSD/BSD imports in async-opcua-xml/src/parser.rs
- [X] T043 [US7] Harden code generator to sort dependency trees topologically in async-opcua-codegen/src/generator.rs
- [X] T044 [US7] Implement dynamic NodeSet parser logic to register custom namespaces at server startup in async-opcua-server/src/nodeset_loader.rs
- [X] T045 [US7] Write tests to load and generate PLCopen / DI companion specs in codegen-tests/src/lib.rs

---

## Phase 10: User Story 8 - Secure Firmware Transmission & OAuth2 Identity (Priority: P3)

**Goal**: Session-bound temporary file transfers (FOTA) and JWT claims identity verification.

**Independent Test**: Log in using OAuth2 token, write to session-bound node, confirm file deleted after logout.

### Implementation for User Story 8

- [X] T046 [US8] Implement IssuedIdentityToken parsing and verification loop in async-opcua-server/src/auth/oauth2.rs
- [X] T047 [US8] Implement temporary FileType node creation in the Address Space in async-opcua-server/src/fota/file_node.rs
- [X] T048 [US8] Implement session lifecycle cleanup handlers to destroy files on channel drops in async-opcua-server/src/fota/cleanup.rs
- [X] T049 [US8] Write integration tests verifying JWT token rejection and temp file deletion in async-opcua-server/tests/fota_integration.rs

---

## Phase N: Polish & Cross-Cutting Concerns

**Purpose**: Improvements that affect multiple user stories

- [X] T050 Documentation updates in docs/ and workspace README.md
- [X] T051 Run cargo fmt, cargo clippy, and cargo test across all workspace crates
- [X] T052 Run quickstart.md validation script and confirm build success

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Stories (Phase 3+)**: All depend on Foundational phase completion
  - User stories can then proceed in parallel (if staffed)
  - Or sequentially in priority order (P1 → P2 → P3)
- **Polish (Final Phase)**: Depends on all desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational (Phase 2) - No dependencies on other stories
- **User Story 2 (P2)**: Can start after Foundational (Phase 2) - May integrate with US1 but should be independently testable
- **User Story 3 (P3)**: Can start after Foundational (Phase 2) - May integrate with US1/US2 but should be independently testable
- **User Story 4 (P4)**: Can start after Foundational (Phase 2) - Independent state execution
- **User Story 5 (P5)**: Depends on User Story 2 (P2) history reads being implemented first
- **User Story 6 (P6)**: Independent security renewal
- **User Story 7 (P7)**: Independent parser hardening
- **User Story 8 (P8)**: Independent identity mapping and temporary file storage

### Parallel Opportunities

- All Setup tasks marked [P] can run in parallel
- All Foundational tasks marked [P] can run in parallel (within Phase 2)
- Models within a story marked [P] can run in parallel
- Different user stories can be worked on in parallel by different team members

---

## Parallel Example: User Story 1

```bash
# Launch models and event structures in parallel:
Task: "Create A&C event types structures in async-opcua-core/src/events.rs"
Task: "Implement ConditionStateMachine structure and EnabledState/ActiveState/AckedState variables in async-opcua-server/src/alarms/state_machine.rs"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (CRITICAL - blocks all stories)
3. Complete Phase 3: User Story 1
4. **STOP and VALIDATE**: Test User Story 1 independently
5. Deploy/demo if ready

### Incremental Delivery

1. Complete Setup + Foundational → Foundation ready
2. Add User Story 1 → Test independently → Deploy/Demo (MVP!)
3. Add User Story 2 → Test independently → Deploy/Demo
4. Add User Story 3 → Test independently → Deploy/Demo
5. Each story adds value without breaking previous stories
