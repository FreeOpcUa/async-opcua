# Tasks: Advanced OPC UA Compliance

**Input**: Design documents from `/specs/003-advanced-opcua-compliance/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization and basic structure

- [X] T001 [P] Verify and update crate dependencies in `async-opcua-crypto/Cargo.toml`
- [X] T002 [P] Verify and update crate dependencies in `async-opcua-pubsub/Cargo.toml`
- [X] T003 [P] Verify and update crate dependencies in `async-opcua-server/Cargo.toml`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can be implemented

- [X] T004 Define common Error Types for Advanced Compliance (`BadFilterNotSupported`, `BadUserAccessDenied`) in `async-opcua-core/src/error.rs`

**Checkpoint**: Foundation ready - user story implementation can now begin in parallel

---

## Phase 3: User Story 1 - Secure PubSub Message Exchange (Priority: P1) 🎯 MVP

**Goal**: Cryptographically signed and encrypted PubSub NetworkMessages using keys retrieved from GetSecurityKeys.

**Independent Test**: Configure a dataset publisher to sign/encrypt messages, and subscribers to verify/decrypt.

### Tests for User Story 1
- [X] T005 [P] [US1] Add integration test for signed/encrypted pubsub in `async-opcua-pubsub/tests/security_tests.rs`

### Implementation for User Story 1
- [X] T006 [P] [US1] Create `SecurityGroup` struct in `async-opcua-pubsub/src/security/group.rs`
- [X] T007 [P] [US1] Implement time-based rotation logic in `async-opcua-pubsub/src/security/rotation.rs`
- [X] T008 [P] [US1] Create `GetSecurityKeys` service API contract in `async-opcua-server/src/services/security.rs`
- [X] T009 [US1] Implement `GetSecurityKeys` handler in `async-opcua-server/src/services/security.rs`
- [X] T010 [US1] Integrate `SecurityGroup` with Publisher signing in `async-opcua-pubsub/src/engine.rs`
- [X] T011 [US1] Integrate `SecurityGroup` with Subscriber verification in `async-opcua-pubsub/src/engine.rs`

**Checkpoint**: At this point, User Story 1 should be fully functional and testable independently

---

## Phase 4: User Story 2 - Subscription Event Filtering (Priority: P1)

**Goal**: Filter events using SelectClauses and WhereClauses.

**Independent Test**: Configure a subscription with an EventFilter and verify only matched events are sent.

### Tests for User Story 2
- [X] T012 [P] [US2] Add integration test for Event Filtering in `async-opcua-server/tests/event_filter_tests.rs`

### Implementation for User Story 2
- [X] T013 [P] [US2] Parse `EventFilter` struct into memory in `async-opcua-server/src/services/subscription/filter.rs`
- [X] T014 [P] [US2] Implement `SelectClauses` extraction logic in `async-opcua-server/src/services/subscription/select.rs`
- [X] T015 [US2] Implement `WhereClauses` evaluation logic in `async-opcua-server/src/services/subscription/where_clause.rs`
- [X] T016 [US2] Enforce authorization checks on event fields in `async-opcua-server/src/services/subscription/filter.rs`
- [X] T017 [US2] Integrate `EventFilter` into the subscription notification loop in `async-opcua-server/src/services/subscription.rs`

**Checkpoint**: At this point, User Stories 1 AND 2 should both work independently

---

## Phase 5: User Story 3 - Asymmetric Encrypted Secrets (Priority: P1)

**Goal**: Decrypt user credentials using RSA-OAEP, handle failure with tarpitting.

**Independent Test**: Connect client using EncryptedSecret, verify server decrypts and activates session.

### Tests for User Story 3
- [X] T018 [P] [US3] Add unit test for decryption failure tarpitting in `async-opcua-server/tests/security_tests.rs`

### Implementation for User Story 3
- [X] T019 [P] [US3] Implement RSA-OAEP decryption utility in `async-opcua-crypto/src/identity/rsa_oaep.rs`
- [X] T020 [US3] Update `ActivateSession` handler to parse `EncryptedSecret` in `async-opcua-server/src/session/negotiate.rs`
- [X] T021 [US3] Implement `tokio::time::sleep` tarpitting on validation failure in `async-opcua-server/src/session/negotiate.rs`

**Checkpoint**: All P1 user stories should now be independently functional

---

## Phase 6: User Story 4 - Graph Query Service (Priority: P2)

**Goal**: Complex object graph queries using QueryFirst/QueryNext.

**Independent Test**: Execute a QueryFirst call with a query filter, verify server returns matching NodeIds.

### Tests for User Story 4
- [X] T022 [P] [US4] Add integration test for complex queries in `async-opcua-server/tests/query_tests.rs`

### Implementation for User Story 4
- [X] T023 [P] [US4] Define `QueryFirstRequest` and `QueryNextRequest` structures in `async-opcua-server/src/services/query/models.rs`
- [X] T024 [P] [US4] Implement basic node type and property filtering in `async-opcua-server/src/services/query/filter.rs`
- [X] T025 [US4] Implement graph traversal iterator (complex joining) in `async-opcua-server/src/services/query/traversal.rs`
- [X] T026 [US4] Implement `QueryFirst` handler with pagination logic in `async-opcua-server/src/services/query/handlers.rs`
- [X] T027 [US4] Implement `QueryNext` handler using continuation points in `async-opcua-server/src/services/query/handlers.rs`
- [X] T028 [US4] Enforce authorization checks on query results in `async-opcua-server/src/services/query/handlers.rs`

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: Improvements that affect multiple user stories

- [X] T029 [P] Documentation updates for new endpoints in `docs/advanced_compliance.md`
- [X] T030 Code cleanup and refactoring across new services
- [X] T031 Run quickstart.md validation
- [X] T032 [P] Add benchmark/load tests for SC-003 (Auth < 50ms latency) in `async-opcua-server/tests/perf_auth.rs`
- [X] T033 [P] Add benchmark/load tests for SC-004 (Query < 100ms for 100k nodes) in `async-opcua-server/tests/perf_query.rs`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Stories (Phase 3+)**: All depend on Foundational phase completion
  - User stories can then proceed in parallel
- **Polish (Final Phase)**: Depends on all desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational - No dependencies on other stories
- **User Story 2 (P1)**: Can start after Foundational - No dependencies on other stories
- **User Story 3 (P1)**: Can start after Foundational - No dependencies on other stories
- **User Story 4 (P2)**: Can start after Foundational - No dependencies on other stories

### Parallel Opportunities

- US1, US2, US3, and US4 can be worked on completely in parallel by different subagents.
- Within stories, models and utility functions marked [P] can run in parallel before their service implementations.

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1 & 2
2. Complete Phase 3 (US1)
3. Validate independent functionality

### Incremental Delivery

Deliver each User Story iteratively, validating each increment independently.
