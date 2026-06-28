# Tasks: Part 14 Subscriber Runtime

**Input**: Design documents from `/specs/037-part14-subscriber/`
**Prerequisites**: [plan.md](./plan.md), [spec.md](./spec.md), [research.md](./research.md), [data-model.md](./data-model.md), [contracts/](./contracts/), [quickstart.md](./quickstart.md)
**Tests**: Required by FR-018. Write each red test before the matching implementation task.
**Format**: `[ID] [P?] [Story] Description (Spec: OPC-10000-14 §x.y.z; Req: FR/SC)`

## Phase 1: Setup

**Purpose**: Create isolated subscriber test surfaces and module entry points.

- [X] T001 [P] Create `async-opcua-pubsub/tests/subscriber_plain_uadp_tests.rs` with fixture imports only. (Spec: OPC-10000-14 §5.4.6.2.2; Req: FR-018)
- [X] T002 [P] Create `async-opcua-pubsub/tests/subscriber_security_tests.rs` with fixture imports only. (Spec: OPC-10000-14 §7.2.4.4.2; Req: FR-018)
- [X] T003 [P] Create `async-opcua-pubsub/tests/subscriber_status_tests.rs` with fixture imports only. (Spec: OPC-10000-14 §9.1.10.1; Req: FR-018)
- [X] T004 Add a subscriber runtime module declaration in `async-opcua-pubsub/src/subscriber.rs`. (Spec: OPC-10000-14 §3.1.4; Req: FR-001)
- [X] T005 Export `SubscriberRuntime` from `async-opcua-pubsub/src/lib.rs`. (Spec: OPC-10000-14 §3.1.4; Req: FR-001)

**Checkpoint**: Test files and module surfaces exist without behavior changes.

## Phase 2: Foundational Configuration

**Purpose**: Define validated Part 14 subscriber configuration before receive behavior.

- [X] T006 Add a red duplicate DataSetReader name validation test in `async-opcua-pubsub/tests/subscriber_plain_uadp_tests.rs`. (Spec: OPC-10000-14 §6.2.9.13.1; Req: FR-003)
- [X] T007 Add a red duplicate target Variable validation test in `async-opcua-pubsub/tests/subscriber_plain_uadp_tests.rs`. (Spec: OPC-10000-14 §6.2.10.2.1; Req: FR-005)
- [X] T008 Add a red legacy `subscribed_variables` to target mapping test in `async-opcua-pubsub/tests/subscriber_plain_uadp_tests.rs`. (Spec: OPC-10000-14 §6.2.10.2.3; Req: FR-005)
- [X] T009 Add `FieldTargetConfig` to `async-opcua-pubsub/src/config.rs`. (Spec: OPC-10000-14 §6.2.10.2.3; Req: FR-005)
- [X] T010 Add DataSetReader filter fields to `async-opcua-pubsub/src/config.rs`. (Spec: OPC-10000-14 §6.2.7.1; Req: FR-002)
- [X] T011 Add DataSetReader timeout fields to `async-opcua-pubsub/src/config.rs`. (Spec: OPC-10000-14 §6.2.9.6; Req: FR-008)
- [X] T012 Add ReaderGroup security fields to `async-opcua-pubsub/src/config.rs`. (Spec: OPC-10000-14 §6.2.5.2; Req: FR-011)
- [X] T013 Add DataSetReader security override fields to `async-opcua-pubsub/src/config.rs`. (Spec: OPC-10000-14 §6.2.9.9; Req: FR-011)
- [X] T014 Implement duplicate DataSetReader name validation in `async-opcua-pubsub/src/config.rs`. (Spec: OPC-10000-14 §6.2.9.13.1; Req: FR-003)
- [X] T015 Implement duplicate target Variable validation in `async-opcua-pubsub/src/config.rs`. (Spec: OPC-10000-14 §6.2.10.2.1; Req: FR-005)
- [X] T016 Implement legacy target mapping in `async-opcua-pubsub/src/config.rs`. (Spec: OPC-10000-14 §6.2.10.2.3; Req: FR-005)
- [X] T017 Convert DataSetReader target mappings in `async-opcua-pubsub/src/config_methods.rs`. (Spec: OPC-10000-14 §9.1.6.10; Req: FR-005)
- [X] T018 Reflect DataSetReader target mapping properties in `async-opcua-pubsub/src/pubsub_model.rs`. (Spec: OPC-10000-14 §9.1.8.2; Req: FR-010)
- [X] T019 Add `DataSetReaderStatus` types in `async-opcua-pubsub/src/subscriber.rs`. (Spec: OPC-10000-14 §9.1.10.1; Req: FR-010)
- [X] T020 Add `SubscriberApplyOutcome` in `async-opcua-pubsub/src/subscriber.rs`. (Spec: OPC-10000-14 §5.4.2.2; Req: FR-010)

**Checkpoint**: Configuration validation can fail before network tasks start.

## Phase 3: User Story 1 - Receive Plain UADP DataSetMessages (P1)

**Goal**: A broker-less UADP UDP message updates only matching target Variables.
**Independent Test**: A loopback or in-memory datagram updates three configured target Variables through one DataSetReader.

### Tests

- [X] T021 [US1] Add a red matching PublisherId test in `async-opcua-pubsub/tests/subscriber_plain_uadp_tests.rs`. (Spec: OPC-10000-14 §6.2.7.1; Req: FR-002)
- [X] T022 [US1] Add a red matching WriterGroupId test in `async-opcua-pubsub/tests/subscriber_plain_uadp_tests.rs`. (Spec: OPC-10000-14 §7.2.4.1; Req: FR-002)
- [X] T023 [US1] Add a red matching DataSetWriterId test in `async-opcua-pubsub/tests/subscriber_plain_uadp_tests.rs`. (Spec: OPC-10000-14 §6.2.9.3; Req: FR-002)
- [X] T024 [US1] Add a red key-frame field-order decode test in `async-opcua-pubsub/tests/subscriber_plain_uadp_tests.rs`. (Spec: OPC-10000-14 §7.2.4.5.5; Req: FR-004)
- [X] T025 [US1] Add a red wildcard PublisherId filter test in `async-opcua-pubsub/tests/subscriber_plain_uadp_tests.rs`. (Spec: OPC-10000-14 §6.2.7.1; Req: FR-002)
- [X] T026 [US1] Add a red wildcard DataSetWriterId filter test in `async-opcua-pubsub/tests/subscriber_plain_uadp_tests.rs`. (Spec: OPC-10000-14 §6.2.9.3; Req: FR-002)
- [X] T027 [US1] Add a red nonmatching PublisherId no-write test in `async-opcua-pubsub/tests/subscriber_plain_uadp_tests.rs`. (Spec: OPC-10000-14 §6.2.7.1; Req: SC-002)
- [X] T028 [US1] Add a red nonmatching WriterGroupId no-write test in `async-opcua-pubsub/tests/subscriber_plain_uadp_tests.rs`. (Spec: OPC-10000-14 §7.2.4.1; Req: SC-002)
- [X] T029 [US1] Add a red nonmatching NetworkMessageNumber no-write test in `async-opcua-pubsub/tests/subscriber_plain_uadp_tests.rs`. (Spec: OPC-10000-14 §7.2.4.4.2; Req: SC-002)
- [X] T030 [US1] Add a red nonmatching DataSetWriterId no-write test in `async-opcua-pubsub/tests/subscriber_plain_uadp_tests.rs`. (Spec: OPC-10000-14 §6.2.9.3; Req: SC-002)
- [X] T031 [US1] Add a red field-count mismatch test in `async-opcua-pubsub/tests/subscriber_plain_uadp_tests.rs`. (Spec: OPC-10000-14 §5.4.2.2; Req: FR-006)
- [X] T032 [US1] Add a red malformed datagram test in `async-opcua-pubsub/tests/subscriber_plain_uadp_tests.rs`. (Spec: OPC-10000-14 §7.2.4.4.2; Req: FR-013)

### Implementation

- [X] T033 [US1] Implement DataSetReader filter matching in `async-opcua-pubsub/src/subscriber.rs`. (Spec: OPC-10000-14 §6.1; Req: FR-002)
- [X] T034 [US1] Implement filtered-message diagnostics in `async-opcua-pubsub/src/subscriber.rs`. (Spec: OPC-10000-14 §6.1; Req: SC-002)
- [X] T035 [US1] Implement missing-header fallback from DataSetReader config in `async-opcua-pubsub/src/subscriber.rs`. (Spec: OPC-10000-14 §7.2.4.1; Req: FR-002)
- [X] T036 [US1] Implement key-frame field-order decode dispatch in `async-opcua-pubsub/src/subscriber.rs`. (Spec: OPC-10000-14 §7.2.4.5.5; Req: FR-004)
- [X] T037 [US1] Implement target Variable preflight resolution in `async-opcua-pubsub/src/subscriber.rs`. (Spec: OPC-10000-14 §6.2.10.2.3; Req: FR-005)
- [X] T038 [US1] Implement atomic target Variable apply in `async-opcua-pubsub/src/subscriber.rs`. (Spec: OPC-10000-14 §5.4.6.2.2; Req: FR-006)
- [X] T039 [US1] Implement plain UADP datagram processing in `async-opcua-pubsub/src/subscriber.rs`. (Spec: OPC-10000-14 §5.4.2.2; Req: FR-001)
- [X] T040 [US1] Implement bounded datagram rejection in `async-opcua-pubsub/src/subscriber.rs`. (Spec: OPC-10000-14 §7.2.4.4.2; Req: FR-014)
- [X] T041 [US1] Add UDP subscriber endpoint parsing in `async-opcua-pubsub/src/transport/udp.rs`. (Spec: OPC-10000-14 §6.4.1.6.1; Req: FR-015)
- [X] T042 [US1] Add unicast UDP receive loop in `async-opcua-pubsub/src/transport/udp.rs`. (Spec: OPC-10000-14 §5.4.6.2.2; Req: FR-015)
- [X] T043 [US1] Add multicast UDP join support in `async-opcua-pubsub/src/transport/udp.rs`. (Spec: OPC-10000-14 §5.4.6.2.2; Req: FR-015)
- [X] T044 [US1] Wire subscriber loop startup in `async-opcua-pubsub/src/engine.rs`. (Spec: OPC-10000-14 §6.1; Req: FR-001)
- [X] T045 [US1] Wire subscriber loop cancellation in `async-opcua-pubsub/src/engine.rs`. (Spec: OPC-10000-14 §5.4.6.2.2; Req: FR-015)
- [X] T046 [US1] Run `cargo test -p async-opcua-pubsub subscriber_plain_uadp`. (Spec: OPC-10000-14 §5.4.6.2.2; Req: SC-001)

**Checkpoint**: Plain UADP subscriber MVP works independently.

## Phase 4: User Story 2 - Receive Secured UADP DataSetMessages (P2)

**Goal**: Secured UADP datagrams verify before decode or target mutation.
**Independent Test**: Signed/encrypted loopback datagram updates targets, while tampered or replayed datagrams do not.

### Tests

- [X] T047 [US2] Add a red SignAndEncrypt apply test in `async-opcua-pubsub/tests/subscriber_security_tests.rs`. (Spec: OPC-10000-14 Annex A.2.1.6; Req: FR-012)
- [X] T048 [US2] Add a red tampered signature rejection test in `async-opcua-pubsub/tests/subscriber_security_tests.rs`. (Spec: OPC-10000-14 Annex A.2.1.5; Req: FR-013)
- [X] T049 [US2] Add a red replay rejection test in `async-opcua-pubsub/tests/subscriber_security_tests.rs`. (Spec: OPC-10000-14 §7.2.4.4.3.2; Req: FR-012)
- [X] T050 [US2] Add a red unknown token rejection test in `async-opcua-pubsub/tests/subscriber_security_tests.rs`. (Spec: OPC-10000-14 §7.2.4.4.2; Req: FR-013)
- [X] T051 [US2] Add a red DataSetReader security override test in `async-opcua-pubsub/tests/subscriber_security_tests.rs`. (Spec: OPC-10000-14 §6.2.9.9; Req: FR-011)

### Implementation

- [X] T052 [US2] Implement effective security resolution in `async-opcua-pubsub/src/subscriber.rs`. (Spec: OPC-10000-14 §6.2.9.9; Req: FR-011)
- [X] T053 [US2] Invoke secured UADP decode before plain UADP dispatch in `async-opcua-pubsub/src/subscriber.rs`. (Spec: OPC-10000-14 §7.2.4.4.2; Req: FR-012)
- [X] T054 [US2] Bind subscriber replay tracking to reader security context in `async-opcua-pubsub/src/engine.rs`. (Spec: OPC-10000-14 §7.2.4.4.3.2; Req: FR-012)
- [X] T055 [US2] Record security failure diagnostics in `async-opcua-pubsub/src/subscriber.rs`. (Spec: OPC-10000-14 §9.1.10.1; Req: FR-010)
- [X] T056 [US2] Reject configured secure readers when security keys are unavailable in `async-opcua-pubsub/src/subscriber.rs`. (Spec: OPC-10000-14 §5.4.5.3; Req: FR-013)
- [X] T057 [US2] Run `cargo test -p async-opcua-pubsub subscriber_security`. (Spec: OPC-10000-14 Annex A.2.1.6; Req: SC-003)

**Checkpoint**: Secured UADP subscriber path fails closed.

## Phase 5: User Story 3 - Observe Reader State and Loss Diagnostics (P3)

**Goal**: DataSetReader state and diagnostics are inspectable without log scraping.
**Independent Test**: A direct runtime test drives first message, gap, duplicate, timeout, recovery.

### Tests

- [X] T058 [US3] Add a red PreOperational to Operational test in `async-opcua-pubsub/tests/subscriber_status_tests.rs`. (Spec: OPC-10000-14 §6.2.1; Req: FR-008)
- [X] T059 [US3] Add a red MessageReceiveTimeout Error test in `async-opcua-pubsub/tests/subscriber_status_tests.rs`. (Spec: OPC-10000-14 §6.2.9.6; Req: FR-008)
- [X] T060 [US3] Add a red timeout recovery test in `async-opcua-pubsub/tests/subscriber_status_tests.rs`. (Spec: OPC-10000-14 §6.2.9.6; Req: FR-008)
- [X] T061 [US3] Add a red sequence gap diagnostic test in `async-opcua-pubsub/tests/subscriber_status_tests.rs`. (Spec: OPC-10000-14 §7.2.3; Req: FR-007)
- [X] T062 [US3] Add a red duplicate sequence diagnostic test in `async-opcua-pubsub/tests/subscriber_status_tests.rs`. (Spec: OPC-10000-14 §7.2.3; Req: FR-007)
- [X] T063 [US3] Add a red metadata major-version timeout test in `async-opcua-pubsub/tests/subscriber_status_tests.rs`. (Spec: OPC-10000-14 §6.2.9.4; Req: FR-009)

### Implementation

- [X] T064 [US3] Implement DataSetReader state transitions in `async-opcua-pubsub/src/subscriber.rs`. (Spec: OPC-10000-14 §6.2.1; Req: FR-008)
- [X] T065 [US3] Implement MessageReceiveTimeout tracking in `async-opcua-pubsub/src/subscriber.rs`. (Spec: OPC-10000-14 §6.2.9.6; Req: FR-008)
- [X] T066 [US3] Implement sequence continuity tracking in `async-opcua-pubsub/src/subscriber.rs`. (Spec: OPC-10000-14 §7.2.3; Req: FR-007)
- [X] T067 [US3] Implement metadata major-version error handling in `async-opcua-pubsub/src/subscriber.rs`. (Spec: OPC-10000-14 §6.2.9.4; Req: FR-009)
- [X] T068 [US3] Expose reader status snapshots in `async-opcua-pubsub/src/engine.rs`. (Spec: OPC-10000-14 §9.1.10.1; Req: FR-010)
- [X] T069 [US3] Reflect reader status snapshots in `async-opcua-pubsub/src/pubsub_model.rs`. (Spec: OPC-10000-14 §9.1.8.2; Req: FR-010)
- [X] T070 [US3] Run `cargo test -p async-opcua-pubsub subscriber_status`. (Spec: OPC-10000-14 §9.1.10.1; Req: SC-004)

**Checkpoint**: Reader status is observable and standards-aligned.

## Phase 6: User Story 4 - Validate Configuration and Document Limits (P4)

**Goal**: Unsupported subscriber surfaces fail explicitly and docs match behavior.
**Independent Test**: Unsupported configurations return deterministic errors before network tasks start.

### Tests

- [X] T071 [US4] Add a red broker transport rejection test in `async-opcua-pubsub/tests/subscriber_plain_uadp_tests.rs`. (Spec: OPC-10000-14 §6.4.2.6.1; Req: FR-016)
- [X] T072 [US4] Add a red JSON mapping rejection test in `async-opcua-pubsub/tests/subscriber_plain_uadp_tests.rs`. (Spec: OPC-10000-14 §6.3.2.4.3; Req: FR-016)
- [X] T073 [US4] Add a red custom UDP fragment rejection test in `async-opcua-pubsub/tests/subscriber_plain_uadp_tests.rs`. (Spec: OPC-10000-14 §5.4.6.2.2; Req: FR-016)
- [X] T074 [US4] Add a red RawData payload rejection test in `async-opcua-pubsub/tests/subscriber_plain_uadp_tests.rs`. (Spec: OPC-10000-14 §5.3.2; Req: FR-016)

### Implementation

- [X] T075 [US4] Reject broker subscriber transports in `async-opcua-pubsub/src/subscriber.rs`. (Spec: OPC-10000-14 §6.4.2.6.1; Req: FR-016)
- [X] T076 [US4] Reject JSON subscriber mapping in `async-opcua-pubsub/src/subscriber.rs`. (Spec: OPC-10000-14 §6.3.2.4.3; Req: FR-016)
- [X] T077 [US4] Reject non-Part-14 UDP fragment headers in `async-opcua-pubsub/src/transport/udp.rs`. (Spec: OPC-10000-14 §5.4.6.2.2; Req: FR-016)
- [X] T078 [US4] Reject RawData DataSetMessage payloads in `async-opcua-pubsub/src/subscriber.rs`. (Spec: OPC-10000-14 §5.3.2; Req: FR-016)
- [X] T079 [US4] Reject delta-frame DataSetMessages in `async-opcua-pubsub/src/subscriber.rs`. (Spec: OPC-10000-14 §7.2.4.5.6; Req: FR-016)
- [X] T080 [US4] Reject event DataSetMessages in `async-opcua-pubsub/src/subscriber.rs`. (Spec: OPC-10000-14 §7.2.4.5.7; Req: FR-016)
- [X] T081 [US4] Update subscriber limitations in `docs/pubsub.md`. (Spec: OPC-10000-14 §5.4.6.2.2; Req: FR-017)
- [X] T082 [US4] Add a subscriber runtime example to `docs/pubsub.md`. (Spec: OPC-10000-14 §6.2.10.2.3; Req: FR-017)
- [X] T083 [US4] Run `cargo test -p async-opcua-pubsub subscriber_plain_uadp`. (Spec: OPC-10000-14 §5.4.6.2.2; Req: SC-006)

**Checkpoint**: Unsupported scope is explicit in code and documentation.

## Phase 7: Polish and Verification

**Purpose**: Verify the full feature surface after all selected user stories.

- [X] T084 Run `cargo fmt --all`. (Spec: OPC-10000-14 §3.1.4; Req: SC-005)
- [X] T085 Run `cargo test -p async-opcua-pubsub message_security`. (Spec: OPC-10000-14 Annex A.2.1.5; Req: SC-003)
- [X] T086 Run `cargo test -p async-opcua-pubsub`. (Spec: OPC-10000-14 §5.4.2.2; Req: SC-005)
- [X] T087 Run `cargo test --workspace`. (Spec: OPC-10000-14 §5.4.6.2.2; Req: SC-005)
- [X] T088 Check `docs/pubsub.md` no longer says subscriber support is decode-only. (Spec: OPC-10000-14 §5.4.6.2.2; Req: FR-017)
- [X] T089 Check malformed subscriber tests cover panic-free malformed datagrams. (Spec: OPC-10000-14 §7.2.4.4.2; Req: SC-007)

## Dependencies and Execution Order

- Phase 1 must complete before Phase 2.
- Phase 2 must complete before any user story implementation.
- US1 is the MVP and must complete before US2 because secured processing dispatches to the same plain UADP apply path.
- US3 depends on US1 because state transitions require accepted messages.
- US4 can start after Phase 2, but documentation tasks should wait until US1 through US3 behavior is stable.
- Phase 7 runs after all selected user stories.

## Parallel Opportunities

- T001, T002, and T003 can run in parallel.
- Security tests in US2 can be authored after T002 without editing US1 test files.
- Status tests in US3 can be authored after T003 without editing US1 or US2 test files.
- Documentation tasks T081 and T082 can run in parallel with final focused test runs after behavior is stable.

## MVP Scope

Complete Phases 1 through 3 for the minimum useful Part 14 subscriber runtime: validated ReaderGroup/DataSetReader configuration, plain UADP datagram receive, matching filters, target Variable apply, and panic-free malformed datagram rejection.
