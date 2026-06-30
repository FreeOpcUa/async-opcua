# Tasks: Audit Findings Remediation

**Input**: Design documents from `/specs/043-fix-audit-findings/`
**Prerequisites**: [plan.md](./plan.md), [spec.md](./spec.md), [research.md](./research.md), [data-model.md](./data-model.md), [contracts/audit-remediation.md](./contracts/audit-remediation.md), [quickstart.md](./quickstart.md)
**Tests**: Required by FR-017. Every remediation starts with a negative-path or lock-in test that must fail before implementation unless the task is explicitly a not-a-bug verification.
**Execution rule**: Work one task to completion before starting the next task. `[P]` marks file-level independence for staffed review only, not permission to batch changes.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel with other `[P]` tasks if staffed because it touches different files and has no dependency on an incomplete task.
- **[Story]**: US1, US2, or US3 from [spec.md](./spec.md).
- Every implementation/remediation task line includes the primary file path to edit; verification-only tasks name the command to run and the evidence file to update.
- Every remediation task includes the OPC UA part/section grounding the expected behavior.
- Suffixes such as `T067a` and `T067b` intentionally split an original task into atomic, independently verifiable subtasks while preserving the original task family.

## Phase 1: Setup

**Purpose**: Freeze the working list and make later remediation traceable.

- [X] T001 Create the selected-finding traceability matrix for 043 in specs/043-fix-audit-findings/finding-matrix.md, mapping each listed task to its audit source, OPC UA section, expected status, state assertion, and targeted verification command.
- [X] T002 [P] Create the per-task verification log template in specs/043-fix-audit-findings/verification.md with columns for task id, failing-test evidence, implementation command, final command, and residual risk.

---

## Phase 2: Foundational

**Purpose**: Add shared test helpers and rule checks that block reliable story work.

- [X] T003a Add shared ActivateSession status-equality assertions in async-opcua-server/tests/security_tests.rs.
- [X] T003b Add shared ActivateSession identity-unchanged assertions in async-opcua-server/tests/security_tests.rs.
- [X] T003c Add shared ActivateSession no-certificate-audit-before-authentication assertions in async-opcua-server/tests/security_tests.rs.
- [X] T004a Add shared PubSub malformed-datagram decode-rejected assertions in async-opcua-pubsub/tests/pubsub_tests.rs.
- [X] T004b Add shared PubSub malformed-datagram subscriber-state-unchanged assertions in async-opcua-pubsub/tests/pubsub_tests.rs.
- [X] T005a Add shared certificate material registry snapshot helpers in async-opcua-server/tests/gds_pull_methods.rs.
- [X] T005b Add shared certificate material unchanged assertion helpers in async-opcua-server/tests/gds_pull_methods.rs.
- [X] T006 Add an MCP citation check section to specs/043-fix-audit-findings/finding-matrix.md requiring each task to cite the exact OPC UA document and section before implementation starts.

**Checkpoint**: Shared traceability and helper scaffolding exist. User story tasks can now proceed one at a time.

---

## Phase 3: User Story 1 - Enforce Identity And Session Trust Boundaries (Priority: P1) MVP

**Goal**: Reject identity-token and session-activation failures at the earliest correct trust boundary, before credentials, user mappings, certificate audits, or session identity state are changed.

**Independent Test**: Run the targeted command listed on each task and then run `cargo test -p async-opcua-server security_tests && cargo test -p async-opcua --test integration_tests adversarial`.

### Tests for User Story 1

- [X] T007a [US1] Add a failing test for P4-SESS-07 in async-opcua-server/src/session/manager.rs proving OPC-10000-4 5.7.3.1 rejects cross-channel activation when SecurityMode differs before user authentication.
- [X] T007b [US1] Add a failing test for P4-SESS-07 in async-opcua-server/src/session/manager.rs proving OPC-10000-4 5.7.3.1 rejects cross-channel activation when SecurityPolicy differs before user authentication.
- [X] T008 [US1] Add a failing test for P4-SESS-08 in async-opcua-server/src/session/manager.rs proving OPC-10000-4 5.7.3.1 rejects anonymous activation over a new Sign-only SecureChannel when a non-anonymous user is required.
- [X] T009 [US1] Add a failing username-token protection test in async-opcua-server/tests/security_tests.rs proving OPC-10000-4 7.40.4 and 7.41 reject unprotected username/password credentials without authenticating the user.
- [X] T010 [US1] Add a failing issued-token protection test in async-opcua-server/tests/security_tests.rs proving OPC-10000-4 7.40.6 and 7.41 reject unprotected issued-token credentials without validating claims.
- [X] T011 [US1] Add a failing X.509 enhanced-signature test in async-opcua-server/tests/security_tests.rs proving OPC-10000-4 6.1.8 and 7.40.5 reject a legacy-only X509IdentityToken signature where channel-bound proof is required.
- [X] T012 [US1] Add a failing X.509 missing-proof test in async-opcua-server/tests/security_tests.rs proving OPC-10000-4 5.7.3.3 and 7.40.5 return the user-token signature status when userTokenSignature is absent.
- [X] T013 [US1] Add a failing state-cleanup test in async-opcua-server/src/session/manager.rs proving OPC-10000-4 5.7.3.2 and 5.7.3.3 failed X.509 activation cannot leave rejected identity state on the session before a later valid activation.

### Implementation for User Story 1

- [X] T014a [US1] Enforce SecurityMode equality for cross-channel activation in async-opcua-server/src/session/manager.rs per OPC-10000-4 5.7.3.1, returning the secure-channel mismatch status before authentication.
- [X] T014b [US1] Enforce SecurityPolicy equality for cross-channel activation in async-opcua-server/src/session/manager.rs per OPC-10000-4 5.7.3.1, returning the secure-channel mismatch status before authentication.
- [X] T015 [US1] Enforce the non-anonymous-on-new-Sign-channel rule in async-opcua-server/src/session/manager.rs per OPC-10000-4 5.7.3.1 without changing existing anonymous None-policy activation.
- [X] T016 [US1] Enforce username/password token protection in async-opcua-server/src/session/negotiate.rs and async-opcua-server/src/authenticator.rs per OPC-10000-4 7.40.4 and 7.41, preserving precise identity-token statuses.
- [X] T017 [US1] Enforce issued-token protection in async-opcua-server/src/session/negotiate.rs and async-opcua-server/src/authenticator.rs per OPC-10000-4 7.40.6 and 7.41 before JWT or claim validation runs.
- [X] T018 [US1] Implement channel-bound X.509 user-token signature selection in async-opcua-server/src/authenticator.rs per OPC-10000-4 6.1.8 and 7.40.5, preserving legacy signature acceptance only for policies that permit it.
- [X] T019 [US1] Map missing or malformed X.509 userTokenSignature to the precise ActivateSession failure in async-opcua-server/src/authenticator.rs per OPC-10000-4 5.7.3.3 and 7.40.5.
- [X] T020 [US1] Delay session identity, roles, and claims assignment in async-opcua-server/src/session/manager.rs until all OPC-10000-4 5.7.3.2 and 5.7.3.3 activation preconditions succeed, and clear rejected intermediate state on every failed activation.
- [X] T021a [US1] Run `cargo test -p async-opcua-server security_tests` and record the result in specs/043-fix-audit-findings/verification.md.
- [X] T021b [US1] Run `cargo test -p async-opcua-server session::manager` and record the result in specs/043-fix-audit-findings/verification.md.
- [X] T021c [US1] Run `cargo test -p async-opcua --test integration_tests adversarial` and record the result in specs/043-fix-audit-findings/verification.md.

**Checkpoint**: US1 is independently complete when every US1 test fails before its implementation task, passes afterward, and no session identity or credential side effect occurs before the required trust boundary.

---

## Phase 4: User Story 2 - Align Certificate And GDS Management Outcomes (Priority: P2)

**Goal**: Make certificate validation and certificate-management methods return OPC UA-conformant statuses, audit events, authorization failures, and atomic trust-material outcomes.

**Independent Test**: Run the targeted command listed on each task and then run `cargo test -p async-opcua-crypto cert_chain && cargo test -p async-opcua-server --test gds_pull_methods && cargo test -p async-opcua-server --test gds_integration`.

### Tests for User Story 2

- [X] T022 [US2] Add a failing non-regression test in async-opcua-server/tests/security_tests.rs proving application-certificate rejected-store failures still return the existing public CreateSession/OpenSecureChannel contract per OPC-10000-4 6.1.3 unless an acceptance test changes it.
- [X] T023 [US2] Add a failing user-identity certificate rejected-store test in async-opcua-server/tests/security_tests.rs proving OPC-10000-4 6.1.3 maps rejected X.509 user certificates to Bad_CertificateUntrusted and emits the certificate audit event.
- [X] T024 [US2] Add a failing weak issuer signature test in async-opcua-crypto/src/tests/cert_chain.rs proving OPC-10000-4 6.1.3 rejects disallowed issuer signature algorithms with a certificate policy or invalid certificate status.
- [X] T025 [US2] Add a failing weak revocation signature test in async-opcua-crypto/src/tests/cert_chain.rs proving OPC-10000-4 6.1.3 rejects disallowed CRL or revocation signature algorithms.
- [X] T026 [US2] Add a failing CA path-length constraint test in async-opcua-crypto/src/tests/cert_chain.rs proving OPC-10000-4 6.1.3 rejects chains that violate certificate path constraints.
- [X] T027a [US2] Add a failing missing PKI storage test in async-opcua-crypto/src/tests/cert_chain.rs proving certificate validation fails closed per OPC-10000-4 6.1.3.
- [X] T027b [US2] Add a failing corrupt PKI storage test in async-opcua-crypto/src/tests/cert_chain.rs proving certificate validation reports auditable certificate context per OPC-10000-4 6.1.3.
- [X] T028 [US2] Add a failing GetRejectedList authorization test in async-opcua-server/tests/gds_pull_methods.rs proving OPC-10000-12 7.8.3.2 requires an authenticated SecureChannel and SecurityAdmin before registry reads.
- [X] T029 [US2] Add a failing UpdateCertificate authorization test in async-opcua-server/tests/gds_pull_methods.rs proving OPC-10000-12 7.10.5 requires an encrypted SecureChannel and SecurityAdmin before recording certificate material.
- [X] T030 [US2] Add a failing CreateSigningRequest authorization test in async-opcua-server/src/gds/push_methods.rs proving OPC-10000-12 7.10.10 requires an encrypted SecureChannel and SecurityAdmin before generating request state.
- [X] T031 [US2] Add a failing authorization test for the implementation-specific FinishSigningRequest helper in async-opcua-server/tests/gds_pull_methods.rs proving its certificate-material return path inherits the OPC-10000-12 7.4 Push Management flow and the encrypted SecureChannel plus SecurityAdmin guard required by OPC-10000-12 7.10.5; do not label FinishSigningRequest as a standard OPC UA method.
- [X] T032a [US2] Add a failing malformed UpdateCertificate certificate input test in async-opcua-server/tests/gds_pull_methods.rs proving OPC-10000-12 7.10.5 rejects malformed certificate bytes without mutating the registry.
- [X] T032b [US2] Add a failing malformed UpdateCertificate private-key input test in async-opcua-server/tests/gds_pull_methods.rs proving OPC-10000-12 7.10.5 rejects malformed private-key bytes without mutating the registry.
- [X] T033 [US2] Add a failing GDS cache atomicity test in async-opcua-server/tests/gds_cache.rs proving a simulated OPC-10000-12 7.4 and 7.10.5 certificate/private-key replacement write failure preserves the previous credential pair.
- [X] T034a [US2] Add a failing OpenSecureChannel certificate-audit source-name test in async-opcua/tests/integration/adversarial.rs proving OPC-10000-5 6.4.15 and OPC-10000-4 6.1.3 use the certificate audit source name.
- [X] T034b [US2] Add a failing suppressed certificate-validation success audit test in async-opcua/tests/integration/adversarial.rs proving OPC-10000-4 5.7.2.2 and 6.1.3 plus OPC-10000-5 6.4.15 emit an auditable record for SC-003 when a suppressed certificate finding succeeds.

### Implementation for User Story 2

- [X] T035 [US2] Split application-certificate and user-identity certificate status mapping in async-opcua-crypto/src/certificate_store.rs so OPC-10000-4 6.1.3 user identity precision does not unintentionally change application-certificate public behavior.
- [X] T036 [US2] Emit user-identity certificate rejected-store status and audit context in async-opcua-server/src/session/audit.rs and async-opcua-server/src/authenticator.rs per OPC-10000-4 6.1.3.
- [X] T037 [US2] Enforce disallowed issuer signature algorithms in async-opcua-crypto/src/cert_chain.rs per OPC-10000-4 6.1.3 while preserving configured policy opt-ins.
- [X] T038 [US2] Enforce disallowed revocation signature algorithms in async-opcua-crypto/src/cert_chain.rs per OPC-10000-4 6.1.3.
- [X] T039 [US2] Enforce CA path-length constraints in async-opcua-crypto/src/cert_chain.rs per OPC-10000-4 6.1.3.
- [X] T040a [US2] Make missing PKI storage fail closed in async-opcua-crypto/src/certificate_store.rs per OPC-10000-4 6.1.3 and return auditable certificate context where available.
- [X] T040b [US2] Make corrupt PKI storage fail closed in async-opcua-crypto/src/certificate_store.rs per OPC-10000-4 6.1.3 and return auditable certificate context where available.
- [X] T041 [US2] Pass request security context into GetRejectedList handling in async-opcua-server/src/gds/pull_methods.rs and async-opcua-server/src/node_manager/method.rs so OPC-10000-12 7.8.3.2 authorization is checked before registry reads.
- [X] T042 [US2] Enforce encrypted SecureChannel plus SecurityAdmin for UpdateCertificate in async-opcua-server/src/gds/pull_methods.rs per OPC-10000-12 7.10.5.
- [X] T043 [US2] Enforce encrypted SecureChannel plus SecurityAdmin for CreateSigningRequest in async-opcua-server/src/gds/push_methods.rs per OPC-10000-12 7.10.10.
- [X] T044 [US2] Enforce encrypted SecureChannel plus SecurityAdmin for the implementation-specific FinishSigningRequest helper in async-opcua-server/src/gds/pull_methods.rs per OPC-10000-12 7.4 and 7.10.5, without representing the helper as a standard OPC UA method.
- [X] T045a [US2] Validate DER certificate input before registry mutation in async-opcua-server/src/gds/pull_methods.rs per OPC-10000-12 7.10.5, preserving existing trust material on every failure.
- [X] T045b [US2] Validate private-key input before registry mutation in async-opcua-server/src/gds/pull_methods.rs per OPC-10000-12 7.10.5, preserving existing trust material on every failure.
- [X] T046 [US2] Write GDS cached certificate and private key through temporary files and atomic rename in async-opcua-server/src/gds/cache.rs per OPC-10000-12 7.4 and 7.10.5 so partial write failures preserve the previous credential pair.
- [X] T047a [US2] Normalize OpenSecureChannel certificate audit source name in async-opcua-server/src/session/audit.rs and async-opcua-server/src/session/controller.rs per OPC-10000-5 6.4.15 and OPC-10000-4 6.1.3.
- [X] T047b [US2] Emit suppressed certificate-validation success audit context in async-opcua-server/src/session/audit.rs and async-opcua-server/src/session/controller.rs per OPC-10000-4 5.7.2.2 and 6.1.3 plus OPC-10000-5 6.4.15 for SC-003.
- [X] T048a [US2] Run `cargo test -p async-opcua-crypto cert_chain` and record the result in specs/043-fix-audit-findings/verification.md.
- [X] T048b [US2] Run `cargo test -p async-opcua-server --test gds_pull_methods` and record the result in specs/043-fix-audit-findings/verification.md.
- [X] T048c [US2] Run `cargo test -p async-opcua-server --test gds_integration` and record the result in specs/043-fix-audit-findings/verification.md.
- [X] T048d [US2] Run `cargo test -p async-opcua --test integration_tests adversarial` and record the result in specs/043-fix-audit-findings/verification.md.

**Checkpoint**: US2 is independently complete when certificate failures are status-specific and auditable, GDS methods reject unauthorized callers before state changes, and replacement failures preserve old trust material.

---

## Phase 5: User Story 3 - Harden Protocol Negative Paths And Status Conformance (Priority: P3)

**Goal**: Make malformed transport, service, PubSub, SKS, XML, history, and encoding inputs fail deterministically with bounded resource use, spec-aligned statuses, and preserved state.

**Independent Test**: Run the targeted command listed on each task and then run `cargo test -p async-opcua-core comms && cargo test -p async-opcua-pubsub && cargo test -p async-opcua-types json && cargo test -p async-opcua-history-sqlite && cargo test -p async-opcua-xml`.

### Tests for User Story 3

- [X] T049 [US3] Add a failing oversized frame test in async-opcua-core/src/comms/tcp_codec.rs proving OPC-10000-6 7.1.2.2 and 7.1.5 reject impossible or oversized declared message sizes before allocation.
- [X] T050 [US3] Add a failing pre-Hello ERR/ACK bound test in async-opcua-core/src/comms/tcp_codec.rs proving OPC-10000-6 7.1.2.2 frames are bounded before negotiation.
- [X] T051 [US3] Add a failing ECC Hello buffer-size test in async-opcua-core/src/comms/tcp_types.rs proving OPC-10000-6 7.1.2.3 allows the ECC 1024-byte minimum only when an ECC policy is intended.
- [X] T052 [US3] Add a failing asymmetric SecurityPolicyUri length test in async-opcua-core/src/comms/security_header.rs proving OPC-10000-6 6.7.2.3 rejects SecurityPolicyUri values longer than 255 bytes.
- [X] T053 [US3] Add a failing unknown-service-id test in async-opcua-core/src/messages/request.rs proving OPC-10000-4 5.3 and 7.34 return an explicit unsupported-service fault without tearing down a reusable channel when allowed.
- [X] T054 [US3] Add a failing maxResponseMessageSize test in async-opcua-server/tests/security_tests.rs proving OPC-10000-4 5.7.2.2 and 5.3 return Bad_ResponseTooLarge when the serialized response body exceeds the client limit.
- [X] T055 [P] [US3] Add a failing returnDiagnostics test in async-opcua-server/tests/service_diagnostics.rs proving OPC-10000-4 7.32 and 7.34 populate ResponseHeader diagnostics and stringTable only when requested.
- [X] T056 [P] [US3] Add a failing MonitoringMode raw-decode test in async-opcua-types/src/generated/types/enums.rs proving OPC-10000-4 5.13.4.3 Table 70 preserves invalid MonitoringMode values long enough to return Bad_MonitoringModeInvalid.
- [X] T057 [US3] Add a failing SetMonitoringMode service test in async-opcua/tests/integration/subscriptions.rs proving OPC-10000-4 5.13.4.3 rejects invalid monitoring mode with Bad_MonitoringModeInvalid.
- [X] T058a [US3] Add a failing JSON Int64 test in async-opcua-types/src/tests/json.rs proving OPC-10000-6 5.4.2.3 encodes and decodes Int64 as a decimal JSON string.
- [X] T058b [US3] Add a failing JSON UInt64 test in async-opcua-types/src/tests/json.rs proving OPC-10000-6 5.4.2.3 encodes and decodes UInt64 as a decimal JSON string.
- [X] T059a [US3] Add a failing JSON NodeId test in async-opcua-types/src/tests/json.rs proving OPC-10000-6 5.4.2.10 uses the 1.05 JSON string form.
- [X] T059b [US3] Add a failing JSON ExpandedNodeId test in async-opcua-types/src/tests/json.rs proving OPC-10000-6 5.4.2.11 uses the 1.05 JSON string form.
- [X] T060 [US3] Add a failing JSON Variant test in async-opcua-types/src/tests/json.rs proving OPC-10000-6 5.4.2.17 uses UaType and Value instead of legacy Type and Body fields.
- [X] T061a [US3] Add a failing JSON ExtensionObject UaBody/null test in async-opcua-types/src/tests/json.rs proving OPC-10000-6 5.4.2.16 handles UaBody and null bodies correctly.
- [X] T061b [US3] Add a failing JSON ExtensionObject duplicate-field test in async-opcua-types/src/tests/json.rs proving OPC-10000-6 5.4.2.16 rejects duplicate JSON field names.
- [X] T062a [US3] Add a failing PubSub UADP invalid-flag test in async-opcua-pubsub/tests/pubsub_tests.rs proving OPC-10000-14 7.2.4.4.2 rejects invalid headers before subscriber state updates.
- [X] T062b [US3] Add a failing PubSub UADP field-count overflow test in async-opcua-pubsub/tests/pubsub_tests.rs proving OPC-10000-14 7.2.4.4.2 rejects overflowing field counts before subscriber state updates.
- [X] T063a [US3] Add a failing PubSub secured trailing-payload test in async-opcua-pubsub/tests/message_security_tests.rs proving OPC-10000-14 7.2.4.4.2 rejects secured payloads with trailing bytes before replay advances.
- [X] T063b [US3] Add a failing PubSub secured oversized-payload test in async-opcua-pubsub/tests/message_security_tests.rs proving OPC-10000-14 7.2.4.4.3.2 rejects oversized secured payloads before subscriber state advances.
- [X] T064 [US3] Add a failing SKS non-current-start-token test in async-opcua-server/tests/security_tests.rs proving OPC-10000-14 8.3.2 returns an available historical key range for a specific older StartingTokenId without inventing an unverified unknown-token fallback.
- [X] T065a [US3] Add a failing XML malformed import test in async-opcua-xml/src/parser.rs proving OPC-10000-6 7.4.3 exposes parse failures.
- [X] T065b [US3] Add a failing XML oversized import test in async-opcua-xml/src/parser.rs proving OPC-10000-6 7.4.3 bounds local XML imports.
- [X] T066 [P] [US3] Add a failing corrupt SQLite history row test in async-opcua-history-sqlite/tests/history_events.rs proving OPC-10000-4 5.11.3 and OPC-10000-11 6.2.2 corrupted encoded event/history values return explicit HistoryRead errors without deleting valid rows.
- [X] T067a [US3] Add a failing AddNodes duplicate browse-name test in async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs proving OPC-10000-4 5.8.2.4 returns Bad_BrowseNameDuplicated as an operation-level result.
- [X] T067b [US3] Add a failing AddNodes invalid type-definition test in async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs proving OPC-10000-4 5.8.2.4 returns Bad_TypeDefinitionInvalid as an operation-level result.
- [X] T067c [US3] Add a failing AddNodes invalid attributes test in async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs proving OPC-10000-4 5.8.2.4 returns Bad_NodeAttributesInvalid as an operation-level result.
- [X] T068a [US3] Add a failing AddReferences abstract-reference test in async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs proving OPC-10000-4 5.8.3.4 rejects abstract references with an operation-level status.
- [X] T068b [US3] Add a failing AddReferences duplicate-reference test in async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs proving OPC-10000-4 5.8.3.4 rejects duplicate references with an operation-level status.
- [X] T068c [US3] Add a failing AddReferences structural-reference test in async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs proving OPC-10000-4 5.8.3.4 rejects structurally disallowed references with an operation-level status.
- [X] T069 [US3] Add a failing cross-manager DeleteNodes reference cleanup test in async-opcua-server/src/session/services/node_management.rs proving OPC-10000-4 5.8.4 deletes target references across node managers when requested.
- [X] T070a [US3] Add a failing ValueRank positive-dimension test in async-opcua-nodes/src/variable.rs and async-opcua-nodes/src/variable_type.rs proving OPC-10000-3 5.6 requires dimension count to match positive ValueRank.
- [X] T070b [US3] Add a failing ArrayDimensions scalar-rank test in async-opcua-nodes/src/variable.rs and async-opcua-nodes/src/variable_type.rs proving OPC-10000-3 5.6 requires ArrayDimensions to be absent for scalar ranks.
- [X] T071a [US3] Add a failing GetEndpoints endpoint-url test in async-opcua/tests/integration/discovery.rs proving OPC-10000-4 5.5.4.2 returns endpoint URLs consistent with the client's connect URL.
- [X] T071b [US3] Add a failing FindServers endpoint-url test in async-opcua/tests/integration/discovery.rs proving OPC-10000-4 5.5.2.2 returns endpoint URLs consistent with the client's connect URL.
- [X] T072a [US3] Add a failing LocalizedText read locale test in async-opcua/tests/integration/read.rs proving OPC-10000-4 5.4 applies session localeIds to reads.
- [X] T072b [US3] Add a failing LocalizedText unsupported special-locale write test in async-opcua/tests/integration/read.rs proving OPC-10000-4 5.4 rejects unsupported special locale writes where required.
- [X] T073 [P] [US3] Add a failing DataAccess PercentDeadband modify test in async-opcua/tests/integration/datachange_overflow.rs proving OPC-10000-8 7.2 fetches EURange when ModifyMonitoredItems adds a Percent deadband.
- [X] T074 [P] [US3] Add a failing NamespaceMetadata NodeClass test in async-opcua/tests/integration/conformance.rs proving OPC-10000-5 6.3.13 exposes metadata property nodes as Variables, not Objects.

### Implementation for User Story 3

- [X] T075 [US3] Enforce declared frame-size bounds in async-opcua-core/src/comms/tcp_codec.rs per OPC-10000-6 7.1.2.2 and 7.1.5 before allocating or splitting buffers.
- [X] T076 [US3] Bound pre-Hello ERR and ACK frames in async-opcua-core/src/comms/tcp_codec.rs per OPC-10000-6 7.1.2.2.
- [X] T077 [US3] Revise Hello/Acknowledge buffer-size validation in async-opcua-core/src/comms/tcp_types.rs per OPC-10000-6 7.1.2.3 so ECC-intended connections can use the 1024-byte minimum without weakening non-ECC connections.
- [X] T078 [US3] Enforce the 255-byte asymmetric SecurityPolicyUri limit in async-opcua-core/src/comms/security_header.rs per OPC-10000-6 6.7.2.3.
- [X] T079 [US3] Convert unknown request type ids into explicit unsupported-service faults in async-opcua-core/src/messages/request.rs and async-opcua-server/src/session/controller.rs per OPC-10000-4 5.3 and 7.34.
- [X] T080 [US3] Enforce client maxResponseMessageSize in async-opcua-server/src/session/manager.rs and async-opcua-core/src/comms/buffer.rs per OPC-10000-4 5.7.2.2 and 5.3.
- [X] T081 [US3] Implement returnDiagnostics propagation in async-opcua-server/src/session/controller.rs and async-opcua-core/src/messages/response.rs per OPC-10000-4 7.32 and 7.34.
- [X] T082 [US3] Preserve invalid MonitoringMode during decode in async-opcua-types/src/generated/types/enums.rs so service code can return Bad_MonitoringModeInvalid per OPC-10000-4 5.13.4.3.
- [X] T083 [US3] Reject invalid monitoring mode in async-opcua-server/src/session/services/monitored_items.rs with Bad_MonitoringModeInvalid per OPC-10000-4 5.13.4.3.
- [X] T084a [US3] Encode and decode JSON Int64 as decimal strings in async-opcua-types/src/json.rs and async-opcua-types/src/basic_types.rs per OPC-10000-6 5.4.2.3.
- [X] T084b [US3] Encode and decode JSON UInt64 as decimal strings in async-opcua-types/src/json.rs and async-opcua-types/src/basic_types.rs per OPC-10000-6 5.4.2.3.
- [X] T085a [US3] Switch JSON NodeId to the 1.05 string form in async-opcua-types/src/node_id/json.rs per OPC-10000-6 5.4.2.10.
- [X] T085b [US3] Switch JSON ExpandedNodeId to the 1.05 string form in async-opcua-types/src/expanded_node_id.rs per OPC-10000-6 5.4.2.11.
- [X] T086 [US3] Switch JSON Variant encoding to UaType and Value in async-opcua-types/src/variant/json.rs per OPC-10000-6 5.4.2.17 while preserving deliberate compatibility only behind an explicit compatibility path.
- [X] T087a [US3] Fix JSON ExtensionObject UaBody/null handling in async-opcua-types/src/extension_object.rs per OPC-10000-6 5.4.2.16.
- [X] T087b [US3] Reject duplicate JSON ExtensionObject field names in async-opcua-types/src/custom/json.rs per OPC-10000-6 5.4.2.16.
- [X] T088a [US3] Reject invalid UADP flags before subscriber mutation in async-opcua-pubsub/src/codec/uadp.rs and async-opcua-pubsub/src/subscriber.rs per OPC-10000-14 7.2.4.4.2.
- [X] T088b [US3] Reject overflowing UADP field counts before subscriber mutation in async-opcua-pubsub/src/codec/uadp.rs and async-opcua-pubsub/src/subscriber.rs per OPC-10000-14 7.2.4.4.2.
- [X] T089a [US3] Reject secured UADP trailing payload bytes in async-opcua-pubsub/src/security/codec.rs per OPC-10000-14 7.2.4.4.2.
- [X] T089b [US3] Reject oversized secured UADP payloads in async-opcua-pubsub/src/security/codec.rs per OPC-10000-14 7.2.4.4.3.2.
- [X] T090 [US3] Return an available SKS historical key range for non-current starting token ids in async-opcua-server/src/services/security.rs per OPC-10000-14 8.3.2 without inventing an unverified unknown-token fallback.
- [X] T091a [US3] Return explicit XML malformed-parse errors in async-opcua-xml/src/parser.rs per OPC-10000-6 7.4.3.
- [X] T091b [US3] Bound oversized XML imports in async-opcua-xml/src/parser.rs per OPC-10000-6 7.4.3.
- [X] T092 [US3] Surface corrupt SQLite history decode errors without deleting valid rows in async-opcua-history-sqlite/src/backend.rs and async-opcua-history-sqlite/src/query.rs per OPC-10000-4 5.11.3 and OPC-10000-11 6.2.2.
- [X] T093a [US3] Enforce AddNodes duplicate browse-name validation in async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs per OPC-10000-4 5.8.2.4.
- [X] T093b [US3] Enforce AddNodes type-definition validation in async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs per OPC-10000-4 5.8.2.4.
- [X] T093c [US3] Enforce AddNodes attribute validation in async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs per OPC-10000-4 5.8.2.4.
- [X] T094a [US3] Enforce AddReferences abstract-reference validation in async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs per OPC-10000-4 5.8.3.4.
- [X] T094b [US3] Enforce AddReferences duplicate-reference validation in async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs per OPC-10000-4 5.8.3.4.
- [X] T094c [US3] Enforce AddReferences structural-reference validation in async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs per OPC-10000-4 5.8.3.4.
- [X] T095 [US3] Implement cross-manager DeleteNodes reference cleanup in async-opcua-server/src/session/services/node_management.rs and async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs per OPC-10000-4 5.8.4.
- [X] T096a [US3] Enforce ValueRank positive-dimension consistency in async-opcua-nodes/src/variable.rs and async-opcua-nodes/src/variable_type.rs per OPC-10000-3 5.6.
- [X] T096b [US3] Enforce ArrayDimensions absence for scalar ranks in async-opcua-nodes/src/variable.rs and async-opcua-nodes/src/variable_type.rs per OPC-10000-3 5.6.
- [X] T097a [US3] Return client-connect-url-consistent endpoint URLs for GetEndpoints in async-opcua-server/src/info.rs and async-opcua-server/src/session/controller.rs per OPC-10000-4 5.5.4.2.
- [X] T097b [US3] Return client-connect-url-consistent endpoint URLs for FindServers in async-opcua-server/src/info.rs and async-opcua-server/src/session/controller.rs per OPC-10000-4 5.5.2.2.
- [X] T098a [US3] Apply session localeIds to LocalizedText reads in async-opcua-server/src/address_space/utils.rs and async-opcua-server/src/session/manager.rs per OPC-10000-4 5.4.
- [X] T098b [US3] Reject unsupported special-locale writes in async-opcua-server/src/address_space/utils.rs and async-opcua-server/src/session/manager.rs per OPC-10000-4 5.4.
- [X] T099 [US3] Fetch EURange on ModifyMonitoredItems PercentDeadband changes in async-opcua-server/src/session/services/monitored_items.rs per OPC-10000-8 7.2.
- [X] T100 [US3] Correct NamespaceMetadata property NodeClass handling in async-opcua-server/src/namespace/mod.rs per OPC-10000-5 6.3.13.
- [X] T101a [US3] Run `cargo test -p async-opcua-core comms` and record the result in specs/043-fix-audit-findings/verification.md.
- [X] T101b [US3] Run `cargo test -p async-opcua-types json` and record the result in specs/043-fix-audit-findings/verification.md.
- [X] T101c [US3] Run `cargo test -p async-opcua-pubsub` and record the result in specs/043-fix-audit-findings/verification.md.
- [X] T101d [US3] Run `cargo test -p async-opcua-server security_tests` and record the result in specs/043-fix-audit-findings/verification.md.
- [X] T101e [US3] Run `cargo test -p async-opcua-xml` and record the result in specs/043-fix-audit-findings/verification.md.
- [X] T101f [US3] Run `cargo test -p async-opcua-history-sqlite` and record the result in specs/043-fix-audit-findings/verification.md.

**Checkpoint**: US3 is independently complete when malformed protocol inputs fail with spec-aligned statuses, bounded resources, and no unintended channel, session, subscriber, XML, or history state mutation.

---

## Final Phase: Polish And Cross-Cutting Concerns

**Purpose**: Close traceability, full verification, and cleanup after the desired story scope is implemented.

- [X] T102 Update specs/043-fix-audit-findings/finding-matrix.md so every completed task has a final status, passing command, and residual-risk note.
- [X] T103 [P] Update specs/043-fix-audit-findings/quickstart.md if any test names or targeted commands changed during implementation.
- [X] T104 Run `cargo fmt --check` and record the result in specs/043-fix-audit-findings/verification.md.
- [X] T105 Run `cargo test --workspace --all-targets --all-features --locked` and record the result in specs/043-fix-audit-findings/verification.md.
- [X] T106 Run `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` and record the result in specs/043-fix-audit-findings/verification.md.
- [X] T106a Run `cargo test -p async-opcua-server certificate_audit` and record the result in specs/043-fix-audit-findings/verification.md.
- [X] T106b Run `cargo test -p async-opcua --test integration_tests session_audit` and record the result in specs/043-fix-audit-findings/verification.md.
- [X] T106c Run `cargo build --locked --profile embedded -p async-opcua-minimal-server` and record the result in specs/043-fix-audit-findings/verification.md.
- [X] T106d Run `cargo build --locked --profile embedded -p async-opcua-foundation-profile-nano-server` and record the result in specs/043-fix-audit-findings/verification.md.
- [X] T106e Run `cargo build --locked --profile embedded -p async-opcua-foundation-profile-micro-server` and record the result in specs/043-fix-audit-findings/verification.md.
- [X] T106f Run `cargo build --locked --profile embedded -p async-opcua-foundation-profile-embedded-server` and record the result in specs/043-fix-audit-findings/verification.md.
- [X] T106g Run `./samples/demo-server/interop/run-interop.sh` and record the result in specs/043-fix-audit-findings/verification.md.
- [X] T106h Run `./samples/demo-server/interop/open62541/run-open62541.sh` and record the result in specs/043-fix-audit-findings/verification.md.
- [X] T106i Run `./samples/demo-server/interop/asyncua/run-asyncua.sh` and record the result in specs/043-fix-audit-findings/verification.md.
- [X] T106j Run `./samples/demo-server/interop/dotnet/run-dotnet.sh` and record the result in specs/043-fix-audit-findings/verification.md.
- [X] T107a Review touched authentication paths for secret logging regressions in specs/043-fix-audit-findings/verification.md.
- [X] T107b Review touched certificate and transport paths for panic-on-untrusted-input regressions in specs/043-fix-audit-findings/verification.md.
- [X] T107c Review touched PubSub, XML, and history paths for secret logging and panic-on-untrusted-input regressions in specs/043-fix-audit-findings/verification.md.
- [X] T108 Update specs/043-fix-audit-findings/tasks.md by checking off only tasks whose failing-first test and final verification evidence are recorded.

---

## Dependencies And Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies.
- **Foundational (Phase 2)**: Depends on Phase 1 and blocks all user story work.
- **User Story 1 (Phase 3)**: Depends on Phase 2. This is the MVP and should complete before US2 and US3.
- **User Story 2 (Phase 4)**: Depends on Phase 2 and should start after US1 unless a US1 task is explicitly reclassified as not applicable.
- **User Story 3 (Phase 5)**: Depends on Phase 2 and should start after US1 and US2 for the default one-task-at-a-time workflow.
- **Final Phase**: Depends on whichever user stories are selected for implementation.

### User Story Dependencies

- **US1**: No dependency on US2 or US3. It protects identity/session trust boundaries and is the MVP.
- **US2**: Can be implemented independently after Phase 2, but should follow US1 because certificate and audit work is downstream of activation boundaries.
- **US3**: Can be implemented independently after Phase 2, but should follow US1/US2 because it is lower priority than authentication, certificate, and GDS trust material.

### Within Each User Story

- Write the test task first and confirm it fails for the targeted behavior.
- Implement only the task's named behavior boundary.
- Run the targeted verification command before moving to the next task.
- Update [verification.md](./verification.md) as soon as a task passes.

---

## Parallel Opportunities

- Setup tasks T001 and T002 touch different files and can be split if staffed.
- US3 returnDiagnostics test T055 and MonitoringMode decode test T056 touch different files.
- US3 SQLite history test T066, DataAccess test T073, and NamespaceMetadata test T074 touch different files.
- Final quickstart update T103 can be done independently from verification log updates after implementation changes settle.

## Parallel Example: User Story 3

```text
Task: "T055 Add returnDiagnostics test in async-opcua-server/tests/service_diagnostics.rs"
Task: "T066 Add corrupt SQLite history row test in async-opcua-history-sqlite/tests/history_events.rs"
Task: "T074 Add NamespaceMetadata NodeClass test in async-opcua/tests/integration/conformance.rs"
```

---

## Implementation Strategy

### MVP First: US1 Only

1. Complete Phase 1 and Phase 2.
2. Complete T007a through T021c in order.
3. Stop and validate US1 with the commands in T021a through T021c.
4. Update [finding-matrix.md](./finding-matrix.md) and [verification.md](./verification.md).

### Incremental Delivery

1. Finish US1 to close the highest-risk identity/session trust-boundary findings.
2. Finish US2 to close certificate, audit, and GDS trust-material findings.
3. Finish US3 in smaller batches by surface: transport, service diagnostics/status, JSON encoding, PubSub/SKS, XML/history, and address-space conformance.

### Completion Gate

Before claiming this feature complete:

1. Every selected finding in [finding-matrix.md](./finding-matrix.md) has a completed task id.
2. Every completed remediation has failing-first evidence in [verification.md](./verification.md).
3. T104, T105, T106, and T106a through T106j are complete.
4. No task is checked off in this file without recorded verification evidence.
