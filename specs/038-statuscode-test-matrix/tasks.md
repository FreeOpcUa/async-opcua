# Tasks: StatusCode Conformance Test Matrix

**Input**: Design documents from `/specs/038-statuscode-test-matrix/`  
**Prerequisites**: [plan.md](./plan.md), [spec.md](./spec.md), [research.md](./research.md), [data-model.md](./data-model.md), [contracts/](./contracts/), [quickstart.md](./quickstart.md)  
**Tests**: Required. Every task below implements exactly one test function in exactly one test file. Minimal production code changes are allowed only to make that one test pass.  
**Format**: `[ID] [P?] [Story] Implement one test <name> in <path>. (Matrix: <row>; Spec: <OPC ref>; Req: <FR/SC>)`

## Phase 1: User Story 1 - Prove Core Service Status Codes (Priority: P1)

**Goal**: Lock exact Part 4 service and Part 6 transport/encoding StatusCodes for implemented deterministic paths.

**Independent Test**: Any single task in this phase is independently complete when its one named test asserts the exact StatusCode and passes with a focused cargo test.

- [X] T001 [P] [US1] Implement one test `invalid_opc_tcp_endpoint_url_returns_bad_tcp_endpoint_url_invalid` in `async-opcua-core/src/tests/url.rs`. (Matrix: P4-SVC-001; Spec: OPC-10000-4 7.38.2; Req: FR-003, FR-004)
- [X] T002 [P] [US1] Implement one test `bad_nonce_invalid_status_is_exact` in `async-opcua-core/src/tests/comms.rs`. (Matrix: P4-SVC-002; Spec: OPC-10000-4 7.38.2; Req: FR-003, FR-004)
- [X] T003 [US1] Implement one test `oversized_tcp_message_chunk_returns_bad_tcp_message_too_large` in `async-opcua-core/src/tests/chunk.rs`. (Matrix: P4-SVC-003; Spec: OPC-10000-6 7.1.2.3; Req: FR-003, FR-004)
- [X] T004 [US1] Implement one test `request_over_message_size_limit_returns_bad_request_too_large` in `async-opcua-core/src/tests/chunk.rs`. (Matrix: P4-SVC-004; Spec: OPC-10000-4 7.38.2; Req: FR-003, FR-004)
- [X] T005 [US1] Implement one test `add_nodes_duplicate_browse_name_returns_bad_browse_name_duplicated` in `async-opcua/tests/integration/node_management.rs`. (Matrix: P4-SVC-008; Spec: OPC-10000-4 5.8.2.4; Req: FR-003, FR-004)
- [X] T006 [US1] Implement one test `add_nodes_mismatched_node_class_returns_bad_node_class_invalid` in `async-opcua/tests/integration/node_management.rs`. (Matrix: P4-SVC-009; Spec: OPC-10000-4 5.8.2.4; Req: FR-003, FR-004)
- [X] T007 [US1] Implement one test `add_nodes_foreign_namespace_returns_bad_node_id_rejected` in `async-opcua/tests/integration/node_management.rs`. (Matrix: P4-SVC-010; Spec: OPC-10000-4 5.8.2.4; Req: FR-003, FR-004)
- [X] T008 [US1] Implement one test `add_references_external_local_only_reference_returns_bad_reference_local_only` in `async-opcua/tests/integration/node_management.rs`. (Matrix: P4-SVC-011; Spec: OPC-10000-4 5.8.4; Req: FR-003, FR-004)
- [X] T009 [P] [US1] Implement one test `service_before_activate_session_returns_bad_session_not_activated` in `async-opcua/tests/integration/hardening.rs`. (Matrix: P4-SVC-014; Spec: OPC-10000-4 7.38.2; Req: FR-003, FR-004)
- [X] T010 [US1] Implement one test `request_after_close_session_returns_bad_session_closed` in `async-opcua/tests/integration/hardening.rs`. (Matrix: P4-SVC-015; Spec: OPC-10000-4 7.38.2; Req: FR-003, FR-004)
- [X] T011 [US1] Implement one test `request_with_invalid_authentication_token_returns_bad_session_id_invalid` in `async-opcua/tests/integration/hardening.rs`. (Matrix: P4-SVC-016; Spec: OPC-10000-4 7.38.2; Req: FR-003, FR-004)

**Checkpoint**: Core service/transport tasks are independently implementable and each adds one test.

## Phase 2: User Story 2 - Prove Implemented Information-Model and Companion Surfaces (Priority: P2)

**Goal**: Lock one-test gaps for implemented data-model, subscription, filter, DataAccess, alarm, history, aggregate, PubSub, security, RBAC, and FX behavior.

**Independent Test**: Any single task in this phase is independently complete when it adds one named test and the focused crate/integration test passes.

- [X] T012 [P] [US2] Implement one test `json_int64_encodes_as_decimal_string` in `async-opcua-types/src/tests/json.rs`. (Matrix: P6-ENC-001; Spec: OPC-10000-6 5.4.2.3; Req: FR-003, FR-005)
- [X] T013 [US2] Implement one test `json_uint64_encodes_as_decimal_string` in `async-opcua-types/src/tests/json.rs`. (Matrix: P6-ENC-002; Spec: OPC-10000-6 5.4.2.3; Req: FR-003, FR-005)
- [X] T014 [US2] Implement one test `json_variant_uses_uatype_and_body_fields` in `async-opcua-types/src/tests/json.rs`. (Matrix: P6-ENC-003; Spec: OPC-10000-6 5.4.2.17; Req: FR-003, FR-005)
- [X] T015 [US2] Implement one test `add_nodes_array_dimensions_value_rank_mismatch_returns_bad_node_attributes_invalid` in `async-opcua/tests/integration/node_management.rs`. (Matrix: P3-MOD-002; Spec: OPC-10000-3 5.6; Req: FR-003, FR-004)
- [X] T016 [US2] Implement one test `add_nodes_abstract_type_definition_returns_bad_type_definition_invalid` in `async-opcua/tests/integration/node_management.rs`. (Matrix: P3-MOD-003; Spec: OPC-10000-3 5.6/6; Req: FR-003, FR-004)
- [X] T017 [US2] Implement one test `add_references_abstract_reference_type_returns_bad_reference_type_id_invalid` in `async-opcua/tests/integration/node_management.rs`. (Matrix: P3-MOD-004; Spec: OPC-10000-3 5.3.1; Req: FR-003, FR-004)
- [X] T018 [US2] Implement one test `symmetric_reference_type_with_inverse_name_returns_bad_node_attributes_invalid` in `async-opcua/tests/integration/node_management.rs`. (Matrix: P3-MOD-005; Spec: OPC-10000-3 5.3.2; Req: FR-003, FR-004)
- [X] T019 [P] [US2] Implement one test `namespace_metadata_properties_read_node_class_variable` in `async-opcua/tests/integration/core_tests.rs`. (Matrix: P5-INF-003; Spec: OPC-10000-5 6.3.14; Req: FR-003, FR-005)
- [X] T020 [US2] Implement one test `create_monitored_items_over_limit_returns_bad_too_many_monitored_items` in `async-opcua/tests/integration/subscriptions.rs`. (Matrix: P4-SUB-001; Spec: OPC-10000-4 5.13.2.3; Req: FR-003, FR-004)
- [X] T021 [US2] Implement one test `modify_missing_subscription_returns_bad_no_subscription` in `async-opcua/tests/integration/subscriptions.rs`. (Matrix: P4-SUB-002; Spec: OPC-10000-4 5.14; Req: FR-003, FR-004)
- [X] T022 [US2] Implement one test `publish_ack_unknown_sequence_returns_bad_sequence_number_unknown` in `async-opcua/tests/integration/subscriptions.rs`. (Matrix: P4-SUB-003; Spec: OPC-10000-4 5.14.5.4; Req: FR-003, FR-004)
- [X] T023 [US2] Implement one test `excess_publish_requests_return_bad_too_many_publish_requests` in `async-opcua/tests/integration/subscriptions.rs`. (Matrix: P4-SUB-004; Spec: OPC-10000-4 5.14.5.1/5.14.5.3; Req: FR-003, FR-004)
- [X] T024 [P] [US2] Implement one test `unsupported_event_filter_operator_returns_bad_filter_operator_unsupported` in `async-opcua-server/tests/event_filter_tests.rs`. (Matrix: P4-FLT-001; Spec: OPC-10000-4 7.7; Req: FR-003, FR-004)
- [X] T025 [US2] Implement one test `event_filter_wrong_operand_count_returns_bad_filter_operand_count_mismatch` in `async-opcua-server/tests/event_filter_tests.rs`. (Matrix: P4-FLT-002; Spec: OPC-10000-4 7.7; Req: FR-003, FR-004)
- [X] T026 [US2] Implement one test `event_filter_invalid_operand_returns_bad_filter_operand_invalid` in `async-opcua-server/tests/event_filter_tests.rs`. (Matrix: P4-FLT-003; Spec: OPC-10000-4 7.7; Req: FR-003, FR-004)
- [X] T027 [US2] Implement one test `modify_monitored_items_percent_deadband_without_eurange_returns_bad_deadband_filter_invalid` in `async-opcua/tests/integration/subscriptions.rs`. (Matrix: P8-DA-001; Spec: OPC-10000-8 7.2; Req: FR-003, FR-004)
- [X] T028 [US2] Implement one test `modify_monitored_items_percent_deadband_with_eurange_succeeds` in `async-opcua/tests/integration/subscriptions.rs`. (Matrix: P8-DA-002; Spec: OPC-10000-8 7.2; Req: FR-003, FR-005)
- [X] T029 [P] [US2] Implement one test `acknowledge_disabled_condition_returns_bad_condition_disabled` in `async-opcua/tests/integration/alarms.rs`. (Matrix: P9-AC-001; Spec: OPC-10000-9 5.7.2; Req: FR-003, FR-004)
- [X] T030 [US2] Implement one test `timed_shelve_out_of_range_returns_bad_shelving_time_out_of_range` in `async-opcua/tests/integration/alarms.rs`. (Matrix: P9-AC-002; Spec: OPC-10000-9 5.8.17.4; Req: FR-003, FR-004)
- [X] T031 [P] [US2] Implement one test `history_read_neither_timestamps_returns_bad_timestamps_to_return_invalid` in `async-opcua/tests/integration/hda.rs`. (Matrix: P11-HA-003; Spec: OPC-10000-4 5.11.3.2; Req: FR-003, FR-004)
- [X] T032 [P] [US2] Implement one test `aggregate_invalid_inputs_returns_bad_aggregate_invalid_inputs` in `async-opcua-server/tests/aggregates_tests.rs`. (Matrix: P13-AGG-001; Spec: OPC-10000-13 5.3.2; Req: FR-003, FR-004)
- [X] T033 [P] [US2] Implement one test `udp_subscriber_bind_conflict_returns_bad_communication_error` in `async-opcua-pubsub/tests/subscriber_plain_uadp_tests.rs`. (Matrix: P14-PUB-003; Spec: OPC-10000-14 5.4.6.2.2; Req: FR-003, FR-004)
- [X] T034 [P] [US2] Implement one test `unknown_issuer_revocation_status_returns_bad_certificate_issuer_revocation_unknown` in `async-opcua-crypto/src/tests/cert_chain.rs`. (Matrix: P2-SEC-001; Spec: OPC-10000-4 6.1.3; Req: FR-003, FR-004)
- [X] T035 [P] [US2] Implement one test `open_secure_channel_untrusted_client_cert_returns_bad_security_checks_failed` in `async-opcua-server/tests/security_tests.rs`. (Matrix: P2-SEC-002; Spec: OPC-10000-4 6.1.3; Req: FR-003, FR-004)
- [X] T036 [P] [US2] Implement one test `fx_verify_requires_lock_returns_bad_requires_lock` in `async-opcua-fx/tests/verify_tests.rs`. (Matrix: P80-FX-001; Spec: OPC-10000-81/83 FX/AC nodeset `EstablishConnections` i=292, `VerifyAssetCmd`, `VerifyFunctionalEntityCmd`; Req: FR-003, FR-004)
- [X] T037 [P] [US2] Implement one test `fx_establish_conflicting_owner_returns_bad_locked` in `async-opcua-fx/tests/establish_tests.rs`. (Matrix: P80-FX-002; Spec: OPC-10000-81/83 FX/AC nodeset `EstablishConnections` i=292; Req: FR-003, FR-004)

**Checkpoint**: Each implemented information-model/companion-surface task is independently actionable.

## Phase 3: User Story 3 - Maintain a Spec-Grounded Coverage Matrix (Priority: P3)

**Goal**: Keep future implementation tied to the matrix.

**Independent Test**: Re-run the three analysis passes after any task-list update and ensure there are no high or critical issues.

No implementation tasks are generated for US3 because the matrix is the contract artifact itself. This avoids violating the one-test-per-task rule.

## Dependencies and Execution Order

- T001 through T004 can start immediately and validate core transport/status-code helpers.
- T005 through T011 use integration fixtures and should run after the workspace baseline is healthy.
- T012 through T014 should be sequenced together because they target JSON encoding compatibility in the same test file.
- T015 through T018 target NodeManagement and may conflict in the same file; run sequentially unless separate branches are used.
- T020 through T028 target subscription/event-filter paths and should be sequenced by file.
- All [P] tasks in different files can run in parallel after their crate fixtures are understood.

## Parallel Opportunities

- T001, T002, T012, T019, T024, T029, T031, T032, T033, T034, T035, T036, and T037 touch different files and can be parallelized.
- T005 through T008 and T015 through T018 share `async-opcua/tests/integration/node_management.rs` and should be serialized.
- T020 through T023 and T027 through T028 share `async-opcua/tests/integration/subscriptions.rs` and should be serialized.

## Implementation Strategy

### MVP First

1. Complete T001 through T004 to prove exact core transport/status-code mappings.
2. Run focused `cargo test -p async-opcua-core`.
3. Stop and review the matrix/task pattern before expanding to integration-heavy tasks.

### Incremental Delivery

1. Implement one task.
2. Run the focused test for that task.
3. Run `cargo fmt --all`.
4. Commit after a small coherent set of passing one-test tasks.
5. Re-run `speckit-analyze` after material task changes.

## Notes

- Do not add grouped or parameterized tests that introduce multiple test functions for one task.
- Do not use live upstream repositories or the upstream GitHub remote for this work.
- Do not convert environmental rows into tests unless an injected deterministic fixture is added first.
