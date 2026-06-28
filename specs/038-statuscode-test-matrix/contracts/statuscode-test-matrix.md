# StatusCode Test Matrix

This matrix is the task-generation contract for feature 038. Rows marked `tasked` must have exactly one task and exactly one planned test function. Rows marked `covered` are included to prevent duplicate work.

## Core Services and Transport

| Row | Standard Reference | Status/Result | Behavior to Lock | Implementation Area | Test Target | Classification | Task |
|-----|--------------------|---------------|------------------|---------------------|-------------|----------------|------|
| P4-SVC-001 | OPC-10000-4 7.38.2 | BadTcpEndpointUrlInvalid | Invalid OPC TCP endpoint URL is rejected with the endpoint URL code, not a generic error | `async-opcua-core/src/comms/url.rs` | `async-opcua-core/src/tests/url.rs` | tasked | T001 |
| P4-SVC-002 | OPC-10000-4 7.38.2 | BadNonceInvalid | Secured-channel nonce length validation returns the exact nonce code | `async-opcua-core/src/comms/secure_channel.rs` | `async-opcua-core/src/tests/comms.rs` | tasked | T002 |
| P4-SVC-003 | OPC-10000-6 7.1.2.3 | BadTcpMessageTooLarge | Oversized TCP message chunk is rejected with the TCP message-too-large code | `async-opcua-core/src/comms/message_chunk.rs` | `async-opcua-core/src/tests/chunk.rs` | tasked | T003 |
| P4-SVC-004 | OPC-10000-4 7.38.2 | BadRequestTooLarge | Encoding a request over negotiated size limits returns request-too-large | `async-opcua-core/src/comms/chunker.rs` | `async-opcua-core/src/tests/chunk.rs` | tasked | T004 |
| P4-SVC-005 | OPC-10000-4 5.12.2.4 | BadArgumentsMissing | Method Call with required inputs omitted returns BadArgumentsMissing | `async-opcua-server/src/node_manager/memory/mod.rs` | `async-opcua/tests/integration/methods.rs` | covered | existing |
| P4-SVC-006 | OPC-10000-4 5.12.2.4 | BadTooManyArguments | Method Call with extra inputs returns BadTooManyArguments | `async-opcua-server/src/node_manager/memory/mod.rs` | `async-opcua/tests/integration/methods.rs` | covered | existing |
| P4-SVC-007 | OPC-10000-4 5.12.2.4 | BadNotExecutable | Non-executable Method returns BadNotExecutable | `async-opcua-server/src/node_manager/memory/mod.rs` | `async-opcua/tests/integration/methods.rs` | covered | existing |
| P4-SVC-008 | OPC-10000-4 5.8.2.4 | BadBrowseNameDuplicated | AddNodes with duplicate browse name under same parent returns BadBrowseNameDuplicated | `async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs` | `async-opcua/tests/integration/node_management.rs` | tasked | T005 |
| P4-SVC-009 | OPC-10000-4 5.8.2.4 | BadNodeClassInvalid | AddNodes with mismatched node class/attributes returns BadNodeClassInvalid | `async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs` | `async-opcua/tests/integration/node_management.rs` | tasked | T006 |
| P4-SVC-010 | OPC-10000-4 5.8.2.4 | BadNodeIdRejected | AddNodes rejects a requested NodeId outside the manager-owned namespace | `async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs` | `async-opcua/tests/integration/node_management.rs` | tasked | T007 |
| P4-SVC-011 | OPC-10000-4 5.8.4 | BadReferenceLocalOnly | AddReferences rejects a local-only reference across server boundaries | `async-opcua-server/src/node_manager/node_management.rs` | `async-opcua/tests/integration/node_management.rs` | tasked | T008 |
| P4-SVC-012 | OPC-10000-4 5.5.5.3 | BadServerNameMissing | RegisterServer rejects online registration without ServerName | `async-opcua-server/src/discovery` | `async-opcua/tests/integration/discovery.rs` | covered | existing |
| P4-SVC-013 | OPC-10000-4 5.5.5.3 | BadDiscoveryUrlMissing | RegisterServer rejects online registration without DiscoveryUrl | `async-opcua-server/src/discovery` | `async-opcua/tests/integration/discovery.rs` | covered | existing |
| P4-SVC-014 | OPC-10000-4 7.38.2 | BadSessionNotActivated | Non-activation service request before ActivateSession returns BadSessionNotActivated | `async-opcua-server/src/session` | `async-opcua/tests/integration/hardening.rs` | tasked | T009 |
| P4-SVC-015 | OPC-10000-4 7.38.2 | BadSessionClosed | Request after CloseSession returns BadSessionClosed or equivalent service fault | `async-opcua-server/src/session` | `async-opcua/tests/integration/hardening.rs` | tasked | T010 |
| P4-SVC-016 | OPC-10000-4 7.38.2 | BadSessionIdInvalid | Request with invalid authentication token returns BadSessionIdInvalid | `async-opcua-server/src/session` | `async-opcua/tests/integration/hardening.rs` | tasked | T011 |

## Encoding, JSON, and Data Model

| Row | Standard Reference | Status/Result | Behavior to Lock | Implementation Area | Test Target | Classification | Task |
|-----|--------------------|---------------|------------------|---------------------|-------------|----------------|------|
| P6-ENC-001 | OPC-10000-6 5.4.2.3 | JSON string | Int64 JSON encoding uses decimal strings | `async-opcua-types/src/json.rs` | `async-opcua-types/src/tests/json.rs` | tasked | T012 |
| P6-ENC-002 | OPC-10000-6 5.4.2.3 | JSON string | UInt64 JSON encoding uses decimal strings | `async-opcua-types/src/json.rs` | `async-opcua-types/src/tests/json.rs` | tasked | T013 |
| P6-ENC-003 | OPC-10000-6 5.4.2.17 | UaType/Body | JSON Variant object uses the Part 6 1.05 field names | `async-opcua-types/src/variant.rs` | `async-opcua-types/src/tests/json.rs` | tasked | T014 |
| P6-ENC-004 | OPC-10000-6 5.2.2.1 | Good boolean decode | Binary Boolean decode treats any non-zero byte as true | `async-opcua-types/src/basic_types.rs` | `async-opcua-types/src/tests/encoding.rs` | covered | existing |
| P6-ENC-005 | OPC-10000-6 5.2.2.17 | ByteString | Reserved Variant type IDs 26-31 decode as ByteString | `async-opcua-types/src/variant.rs` | `async-opcua-types/src/tests/variant.rs` | covered | existing |
| P6-ENC-006 | OPC-10000-6 5.2.2.17 | Good clamp | DataValue picoseconds >= 10000 decode as 9999 | `async-opcua-types/src/data_value.rs` | `async-opcua-types/src/tests/encoding.rs` | covered | existing |
| P3-MOD-001 | OPC-10000-3 5.6 | Normalized ValueRank | Invalid ValueRank setter values normalize per Part 3 | `async-opcua-nodes/src/variable.rs` | `async-opcua/tests/integration/node_management.rs` | covered | existing |
| P3-MOD-002 | OPC-10000-3 5.6 | BadNodeAttributesInvalid | AddNodes rejects ArrayDimensions inconsistent with ValueRank | `async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs` | `async-opcua/tests/integration/node_management.rs` | tasked | T015 |
| P3-MOD-003 | OPC-10000-3 5.6/6 | BadTypeDefinitionInvalid | AddNodes rejects abstract ObjectType/VariableType instantiation | `async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs` | `async-opcua/tests/integration/node_management.rs` | tasked | T016 |
| P3-MOD-004 | OPC-10000-3 5.3.1 | BadReferenceTypeIdInvalid | AddReferences rejects abstract ReferenceTypes | `async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs` | `async-opcua/tests/integration/node_management.rs` | tasked | T017 |
| P3-MOD-005 | OPC-10000-3 5.3.2 | BadNodeAttributesInvalid | Symmetric ReferenceType cannot include InverseName | `async-opcua-nodes/src/reference_type.rs` | `async-opcua/tests/integration/node_management.rs` | tasked | T018 |
| P3-MOD-006 | OPC-10000-3 5.2.1 | BadSecurityModeInsufficient | AccessRestrictions requiring encryption are enforced | `async-opcua-server/src/rbac` | `async-opcua/tests/integration/rbac.rs` | covered | existing |
| P5-INF-001 | OPC-10000-5 6.3.2 | LocaleIdArray populated | ServerCapabilities LocaleIdArray reflects configured locales | `async-opcua-server/src/info.rs` | `async-opcua/tests/integration/core_tests.rs` | covered | existing |
| P5-INF-002 | OPC-10000-5 6.3.2 | Duration Double | MinSupportedSampleRate value matches Duration datatype | `async-opcua-server/src/info.rs` | `async-opcua/tests/integration/core_tests.rs` | covered | existing |
| P5-INF-003 | OPC-10000-5 6.3.14 | Variable NodeClass | NamespaceMetadata property NodeClass reads as Variable | `async-opcua-server/src/namespace` | `async-opcua/tests/integration/core_tests.rs` | tasked | T019 |

## Subscriptions, Filters, DataAccess, Alarms

| Row | Standard Reference | Status/Result | Behavior to Lock | Implementation Area | Test Target | Classification | Task |
|-----|--------------------|---------------|------------------|---------------------|-------------|----------------|------|
| P4-SUB-001 | OPC-10000-4 5.13.2.3 | BadTooManyMonitoredItems | CreateMonitoredItems over operation limit returns BadTooManyMonitoredItems | `async-opcua-server/src/session/services/monitored_items.rs` | `async-opcua/tests/integration/subscriptions.rs` | tasked | T020 |
| P4-SUB-002 | OPC-10000-4 5.14 | BadNoSubscription | Publish/modify path for missing subscription returns BadNoSubscription | `async-opcua-server/src/subscriptions` | `async-opcua/tests/integration/subscriptions.rs` | tasked | T021 |
| P4-SUB-003 | OPC-10000-4 5.14.5.4 | BadSequenceNumberUnknown | Publish acknowledgement for an unknown sequence returns BadSequenceNumberUnknown | `async-opcua-server/src/subscriptions/session_subscriptions.rs` | `async-opcua/tests/integration/subscriptions.rs` | tasked | T022 |
| P4-SUB-004 | OPC-10000-4 5.14.5.1/5.14.5.3 | BadTooManyPublishRequests | Excess queued publish requests return BadTooManyPublishRequests | `async-opcua-server/src/subscriptions/session_subscriptions.rs` | `async-opcua/tests/integration/subscriptions.rs` | tasked | T023 |
| P4-FLT-001 | OPC-10000-4 7.7 | BadFilterOperatorUnsupported | Unsupported event filter operator is rejected | `async-opcua-nodes/src/events/validation.rs` | `async-opcua-server/tests/event_filter_tests.rs` | tasked | T024 |
| P4-FLT-002 | OPC-10000-4 7.7 | BadFilterOperandCountMismatch | ContentFilter with wrong operand count is rejected | `async-opcua-nodes/src/events/validation.rs` | `async-opcua-server/tests/event_filter_tests.rs` | tasked | T025 |
| P4-FLT-003 | OPC-10000-4 7.7 | BadFilterOperandInvalid | ContentFilter with invalid operand is rejected | `async-opcua-nodes/src/events/validation.rs` | `async-opcua-server/tests/event_filter_tests.rs` | tasked | T026 |
| P8-DA-001 | OPC-10000-8 7.2 | BadDeadbandFilterInvalid | ModifyMonitoredItems adding PercentDeadband without EURange returns BadDeadbandFilterInvalid | `async-opcua-server/src/subscriptions/monitored_item.rs` | `async-opcua/tests/integration/subscriptions.rs` | tasked | T027 |
| P8-DA-002 | OPC-10000-8 7.2 | Good | ModifyMonitoredItems adding PercentDeadband with EURange succeeds | `async-opcua-server/src/subscriptions/monitored_item.rs` | `async-opcua/tests/integration/subscriptions.rs` | tasked | T028 |
| P9-AC-001 | OPC-10000-9 5.7.2 | BadConditionDisabled | Acknowledge on disabled condition returns BadConditionDisabled | `async-opcua-server/src/alarms/methods.rs` | `async-opcua/tests/integration/alarms.rs` | tasked | T029 |
| P9-AC-002 | OPC-10000-9 5.8.17.4 | BadShelvingTimeOutOfRange | TimedShelve rejects out-of-range shelving time | `async-opcua-server/src/alarms/state_machine.rs` | `async-opcua/tests/integration/alarms.rs` | tasked | T030 |

## History, Aggregates, PubSub, Security, FX

| Row | Standard Reference | Status/Result | Behavior to Lock | Implementation Area | Test Target | Classification | Task |
|-----|--------------------|---------------|------------------|---------------------|-------------|----------------|------|
| P11-HA-001 | OPC-10000-11 6.2.2 | BadNoEntryExists | Replace history data at absent timestamp returns BadNoEntryExists | `async-opcua-history-sqlite/src/backend.rs` | `async-opcua-history-sqlite/tests/history_update_data.rs` | covered | existing |
| P11-HA-002 | OPC-10000-11 6.2.2 | BadEntryExists | Insert duplicate history data returns BadEntryExists | `async-opcua-history-sqlite/src/backend.rs` | `async-opcua-history-sqlite/tests/history_update_data.rs` | covered | existing |
| P11-HA-003 | OPC-10000-4 5.11.3.2 | BadTimestampsToReturnInvalid | HistoryRead rejects TimestampsToReturn::Neither where Part 11 does not allow it | `async-opcua-server/src/session/services/attribute.rs` | `async-opcua/tests/integration/hda.rs` | tasked | T031 |
| P13-AGG-001 | OPC-10000-13 5.3.2 | BadAggregateInvalidInputs | Aggregate interval with invalid inputs reports BadAggregateInvalidInputs | `async-opcua-server/src/aggregates` | `async-opcua-server/tests/aggregates_tests.rs` | tasked | T032 |
| P13-AGG-002 | OPC-10000-13 5.3.2 | BadAggregateNotSupported | Unsupported aggregate function returns BadAggregateNotSupported | `async-opcua-server/src/aggregates` | `async-opcua-server/tests/aggregates_tests.rs` | covered | existing |
| P14-PUB-001 | OPC-10000-14 7.2.4.4.2 | BadSecurityChecksFailed | Secured UADP unknown SecurityTokenId is rejected before target mutation | `async-opcua-pubsub/src/subscriber.rs` | `async-opcua-pubsub/tests/subscriber_security_tests.rs` | covered | existing |
| P14-PUB-002 | OPC-10000-14 7.2.4.4.3.2 | BadSecurityChecksFailed | Secured UADP replay is rejected before target mutation | `async-opcua-pubsub/src/subscriber.rs` | `async-opcua-pubsub/tests/subscriber_security_tests.rs` | covered | existing |
| P14-PUB-003 | OPC-10000-14 5.4.6.2.2 | BadCommunicationError | UDP subscriber bind failure maps to BadCommunicationError | `async-opcua-pubsub/src/transport/udp.rs` | `async-opcua-pubsub/tests/subscriber_plain_uadp_tests.rs` | tasked | T033 |
| P2-SEC-001 | OPC-10000-4 6.1.3 | BadCertificateIssuerRevocationUnknown | Unknown issuer revocation status maps to BadCertificateIssuerRevocationUnknown | `async-opcua-crypto/src/cert_chain.rs` | `async-opcua-crypto/src/tests/cert_chain.rs` | tasked | T034 |
| P2-SEC-002 | OPC-10000-4 6.1.3 | BadSecurityChecksFailed | OpenSecureChannel rejects untrusted client certificate before session creation | `async-opcua-server/src/session/controller.rs` | `async-opcua-server/tests/security_tests.rs` | tasked | T035 |
| P18-RBAC-001 | OPC-10000-3 5.2.1 | BadUserAccessDenied | RolePermissions deny a configured write operation | `async-opcua-server/src/rbac` | `async-opcua/tests/integration/rbac.rs` | covered | existing |
| P80-FX-001 | OPC-10000-81/83 FX/AC nodeset `EstablishConnections` i=292, `VerifyAssetCmd`, `VerifyFunctionalEntityCmd` | BadRequiresLock | FX Verify* command requiring lock returns BadRequiresLock when unlocked | `async-opcua-fx/src/establish.rs` | `async-opcua-fx/tests/verify_tests.rs` | tasked | T036 |
| P80-FX-002 | OPC-10000-81/83 FX/AC nodeset `EstablishConnections` i=292 | BadLocked | FX EstablishConnections reports BadLocked for conflicting owner | `async-opcua-fx/src/establish.rs` | `async-opcua-fx/tests/establish_tests.rs` | tasked | T037 |

## Environmental or Deferred Rows

| Row | Standard Reference | Status/Result | Reason |
|-----|--------------------|---------------|--------|
| ENV-001 | OPC-10000-4 7.38.2 | BadCommunicationError | Real transport partition and socket exhaustion are environmental; only deterministic local bind failure is tasked. |
| ENV-002 | OPC-10000-14 third-party interop | PubSub CTR interop | Requires external .NET/open62541 PubSub-CTR tooling not available in normal CI. |
| ENV-003 | OPC-10000-4 6.1.3 | Live OCSP errors | Core accepts supplied/stapled OCSP; live fetching/responder infrastructure is not implemented. |
