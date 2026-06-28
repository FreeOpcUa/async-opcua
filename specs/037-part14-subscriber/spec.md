# Feature Specification: Part 14 Subscriber Runtime

**Feature Branch**: `037-part14-subscriber`  
**Created**: 2026-06-28  
**Status**: Draft  
**Input**: User description: "Implement OPC UA Part 14 PubSub subscriber/DataSetReader support for UADP over UDP and secured UADP: configure ReaderGroups and DataSetReaders, receive brokerless NetworkMessages, validate WriterGroup/DataSetWriter identifiers and sequence continuity, verify and decrypt secured NetworkMessages, decode DataSetMessages into field values, update configured target Variables safely, expose observable status/diagnostics for dropped invalid messages, and document limits. TSN hardware scheduling, brokered MQTT/AMQP subscriber operation, and full PubSub information-model method surface are out of scope unless needed for fail-closed behavior."

## Standards Grounding

- OPC 10000-14 Section 3.1.4 defines a DataSetReader as the entity that extracts a DataSetMessage from a received NetworkMessage and decodes it.
- OPC 10000-14 Section 5.4.2.2 requires received DataSetMessages of interest to be passed to a DataSetReader, with DataSetMetaData used to decode the DataSet content.
- OPC 10000-14 Section 5.4.6.2.2 describes the broker-less OPC UA UDP subscriber model and notes that UDP does not guarantee timeliness, delivery, ordering, or duplicate protection.
- OPC 10000-14 Sections 6.1, 6.2.8, and 6.2.9 define ReaderGroup and DataSetReader configuration as the subscriber-side grouping and filtering model.
- OPC 10000-14 Sections 6.2.10.2.1 and 6.2.10.2.3 define target-variable mappings between received DataSet fields and target Variables.
- OPC 10000-14 Sections 6.2.1, 6.2.9.4, and 6.2.9.6 define DataSetReader state behavior for first data, metadata version gaps, and message receive timeout.
- OPC 10000-14 Sections 7.2.3, 7.2.4.1, 7.2.4.4.2, and 7.2.4.4.3.2 define sequence number behavior, UADP NetworkMessage layout, SecurityHeader presence, and AES-CTR nonce handling.
- OPC 10000-14 Sections 9.1.8.2 and 9.1.10.1 define the DataSetReader Status object and PubSubStatusType expectations.

## User Scenarios & Testing *(mandatory)*

Tests are required for this feature. Network decoding, security verification, and target-variable writes must be covered by red tests before implementation tasks for the relevant story.

### User Story 1 - Receive plain UADP DataSetMessages (Priority: P1)

As a server embedding the PubSub crate, I can configure a ReaderGroup with DataSetReaders, receive broker-less UADP NetworkMessages over UDP, and have matching DataSetMessage fields written to configured target Variables.

**Why this priority**: A subscriber runtime without plain UADP receive and apply behavior does not satisfy the basic Part 14 DataSetReader role described in OPC 10000-14 Sections 3.1.4, 5.4.2.2, and 5.4.6.2.2.

**Independent Test**: Configure one ReaderGroup, one DataSetReader, and three target Variables; send a matching UADP datagram on loopback; verify only the matching Variables are updated and reader diagnostics show one accepted message.

**Acceptance Scenarios**:

1. **Given** a DataSetReader with PublisherId, WriterGroupId, DataSetWriterId, and target Variables configured, **When** a matching UADP key-frame DataSetMessage arrives over UDP, **Then** the decoded fields are applied to the matching target Variables in configured field order.
2. **Given** a configured DataSetReader, **When** a UADP NetworkMessage arrives with a different PublisherId, WriterGroupId, NetworkMessageNumber, or DataSetWriterId, **Then** the message is ignored without changing target Variables.
3. **Given** a configured DataSetReader, **When** a malformed, oversized, or unsupported UADP datagram arrives, **Then** the runtime rejects it without panicking and records a drop diagnostic.
4. **Given** a configured DataSetReader using zero or null wildcard filters allowed by OPC 10000-14 Sections 6.2.7.1 and 6.2.9.3, **When** an otherwise matching DataSetMessage arrives, **Then** the wildcarded filter does not block the update.

---

### User Story 2 - Receive secured UADP DataSetMessages (Priority: P2)

As a subscriber operator, I can enable Part 14 UADP NetworkMessage security for a ReaderGroup or DataSetReader so signed and encrypted datagrams are verified, decrypted, replay-checked, and applied only when valid.

**Why this priority**: The crate already has PubSub security primitives, but Part 14 subscriber behavior must fail closed before target Variables are mutated.

**Independent Test**: Build a signed-and-encrypted UADP datagram with a known security group token, deliver it through the subscriber path, and verify the target Variables update; repeat with tampered, replayed, and unknown-token datagrams and verify no updates occur.

**Acceptance Scenarios**:

1. **Given** a ReaderGroup configured for SignAndEncrypt, **When** a datagram with a valid SecurityHeader, token id, nonce, signature, and encrypted payload arrives, **Then** the subscriber verifies, decrypts, decodes, and applies it.
2. **Given** a ReaderGroup configured for security, **When** the datagram signature, nonce, token id, or replay window check fails, **Then** no target Variable changes and the diagnostic reason is observable.
3. **Given** both ReaderGroup and DataSetReader security settings, **When** the DataSetReader security mode is not INVALID, **Then** the DataSetReader setting overrides the ReaderGroup setting as required by OPC 10000-14 Section 6.2.9.9.

---

### User Story 3 - Observe reader state and loss diagnostics (Priority: P3)

As an operator or integration test, I can inspect each DataSetReader status to see whether it is disabled, pre-operational, operational, or error, plus counters for accepted, filtered, dropped, timeout, sequence gap, duplicate, replay, and security failures.

**Why this priority**: UDP provides no ordering or duplicate guarantees, and OPC 10000-14 Sections 6.2.1, 6.2.9.6, 7.2.3, 9.1.8.2, and 9.1.10.1 make state and status visible subscriber behavior, not internal debug-only behavior.

**Independent Test**: Drive the subscriber with one valid message, an intentional sequence gap, a duplicate message, and a receive timeout; verify state transitions and counters without relying on any external publisher.

**Acceptance Scenarios**:

1. **Given** an enabled DataSetReader in PreOperational state, **When** the first valid key-frame DataSetMessage is applied, **Then** its state becomes Operational.
2. **Given** an Operational DataSetReader with MessageReceiveTimeout configured, **When** no new DataSetMessage arrives before the timeout, **Then** its state becomes Error.
3. **Given** a DataSetReader in Error because of MessageReceiveTimeout, **When** the next valid new DataSetMessage arrives, **Then** the timeout error clears and the reader returns to Operational.
4. **Given** a DataSetReader with sequence tracking enabled, **When** a duplicate, out-of-order, or gapped sequence is observed, **Then** diagnostics record the condition while applying only messages accepted by the receiver policy.

---

### User Story 4 - Validate configuration and document limits (Priority: P4)

As a library maintainer, I can reject invalid or unsupported Part 14 subscriber configurations with explicit errors, and the docs accurately describe supported and unsupported subscriber modes.

**Why this priority**: Clear fail-closed boundaries prevent accidental non-conformant behavior for brokered transports, TSN scheduling, unsupported DataSetMessage encodings, and incomplete information-model methods.

**Independent Test**: Validate a set of unsupported configurations and malformed datagrams through the public API; verify deterministic errors and no background task spawn.

**Acceptance Scenarios**:

1. **Given** duplicate DataSetReader names in one ReaderGroup, **When** the subscriber configuration is validated, **Then** validation fails before any receive loop starts.
2. **Given** duplicate target Variables in one TargetVariables set, **When** the DataSetReader configuration is validated, **Then** validation fails before messages can mutate the AddressSpace.
3. **Given** a brokered MQTT, brokered AMQP, JSON mapping, TSN hardware scheduling, or unsupported DataSetMessage representation request, **When** the subscriber starts, **Then** the runtime returns an unsupported error and docs list the limit.

### Edge Cases

- Missing UADP header fields: if OPC 10000-14 Section 7.2.4.1 allows the subscriber to know missing values from DataSetReader configuration, the runtime may use configured values; otherwise it must reject the datagram.
- PublisherId and DataSetWriterId wildcards: zero integer, null, or empty configured values are treated as ignored filters where the referenced Part 14 sections allow that behavior.
- Sequence number wrap: wrap is accepted only at the configured unsigned width boundary; duplicates and gaps are recorded.
- DataSetMetaData major version gap: if the received metadata version cannot be reconciled within MessageReceiveTimeout, the DataSetReader moves to Error.
- Field count mismatch: no target Variables are mutated for that DataSetReader unless all required target-field mappings can be resolved.
- Bad field status or unsupported override value handling: fail closed until the supported behavior is explicitly implemented.
- Unsupported DataSetMessage forms: delta frame, event, RawData, JSON, broker transport, TSN hardware scheduling, and full PubSub method surface are out of scope for this feature unless a specific fail-closed check is required.
- Existing UDP publisher custom fragmentation: subscriber behavior is standards-oriented UADP datagrams; non-Part-14 custom fragment headers are rejected and documented.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST provide a production subscriber runtime for broker-less OPC UA UDP UADP NetworkMessages configured through PubSubConnection ReaderGroups and DataSetReaders. (OPC 10000-14 Sections 4.3, 5.4.6.2.2, 6.1, 6.2.8)
- **FR-002**: The system MUST filter received NetworkMessages and DataSetMessages by configured PublisherId, WriterGroupId, NetworkMessageNumber, and DataSetWriterId, including Part 14 wildcard behavior for null, empty, or zero PublisherId and zero DataSetWriterId. (OPC 10000-14 Sections 6.2.7.1, 6.2.9.3, 7.2.4.1, 7.2.4.4.2)
- **FR-003**: The system MUST validate DataSetReader names as unique within a ReaderGroup before starting subscriber receive loops. (OPC 10000-14 Section 6.2.9.13.1)
- **FR-004**: The system MUST decode supported UADP key-frame DataSetMessages using DataSetReader configuration and DataSetMetaData-compatible field ordering. (OPC 10000-14 Sections 5.4.2.2, 5.3.2, 7.2.4.5.5)
- **FR-005**: The system MUST map decoded DataSet fields to configured target Variables using a FieldTargetDataType-equivalent mapping, including field index, target NodeId, AttributeId, index range placeholder, and override handling status. (OPC 10000-14 Sections 6.2.10.2.1, 6.2.10.2.3, 9.1.8.5)
- **FR-006**: The system MUST apply each accepted DataSetReader update without partial writes when any required target mapping, field count, target node, type, or writeability validation fails.
- **FR-007**: The system MUST track sequence continuity for received UADP messages and expose duplicate, out-of-order, gap, and wrap behavior through diagnostics. (OPC 10000-14 Sections 5.3.3, 7.2.3)
- **FR-008**: The system MUST implement DataSetReader status transitions from Disabled or PreOperational to Operational after the first valid key frame, to Error on MessageReceiveTimeout, and back to Operational on the next valid new DataSetMessage. (OPC 10000-14 Sections 6.2.1, 6.2.9.6)
- **FR-009**: The system MUST set DataSetReader state to Error when DataSetMetaData major version changes and updated metadata is unavailable within MessageReceiveTimeout. (OPC 10000-14 Section 6.2.9.4)
- **FR-010**: The system MUST expose per-DataSetReader status snapshots and diagnostics compatible with the current information-model reflection approach. (OPC 10000-14 Sections 9.1.8.2, 9.1.10.1)
- **FR-011**: The system MUST support ReaderGroup-level and DataSetReader-level security configuration, with DataSetReader settings overriding ReaderGroup settings when not INVALID. (OPC 10000-14 Sections 6.2.5.2, 6.2.9.9)
- **FR-012**: The system MUST verify, decrypt, and replay-check secured UADP NetworkMessages before UADP payload decoding or target Variable mutation. (OPC 10000-14 Sections 7.2.4.4.2, 7.2.4.4.3.2, Annex A.2.1.5, Annex A.2.1.6)
- **FR-013**: The system MUST reject malformed, oversized, unsupported, tampered, unknown-token, or replayed datagrams without panics and without target Variable mutation.
- **FR-014**: The system MUST bound datagram size, field count, decode recursion, and allocation behavior using existing codec limits where possible.
- **FR-015**: The system MUST provide cancellation-safe UDP subscriber receive loops for unicast and multicast broker-less addresses configured on PubSubConnection or DataSetReader transport settings. (OPC 10000-14 Sections 5.4.6.2.2, 6.4.1.6.1)
- **FR-016**: The system MUST explicitly reject brokered MQTT/AMQP subscriber mode, JSON subscriber mapping, TSN hardware scheduling, non-Part-14 UDP fragment headers, delta frames, event DataSetMessages, RawData payloads, and full PubSub information-model method coverage for this feature.
- **FR-017**: The system MUST update `docs/pubsub.md` and quickstart material so repository documentation no longer says subscriber support is decode-only once the runtime is implemented.
- **FR-018**: The implementation MUST include unit and integration tests for each user story before the corresponding implementation tasks are marked complete.

### Key Entities *(include if feature involves data)*

- **ReaderGroupConfig**: Subscriber-side grouping for DataSetReaders, shared security settings, and runtime state aggregation.
- **DataSetReaderConfig**: Subscriber filter and decode configuration for one DataSetWriter stream, including PublisherId, WriterGroupId, NetworkMessageNumber, DataSetWriterId, DataSetMetaData, security override, MessageReceiveTimeout, and target-variable mappings.
- **FieldTargetConfig**: Local representation of the Part 14 FieldTargetDataType relation between a DataSet field and a target Variable.
- **SubscriberRuntime**: Runtime receive, decode, security, dispatch, apply, cancellation, and diagnostics coordinator.
- **DataSetReaderStatus**: Observable per-reader state, last sequence, last receive time, last error, and counters.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A loopback UADP UDP subscriber test updates at least three configured target Variables from one matching key-frame DataSetMessage.
- **SC-002**: Nonmatching PublisherId, WriterGroupId, NetworkMessageNumber, and DataSetWriterId datagrams leave target Variables unchanged and increment filtered diagnostics.
- **SC-003**: Tampered, replayed, unknown-token, malformed, oversized, and unsupported datagrams leave target Variables unchanged and increment drop/security diagnostics.
- **SC-004**: MessageReceiveTimeout transitions an Operational DataSetReader to Error, and the next valid new message returns it to Operational.
- **SC-005**: Targeted tests pass with `cargo test -p async-opcua-pubsub subscriber` and existing PubSub security tests remain green.
- **SC-006**: `docs/pubsub.md` accurately describes supported subscriber receive modes and explicit out-of-scope limits.
- **SC-007**: No subscriber decode or apply path panics under malformed datagram fuzz-style regression inputs included in the test suite.

## Assumptions

- The first implementation supports UADP key-frame DataSetMessages over broker-less UDP and uses the existing UADP codec and security codec as the base.
- DataSetMetaData retrieval from remote publishers is out of scope; configured metadata is required and metadata-version mismatch fails closed.
- Target-variable writes initially support the Value attribute for scalar values; index range writes and full override-value behavior are validated or explicitly rejected until implemented.
- The existing read-only PubSub information-model reflection is reused for status visibility; full Part 14 method-surface completeness remains separate backlog work.
- Existing publisher custom UDP fragmentation is treated as non-standard for subscriber receive behavior and is not reassembled by this feature.
