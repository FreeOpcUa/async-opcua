# Data Model: Part 14 Subscriber Runtime

## ReaderGroupConfig

Represents a subscriber-side grouping of DataSetReaders.

Fields to preserve or extend:

- `reader_group_id`: local identifier for the ReaderGroup.
- `dataset_readers`: list of `DataSetReaderConfig` entries.
- `security_mode`: optional shared security mode for received NetworkMessages.
- `security_policy_uri`: optional shared security policy URI.
- `security_group_id`: optional shared security group id.

Validation:

- DataSetReader names must be unique within the group. (OPC 10000-14 Section 6.2.9.13.1)
- Shared security settings must be complete when security mode requires signing or encryption. (OPC 10000-14 Section 6.2.5.2)

## DataSetReaderConfig

Represents the Part 14 subscriber filter, decode, security, timeout, and target-apply settings for one received stream.

Fields to preserve or extend:

- `name`: optional human-readable name, unique within a ReaderGroup.
- `dataset_reader_id`: local identifier.
- `publisher_id`: optional subscriber-side PublisherId filter. (OPC 10000-14 Section 6.2.7.1)
- `writer_group_id`: optional UADP WriterGroupId filter. (OPC 10000-14 Sections 7.2.4.1 and 7.2.4.4.2)
- `network_message_number`: optional UADP NetworkMessageNumber filter. (OPC 10000-14 Section 7.2.4.4.2)
- `dataset_writer_id`: DataSetWriterId filter; zero means ignore this filter. (OPC 10000-14 Section 6.2.9.3)
- `message_receive_timeout`: optional timeout from first Operational state. (OPC 10000-14 Section 6.2.9.6)
- `dataset_metadata`: configured metadata needed to decode field order and validate versions. (OPC 10000-14 Section 5.4.2.2)
- `security_mode`: optional DataSetReader security override. (OPC 10000-14 Section 6.2.9.9)
- `security_policy_uri`: optional DataSetReader security override.
- `security_group_id`: optional DataSetReader security override.
- `target_variables`: list of `FieldTargetConfig`.
- `subscribed_variables`: legacy shorthand mapped to `FieldTargetConfig` entries using Value attribute and field index order.

Validation:

- The runtime must reject missing target mappings for supported receive mode.
- The runtime must reject duplicate target NodeIds within one target list. (OPC 10000-14 Section 6.2.10.2.1)
- The runtime must reject unsupported RawData, delta, event, broker, JSON, or TSN hardware settings with explicit errors.
- The runtime must validate security override completeness before starting a receive loop.

## FieldTargetConfig

Local representation of the Part 14 FieldTargetDataType relation between a DataSet field and a target Variable.

Fields:

- `dataset_field_index`: zero-based field index for UADP field order.
- `dataset_field_id`: optional Guid when metadata supplies stable field ids.
- `target_node_id`: target Variable NodeId.
- `attribute_id`: target AttributeId; first implementation supports Value.
- `index_range`: optional NumericRange placeholder; unsupported ranges are rejected until implemented.
- `override_value_handling`: configured handling for non-Operational state or Bad field status; unsupported modes fail closed until implemented.

Validation:

- `target_node_id` must resolve to a Variable node before any update is applied.
- `attribute_id` must be Value for the first implementation.
- `dataset_field_index` must be within the decoded DataSetMessage field count.

## SubscriberRuntime

Coordinates UDP receive, security processing, UADP decode, DataSetReader dispatch, target apply, cancellation, and diagnostics.

Fields:

- `connections`: PubSubConnectionConfig entries with ReaderGroups.
- `address_space`: shared AddressSpace handle used only during bounded apply operations.
- `security_registry`: existing PubSub security group/key registry.
- `reader_status`: map keyed by connection, ReaderGroup, and DataSetReader ids.
- `decode_limits`: datagram size and field-count limits from existing codec configuration.
- `tasks`: cancellation-safe receive-loop handles.

Invariants:

- No payload decode or target mutation occurs until required security checks pass.
- Target mutation for one DataSetReader update is all-or-nothing.
- Runtime cancellation stops receive loops without leaking tasks.

## DataSetReaderStatus

Observable per-reader status snapshot.

Fields:

- `state`: Disabled, PreOperational, Operational, or Error.
- `last_sequence_number`: optional last accepted sequence number.
- `last_receive_time`: optional monotonic receive timestamp.
- `last_error`: optional structured error code.
- `accepted_count`: accepted DataSetMessages.
- `filtered_count`: messages filtered by reader criteria.
- `dropped_count`: malformed or unsupported datagrams.
- `sequence_gap_count`: missing sequence observations.
- `duplicate_count`: duplicate sequence observations.
- `out_of_order_count`: out-of-order sequence observations.
- `timeout_count`: MessageReceiveTimeout expirations.
- `security_failure_count`: failed signature, encryption, token, nonce, or replay checks.

State rules:

- Enabled reader starts PreOperational until first accepted key-frame DataSetMessage. (OPC 10000-14 Section 6.2.1)
- Operational reader moves to Error after MessageReceiveTimeout without a new DataSetMessage. (OPC 10000-14 Section 6.2.9.6)
- Error reader caused by timeout returns to Operational on the next valid new DataSetMessage.
- Metadata major-version mismatch moves the reader to Error if updated metadata is unavailable within MessageReceiveTimeout. (OPC 10000-14 Section 6.2.9.4)

## SubscriberApplyOutcome

Result returned by one datagram process operation.

Fields:

- `matched_readers`: count of readers whose filters matched the message.
- `applied_readers`: count of readers whose target Variables were updated.
- `filtered_readers`: count of readers that rejected the message by filters.
- `dropped_reason`: optional structured failure for datagram-level drop.
- `security_result`: accepted, unsigned, verified, decrypted, replay_rejected, token_unknown, signature_bad, or unsupported.

Usage:

- Tests can assert outcomes without inspecting logs.
- Engine receive loops can update diagnostics from one structured result.
