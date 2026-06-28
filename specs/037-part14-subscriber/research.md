# Research: Part 14 Subscriber Runtime

## OPC UA Reference Evidence

- OPC 10000-14 Section 3.1.4: A DataSetReader extracts a DataSetMessage from a received NetworkMessage and decodes it.
- OPC 10000-14 Section 5.4.2.2: DataSetMessages of interest are passed to a DataSetReader, where DataSetMetaData is used to decode DataSet content.
- OPC 10000-14 Section 5.4.6.2.2: Broker-less OPC UA UDP maps UADP DataSetMessage fields to internal Variables through DataSetReader configuration; UDP has no timeliness, delivery, ordering, or duplicate guarantee.
- OPC 10000-14 Section 6.1: DataSetReader parameters are subscriber-side filters for received NetworkMessages/DataSetMessages plus processing settings for decoded DataSets.
- OPC 10000-14 Section 6.2.7.1: PublisherId filtering belongs to DataSetReader parameters on the subscriber side.
- OPC 10000-14 Section 6.2.8: ReaderGroup groups DataSetReaders and does not add extra UADP/datagram mapping parameters.
- OPC 10000-14 Section 6.2.9.3: DataSetWriterId is a DataSetReader filter; zero is ignored as a filter.
- OPC 10000-14 Section 6.2.9.4: DataSetMetaData major-version changes require metadata update or DataSetReader Error state after MessageReceiveTimeout.
- OPC 10000-14 Section 6.2.9.6: MessageReceiveTimeout starts when DataSetReader becomes Operational.
- OPC 10000-14 Section 6.2.9.9: DataSetReader SecurityMode overrides ReaderGroup SecurityMode when not INVALID.
- OPC 10000-14 Section 6.2.10.2.3: FieldTargetDataType relates DataSetMessage fields to target Variables.
- OPC 10000-14 Sections 7.2.3, 7.2.4.1, and 7.2.4.4.2: sequence numbers, missing header information from DataSetReader configuration, WriterGroupId, NetworkMessageNumber, and SecurityHeader layout.
- OPC 10000-14 Section 7.2.4.4.3.2: AES-CTR uses the first eight SecurityHeader nonce bytes as MessageNonce.
- OPC 10000-14 Sections 9.1.8.2 and 9.1.10.1: DataSetReader exposes status through the Part 14 information-model status pattern.

## Existing Code Findings

- `async-opcua-pubsub/src/config.rs` already has `ReaderGroupConfig` and `DataSetReaderConfig`, but DataSetReader targets are currently only `subscribed_variables: Vec<NodeId>`.
- `async-opcua-pubsub/src/subscriber.rs` has a direct `apply_network_message` helper and `decode_and_apply`, but no production receive loop, status state, security integration, timeout handling, or structured diagnostics.
- `async-opcua-pubsub/src/codec/uadp.rs` already models `PublisherId`, `UadpNetworkMessage`, and `UadpDataSetMessage`, with existing decode limits for field counts.
- `async-opcua-pubsub/src/security/codec.rs` already implements secured UADP encode/decode with SecurityHeader, AES-CTR, HMAC, nonce, and key token behavior.
- `async-opcua-pubsub/src/engine.rs` has publisher lifecycle code and a secured subscriber decode helper, but does not start subscriber receive loops.
- `async-opcua-pubsub/src/pubsub_model.rs` reflects ReaderGroup and DataSetReader objects, but runtime status needs to be fed into that visibility.
- `docs/pubsub.md` still describes subscriber support as decode-only and must be updated after runtime support lands.

## Decisions

### D1: Scope the first runtime to broker-less UADP over UDP

**Decision**: Implement Part 14 subscriber receive behavior for UADP NetworkMessages over UDP only.

**Rationale**: This directly satisfies OPC 10000-14 Sections 5.4.6.2.2 and 6.1 for the current crate capabilities. JSON, MQTT, AMQP, and TSN hardware scheduling require different mapping and transport semantics.

**Alternatives rejected**:

- Implement brokered subscriber transport now: rejected because it would mix Part 14 broker semantics into the UADP/UDP gap.
- Implement JSON mapping now: rejected because existing codec coverage is UADP.

### D2: Treat ReaderGroup as grouping plus shared security, not as a WriterGroupId alias

**Decision**: Add explicit DataSetReader filter fields for WriterGroupId and NetworkMessageNumber instead of interpreting `ReaderGroupConfig.reader_group_id` as a UADP WriterGroupId.

**Rationale**: OPC 10000-14 Sections 6.2.8 and 6.3.1.2 say ReaderGroup adds no UADP-specific mapping parameters. UADP filtering by WriterGroupId and NetworkMessageNumber is a message-layout concern in Sections 7.2.4.1 and 7.2.4.4.2.

**Alternatives rejected**:

- Reuse `reader_group_id` for WriterGroupId: rejected because it conflates a local grouping identifier with a wire-level UADP group header.

### D3: Introduce FieldTargetConfig while keeping legacy subscribed_variables compatibility

**Decision**: Add a FieldTargetDataType-equivalent local `FieldTargetConfig` and map existing `subscribed_variables` entries to Value-attribute targets by field index.

**Rationale**: OPC 10000-14 Section 6.2.10.2.3 defines target-variable metadata beyond NodeId. Keeping legacy config compatibility avoids breaking current tests while giving the subscriber runtime room for AttributeId, index range, and override handling.

**Alternatives rejected**:

- Continue with only `Vec<NodeId>`: rejected because it cannot represent the Part 14 target relation clearly.

### D4: Apply accepted DataSetReader updates atomically per reader

**Decision**: Resolve all target Variables and validate field counts before mutating any target for one DataSetReader update.

**Rationale**: Part 14 does not require partial writes, and the project constitution favors fail-closed decode paths. Atomic apply prevents half-updated industrial state when configuration is wrong.

**Alternatives rejected**:

- Best-effort per-field updates: rejected because failure diagnostics become ambiguous and stale values can mix with new fields.

### D5: Reuse existing secured UADP codec before subscriber dispatch

**Decision**: The subscriber path will use the existing security codec for SecurityHeader verification, AES-CTR decrypt, HMAC verification, and key-token selection before UADP message filtering.

**Rationale**: OPC 10000-14 Sections 7.2.4.4.2 and 7.2.4.4.3.2 define security at the NetworkMessage level. Decoding or applying payload fields before verification would violate fail-closed behavior.

**Alternatives rejected**:

- Add a subscriber-specific security codec: rejected because it would duplicate already tested logic.

### D6: Expose status snapshots from the runtime and reflect them where possible

**Decision**: Add per-reader status snapshots for state, counters, last sequence, last receive time, and last error; wire them into existing PubSub model reflection where feasible.

**Rationale**: OPC 10000-14 Sections 9.1.8.2 and 9.1.10.1 make status a visible part of the DataSetReader model. Tests need an API that does not require external clients.

**Alternatives rejected**:

- Log-only diagnostics: rejected because logs are not a standards-facing status surface.

### D7: Reject non-Part-14 custom UDP fragment headers in subscriber receive

**Decision**: The subscriber runtime expects each UDP datagram to contain a UADP NetworkMessage and rejects the existing publisher-specific fragment header.

**Rationale**: OPC 10000-14 Section 5.4.6.2.2 covers broker-less UDP but does not define the crate's custom fragmentation header. Standards-oriented subscriber behavior must not silently accept proprietary headers as UADP.

**Alternatives rejected**:

- Reassemble custom fragments in the subscriber: rejected because it would define non-standard subscriber behavior before the Part 14 baseline is complete.

### D8: Start with key-frame Variant/DataValue payloads and fail closed for unsupported message forms

**Decision**: Support key-frame UADP DataSetMessages with Variant and DataValue-compatible fields; reject delta frames, event DataSetMessages, RawData, and JSON mapping until separate features define them.

**Rationale**: OPC 10000-14 allows multiple DataSetMessage forms. The current codec and target apply path are closest to key-frame field values, which gives a conformant baseline without overpromising coverage.

**Alternatives rejected**:

- Decode all DataSetMessage forms in one pass: rejected because it would make task boundaries too large and risk non-atomic behavior.
