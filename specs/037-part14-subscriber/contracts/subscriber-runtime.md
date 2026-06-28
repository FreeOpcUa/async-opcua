# Contract: Part 14 Subscriber Runtime

This contract describes the public Rust-facing behavior expected from the implementation. Names may be adjusted to match crate conventions, but the behavior and status surfaces must remain.

## Configuration Contract

### FieldTargetConfig

```rust
pub struct FieldTargetConfig {
    pub dataset_field_index: usize,
    pub dataset_field_id: Option<Guid>,
    pub target_node_id: NodeId,
    pub attribute_id: AttributeId,
    pub index_range: Option<String>,
    pub override_value_handling: OverrideValueHandling,
}
```

Required behavior:

- Value AttributeId is supported.
- Unsupported AttributeIds, index ranges, or override modes produce validation errors before receive loops start.
- Existing `subscribed_variables` entries map to `FieldTargetConfig` entries by index for compatibility.

### DataSetReaderConfig extensions

```rust
pub struct DataSetReaderConfig {
    pub name: Option<String>,
    pub dataset_reader_id: u16,
    pub publisher_id: Option<PublisherId>,
    pub writer_group_id: Option<u16>,
    pub network_message_number: Option<u16>,
    pub dataset_writer_id: u16,
    pub message_receive_timeout: Option<Duration>,
    pub security_mode: Option<MessageSecurityMode>,
    pub security_policy_uri: Option<String>,
    pub security_group_id: Option<String>,
    pub target_variables: Vec<FieldTargetConfig>,
    pub subscribed_variables: Vec<NodeId>,
}
```

Required behavior:

- `dataset_writer_id == 0` ignores the DataSetWriterId filter. (OPC 10000-14 Section 6.2.9.3)
- Null, empty, or zero PublisherId ignores the PublisherId filter where represented by local types. (OPC 10000-14 Section 6.2.7.1)
- Non-INVALID DataSetReader security mode overrides ReaderGroup security mode. (OPC 10000-14 Section 6.2.9.9)

## Runtime Contract

### SubscriberRuntime

```rust
pub struct SubscriberRuntime;

impl SubscriberRuntime {
    pub fn validate(config: &PubSubConnectionConfig) -> Result<(), StatusCode>;

    pub fn process_datagram(
        &mut self,
        datagram: &[u8],
        context: &EncodingContext,
    ) -> Result<SubscriberApplyOutcome, StatusCode>;

    pub fn reader_status(&self, reader_id: u16) -> Option<DataSetReaderStatus>;
}
```

Required behavior:

- `validate` checks ReaderGroup/DataSetReader structure, security completeness, target uniqueness, and unsupported settings.
- `process_datagram` verifies security before UADP payload decode when security is configured.
- `process_datagram` applies accepted values atomically per DataSetReader.
- `process_datagram` never panics on malformed input.
- `reader_status` returns a snapshot suitable for tests and information-model reflection.

### Engine integration

```rust
impl PubSubEngine {
    pub async fn start_subscribers(&mut self) -> Result<(), StatusCode>;
    pub async fn stop_subscribers(&mut self) -> Result<(), StatusCode>;
    pub fn subscriber_status(&self, reader_id: u16) -> Option<DataSetReaderStatus>;
}
```

Required behavior:

- `start_subscribers` starts only configured broker-less UADP/UDP ReaderGroups.
- Unsupported subscriber transports or mappings return `BadNotSupported` before spawning a receive task.
- `stop_subscribers` cancels all receive loops and awaits task shutdown.
- Existing publisher lifecycle behavior remains unchanged.

## UDP Receive Contract

```rust
pub struct UdpSubscriber;

impl UdpSubscriber {
    pub async fn run(
        &self,
        endpoint: UdpSubscriberEndpoint,
        runtime: SubscriberRuntimeHandle,
        cancel: CancellationToken,
    ) -> Result<(), StatusCode>;
}
```

Required behavior:

- The receive loop binds unicast or multicast UDP endpoints from PubSub configuration.
- One UDP datagram maps to one UADP NetworkMessage.
- Non-Part-14 custom fragment headers are rejected.
- Cancellation exits the loop without leaking tasks.

## Status Contract

```rust
pub struct DataSetReaderStatus {
    pub state: PubSubState,
    pub last_sequence_number: Option<u64>,
    pub last_receive_time: Option<Instant>,
    pub last_error: Option<SubscriberError>,
    pub accepted_count: u64,
    pub filtered_count: u64,
    pub dropped_count: u64,
    pub sequence_gap_count: u64,
    pub duplicate_count: u64,
    pub out_of_order_count: u64,
    pub timeout_count: u64,
    pub security_failure_count: u64,
}
```

Required behavior:

- First accepted key-frame DataSetMessage changes PreOperational to Operational. (OPC 10000-14 Section 6.2.1)
- MessageReceiveTimeout changes Operational to Error. (OPC 10000-14 Section 6.2.9.6)
- Next valid new DataSetMessage after timeout returns Error to Operational.
- Security failures increment diagnostics without target mutation.
