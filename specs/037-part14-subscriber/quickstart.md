# Quickstart: Part 14 Subscriber Runtime

## Goal

Validate that the PubSub crate can receive broker-less UADP over UDP, dispatch the DataSetMessage to a matching DataSetReader, and update target Variables safely.

## Expected workflow after implementation

1. Configure a `PubSubConnectionConfig` with one ReaderGroup and one DataSetReader.
2. Give the DataSetReader a PublisherId filter, WriterGroupId filter, DataSetWriterId filter, MessageReceiveTimeout, and target Variables.
3. Start the subscriber runtime through `PubSubEngine::start_subscribers`.
4. Send a matching UADP key-frame NetworkMessage to the configured UDP endpoint.
5. Read the target Variables from the AddressSpace.
6. Query `subscriber_status` for accepted count and Operational state.

## Focused validation commands

```bash
cargo test -p async-opcua-pubsub subscriber_plain_uadp
cargo test -p async-opcua-pubsub subscriber_security
cargo test -p async-opcua-pubsub subscriber_status
cargo test -p async-opcua-pubsub message_security
```

## Full crate validation

```bash
cargo test -p async-opcua-pubsub
```

## Supported in this feature

- Broker-less OPC UA UDP subscriber receive path.
- UADP NetworkMessages.
- Key-frame DataSetMessages with supported value encodings.
- DataSetReader filtering by PublisherId, WriterGroupId, NetworkMessageNumber, and DataSetWriterId.
- Field-to-target Variable mapping through FieldTargetDataType-equivalent configuration.
- ReaderGroup or DataSetReader secured UADP with fail-closed verification.
- DataSetReader status and diagnostics.

## Explicitly unsupported in this feature

- Brokered MQTT or AMQP subscriber transports.
- JSON PubSub subscriber mapping.
- TSN hardware scheduling.
- Delta frame, event DataSetMessage, and RawData subscriber application.
- Full Part 14 PubSub information-model method coverage.
- Custom UDP fragment reassembly that is not defined by OPC 10000-14.
