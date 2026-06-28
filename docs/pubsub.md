# OPC UA PubSub Configuration & Usage

The `async-opcua-pubsub` crate implements the OPC UA PubSub (Part 14) specifications, supporting both brokered and brokerless communication protocols.

## 1. Supported Transport Protocols

1. **UDP Multicast (UADP)**: Brokerless communication ideal for high-throughput, low-latency factory floor networks.
2. **MQTT (JSON)**: Brokered communication for cloud and IoT integration.
3. **AMQP (JSON)**: Enterprise messaging integration using brokers like RabbitMQ.
4. **WebSockets (JSON)**: Web-based telemetry streaming.

## 2. Configuration Structures

The main configuration is defined via `PubSubConnectionConfig`:

```rust
pub struct PubSubConnectionConfig {
    pub connection_id: String,
    pub name: String,
    pub address: String, // e.g. "udp://239.0.0.1:4840" or "mqtt://localhost:1883"
    pub writer_groups: Vec<WriterGroupConfig>,
    pub reader_groups: Vec<ReaderGroupConfig>,
}

pub struct WriterGroupConfig {
    pub writer_group_id: u16,
    pub publishing_interval: u64, // millisecond interval
    pub encoding: MessageEncoding, // MessageEncoding::Uadp or MessageEncoding::Json
    pub dataset_writers: Vec<DataSetWriterConfig>,
}

pub struct DataSetWriterConfig {
    pub dataset_writer_id: u16,
    pub dataset_name: String,
    pub published_dataset: PublishedDataSetConfig,
}

pub struct PublishedDataSetConfig {
    pub published_variables: Vec<NodeId>,
}

pub struct ReaderGroupConfig {
    pub reader_group_id: u16,
    pub security_mode: Option<MessageSecurityMode>,
    pub security_policy_uri: Option<String>,
    pub security_group_id: Option<String>,
    pub dataset_readers: Vec<DataSetReaderConfig>,
}

pub struct DataSetReaderConfig {
    pub dataset_reader_id: u16,
    pub dataset_writer_id: u16,
    pub publisher_id: Option<PublisherId>,
    pub writer_group_id: Option<u16>,
    pub network_message_number: Option<u16>,
    pub target_variables: Vec<FieldTargetConfig>,
}
```

## 3. Running the PubSub Bridge

To bridge data from an OPC UA server's AddressSpace to a PubSub broker/multicast endpoint:

```rust
use async_opcua_pubsub::{PubSubConnectionConfig, WriterGroupConfig, DataSetWriterConfig, PublishedDataSetConfig, MessageEncoding};
use opcua_types::NodeId;
use std::sync::Arc;

// 1. Define configuration
let config = PubSubConnectionConfig {
    connection_id: "conn-1".to_string(),
    name: "FactorySensors".to_string(),
    address: "udp://239.0.0.1:4840".to_string(),
    writer_groups: vec![WriterGroupConfig {
        writer_group_id: 101,
        publishing_interval: 1000,
        encoding: MessageEncoding::Uadp,
        dataset_writers: vec![DataSetWriterConfig {
            dataset_writer_id: 1,
            dataset_name: "TemperatureDataSet".to_string(),
            published_dataset: PublishedDataSetConfig {
                published_variables: vec![NodeId::new(2, "TemperatureSensor")],
            },
        }],
    }],
    reader_groups: Vec::new(),
};

// 2. Start the PubSub bridge with an OPC UA Server instance
let server = Arc::new(server_instance);
let _bridge = async_opcua_pubsub::start_pubsub_bridge(config, server).await.unwrap();
```

## 4. Running a UADP Subscriber

The subscriber runtime applies matching UADP key-frame DataSetMessages to configured target Variables. Matching uses the configured PublisherId, WriterGroupId, NetworkMessageNumber, and DataSetWriterId filters; omitted PublisherId/WriterGroupId/NetworkMessageNumber and a DataSetWriterId of `0` act as wildcards.

```rust
use std::sync::Arc;

use opcua_core::sync::RwLock;
use opcua_pubsub::{
    DataSetReaderConfig, FieldTargetConfig, PubSubConnectionConfig, ReaderGroupConfig,
    SubscriberRuntime,
};
use opcua_server::address_space::AddressSpace;
use opcua_types::{ContextOwned, NodeId};

let address_space = Arc::new(RwLock::new(AddressSpace::new()));
let target = NodeId::new(2, "TemperatureTarget");

let config = PubSubConnectionConfig {
    connection_id: "subscriber-1".to_string(),
    name: "LineSubscriber".to_string(),
    address: "udp://239.0.0.1:4840".to_string(),
    writer_groups: Vec::new(),
    reader_groups: vec![ReaderGroupConfig {
        reader_group_id: 1,
        dataset_readers: vec![DataSetReaderConfig {
            dataset_reader_id: 1,
            dataset_writer_id: 10,
            target_variables: vec![FieldTargetConfig::value(0, target)],
            ..DataSetReaderConfig::default()
        }],
        ..ReaderGroupConfig::default()
    }],
};

let mut runtime = SubscriberRuntime::with_connections(address_space, vec![config])?;
let ctx_owned = ContextOwned::default();
let ctx = ctx_owned.context();
runtime.process_datagram(&udp_payload, &ctx)?;
let status = runtime.reader_status(1);
```

## Limitations and experimental features

- **Subscriber scope**: the reader side supports brokerless UDP UADP key-frame
  DataSetMessages with Variant/DataValue-compatible fields and Value-attribute
  target writes. JSON mapping, broker transports, RawData payloads, delta frames,
  event DataSetMessages, non-Value target attributes, index ranges, and the
  crate's legacy publisher fragmentation header are rejected with
  `BadNotSupported`.
- **Message security**: secured UADP NetworkMessages use the OPC UA Part 14
  SecurityHeader, SecurityTokenId, MessageNonce, AES-CTR payload encryption,
  HMAC-SHA256 signing, and subscriber anti-replay checks before target Variables
  are updated. Secure subscriber processing requires a registered
  `SecurityGroup` and matching ReaderGroup/DataSetReader security settings.
- **TSN is a simulated stub**: the `tsn://` transport is gated behind the
  off-by-default `tsn` feature of `async-opcua-pubsub`. Its AF_XDP socket is
  a simulated loopback and scheduling shells out to `tc taprio`; it has not
  been validated on real TSN hardware (spec 004 T046). The 2026-06-28 T046
  closeout found no PHC device, no NIC hardware timestamp modes, no local
  PTP/cyclictest tooling, and no effective raw-socket capability in this
  workspace, so no sub-millisecond jitter claim is made.
