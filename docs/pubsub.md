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
};

// 2. Start the PubSub bridge with an OPC UA Server instance
let server = Arc::new(server_instance);
let _bridge = async_opcua_pubsub::start_pubsub_bridge(config, server).await.unwrap();
```
