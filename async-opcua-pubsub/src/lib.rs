//! OPC UA PubSub (Part 14) implementation.

/// Configuration structures for OPC UA PubSub.
pub mod config;

/// Codec modules for UADP and JSON payloads.
pub mod codec;

/// Transport drivers (MQTT, UDP) for PubSub.
pub mod transport;

pub use config::{
    DataSetWriterConfig, MessageEncoding, PubSubConnectionConfig, PublishedDataSetConfig,
    WriterGroupConfig,
};

pub use transport::mqtt::MqttPublisher;
pub use transport::udp::UdpPublisher;

pub use codec::json::{json_value_to_opcua, JsonDataSetMessage, JsonNetworkMessage};
pub use codec::uadp::{PublisherId, UadpDataSetMessage, UadpNetworkMessage};

/// Bridge module to monitor AddressSpace changes and publish events.
pub mod bridge;
pub use bridge::PubSubBridge;

use opcua_types::StatusCode;

/// Trait to manage PubSub publisher instances.
pub trait PubSubPublisher: Send + Sync {
    /// Starts cyclic data transmission using the connection config.
    fn start_publishing(
        &self,
        connection_config: PubSubConnectionConfig,
        cancel_token: tokio_util::sync::CancellationToken,
    ) -> Result<tokio::task::JoinHandle<()>, StatusCode>;
}
