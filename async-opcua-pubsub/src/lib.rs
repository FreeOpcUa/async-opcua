//! OPC UA PubSub (Part 14) implementation.

/// Configuration structures for OPC UA PubSub.
pub mod config;

/// Codec modules for UADP and JSON payloads.
pub mod codec;

/// Transport drivers (AMQP, MQTT, UDP, WebSocket) for PubSub.
pub mod transport;

/// Main PubSub publishing engine coordinator.
pub mod engine;

/// PubSub security key management.
///
/// Note: the message security envelope used here (`OPCUAPS1`) is a
/// proprietary format, not the UADP SecurityHeader from OPC UA Part 14 —
/// it does not interoperate with other PubSub stacks. Treat PubSub
/// security as experimental until the spec header is implemented.
pub mod security;

pub use config::{
    DataSetWriterConfig, MessageEncoding, PubSubConnectionConfig, PublishedDataSetConfig,
    WriterGroupConfig,
};

pub use engine::{PubSubEngine, TransportKind};
pub use security::{
    SecurityGroup, SecurityKeySet, SharedSecurityGroup, TimeBasedKeyRotator, UadpSecurityCodec,
};

pub use transport::amqp::AmqpPublisher;
pub use transport::mqtt::MqttPublisher;
#[cfg(feature = "tsn")]
pub use transport::tsn::publisher::TsnPublisher;
pub use transport::udp::UdpPublisher;
pub use transport::websocket::WebSocketPublisher;

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
