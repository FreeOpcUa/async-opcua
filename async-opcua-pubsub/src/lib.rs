//! OPC UA PubSub (Part 14) implementation.

/// Configuration structures for OPC UA PubSub.
pub mod config;

/// Codec modules for UADP and JSON payloads.
pub mod codec;

/// Transport drivers (AMQP, MQTT, UDP, WebSocket) for PubSub.
pub mod transport;

/// Main PubSub publishing engine coordinator.
pub mod engine;

/// Read-only PubSub information-model reflection.
pub mod pubsub_model;

/// Writable PubSub configuration methods.
pub mod config_methods;

/// Subscriber helpers for applying received PubSub DataSets.
pub mod subscriber;

/// PubSub id reservation and configuration-version compatibility helpers.
pub mod reservation;

/// OPC UA FX in-process connection orchestration helpers.
pub mod fx;

/// PubSub security key management and OPC UA Part 14 secured-NetworkMessage codec.
///
/// Secured UADP NetworkMessages use the Part 14 (§7.2.4.4) wire format: the real SecurityHeader
/// (SecurityFlags, SecurityTokenId, MessageNonce), AES-CTR encryption of the payload region with a
/// per-message nonce, and an HMAC-SHA256 signature over the entire message. The subscriber enforces
/// a bounded anti-replay window on the NetworkMessage sequence number.
pub mod security;

pub use config::{
    DataSetFieldEncoding, DataSetMessageKind, DataSetReaderConfig, DataSetWriterConfig,
    FieldTargetConfig, MessageEncoding, PubSubConnectionConfig, PublishedDataItemsConfig,
    PublishedDataSetConfig, ReaderGroupConfig, WriterGroupConfig,
};
pub use config_methods::{register_pubsub_config_methods, PubSubConfigManager};

pub use engine::{PubSubEngine, TransportKind};
pub use fx::{ConnectionManager, EstablishedConnection};
pub use reservation::{configuration_version_compatible, IdReservation};
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
pub use subscriber::{
    apply_network_message, decode_and_apply, DataSetReaderStatus, SubscriberApplyOutcome,
    SubscriberError, SubscriberRuntime,
};

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
