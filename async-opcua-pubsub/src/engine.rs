//! PubSub publishing coordinator.

use std::{collections::HashMap, sync::Arc};

use opcua_core::sync::RwLock;
use opcua_crypto::SecurityPolicy;
use opcua_server::address_space::AddressSpace;
use opcua_types::{Context, MessageSecurityMode, StatusCode};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{
    codec::uadp::UadpNetworkMessage,
    security::{SecurityGroup, SharedSecurityGroup, UadpSecurityCodec},
    transport::{
        amqp::AmqpPublisher, mqtt::MqttPublisher, udp::UdpPublisher,
        websocket::WebSocketPublisher,
    },
    PubSubConnectionConfig, PubSubPublisher,
};

/// Supported OPC UA PubSub transport mappings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// MQTT broker transport.
    Mqtt,
    /// UDP multicast or unicast transport.
    Udp,
    /// AMQP broker transport.
    Amqp,
    /// WebSocket transport.
    WebSocket,
    /// TSN transport. Experimental, requires the `tsn` feature.
    #[cfg(feature = "tsn")]
    Tsn,
}

impl TransportKind {
    /// Classifies a PubSub connection address by URI scheme.
    pub fn from_address(address: &str) -> Result<Self, StatusCode> {
        let address = address.trim();

        if address.starts_with("mqtt://") || address.starts_with("mqtts://") {
            return Ok(Self::Mqtt);
        }

        if address.starts_with("udp://") {
            return Ok(Self::Udp);
        }

        #[cfg(feature = "tsn")]
        if address.starts_with("tsn://") {
            return Ok(Self::Tsn);
        }

        if address.starts_with("amqp://") || address.starts_with("amqps://") {
            return Ok(Self::Amqp);
        }

        if address.starts_with("ws://") || address.starts_with("wss://") {
            return Ok(Self::WebSocket);
        }

        Err(StatusCode::BadInvalidArgument)
    }
}

/// Coordinates PubSub connection configurations and transport publishing loops.
pub struct PubSubEngine {
    address_space: Arc<RwLock<AddressSpace>>,
    connections: Vec<PubSubConnectionConfig>,
    security_groups: HashMap<String, SharedSecurityGroup>,
    cancel_token: Option<CancellationToken>,
    publisher_handles: Vec<JoinHandle<()>>,
}

impl PubSubEngine {
    /// Creates an empty PubSub engine for the supplied OPC UA address space.
    pub fn new(address_space: Arc<RwLock<AddressSpace>>) -> Self {
        Self {
            address_space,
            connections: Vec::new(),
            security_groups: HashMap::new(),
            cancel_token: None,
            publisher_handles: Vec::new(),
        }
    }

    /// Creates a PubSub engine preloaded with connection configurations.
    pub fn with_connections(
        address_space: Arc<RwLock<AddressSpace>>,
        connections: Vec<PubSubConnectionConfig>,
    ) -> Self {
        Self {
            address_space,
            connections,
            security_groups: HashMap::new(),
            cancel_token: None,
            publisher_handles: Vec::new(),
        }
    }

    /// Adds a connection configuration to be started on the next engine start.
    pub fn add_connection(&mut self, connection: PubSubConnectionConfig) {
        self.connections.push(connection);
    }

    /// Removes a connection configuration by connection id.
    pub fn remove_connection(&mut self, connection_id: &str) -> Option<PubSubConnectionConfig> {
        let index = self
            .connections
            .iter()
            .position(|connection| connection.connection_id == connection_id)?;
        Some(self.connections.remove(index))
    }

    /// Returns the configured PubSub connections.
    pub fn connection_configs(&self) -> &[PubSubConnectionConfig] {
        &self.connections
    }

    /// Registers a PubSub security group for publisher message signing.
    pub fn register_security_group(
        &mut self,
        security_group: SecurityGroup,
    ) -> SharedSecurityGroup {
        let group_id = security_group.group_id().to_string();
        let shared_group = Arc::new(RwLock::new(security_group));
        self.security_groups.insert(group_id, shared_group.clone());
        shared_group
    }

    /// Registers shared PubSub security group state for publisher message signing.
    pub fn register_shared_security_group(&mut self, security_group: SharedSecurityGroup) {
        let group_id = security_group.read().group_id().to_string();
        self.security_groups.insert(group_id, security_group);
    }

    /// Removes a registered PubSub security group.
    pub fn remove_security_group(&mut self, group_id: &str) -> Option<SharedSecurityGroup> {
        self.security_groups.remove(group_id)
    }

    /// Returns a registered PubSub security group.
    pub fn security_group(&self, group_id: &str) -> Option<SharedSecurityGroup> {
        self.security_groups.get(group_id).cloned()
    }

    /// Encodes a publisher UADP NetworkMessage using the current key for a security group.
    pub fn encode_publisher_uadp_message(
        &self,
        security_group_id: &str,
        security_mode: MessageSecurityMode,
        security_policy: SecurityPolicy,
        message: &UadpNetworkMessage,
        ctx: &Context<'_>,
    ) -> Result<Vec<u8>, StatusCode> {
        let security_group = self
            .security_groups
            .get(security_group_id)
            .ok_or(StatusCode::BadSecurityChecksFailed)?;
        let key_set = security_group.read().current_key_set().clone();
        UadpSecurityCodec::new(security_mode, security_policy, key_set)
            .encode_network_message(message, ctx)
            .map_err(|error| error.status())
    }

    /// Signs a publisher UADP NetworkMessage using the current key for a security group.
    pub fn sign_publisher_uadp_message(
        &self,
        security_group_id: &str,
        security_policy: SecurityPolicy,
        message: &UadpNetworkMessage,
        ctx: &Context<'_>,
    ) -> Result<Vec<u8>, StatusCode> {
        self.encode_publisher_uadp_message(
            security_group_id,
            MessageSecurityMode::Sign,
            security_policy,
            message,
            ctx,
        )
    }

    /// Decodes and verifies a subscriber UADP NetworkMessage using a security group's current key.
    pub fn decode_subscriber_uadp_message(
        &self,
        security_group_id: &str,
        security_mode: MessageSecurityMode,
        security_policy: SecurityPolicy,
        payload: &[u8],
        ctx: &Context<'_>,
    ) -> Result<UadpNetworkMessage, StatusCode> {
        let security_group = self
            .security_groups
            .get(security_group_id)
            .ok_or(StatusCode::BadSecurityChecksFailed)?;
        let key_set = security_group.read().current_key_set().clone();
        UadpSecurityCodec::new(security_mode, security_policy, key_set)
            .decode_network_message(payload, ctx)
            .map_err(|error| error.status())
    }

    /// Returns true when the engine has started publisher loops.
    pub fn is_running(&self) -> bool {
        self.cancel_token.is_some()
    }

    /// Returns the number of active publisher coordinator handles.
    pub fn active_handle_count(&self) -> usize {
        self.publisher_handles.len()
    }

    /// Starts transport publisher loops for all configured connections.
    pub fn start(&mut self) -> Result<(), StatusCode> {
        if self.is_running() {
            return Ok(());
        }

        let cancel_token = CancellationToken::new();
        let mut handles = Vec::with_capacity(self.connections.len());

        for connection in &self.connections {
            match self.start_connection(connection.clone(), cancel_token.clone()) {
                Ok(handle) => handles.push(handle),
                Err(status) => {
                    cancel_token.cancel();
                    for handle in handles {
                        handle.abort();
                    }
                    return Err(status);
                }
            }
        }

        self.cancel_token = Some(cancel_token);
        self.publisher_handles = handles;
        Ok(())
    }

    /// Stops all active publisher loops and waits for their coordinator tasks to finish.
    pub async fn stop(&mut self) {
        if let Some(cancel_token) = self.cancel_token.take() {
            cancel_token.cancel();
        }

        while let Some(handle) = self.publisher_handles.pop() {
            let _ = handle.await;
        }
    }

    fn start_connection(
        &self,
        connection: PubSubConnectionConfig,
        cancel_token: CancellationToken,
    ) -> Result<JoinHandle<()>, StatusCode> {
        match TransportKind::from_address(&connection.address)? {
            TransportKind::Mqtt => MqttPublisher::new(self.address_space.clone())
                .start_publishing(connection, cancel_token),
            TransportKind::Udp => UdpPublisher::new(self.address_space.clone())
                .start_publishing(connection, cancel_token),
            #[cfg(feature = "tsn")]
            TransportKind::Tsn => {
                crate::transport::tsn::publisher::TsnPublisher::new(self.address_space.clone())
                    .start_publishing(connection, cancel_token)
            }
            TransportKind::Amqp => AmqpPublisher::new(self.address_space.clone())
                .start_publishing(connection, cancel_token),
            TransportKind::WebSocket => WebSocketPublisher::new(self.address_space.clone())
                .start_publishing(connection, cancel_token),
        }
    }
}
