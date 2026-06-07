//! PubSub publishing coordinator.

use std::sync::Arc;

use opcua_core::sync::RwLock;
use opcua_server::address_space::AddressSpace;
use opcua_types::StatusCode;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{
    transport::{
        amqp::AmqpPublisher, mqtt::MqttPublisher, udp::UdpPublisher, websocket::WebSocketPublisher,
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
    cancel_token: Option<CancellationToken>,
    publisher_handles: Vec<JoinHandle<()>>,
}

impl PubSubEngine {
    /// Creates an empty PubSub engine for the supplied OPC UA address space.
    pub fn new(address_space: Arc<RwLock<AddressSpace>>) -> Self {
        Self {
            address_space,
            connections: Vec::new(),
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
            TransportKind::Amqp => AmqpPublisher::new(self.address_space.clone())
                .start_publishing(connection, cancel_token),
            TransportKind::WebSocket => WebSocketPublisher::new(self.address_space.clone())
                .start_publishing(connection, cancel_token),
        }
    }
}
