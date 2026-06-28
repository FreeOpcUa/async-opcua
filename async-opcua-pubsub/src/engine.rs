//! PubSub publishing coordinator.

use std::{collections::HashMap, sync::Arc};

use opcua_core::sync::RwLock;
use opcua_crypto::SecurityPolicy;
use opcua_server::address_space::AddressSpace;
use opcua_types::{Context, ContextOwned, MessageSecurityMode, StatusCode};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{
    codec::uadp::UadpNetworkMessage,
    security::{ReplayWindow, SecurityGroup, SharedSecurityGroup, UadpSecurityCodec},
    subscriber::{
        effective_security_config, DataSetReaderStatus, SubscriberApplyOutcome, SubscriberRuntime,
        SubscriberSecurityConfig,
    },
    transport::{
        amqp::AmqpPublisher,
        mqtt::MqttPublisher,
        udp::{bind_subscriber_socket, UdpPublisher, UdpSubscriberEndpoint},
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
    replay_windows: RwLock<HashMap<String, ReplayWindow>>,
    cancel_token: Option<CancellationToken>,
    publisher_handles: Vec<JoinHandle<()>>,
    subscriber_runtime: Option<Arc<RwLock<SubscriberRuntime>>>,
    subscriber_cancel_token: Option<CancellationToken>,
    subscriber_handles: Vec<JoinHandle<()>>,
}

impl PubSubEngine {
    /// Creates an empty PubSub engine for the supplied OPC UA address space.
    pub fn new(address_space: Arc<RwLock<AddressSpace>>) -> Self {
        Self {
            address_space,
            connections: Vec::new(),
            security_groups: HashMap::new(),
            replay_windows: RwLock::new(HashMap::new()),
            cancel_token: None,
            publisher_handles: Vec::new(),
            subscriber_runtime: None,
            subscriber_cancel_token: None,
            subscriber_handles: Vec::new(),
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
            replay_windows: RwLock::new(HashMap::new()),
            cancel_token: None,
            publisher_handles: Vec::new(),
            subscriber_runtime: None,
            subscriber_cancel_token: None,
            subscriber_handles: Vec::new(),
        }
    }

    /// Adds a connection configuration to be started on the next engine start.
    pub fn add_connection(&mut self, connection: PubSubConnectionConfig) {
        self.connections.push(connection);
        if self.subscriber_cancel_token.is_none() {
            self.subscriber_runtime = None;
        }
    }

    /// Removes a connection configuration by connection id.
    pub fn remove_connection(&mut self, connection_id: &str) -> Option<PubSubConnectionConfig> {
        let index = self
            .connections
            .iter()
            .position(|connection| connection.connection_id == connection_id)?;
        let removed = self.connections.remove(index);
        if self.subscriber_cancel_token.is_none() {
            self.subscriber_runtime = None;
        }
        Some(removed)
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
        self.replay_windows.write().remove(&group_id);
        self.security_groups.insert(group_id, shared_group.clone());
        shared_group
    }

    /// Registers shared PubSub security group state for publisher message signing.
    pub fn register_shared_security_group(&mut self, security_group: SharedSecurityGroup) {
        let group_id = security_group.read().group_id().to_string();
        self.replay_windows.write().remove(&group_id);
        self.security_groups.insert(group_id, security_group);
    }

    /// Removes a registered PubSub security group.
    pub fn remove_security_group(&mut self, group_id: &str) -> Option<SharedSecurityGroup> {
        self.replay_windows.write().remove(group_id);
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
        let (token_id, key_sets) = {
            let security_group = security_group.read();
            (
                security_group.current_key_set().token_id(),
                vec![
                    security_group.current_key_set().clone(),
                    security_group.next_key_set().clone(),
                ],
            )
        };
        let message = UadpSecurityCodec::with_candidates(security_mode, security_policy, key_sets)
            .decode_network_message(payload, ctx)
            .map_err(|error| error.status())?;

        if security_mode != MessageSecurityMode::None {
            self.replay_windows
                .write()
                .entry(security_group_id.to_string())
                .or_default()
                .check(token_id, message.sequence_number)
                .map_err(|error| error.status())?;
        }

        Ok(message)
    }

    /// Processes one subscriber datagram for the named connection.
    pub fn process_subscriber_datagram(
        &mut self,
        connection_id: &str,
        payload: &[u8],
        ctx: &Context<'_>,
    ) -> Result<SubscriberApplyOutcome, StatusCode> {
        let connection = self
            .connections
            .iter()
            .find(|connection| connection.connection_id == connection_id)
            .cloned()
            .ok_or(StatusCode::BadNotFound)?;
        connection.validate_subscriber_config()?;

        let reader_ids = connection_reader_ids(&connection);
        let security = first_effective_security(&connection);
        let runtime = self.ensure_subscriber_runtime()?;

        if let Some(security) = security {
            let security_policy = SecurityPolicy::from_uri(&security.security_policy_uri);
            let decoded = if security_policy == SecurityPolicy::Unknown {
                Err(StatusCode::BadSecurityChecksFailed)
            } else {
                self.decode_subscriber_uadp_message(
                    &security.security_group_id,
                    security.security_mode,
                    security_policy,
                    payload,
                    ctx,
                )
            };

            return match decoded {
                Ok(message) => runtime.write().process_network_message(&message),
                Err(status) => {
                    runtime
                        .write()
                        .record_security_failure_for_readers(&reader_ids);
                    Err(status)
                }
            };
        }

        let result = runtime.write().process_datagram(payload, ctx);
        result
    }

    /// Returns a subscriber DataSetReader status snapshot.
    #[must_use]
    pub fn subscriber_status(&self, reader_id: u16) -> Option<DataSetReaderStatus> {
        self.subscriber_runtime
            .as_ref()
            .and_then(|runtime| runtime.read().reader_status(reader_id))
    }

    /// Returns true when the engine has started publisher loops.
    pub fn is_running(&self) -> bool {
        self.cancel_token.is_some()
    }

    /// Returns the number of active publisher coordinator handles.
    pub fn active_handle_count(&self) -> usize {
        self.publisher_handles.len()
    }

    /// Returns true when subscriber receive loops are running.
    pub fn subscribers_are_running(&self) -> bool {
        self.subscriber_cancel_token.is_some()
    }

    /// Returns the number of active subscriber receive task handles.
    pub fn active_subscriber_handle_count(&self) -> usize {
        self.subscriber_handles.len()
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
        self.stop_subscribers().await;

        if let Some(cancel_token) = self.cancel_token.take() {
            cancel_token.cancel();
        }

        while let Some(handle) = self.publisher_handles.pop() {
            let _ = handle.await;
        }
    }

    /// Starts UDP subscriber receive loops for configured ReaderGroups.
    pub fn start_subscribers(&mut self) -> Result<(), StatusCode> {
        if self.subscribers_are_running() {
            return Ok(());
        }

        let connections = self
            .connections
            .iter()
            .filter(|connection| !connection.reader_groups.is_empty())
            .cloned()
            .collect::<Vec<_>>();
        if connections.is_empty() {
            return Ok(());
        }

        for connection in &connections {
            connection.validate_subscriber_config()?;
        }

        let runtime = self.ensure_subscriber_runtime()?;
        let cancel_token = CancellationToken::new();
        let mut handles = Vec::with_capacity(connections.len());

        for connection in connections {
            let endpoint = UdpSubscriberEndpoint::parse(&connection.address)?;
            let runtime = runtime.clone();
            let cancel_token = cancel_token.clone();
            let connection_id = connection.connection_id;

            handles.push(tokio::spawn(async move {
                let socket = match bind_subscriber_socket(endpoint).await {
                    Ok(socket) => socket,
                    Err(status) => {
                        tracing::error!(
                            ?status,
                            %connection_id,
                            "failed to bind PubSub subscriber UDP socket"
                        );
                        return;
                    }
                };
                let mut buf = vec![0_u8; 65_535];

                loop {
                    tokio::select! {
                        _ = cancel_token.cancelled() => break,
                        received = socket.recv_from(&mut buf) => {
                            match received {
                                Ok((len, _peer)) => {
                                    let ctx_owned = ContextOwned::default();
                                    let ctx = ctx_owned.context();
                                    if let Err(status) = runtime.write().process_datagram(&buf[..len], &ctx) {
                                        tracing::debug!(
                                            ?status,
                                            %connection_id,
                                            "dropped PubSub subscriber UDP datagram"
                                        );
                                    }
                                }
                                Err(error) => {
                                    tracing::warn!(
                                        ?error,
                                        %connection_id,
                                        "failed to receive PubSub subscriber UDP datagram"
                                    );
                                }
                            }
                        }
                    }
                }
            }));
        }

        self.subscriber_cancel_token = Some(cancel_token);
        self.subscriber_handles = handles;
        Ok(())
    }

    /// Stops all subscriber receive loops and waits for them to finish.
    pub async fn stop_subscribers(&mut self) {
        if let Some(cancel_token) = self.subscriber_cancel_token.take() {
            cancel_token.cancel();
        }

        while let Some(handle) = self.subscriber_handles.pop() {
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

    fn ensure_subscriber_runtime(&mut self) -> Result<Arc<RwLock<SubscriberRuntime>>, StatusCode> {
        if let Some(runtime) = &self.subscriber_runtime {
            return Ok(runtime.clone());
        }

        let runtime = SubscriberRuntime::with_connections(
            self.address_space.clone(),
            self.connections.clone(),
        )?;
        let runtime = Arc::new(RwLock::new(runtime));
        self.subscriber_runtime = Some(runtime.clone());
        Ok(runtime)
    }
}

fn first_effective_security(
    connection: &PubSubConnectionConfig,
) -> Option<SubscriberSecurityConfig> {
    connection
        .reader_groups
        .iter()
        .flat_map(|reader_group| {
            reader_group
                .dataset_readers
                .iter()
                .filter_map(move |reader| effective_security_config(reader_group, reader))
        })
        .next()
}

fn connection_reader_ids(connection: &PubSubConnectionConfig) -> Vec<u16> {
    connection
        .reader_groups
        .iter()
        .flat_map(|reader_group| reader_group.dataset_readers.iter())
        .map(|reader| reader.dataset_reader_id)
        .collect()
}
