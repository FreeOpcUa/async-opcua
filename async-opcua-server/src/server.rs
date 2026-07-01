use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::{
        atomic::{AtomicU16, AtomicU8},
        Arc,
    },
    time::Duration,
};

use arc_swap::ArcSwap;
use futures::{future::Either, never::Never, stream::FuturesUnordered, FutureExt, StreamExt};
use opcua_core::{sync::RwLock, trace_read_lock, trace_write_lock};
use opcua_nodes::DefaultTypeTree;
use tokio::{
    net::{TcpListener, TcpStream},
    pin,
    sync::{mpsc, Notify},
    task::{JoinError, JoinHandle},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use opcua_core::{config::Config, handle::AtomicHandle};
use opcua_crypto::{CertificateStore, RevocationMode, ValidationOptions};

use crate::metrics::ServerMetricsSnapshot;
#[cfg(feature = "wss")]
use crate::transport::WebSocketConnector;
use crate::{
    diagnostics::ServerDiagnostics,
    node_manager::{DefaultTypeTreeGetter, ServerContext},
    reverse_connect::{self, ReverseConnectionManager},
    session::controller::{ControllerCommand, SessionStarter},
    transport::{
        tcp::{TcpConnector, TransportConfig},
        ReverseTcpConnector,
    },
    ServerStatusWrapper,
};
use opcua_types::{DateTime, LocalizedText, ServerState, UAString};

use super::{
    authenticator::DefaultAuthenticator,
    builder::ServerBuilder,
    config::{ServerConfig, TcpKeepaliveConfig},
    info::ServerInfo,
    node_manager::{NodeManagers, NodeManagersRef},
    server_handle::ServerHandle,
    session::manager::SessionManager,
    subscriptions::SubscriptionCache,
    ServerCapabilities,
};

struct ConnectionInfo {
    command_send: tokio::sync::mpsc::Sender<ControllerCommand>,
    ip: IpAddr,
}

struct ConnectionSlots<'a> {
    connections: &'a mut FuturesUnordered<JoinHandle<u32>>,
    connection_map: &'a mut HashMap<u32, ConnectionInfo>,
}

struct TcpConnectionDeps {
    max_connections: usize,
    max_connections_per_ip: usize,
    transport_config: TransportConfig,
    info: Arc<ServerInfo>,
    session_manager: Arc<RwLock<SessionManager>>,
    certificate_store: Arc<RwLock<CertificateStore>>,
    node_managers: NodeManagers,
    subscriptions: Arc<SubscriptionCache>,
}

#[derive(Clone)]
enum AcceptedTransport {
    Tcp,
    #[cfg(feature = "wss")]
    Wss(Arc<rustls::ServerConfig>),
}

fn configure_tcp_stream(stream: &TcpStream, addr: SocketAddr, tcp_keepalive: &TcpKeepaliveConfig) {
    if let Err(e) = stream.set_nodelay(true) {
        warn!("Failed to set TCP_NODELAY for {addr}: {e}");
    }
    if tcp_keepalive.enabled {
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(tcp_keepalive.idle_secs))
            .with_interval(Duration::from_secs(tcp_keepalive.interval_secs))
            .with_retries(tcp_keepalive.retries);
        if let Err(e) = socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive) {
            warn!("Failed to set TCP keep-alive for {addr}: {e}");
        }
    }
}

impl TcpConnectionDeps {
    fn accept<T: Send + 'static>(
        &self,
        slots: &mut ConnectionSlots<'_>,
        socket: TcpStream,
        addr: SocketAddr,
        token: Option<T>,
        connection_counter: u32,
        transport: AcceptedTransport,
    ) -> bool {
        if slots.connection_map.len() >= self.max_connections {
            warn!(
                "Closing connection from {addr}: max_connections ({}) reached",
                self.max_connections
            );
            drop(socket);
            drop(token);
            return false;
        }
        let ip = addr.ip();
        if self.max_connections_per_ip > 0 {
            let connections_from_ip = slots
                .connection_map
                .values()
                .filter(|connection| connection.ip == ip)
                .count();
            if connections_from_ip >= self.max_connections_per_ip {
                warn!("Closing connection from {addr}: max_connections_per_ip reached");
                drop(socket);
                drop(token);
                return false;
            }
        }

        configure_tcp_stream(&socket, addr, &self.transport_config.tcp_keepalive);

        let (send, recv) = tokio::sync::mpsc::channel(5);
        info!("Accept new connection from {addr} ({connection_counter})");
        self.info.metrics.record_connection_accepted();
        let handle = match transport {
            AcceptedTransport::Tcp => {
                let conn = SessionStarter::new(
                    TcpConnector::new(
                        socket,
                        self.transport_config.clone(),
                        self.info.decoding_options(),
                    ),
                    self.info.clone(),
                    self.session_manager.clone(),
                    self.certificate_store.clone(),
                    self.node_managers.clone(),
                    self.subscriptions.clone(),
                );
                spawn_connection(conn, recv, token, connection_counter)
            }
            #[cfg(feature = "wss")]
            AcceptedTransport::Wss(tls_config) => {
                let conn = SessionStarter::new(
                    WebSocketConnector::new(
                        socket,
                        tls_config,
                        self.transport_config.clone(),
                        self.info.decoding_options(),
                    ),
                    self.info.clone(),
                    self.session_manager.clone(),
                    self.certificate_store.clone(),
                    self.node_managers.clone(),
                    self.subscriptions.clone(),
                );
                spawn_connection(conn, recv, token, connection_counter)
            }
        };
        slots.connections.push(handle);
        slots.connection_map.insert(
            connection_counter,
            ConnectionInfo {
                command_send: send,
                ip,
            },
        );
        true
    }
}

fn spawn_connection<C, T>(
    conn: SessionStarter<C>,
    recv: tokio::sync::mpsc::Receiver<ControllerCommand>,
    token: Option<T>,
    connection_counter: u32,
) -> JoinHandle<u32>
where
    C: crate::transport::Connector + Send + 'static,
    C::Transport: crate::transport::tcp::ConnectionTransport,
    T: Send + 'static,
{
    tokio::spawn(async move {
        let _token = token;
        // Catch panics so the task always yields its counter, otherwise
        // the connection_map slot leaks and permanently consumes
        // max_connections capacity.
        if let Err(payload) = std::panic::AssertUnwindSafe(conn.run(recv, |_| {}))
            .catch_unwind()
            .await
        {
            log_connection_panic(connection_counter, payload);
        }
        connection_counter
    })
}

fn log_connection_panic(connection_counter: u32, payload: Box<dyn std::any::Any + Send>) {
    let message = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("unknown panic payload");
    error!("Connection task {connection_counter} panicked: {message}");
}

enum ConnectionSource<T> {
    Listener(TcpListener),
    Streams(mpsc::Receiver<(TcpStream, SocketAddr, T)>),
    Closed,
}

impl<T> ConnectionSource<T> {
    async fn next(&mut self) -> Option<Result<(TcpStream, SocketAddr, Option<T>), std::io::Error>> {
        match self {
            Self::Listener(listener) => Some(
                listener
                    .accept()
                    .await
                    .map(|(socket, addr)| (socket, addr, None)),
            ),
            Self::Streams(rx) => rx
                .recv()
                .await
                .map(|(socket, addr, token)| Ok((socket, addr, Some(token)))),
            Self::Closed => futures::future::pending().await,
        }
    }

    fn is_closed(&self) -> bool {
        matches!(self, Self::Closed)
    }
}

/// The server struct. This is consumed when run, so you will typically not hold onto this for longer
/// periods of time.
pub struct Server {
    /// Certificate store
    certificate_store: Arc<RwLock<CertificateStore>>,
    /// Session manager
    session_manager: Arc<RwLock<SessionManager>>,
    /// Open connections.
    connections: FuturesUnordered<JoinHandle<u32>>,
    /// Map to metadata about each open connection
    connection_map: HashMap<u32, ConnectionInfo>,
    /// Server configuration, fixed after the server is started
    config: Arc<ServerConfig>,
    /// Context for use by connections to access general server state.
    info: Arc<ServerInfo>,
    /// Subscription cache, global because subscriptions outlive sessions.
    subscriptions: Arc<SubscriptionCache>,
    /// List of node managers
    node_managers: NodeManagers,
    /// Cancellation token
    token: CancellationToken,
    /// Notify that is woken up if a new session is added to the session manager.
    session_notify: Arc<Notify>,
    /// Wrapper managing the `ServerStatus` server variable.
    status: Arc<ServerStatusWrapper>,
    /// Manager for reverse connections. This does nothing unless users register
    /// reverse connect targets.
    reverse_connect_manager: ReverseConnectionManager,
}

impl Server {
    pub(crate) fn new_from_builder(builder: ServerBuilder) -> Result<(Self, ServerHandle), String> {
        if let Err(e) = builder.config.validate() {
            return Err(format!(
                "Builder configuration is invalid: {}",
                e.join(", ")
            ));
        }

        let mut config = builder.config;

        let application_name = config.application_name.clone();
        let application_uri = UAString::from(&config.application_uri);
        let product_uri = UAString::from(&config.product_uri);
        let servers = vec![config.application_uri.clone()];
        /* let base_endpoint = format!(
            "opc.tcp://{}:{}",
            config.tcp_config.host, config.tcp_config.port
        ); */

        // let diagnostics = Arc::new(RwLock::new(ServerDiagnostics::default()));
        let send_buffer_size = config.limits.send_buffer_size;
        let receive_buffer_size = config.limits.receive_buffer_size;

        let application_description = if config.create_sample_keypair {
            Some(config.application_description())
        } else {
            None
        };

        let (mut certificate_store, server_certificate, server_pkey) =
            CertificateStore::new_with_x509_data(
                &config.pki_dir,
                false,
                config.certificate_path.as_deref(),
                config.private_key_path.as_deref(),
                application_description,
            );

        if server_certificate.is_none() || server_pkey.is_none() {
            warn!(
                "Server is missing its application instance certificate and/or its private key. Encrypted endpoints will not function correctly."
            );
        }

        config.read_x509_thumbprints();

        if config.certificate_validation.trust_client_certs {
            info!(
                "Server has chosen to auto trust client certificates. You do not want to do this in production code."
            );
            certificate_store.set_trust_unknown_certs(true);
        }
        certificate_store.set_check_time(config.certificate_validation.check_time);
        certificate_store.set_validation_options(ValidationOptions {
            revocation_mode: if config.certificate_validation.require_revocation {
                RevocationMode::Required
            } else {
                RevocationMode::Lenient
            },
            ..Default::default()
        });

        let mut role_resolver =
            crate::rbac::resolver::RoleResolver::from_user_tokens(&config.user_tokens);
        for mapping in &config.identity_mapping_rules {
            role_resolver.add_mapping(mapping.role_node_id.clone(), mapping.rule.clone());
        }
        let namespace_defaults =
            crate::rbac::defaults::NamespaceDefaults::from_config(&config.namespace_defaults);
        let config = Arc::new(config);

        let service_level = Arc::new(AtomicU8::new(255));

        #[cfg(feature = "discovery-mdns")]
        let mdns = if config.multicast_discovery.enabled {
            let own_instance = config
                .multicast_discovery
                .mdns_server_name
                .clone()
                .unwrap_or_else(|| config.application_name.clone());
            Some(Arc::new(crate::discovery_mdns::MdnsDiscovery::new(
                own_instance,
            )))
        } else {
            None
        };

        #[cfg(feature = "discovery-mdns")]
        let registered_mdns = if config.multicast_discovery.enabled {
            match crate::discovery_mdns::MdnsAdvertisementRegistry::new() {
                Ok(registry) => Some(Arc::new(registry)),
                Err(e) => {
                    warn!("mDNS registered-server advertisements unavailable: {e}");
                    None
                }
            }
        } else {
            None
        };

        let type_tree = Arc::new(RwLock::new(DefaultTypeTree::new()));

        let certificate_store = Arc::new(RwLock::new(certificate_store));

        let info = ServerInfo {
            authenticator: builder
                .authenticator
                .unwrap_or_else(|| Arc::new(DefaultAuthenticator::new(config.user_tokens.clone()))),
            role_resolver: Arc::new(RwLock::new(role_resolver)),
            namespace_defaults,
            application_uri,
            product_uri,
            application_name: LocalizedText {
                locale: UAString::null(),
                text: UAString::from(application_name),
            },
            start_time: ArcSwap::new(Arc::new(opcua_types::DateTime::now())),
            servers,
            config: config.clone(),
            server_certificate: RwLock::new(server_certificate),
            server_pkey: RwLock::new(server_pkey),
            certificate_store: certificate_store.clone(),
            operational_limits: config.limits.operational.clone(),
            state: ArcSwap::new(Arc::new(ServerState::Shutdown)),
            send_buffer_size,
            receive_buffer_size,
            type_tree: type_tree.clone(),
            type_tree_snapshot: ArcSwap::new(Arc::new(None)),
            subscription_id_handle: AtomicHandle::new(1),
            monitored_item_id_handle: AtomicHandle::new(1),
            secure_channel_id_handle: Arc::new(AtomicHandle::new(1)),
            capabilities: ServerCapabilities::default(),
            service_level: service_level.clone(),
            port: AtomicU16::new(0),
            type_tree_getter: builder
                .type_tree_getter
                .unwrap_or_else(|| Arc::new(DefaultTypeTreeGetter)),
            type_loaders: RwLock::new(builder.type_loaders),
            registered_servers: RwLock::new(Default::default()),
            #[cfg(feature = "discovery-mdns")]
            mdns,
            #[cfg(feature = "discovery-mdns")]
            registered_mdns,
            diagnostics: ServerDiagnostics {
                enabled: config.diagnostics,
                ..Default::default()
            },
            metrics: Arc::new(crate::metrics::ServerMetrics::new()),
            fota_cleanup: Default::default(),
        };

        let info = Arc::new(info);
        let node_managers_ref = NodeManagersRef::new_empty();
        let subscriptions = Arc::new(SubscriptionCache::new_with_node_managers(
            config.limits.subscriptions,
            node_managers_ref.clone(),
        ));
        let status_wrapper = Arc::new(ServerStatusWrapper::new(
            builder.build_info,
            subscriptions.clone(),
        ));
        let context = ServerContext {
            node_managers: node_managers_ref.clone(),
            subscriptions: subscriptions.clone(),
            info: info.clone(),
            authenticator: info.authenticator.clone(),
            type_tree: type_tree.clone(),
            type_tree_getter: info.type_tree_getter.clone(),
            status: status_wrapper.clone(),
        };

        let mut final_node_managers = Vec::new();
        for nm_builder in builder.node_managers {
            final_node_managers.push(nm_builder.build(context.clone()));
        }

        let node_managers = NodeManagers::new(final_node_managers);
        node_managers_ref.init_from_node_managers(node_managers.clone());

        #[cfg(feature = "generated-address-space")]
        if let Some(core_node_manager) =
            node_managers.get_of_type::<crate::node_manager::memory::CoreNodeManager>()
        {
            crate::rbac::role_management::register_role_management_methods(
                &core_node_manager,
                Arc::clone(&info.role_resolver),
                Arc::clone(core_node_manager.address_space()),
            );
        }

        let session_notify = Arc::new(Notify::new());
        let session_manager = Arc::new(RwLock::new(SessionManager::new(
            info.clone(),
            session_notify.clone(),
        )));

        let (reverse_connect_manager, reverse_connect_handle) =
            reverse_connect::ReverseConnectionManager::new(Duration::from_millis(
                config.reverse_connect_failure_delay_ms,
            ));

        let handle = ServerHandle::new(
            info.clone(),
            certificate_store.clone(),
            service_level,
            subscriptions.clone(),
            node_managers.clone(),
            session_manager.clone(),
            type_tree.clone(),
            status_wrapper.clone(),
            builder.token.clone(),
            reverse_connect_handle,
        );
        Ok((
            Self {
                certificate_store,
                session_manager,
                connections: FuturesUnordered::new(),
                connection_map: HashMap::new(),
                subscriptions,
                config,
                info,
                node_managers,
                token: builder.token,
                session_notify,
                status: status_wrapper.clone(),
                reverse_connect_manager,
            },
            handle,
        ))
    }

    /// Get a reference to the SubscriptionCache containing all subscriptions on the server.
    pub fn subscriptions(&self) -> Arc<SubscriptionCache> {
        self.subscriptions.clone()
    }

    /// Returns a point-in-time copy of this server's metrics.
    pub fn metrics_snapshot(&self) -> ServerMetricsSnapshot {
        self.info.metrics.snapshot()
    }

    #[allow(clippy::await_holding_lock)]
    async fn initialize_node_managers(&self, context: &ServerContext) -> Result<(), String> {
        info!("Initializing node managers");
        {
            if self.node_managers.is_empty() {
                return Err("No node managers defined, server is invalid".to_string());
            }

            // Normally we would strongly attempt to avoid holding a lock over an await point,
            // but during initialization we essentially own the type tree, so this shouldn't deadlock
            // unless a manager for whatever reason attempts to lock the type tree again.
            let mut type_tree = trace_write_lock!(self.info.type_tree);

            for mgr in self.node_managers.iter() {
                mgr.init(&mut type_tree, context.clone()).await;
            }

            self.info.publish_type_tree_snapshot(&type_tree);
        }
        Ok(())
    }

    #[cfg(feature = "discovery-server-registration")]
    async fn run_discovery_server_registration(info: Arc<ServerInfo>) -> Never {
        let registered_server = info.registered_server();
        let Some(discovery_server_url) = info.config.discovery_server_url.as_ref() else {
            loop {
                futures::future::pending::<()>().await;
            }
        };
        crate::discovery::periodic_discovery_server_registration(
            discovery_server_url,
            registered_server,
            info.config.pki_dir.clone(),
            Duration::from_secs(5 * 60),
        )
        .await
    }

    fn server_context(&self) -> ServerContext {
        ServerContext {
            node_managers: self.node_managers.as_weak(),
            subscriptions: self.subscriptions.clone(),
            info: self.info.clone(),
            authenticator: self.info.authenticator.clone(),
            type_tree: self.info.type_tree.clone(),
            type_tree_getter: self.info.type_tree_getter.clone(),
            status: self.status.clone(),
        }
    }

    async fn prepare_to_run(&self, context: &ServerContext) -> Result<(), String> {
        self.initialize_node_managers(context).await?;

        self.status.set_server_started();
        self.info.start_time.store(Arc::new(DateTime::now()));
        Ok(())
    }

    fn transport_config(&self) -> TransportConfig {
        TransportConfig {
            send_buffer_size: self.info.config.limits.send_buffer_size,
            max_message_size: self.info.config.limits.max_message_size,
            max_chunk_count: self.info.config.limits.max_chunk_count,
            receive_buffer_size: self.info.config.limits.receive_buffer_size,
            hello_timeout: Duration::from_secs(self.info.config.tcp_config.hello_timeout as u64),
            tcp_keepalive: self.info.config.tcp_config.tcp_keepalive,
        }
    }

    fn tcp_connection_deps(&self) -> TcpConnectionDeps {
        TcpConnectionDeps {
            max_connections: self.config.max_connections,
            max_connections_per_ip: self.config.max_connections_per_ip,
            transport_config: self.transport_config(),
            info: self.info.clone(),
            session_manager: self.session_manager.clone(),
            certificate_store: self.certificate_store.clone(),
            node_managers: self.node_managers.clone(),
            subscriptions: self.subscriptions.clone(),
        }
    }

    async fn run_connection_loop<T: Send + 'static>(
        &mut self,
        context: &ServerContext,
        mut connection_source: ConnectionSource<T>,
        transport: AcceptedTransport,
    ) -> Result<(), String> {
        let mut connection_counter = 0;

        #[cfg(feature = "discovery-server-registration")]
        let discovery_fut = Self::run_discovery_server_registration(self.info.clone());

        #[cfg(not(feature = "discovery-server-registration"))]
        let discovery_fut = futures::future::pending();

        pin!(discovery_fut);

        #[cfg(feature = "discovery-mdns")]
        let mdns_fut = crate::discovery_mdns::run_mdns_discovery(self.info.clone());

        #[cfg(not(feature = "discovery-mdns"))]
        let mdns_fut = futures::future::pending();

        pin!(mdns_fut);

        let subscription_fut =
            Self::run_subscription_ticks(self.config.subscription_poll_interval_ms, context);
        pin!(subscription_fut);

        let session_expiry_fut =
            Self::run_session_expiry(&self.session_manager, &self.session_notify);
        pin!(session_expiry_fut);

        loop {
            if connection_source.is_closed() && self.connections.is_empty() {
                break;
            }

            let conn_fut = if self.connections.is_empty() {
                if self.token.is_cancelled() {
                    break;
                }
                Either::Left(futures::future::pending::<Option<Result<u32, JoinError>>>())
            } else {
                Either::Right(self.connections.next())
            };
            let reverse_connect_fut = if self.connection_map.len() >= self.config.max_connections {
                Either::Left(futures::future::pending())
            } else {
                Either::Right(self.reverse_connect_manager.wait_for_connection())
            };

            tokio::select! {
                conn_res = conn_fut => {
                    match conn_res.unwrap() {
                        Ok(id) => {
                            info!("Connection {} terminated", id);
                            self.connection_map.remove(&id);
                            self.info.metrics.record_connection_closed();
                        },
                        Err(e) => error!("Connection panic! {e}")
                    }
                }
                _ = &mut subscription_fut => {}
                _ = &mut discovery_fut => {}
                _ = &mut mdns_fut => {}
                _ = &mut session_expiry_fut => {}
                rs = connection_source.next() => {
                    match rs {
                        Some(Ok((socket, addr, token))) => {
                            let deps = self.tcp_connection_deps();
                            let mut slots = ConnectionSlots {
                                connections: &mut self.connections,
                                connection_map: &mut self.connection_map,
                            };
                            let accepted = deps.accept(
                                &mut slots,
                                socket,
                                addr,
                                token,
                                connection_counter,
                                transport.clone(),
                            );
                            if accepted {
                                connection_counter += 1;
                            }
                        }
                        Some(Err(e)) => {
                            error!("Failed to accept client connection: {:?}", e);
                        }
                        None => {
                            info!("Stream handoff channel closed");
                            connection_source = ConnectionSource::Closed;
                        }
                    }
                }
                rev_connect = reverse_connect_fut => {
                    debug!("Attempting reverse connection to {:?}", rev_connect.target.address);
                    let conn = SessionStarter::new(
                        ReverseTcpConnector::new(
                            self.transport_config(),
                            self.info.decoding_options(),
                            rev_connect.target.address,
                            self.info.application_uri.to_string(),
                            rev_connect.target.endpoint_url,
                        ),
                        self.info.clone(),
                        self.session_manager.clone(),
                        self.certificate_store.clone(),
                        self.node_managers.clone(),
                        self.subscriptions.clone()
                    );

                    // We need to make sure that the reverse connect handle is passed
                    // to the connection task, so that we can signal the result of the connection attempt
                    // back to the reverse connect manager.
                    let (send, recv) = tokio::sync::mpsc::channel(5);
                    let rev_handle = rev_connect.handle;
                    self.info.metrics.record_connection_accepted();
                    let handle = tokio::spawn(async move {
                        let run = conn.run(recv, |status| {
                            rev_handle.set_result(status);
                        });
                        if let Err(payload) = std::panic::AssertUnwindSafe(run)
                            .catch_unwind()
                            .await
                        {
                            log_connection_panic(connection_counter, payload);
                        }
                        connection_counter
                    });
                    self.connections.push(handle);
                    self.connection_map.insert(connection_counter, ConnectionInfo {
                        command_send: send,
                        ip: rev_connect.target.address.ip(),
                    });
                    connection_counter += 1;
                }
                _ = self.token.cancelled() => {
                    for conn in self.connection_map.values() {
                        let _ = conn.command_send.send(ControllerCommand::Close).await;
                    }
                }
            }
        }

        Ok(())
    }

    /// Run the server using a given TCP listener.
    /// Note that the configured TCP endpoint is still used to create the endpoint
    /// descriptions, you must properly set `host` and `port` even when using this.
    ///
    /// This is useful for testing, as you can bind a `TcpListener` to port `0` auto-assign
    /// a port.
    pub async fn run_with(mut self, listener: TcpListener) -> Result<(), String> {
        let context = self.server_context();
        self.prepare_to_run(&context).await?;

        let addr = listener
            .local_addr()
            .map_err(|e| format!("Failed to bind socket: {e:?}"))?;
        info!("Now listening for connections on {addr}");

        self.info
            .port
            .store(addr.port(), std::sync::atomic::Ordering::Relaxed);

        self.log_endpoint_info();
        self.run_connection_loop(
            &context,
            ConnectionSource::<()>::Listener(listener),
            AcceptedTransport::Tcp,
        )
        .await
    }

    /// Run the server using a given TCP listener for `opc.wss` connections.
    ///
    /// The configured TCP endpoint is still used to create endpoint descriptions,
    /// but accepted sockets are upgraded with TLS and WebSocket framing before
    /// the normal OPC UA binary transport handshake.
    #[cfg(feature = "wss")]
    pub async fn run_with_wss(mut self, listener: TcpListener) -> Result<(), String> {
        let Some(tls_config) = self.config.wss_tls.as_ref().map(|config| config.0.clone()) else {
            return Err("Cannot run WSS listener without a WSS rustls ServerConfig".to_string());
        };

        let context = self.server_context();
        self.prepare_to_run(&context).await?;

        let addr = listener
            .local_addr()
            .map_err(|e| format!("Failed to bind socket: {e:?}"))?;
        info!("Now listening for WSS connections on {addr}");

        self.info
            .port
            .store(addr.port(), std::sync::atomic::Ordering::Relaxed);

        self.log_endpoint_info();
        self.run_connection_loop(
            &context,
            ConnectionSource::<()>::Listener(listener),
            AcceptedTransport::Wss(tls_config),
        )
        .await
    }

    /// Run the server using externally accepted TCP streams and caller-owned
    /// per-connection tokens.
    ///
    /// The configured TCP endpoint is still used to create endpoint descriptions,
    /// so callers must set `host` and `port` to match the listener that accepted
    /// the streams. The server exits after the stream channel closes and active
    /// connections finish.
    ///
    /// The token is never inspected by the server. It is moved into the spawned
    /// connection task and dropped when that task exits; if the stream is
    /// rejected by `max_connections`, the token is dropped with the stream.
    pub async fn run_with_streams<T: Send + 'static>(
        mut self,
        rx: mpsc::Receiver<(TcpStream, SocketAddr, T)>,
    ) -> Result<(), String> {
        let context = self.server_context();
        self.prepare_to_run(&context).await?;

        let port = self.config.tcp_config.port;
        self.info
            .port
            .store(port, std::sync::atomic::Ordering::Relaxed);
        info!(
            "Now accepting handed-off TCP connections for {}",
            self.info.base_endpoint()
        );

        self.log_endpoint_info();
        self.run_connection_loop(
            &context,
            ConnectionSource::Streams(rx),
            AcceptedTransport::Tcp,
        )
        .await
    }

    /// Run the server. The provided `token` can be used to stop the server gracefully.
    pub async fn run(self) -> Result<(), String> {
        let addr = self.get_socket_address();

        let Some(addr) = addr else {
            error!("Cannot resolve server address, check server configuration");
            return Err("Cannot resolve server address, check server configuration".to_owned());
        };

        info!("Try to bind address at {addr}");
        let listener = match TcpListener::bind(&addr).await {
            Ok(listener) => listener,
            Err(e) => {
                error!("Failed to bind socket: {:?}", e);
                return Err(format!("Failed to bind socket: {e:?}"));
            }
        };

        self.run_with(listener).await
    }

    async fn run_subscription_ticks(_interval: u64, context: &ServerContext) -> Never {
        let context = context.clone();
        let cleanup_rx = context.subscriptions.take_cleanup_receiver();

        if let Some(rx) = cleanup_rx {
            let subscriptions = context.subscriptions.clone();
            subscriptions.run_cleanup(&context, rx).await;
        }

        futures::future::pending().await
    }

    async fn run_session_expiry(sessions: &RwLock<SessionManager>, notify: &Notify) -> Never {
        loop {
            let ((expiry, expired), notified) = {
                let session_lck = trace_read_lock!(sessions);
                // Make sure to create the notified future while we still hold the lock.
                (session_lck.check_session_expiry(), notify.notified())
            };
            if !expired.is_empty() {
                let mut session_lck = trace_write_lock!(sessions);
                for id in expired {
                    session_lck.expire_session(&id);
                }
            }
            tokio::select! {
                _ = tokio::time::sleep_until(expiry.into()) => {}
                _ = notified => {}
            }
        }
    }

    /// Log information about the endpoints on this server
    fn log_endpoint_info(&self) {
        info!("OPC UA Server: {}", self.info.application_name);
        info!("Base url: {}", self.info.base_endpoint());
        info!("Supported endpoints:");
        for (id, endpoint) in &self.config.endpoints {
            let users: Vec<String> = endpoint.user_token_ids.iter().cloned().collect();
            let users = users.join(", ");
            info!("Endpoint \"{}\": {}", id, endpoint.path);
            info!("  Security Mode:    {}", endpoint.security_mode);
            info!("  Security Policy:  {}", endpoint.security_policy);
            info!("  Supported user tokens - {}", users);
        }
    }

    /// Returns the server socket address.
    fn get_socket_address(&self) -> Option<SocketAddr> {
        // Resolve this host / port to an address (or not)
        let address = format!(
            "{}:{}",
            self.config.tcp_config.host, self.config.tcp_config.port
        );
        if let Ok(mut addrs_iter) = address.to_socket_addrs() {
            addrs_iter.next()
        } else {
            None
        }
    }
}
