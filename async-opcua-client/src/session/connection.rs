use std::{net::SocketAddr, str::FromStr, sync::Arc};

use opcua_core::{comms::url::is_opc_ua_binary_url, config::Config, sync::RwLock};
use opcua_crypto::{CertificateStore, SecurityPolicy};
use opcua_types::{
    ContextOwned, EndpointDescription, Error, MessageSecurityMode, NamespaceMap, NodeId,
    StatusCode, TypeLoader, UserTokenType,
};
use tokio::net::TcpListener;

use crate::{
    reverse_connect::TcpConnectorReceiver,
    transport::{
        tcp::TransportConfiguration, ConnectorBuilder, ReverseHelloVerifier, ReverseTcpConnector,
    },
    AsyncSecureChannel, ClientConfig, IdentityToken,
};

use super::{Client, EndpointInfo, Session, SessionEventLoop};

struct SessionBuilderInner {
    session_id: Option<NodeId>,
    user_identity_token: IdentityToken,
    type_loaders: Vec<Arc<dyn TypeLoader>>,
}

/// Trait for getting a connection builder for a given endpoint.
/// This is not the neatest interface, but it makes it possible to use a different
/// connection source in the session builder.
///
/// Essentially, ConnectionSource takes an endpoint, and returns a connector builder,
/// which is directly converted into a connector, which is then used to create a
/// transport.
///
/// In practice:
///
///  - A ConnectionSource uses an EndpointDescription to get a ConnectorBuilder.
///  - A ConnectorBuilder is directly converted into a Connector. This trait exists
///    so that methods that connect to an endpoint can take a type that implements ConnectorBuilder,
///    for example an endpoint description.
///  - A Connector is used to create a transport, which is then used to connect to the server.
pub trait ConnectionSource {
    /// The type of connector builder returned by this connection source.
    type Builder: ConnectorBuilder;

    /// Get a connector builder for the given endpoint description.
    fn get_connector(&self, endpoint: &EndpointDescription) -> Result<Self::Builder, Error>;
}

/// Connection source for a direct OPC/TCP binary connection.
/// This is the default connection source used by the session builder, and by far the most
/// common when connecting to an OPC-UA server.
pub struct DirectConnectionSource;

impl ConnectionSource for DirectConnectionSource {
    type Builder = String;
    fn get_connector(&self, endpoint: &EndpointDescription) -> Result<Self::Builder, Error> {
        Ok(endpoint.endpoint_url.as_ref().to_string())
    }
}

/// Connection source for a reverse connection.
/// When using this, the server will initiate the connection to the client.
pub struct ReverseConnectionSource {
    listener: TcpConnectorReceiver,
    verifier: Option<Arc<dyn ReverseHelloVerifier + Send + Sync>>,
}

impl ReverseConnectionSource {
    /// Create a new reverse connection source with a TCP listener.
    pub fn new_listener(listener: Arc<TcpListener>) -> Self {
        Self {
            listener: TcpConnectorReceiver::Listener(listener),
            verifier: None,
        }
    }

    /// Create a new reverse connection source listening on the given address.
    pub fn new_address(address: SocketAddr) -> Self {
        Self {
            listener: TcpConnectorReceiver::Address(address),
            verifier: None,
        }
    }

    /// Set a custom verifier for the reverse connection source.
    /// If not set, the default verifier will be used, which
    /// simply compares the endpoint URL with the configured endpoint URL.
    pub fn with_verifier(
        mut self,
        verifier: impl ReverseHelloVerifier + Send + Sync + 'static,
    ) -> Self {
        self.verifier = Some(Arc::new(verifier));
        self
    }
}

impl ConnectionSource for ReverseConnectionSource {
    type Builder = ReverseTcpConnector;

    fn get_connector(&self, endpoint: &EndpointDescription) -> Result<Self::Builder, Error> {
        if let Some(verifier) = self.verifier.clone() {
            Ok(ReverseTcpConnector::new(
                self.listener.clone(),
                verifier,
                endpoint.clone(),
            ))
        } else {
            Ok(ReverseTcpConnector::new_default(
                endpoint.clone(),
                self.listener.clone(),
            ))
        }
    }
}

/// Type-state builder for a session and session event loop.
/// To use, you will typically first call [SessionBuilder::with_endpoints] to set
/// a list of available endpoints, then one of the `connect_to` methods, then finally
/// [SessionBuilder::build].
pub struct SessionBuilder<'a, T = (), R = (), C = DirectConnectionSource> {
    endpoint: T,
    config: &'a ClientConfig,
    endpoints: R,
    inner: SessionBuilderInner,
    connection_source: C,
}

impl<'a> SessionBuilder<'a, (), (), DirectConnectionSource> {
    /// Create a new, empty session builder.
    pub fn new(config: &'a ClientConfig) -> Self {
        Self {
            endpoint: (),
            config,
            endpoints: (),
            inner: SessionBuilderInner {
                session_id: None,
                user_identity_token: IdentityToken::Anonymous,
                type_loaders: Vec::new(),
            },
            connection_source: DirectConnectionSource,
        }
    }
}

impl<'a, T, C> SessionBuilder<'a, T, (), C> {
    /// Set a list of available endpoints on the server.
    ///
    /// You'll typically get this from [Client::get_server_endpoints].
    pub fn with_endpoints(
        self,
        endpoints: Vec<EndpointDescription>,
    ) -> SessionBuilder<'a, T, Vec<EndpointDescription>, C> {
        SessionBuilder {
            inner: self.inner,
            endpoint: self.endpoint,
            config: self.config,
            endpoints,
            connection_source: self.connection_source,
        }
    }
}

impl<'a, T, R, C> SessionBuilder<'a, T, R, C> {
    /// Set the user identity token to use.
    pub fn user_identity_token(mut self, identity_token: IdentityToken) -> Self {
        self.inner.user_identity_token = identity_token;
        self
    }

    /// Set an initial session ID. The session will try to reactivate this session
    /// before creating a new session. This can be useful to persist session IDs
    /// between program executions, to avoid having to recreate subscriptions.
    pub fn session_id(mut self, session_id: NodeId) -> Self {
        self.inner.session_id = Some(session_id);
        self
    }

    /// Add an initial type loader to the session. You can add more of these later.
    /// Note that custom type loaders will likely not work until namespaces
    /// are fetched from the server.
    pub fn type_loader(mut self, type_loader: Arc<dyn TypeLoader>) -> Self {
        self.inner.type_loaders.push(type_loader);
        self
    }

    fn endpoint_supports_token(&self, endpoint: &EndpointDescription) -> bool {
        match &self.inner.user_identity_token {
            IdentityToken::Anonymous => {
                endpoint.user_identity_tokens.is_none()
                    || endpoint
                        .user_identity_tokens
                        .as_ref()
                        .is_some_and(|e| e.iter().any(|p| p.token_type == UserTokenType::Anonymous))
            }
            IdentityToken::UserName(_, _) => endpoint
                .user_identity_tokens
                .as_ref()
                .is_some_and(|e| e.iter().any(|p| p.token_type == UserTokenType::UserName)),
            IdentityToken::X509(_, _) => endpoint
                .user_identity_tokens
                .as_ref()
                .is_some_and(|e| e.iter().any(|p| p.token_type == UserTokenType::Certificate)),
            IdentityToken::IssuedToken(_) => endpoint
                .user_identity_tokens
                .as_ref()
                .is_some_and(|e| e.iter().any(|p| p.token_type == UserTokenType::IssuedToken)),
        }
    }

    /// Set the connection source to use. This is used to create the transport
    /// connector. Defaults to a direct TCP connection, implemented by `()`.
    pub fn with_connector<CS>(self, connection_source: CS) -> SessionBuilder<'a, T, R, CS>
    where
        CS: ConnectionSource,
    {
        SessionBuilder {
            inner: self.inner,
            endpoint: self.endpoint,
            config: self.config,
            endpoints: self.endpoints,
            connection_source,
        }
    }
}

impl<'a, C> SessionBuilder<'a, (), Vec<EndpointDescription>, C> {
    /// Connect to an endpoint matching the given endpoint description.
    pub fn connect_to_matching_endpoint(
        self,
        endpoint: impl Into<EndpointDescription>,
    ) -> Result<SessionBuilder<'a, EndpointDescription, Vec<EndpointDescription>, C>, Error> {
        let endpoint = endpoint.into();

        let security_policy = SecurityPolicy::from_str(endpoint.security_policy_uri.as_ref())
            .map_err(|_| {
                Error::new(
                    StatusCode::BadSecurityPolicyRejected,
                    format!(
                        "Invalid security policy: {}",
                        endpoint.security_policy_uri.as_ref()
                    ),
                )
            })?;
        let server_endpoint = Client::find_matching_endpoint(
            &self.endpoints,
            endpoint.endpoint_url.as_ref(),
            security_policy,
            endpoint.security_mode,
        )
        .ok_or(Error::new(
            StatusCode::BadTcpEndpointUrlInvalid,
            format!(
                "Cannot find matching endpoint for {}",
                endpoint.endpoint_url.as_ref()
            ),
        ))?;

        Ok(SessionBuilder {
            inner: self.inner,
            endpoint: server_endpoint,
            config: self.config,
            endpoints: self.endpoints,
            connection_source: self.connection_source,
        })
    }

    /// Connect to the configured default endpoint, this will use the user identity token configured in the
    /// default endpoint.
    pub fn connect_to_default_endpoint(
        mut self,
    ) -> Result<SessionBuilder<'a, EndpointDescription, Vec<EndpointDescription>, C>, Error> {
        let default_endpoint_id = self.config.default_endpoint.clone();
        let endpoint = if default_endpoint_id.is_empty() {
            return Err(Error::new(
                StatusCode::BadConfigurationError,
                "No default endpoint has been specified",
            ));
        } else if let Some(endpoint) = self.config.endpoints.get(&default_endpoint_id) {
            endpoint.clone()
        } else {
            return Err(Error::new(
                StatusCode::BadInvalidArgument,
                format!("Cannot find default endpoint with id {default_endpoint_id}"),
            ));
        };
        let user_identity_token = self.config.client_identity_token(&endpoint.user_token_id)?;
        let endpoint = self
            .config
            .endpoint_description_for_client_endpoint(&endpoint, &self.endpoints)?;
        self.inner.user_identity_token = user_identity_token;
        Ok(SessionBuilder {
            inner: self.inner,
            endpoint,
            config: self.config,
            endpoints: self.endpoints,
            connection_source: self.connection_source,
        })
    }

    /// Connect to the configured endpoint with the given id, this will use the user identity token configured in the
    /// configured endpoint.
    pub fn connect_to_endpoint_id(
        mut self,
        endpoint_id: impl Into<String>,
    ) -> Result<SessionBuilder<'a, EndpointDescription, Vec<EndpointDescription>, C>, Error> {
        let endpoint_id = endpoint_id.into();
        let endpoint = self.config.endpoints.get(&endpoint_id).ok_or_else(|| {
            Error::new(
                StatusCode::BadInvalidArgument,
                format!("Cannot find endpoint with id {endpoint_id}"),
            )
        })?;
        let user_identity_token = self.config.client_identity_token(&endpoint.user_token_id)?;

        let endpoint = self
            .config
            .endpoint_description_for_client_endpoint(endpoint, &self.endpoints)?;
        self.inner.user_identity_token = user_identity_token;
        Ok(SessionBuilder {
            inner: self.inner,
            endpoint,
            config: self.config,
            endpoints: self.endpoints,
            connection_source: self.connection_source,
        })
    }

    /// Attempt to pick the "best" endpoint. If `secure` is `false` this means
    /// any unencrypted endpoint that supports the configured identity token.
    /// If `secure` is `true`, the endpoint that supports the configured identity token with the highest
    /// `securityLevel`.
    pub fn connect_to_best_endpoint(
        self,
        secure: bool,
    ) -> Result<SessionBuilder<'a, EndpointDescription, Vec<EndpointDescription>, C>, Error> {
        let endpoint = if secure {
            self.endpoints
                .iter()
                .filter(|e| self.endpoint_supports_token(e))
                .max_by(|a, b| a.security_level.cmp(&b.security_level))
        } else {
            self.endpoints.iter().find(|e| {
                e.security_mode == MessageSecurityMode::None && self.endpoint_supports_token(e)
            })
        };
        let Some(endpoint) = endpoint else {
            return Err(Error::new(
                StatusCode::BadInvalidArgument,
                "No suitable endpoint found",
            ));
        };
        Ok(SessionBuilder {
            inner: self.inner,
            endpoint: endpoint.clone(),
            config: self.config,
            endpoints: self.endpoints,
            connection_source: self.connection_source,
        })
    }
}

impl<'a, R, C> SessionBuilder<'a, (), R, C> {
    /// Connect directly to an endpoint description, this does not require you to list
    /// endpoints on the server first.
    pub fn connect_to_endpoint_directly(
        self,
        endpoint: impl Into<EndpointDescription>,
    ) -> Result<SessionBuilder<'a, EndpointDescription, R, C>, Error> {
        let endpoint = endpoint.into();
        if !is_opc_ua_binary_url(endpoint.endpoint_url.as_ref()) {
            return Err(Error::new(
                StatusCode::BadTcpEndpointUrlInvalid,
                format!(
                    "Endpoint url {} is not a valid / supported url",
                    endpoint.endpoint_url
                ),
            ));
        }
        Ok(SessionBuilder {
            endpoint,
            config: self.config,
            endpoints: self.endpoints,
            inner: self.inner,
            connection_source: self.connection_source,
        })
    }
}

type ResultEventLoop<C> =
    SessionEventLoop<<<C as ConnectionSource>::Builder as ConnectorBuilder>::ConnectorType>;

impl<R, C> SessionBuilder<'_, EndpointDescription, R, C>
where
    C: ConnectionSource,
{
    /// Build the session and session event loop. Note that you will need to
    /// start polling the event loop before a connection is actually established.
    pub fn build(
        self,
        certificate_store: Arc<RwLock<CertificateStore>>,
    ) -> Result<(Arc<Session>, ResultEventLoop<C>), Error> {
        let connector = self
            .connection_source
            .get_connector(&self.endpoint)?
            .build()?;
        let ctx = self.make_encoding_context();
        Ok(Session::new(
            Self::build_channel_inner(
                certificate_store,
                self.inner.user_identity_token,
                self.endpoint,
                self.config,
                ctx,
            ),
            self.config.session_name.clone().into(),
            self.config.application_description(),
            self.config.session_retry_policy(),
            self.config.decoding_options.as_comms_decoding_options(),
            self.config,
            self.inner.session_id,
            connector,
        ))
    }

    fn make_encoding_context(&self) -> ContextOwned {
        let mut encoding_context = ContextOwned::new_default(
            NamespaceMap::new(),
            self.config.decoding_options.as_comms_decoding_options(),
        );

        for loader in self.inner.type_loaders.iter().cloned() {
            encoding_context.loaders_mut().add(loader);
        }

        encoding_context
    }

    fn build_channel_inner(
        certificate_store: Arc<RwLock<CertificateStore>>,
        identity_token: IdentityToken,
        endpoint: EndpointDescription,
        config: &ClientConfig,
        ctx: ContextOwned,
    ) -> AsyncSecureChannel {
        AsyncSecureChannel::new(
            certificate_store,
            EndpointInfo {
                endpoint,
                user_identity_token: identity_token,
                preferred_locales: config.preferred_locales.clone(),
            },
            config.session_retry_policy(),
            config.performance.ignore_clock_skew,
            Arc::default(),
            TransportConfiguration {
                send_buffer_size: config.decoding_options.max_chunk_size,
                recv_buffer_size: config.decoding_options.max_incoming_chunk_size,
                max_message_size: config.decoding_options.max_message_size,
                max_chunk_count: config.decoding_options.max_chunk_count,
            },
            config.channel_lifetime,
            Arc::new(RwLock::new(ctx)),
        )
    }

    /// Build a channel only, not creating a session.
    /// This is useful if you want to manage the session lifetime yourself.
    pub fn build_channel(
        self,
        certificate_store: Arc<RwLock<CertificateStore>>,
    ) -> Result<AsyncSecureChannel, Error> {
        let ctx = self.make_encoding_context();
        Ok(Self::build_channel_inner(
            certificate_store,
            self.inner.user_identity_token,
            self.endpoint,
            self.config,
            ctx,
        ))
    }
}
