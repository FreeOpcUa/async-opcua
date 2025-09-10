use std::{str::FromStr, sync::Arc};

use opcua_core::{comms::url::is_opc_ua_binary_url, config::Config, sync::RwLock};
use opcua_crypto::{CertificateStore, SecurityPolicy};
use opcua_types::{
    ContextOwned, EndpointDescription, MessageSecurityMode, NamespaceMap, NodeId, StatusCode,
    TypeLoader, UserTokenType,
};
use tracing::error;

use crate::{
    transport::{
        tcp::{TcpConnector, TransportConfiguration},
        Connector,
    },
    AsyncSecureChannel, ClientConfig, IdentityToken,
};

use super::{Client, EndpointInfo, Session, SessionEventLoop};

struct SessionBuilderInner {
    session_id: Option<NodeId>,
    user_identity_token: IdentityToken,
    connector: Box<dyn Connector>,
    type_loaders: Vec<Arc<dyn TypeLoader>>,
}

/// Type-state builder for a session and session event loop.
/// To use, you will typically first call [SessionBuilder::with_endpoints] to set
/// a list of available endpoints, then one of the `connect_to` methods, then finally
/// [SessionBuilder::build].
pub struct SessionBuilder<'a, T = (), R = ()> {
    endpoint: T,
    config: &'a ClientConfig,
    endpoints: R,
    inner: SessionBuilderInner,
}

impl<'a> SessionBuilder<'a, (), ()> {
    /// Create a new, empty session builder.
    pub fn new(config: &'a ClientConfig) -> Self {
        Self {
            endpoint: (),
            config,
            endpoints: (),
            inner: SessionBuilderInner {
                session_id: None,
                user_identity_token: IdentityToken::Anonymous,
                connector: Box::new(TcpConnector),
                type_loaders: Vec::new(),
            },
        }
    }
}

impl<'a, T> SessionBuilder<'a, T, ()> {
    /// Set a list of available endpoints on the server.
    ///
    /// You'll typically get this from [Client::get_server_endpoints].
    pub fn with_endpoints(
        self,
        endpoints: Vec<EndpointDescription>,
    ) -> SessionBuilder<'a, T, Vec<EndpointDescription>> {
        SessionBuilder {
            inner: self.inner,
            endpoint: self.endpoint,
            config: self.config,
            endpoints,
        }
    }
}

impl<T, R> SessionBuilder<'_, T, R> {
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
}

impl<'a> SessionBuilder<'a, (), Vec<EndpointDescription>> {
    /// Connect to an endpoint matching the given endpoint description.
    pub fn connect_to_matching_endpoint(
        self,
        endpoint: impl Into<EndpointDescription>,
    ) -> Result<SessionBuilder<'a, EndpointDescription, Vec<EndpointDescription>>, StatusCode> {
        let endpoint = endpoint.into();

        let security_policy = SecurityPolicy::from_str(endpoint.security_policy_uri.as_ref())
            .map_err(|_| StatusCode::BadSecurityPolicyRejected)?;
        let server_endpoint = Client::find_matching_endpoint(
            &self.endpoints,
            endpoint.endpoint_url.as_ref(),
            security_policy,
            endpoint.security_mode,
        )
        .ok_or(StatusCode::BadTcpEndpointUrlInvalid)
        .inspect_err(|_| {
            error!(
                "Cannot find matching endpoint for {}",
                endpoint.endpoint_url.as_ref()
            );
        })?;

        Ok(SessionBuilder {
            inner: self.inner,
            endpoint: server_endpoint,
            config: self.config,
            endpoints: self.endpoints,
        })
    }

    /// Connect to the configured default endpoint, this will use the user identity token configured in the
    /// default endpoint.
    pub fn connect_to_default_endpoint(
        mut self,
    ) -> Result<SessionBuilder<'a, EndpointDescription, Vec<EndpointDescription>>, String> {
        let default_endpoint_id = self.config.default_endpoint.clone();
        let endpoint = if default_endpoint_id.is_empty() {
            return Err("No default endpoint has been specified".to_string());
        } else if let Some(endpoint) = self.config.endpoints.get(&default_endpoint_id) {
            endpoint.clone()
        } else {
            return Err(format!(
                "Cannot find default endpoint with id {default_endpoint_id}"
            ));
        };
        let user_identity_token = self
            .config
            .client_identity_token(&endpoint.user_token_id)
            .map_err(|e| e.to_string())?;
        let endpoint = self
            .config
            .endpoint_description_for_client_endpoint(&endpoint, &self.endpoints)?;
        self.inner.user_identity_token = user_identity_token;
        Ok(SessionBuilder {
            inner: self.inner,
            endpoint,
            config: self.config,
            endpoints: self.endpoints,
        })
    }

    /// Connect to the configured endpoint with the given id, this will use the user identity token configured in the
    /// configured endpoint.
    pub fn connect_to_endpoint_id(
        mut self,
        endpoint_id: impl Into<String>,
    ) -> Result<SessionBuilder<'a, EndpointDescription, Vec<EndpointDescription>>, String> {
        let endpoint_id = endpoint_id.into();
        let endpoint = self
            .config
            .endpoints
            .get(&endpoint_id)
            .ok_or_else(|| format!("Cannot find endpoint with id {endpoint_id}"))?;
        let user_identity_token = self
            .config
            .client_identity_token(&endpoint.user_token_id)
            .map_err(|e| e.to_string())?;

        let endpoint = self
            .config
            .endpoint_description_for_client_endpoint(endpoint, &self.endpoints)?;
        self.inner.user_identity_token = user_identity_token;
        Ok(SessionBuilder {
            inner: self.inner,
            endpoint,
            config: self.config,
            endpoints: self.endpoints,
        })
    }

    /// Attempt to pick the "best" endpoint. If `secure` is `false` this means
    /// any unencrypted endpoint that supports the configured identity token.
    /// If `secure` is `true`, the endpoint that supports the configured identity token with the highest
    /// `securityLevel`.
    pub fn connect_to_best_endpoint(
        self,
        secure: bool,
    ) -> Result<SessionBuilder<'a, EndpointDescription, Vec<EndpointDescription>>, String> {
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
            return Err("No suitable endpoint found".to_owned());
        };
        Ok(SessionBuilder {
            inner: self.inner,
            endpoint: endpoint.clone(),
            config: self.config,
            endpoints: self.endpoints,
        })
    }
}

impl<'a, R> SessionBuilder<'a, (), R> {
    /// Connect directly to an endpoint description, this does not require you to list
    /// endpoints on the server first.
    pub fn connect_to_endpoint_directly(
        self,
        endpoint: impl Into<EndpointDescription>,
    ) -> Result<SessionBuilder<'a, EndpointDescription, R>, String> {
        let endpoint = endpoint.into();
        if !is_opc_ua_binary_url(endpoint.endpoint_url.as_ref()) {
            return Err(format!(
                "Endpoint url {} is not a valid / supported url",
                endpoint.endpoint_url
            ));
        }
        Ok(SessionBuilder {
            endpoint,
            config: self.config,
            endpoints: self.endpoints,
            inner: self.inner,
        })
    }
}

impl<R> SessionBuilder<'_, EndpointDescription, R> {
    /// Build the session and session event loop. Note that you will need to
    /// start polling the event loop before a connection is actually established.
    pub fn build(
        self,
        certificate_store: Arc<RwLock<CertificateStore>>,
    ) -> (Arc<Session>, SessionEventLoop) {
        let ctx = self.make_encoding_context();
        Session::new(
            Self::build_channel_inner(
                certificate_store,
                self.inner.user_identity_token,
                self.endpoint,
                self.config,
                self.inner.connector,
                ctx,
            ),
            self.config.session_name.clone().into(),
            self.config.application_description(),
            self.config.session_retry_policy(),
            self.config.decoding_options.as_comms_decoding_options(),
            self.config,
            self.inner.session_id,
        )
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
        connector: Box<dyn Connector>,
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
            connector,
            config.channel_lifetime,
            Arc::new(RwLock::new(ctx)),
        )
    }

    /// Build a channel only, not creating a session.
    /// This is useful if you want to manage the session lifetime yourself.
    pub fn build_channel(
        self,
        certificate_store: Arc<RwLock<CertificateStore>>,
    ) -> AsyncSecureChannel {
        let ctx = self.make_encoding_context();
        Self::build_channel_inner(
            certificate_store,
            self.inner.user_identity_token,
            self.endpoint,
            self.config,
            self.inner.connector,
            ctx,
        )
    }
}
