use std::{str::FromStr, sync::Arc};

use chrono::Duration;
use tokio::{pin, select};
use tracing::error;

use crate::{
    transport::{
        tcp::TransportConfiguration, Connector, ConnectorBuilder, TcpConnector, TransportPollResult,
    },
    AsyncSecureChannel, ClientConfig, ClientEndpoint, IdentityToken,
};
use opcua_core::{
    comms::url::{
        hostname_from_url, server_url_from_endpoint_url, url_matches_except_host,
        url_with_replaced_hostname,
    },
    config::Config,
    sync::RwLock,
    ResponseMessage,
};
use opcua_crypto::{CertificateStore, SecurityPolicy};
use opcua_types::{
    ApplicationDescription, ContextOwned, DecodingOptions, EndpointDescription, Error,
    FindServersOnNetworkRequest, FindServersOnNetworkResponse, FindServersRequest,
    GetEndpointsRequest, MessageSecurityMode, NamespaceMap, RegisterServerRequest,
    RegisteredServer, StatusCode, UAString,
};

use super::{
    connection::SessionBuilder, process_service_result, process_unexpected_response, EndpointInfo,
    Session, SessionEventLoop,
};

/// Wrapper around common data for generating sessions and performing requests
/// with one-shot connections.
pub struct Client {
    /// Client configuration
    pub(super) config: ClientConfig,
    /// Certificate store is where certificates go.
    certificate_store: Arc<RwLock<CertificateStore>>,
}

impl Client {
    /// Create a new client from config.
    ///
    /// Note that this does not make any connection to the server.
    ///
    /// # Arguments
    ///
    /// * `config` - Client configuration object.
    pub fn new(config: ClientConfig) -> Self {
        let application_description = if config.create_sample_keypair {
            Some(config.application_description())
        } else {
            None
        };

        let (mut certificate_store, client_certificate, client_pkey) =
            CertificateStore::new_with_x509_data(
                &config.pki_dir,
                false,
                config.certificate_path.as_deref(),
                config.private_key_path.as_deref(),
                application_description,
            );
        if client_certificate.is_none() || client_pkey.is_none() {
            error!("Client is missing its application instance certificate and/or its private key. Encrypted endpoints will not function correctly.")
        }

        // Clients may choose to skip additional server certificate validations
        certificate_store.set_skip_verify_certs(!config.verify_server_certs);

        // Clients may choose to auto trust servers to save some messing around with rejected certs
        certificate_store.set_trust_unknown_certs(config.trust_server_certs);

        // The session retry policy dictates how many times to retry if connection to the server goes down
        // and on what interval

        Self {
            config,
            certificate_store: Arc::new(RwLock::new(certificate_store)),
        }
    }

    /// Get a new session builder that can be used to build a session dynamically.
    pub fn session_builder(&self) -> SessionBuilder<'_> {
        SessionBuilder::<'_>::new(&self.config)
    }

    /// Connects to a named endpoint that you have defined in the `ClientConfig`
    /// and creates a [`Session`] for that endpoint. Note that `GetEndpoints` is first
    /// called on the server and it is expected to support the endpoint you intend to connect to.
    ///
    /// # Returns
    ///
    /// * `Ok((Arc<Session>, SessionEventLoop))` - Session and event loop.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn connect_to_endpoint_id(
        &mut self,
        endpoint_id: impl Into<String>,
    ) -> Result<(Arc<Session>, SessionEventLoop<TcpConnector>), Error> {
        self.session_builder()
            .with_endpoints(self.get_server_endpoints().await?)
            .connect_to_endpoint_id(endpoint_id)?
            .build(self.certificate_store.clone())
    }

    /// Connects to an ad-hoc server endpoint description.
    ///
    /// This function returns both a reference to the session, and a `SessionEventLoop`. You must run and
    /// poll the event loop in order to actually establish a connection.
    ///
    /// This method will not attempt to create a session on the server, that will only happen once you start polling
    /// the session event loop.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - Discovery endpoint, the client will first connect to this in order to get a list of the
    ///   available endpoints on the server.
    /// * `user_identity_token` - Identity token to use for authentication.
    ///
    /// # Returns
    ///
    /// * `Ok((Arc<Session>, SessionEventLoop))` - Session and event loop.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn connect_to_matching_endpoint(
        &mut self,
        endpoint: impl Into<EndpointDescription>,
        user_identity_token: IdentityToken,
    ) -> Result<(Arc<Session>, SessionEventLoop<TcpConnector>), Error> {
        let endpoint = endpoint.into();

        // Get the server endpoints
        let server_url = endpoint.endpoint_url.as_ref();

        self.session_builder()
            .with_endpoints(self.get_server_endpoints_from_url(server_url).await?)
            .connect_to_matching_endpoint(endpoint)?
            .user_identity_token(user_identity_token)
            .build(self.certificate_store.clone())
    }

    /// Connects to a server directly using provided [`EndpointDescription`].
    ///
    /// This function returns both a reference to the session, and a `SessionEventLoop`. You must run and
    /// poll the event loop in order to actually establish a connection.
    ///
    /// This method will not attempt to create a session on the server, that will only happen once you start polling
    /// the session event loop.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - Endpoint to connect to.
    /// * `identity_token` - Identity token for authentication.
    ///
    /// # Returns
    ///
    /// * `Ok((Arc<Session>, SessionEventLoop))` - Session and event loop.
    /// * `Err(Error)` - Endpoint is invalid.
    ///
    pub fn connect_to_endpoint_directly(
        &mut self,
        endpoint: impl Into<EndpointDescription>,
        identity_token: IdentityToken,
    ) -> Result<(Arc<Session>, SessionEventLoop<TcpConnector>), Error> {
        self.session_builder()
            .connect_to_endpoint_directly(endpoint)?
            .user_identity_token(identity_token)
            .build(self.certificate_store.clone())
    }

    /// Creates a new [`Session`] using the default endpoint specified in the config. If
    /// there is no default, or the endpoint does not exist, this function will return an error
    ///
    /// This function returns both a reference to the session, and a `SessionEventLoop`. You must run and
    /// poll the event loop in order to actually establish a connection.
    ///
    /// This method will not attempt to create a session on the server, that will only happen once you start polling
    /// the session event loop.
    ///
    /// # Arguments
    ///
    /// * `endpoints` - A list of [`EndpointDescription`] containing the endpoints available on the server.
    ///
    /// # Returns
    ///
    /// * `Ok((Arc<Session>, SessionEventLoop))` - Session and event loop.
    /// * `Err(String)` - Endpoint is invalid.
    ///
    pub async fn connect_to_default_endpoint(
        &mut self,
    ) -> Result<(Arc<Session>, SessionEventLoop<TcpConnector>), Error> {
        self.session_builder()
            .with_endpoints(self.get_server_endpoints().await?)
            .connect_to_default_endpoint()?
            .build(self.certificate_store.clone())
    }

    /// Create a secure channel using the provided [`SessionInfo`].
    ///
    /// This is used when creating temporary connections to the server, when creating a session,
    /// [`Session`] manages its own channel.
    fn channel_from_endpoint_info(
        &self,
        endpoint_info: EndpointInfo,
        channel_lifetime: u32,
    ) -> AsyncSecureChannel {
        AsyncSecureChannel::new(
            self.certificate_store.clone(),
            endpoint_info,
            self.config.session_retry_policy(),
            self.config.performance.ignore_clock_skew,
            Arc::default(),
            TransportConfiguration {
                send_buffer_size: self.config.decoding_options.max_chunk_size,
                recv_buffer_size: self.config.decoding_options.max_incoming_chunk_size,
                max_message_size: self.config.decoding_options.max_message_size,
                max_chunk_count: self.config.decoding_options.max_chunk_count,
            },
            channel_lifetime,
            // We should only ever need the default decoding context for temporary connections.
            Arc::new(RwLock::new(ContextOwned::new_default(
                NamespaceMap::new(),
                self.decoding_options(),
            ))),
        )
    }

    /// Gets the [`ClientEndpoint`] information for the default endpoint, as defined
    /// by the configuration. If there is no default endpoint, this function will return an error.
    ///
    /// # Returns
    ///
    /// * `Ok(ClientEndpoint)` - The default endpoint set in config.
    /// * `Err(String)` - No default endpoint could be found.
    pub fn default_endpoint(&self) -> Result<ClientEndpoint, String> {
        let default_endpoint_id = self.config.default_endpoint.clone();
        if default_endpoint_id.is_empty() {
            Err("No default endpoint has been specified".to_string())
        } else if let Some(endpoint) = self.config.endpoints.get(&default_endpoint_id) {
            Ok(endpoint.clone())
        } else {
            Err(format!(
                "Cannot find default endpoint with id {default_endpoint_id}"
            ))
        }
    }

    /// Get the list of endpoints for the server at the configured default endpoint.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<EndpointDescription>)` - A list of the available endpoints on the server.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    pub async fn get_server_endpoints(&self) -> Result<Vec<EndpointDescription>, Error> {
        let default_endpoint = self
            .default_endpoint()
            .map_err(|e| Error::new(StatusCode::BadConfigurationError, e))?;
        if let Ok(server_url) = server_url_from_endpoint_url(&default_endpoint.url) {
            self.get_server_endpoints_from_url(server_url).await
        } else {
            error!(
                "Cannot create a server url from the specified endpoint url {}",
                default_endpoint.url
            );
            Err(Error::new(
                StatusCode::BadUnexpectedError,
                format!(
                    "Cannot create a server url from the specified endpoint url {}",
                    default_endpoint.url
                ),
            ))
        }
    }

    fn decoding_options(&self) -> DecodingOptions {
        let decoding_options = &self.config.decoding_options;
        DecodingOptions {
            max_chunk_count: decoding_options.max_chunk_count,
            max_message_size: decoding_options.max_message_size,
            max_string_length: decoding_options.max_string_length,
            max_byte_string_length: decoding_options.max_byte_string_length,
            max_array_length: decoding_options.max_array_length,
            client_offset: Duration::zero(),
            ..Default::default()
        }
    }

    async fn get_server_endpoints_inner(
        &self,
        endpoint: &EndpointDescription,
        channel: &AsyncSecureChannel,
        locale_ids: Option<Vec<UAString>>,
        profile_uris: Option<Vec<UAString>>,
    ) -> Result<Vec<EndpointDescription>, StatusCode> {
        let request = GetEndpointsRequest {
            request_header: channel.make_request_header(self.config.request_timeout),
            endpoint_url: endpoint.endpoint_url.clone(),
            locale_ids,
            profile_uris,
        };
        // Send the message and wait for a response.
        let response = channel.send(request, self.config.request_timeout).await?;
        if let ResponseMessage::GetEndpoints(response) = response {
            process_service_result(&response.response_header)?;
            match response.endpoints {
                None => Ok(Vec::new()),
                Some(endpoints) => Ok(endpoints),
            }
        } else {
            Err(process_unexpected_response(response))
        }
    }

    /// Get the list of endpoints for the server at the given URL.
    ///
    /// # Arguments
    ///
    /// * `server` - Connector to an OPC-UA server. This is implemented for `String` and `&str`, which will
    ///   do a direct connection.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<EndpointDescription>)` - A list of the available endpoints on the server.
    /// * `Err(Error)` - Request failed, [Status code](StatusCode) is the reason for failure.
    pub async fn get_server_endpoints_from_url(
        &self,
        server: impl ConnectorBuilder,
    ) -> Result<Vec<EndpointDescription>, Error> {
        self.get_endpoints(server, &[], &[]).await
    }

    /// Get the list of endpoints for the server at the given URL.
    ///
    /// # Arguments
    ///
    /// * `server` - Connector to an OPC-UA server. This is implemented for `String` and `&str`, which will
    ///   do a direct connection.
    /// * `locale_ids` - List of required locale IDs on the given server endpoint.
    /// * `profile_uris` - Returned endpoints should match one of these profile URIs.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<EndpointDescription>)` - A list of the available endpoints on the server.
    /// * `Err(Error)` - Request failed, [Status code](StatusCode) is the reason for failure.
    pub async fn get_endpoints(
        &self,
        server: impl ConnectorBuilder,
        locale_ids: &[&str],
        profile_uris: &[&str],
    ) -> Result<Vec<EndpointDescription>, Error> {
        let server = server.build()?;
        let preferred_locales = Vec::new();
        // Most of these fields mean nothing when getting endpoints
        let endpoint = server.default_endpoint();
        let endpoint_info = EndpointInfo {
            endpoint: endpoint.clone(),
            user_identity_token: IdentityToken::Anonymous,
            preferred_locales,
        };
        let channel = self.channel_from_endpoint_info(endpoint_info, self.config.channel_lifetime);

        let mut evt_loop = channel
            .connect(&server)
            .await
            .map_err(|e| Error::new(e, "Failed to connect to server"))?;

        let send_fut = self.get_server_endpoints_inner(
            &endpoint,
            &channel,
            if locale_ids.is_empty() {
                None
            } else {
                Some(locale_ids.iter().map(|i| (*i).into()).collect())
            },
            if profile_uris.is_empty() {
                None
            } else {
                Some(profile_uris.iter().map(|i| (*i).into()).collect())
            },
        );
        pin!(send_fut);

        let res = loop {
            select! {
                r = evt_loop.poll() => {
                    if let TransportPollResult::Closed(e) = r {
                        return Err(Error::new(e, "Transport closed unexpectedly"));
                    }
                },
                res = &mut send_fut => break res.map_err(|e| Error::new(e, "Failed to get endpoints")),
            }
        };

        channel.close_channel().await;

        loop {
            if matches!(evt_loop.poll().await, TransportPollResult::Closed(_)) {
                break;
            }
        }

        res
    }

    async fn find_servers_inner(
        &self,
        endpoint_url: String,
        channel: &AsyncSecureChannel,
        locale_ids: Option<Vec<UAString>>,
        server_uris: Option<Vec<UAString>>,
    ) -> Result<Vec<ApplicationDescription>, StatusCode> {
        let request = FindServersRequest {
            request_header: channel.make_request_header(self.config.request_timeout),
            endpoint_url: endpoint_url.into(),
            locale_ids,
            server_uris,
        };

        let response = channel.send(request, self.config.request_timeout).await?;
        if let ResponseMessage::FindServers(response) = response {
            process_service_result(&response.response_header)?;
            Ok(response.servers.unwrap_or_default())
        } else {
            Err(process_unexpected_response(response))
        }
    }

    /// Connects to a discovery server and asks the server for a list of
    /// available servers' [`ApplicationDescription`].
    ///
    /// # Arguments
    ///
    /// * `discovery_endpoint_url` - Discovery endpoint to connect to.
    /// * `locale_ids` - List of locales to use.
    /// * `server_uris` - List of servers to return. If empty, all known servers are returned.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<ApplicationDescription>)` - List of descriptions for servers known to the discovery server.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    pub async fn find_servers(
        &self,
        discovery_endpoint: impl ConnectorBuilder,
        locale_ids: Option<Vec<UAString>>,
        server_uris: Option<Vec<UAString>>,
    ) -> Result<Vec<ApplicationDescription>, StatusCode> {
        let discovery_endpoint = discovery_endpoint.build()?;
        let endpoint = discovery_endpoint.default_endpoint();
        let session_info = EndpointInfo {
            endpoint: endpoint.clone(),
            user_identity_token: IdentityToken::Anonymous,
            preferred_locales: Vec::new(),
        };
        let channel = self.channel_from_endpoint_info(session_info, self.config.channel_lifetime);

        let mut evt_loop = channel.connect(&discovery_endpoint).await?;

        let send_fut = self.find_servers_inner(
            evt_loop.connected_url().to_owned(),
            &channel,
            locale_ids,
            server_uris,
        );
        pin!(send_fut);

        let res = loop {
            select! {
                r = evt_loop.poll() => {
                    if let TransportPollResult::Closed(e) = r {
                        return Err(e);
                    }
                },
                res = &mut send_fut => break res
            }
        };

        channel.close_channel().await;

        loop {
            if matches!(evt_loop.poll().await, TransportPollResult::Closed(_)) {
                break;
            }
        }

        res
    }

    async fn find_servers_on_network_inner(
        &self,
        starting_record_id: u32,
        max_records_to_return: u32,
        server_capability_filter: Option<Vec<UAString>>,
        channel: &AsyncSecureChannel,
    ) -> Result<FindServersOnNetworkResponse, StatusCode> {
        let request = FindServersOnNetworkRequest {
            request_header: channel.make_request_header(self.config.request_timeout),
            starting_record_id,
            max_records_to_return,
            server_capability_filter,
        };

        let response = channel.send(request, self.config.request_timeout).await?;
        if let ResponseMessage::FindServersOnNetwork(response) = response {
            process_service_result(&response.response_header)?;
            Ok(*response)
        } else {
            Err(process_unexpected_response(response))
        }
    }

    /// Connects to a discovery server and asks for a list of available servers on the network.
    ///
    /// See OPC UA Part 4 - Services 5.5.3 for a complete description of the service.
    ///
    /// # Arguments
    ///
    /// * `discovery_endpoint_url` - Endpoint to connect to.
    /// * `starting_record_id` - Only records with an identifier greater than this number
    ///   will be returned.
    /// * `max_records_to_return` - The maximum number of records to return in the response.
    ///   0 indicates that there is no limit.
    /// * `server_capability_filter` - List of server capability filters. Only records with
    ///   all the specified server capabilities are returned.
    ///
    /// # Returns
    ///
    /// * `Ok(FindServersOnNetworkResponse)` - Full service response object.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    pub async fn find_servers_on_network(
        &self,
        discovery_endpoint: impl ConnectorBuilder,
        starting_record_id: u32,
        max_records_to_return: u32,
        server_capability_filter: Option<Vec<UAString>>,
    ) -> Result<FindServersOnNetworkResponse, StatusCode> {
        let discovery_endpoint = discovery_endpoint.build()?;
        let endpoint = discovery_endpoint.default_endpoint();
        let session_info = EndpointInfo {
            endpoint: endpoint.clone(),
            user_identity_token: IdentityToken::Anonymous,
            preferred_locales: Vec::new(),
        };
        let channel = self.channel_from_endpoint_info(session_info, self.config.channel_lifetime);

        let mut evt_loop = channel.connect(&discovery_endpoint).await?;

        let send_fut = self.find_servers_on_network_inner(
            starting_record_id,
            max_records_to_return,
            server_capability_filter,
            &channel,
        );
        pin!(send_fut);

        let res = loop {
            select! {
                r = evt_loop.poll() => {
                    if let TransportPollResult::Closed(e) = r {
                        return Err(e);
                    }
                },
                res = &mut send_fut => break res
            }
        };

        channel.close_channel().await;

        loop {
            if matches!(evt_loop.poll().await, TransportPollResult::Closed(_)) {
                break;
            }
        }

        res
    }

    /// Find an endpoint supplied from the list of endpoints that matches the input criteria.
    ///
    /// # Arguments
    ///
    /// * `endpoints` - List of available endpoints on the server.
    /// * `endpoint_url` - Given endpoint URL.
    /// * `security_policy` - Required security policy.
    /// * `security_mode` - Required security mode.
    ///
    /// # Returns
    ///
    /// * `Some(EndpointDescription)` - Validated endpoint.
    /// * `None` - No matching endpoint was found.
    pub fn find_matching_endpoint(
        endpoints: &[EndpointDescription],
        endpoint_url: &str,
        security_policy: SecurityPolicy,
        security_mode: MessageSecurityMode,
    ) -> Option<EndpointDescription> {
        if security_policy == SecurityPolicy::Unknown {
            panic!("Cannot match against unknown security policy");
        }

        let mut matching_endpoint = endpoints
            .iter()
            .find(|e| {
                // Endpoint matches if the security mode, policy and url match
                security_mode == e.security_mode
                    && security_policy == SecurityPolicy::from_uri(e.security_policy_uri.as_ref())
                    && url_matches_except_host(endpoint_url, e.endpoint_url.as_ref())
            })
            .cloned()?;

        let hostname = hostname_from_url(endpoint_url).ok()?;
        let new_endpoint_url =
            url_with_replaced_hostname(matching_endpoint.endpoint_url.as_ref(), &hostname).ok()?;

        // Issue #16, #17 - the server may advertise an endpoint whose hostname is inaccessible
        // to the client so substitute the advertised hostname with the one the client supplied.
        matching_endpoint.endpoint_url = new_endpoint_url.into();
        Some(matching_endpoint)
    }

    /// Determine if we recognize the security of this endpoint.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - Endpoint to check.
    ///
    /// # Returns
    ///
    /// * `bool` - `true` if the endpoint is supported.
    pub fn is_supported_endpoint(&self, endpoint: &EndpointDescription) -> bool {
        if let Ok(security_policy) = SecurityPolicy::from_str(endpoint.security_policy_uri.as_ref())
        {
            !matches!(security_policy, SecurityPolicy::Unknown)
        } else {
            false
        }
    }

    async fn register_server_inner(
        &self,
        server: RegisteredServer,
        channel: &AsyncSecureChannel,
    ) -> Result<(), StatusCode> {
        let request = RegisterServerRequest {
            request_header: channel.make_request_header(self.config.request_timeout),
            server,
        };
        let response = channel.send(request, self.config.request_timeout).await?;
        if let ResponseMessage::RegisterServer(response) = response {
            process_service_result(&response.response_header)?;
            Ok(())
        } else {
            Err(process_unexpected_response(response))
        }
    }

    /// Get the best endpoint for the server, "best" here is the endpoint with the highest security level.
    ///
    /// # Arguments
    ///
    /// * `discovery_endpoint` - Endpoint to connect to.
    pub async fn get_best_endpoint(
        &self,
        discovery_endpoint: impl ConnectorBuilder,
    ) -> Result<EndpointDescription, Error> {
        let discovery_endpoint = discovery_endpoint.build()?;
        let endpoints = self
            .get_server_endpoints_from_url(
                discovery_endpoint.default_endpoint().endpoint_url.as_ref(),
            )
            .await?;
        if endpoints.is_empty() {
            return Err(Error::new(
                StatusCode::BadUnexpectedError,
                "No endpoints returned from server",
            ));
        }

        let Some(endpoint) = endpoints
            .into_iter()
            .filter(|e| self.is_supported_endpoint(e))
            .max_by(|a, b| a.security_level.cmp(&b.security_level))
        else {
            error!("Cannot find an endpoint that we can use");
            return Err(Error::new(
                StatusCode::BadUnexpectedError,
                "No supported endpoints returned from server",
            ));
        };

        Ok(endpoint)
    }

    /// This function is used by servers that wish to register themselves with a discovery server.
    /// i.e. one server is the client to another server. The server sends a [`RegisterServerRequest`]
    /// to the discovery server to register itself. Servers are expected to re-register themselves periodically
    /// with the discovery server, with a maximum of 10 minute intervals.
    ///
    /// See OPC UA Part 4 - Services 5.4.5 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `connector` - Connector to the discovery server. This is implemented for `String` and `&str`.
    ///   A simple usage would be to just pass `server_endpoint.endpoint_url.as_ref()` here.
    /// * `server_endpoint` - The endpoint to use for registration. If this requires security, you first need to get an appropriate.
    ///   server endpoint using `get_best_endpoint` or `get_server_endpoints_from_url`.
    /// * `server` - The server to register
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Success
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn register_server(
        &self,
        connector: impl ConnectorBuilder,
        server_endpoint: &EndpointDescription,
        server: RegisteredServer,
    ) -> Result<(), StatusCode> {
        let endpoint_info = EndpointInfo {
            endpoint: server_endpoint.clone(),
            user_identity_token: IdentityToken::Anonymous,
            preferred_locales: Vec::new(),
        };
        let connector = connector.build()?;
        let channel = self.channel_from_endpoint_info(endpoint_info, self.config.channel_lifetime);

        let mut evt_loop = channel.connect(&connector).await?;

        let send_fut = self.register_server_inner(server, &channel);
        pin!(send_fut);

        let res = loop {
            select! {
                r = evt_loop.poll() => {
                    if let TransportPollResult::Closed(e) = r {
                        return Err(e);
                    }
                },
                res = &mut send_fut => break res
            }
        };

        channel.close_channel().await;

        loop {
            if matches!(evt_loop.poll().await, TransportPollResult::Closed(_)) {
                break;
            }
        }

        res
    }

    /// Get the certificate store.
    pub fn certificate_store(&self) -> &Arc<RwLock<CertificateStore>> {
        &self.certificate_store
    }
}
