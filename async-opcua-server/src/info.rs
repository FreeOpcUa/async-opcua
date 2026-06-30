// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Provides server state information, such as status, configuration, running servers and so on.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU16, AtomicU8, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use opcua_nodes::DefaultTypeTree;
use tracing::{debug, error, warn};

use crate::auth::oauth2::validate_issued_jwt;
use crate::authenticator::{
    issued_token_security_policy, user_pass_security_policy_id, verify_x509_user_token_signature,
    Password,
};
use crate::diagnostics::{ServerDiagnostics, ServerDiagnosticsSummary};
use crate::node_manager::TypeTreeForUser;
use crate::rbac::defaults::NamespaceDefaults;
use crate::rbac::resolver::RoleResolver;
use crate::session::negotiate::{
    decrypt_identity_token_secret, issued_token_secret_needs_decrypt,
    tarpit_authentication_failure, username_password_secret_needs_decrypt,
    validate_issued_token_protection, validate_username_password_token_protection,
    EccSecretContext,
};
use opcua_core::comms::url::{hostname_from_url, url_matches_except_host};
use opcua_core::config::Config;
use opcua_core::handle::AtomicHandle;
use opcua_core::sync::RwLock;
use opcua_crypto::identity::{LocalOAuth2Validator, OAuth2IdentityValidator};
use opcua_crypto::{CertificateStore, PrivateKey, SecurityPolicy, SuppressedFinding, X509};
#[cfg(feature = "discovery-mdns")]
use opcua_types::MdnsDiscoveryConfiguration;
use opcua_types::{
    profiles, status_code::StatusCode, ActivateSessionRequest, AnonymousIdentityToken,
    ApplicationDescription, ApplicationType, EndpointDescription, RegisteredServer,
    ServerState as ServerStateType, SignatureData, UserNameIdentityToken, UserTokenType,
    X509IdentityToken,
};
use opcua_types::{
    ByteString, ContextOwned, DateTime, DecodingOptions, Error, ExtensionObject,
    IssuedIdentityToken, LocalizedText, MessageSecurityMode, NamespaceMap, TypeLoader,
    TypeLoaderCollection, UAString,
};

use crate::config::{ServerConfig, ServerEndpoint};

use super::authenticator::{AuthManager, UserToken};
use super::identity_token::{IdentityToken, POLICY_ID_ANONYMOUS, POLICY_ID_X509};
use super::{OperationalLimits, ServerCapabilities, ANONYMOUS_USER_TOKEN_ID};

const MAX_REGISTERED_SERVERS: usize = 1000;

#[cfg(feature = "discovery-mdns")]
fn registered_mdns_name(server: &RegisteredServer, config: &MdnsDiscoveryConfiguration) -> String {
    if !config.mdns_server_name.is_null() && !config.mdns_server_name.is_empty() {
        return bounded_mdns_string(
            config.mdns_server_name.as_ref(),
            crate::discovery_mdns::MAX_STR,
        );
    }

    let name = server
        .server_names
        .as_ref()
        .and_then(|names| names.first())
        .map(|name| name.text.as_ref())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| server.server_uri.as_ref());
    bounded_mdns_string(name, crate::discovery_mdns::MAX_STR)
}

#[cfg(feature = "discovery-mdns")]
fn registered_mdns_capabilities(config: &MdnsDiscoveryConfiguration) -> Vec<String> {
    let mut caps: Vec<String> = config
        .server_capabilities
        .as_ref()
        .into_iter()
        .flat_map(|caps| caps.iter())
        .filter(|cap| !cap.is_null() && !cap.is_empty())
        .take(crate::discovery_mdns::MAX_CAPS)
        .map(|cap| bounded_mdns_string(cap.as_ref(), crate::discovery_mdns::MAX_CAP_LEN))
        .collect();

    if caps.is_empty() {
        caps.push("NA".to_owned());
    }

    caps
}

#[cfg(feature = "discovery-mdns")]
fn bounded_mdns_string(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        return value.to_owned();
    }

    let mut output = String::with_capacity(max_len);
    for ch in value.chars() {
        let next_len = output.len().saturating_add(ch.len_utf8());
        if next_len > max_len {
            break;
        }
        output.push(ch);
    }
    output
}

/// Server state is any configuration associated with the server as a whole that individual sessions might
/// be interested in.
pub struct ServerInfo {
    /// The application URI
    pub application_uri: UAString,
    /// The product URI
    pub product_uri: UAString,
    /// The application name
    pub application_name: LocalizedText,
    /// The time the server started
    pub start_time: ArcSwap<DateTime>,
    /// The list of servers (by urn)
    pub servers: Vec<String>,
    /// Server configuration
    pub config: Arc<ServerConfig>,
    /// Server public certificate read from config location or null if there is none
    pub server_certificate: RwLock<Option<X509>>,
    /// Server private key
    pub server_pkey: RwLock<Option<PrivateKey>>,
    /// Certificate store used to validate incoming application and user identity certificates.
    pub(crate) certificate_store: Arc<RwLock<CertificateStore>>,
    /// Operational limits
    pub(crate) operational_limits: OperationalLimits,
    /// Current state
    pub state: ArcSwap<ServerStateType>,
    /// Audit log
    // pub(crate) audit_log: Arc<RwLock<AuditLog>>,
    /// Diagnostic information
    // pub(crate) diagnostics: Arc<RwLock<ServerDiagnostics>>,
    /// Size of the send buffer in bytes
    pub send_buffer_size: usize,
    /// Size of the receive buffer in bytes
    pub receive_buffer_size: usize,
    /// Authenticator to use when verifying user identities, and checking for user access.
    pub authenticator: Arc<dyn AuthManager>,
    /// Resolver for mapping activated identities to granted role NodeIds.
    pub(crate) role_resolver: Arc<RwLock<RoleResolver>>,
    /// Per-namespace default RolePermissions and AccessRestrictions.
    pub(crate) namespace_defaults: NamespaceDefaults,
    /// Structure containing type metadata shared by the entire server.
    pub type_tree: Arc<RwLock<DefaultTypeTree>>,
    /// Wrapper to get a type tree for a specific user.
    pub type_tree_getter: Arc<dyn TypeTreeForUser>,
    /// Generator for subscription IDs.
    pub subscription_id_handle: AtomicHandle,
    /// Generator for monitored item IDs.
    pub monitored_item_id_handle: AtomicHandle,
    /// Generator for secure channel IDs.
    pub secure_channel_id_handle: Arc<AtomicHandle>,
    /// Server capabilities
    pub capabilities: ServerCapabilities,
    /// Service level observer.
    pub service_level: Arc<AtomicU8>,
    /// Currently active local port.
    pub port: AtomicU16,
    /// List of active type loaders
    pub type_loaders: RwLock<TypeLoaderCollection>,
    /// Registered servers advertised by this server when acting as a Local Discovery Server.
    pub(crate) registered_servers: RwLock<HashMap<UAString, RegisteredServer>>,
    /// Servers discovered via OPC UA Part 12 multicast discovery.
    #[cfg(feature = "discovery-mdns")]
    pub(crate) mdns: Option<std::sync::Arc<crate::discovery_mdns::MdnsDiscovery>>,
    /// mDNS advertisements for servers registered via RegisterServer2 discovery configuration.
    #[cfg(feature = "discovery-mdns")]
    pub(crate) registered_mdns:
        Option<std::sync::Arc<crate::discovery_mdns::MdnsAdvertisementRegistry>>,
    /// Current server diagnostics.
    pub diagnostics: ServerDiagnostics,
    /// Performance metrics for this server instance.
    pub metrics: Arc<crate::metrics::ServerMetrics>,
}

pub(crate) struct X509UserCertificateValidation {
    pub certificate: ByteString,
    pub suppressed_findings: Vec<SuppressedFinding>,
}

pub(crate) struct EndpointAuthentication {
    pub user_token: UserToken,
    pub claims: Option<opcua_crypto::identity::ClaimProfile>,
    pub x509_user_certificate_validation: Option<X509UserCertificateValidation>,
}

impl EndpointAuthentication {
    fn new(user_token: UserToken, claims: Option<opcua_crypto::identity::ClaimProfile>) -> Self {
        Self {
            user_token,
            claims,
            x509_user_certificate_validation: None,
        }
    }

    fn x509(user_token: UserToken, validation: X509UserCertificateValidation) -> Self {
        Self {
            user_token,
            claims: None,
            x509_user_certificate_validation: Some(validation),
        }
    }
}

impl ServerInfo {
    /// Get the list of endpoints that match the provided filters.
    pub fn endpoints(
        &self,
        endpoint_url: &UAString,
        transport_profile_uris: &Option<Vec<UAString>>,
    ) -> Option<Vec<EndpointDescription>> {
        self.endpoints_with_filters(endpoint_url, transport_profile_uris, &None)
    }

    /// Get the list of endpoints that match the provided filters.
    pub fn endpoints_with_filters(
        &self,
        endpoint_url: &UAString,
        transport_profile_uris: &Option<Vec<UAString>>,
        locale_ids: &Option<Vec<UAString>>,
    ) -> Option<Vec<EndpointDescription>> {
        self.endpoints_with_filters_inner(endpoint_url, transport_profile_uris, locale_ids, false)
    }

    /// Get the list of endpoints for GetEndpoints, returning endpoint URLs that
    /// are consistent with the DiscoveryEndpoint URL supplied by the client.
    pub(crate) fn get_endpoints_with_filters(
        &self,
        endpoint_url: &UAString,
        transport_profile_uris: &Option<Vec<UAString>>,
        locale_ids: &Option<Vec<UAString>>,
    ) -> Option<Vec<EndpointDescription>> {
        self.endpoints_with_filters_inner(endpoint_url, transport_profile_uris, locale_ids, true)
    }

    fn endpoints_with_filters_inner(
        &self,
        endpoint_url: &UAString,
        transport_profile_uris: &Option<Vec<UAString>>,
        locale_ids: &Option<Vec<UAString>>,
        mirror_requested_endpoint_url: bool,
    ) -> Option<Vec<EndpointDescription>> {
        // Filter endpoints based on profile_uris
        debug!(
            "Endpoints requested, transport profile uris {:?}",
            transport_profile_uris
        );
        if let Some(ref transport_profile_uris) = *transport_profile_uris {
            // Note - some clients pass an empty array
            if !transport_profile_uris.is_empty() {
                // As we only support binary transport, the result is None if the supplied profile_uris does not contain that profile
                let found_binary_transport = transport_profile_uris.iter().any(|profile_uri| {
                    profile_uri.as_ref() == profiles::TRANSPORT_PROFILE_URI_BINARY
                });
                if !found_binary_transport {
                    error!(
                        "Client wants to connect with a non binary transport {:#?}",
                        transport_profile_uris
                    );
                    return None;
                }
            }
        }

        if !self.supports_locale_ids(locale_ids) {
            debug!(
                "Endpoint request locale ids {:?} are not supported by server locales {:?}",
                locale_ids, self.config.locale_ids
            );
            return Some(vec![]);
        }

        if endpoint_url.is_empty() {
            let endpoints = self
                .config
                .endpoints
                .values()
                .map(|e| self.new_endpoint_description(e, true, None))
                .collect();
            return Some(endpoints);
        }

        if let Ok(hostname) = hostname_from_url(endpoint_url.as_ref()) {
            if !hostname.eq_ignore_ascii_case(&self.config.tcp_config.host) {
                debug!(
                    "Endpoint url \"{}\" hostname supplied by caller does not match server's hostname \"{}\"",
                    endpoint_url, &self.config.tcp_config.host
                );
            }
            let base_endpoint_url = self.base_endpoint();
            let endpoints = self
                .config
                .endpoints
                .values()
                .filter(|e| {
                    url_matches_except_host(
                        &e.endpoint_url(&base_endpoint_url),
                        endpoint_url.as_ref(),
                    )
                })
                .map(|e| {
                    self.new_endpoint_description(
                        e,
                        true,
                        mirror_requested_endpoint_url.then_some(endpoint_url.as_ref()),
                    )
                })
                .collect();
            Some(endpoints)
        } else {
            warn!(
                "Endpoint url \"{}\" is unrecognized, using default",
                endpoint_url
            );
            if let Some(e) = self.config.default_endpoint() {
                Some(vec![self.new_endpoint_description(e, true, None)])
            } else {
                Some(vec![])
            }
        }
    }

    /// Return whether the local server matches `FindServers` discovery filters.
    pub(crate) fn matches_find_servers_filters(
        &self,
        endpoint_url: &UAString,
        locale_ids: &Option<Vec<UAString>>,
    ) -> bool {
        self.supports_locale_ids(locale_ids) && self.matches_discovery_endpoint_url(endpoint_url)
    }

    /// Applies a RegisterServer request to the in-memory discovery registry.
    pub(crate) fn apply_register_server(&self, server: RegisteredServer) -> StatusCode {
        if server.server_uri.is_null() || server.server_uri.is_empty() {
            return StatusCode::BadServerUriInvalid;
        }

        let server_uri = server.server_uri.clone();
        let mut registered_servers = self.registered_servers.write();

        if !server.is_online {
            registered_servers.remove(&server_uri);
            return StatusCode::Good;
        }

        // Part 4 §5.5.5: an online registration must provide a ServerName and a DiscoveryUrl.
        if server.server_names.as_ref().is_none_or(|n| n.is_empty()) {
            return StatusCode::BadServerNameMissing;
        }
        if server.discovery_urls.as_ref().is_none_or(|u| u.is_empty()) {
            return StatusCode::BadDiscoveryUrlMissing;
        }

        if !registered_servers.contains_key(&server_uri)
            && registered_servers.len() >= MAX_REGISTERED_SERVERS
        {
            return StatusCode::BadTooManyOperations;
        }

        registered_servers.insert(server_uri, server);
        StatusCode::Good
    }

    #[cfg(feature = "discovery-mdns")]
    pub(crate) fn apply_register_server2_mdns_configuration(
        &self,
        server: &RegisteredServer,
        config: &MdnsDiscoveryConfiguration,
    ) -> StatusCode {
        let Some(registered_mdns) = &self.registered_mdns else {
            return StatusCode::BadNotSupported;
        };

        if !server.is_online {
            self.remove_registered_mdns(&server.server_uri);
            return StatusCode::Good;
        }

        let Some(discovery_url) = server
            .discovery_urls
            .as_ref()
            .and_then(|urls| urls.first())
            .filter(|url| !url.is_null() && !url.is_empty())
        else {
            return StatusCode::BadDiscoveryUrlMissing;
        };
        let mdns_name = registered_mdns_name(server, config);
        if mdns_name.is_empty() {
            return StatusCode::BadServerNameMissing;
        }
        let caps = registered_mdns_capabilities(config);

        match registered_mdns.register(
            server.server_uri.as_ref(),
            &mdns_name,
            discovery_url.as_ref(),
            &caps,
        ) {
            Ok(()) => StatusCode::Good,
            Err(e) => {
                warn!("RegisterServer2 mDNS advertisement unavailable: {e}");
                StatusCode::BadNotSupported
            }
        }
    }

    #[cfg(feature = "discovery-mdns")]
    pub(crate) fn remove_registered_mdns(&self, server_uri: &UAString) {
        if let Some(registered_mdns) = &self.registered_mdns {
            registered_mdns.unregister(server_uri.as_ref());
        }
    }

    /// Returns servers as `ServerOnNetwork` records for FindServersOnNetwork (Part 4 §5.5.3).
    /// Registered servers are sorted by server URI. When mDNS discovery is enabled, discovered servers
    /// are merged in and sorted by DNS-SD service instance name.
    pub(crate) fn find_servers_on_network(
        &self,
        starting_record_id: u32,
        max_records_to_return: u32,
        capability_filter: &Option<Vec<UAString>>,
    ) -> Vec<opcua_types::ServerOnNetwork> {
        let want_caps = capability_filter
            .as_ref()
            .is_some_and(|f| f.iter().any(|c| !c.is_null() && !c.is_empty()));

        #[cfg(not(feature = "discovery-mdns"))]
        {
            let registered = self.registered_servers.read();
            let mut servers: Vec<_> = registered.values().collect();
            servers.sort_by(|a, b| a.server_uri.as_ref().cmp(b.server_uri.as_ref()));

            servers
                .into_iter()
                .enumerate()
                .map(|(i, server)| (i as u32, server))
                .filter(|(record_id, _)| *record_id >= starting_record_id)
                // We do not track per-server capabilities, so we can only satisfy an empty filter.
                .filter(|_| !want_caps)
                .map(|(record_id, server)| opcua_types::ServerOnNetwork {
                    record_id,
                    server_name: server
                        .server_names
                        .as_ref()
                        .and_then(|n| n.first())
                        .map(|n| n.text.clone())
                        .unwrap_or_else(|| server.server_uri.clone()),
                    discovery_url: server
                        .discovery_urls
                        .as_ref()
                        .and_then(|u| u.first())
                        .cloned()
                        .unwrap_or_default(),
                    server_capabilities: None,
                })
                .take(if max_records_to_return == 0 {
                    usize::MAX
                } else {
                    max_records_to_return as usize
                })
                .collect()
        }

        #[cfg(feature = "discovery-mdns")]
        {
            struct Candidate {
                sort_key: String,
                server_name: UAString,
                discovery_url: UAString,
                caps: Option<Vec<String>>,
            }

            let mut candidates: Vec<Candidate> = {
                let registered = self.registered_servers.read();
                registered
                    .values()
                    .map(|server| Candidate {
                        sort_key: server.server_uri.as_ref().to_owned(),
                        server_name: server
                            .server_names
                            .as_ref()
                            .and_then(|n| n.first())
                            .map(|n| n.text.clone())
                            .unwrap_or_else(|| server.server_uri.clone()),
                        discovery_url: server
                            .discovery_urls
                            .as_ref()
                            .and_then(|u| u.first())
                            .cloned()
                            .unwrap_or_default(),
                        caps: None,
                    })
                    .collect()
            };

            let discovered = self
                .mdns
                .as_ref()
                .map(|mdns| mdns.snapshot())
                .unwrap_or_default();
            candidates.extend(discovered.into_iter().map(|server| Candidate {
                sort_key: server.instance_name,
                server_name: UAString::from(server.server_name),
                discovery_url: UAString::from(server.discovery_url),
                caps: Some(server.capabilities),
            }));

            candidates.sort_by(|a, b| a.sort_key.cmp(&b.sort_key));

            candidates
                .into_iter()
                .enumerate()
                .map(|(i, server)| (i as u32, server))
                .filter(|(record_id, _)| *record_id >= starting_record_id)
                .filter(|(_, server)| {
                    !want_caps
                        || server.caps.as_ref().is_some_and(|caps| {
                            capability_filter.as_ref().is_some_and(|filter| {
                                filter
                                    .iter()
                                    .filter(|cap| !cap.is_null() && !cap.is_empty())
                                    .all(|requested| {
                                        caps.iter()
                                            .any(|cap| cap.eq_ignore_ascii_case(requested.as_ref()))
                                    })
                            })
                        })
                })
                .map(|(record_id, server)| opcua_types::ServerOnNetwork {
                    record_id,
                    server_name: server.server_name,
                    discovery_url: server.discovery_url,
                    server_capabilities: server
                        .caps
                        .map(|caps| caps.into_iter().map(UAString::from).collect()),
                })
                .take(if max_records_to_return == 0 {
                    usize::MAX
                } else {
                    max_records_to_return as usize
                })
                .collect()
        }
    }

    /// Returns registered servers as application descriptions for FindServers.
    pub(crate) fn registered_application_descriptions(
        &self,
        _endpoint_url: &UAString,
        locale_ids: &Option<Vec<UAString>>,
    ) -> Vec<ApplicationDescription> {
        self.registered_servers
            .read()
            .values()
            .map(|server| ApplicationDescription {
                application_uri: server.server_uri.clone(),
                product_uri: server.product_uri.clone(),
                application_name: registered_server_application_name(server, locale_ids),
                application_type: server.server_type,
                gateway_server_uri: server.gateway_server_uri.clone(),
                discovery_profile_uri: UAString::null(),
                discovery_urls: server.discovery_urls.clone(),
            })
            .collect()
    }

    /// Returns this server's application description for FindServers.
    pub(crate) fn find_servers_application_description(
        &self,
        endpoint_url: &UAString,
    ) -> ApplicationDescription {
        let mut description = self.config.application_description();
        if !endpoint_url.is_empty() {
            description.discovery_urls = Some(vec![endpoint_url.clone()]);
        }
        description
    }

    fn supports_locale_ids(&self, locale_ids: &Option<Vec<UAString>>) -> bool {
        let Some(locale_ids) = locale_ids else {
            return true;
        };
        if locale_ids.is_empty() {
            return true;
        }

        locale_ids.iter().any(|requested| {
            requested.is_empty()
                || self
                    .config
                    .locale_ids
                    .iter()
                    .any(|supported| locale_id_matches(supported, requested.as_ref()))
        })
    }

    fn matches_discovery_endpoint_url(&self, endpoint_url: &UAString) -> bool {
        if endpoint_url.is_empty() {
            return true;
        }

        let requested = endpoint_url.as_ref();
        let base_endpoint_url = self.base_endpoint();
        self.config
            .endpoints
            .values()
            .map(|endpoint| endpoint.endpoint_url(&base_endpoint_url))
            .chain(self.config.discovery_urls.iter().cloned())
            .any(|advertised_url| url_matches_except_host(&advertised_url, requested))
    }

    /// Check if the endpoint given by `endpoint_url`, `security_policy`, and `security_mode`
    /// exists on the server.
    pub fn endpoint_exists(
        &self,
        endpoint_url: &str,
        security_policy: SecurityPolicy,
        security_mode: MessageSecurityMode,
    ) -> bool {
        if security_policy.is_deprecated() && !self.config.allow_legacy_crypto {
            return false;
        }
        self.config
            .find_endpoint(
                endpoint_url,
                &self.base_endpoint(),
                security_policy,
                security_mode,
            )
            .is_some()
    }

    /// Validate that the requested endpoint host is one the server advertises,
    /// or one bound to the server application certificate.
    pub(crate) fn validate_endpoint_hostname(&self, endpoint_url: &str) -> Result<(), StatusCode> {
        let hostname =
            hostname_from_url(endpoint_url).map_err(|_| StatusCode::BadTcpEndpointUrlInvalid)?;

        if self.endpoint_hostname_matches_advertised_endpoint(endpoint_url, &hostname) {
            return Ok(());
        }

        if self
            .server_certificate
            .read()
            .as_ref()
            .is_some_and(|cert| cert.is_hostname_valid(&hostname).is_ok())
        {
            return Ok(());
        }

        error!(
            "Endpoint url \"{}\" hostname \"{}\" is not present in the server certificate or advertised endpoints",
            endpoint_url, hostname
        );
        Err(StatusCode::BadCertificateHostNameInvalid)
    }

    fn endpoint_hostname_matches_advertised_endpoint(
        &self,
        endpoint_url: &str,
        hostname: &str,
    ) -> bool {
        let base_endpoint_url = self.base_endpoint();

        self.config
            .endpoints
            .values()
            .map(|endpoint| endpoint.endpoint_url(&base_endpoint_url))
            .chain(self.config.discovery_urls.iter().cloned())
            .any(|advertised_url| {
                url_matches_except_host(&advertised_url, endpoint_url)
                    && hostname_from_url(&advertised_url)
                        .is_ok_and(|advertised_host| advertised_host.eq_ignore_ascii_case(hostname))
            })
    }

    /// Make matching endpoint descriptions for the specified url.
    /// If none match then None will be passed, therefore if Some is returned it will be guaranteed
    /// to contain at least one result.
    pub fn new_endpoint_descriptions(
        &self,
        endpoint_url: &str,
    ) -> Option<Vec<EndpointDescription>> {
        debug!("find_endpoint, url = {}", endpoint_url);
        let base_endpoint_url = self.base_endpoint();
        let endpoints: Vec<EndpointDescription> = self
            .config
            .endpoints
            .iter()
            .filter(|&(_, e)| {
                // Test end point's security_policy_uri and matching url
                url_matches_except_host(&e.endpoint_url(&base_endpoint_url), endpoint_url)
            })
            // Deprecated policies are not advertised unless explicitly
            // allowed at runtime.
            .filter(|&(_, e)| {
                self.config.allow_legacy_crypto || !e.security_policy().is_deprecated()
            })
            .map(|(_, e)| self.new_endpoint_description(e, false, None))
            .collect();
        if endpoints.is_empty() {
            None
        } else {
            Some(endpoints)
        }
    }

    /// Constructs a new endpoint description using the server's info and that in an Endpoint
    fn new_endpoint_description(
        &self,
        endpoint: &ServerEndpoint,
        all_fields: bool,
        endpoint_url_override: Option<&str>,
    ) -> EndpointDescription {
        let base_endpoint_url = self.base_endpoint();

        let user_identity_tokens = self.authenticator.user_token_policies(endpoint);

        // CreateSession doesn't need all the endpoint description
        // and docs say not to bother sending the server and server
        // certificate info.
        let (server, server_certificate) = if all_fields {
            (
                ApplicationDescription {
                    application_uri: self.application_uri.clone(),
                    product_uri: self.product_uri.clone(),
                    application_name: self.application_name.clone(),
                    application_type: self.application_type(),
                    gateway_server_uri: self.gateway_server_uri(),
                    discovery_profile_uri: UAString::null(),
                    discovery_urls: self.discovery_urls(),
                },
                self.server_certificate_as_byte_string(),
            )
        } else {
            (
                ApplicationDescription {
                    application_uri: self.application_uri.clone(),
                    product_uri: UAString::null(),
                    application_name: LocalizedText::null(),
                    application_type: self.application_type(),
                    gateway_server_uri: self.gateway_server_uri(),
                    discovery_profile_uri: UAString::null(),
                    discovery_urls: self.discovery_urls(),
                },
                ByteString::null(),
            )
        };

        EndpointDescription {
            endpoint_url: endpoint_url_override
                .map_or_else(
                    || endpoint.endpoint_url(&base_endpoint_url),
                    ToOwned::to_owned,
                )
                .into(),
            server,
            server_certificate,
            security_mode: endpoint.message_security_mode(),
            security_policy_uri: UAString::from(endpoint.security_policy().to_uri()),
            user_identity_tokens: Some(user_identity_tokens),
            transport_profile_uri: UAString::from(profiles::TRANSPORT_PROFILE_URI_BINARY),
            security_level: endpoint.security_level,
        }
    }

    /// Get the list of discovery URLs on the server.
    pub fn discovery_urls(&self) -> Option<Vec<UAString>> {
        if self.config.discovery_urls.is_empty() {
            None
        } else {
            Some(
                self.config
                    .discovery_urls
                    .iter()
                    .map(UAString::from)
                    .collect(),
            )
        }
    }

    /// Get the application type, will be `Server`.
    pub fn application_type(&self) -> ApplicationType {
        ApplicationType::Server
    }

    /// Get the gateway server URI.
    pub fn gateway_server_uri(&self) -> UAString {
        UAString::null()
    }

    /// Get the current server state.
    pub fn state(&self) -> ServerStateType {
        **self.state.load()
    }

    /// Check if the server state indicates the server is running.
    pub fn is_running(&self) -> bool {
        self.state() == ServerStateType::Running
    }

    /// Get the base endpoint, i.e. the configured host + current port.
    pub fn base_endpoint(&self) -> String {
        format!(
            "opc.tcp://{}:{}",
            self.config.tcp_config.host,
            self.port.load(Ordering::Relaxed)
        )
    }

    /// Get the server certificate as a byte string.
    pub fn server_certificate_as_byte_string(&self) -> ByteString {
        let cert = self.server_certificate.read();
        if let Some(ref server_certificate) = *cert {
            server_certificate.as_byte_string()
        } else {
            ByteString::null()
        }
    }

    /// Get a representation of this server as a `RegisteredServer` object.
    pub fn registered_server(&self) -> RegisteredServer {
        let server_uri = self.application_uri.clone();
        let product_uri = self.product_uri.clone();
        let gateway_server_uri = self.gateway_server_uri();
        let discovery_urls = self.discovery_urls();
        let server_type = self.application_type();
        let is_online = self.is_running();
        let server_names = Some(vec![self.application_name.clone()]);
        // Server names
        RegisteredServer {
            server_uri,
            product_uri,
            server_names,
            server_type,
            gateway_server_uri,
            discovery_urls,
            semaphore_file_path: UAString::null(),
            is_online,
        }
    }

    /// Authenticates access to an endpoint. The endpoint is described by its path, policy, mode and
    /// the token is supplied in an extension object that must be extracted and authenticated.
    ///
    /// It is possible that the endpoint does not exist, or that the token is invalid / unsupported
    /// or that the token cannot be used with the end point. The return codes reflect the responses
    /// that ActivateSession would expect from a service call.
    pub async fn authenticate_endpoint(
        &self,
        request: &ActivateSessionRequest,
        endpoint_url: &str,
        security_policy: SecurityPolicy,
        security_mode: MessageSecurityMode,
        user_identity_token: ExtensionObject,
        server_nonce: &ByteString,
    ) -> Result<(UserToken, Option<opcua_crypto::identity::ClaimProfile>), Error> {
        let authentication = self
            .authenticate_endpoint_with_ecc_ctx(
                request,
                endpoint_url,
                security_policy,
                security_mode,
                user_identity_token,
                server_nonce,
                EccSecretContext::default(),
            )
            .await?;
        Ok((authentication.user_token, authentication.claims))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn authenticate_endpoint_with_ecc_ctx(
        &self,
        request: &ActivateSessionRequest,
        endpoint_url: &str,
        security_policy: SecurityPolicy,
        security_mode: MessageSecurityMode,
        user_identity_token: ExtensionObject,
        server_nonce: &ByteString,
        ecc_ctx: EccSecretContext,
    ) -> Result<EndpointAuthentication, Error> {
        // Get security from endpoint url
        let result = if let Some(endpoint) = self.config.find_endpoint(
            endpoint_url,
            &self.base_endpoint(),
            security_policy,
            security_mode,
        ) {
            // Now validate the user identity token
            match IdentityToken::new(user_identity_token) {
                IdentityToken::None => {
                    error!("User identity token type unsupported");
                    Err(Error::new(
                        StatusCode::BadIdentityTokenInvalid,
                        "User identity token type unsupported",
                    ))
                }
                IdentityToken::Anonymous(token) => self
                    .authenticate_anonymous_token(endpoint, &token)
                    .await
                    .map(|token| EndpointAuthentication::new(token, None)),
                IdentityToken::UserName(token) => {
                    let server_key = self.server_pkey.read().clone();
                    self.authenticate_username_identity_token(
                        endpoint,
                        &token,
                        &server_key,
                        server_nonce,
                        security_policy,
                        &ecc_ctx,
                    )
                    .await
                    .map(|token| EndpointAuthentication::new(token, None))
                }
                IdentityToken::X509(token) => {
                    // Clone out of the lock; the guard must not be held
                    // across the await below.
                    let server_cert = self.server_certificate.read().clone();
                    self.authenticate_x509_identity_token(
                        endpoint,
                        &token,
                        &request.user_token_signature,
                        &server_cert,
                        server_nonce,
                    )
                    .await
                    .map(|(token, validation)| EndpointAuthentication::x509(token, validation))
                }
                IdentityToken::IssuedToken(token) => {
                    let server_key = self.server_pkey.read().clone();
                    self.authenticate_issued_identity_token(
                        endpoint,
                        &token,
                        &server_key,
                        server_nonce,
                        security_policy,
                        &ecc_ctx,
                    )
                    .await
                    .map(|(token, claims)| EndpointAuthentication::new(token, claims))
                }
                IdentityToken::Invalid(o) => Err(Error::new(
                    StatusCode::BadIdentityTokenInvalid,
                    format!(
                        "User identity token type {} is unsupported",
                        o.body.map(|b| b.type_name()).unwrap_or("None")
                    ),
                )),
            }
        } else {
            Err(Error::new(
                StatusCode::BadIdentityTokenRejected,
                format!(
                    "Cannot find endpoint that matches path \"{endpoint_url}\", security policy {security_policy:?}, and security mode {security_mode:?}"
                ),
            ))
        };

        tarpit_authentication_failure(result).await
    }

    /// Returns the decoding options of the server
    pub fn decoding_options(&self) -> DecodingOptions {
        self.config.decoding_options()
    }

    /// Authenticates an anonymous token, i.e. does the endpoint support anonymous access or not
    async fn authenticate_anonymous_token(
        &self,
        endpoint: &ServerEndpoint,
        token: &AnonymousIdentityToken,
    ) -> Result<UserToken, Error> {
        if token.policy_id.as_ref() != POLICY_ID_ANONYMOUS {
            return Err(Error::new(
                StatusCode::BadIdentityTokenInvalid,
                format!(
                    "Token doesn't possess the correct policy id. Got {}, expected {}",
                    token.policy_id.as_ref(),
                    POLICY_ID_ANONYMOUS
                ),
            ));
        }
        self.authenticator
            .authenticate_anonymous_token(endpoint)
            .await?;

        Ok(UserToken(ANONYMOUS_USER_TOKEN_ID.to_string()))
    }

    /// Authenticates the username identity token with the supplied endpoint. The function returns the user token identifier
    /// that matches the identity token.
    async fn authenticate_username_identity_token(
        &self,
        endpoint: &ServerEndpoint,
        token: &UserNameIdentityToken,
        server_key: &Option<PrivateKey>,
        server_nonce: &ByteString,
        _security_policy: SecurityPolicy,
        ecc_ctx: &EccSecretContext,
    ) -> Result<UserToken, Error> {
        if !self.authenticator.supports_user_pass(endpoint) {
            Err(Error::new(
                StatusCode::BadIdentityTokenRejected,
                "Endpoint doesn't support username password tokens",
            ))
        } else if token.policy_id != user_pass_security_policy_id(endpoint) {
            Err(Error::new(
                StatusCode::BadIdentityTokenRejected,
                "Token doesn't possess the correct policy id",
            ))
        } else if token.user_name.is_empty() {
            Err(Error::new(
                StatusCode::BadIdentityTokenRejected,
                "User identify token supplied no username",
            ))
        } else {
            debug!(
                "policy id = {}, encryption algorithm = {}",
                token.policy_id.as_ref(),
                token.encryption_algorithm.as_ref()
            );
            let user_token_security_policy = endpoint.password_security_policy();
            validate_username_password_token_protection(token, user_token_security_policy)?;
            let needs_decrypt =
                username_password_secret_needs_decrypt(token, user_token_security_policy);
            let token_password = if needs_decrypt {
                let decrypted = decrypt_identity_token_secret(
                    token,
                    server_nonce.as_ref(),
                    user_token_security_policy,
                    server_key,
                    ecc_ctx,
                )?;
                String::from_utf8(decrypted.value.unwrap_or_default().to_vec()).map_err(|e| {
                    Error::new(
                        StatusCode::BadIdentityTokenInvalid,
                        format!("Failed to decode identity token to string: {e}"),
                    )
                })?
            } else {
                token.plaintext_password()?
            };

            self.authenticator
                .authenticate_username_identity_token(
                    endpoint,
                    token.user_name.as_ref(),
                    &Password::new(token_password),
                )
                .await
        }
    }

    /// Authenticate the x509 token against the endpoint. The function returns the user token identifier
    /// that matches the identity token.
    async fn authenticate_x509_identity_token(
        &self,
        endpoint: &ServerEndpoint,
        token: &X509IdentityToken,
        user_token_signature: &SignatureData,
        server_certificate: &Option<X509>,
        server_nonce: &ByteString,
    ) -> Result<(UserToken, X509UserCertificateValidation), Error> {
        if !self.authenticator.supports_x509(endpoint) {
            error!("Endpoint doesn't support x509 tokens");
            Err(Error::new(
                StatusCode::BadIdentityTokenRejected,
                "Endpoint doesn't support x509 tokens",
            ))
        } else if token.policy_id.as_ref() != POLICY_ID_X509 {
            error!("Token doesn't possess the correct policy id");
            Err(Error::new(
                StatusCode::BadIdentityTokenRejected,
                "Token doesn't possess the correct policy id",
            ))
        } else {
            let signing_cert = X509::from_byte_string(&token.certificate_data)?;
            let suppressed_findings = match server_certificate {
                Some(ref server_certificate) => {
                    // Find the security policy used for verifying tokens
                    let user_identity_tokens = self.authenticator.user_token_policies(endpoint);
                    let security_policy = user_identity_tokens
                        .iter()
                        .find(|t| t.token_type == UserTokenType::Certificate)
                        .map(|t| SecurityPolicy::from_uri(t.security_policy_uri.as_ref()))
                        .unwrap_or_else(|| endpoint.security_policy());

                    // The security policy has to be something that can encrypt
                    match security_policy {
                        SecurityPolicy::Unknown | SecurityPolicy::None => Err(Error::new(
                            StatusCode::BadIdentityTokenInvalid,
                            "Bad security policy",
                        )),
                        security_policy => {
                            let suppressed_findings = {
                                let certificate_store = self.certificate_store.read();
                                certificate_store
                                    .validate_user_identity_cert(&signing_cert, security_policy)?
                            };

                            // Verify token proof-of-possession after the certificate itself is
                            // trusted and valid for user authentication.
                            verify_x509_user_token_signature(
                                &signing_cert,
                                user_token_signature,
                                security_policy,
                                server_certificate,
                                server_nonce.as_ref(),
                            )?;
                            Ok(suppressed_findings)
                        }
                    }
                }
                None => Err(Error::new(
                    StatusCode::BadIdentityTokenInvalid,
                    "Server certificate missing, cannot validate X509 tokens",
                )),
            }?;

            // Check the endpoint to see if this token is supported
            let signing_thumbprint = signing_cert.thumbprint();

            let user_token = self
                .authenticator
                .authenticate_x509_identity_token(endpoint, &signing_thumbprint)
                .await?;

            Ok((
                user_token,
                X509UserCertificateValidation {
                    certificate: token.certificate_data.clone(),
                    suppressed_findings,
                },
            ))
        }
    }

    async fn authenticate_issued_identity_token(
        &self,
        endpoint: &ServerEndpoint,
        token: &IssuedIdentityToken,
        server_key: &Option<PrivateKey>,
        server_nonce: &ByteString,
        _security_policy: SecurityPolicy,
        ecc_ctx: &EccSecretContext,
    ) -> Result<(UserToken, Option<opcua_crypto::identity::ClaimProfile>), Error> {
        if !self.authenticator.supports_issued_token(endpoint) {
            Err(Error::new(
                StatusCode::BadIdentityTokenRejected,
                "Endpoint doesn't support issued tokens",
            ))
        } else if token.policy_id != issued_token_security_policy(endpoint) {
            Err(Error::new(
                StatusCode::BadIdentityTokenRejected,
                "Token doesn't possess the correct policy id",
            ))
        } else {
            debug!(
                "policy id = {}, encryption algorithm = {}",
                token.policy_id.as_ref(),
                token.encryption_algorithm.as_ref()
            );
            let user_token_security_policy = endpoint.password_security_policy();
            validate_issued_token_protection(token, user_token_security_policy)?;
            let needs_decrypt =
                issued_token_secret_needs_decrypt(token, user_token_security_policy);
            let decrypted_token = if needs_decrypt {
                decrypt_identity_token_secret(
                    token,
                    server_nonce.as_ref(),
                    user_token_security_policy,
                    server_key,
                    ecc_ctx,
                )?
            } else {
                token.token_data.clone()
            };

            let issued_jwt = validate_issued_jwt(&decrypted_token)?;
            debug!(
                "accepted issued JWT token hash={}, subject={}",
                issued_jwt.token_hash(),
                issued_jwt.claims().sub.as_deref().unwrap_or("")
            );

            // ponytail: issued-token auth now requires explicit issuer, audience, and issuer
            // certificate configuration instead of falling back to defaults or any trusted cert.
            let missing_oauth2_config = || {
                Error::new(
                    StatusCode::BadIdentityTokenRejected,
                    "OAuth2 issuer/audience not configured",
                )
            };
            let issuer = self
                .config
                .oauth2_issuer
                .clone()
                .ok_or_else(missing_oauth2_config)?;
            let audience = self
                .config
                .oauth2_audience
                .clone()
                .ok_or_else(missing_oauth2_config)?;
            let issuer_cert_path = self
                .config
                .oauth2_issuer_certificate_path
                .as_ref()
                .ok_or_else(missing_oauth2_config)?;
            let issuer_cert = CertificateStore::read_cert(issuer_cert_path)
                .map_err(|_| missing_oauth2_config())?;
            let validator = LocalOAuth2Validator::new(issuer, audience, issuer_cert);
            let claims = validator
                .validate_token(issued_jwt.raw())
                .map_err(|status| {
                    Error::new(status, "Issued identity token failed OAuth2 validation")
                })?;

            Ok((UserToken(claims.username.clone()), Some(claims)))
        }
    }

    pub(crate) fn initial_encoding_context(&self) -> ContextOwned {
        // The namespace map is populated later, once the session is connected.
        ContextOwned::new(
            NamespaceMap::new(),
            self.type_loaders.read().clone(),
            self.decoding_options(),
        )
    }

    /// Add a type loader to the server.
    /// Note that there is no mechanism to ensure uniqueness,
    /// you should avoid adding the same type loader more than once, it will
    /// work, but there will be a small performance overhead.
    pub fn add_type_loader(&self, type_loader: Arc<dyn TypeLoader>) {
        self.type_loaders.write().add(type_loader);
    }

    /// Convenience method to get the diagnostics summary.
    pub fn summary(&self) -> &ServerDiagnosticsSummary {
        &self.diagnostics.summary
    }

    /* pub(crate) fn raise_and_log<T>(&self, event: T) -> Result<NodeId, ()>
    where
        T: AuditEvent + Event,
    {
        let audit_log = trace_write_lock!(self.audit_log);
        audit_log.raise_and_log(event)
    } */
}

fn locale_id_matches(supported: &str, requested: &str) -> bool {
    let supported = supported.trim().replace('_', "-").to_ascii_lowercase();
    let requested = requested.trim().replace('_', "-").to_ascii_lowercase();

    if supported.is_empty() || requested.is_empty() {
        return requested.is_empty();
    }
    if supported == requested {
        return true;
    }

    let supported_is_neutral = !supported.contains('-');
    let requested_is_neutral = !requested.contains('-');

    (supported_is_neutral && requested.starts_with(&format!("{supported}-")))
        || (requested_is_neutral && supported.starts_with(&format!("{requested}-")))
}

fn registered_server_application_name(
    server: &RegisteredServer,
    locale_ids: &Option<Vec<UAString>>,
) -> LocalizedText {
    let Some(server_names) = server.server_names.as_ref() else {
        return LocalizedText::null();
    };

    if let Some(locale_ids) = locale_ids {
        for requested in locale_ids {
            if let Some(name) = server_names
                .iter()
                .find(|name| locale_id_matches(name.locale.as_ref(), requested.as_ref()))
            {
                return name.clone();
            }
        }
    }

    server_names
        .first()
        .cloned()
        .unwrap_or_else(LocalizedText::null)
}

#[cfg(test)]
mod tests {
    use opcua_crypto::{AlternateNames, SecurityPolicy, X509Data, X509};
    use opcua_types::{
        ApplicationType, MessageSecurityMode, RegisteredServer, StatusCode, UAString,
    };

    use crate::{ServerBuilder, ANONYMOUS_USER_TOKEN_ID};

    // Feature 024 (Claude, independent): the LDS registry is bounded and rejects/validates crafted
    // input without panic (FR-004), and online/offline registration semantics are correct (§5.5.5).
    fn reg(uri: &str, is_online: bool) -> RegisteredServer {
        RegisteredServer {
            server_uri: uri.into(),
            product_uri: UAString::null(),
            // ServerName + DiscoveryUrl are required for an online registration (Part 4 §5.5.5).
            server_names: Some(vec![opcua_types::LocalizedText::new("en", "Test")]),
            server_type: ApplicationType::Server,
            gateway_server_uri: UAString::null(),
            discovery_urls: Some(vec!["opc.tcp://127.0.0.1:4840/".into()]),
            semaphore_file_path: UAString::null(),
            is_online,
        }
    }

    #[tokio::test]
    async fn register_server_registry_is_bounded_and_safe() {
        let (_server, handle) = ServerBuilder::new()
            .without_node_managers()
            .application_name("Registry Bound Test")
            .application_uri("urn:registry-bound-test")
            .product_uri("urn:registry-bound-test")
            .discovery_urls(vec!["opc.tcp://127.0.0.1:4840/".to_string()])
            .host("127.0.0.1")
            .port(4840)
            .add_endpoint(
                "root",
                (
                    "/",
                    SecurityPolicy::None,
                    MessageSecurityMode::None,
                    &[ANONYMOUS_USER_TOKEN_ID] as &[&str],
                ),
            )
            .build()
            .expect("server should build");
        let info = handle.info();

        // A null (missing) server URI is rejected (no panic, no insert).
        let mut null_uri = reg("x", true);
        null_uri.server_uri = UAString::null();
        assert_eq!(
            info.apply_register_server(null_uri),
            StatusCode::BadServerUriInvalid
        );
        // Unregistering an unknown server is a clean no-op success.
        assert_eq!(
            info.apply_register_server(reg("urn:never-registered", false)),
            StatusCode::Good
        );

        // Fill the registry to the cap.
        for i in 0..super::MAX_REGISTERED_SERVERS {
            assert_eq!(
                info.apply_register_server(reg(&format!("urn:s{i}"), true)),
                StatusCode::Good
            );
        }
        // A NEW distinct registration beyond the cap is rejected (no unbounded growth).
        assert_eq!(
            info.apply_register_server(reg("urn:over-cap", true)),
            StatusCode::BadTooManyOperations
        );
        // Updating an EXISTING entry while full still succeeds (not a new key).
        assert_eq!(
            info.apply_register_server(reg("urn:s0", true)),
            StatusCode::Good
        );
        // Removing one frees a slot for a new registration.
        assert_eq!(
            info.apply_register_server(reg("urn:s0", false)),
            StatusCode::Good
        );
        assert_eq!(
            info.apply_register_server(reg("urn:over-cap", true)),
            StatusCode::Good
        );
    }

    // C6 (multi-AI cross-check): concurrent online/offline RegisterServer for the same URIs must leave
    // a consistent registry — no duplicate and no half-deleted entries. The registry is an
    // RwLock<HashMap> keyed by server URI, so this pins that race-safety.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_register_unregister_keeps_registry_consistent() {
        let (_server, handle) = ServerBuilder::new()
            .without_node_managers()
            .application_name("Registry Race Test")
            .application_uri("urn:registry-race-test")
            .product_uri("urn:registry-race-test")
            .discovery_urls(vec!["opc.tcp://127.0.0.1:4840/".to_string()])
            .host("127.0.0.1")
            .port(4840)
            .add_endpoint(
                "root",
                (
                    "/",
                    SecurityPolicy::None,
                    MessageSecurityMode::None,
                    &[ANONYMOUS_USER_TOKEN_ID] as &[&str],
                ),
            )
            .build()
            .expect("server should build");
        let info = handle.info().clone();

        // Hammer 4 URIs with interleaved online/offline registrations from many tasks.
        let mut tasks = Vec::new();
        for t in 0..16u32 {
            let info = info.clone();
            tasks.push(tokio::spawn(async move {
                for i in 0..200u32 {
                    let uri = format!("urn:race-{}", i % 4);
                    let online = (t + i) % 2 == 0;
                    info.apply_register_server(reg(&uri, online));
                }
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }

        // Deterministic settle: register all four online.
        for i in 0..4 {
            assert_eq!(
                info.apply_register_server(reg(&format!("urn:race-{i}"), true)),
                StatusCode::Good
            );
        }

        // Each URI must appear exactly once — no duplicates, none lost.
        let descs = info.registered_application_descriptions(&UAString::null(), &None);
        for i in 0..4 {
            let uri: UAString = format!("urn:race-{i}").into();
            assert_eq!(
                descs.iter().filter(|d| d.application_uri == uri).count(),
                1,
                "URI urn:race-{i} must be present exactly once after the concurrent storm"
            );
        }
    }

    #[tokio::test]
    async fn endpoints_filter_by_requested_endpoint_url() {
        let user_token_ids = [ANONYMOUS_USER_TOKEN_ID];
        let (_server, handle) = ServerBuilder::new()
            .without_node_managers()
            .application_name("Endpoint URL Filter Test")
            .application_uri("urn:endpoint-url-filter-test")
            .product_uri("urn:endpoint-url-filter-test")
            .discovery_urls(vec!["opc.tcp://127.0.0.1:4840/".to_string()])
            .host("127.0.0.1")
            .port(4840)
            .add_endpoint(
                "root",
                (
                    "/",
                    SecurityPolicy::None,
                    MessageSecurityMode::None,
                    &user_token_ids as &[&str],
                ),
            )
            .add_endpoint(
                "diagnostics",
                (
                    "/diagnostics",
                    SecurityPolicy::None,
                    MessageSecurityMode::None,
                    &user_token_ids as &[&str],
                ),
            )
            .build()
            .expect("server should build");

        let endpoints = handle
            .info()
            .endpoints(
                &UAString::from("opc.tcp://localhost:4840/diagnostics"),
                &None,
            )
            .expect("endpoints should be returned");

        assert_eq!(endpoints.len(), 1);
        assert!(endpoints[0].endpoint_url.as_ref().ends_with("/diagnostics"));

        let endpoints = handle
            .info()
            .endpoints(&UAString::from("opc.tcp://localhost:4840/missing"), &None)
            .expect("endpoint filtering should return an empty list");
        assert!(endpoints.is_empty());
    }

    #[tokio::test]
    async fn find_servers_filters_match_endpoint_url_and_locale_ids() {
        let user_token_ids = [ANONYMOUS_USER_TOKEN_ID];
        let (_server, handle) = ServerBuilder::new()
            .without_node_managers()
            .application_name("FindServers Filter Test")
            .application_uri("urn:find-servers-filter-test")
            .product_uri("urn:find-servers-filter-test")
            .discovery_urls(vec!["opc.tcp://127.0.0.1:4840/diagnostics".to_string()])
            .locale_ids(vec!["de-DE".to_string()])
            .host("127.0.0.1")
            .port(4840)
            .add_endpoint(
                "diagnostics",
                (
                    "/diagnostics",
                    SecurityPolicy::None,
                    MessageSecurityMode::None,
                    &user_token_ids as &[&str],
                ),
            )
            .build()
            .expect("server should build");

        assert!(handle.info().matches_find_servers_filters(
            &UAString::from("opc.tcp://localhost:4840/diagnostics"),
            &Some(vec![UAString::from("de")])
        ));
        assert!(!handle.info().matches_find_servers_filters(
            &UAString::from("opc.tcp://localhost:4840/missing"),
            &Some(vec![UAString::from("de")])
        ));
        assert!(!handle.info().matches_find_servers_filters(
            &UAString::from("opc.tcp://localhost:4840/diagnostics"),
            &Some(vec![UAString::from("fr-FR")])
        ));
    }

    #[tokio::test]
    async fn endpoint_hostname_validation_requires_certificate_san_or_advertised_endpoint_host() {
        let user_token_ids = [ANONYMOUS_USER_TOKEN_ID];
        let (_server, handle) = ServerBuilder::new()
            .without_node_managers()
            .application_name("Endpoint Host Test")
            .application_uri("urn:endpoint-filter-test")
            .product_uri("urn:endpoint-filter-test")
            .discovery_urls(vec!["opc.tcp://127.0.0.1:4840/".to_string()])
            .add_endpoint(
                "modern",
                (
                    "/",
                    SecurityPolicy::Aes256Sha256RsaPss,
                    MessageSecurityMode::Sign,
                    &user_token_ids as &[&str],
                ),
            )
            .host("127.0.0.1")
            .port(4840)
            .build()
            .expect("server should build");

        let err = handle
            .info()
            .validate_endpoint_hostname("opc.tcp://not-advertised.example:4840/")
            .expect_err("unknown endpoint host should be rejected");
        assert_eq!(err, opcua_types::StatusCode::BadCertificateHostNameInvalid);

        let mut alt_host_names = AlternateNames::new();
        alt_host_names.add_uri("urn:endpoint-filter-test");
        alt_host_names.add_dns("public.example");
        let cert = X509::cert_and_pkey(&X509Data {
            key_size: 2048,
            common_name: "Endpoint Filter Test".to_string(),
            organization: "async-opcua tests".to_string(),
            organizational_unit: "server".to_string(),
            country: "US".to_string(),
            state: "test".to_string(),
            alt_host_names,
            certificate_duration_days: 30,
        })
        .expect("test certificate should be generated")
        .0;
        *handle.info().server_certificate.write() = Some(cert);

        handle
            .info()
            .validate_endpoint_hostname("opc.tcp://public.example:4840/")
            .expect("certificate SAN host should be accepted");
        handle
            .info()
            .validate_endpoint_hostname("opc.tcp://127.0.0.1:4840/")
            .expect("advertised endpoint host should be accepted");
    }

    // Feature 036 (Claude, independent): with multicast discovery NOT configured (the default, and
    // the only possibility when the feature is compiled out), FindServersOnNetwork behaves exactly as
    // the pull-based form — a non-empty capability filter matches nothing (FR-007 / SC-004).
    #[tokio::test]
    async fn find_servers_on_network_pull_based_unchanged_without_mdns() {
        let (_server, handle) = ServerBuilder::new()
            .without_node_managers()
            .application_name("PullOnly")
            .application_uri("urn:pull-only")
            .discovery_urls(vec!["opc.tcp://127.0.0.1:4840/".to_string()])
            .host("127.0.0.1")
            .port(4840)
            .add_endpoint(
                "root",
                (
                    "/",
                    SecurityPolicy::None,
                    MessageSecurityMode::None,
                    &[ANONYMOUS_USER_TOKEN_ID] as &[&str],
                ),
            )
            .build()
            .expect("server should build");
        let info = handle.info();
        assert_eq!(
            info.apply_register_server(reg("urn:registered", true)),
            StatusCode::Good
        );

        // No filter → the registered server is returned.
        assert_eq!(info.find_servers_on_network(0, 0, &None).len(), 1);
        // A non-empty capability filter matches nothing (registered servers carry no caps).
        assert!(info
            .find_servers_on_network(0, 0, &Some(vec!["DA".into()]))
            .is_empty());
    }

    // Feature 036 (Claude, independent): FindServersOnNetwork merges mDNS-discovered servers with
    // the pull-based registry, applies the capability filter against advertised caps, excludes self
    // and expired records (Part 4 §5.5.3; FR-003/FR-004/FR-005/FR-006).
    #[cfg(feature = "discovery-mdns")]
    #[tokio::test]
    async fn find_servers_on_network_merges_filters_and_excludes_self_and_expired() {
        use crate::discovery_mdns::{DiscoveredServer, MdnsDiscovery};
        use std::time::{Duration, Instant};

        let (_server, handle) = ServerBuilder::new()
            .without_node_managers()
            .application_name("MdnsMerge")
            .application_uri("urn:mdns-merge")
            .discovery_urls(vec!["opc.tcp://127.0.0.1:4840/".to_string()])
            .host("127.0.0.1")
            .port(4840)
            .add_endpoint(
                "root",
                (
                    "/",
                    SecurityPolicy::None,
                    MessageSecurityMode::None,
                    &[ANONYMOUS_USER_TOKEN_ID] as &[&str],
                ),
            )
            .multicast_discovery(true)
            .build()
            .expect("server should build");
        let info = handle.info();

        // One pull-based registered server (no advertised caps), name "Test".
        assert_eq!(
            info.apply_register_server(reg("urn:registered", true)),
            StatusCode::Good
        );

        // Seed the discovery cache directly.
        let cache: &MdnsDiscovery = info.mdns.as_ref().expect("mdns cache present when enabled");
        let future = Instant::now() + Duration::from_secs(300);
        let past = Instant::now() - Duration::from_secs(1);
        let dv = |inst: &str, url: &str, caps: &[&str], exp: Instant| DiscoveredServer {
            instance_name: inst.to_owned(),
            discovery_url: url.to_owned(),
            server_name: inst.to_owned(),
            capabilities: caps.iter().map(|s| (*s).to_owned()).collect(),
            expires_at: exp,
        };
        cache.insert(dv("DiscA", "opc.tcp://10.0.0.1:4840/", &["DA"], future));
        cache.insert(dv(
            "DiscB",
            "opc.tcp://10.0.0.2:4840/",
            &["HD", "AC"],
            future,
        ));
        cache.insert(dv("DiscExpired", "opc.tcp://10.0.0.9:4840/", &["DA"], past)); // FR-006
        cache.insert(dv("MdnsMerge", "opc.tcp://10.0.0.3:4840/", &["DA"], future)); // self (FR-005)

        // No filter → registered ("Test") + DiscA + DiscB; expired + self excluded.
        let all = info.find_servers_on_network(0, 0, &None);
        let names: Vec<String> = all.iter().map(|s| s.server_name.to_string()).collect();
        assert_eq!(
            all.len(),
            3,
            "registered + 2 live discovered; got {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "Test"),
            "registered present: {names:?}"
        );
        assert!(names.iter().any(|n| n == "DiscA"));
        assert!(names.iter().any(|n| n == "DiscB"));
        assert!(
            !names.iter().any(|n| n == "DiscExpired"),
            "expired excluded"
        );
        assert!(!names.iter().any(|n| n == "MdnsMerge"), "self excluded");

        // Filter ["DA"] → only DiscA (DiscB advertises HD/AC; registered has no caps).
        let da = info.find_servers_on_network(0, 0, &Some(vec!["DA".into()]));
        assert_eq!(da.len(), 1, "only the DA-capable discovered server");
        assert_eq!(da[0].server_name.to_string(), "DiscA");
        assert!(da[0]
            .server_capabilities
            .as_ref()
            .is_some_and(|c| c.iter().any(|cap| cap.as_ref() == "DA")));
    }
}
