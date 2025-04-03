// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Client configuration data.

use std::{
    self,
    collections::BTreeMap,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use chrono::TimeDelta;
use serde::{Deserialize, Serialize};
use tracing::warn;

use opcua_core::config::Config;
use opcua_crypto::SecurityPolicy;
use opcua_types::{ApplicationType, EndpointDescription, MessageSecurityMode, UAString};

use crate::{Client, IdentityToken, SessionRetryPolicy};

/// Token ID of the anonymous user token.
pub const ANONYMOUS_USER_TOKEN_ID: &str = "ANONYMOUS";

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
/// User token in client configuration.
pub struct ClientUserToken {
    /// Username
    pub user: String,
    /// Password
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Certificate path for x509 authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_path: Option<String>,
    /// Private key path for x509 authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_path: Option<String>,
}

impl ClientUserToken {
    /// Constructs a client token which holds a username and password.
    pub fn user_pass<S, T>(user: S, password: T) -> Self
    where
        S: Into<String>,
        T: Into<String>,
    {
        ClientUserToken {
            user: user.into(),
            password: Some(password.into()),
            cert_path: None,
            private_key_path: None,
        }
    }

    /// Constructs a client token which holds a username and paths to X509 certificate and private key.
    pub fn x509<S>(user: S, cert_path: &Path, private_key_path: &Path) -> Self
    where
        S: Into<String>,
    {
        // Apparently on Windows, a PathBuf can hold weird non-UTF chars but they will not
        // be stored in a config file properly in any event, so this code will lossily strip them out.
        ClientUserToken {
            user: user.into(),
            password: None,
            cert_path: Some(cert_path.to_string_lossy().to_string()),
            private_key_path: Some(private_key_path.to_string_lossy().to_string()),
        }
    }

    /// Test if the token, i.e. that it has a name, and either a password OR a cert path and key path.
    /// The paths are not validated.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        if self.user.is_empty() {
            errors.push("User token has an empty name.".to_owned());
        }
        // A token must properly represent one kind of token or it is not valid
        if self.password.is_some() {
            if self.cert_path.is_some() || self.private_key_path.is_some() {
                errors.push(format!(
                    "User token {} holds a password and certificate info - it cannot be both.",
                    self.user
                ));
            }
        } else if self.cert_path.is_none() && self.private_key_path.is_none() {
            errors.push(format!(
                "User token {} fails to provide a password or certificate info.",
                self.user
            ));
        } else if self.cert_path.is_none() || self.private_key_path.is_none() {
            errors.push(format!(
                "User token {} fails to provide both a certificate path and a private key path.",
                self.user
            ));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Describes an endpoint, it's url security policy, mode and user token
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct ClientEndpoint {
    /// Endpoint path
    pub url: String,
    /// Security policy
    pub security_policy: String,
    /// Security mode
    pub security_mode: String,
    /// User id to use with the endpoint
    #[serde(default = "ClientEndpoint::anonymous_id")]
    pub user_token_id: String,
}

impl ClientEndpoint {
    /// Makes a client endpoint
    pub fn new<T>(url: T) -> Self
    where
        T: Into<String>,
    {
        ClientEndpoint {
            url: url.into(),
            security_policy: SecurityPolicy::None.to_str().into(),
            security_mode: MessageSecurityMode::None.into(),
            user_token_id: Self::anonymous_id(),
        }
    }

    fn anonymous_id() -> String {
        ANONYMOUS_USER_TOKEN_ID.to_string()
    }

    /// Returns the security policy for this endpoint.
    pub fn security_policy(&self) -> SecurityPolicy {
        SecurityPolicy::from_str(&self.security_policy).unwrap()
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct DecodingOptions {
    /// Maximum size of a message chunk in bytes. 0 means no limit
    #[serde(default = "defaults::max_message_size")]
    pub(crate) max_message_size: usize,
    /// Maximum number of chunks in a message. 0 means no limit
    #[serde(default = "defaults::max_chunk_count")]
    pub(crate) max_chunk_count: usize,
    /// Maximum size of each individual sent message chunk.
    #[serde(default = "defaults::max_chunk_size")]
    pub(crate) max_chunk_size: usize,
    /// Maximum size of each received chunk.
    #[serde(default = "defaults::max_incoming_chunk_size")]
    pub(crate) max_incoming_chunk_size: usize,
    /// Maximum length in bytes (not chars!) of a string. 0 actually means 0, i.e. no string permitted
    #[serde(default = "defaults::max_string_length")]
    pub(crate) max_string_length: usize,
    /// Maximum length in bytes of a byte string. 0 actually means 0, i.e. no byte string permitted
    #[serde(default = "defaults::max_byte_string_length")]
    pub(crate) max_byte_string_length: usize,
    /// Maximum number of array elements. 0 actually means 0, i.e. no array permitted
    #[serde(default = "defaults::max_array_length")]
    pub(crate) max_array_length: usize,
}

impl DecodingOptions {
    pub fn as_comms_decoding_options(&self) -> opcua_types::DecodingOptions {
        opcua_types::DecodingOptions {
            max_chunk_count: self.max_chunk_count,
            max_message_size: self.max_message_size,
            max_string_length: self.max_string_length,
            max_byte_string_length: self.max_byte_string_length,
            max_array_length: self.max_array_length,
            client_offset: TimeDelta::zero(),
            ..Default::default()
        }
    }
}

impl Default for DecodingOptions {
    fn default() -> Self {
        Self {
            max_message_size: defaults::max_message_size(),
            max_chunk_count: defaults::max_chunk_count(),
            max_chunk_size: defaults::max_chunk_size(),
            max_incoming_chunk_size: defaults::max_incoming_chunk_size(),
            max_string_length: defaults::max_string_length(),
            max_byte_string_length: defaults::max_byte_string_length(),
            max_array_length: defaults::max_array_length(),
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Performance {
    /// Ignore clock skew allows the client to make a successful connection to the server, even
    /// when the client and server clocks are out of sync.
    #[serde(default)]
    pub(crate) ignore_clock_skew: bool,
    /// Maximum number of monitored items per request when recreating subscriptions on session recreation.
    #[serde(default = "defaults::recreate_monitored_items_chunk")]
    pub(crate) recreate_monitored_items_chunk: usize,
}

impl Default for Performance {
    fn default() -> Self {
        Self {
            ignore_clock_skew: false,
            recreate_monitored_items_chunk: defaults::recreate_monitored_items_chunk(),
        }
    }
}

/// Client OPC UA configuration
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct ClientConfig {
    /// Name of the application that the client presents itself as to the server
    pub(crate) application_name: String,
    /// The application uri
    pub(crate) application_uri: String,
    /// Product uri
    pub(crate) product_uri: String,
    /// Autocreates public / private keypair if they don't exist. For testing/samples only
    /// since you do not have control of the values
    pub(crate) create_sample_keypair: bool,
    /// Custom certificate path, to be used instead of the default .der certificate path
    pub(crate) certificate_path: Option<PathBuf>,
    /// Custom private key path, to be used instead of the default private key path
    pub(crate) private_key_path: Option<PathBuf>,
    /// Auto trusts server certificates. For testing/samples only unless you're sure what you're
    /// doing.
    pub(crate) trust_server_certs: bool,
    /// Verify server certificates. For testing/samples only unless you're sure what you're
    /// doing.
    pub(crate) verify_server_certs: bool,
    /// PKI folder, either absolute or relative to executable
    pub(crate) pki_dir: PathBuf,
    /// Preferred locales
    pub(crate) preferred_locales: Vec<String>,
    /// Identifier of the default endpoint
    pub(crate) default_endpoint: String,
    /// List of end points
    pub(crate) endpoints: BTreeMap<String, ClientEndpoint>,
    /// User tokens
    pub(crate) user_tokens: BTreeMap<String, ClientUserToken>,
    /// Requested channel lifetime in milliseconds.
    #[serde(default = "defaults::channel_lifetime")]
    pub(crate) channel_lifetime: u32,
    /// Decoding options used for serialization / deserialization
    #[serde(default)]
    pub(crate) decoding_options: DecodingOptions,
    /// Maximum number of times to attempt to reconnect to the server before giving up.
    /// -1 retries forever
    #[serde(default = "defaults::session_retry_limit")]
    pub(crate) session_retry_limit: i32,

    /// Initial delay for exponential backoff when reconnecting to the server.
    #[serde(default = "defaults::session_retry_initial")]
    pub(crate) session_retry_initial: Duration,
    /// Max delay between retry attempts.
    #[serde(default = "defaults::session_retry_max")]
    pub(crate) session_retry_max: Duration,
    /// Interval between each keep-alive request sent to the server.
    #[serde(default = "defaults::keep_alive_interval")]
    pub(crate) keep_alive_interval: Duration,
    /// Maximum number of failed keep alives before the client will be closed.
    /// Note that this should not actually needed if the server is compliant,
    /// only if the connection ends up in a bad state and needs to be
    /// forcibly reset.
    #[serde(default = "defaults::max_failed_keep_alive_count")]
    pub(crate) max_failed_keep_alive_count: u64,

    /// Timeout for each request sent to the server.
    #[serde(default = "defaults::request_timeout")]
    pub(crate) request_timeout: Duration,
    /// Timeout for publish requests, separate from normal timeout since
    /// subscriptions are often more time sensitive.
    #[serde(default = "defaults::publish_timeout")]
    pub(crate) publish_timeout: Duration,
    /// Minimum publish interval. Setting this higher will make sure that subscriptions
    /// publish together, which may reduce the number of publish requests if you have a lot of subscriptions.
    #[serde(default = "defaults::min_publish_interval")]
    pub(crate) min_publish_interval: Duration,

    /// Client performance settings
    pub(crate) performance: Performance,
    /// Automatically recreate subscriptions on reconnect, by first calling
    /// `transfer_subscriptions`, then attempting to recreate subscriptions if that fails.
    #[serde(default = "defaults::recreate_subscriptions")]
    pub(crate) recreate_subscriptions: bool,
    /// Session name
    pub(crate) session_name: String,
    /// Requested session timeout in milliseconds
    #[serde(default = "defaults::session_timeout")]
    pub(crate) session_timeout: u32,
}

impl Config for ClientConfig {
    /// Test if the config is valid, which requires at the least that
    fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.application_name.is_empty() {
            errors.push("Application name is empty".to_owned());
        }
        if self.application_uri.is_empty() {
            errors.push("Application uri is empty".to_owned());
        }
        if self.user_tokens.contains_key(ANONYMOUS_USER_TOKEN_ID) {
            errors.push(format!(
                "User tokens contains the reserved \"{}\" id",
                ANONYMOUS_USER_TOKEN_ID
            ));
        }
        if self.user_tokens.contains_key("") {
            errors.push("User tokens contains an endpoint with an empty id".to_owned());
        }
        self.user_tokens.iter().for_each(|(k, token)| {
            if let Err(e) = token.validate() {
                errors.push(format!("Token {k} failed to validate: {}", e.join(", ")))
            }
        });
        if self.endpoints.is_empty() {
            warn!("Endpoint config contains no endpoints");
        } else {
            // Check for invalid ids in endpoints
            if self.endpoints.contains_key("") {
                errors.push("Endpoints contains an endpoint with an empty id".to_owned());
            }
            if !self.default_endpoint.is_empty()
                && !self.endpoints.contains_key(&self.default_endpoint)
            {
                errors.push(format!(
                    "Default endpoint id {} does not exist in list of endpoints",
                    self.default_endpoint
                ));
            }
            // Check for invalid security policy and modes in endpoints
            self.endpoints.iter().for_each(|(id, e)| {
                if SecurityPolicy::from_str(&e.security_policy).unwrap() != SecurityPolicy::Unknown
                {
                    if MessageSecurityMode::Invalid
                        == MessageSecurityMode::from(e.security_mode.as_ref())
                    {
                        errors.push(format!(
                            "Endpoint {} security mode {} is invalid",
                            id, e.security_mode
                        ));
                    }
                } else {
                    errors.push(format!(
                        "Endpoint {} security policy {} is invalid",
                        id, e.security_policy
                    ));
                }
            });
        }
        if self.session_retry_limit < 0 && self.session_retry_limit != -1 {
            errors.push(format!("Session retry limit of {} is invalid - must be -1 (infinite), 0 (never) or a positive value", self.session_retry_limit));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn application_name(&self) -> UAString {
        UAString::from(&self.application_name)
    }

    fn application_uri(&self) -> UAString {
        UAString::from(&self.application_uri)
    }

    fn product_uri(&self) -> UAString {
        UAString::from(&self.product_uri)
    }

    fn application_type(&self) -> ApplicationType {
        ApplicationType::Client
    }
}

impl ClientConfig {
    /// Get the configured session retry policy.
    pub fn session_retry_policy(&self) -> SessionRetryPolicy {
        SessionRetryPolicy::new(
            self.session_retry_max,
            if self.session_retry_limit < 0 {
                None
            } else {
                Some(self.session_retry_limit as u32)
            },
            self.session_retry_initial,
        )
    }

    /// Returns an identity token corresponding to the matching user in the configuration. Or None
    /// if there is no matching token.
    pub fn client_identity_token(&self, user_token_id: impl Into<String>) -> Option<IdentityToken> {
        let user_token_id = user_token_id.into();
        if user_token_id == ANONYMOUS_USER_TOKEN_ID {
            Some(IdentityToken::Anonymous)
        } else {
            let token = self.user_tokens.get(&user_token_id)?;

            if let Some(ref password) = token.password {
                Some(IdentityToken::UserName(
                    token.user.clone(),
                    password.clone(),
                ))
            } else if let Some(ref cert_path) = token.cert_path {
                token.private_key_path.as_ref().map(|private_key_path| {
                    IdentityToken::X509(PathBuf::from(cert_path), PathBuf::from(private_key_path))
                })
            } else {
                None
            }
        }
    }

    /// Creates a [`EndpointDescription`](EndpointDescription) information from the supplied client endpoint.
    pub(super) fn endpoint_description_for_client_endpoint(
        &self,
        client_endpoint: &ClientEndpoint,
        endpoints: &[EndpointDescription],
    ) -> Result<EndpointDescription, String> {
        let security_policy =
            SecurityPolicy::from_str(&client_endpoint.security_policy).map_err(|_| {
                format!(
                    "Endpoint {} security policy {} is invalid",
                    client_endpoint.url, client_endpoint.security_policy
                )
            })?;
        let security_mode = MessageSecurityMode::from(client_endpoint.security_mode.as_ref());
        if security_mode == MessageSecurityMode::Invalid {
            return Err(format!(
                "Endpoint {} security mode {} is invalid",
                client_endpoint.url, client_endpoint.security_mode
            ));
        }
        let endpoint_url = client_endpoint.url.clone();
        let endpoint = Client::find_matching_endpoint(
            endpoints,
            &endpoint_url,
            security_policy,
            security_mode,
        )
        .ok_or_else(|| {
            format!(
                "Endpoint {}, {:?} / {:?} does not match any supplied by the server",
                endpoint_url, security_policy, security_mode
            )
        })?;

        Ok(endpoint)
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self::new("", "")
    }
}

mod defaults {
    use std::time::Duration;

    use crate::retry::SessionRetryPolicy;

    pub fn verify_server_certs() -> bool {
        true
    }

    pub fn channel_lifetime() -> u32 {
        60_000
    }

    pub fn session_retry_limit() -> i32 {
        SessionRetryPolicy::DEFAULT_RETRY_LIMIT as i32
    }

    pub fn session_retry_initial() -> Duration {
        Duration::from_secs(1)
    }

    pub fn session_retry_max() -> Duration {
        Duration::from_secs(30)
    }

    pub fn keep_alive_interval() -> Duration {
        Duration::from_secs(10)
    }

    pub fn max_array_length() -> usize {
        opcua_types::constants::MAX_ARRAY_LENGTH
    }

    pub fn max_byte_string_length() -> usize {
        opcua_types::constants::MAX_BYTE_STRING_LENGTH
    }

    pub fn max_chunk_count() -> usize {
        opcua_types::constants::MAX_CHUNK_COUNT
    }

    pub fn max_chunk_size() -> usize {
        65535
    }

    pub fn max_failed_keep_alive_count() -> u64 {
        0
    }

    pub fn max_incoming_chunk_size() -> usize {
        65535
    }

    pub fn max_message_size() -> usize {
        opcua_types::constants::MAX_MESSAGE_SIZE
    }

    pub fn max_string_length() -> usize {
        opcua_types::constants::MAX_STRING_LENGTH
    }

    pub fn request_timeout() -> Duration {
        Duration::from_secs(60)
    }

    pub fn publish_timeout() -> Duration {
        Duration::from_secs(60)
    }

    pub fn min_publish_interval() -> Duration {
        Duration::from_millis(100)
    }

    pub fn recreate_monitored_items_chunk() -> usize {
        1000
    }

    pub fn recreate_subscriptions() -> bool {
        true
    }

    pub fn session_timeout() -> u32 {
        60_000
    }
}

impl ClientConfig {
    /// The default PKI directory
    pub const PKI_DIR: &'static str = "pki";

    /// Create a new default client config.
    pub fn new(application_name: impl Into<String>, application_uri: impl Into<String>) -> Self {
        let mut pki_dir = std::env::current_dir().unwrap();
        pki_dir.push(Self::PKI_DIR);

        ClientConfig {
            application_name: application_name.into(),
            application_uri: application_uri.into(),
            product_uri: String::new(),
            create_sample_keypair: false,
            certificate_path: None,
            private_key_path: None,
            trust_server_certs: false,
            verify_server_certs: defaults::verify_server_certs(),
            pki_dir,
            preferred_locales: Vec::new(),
            default_endpoint: String::new(),
            endpoints: BTreeMap::new(),
            user_tokens: BTreeMap::new(),
            channel_lifetime: defaults::channel_lifetime(),
            decoding_options: DecodingOptions::default(),
            session_retry_limit: defaults::session_retry_limit(),
            session_retry_initial: defaults::session_retry_initial(),
            session_retry_max: defaults::session_retry_max(),
            keep_alive_interval: defaults::keep_alive_interval(),
            max_failed_keep_alive_count: defaults::max_failed_keep_alive_count(),
            request_timeout: defaults::request_timeout(),
            publish_timeout: defaults::publish_timeout(),
            min_publish_interval: defaults::min_publish_interval(),
            performance: Performance::default(),
            recreate_subscriptions: defaults::recreate_subscriptions(),
            session_name: "Rust OPC UA Client".into(),
            session_timeout: defaults::session_timeout(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{self, collections::BTreeMap, path::PathBuf};

    use crate::ClientBuilder;
    use opcua_core::config::Config;
    use opcua_crypto::SecurityPolicy;
    use opcua_types::MessageSecurityMode;

    use super::{ClientConfig, ClientEndpoint, ClientUserToken, ANONYMOUS_USER_TOKEN_ID};

    fn make_test_file(filename: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(filename);
        path
    }

    pub fn sample_builder() -> ClientBuilder {
        ClientBuilder::new()
            .application_name("OPC UA Sample Client")
            .application_uri("urn:SampleClient")
            .create_sample_keypair(true)
            .certificate_path("own/cert.der")
            .private_key_path("private/private.pem")
            .trust_server_certs(true)
            .pki_dir("./pki")
            .endpoints(vec![
                (
                    "sample_none",
                    ClientEndpoint {
                        url: String::from("opc.tcp://127.0.0.1:4855/"),
                        security_policy: String::from(SecurityPolicy::None.to_str()),
                        security_mode: String::from(MessageSecurityMode::None),
                        user_token_id: ANONYMOUS_USER_TOKEN_ID.to_string(),
                    },
                ),
                (
                    "sample_basic128rsa15",
                    ClientEndpoint {
                        url: String::from("opc.tcp://127.0.0.1:4855/"),
                        security_policy: String::from(SecurityPolicy::Basic128Rsa15.to_str()),
                        security_mode: String::from(MessageSecurityMode::SignAndEncrypt),
                        user_token_id: ANONYMOUS_USER_TOKEN_ID.to_string(),
                    },
                ),
                (
                    "sample_basic256",
                    ClientEndpoint {
                        url: String::from("opc.tcp://127.0.0.1:4855/"),
                        security_policy: String::from(SecurityPolicy::Basic256.to_str()),
                        security_mode: String::from(MessageSecurityMode::SignAndEncrypt),
                        user_token_id: ANONYMOUS_USER_TOKEN_ID.to_string(),
                    },
                ),
                (
                    "sample_basic256sha256",
                    ClientEndpoint {
                        url: String::from("opc.tcp://127.0.0.1:4855/"),
                        security_policy: String::from(SecurityPolicy::Basic256Sha256.to_str()),
                        security_mode: String::from(MessageSecurityMode::SignAndEncrypt),
                        user_token_id: ANONYMOUS_USER_TOKEN_ID.to_string(),
                    },
                ),
            ])
            .default_endpoint("sample_none")
            .user_token(
                "sample_user",
                ClientUserToken::user_pass("sample1", "sample1pwd"),
            )
            .user_token(
                "sample_user2",
                ClientUserToken::user_pass("sample2", "sample2pwd"),
            )
    }

    pub fn default_sample_config() -> ClientConfig {
        sample_builder().config()
    }

    #[test]
    fn client_sample_config() {
        // This test exists to create the samples/client.conf file
        // This test only exists to dump a sample config
        let config = default_sample_config();
        let mut path = std::env::current_dir().unwrap();
        path.push("..");
        path.push("samples");
        path.push("client.conf");
        println!("Path is {:?}", path);

        let saved = config.save(&path);
        println!("Saved = {:?}", saved);
        assert!(saved.is_ok());
        config.validate().unwrap();
    }

    #[test]
    fn client_config() {
        let path = make_test_file("client_config.yaml");
        println!("Client path = {:?}", path);
        let config = default_sample_config();
        let saved = config.save(&path);
        println!("Saved = {:?}", saved);
        assert!(config.save(&path).is_ok());
        if let Ok(config2) = ClientConfig::load(&path) {
            assert_eq!(config, config2);
        } else {
            panic!("Cannot load config from file");
        }
    }

    #[test]
    fn client_invalid_security_policy_config() {
        let mut config = default_sample_config();
        // Security policy is wrong
        config.endpoints = BTreeMap::new();
        config.endpoints.insert(
            String::from("sample_none"),
            ClientEndpoint {
                url: String::from("opc.tcp://127.0.0.1:4855"),
                security_policy: String::from("http://blah"),
                security_mode: String::from(MessageSecurityMode::None),
                user_token_id: ANONYMOUS_USER_TOKEN_ID.to_string(),
            },
        );
        assert_eq!(
            config.validate().unwrap_err().join(", "),
            "Endpoint sample_none security policy http://blah is invalid"
        );
    }

    #[test]
    fn client_invalid_security_mode_config() {
        let mut config = default_sample_config();
        // Message security mode is wrong
        config.endpoints = BTreeMap::new();
        config.endpoints.insert(
            String::from("sample_none"),
            ClientEndpoint {
                url: String::from("opc.tcp://127.0.0.1:4855"),
                security_policy: String::from(SecurityPolicy::Basic128Rsa15.to_uri()),
                security_mode: String::from("SingAndEncrypt"),
                user_token_id: ANONYMOUS_USER_TOKEN_ID.to_string(),
            },
        );
        assert_eq!(
            config.validate().unwrap_err().join(", "),
            "Endpoint sample_none security mode SingAndEncrypt is invalid"
        );
    }

    #[test]
    fn client_anonymous_user_tokens_id() {
        let mut config = default_sample_config();
        // id anonymous is reserved
        config.user_tokens = BTreeMap::new();
        config.user_tokens.insert(
            String::from("ANONYMOUS"),
            ClientUserToken {
                user: String::new(),
                password: Some(String::new()),
                cert_path: None,
                private_key_path: None,
            },
        );
        assert_eq!(
            config.validate().unwrap_err().join(", "),
            "User tokens contains the reserved \"ANONYMOUS\" id, Token ANONYMOUS failed to validate: User token has an empty name."
        );
    }
}
