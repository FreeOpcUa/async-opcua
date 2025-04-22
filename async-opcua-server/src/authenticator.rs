//! The [AuthManager] trait, and tooling related to this.

use async_trait::async_trait;

use opcua_crypto::{SecurityPolicy, Thumbprint};
use opcua_types::{
    Error, MessageSecurityMode, NodeId, StatusCode, UAString, UserTokenPolicy, UserTokenType,
};
use tracing::{debug, error};

use crate::identity_token::{
    POLICY_ID_ANONYMOUS, POLICY_ID_USER_PASS_NONE, POLICY_ID_USER_PASS_RSA_15,
    POLICY_ID_USER_PASS_RSA_OAEP, POLICY_ID_X509,
};

use super::{
    address_space::AccessLevel, config::ANONYMOUS_USER_TOKEN_ID, ServerEndpoint, ServerUserToken,
};
use std::{collections::BTreeMap, fmt::Debug};

/// Debug-safe wrapper around a password.
#[derive(Clone, PartialEq, Eq)]
pub struct Password(String);

impl Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Password").field(&"****").finish()
    }
}

impl Password {
    /// Create a new debug-safe password.
    pub fn new(password: String) -> Self {
        Self(password)
    }

    /// get the inner value. Note: you should make sure not to log this!
    pub fn get(&self) -> &str {
        &self.0
    }
}

/// A unique identifier for a _user_. Distinct from a client/session, a user can
/// have multiple sessions at the same time, and is typically the value we use to
/// control access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserToken(pub String);

/// Key used to identify a user.
/// Goes beyond just the identity token, since some services require
/// information about the application URI and security mode as well.
#[derive(Debug, Clone)]
pub struct UserSecurityKey {
    /// Raw user token.
    pub token: UserToken,
    /// Connection security mode.
    pub security_mode: MessageSecurityMode,
    /// Client application URI.
    pub application_uri: String,
}

impl UserToken {
    /// `true` if this is an anonymous user token.
    pub fn is_anonymous(&self) -> bool {
        self.0 == ANONYMOUS_USER_TOKEN_ID
    }
}

/// Permissions for the core and diagnostics node managers.
#[derive(Default, Debug, Clone)]
pub struct CoreServerPermissions {
    /// Whether the user can read the server diagnostics.
    pub read_diagnostics: bool,
}

#[allow(unused)]
#[async_trait]
/// The AuthManager trait is used to let servers control access to the server.
/// It serves two main purposes:
///
/// - It validates user credentials and returns a user token. Two clients with the
///   same user token are considered the _same_ user, and have some ability to interfere
///   with each other.
/// - It uses user tokens to check access levels.
///
/// Note that the only async methods are the ones validating access tokens. This means
/// that these methods should load and store any information you need to check user
/// access level down the line.
///
/// This is currently the only way to restrict access to core resources. For resources in
/// your own custom node managers you are free to use whatever access regime you want.
pub trait AuthManager: Send + Sync + 'static {
    /// Validate whether an anonymous user is allowed to access the given endpoint.
    /// This does not return a user token, all anonymous users share the same special token.
    async fn authenticate_anonymous_token(&self, endpoint: &ServerEndpoint) -> Result<(), Error> {
        Err(Error::new(
            StatusCode::BadIdentityTokenRejected,
            "Anonymous identity token unsupported",
        ))
    }

    /// Validate the given username and password for `endpoint`.
    /// This should return a user token associated with the user, for example the username itself.
    async fn authenticate_username_identity_token(
        &self,
        endpoint: &ServerEndpoint,
        username: &str,
        password: &Password,
    ) -> Result<UserToken, Error> {
        Err(Error::new(
            StatusCode::BadIdentityTokenRejected,
            "Username identity token unsupported",
        ))
    }

    /// Validate the signing thumbprint for `endpoint`.
    /// This should return a user token associated with the user.
    async fn authenticate_x509_identity_token(
        &self,
        endpoint: &ServerEndpoint,
        signing_thumbprint: &Thumbprint,
    ) -> Result<UserToken, Error> {
        Err(Error::new(
            StatusCode::BadIdentityTokenRejected,
            "X509 identity token unsupported",
        ))
    }

    /// Return the effective user access level for the given node ID
    fn effective_user_access_level(
        &self,
        token: &UserToken,
        user_access_level: AccessLevel,
        node_id: &NodeId,
    ) -> AccessLevel {
        user_access_level
    }

    /// Return whether a method is actually user executable, overriding whatever is returned by the
    /// node manager.
    fn is_user_executable(&self, token: &UserToken, method_id: &NodeId) -> bool {
        true
    }

    /// Return the valid user token policies for the given endpoint.
    /// Only valid tokens will be passed to the authenticator.
    fn user_token_policies(&self, endpoint: &ServerEndpoint) -> Vec<UserTokenPolicy>;

    /// Return whether the endpoint supports anonymous authentication.
    fn supports_anonymous(&self, endpoint: &ServerEndpoint) -> bool {
        self.user_token_policies(endpoint)
            .iter()
            .any(|e| e.token_type == UserTokenType::Anonymous)
    }

    /// Return whether the endpoint supports username/password authentication.
    fn supports_user_pass(&self, endpoint: &ServerEndpoint) -> bool {
        self.user_token_policies(endpoint)
            .iter()
            .any(|e| e.token_type == UserTokenType::UserName)
    }

    /// Return whether the endpoint supports x509-certificate authentication.
    fn supports_x509(&self, endpoint: &ServerEndpoint) -> bool {
        self.user_token_policies(endpoint)
            .iter()
            .any(|e| e.token_type == UserTokenType::Certificate)
    }

    /// Return the permissions for the core server for the given user.
    fn core_permissions(&self, token: &UserToken) -> CoreServerPermissions {
        CoreServerPermissions::default()
    }
}

/// A simple authenticator that keeps a map of valid users in memory.
/// In production applications you will almost always want to create your own
/// custom authenticator.
pub struct DefaultAuthenticator {
    users: BTreeMap<String, ServerUserToken>,
}

impl DefaultAuthenticator {
    /// Create a new default authenticator with the given set of users.
    pub fn new(users: BTreeMap<String, ServerUserToken>) -> Self {
        Self { users }
    }
}

#[async_trait]
impl AuthManager for DefaultAuthenticator {
    async fn authenticate_anonymous_token(&self, endpoint: &ServerEndpoint) -> Result<(), Error> {
        if !endpoint.user_token_ids.contains(ANONYMOUS_USER_TOKEN_ID) {
            return Err(Error::new(
                StatusCode::BadIdentityTokenRejected,
                format!(
                    "Endpoint \"{}\" does not support anonymous authentication",
                    endpoint.path
                ),
            ));
        }
        Ok(())
    }

    async fn authenticate_username_identity_token(
        &self,
        endpoint: &ServerEndpoint,
        username: &str,
        password: &Password,
    ) -> Result<UserToken, Error> {
        let token_password = password.get();
        for user_token_id in &endpoint.user_token_ids {
            if let Some(server_user_token) = self.users.get(user_token_id) {
                if server_user_token.is_user_pass() && server_user_token.user == username {
                    // test for empty password
                    let valid = if let Some(server_password) = server_user_token.pass.as_ref() {
                        server_password.as_bytes() == token_password.as_bytes()
                    } else {
                        token_password.is_empty()
                    };

                    if !valid {
                        error!(
                            "Cannot authenticate \"{}\", password is invalid",
                            server_user_token.user
                        );
                        return Err(Error::new(
                            StatusCode::BadIdentityTokenRejected,
                            format!("Cannot authenticate user \"{username}\""),
                        ));
                    } else {
                        return Ok(UserToken(user_token_id.clone()));
                    }
                }
            }
        }
        error!(
            "Cannot authenticate \"{}\", user not found for endpoint",
            username
        );
        Err(Error::new(
            StatusCode::BadIdentityTokenRejected,
            format!("Cannot authenticate \"{}\"", username),
        ))
    }

    async fn authenticate_x509_identity_token(
        &self,
        endpoint: &ServerEndpoint,
        signing_thumbprint: &Thumbprint,
    ) -> Result<UserToken, Error> {
        // Check the endpoint to see if this token is supported
        for user_token_id in &endpoint.user_token_ids {
            if let Some(server_user_token) = self.users.get(user_token_id) {
                if let Some(ref user_thumbprint) = server_user_token.thumbprint {
                    // The signing cert matches a user's identity, so it is valid
                    if user_thumbprint == signing_thumbprint {
                        return Ok(UserToken(user_token_id.clone()));
                    }
                }
            }
        }
        Err(Error::new(
            StatusCode::BadIdentityTokenRejected,
            "Authentication failed",
        ))
    }

    fn user_token_policies(&self, endpoint: &ServerEndpoint) -> Vec<UserTokenPolicy> {
        let mut user_identity_tokens = Vec::with_capacity(3);

        // Anonymous policy
        if endpoint.user_token_ids.contains(ANONYMOUS_USER_TOKEN_ID) {
            user_identity_tokens.push(UserTokenPolicy {
                policy_id: UAString::from(POLICY_ID_ANONYMOUS),
                token_type: UserTokenType::Anonymous,
                issued_token_type: UAString::null(),
                issuer_endpoint_url: UAString::null(),
                security_policy_uri: UAString::null(),
            });
        }
        // User pass policy
        if endpoint.user_token_ids.iter().any(|id| {
            id != ANONYMOUS_USER_TOKEN_ID
                && self.users.get(id).is_some_and(|token| token.is_user_pass())
        }) {
            // The endpoint may set a password security policy
            user_identity_tokens.push(UserTokenPolicy {
                policy_id: user_pass_security_policy_id(endpoint),
                token_type: UserTokenType::UserName,
                issued_token_type: UAString::null(),
                issuer_endpoint_url: UAString::null(),
                security_policy_uri: user_pass_security_policy_uri(endpoint),
            });
        }
        // X509 policy
        if endpoint.user_token_ids.iter().any(|id| {
            id != ANONYMOUS_USER_TOKEN_ID && self.users.get(id).is_some_and(|token| token.is_x509())
        }) {
            user_identity_tokens.push(UserTokenPolicy {
                policy_id: UAString::from(POLICY_ID_X509),
                token_type: UserTokenType::Certificate,
                issued_token_type: UAString::null(),
                issuer_endpoint_url: UAString::null(),
                security_policy_uri: UAString::from(SecurityPolicy::Basic128Rsa15.to_uri()),
            });
        }

        if user_identity_tokens.is_empty() {
            debug!(
                "user_identity_tokens() returned zero endpoints for endpoint {} / {} {}",
                endpoint.path, endpoint.security_policy, endpoint.security_mode
            );
        }

        user_identity_tokens
    }

    fn core_permissions(&self, token: &UserToken) -> CoreServerPermissions {
        self.users
            .get(token.0.as_str())
            .map(|r| CoreServerPermissions {
                read_diagnostics: r.read_diagnostics,
            })
            .unwrap_or_default()
    }
}

/// Get the username and password policy ID for the given endpioint.
pub fn user_pass_security_policy_id(endpoint: &ServerEndpoint) -> UAString {
    match endpoint.password_security_policy() {
        SecurityPolicy::None => POLICY_ID_USER_PASS_NONE,
        SecurityPolicy::Basic128Rsa15 => POLICY_ID_USER_PASS_RSA_15,
        SecurityPolicy::Basic256 | SecurityPolicy::Basic256Sha256 => POLICY_ID_USER_PASS_RSA_OAEP,
        // TODO this is a placeholder
        SecurityPolicy::Aes128Sha256RsaOaep | SecurityPolicy::Aes256Sha256RsaPss => {
            POLICY_ID_USER_PASS_RSA_OAEP
        }
        _ => {
            panic!()
        }
    }
    .into()
}

/// Get the username and password policy URI for the given endpioint.
pub fn user_pass_security_policy_uri(_endpoint: &ServerEndpoint) -> UAString {
    // TODO we could force the security policy uri for passwords to be something other than the default
    //  here to ensure they're secure even when the endpoint's security policy is None.
    UAString::null()
}
