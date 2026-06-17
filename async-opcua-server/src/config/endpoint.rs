use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use serde::{Deserialize, Serialize};

use opcua_crypto::SecurityPolicy;
use opcua_types::MessageSecurityMode;

use super::server::{ServerUserToken, ANONYMOUS_USER_TOKEN_ID};

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
/// A configured server endpoint.
pub struct ServerEndpoint {
    /// Endpoint path
    pub path: String,
    /// Security policy
    pub security_policy: String,
    /// Security mode
    pub security_mode: String,
    /// Security level, higher being more secure
    pub security_level: u8,
    /// Password security policy when a client supplies a user name identity token
    pub password_security_policy: Option<String>,
    /// User tokens
    pub user_token_ids: BTreeSet<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Hash, Eq)]
/// Unique ID of an endpoint.
pub struct EndpointIdentifier {
    /// Endpoint path
    pub path: String,
    /// Security policy
    pub security_policy: String,
    /// Security mode
    pub security_mode: String,
}

impl From<&ServerEndpoint> for EndpointIdentifier {
    fn from(value: &ServerEndpoint) -> Self {
        Self {
            path: value.path.clone(),
            security_policy: value.security_policy.clone(),
            security_mode: value.security_mode.clone(),
        }
    }
}

/// Convenience method to make an endpoint from a tuple
impl<'a> From<(&'a str, SecurityPolicy, MessageSecurityMode, &'a [&'a str])> for ServerEndpoint {
    fn from(v: (&'a str, SecurityPolicy, MessageSecurityMode, &'a [&'a str])) -> ServerEndpoint {
        ServerEndpoint {
            path: v.0.into(),
            security_policy: v.1.to_string(),
            security_mode: v.2.to_string(),
            security_level: Self::security_level(v.1, v.2),
            password_security_policy: None,
            user_token_ids: v.3.iter().map(|id| id.to_string()).collect(),
        }
    }
}

impl ServerEndpoint {
    /// Create a new server endpoint.
    pub fn new<T>(
        path: T,
        security_policy: SecurityPolicy,
        security_mode: MessageSecurityMode,
        user_token_ids: &[String],
    ) -> Self
    where
        T: Into<String>,
    {
        ServerEndpoint {
            path: path.into(),
            security_policy: security_policy.to_string(),
            security_mode: security_mode.to_string(),
            security_level: Self::security_level(security_policy, security_mode),
            password_security_policy: None,
            user_token_ids: user_token_ids.iter().cloned().collect(),
        }
    }

    /// Recommends a security level for the supplied security policy
    fn security_level(security_policy: SecurityPolicy, security_mode: MessageSecurityMode) -> u8 {
        let security_level = match security_policy {
            SecurityPolicy::Aes128Sha256RsaOaep => 2,
            SecurityPolicy::Basic256Sha256 => 4,
            SecurityPolicy::Aes256Sha256RsaPss => 5,
            _ => 0,
        };
        if security_mode == MessageSecurityMode::SignAndEncrypt {
            security_level + 10
        } else {
            security_level
        }
    }

    /// Create a new unsecured server endpoint.
    pub fn new_none<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::None,
            MessageSecurityMode::None,
            user_token_ids,
        )
    }

    /// Create a new server endpoint with Basic256Sha256 signing.
    pub fn new_basic256sha256_sign<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::Basic256Sha256,
            MessageSecurityMode::Sign,
            user_token_ids,
        )
    }

    /// Create a new server endpoint with Basic256Sha256 encryption.
    pub fn new_basic256sha256_sign_encrypt<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::Basic256Sha256,
            MessageSecurityMode::SignAndEncrypt,
            user_token_ids,
        )
    }

    /// Create a new server endpoint with AES128/SHA256 RSA-OAEP signing.
    pub fn new_aes128_sha256_rsaoaep_sign<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::Aes128Sha256RsaOaep,
            MessageSecurityMode::Sign,
            user_token_ids,
        )
    }

    /// Create a new server endpoint with AES128/SHA256 RSA-OAEP encryption.
    pub fn new_aes128_sha256_rsaoaep_sign_encrypt<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::Aes128Sha256RsaOaep,
            MessageSecurityMode::SignAndEncrypt,
            user_token_ids,
        )
    }

    /// Create a new server endpoint with AES128/SHA256 RSA-PSS signing.
    pub fn new_aes256_sha256_rsapss_sign<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::Aes256Sha256RsaPss,
            MessageSecurityMode::Sign,
            user_token_ids,
        )
    }

    /// Create a new server endpoint with AES128/SHA256 RSA-PSS encryption.
    pub fn new_aes256_sha256_rsapss_sign_encrypt<T>(path: T, user_token_ids: &[String]) -> Self
    where
        T: Into<String>,
    {
        Self::new(
            path,
            SecurityPolicy::Aes256Sha256RsaPss,
            MessageSecurityMode::SignAndEncrypt,
            user_token_ids,
        )
    }

    /// Validate the endpoint and return a list of validation errors.
    pub fn validate(
        &self,
        id: &str,
        user_tokens: &BTreeMap<String, ServerUserToken>,
        allow_legacy_crypto: bool,
    ) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Validate that the user token ids exist
        for id in &self.user_token_ids {
            // Skip anonymous
            if id == ANONYMOUS_USER_TOKEN_ID {
                continue;
            }
            if !user_tokens.contains_key(id) {
                errors.push(format!("Cannot find user token with id {id}"));
            }
        }

        if let Some(ref password_security_policy) = self.password_security_policy {
            let parsed_password_security_policy =
                SecurityPolicy::from_str(password_security_policy).unwrap();
            if parsed_password_security_policy == SecurityPolicy::Unknown {
                errors.push(format!("Endpoint {id} is invalid. Password security policy \"{password_security_policy}\" is invalid. Valid values are None, Basic256Sha256, Aes128Sha256RsaOaep, Aes256Sha256RsaPss"));
            } else if let Some(error) =
                legacy_policy_error(id, parsed_password_security_policy, allow_legacy_crypto)
            {
                errors.push(error);
            }
        }

        // Validate the security policy and mode
        let security_policy = SecurityPolicy::from_str(&self.security_policy).unwrap();
        let security_mode = MessageSecurityMode::from(self.security_mode.as_ref());
        if security_policy == SecurityPolicy::Unknown {
            errors.push(format!("Endpoint {} is invalid. Security policy \"{}\" is invalid. Valid values are None, Basic256Sha256, Aes128Sha256RsaOaep, Aes256Sha256RsaPss", id, self.security_policy));
        } else if let Some(error) = legacy_policy_error(id, security_policy, allow_legacy_crypto) {
            errors.push(error);
        } else if security_mode == MessageSecurityMode::Invalid {
            errors.push(format!("Endpoint {} is invalid. Security mode \"{}\" is invalid. Valid values are None, Sign, SignAndEncrypt", id, self.security_mode));
        } else if (security_policy == SecurityPolicy::None
            && security_mode != MessageSecurityMode::None)
            || (security_policy != SecurityPolicy::None
                && security_mode == MessageSecurityMode::None)
        {
            errors.push(format!("Endpoint {id} is invalid. Security policy and security mode must both contain None or neither of them should (1)."));
        } else if security_policy != SecurityPolicy::None
            && security_mode == MessageSecurityMode::None
        {
            errors.push(format!("Endpoint {id} is invalid. Security policy and security mode must both contain None or neither of them should (2)."));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Get the security policy of this endpoint.
    pub fn security_policy(&self) -> SecurityPolicy {
        SecurityPolicy::from_str(&self.security_policy).unwrap()
    }

    /// Get the message security mode of this endpoint.
    pub fn message_security_mode(&self) -> MessageSecurityMode {
        MessageSecurityMode::from(self.security_mode.as_ref())
    }

    /// Get the URL of this endpoint, with `base_endpoint` as root.
    pub fn endpoint_url(&self, base_endpoint: &str) -> String {
        format!("{}{}", base_endpoint, self.path)
    }

    /// Returns the effective password security policy for the endpoint. This is the explicitly set password
    /// security policy, or just the regular security policy.
    pub fn password_security_policy(&self) -> SecurityPolicy {
        let mut password_security_policy = self.security_policy();
        if let Some(ref security_policy) = self.password_security_policy {
            match SecurityPolicy::from_str(security_policy).unwrap() {
                SecurityPolicy::Unknown => {
                    tracing::error!("Password security policy {security_policy} is unrecognized");
                    password_security_policy = SecurityPolicy::None;
                }
                security_policy => {
                    password_security_policy = security_policy;
                }
            }
        }
        password_security_policy
    }
}

/// Returns the validation error for a legacy (deprecated) security policy
/// that is not currently usable, either because the deployment has not
/// opted in via `allow_legacy_crypto` or because the build excludes the
/// `legacy-crypto` feature.
fn legacy_policy_error(
    id: &str,
    policy: SecurityPolicy,
    allow_legacy_crypto: bool,
) -> Option<String> {
    if !policy.is_deprecated() {
        return None;
    }
    if !policy.is_supported() {
        Some(format!(
            "Endpoint {id} is invalid. Security policy \"{policy}\" is deprecated and this build does not include the 'legacy-crypto' feature."
        ))
    } else if !allow_legacy_crypto {
        Some(format!(
            "Endpoint {id} is invalid. Security policy \"{policy}\" is deprecated and disabled by default. Set allow_legacy_crypto: true in the server configuration to enable it."
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_security_policy_message_excludes_legacy_policies() {
        let user_tokens = BTreeMap::new();
        let endpoint = ServerEndpoint {
            path: "/".to_string(),
            security_policy: "InvalidPolicy".to_string(),
            security_mode: "Sign".to_string(),
            security_level: 0,
            password_security_policy: None,
            user_token_ids: BTreeSet::new(),
        };

        let errors = endpoint
            .validate("invalid", &user_tokens, false)
            .unwrap_err();
        let message = errors.join("\n");

        assert_eq!(
            message,
            "Endpoint invalid is invalid. Security policy \"InvalidPolicy\" is invalid. Valid values are None, Basic256Sha256, Aes128Sha256RsaOaep, Aes256Sha256RsaPss"
        );
    }

    /// L8: an unrecognized `password_security_policy` on a programmatically-built endpoint
    /// (one that skipped `validate()`) must NOT panic on the auth hot path; it falls back
    /// to the safe default (None).
    #[test]
    fn invalid_password_security_policy_does_not_panic() {
        let endpoint = ServerEndpoint {
            path: "/".to_string(),
            security_policy: "None".to_string(),
            security_mode: "None".to_string(),
            security_level: 0,
            password_security_policy: Some("InvalidPolicy".to_string()),
            user_token_ids: BTreeSet::new(),
        };
        assert_eq!(endpoint.password_security_policy(), SecurityPolicy::None);
    }

    #[test]
    fn legacy_policy_rejected_by_default_with_actionable_message() {
        let user_tokens = BTreeMap::new();
        let endpoint = ServerEndpoint {
            path: "/".to_string(),
            security_policy: "Basic256".to_string(),
            security_mode: "SignAndEncrypt".to_string(),
            security_level: 0,
            password_security_policy: None,
            user_token_ids: BTreeSet::new(),
        };

        let errors = endpoint
            .validate("legacy", &user_tokens, false)
            .unwrap_err();
        let message = errors.join("\n");
        assert!(
            message.contains("allow_legacy_crypto") || message.contains("legacy-crypto"),
            "error must name the runtime switch or missing feature: {message}"
        );
    }

    #[test]
    fn legacy_policy_accepted_when_allowed() {
        if !SecurityPolicy::Basic128Rsa15.is_supported() {
            // Build without the legacy-crypto feature.
            return;
        }
        let user_tokens = BTreeMap::new();
        let endpoint = ServerEndpoint {
            path: "/".to_string(),
            security_policy: "Basic128Rsa15".to_string(),
            security_mode: "Sign".to_string(),
            security_level: 0,
            password_security_policy: None,
            user_token_ids: BTreeSet::new(),
        };

        assert!(endpoint.validate("legacy", &user_tokens, true).is_ok());
    }

    #[test]
    fn legacy_password_policy_follows_the_same_rules() {
        let user_tokens = BTreeMap::new();
        let mut endpoint = ServerEndpoint::new_basic256sha256_sign("/", &[]);
        endpoint.password_security_policy = Some("Basic128Rsa15".to_string());

        let errors = endpoint
            .validate("legacy", &user_tokens, false)
            .unwrap_err();
        let message = errors.join("\n");
        assert!(
            message.contains("allow_legacy_crypto") || message.contains("legacy-crypto"),
            "error must name the runtime switch or missing feature: {message}"
        );

        if SecurityPolicy::Basic128Rsa15.is_supported() {
            assert!(endpoint.validate("legacy", &user_tokens, true).is_ok());
        }
    }

    #[test]
    fn invalid_password_security_policy_message_excludes_legacy_policies() {
        let user_tokens = BTreeMap::new();
        let mut endpoint = ServerEndpoint::new_basic256sha256_sign("/", &[]);
        endpoint.password_security_policy = Some("InvalidPolicy".to_string());

        let errors = endpoint
            .validate("invalid", &user_tokens, false)
            .unwrap_err();
        let message = errors.join("\n");

        assert_eq!(
            message,
            "Endpoint invalid is invalid. Password security policy \"InvalidPolicy\" is invalid. Valid values are None, Basic256Sha256, Aes128Sha256RsaOaep, Aes256Sha256RsaPss"
        );
    }

    #[test]
    fn basic256sha256_convenience_constructors_remain() {
        let user_token_ids = [];

        let sign = ServerEndpoint::new_basic256sha256_sign("/", &user_token_ids);
        let sign_encrypt = ServerEndpoint::new_basic256sha256_sign_encrypt("/", &user_token_ids);

        assert_eq!(sign.security_policy(), SecurityPolicy::Basic256Sha256);
        assert_eq!(sign.message_security_mode(), MessageSecurityMode::Sign);
        assert_eq!(
            sign_encrypt.security_policy(),
            SecurityPolicy::Basic256Sha256
        );
        assert_eq!(
            sign_encrypt.message_security_mode(),
            MessageSecurityMode::SignAndEncrypt
        );
    }
}
