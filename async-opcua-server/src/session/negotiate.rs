use std::time::Duration;

use opcua_crypto::{
    identity::decrypt_rsa_oaep_secret, legacy_decrypt_secret, LegacySecret, PrivateKey,
    SecurityPolicy,
};
use opcua_types::{ByteString, Error, StatusCode};

const IDENTITY_TOKEN_VALIDATION_TARPIT: Duration = Duration::from_millis(100);

/// Validates whether a secure-channel security policy is allowed by server configuration.
pub fn validate_security_policy(
    policy: SecurityPolicy,
    allow_legacy_crypto: bool,
) -> Result<(), StatusCode> {
    if policy.is_deprecated() && !allow_legacy_crypto {
        Err(StatusCode::BadSecurityPolicyRejected)
    } else {
        Ok(())
    }
}

/// Delays failed identity-token validation without blocking Tokio workers.
pub(crate) async fn tarpit_identity_token_validation_failure(error: Error) -> Error {
    tokio::time::sleep(IDENTITY_TOKEN_VALIDATION_TARPIT).await;
    Error::new(
        StatusCode::BadUserAccessDenied,
        format!("Identity token validation failed: {error}"),
    )
}

/// Delays any failed authentication result without blocking Tokio workers.
pub(crate) async fn tarpit_authentication_failure<T>(result: Result<T, Error>) -> Result<T, Error> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => Err(tarpit_identity_token_validation_failure(error).await),
    }
}

/// Decrypts an ActivateSession identity-token secret.
pub(crate) fn decrypt_identity_token_secret(
    secret: &impl LegacySecret,
    server_nonce: &[u8],
    server_key: &PrivateKey,
) -> Result<ByteString, Error> {
    if secret.encryption_algorithm().is_empty() {
        return Ok(secret.raw_secret().clone());
    }

    let encryption_algorithm = secret.encryption_algorithm().as_ref();
    if is_rsa_oaep_encrypted_secret_algorithm(encryption_algorithm) {
        legacy_decrypt_secret(secret, server_nonce, server_key).or_else(|_| {
            decrypt_rsa_oaep_secret(
                encryption_algorithm,
                secret.raw_secret().as_ref(),
                server_key,
            )
            .map(ByteString::from)
        })
    } else {
        legacy_decrypt_secret(secret, server_nonce, server_key)
    }
}

fn is_rsa_oaep_encrypted_secret_algorithm(encryption_algorithm: &str) -> bool {
    [
        SecurityPolicy::Aes128Sha256RsaOaep,
        SecurityPolicy::Basic256Sha256,
        SecurityPolicy::Aes256Sha256RsaPss,
    ]
    .into_iter()
    .filter_map(|policy| policy.asymmetric_encryption_algorithm())
    .any(|algorithm| algorithm == encryption_algorithm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_deprecated_security_policy_by_default() {
        let result = validate_security_policy(SecurityPolicy::Basic256, false);

        assert_eq!(result, Err(StatusCode::BadSecurityPolicyRejected));
    }

    #[test]
    fn allows_deprecated_security_policy_when_legacy_crypto_is_enabled() {
        let result = validate_security_policy(SecurityPolicy::Basic256, true);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn accepts_modern_security_policy_by_default() {
        let result = validate_security_policy(SecurityPolicy::Aes256Sha256RsaPss, false);

        assert_eq!(result, Ok(()));
    }
}
