#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::{error::Error as StdError, fmt, time::Duration};

use opcua_crypto::{
    identity::decrypt_rsa_oaep_secret, legacy_decrypt_secret, LegacySecret, PrivateKey,
    SecurityPolicy,
};
use opcua_types::{ByteString, Error, IssuedIdentityToken, StatusCode, UserNameIdentityToken};

const IDENTITY_TOKEN_VALIDATION_TARPIT: Duration = Duration::from_millis(100);

/// Per-activation context needed to decrypt an ECC `EccEncryptedSecret` identity-token secret.
#[derive(Default)]
pub(crate) struct EccSecretContext {
    #[cfg(feature = "ecc")]
    pub(crate) server_ephemeral: Option<opcua_crypto::ecc::EphemeralPrivateKey>,
    #[cfg(feature = "ecc")]
    pub(crate) client_certificate: Option<opcua_crypto::X509>,
}

/// Delays failed identity-token validation without blocking Tokio workers.
pub(crate) async fn tarpit_identity_token_validation_failure(error: Error) -> Error {
    let status = error.status();
    let preserve_status = preserves_identity_token_failure_status(status)
        || is_identity_token_policy_protection_failure(&error);
    tokio::time::sleep(IDENTITY_TOKEN_VALIDATION_TARPIT).await;
    if preserve_status {
        return error;
    }
    Error::new(
        StatusCode::BadUserAccessDenied,
        format!("Identity token validation failed: {error}"),
    )
}

fn preserves_identity_token_failure_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::BadUserSignatureInvalid
            | StatusCode::BadCertificateInvalid
            | StatusCode::BadCertificateTimeInvalid
            | StatusCode::BadCertificateIssuerTimeInvalid
            | StatusCode::BadCertificateHostNameInvalid
            | StatusCode::BadCertificateUriInvalid
            | StatusCode::BadCertificateUseNotAllowed
            | StatusCode::BadCertificateIssuerUseNotAllowed
            | StatusCode::BadCertificateUntrusted
            | StatusCode::BadCertificateRevocationUnknown
            | StatusCode::BadCertificateIssuerRevocationUnknown
            | StatusCode::BadCertificateRevoked
            | StatusCode::BadCertificateIssuerRevoked
            | StatusCode::BadCertificateChainIncomplete
            | StatusCode::BadCertificatePolicyCheckFailed
    )
}

fn is_identity_token_policy_protection_failure(error: &Error) -> bool {
    StdError::source(error).is_some_and(|source| source.is::<IdentityTokenPolicyProtectionError>())
}

#[derive(Debug)]
struct IdentityTokenPolicyProtectionError(&'static str);

impl fmt::Display for IdentityTokenPolicyProtectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl StdError for IdentityTokenPolicyProtectionError {}

fn identity_token_policy_protection_error(message: &'static str) -> Error {
    Error::new(
        StatusCode::BadIdentityTokenInvalid,
        IdentityTokenPolicyProtectionError(message),
    )
}

/// Delays any failed authentication result without blocking Tokio workers.
pub(crate) async fn tarpit_authentication_failure<T>(result: Result<T, Error>) -> Result<T, Error> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => Err(tarpit_identity_token_validation_failure(error).await),
    }
}

/// Validate that a username/password identity token is protected as required by its policy.
pub(crate) fn validate_username_password_token_protection(
    token: &UserNameIdentityToken,
    token_security_policy: SecurityPolicy,
) -> Result<(), Error> {
    if token_security_policy != SecurityPolicy::None
        && token.encryption_algorithm.is_empty()
        && !is_ecc_user_token_policy(token_security_policy)
    {
        return Err(identity_token_policy_protection_error(
            "Username/password identity token is not encrypted as required by UserTokenPolicy",
        ));
    }

    Ok(())
}

/// Returns whether the username/password token secret must be decrypted before authentication.
pub(crate) fn username_password_secret_needs_decrypt(
    token: &UserNameIdentityToken,
    token_security_policy: SecurityPolicy,
) -> bool {
    !token.encryption_algorithm.is_empty() || is_ecc_user_token_policy(token_security_policy)
}

/// Validate that an issued identity token is protected as required by its policy.
pub(crate) fn validate_issued_token_protection(
    token: &IssuedIdentityToken,
    token_security_policy: SecurityPolicy,
) -> Result<(), Error> {
    if token_security_policy != SecurityPolicy::None
        && token.encryption_algorithm.is_empty()
        && !is_ecc_user_token_policy(token_security_policy)
    {
        return Err(identity_token_policy_protection_error(
            "Issued identity token is not encrypted as required by UserTokenPolicy",
        ));
    }

    Ok(())
}

/// Returns whether the issued token secret must be decrypted before validation.
pub(crate) fn issued_token_secret_needs_decrypt(
    token: &IssuedIdentityToken,
    token_security_policy: SecurityPolicy,
) -> bool {
    !token.encryption_algorithm.is_empty() || is_ecc_user_token_policy(token_security_policy)
}

/// Decrypts an ActivateSession identity-token secret.
// `security_policy` / `ecc_ctx` are only consumed by the ECC branch below.
#[cfg_attr(not(feature = "ecc"), allow(unused_variables))]
pub(crate) fn decrypt_identity_token_secret(
    secret: &impl LegacySecret,
    server_nonce: &[u8],
    security_policy: SecurityPolicy,
    server_key: &Option<PrivateKey>,
    ecc_ctx: &EccSecretContext,
) -> Result<ByteString, Error> {
    #[cfg(feature = "ecc")]
    if matches!(
        security_policy,
        SecurityPolicy::EccNistP256 | SecurityPolicy::EccNistP384
    ) {
        let (Some(eph), Some(cert)) = (&ecc_ctx.server_ephemeral, &ecc_ctx.client_certificate)
        else {
            return Err(Error::new(
                StatusCode::BadIdentityTokenRejected,
                "identity token rejected",
            ));
        };
        return opcua_crypto::ecc::ecc_decrypt_secret(
            security_policy,
            secret.raw_secret().as_ref(),
            server_nonce,
            eph,
            cert,
        );
    }

    if secret.encryption_algorithm().is_empty() {
        return Ok(secret.raw_secret().clone());
    }

    let Some(server_key) = server_key else {
        return Err(Error::new(
            StatusCode::BadIdentityTokenInvalid,
            "Identity token is encrypted but no server private key was supplied",
        ));
    };

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

fn is_ecc_user_token_policy(security_policy: SecurityPolicy) -> bool {
    matches!(
        security_policy,
        SecurityPolicy::EccNistP256 | SecurityPolicy::EccNistP384
    )
}

#[cfg(all(test, feature = "ecc"))]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod ecc_routing_tests {
    //! Server-side routing test for the ECC `EccEncryptedSecret` identity-token path (feature 016 T009).
    //! Independent of the crypto-crate tests: it drives `decrypt_identity_token_secret` (the server's
    //! policy routing + `EccSecretContext` plumbing) using the public `ecc_encrypt_secret` producer.
    use super::{decrypt_identity_token_secret, EccSecretContext};
    use opcua_crypto::ecc::{
        ecc_encrypt_secret, generate_ephemeral_keypair, EccCurve, EphemeralPrivateKey,
    };
    use opcua_crypto::{SecurityPolicy, X509Data, X509};
    use opcua_types::{ByteString, IssuedIdentityToken, UserNameIdentityToken};

    fn ec_cert(curve: EccCurve) -> (X509, opcua_crypto::PrivateKey) {
        let data = X509Data {
            key_size: 0,
            common_name: "ecc routing test".to_string(),
            organization: "t".to_string(),
            organizational_unit: "t".to_string(),
            country: "IE".to_string(),
            state: "t".to_string(),
            alt_host_names: vec!["urn:t".to_string(), "localhost".to_string()].into(),
            certificate_duration_days: 60,
        };
        X509::cert_and_pkey_ecc(curve, &data).expect("ec cert")
    }

    #[test]
    fn routes_ecc_username_secret_through_ecc_decrypt() {
        let policy = SecurityPolicy::EccNistP256;
        let curve = EccCurve::P256;
        let (client_cert, client_key) = ec_cert(curve);
        let server_kp = generate_ephemeral_keypair(curve).expect("server kp");
        let server_pub = server_kp.public_key().clone();
        let server_priv_scalar = server_kp.private_key().scalar().to_vec();
        let server_nonce = vec![0x42u8; 32];
        let password = b"ecc-routed-password";

        let secret_bytes = ecc_encrypt_secret(
            policy,
            &server_nonce,
            &server_pub,
            &client_key,
            &client_cert,
            password,
        )
        .expect("encrypt");

        let token = UserNameIdentityToken {
            password: ByteString::from(secret_bytes),
            ..Default::default()
        };

        let ctx = EccSecretContext {
            server_ephemeral: Some(
                EphemeralPrivateKey::from_scalar_bytes(curve, &server_priv_scalar).unwrap(),
            ),
            client_certificate: Some(client_cert.clone()),
        };

        let recovered =
            decrypt_identity_token_secret(&token, &server_nonce, policy, &None, &ctx).unwrap();
        assert_eq!(recovered.as_ref(), &password[..]);

        // Missing ECC context -> uniform reject (no server ephemeral / client cert).
        let empty = EccSecretContext::default();
        assert!(
            decrypt_identity_token_secret(&token, &server_nonce, policy, &None, &empty).is_err()
        );

        // Wrong server nonce -> reject.
        assert!(decrypt_identity_token_secret(&token, &[0u8; 32], policy, &None, &ctx).is_err());
    }

    /// US3: the same ECC routing applies to an `IssuedIdentityToken` (its `token_data` is the secret).
    #[test]
    fn routes_ecc_issued_secret_through_ecc_decrypt() {
        let policy = SecurityPolicy::EccNistP384;
        let curve = EccCurve::P384;
        let (client_cert, client_key) = ec_cert(curve);
        let server_kp = generate_ephemeral_keypair(curve).expect("server kp");
        let server_pub = server_kp.public_key().clone();
        let server_priv_scalar = server_kp.private_key().scalar().to_vec();
        let server_nonce = vec![0x7Eu8; 32];
        let token_data = b"issued-jwt-bytes-over-ecc";

        let secret_bytes = ecc_encrypt_secret(
            policy,
            &server_nonce,
            &server_pub,
            &client_key,
            &client_cert,
            token_data,
        )
        .expect("encrypt");

        let token = IssuedIdentityToken {
            token_data: ByteString::from(secret_bytes),
            ..Default::default()
        };
        let ctx = EccSecretContext {
            server_ephemeral: Some(
                EphemeralPrivateKey::from_scalar_bytes(curve, &server_priv_scalar).unwrap(),
            ),
            client_certificate: Some(client_cert.clone()),
        };

        let recovered =
            decrypt_identity_token_secret(&token, &server_nonce, policy, &None, &ctx).unwrap();
        assert_eq!(recovered.as_ref(), &token_data[..]);
        // Wrong nonce -> reject.
        assert!(decrypt_identity_token_secret(&token, &[0u8; 32], policy, &None, &ctx).is_err());
    }
}
