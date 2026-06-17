use std::{
    fs::File,
    io::Write,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use parking_lot::RwLock;
use serde_json::json;

use crate::{
    certificate_store::CertificateStore,
    identity::{
        decrypt_rsa_oaep_secret, ClaimProfile, LocalOAuth2Validator, OAuth2IdentityValidator,
    },
    tests::{make_certificate_store, make_test_cert_2048},
    KeySize, PrivateKey, SecurityPolicy,
};
use opcua_types::status_code::StatusCode;

struct TestIdentityValidator;

impl OAuth2IdentityValidator for TestIdentityValidator {
    fn validate_token(&self, token_jwt: &str) -> Result<ClaimProfile, StatusCode> {
        if token_jwt == "valid.jwt" {
            Ok(ClaimProfile {
                username: "operator".to_string(),
                roles: vec!["brewer".to_string()],
                permissions: vec!["read".to_string()],
            })
        } else {
            Err(StatusCode::BadIdentityTokenInvalid)
        }
    }
}

#[test]
fn oauth2_identity_validator_returns_claim_profile() {
    let validator = TestIdentityValidator;

    let profile = validator.validate_token("valid.jwt").unwrap();

    assert_eq!(profile.username, "operator");
    assert_eq!(profile.roles, vec!["brewer"]);
    assert_eq!(profile.permissions, vec!["read"]);
    assert!(matches!(
        validator.validate_token("invalid.jwt"),
        Err(StatusCode::BadIdentityTokenInvalid)
    ));
}

fn create_signed_jwt(payload: serde_json::Value, private_key: &PrivateKey) -> String {
    let header = json!({"alg": "RS256", "typ": "JWT"});
    let encoded_header = BASE64_URL_SAFE_NO_PAD.encode(header.to_string());
    let encoded_payload = BASE64_URL_SAFE_NO_PAD.encode(payload.to_string());
    let signing_input = format!("{encoded_header}.{encoded_payload}");
    let mut signature = [0u8; 256];
    let signature_len = private_key
        .sign_sha256(signing_input.as_bytes(), &mut signature)
        .unwrap();
    let encoded_signature = BASE64_URL_SAFE_NO_PAD.encode(&signature[..signature_len]);

    format!("{signing_input}.{encoded_signature}")
}

fn create_trusted_validator() -> (tempdir::TempDir, LocalOAuth2Validator, PrivateKey) {
    let (tmp_dir, cert_store) = make_certificate_store();
    let (cert, private_key) = make_test_cert_2048();
    let mut cert_path = cert_store.trusted_certs_dir();
    cert_path.push(CertificateStore::cert_file_name(&cert));

    let mut file = File::create(cert_path).unwrap();
    file.write_all(&cert.to_der().unwrap()).unwrap();

    let validator = LocalOAuth2Validator::new(
        Arc::new(RwLock::new(cert_store)),
        "https://issuer.example".to_string(),
        "opcua-server".to_string(),
    );

    (tmp_dir, validator, private_key)
}

fn future_expiration() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 3600
}

#[test]
fn local_oauth2_validator_accepts_valid_bearer_token() {
    let (_tmp_dir, validator, private_key) = create_trusted_validator();
    let token = create_signed_jwt(
        json!({
            "iss": "https://issuer.example",
            "aud": ["engineering-tools", "opcua-server"],
            "exp": future_expiration(),
            "sub": "operator",
            "roles": ["brewer", "maintenance"],
            "permissions": ["read", "write"]
        }),
        &private_key,
    );

    let profile = validator
        .validate_token(&format!("Bearer {token}"))
        .expect("valid signed JWT should be accepted");

    assert_eq!(profile.username, "operator");
    assert_eq!(profile.roles, vec!["brewer", "maintenance"]);
    assert_eq!(profile.permissions, vec!["read", "write"]);
}

#[test]
fn local_oauth2_validator_rejects_invalid_audience() {
    let (_tmp_dir, validator, private_key) = create_trusted_validator();
    let token = create_signed_jwt(
        json!({
            "iss": "https://issuer.example",
            "aud": "wrong-audience",
            "exp": future_expiration(),
            "sub": "operator"
        }),
        &private_key,
    );

    assert!(matches!(
        validator.validate_token(&token),
        Err(StatusCode::BadIdentityTokenRejected)
    ));
}

fn rsa_encrypt(policy: SecurityPolicy, private_key: &PrivateKey, plaintext: &[u8]) -> Vec<u8> {
    let public_key = private_key.to_public_key();
    let mut ciphertext = vec![0u8; policy.calculate_cipher_text_size(plaintext.len(), &public_key)];
    let ciphertext_len = policy
        .asymmetric_encrypt(&public_key, plaintext, &mut ciphertext)
        .unwrap();
    ciphertext.truncate(ciphertext_len);
    ciphertext
}

#[test]
fn rsa_oaep_secret_decrypts_supported_algorithms() {
    let private_key = PrivateKey::new(2048).unwrap();
    let secret = b"operator-password";

    for (policy, algorithm) in [
        (
            SecurityPolicy::Aes128Sha256RsaOaep,
            crate::algorithms::ENC_RSA_OAEP,
        ),
        (
            SecurityPolicy::Aes256Sha256RsaPss,
            crate::algorithms::ENC_RSA_OAEP_SHA256,
        ),
    ] {
        let ciphertext = rsa_encrypt(policy, &private_key, secret);

        let plaintext = decrypt_rsa_oaep_secret(algorithm, &ciphertext, &private_key).unwrap();

        assert_eq!(plaintext, secret);
    }
}

#[test]
fn rsa_oaep_secret_rejects_partial_ciphertext_block() {
    let private_key = PrivateKey::new(2048).unwrap();
    let short_ciphertext = vec![0u8; private_key.cipher_text_block_size() - 1];

    let err = decrypt_rsa_oaep_secret(
        crate::algorithms::ENC_RSA_OAEP,
        &short_ciphertext,
        &private_key,
    )
    .unwrap_err();

    assert_eq!(err.status(), StatusCode::BadIdentityTokenInvalid);
}

#[test]
fn legacy_secret_rejects_partial_ciphertext_block() {
    // C2: a non-block-aligned legacy ciphertext must be rejected with an error,
    // not panic via an out-of-bounds slice in private_decrypt.
    let private_key = PrivateKey::new(2048).unwrap();
    let server_nonce = [0u8; 32];
    let short = opcua_types::ByteString::from(vec![0u8; private_key.cipher_text_block_size() - 1]);
    let err = crate::user_identity::legacy_secret_decrypt::<crate::policy::aes::Pkcs1v15>(
        &short,
        &server_nonce,
        &private_key,
    )
    .unwrap_err();
    assert_eq!(err.status(), StatusCode::BadIdentityTokenInvalid);
}

#[test]
fn legacy_secret_rejects_empty_ciphertext() {
    // C2: empty ciphertext must be rejected, not panic.
    let private_key = PrivateKey::new(2048).unwrap();
    let server_nonce = [0u8; 32];
    let err = crate::user_identity::legacy_secret_decrypt::<crate::policy::aes::Pkcs1v15>(
        &opcua_types::ByteString::null(),
        &server_nonce,
        &private_key,
    )
    .unwrap_err();
    assert_eq!(err.status(), StatusCode::BadIdentityTokenInvalid);
}
