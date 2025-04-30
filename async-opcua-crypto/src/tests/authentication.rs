use opcua_types::{
    ByteString, MessageSecurityMode, UAString, UserNameIdentityToken, UserTokenType,
};

use crate::{
    self as crypto, legacy_decrypt_secret, legacy_encrypt_secret, random, tests::*, SecurityPolicy,
};

#[test]
fn user_name_identity_token_valid() {
    let mut id = UserNameIdentityToken {
        policy_id: UAString::null(),
        user_name: UAString::null(),
        password: ByteString::null(),
        encryption_algorithm: UAString::null(),
    };
    assert!(!id.is_valid());
    id.user_name = UAString::from("x");
    assert!(!id.is_valid());
    id.user_name = UAString::null();
    id.password = ByteString::from(b"xyz");
    assert!(!id.is_valid());
    id.user_name = UAString::from("x");
    assert!(id.is_valid());
}

#[test]
fn user_name_identity_token_encrypted() {
    let password = String::from("abcdef123456");
    let nonce = random::byte_string(20);
    let (cert, pkey) = make_test_cert_1024();
    let cert = Some(cert);

    let mut user_token_policy = opcua_types::UserTokenPolicy {
        policy_id: UAString::from("x"),
        token_type: UserTokenType::UserName,
        issued_token_type: UAString::null(),
        issuer_endpoint_url: UAString::null(),
        security_policy_uri: UAString::null(),
    };

    // These tests correspond to rows in OPC UA Part 4, table 179. Using various combinations
    // of secure channel security policy and user token security policy, we expect plaintext,
    // or the correct encryption to happen.

    // #1 This should be plaintext since channel security policy is none, token policy is empty
    let token = legacy_encrypt_secret(
        SecurityPolicy::None,
        MessageSecurityMode::None,
        &user_token_policy,
        nonce.as_ref(),
        &cert,
        password.as_bytes(),
    )
    .unwrap();
    assert!(token.encryption_algorithm.is_null());
    assert_eq!(token.secret.as_ref(), password.as_bytes());
    let password1 = legacy_decrypt_secret(&token, nonce.as_ref(), &pkey).unwrap();
    assert_eq!(
        password,
        String::from_utf8(password1.value.unwrap()).unwrap()
    );

    // #2 This should be plaintext since channel security policy is none, token policy is none
    user_token_policy.security_policy_uri = UAString::from(SecurityPolicy::None.to_uri());
    let token = legacy_encrypt_secret(
        SecurityPolicy::None,
        MessageSecurityMode::None,
        &user_token_policy,
        nonce.as_ref(),
        &cert,
        password.as_bytes(),
    )
    .unwrap();
    assert!(token.encryption_algorithm.is_null());
    assert_eq!(token.secret.as_ref(), password.as_bytes());
    let password1 = legacy_decrypt_secret(&token, nonce.as_ref(), &pkey).unwrap();
    assert_eq!(
        password,
        String::from_utf8(password1.value.unwrap()).unwrap()
    );

    // #3 This should be Rsa15 since channel security policy is none, token policy is Rsa15
    user_token_policy.security_policy_uri = UAString::from(SecurityPolicy::Basic128Rsa15.to_uri());
    let token = legacy_encrypt_secret(
        SecurityPolicy::None,
        MessageSecurityMode::None,
        &user_token_policy,
        nonce.as_ref(),
        &cert,
        password.as_bytes(),
    )
    .unwrap();
    assert_eq!(
        token.encryption_algorithm.as_ref(),
        crypto::algorithms::ENC_RSA_15
    );
    let password1 = legacy_decrypt_secret(&token, nonce.as_ref(), &pkey).unwrap();
    assert_eq!(
        password,
        String::from_utf8(password1.value.unwrap()).unwrap()
    );

    // #4 This should be Rsa-15 since channel security policy is Rsa15, token policy is empty
    user_token_policy.security_policy_uri = UAString::null();
    let token = legacy_encrypt_secret(
        SecurityPolicy::Basic128Rsa15,
        MessageSecurityMode::SignAndEncrypt,
        &user_token_policy,
        nonce.as_ref(),
        &cert,
        password.as_bytes(),
    )
    .unwrap();
    assert_eq!(
        token.encryption_algorithm.as_ref(),
        crypto::algorithms::ENC_RSA_15
    );
    let password1 = legacy_decrypt_secret(&token, nonce.as_ref(), &pkey).unwrap();
    assert_eq!(
        password,
        String::from_utf8(password1.value.unwrap()).unwrap()
    );

    // #5 This should be Rsa-OAEP since channel security policy is Rsa-15, token policy is Rsa-OAEP
    user_token_policy.security_policy_uri = UAString::from(SecurityPolicy::Basic256Sha256.to_uri());
    let token = legacy_encrypt_secret(
        SecurityPolicy::Basic128Rsa15,
        MessageSecurityMode::SignAndEncrypt,
        &user_token_policy,
        nonce.as_ref(),
        &cert,
        password.as_bytes(),
    )
    .unwrap();
    assert_eq!(
        token.encryption_algorithm.as_ref(),
        crypto::algorithms::ENC_RSA_OAEP
    );
    let password1 = legacy_decrypt_secret(&token, nonce.as_ref(), &pkey).unwrap();
    assert_eq!(
        password,
        String::from_utf8(password1.value.unwrap()).unwrap()
    );

    // #6 This should be Rsa-OAEP since channel security policy is Rsa-OAEP,  token policy is Rsa-OAEP
    user_token_policy.security_policy_uri =
        UAString::from(SecurityPolicy::Aes256Sha256RsaPss.to_uri());
    let token = legacy_encrypt_secret(
        SecurityPolicy::Basic256Sha256,
        MessageSecurityMode::SignAndEncrypt,
        &user_token_policy,
        nonce.as_ref(),
        &cert,
        password.as_bytes(),
    )
    .unwrap();
    assert_eq!(
        token.encryption_algorithm.as_ref(),
        crypto::algorithms::ENC_RSA_OAEP_SHA256
    );
    let password1 = legacy_decrypt_secret(&token, nonce.as_ref(), &pkey).unwrap();
    assert_eq!(
        password,
        String::from_utf8(password1.value.unwrap()).unwrap()
    );

    // #7 This should be None since channel security policy is Rsa-15, token policy is None
    user_token_policy.security_policy_uri = UAString::from(SecurityPolicy::None.to_uri());
    let token = legacy_encrypt_secret(
        SecurityPolicy::Basic128Rsa15,
        MessageSecurityMode::SignAndEncrypt,
        &user_token_policy,
        nonce.as_ref(),
        &cert,
        password.as_bytes(),
    )
    .unwrap();
    assert!(token.encryption_algorithm.is_empty());
    let password1 = legacy_decrypt_secret(&token, nonce.as_ref(), &pkey).unwrap();
    assert_eq!(
        password,
        String::from_utf8(password1.value.unwrap()).unwrap()
    );
}
