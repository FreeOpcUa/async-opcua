//! Independent tests for FX piece 6: Part-14 SetSecurityKeys (key push) on SecurityKeyService.

use opcua_server::services::security::{
    GetSecurityKeysRequest, SecurityKeyService, SetSecurityKeysRequest, CURRENT_SECURITY_TOKEN_ID,
};
use opcua_types::{ByteString, StatusCode};

const POLICY: &str = "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss";

fn bs(s: &str) -> ByteString {
    ByteString::from(s.as_bytes())
}

fn push(group: &str) -> SetSecurityKeysRequest {
    SetSecurityKeysRequest::new(
        group,
        POLICY,
        5,                        // current_token_id
        bs("k5"),                 // current_key
        vec![bs("k6"), bs("k7")], // future_keys
        1_000.0,                  // time_to_next_key (ms)
        2_000.0,                  // key_lifetime (ms)
    )
}

#[test]
fn pushed_keys_are_retrievable_via_get() {
    let service = SecurityKeyService::new();
    service.set_security_keys(push("group-1")).unwrap();

    let resp = service
        .get_security_keys(GetSecurityKeysRequest::new(
            "group-1",
            CURRENT_SECURITY_TOKEN_ID,
            3,
        ))
        .unwrap();

    assert_eq!(resp.security_policy_uri.as_ref(), POLICY);
    assert_eq!(resp.first_token_id, 5);
    assert_eq!(resp.keys, vec![bs("k5"), bs("k6"), bs("k7")]);
    assert_eq!(resp.key_lifetime, 2_000.0);
    // time_to_next_key was pushed as ~1000ms remaining.
    assert!(resp.time_to_next_key <= 1_000.0 && resp.time_to_next_key > 500.0);
}

#[test]
fn pushed_future_token_resolves_to_later_keys() {
    let service = SecurityKeyService::new();
    service.set_security_keys(push("group-1")).unwrap();

    // Start at token 6 -> [k6, k7].
    let resp = service
        .get_security_keys(GetSecurityKeysRequest::new("group-1", 6, 5))
        .unwrap();
    assert_eq!(resp.first_token_id, 6);
    assert_eq!(resp.keys, vec![bs("k6"), bs("k7")]);
}

#[test]
fn set_security_keys_replaces_existing_material() {
    let service = SecurityKeyService::new();
    service.set_security_keys(push("group-1")).unwrap();

    let replacement =
        SetSecurityKeysRequest::new("group-1", POLICY, 10, bs("new"), vec![], 2_000.0, 2_000.0);
    service.set_security_keys(replacement).unwrap();

    let resp = service
        .get_security_keys(GetSecurityKeysRequest::new(
            "group-1",
            CURRENT_SECURITY_TOKEN_ID,
            5,
        ))
        .unwrap();
    assert_eq!(resp.first_token_id, 10);
    assert_eq!(resp.keys, vec![bs("new")]);
}

#[test]
fn set_security_keys_rejects_invalid_requests() {
    let service = SecurityKeyService::new();

    // Empty group id.
    let mut bad = push("");
    assert_eq!(
        service.set_security_keys(bad).unwrap_err(),
        StatusCode::BadInvalidArgument
    );
    // Empty policy uri.
    bad = push("group-1");
    bad.security_policy_uri = "".into();
    assert_eq!(
        service.set_security_keys(bad).unwrap_err(),
        StatusCode::BadInvalidArgument
    );
    // Null current key.
    bad = push("group-1");
    bad.current_key = ByteString::null();
    assert_eq!(
        service.set_security_keys(bad).unwrap_err(),
        StatusCode::BadInvalidArgument
    );
    // Zero key lifetime.
    bad = push("group-1");
    bad.key_lifetime = 0.0;
    assert_eq!(
        service.set_security_keys(bad).unwrap_err(),
        StatusCode::BadInvalidArgument
    );
}
