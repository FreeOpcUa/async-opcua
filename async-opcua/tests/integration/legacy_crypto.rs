//! Tests for runtime-gated legacy (deprecated) security policies.

use std::time::Duration;

use crate::utils::{hostname, test_node_manager, test_server, Tester};
use opcua::client::ClientBuilder;
use opcua::{
    client::IdentityToken,
    crypto::SecurityPolicy,
    server::ServerBuilder,
    types::{EndpointDescription, MessageSecurityMode},
};
use opcua_server::ANONYMOUS_USER_TOKEN_ID;

/// A server that only offers modern endpoints and keeps the default
/// `allow_legacy_crypto: false`.
fn modern_only_server() -> ServerBuilder {
    let endpoint_path = "/";
    let user_token_ids = vec![ANONYMOUS_USER_TOKEN_ID];
    ServerBuilder::new()
        .application_name("integration_server")
        .application_uri("urn:integration_server")
        .product_uri("urn:integration_server Testkit")
        .create_sample_keypair(true)
        .host(hostname())
        .trust_client_certs(true)
        .add_endpoint(
            "none",
            (
                endpoint_path,
                SecurityPolicy::None,
                MessageSecurityMode::None,
                &user_token_ids as &[&str],
            ),
        )
        .add_endpoint(
            "basic256sha256_sign_encrypt",
            (
                endpoint_path,
                SecurityPolicy::Basic256Sha256,
                MessageSecurityMode::SignAndEncrypt,
                &user_token_ids as &[&str],
            ),
        )
        .with_node_manager(test_node_manager())
}

#[tokio::test]
async fn legacy_endpoint_not_matched_when_disallowed() {
    let mut tester = Tester::new(modern_only_server(), true).await;

    // The server neither advertises nor accepts legacy endpoints, so
    // endpoint matching must fail without establishing a session.
    let result = tester
        .connect(
            SecurityPolicy::Basic128Rsa15,
            MessageSecurityMode::SignAndEncrypt,
            IdentityToken::Anonymous,
        )
        .await;
    assert!(
        result.is_err(),
        "legacy endpoint must not match on a server with allow_legacy_crypto disabled"
    );

    // The server must still be healthy for modern connections.
    let (session, lp) = tester
        .connect(
            SecurityPolicy::Basic256Sha256,
            MessageSecurityMode::SignAndEncrypt,
            IdentityToken::Anonymous,
        )
        .await
        .unwrap();
    lp.spawn();
    tokio::time::timeout(Duration::from_secs(10), session.wait_for_connection())
        .await
        .unwrap();
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn legacy_open_secure_channel_rejected_when_disallowed() {
    let mut tester = Tester::new(modern_only_server(), true).await;

    // Fetch a real endpoint description so the legacy attempt carries the
    // server's actual certificate, then rewrite it to a legacy policy. This
    // bypasses endpoint matching and drives the OpenSecureChannel path.
    let url = tester.endpoint();
    let endpoints = tester
        .client
        .get_server_endpoints_from_url(url)
        .await
        .unwrap();
    let modern = endpoints
        .iter()
        .find(|e| {
            e.security_policy_uri.as_ref() == SecurityPolicy::Basic256Sha256.to_uri()
                && e.security_mode == MessageSecurityMode::SignAndEncrypt
        })
        .expect("modern endpoint should be advertised")
        .clone();

    let legacy = EndpointDescription {
        security_policy_uri: SecurityPolicy::Basic128Rsa15.to_uri().into(),
        ..modern
    };

    let (_session, lp) = tester
        .client
        .connect_to_endpoint_directly(legacy, IdentityToken::Anonymous)
        .unwrap();
    let handle = lp.spawn();

    // The server rejects the OpenSecureChannel; with the quick retry policy
    // the event loop exhausts its retries and terminates with an error.
    let status = tokio::time::timeout(Duration::from_secs(30), handle)
        .await
        .expect("event loop should give up quickly on rejected OSC")
        .expect("event loop task should not panic");
    assert!(
        status.is_bad(),
        "legacy OpenSecureChannel must be rejected when allow_legacy_crypto is disabled, got {status}"
    );

    // The server must survive the rejected attempt.
    let (session, lp) = tester
        .connect(
            SecurityPolicy::Basic256Sha256,
            MessageSecurityMode::SignAndEncrypt,
            IdentityToken::Anonymous,
        )
        .await
        .unwrap();
    lp.spawn();
    tokio::time::timeout(Duration::from_secs(10), session.wait_for_connection())
        .await
        .unwrap();
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn get_endpoints_includes_legacy_when_allowed() {
    // The default test server allows legacy crypto and configures the
    // deprecated endpoints.
    let tester = Tester::new(test_server(), true).await;

    let url = tester.endpoint();
    let endpoints = tester
        .client
        .get_server_endpoints_from_url(url)
        .await
        .unwrap();
    for policy in [SecurityPolicy::Basic128Rsa15, SecurityPolicy::Basic256] {
        assert!(
            endpoints
                .iter()
                .any(|e| e.security_policy_uri.as_ref() == policy.to_uri()),
            "expected {policy} endpoint to be advertised when legacy is allowed"
        );
    }
}

#[tokio::test]
async fn client_refuses_legacy_endpoint_without_opt_in() {
    // Server allows legacy, but this client keeps the default
    // allow_legacy_crypto: false and must refuse before any traffic.
    let client = ClientBuilder::new()
        .application_name("integration_client")
        .application_uri("x")
        .pki_dir("./pki-client/legacy-refusal")
        .create_sample_keypair(true)
        .trust_server_certs(true)
        .session_retry_limit(1);
    let mut tester = Tester::new_custom_client(test_server(), client).await;

    let result = tester
        .connect(
            SecurityPolicy::Basic128Rsa15,
            MessageSecurityMode::SignAndEncrypt,
            IdentityToken::Anonymous,
        )
        .await;
    let error = result.err().expect("client must refuse legacy endpoint");
    assert_eq!(
        error.status(),
        opcua::types::StatusCode::BadSecurityPolicyRejected
    );
    assert!(
        error.to_string().contains("allow_legacy_crypto"),
        "error must name the client switch: {error}"
    );
}

#[tokio::test]
async fn client_connects_to_legacy_endpoint_with_opt_in() {
    // Default test harness: both sides opt in.
    let mut tester = Tester::new(test_server(), false).await;
    let (session, lp) = tester
        .connect(
            SecurityPolicy::Basic128Rsa15,
            MessageSecurityMode::SignAndEncrypt,
            IdentityToken::Anonymous,
        )
        .await
        .unwrap();
    lp.spawn();
    tokio::time::timeout(Duration::from_secs(10), session.wait_for_connection())
        .await
        .unwrap();
    session.disconnect().await.unwrap();
}
