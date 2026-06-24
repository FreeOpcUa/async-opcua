//! Behavioral regression tests for feature 009 hardening findings.
//!
//! These exercise fixes that were otherwise covered only by compile-time/config
//! guards, against the real client+server `Tester` harness.

use std::time::Duration;

use opcua::{
    client::{ClientBuilder, IdentityToken},
    crypto::SecurityPolicy,
    types::{MessageSecurityMode, NodeId, ReadValueId, StatusCode, VariableId},
};
use opcua_client::{services::Read, UARequest};

use crate::utils::{default_server, hostname, setup, Tester};

/// H5 / L9: the server must reject a `CreateSession` whose client-certificate
/// SubjectAltName URI does not match the declared `applicationUri`. The harness
/// provisions a shared certificate (SAN `urn:integration_server`); a client that
/// declares a different `applicationUri` must be rejected with
/// `BadCertificateUriInvalid` rather than activated.
#[tokio::test]
async fn cert_application_uri_mismatch_is_rejected() {
    let client = ClientBuilder::new()
        .application_name("integration_client")
        .application_uri("urn:client-uri-deliberately-wrong")
        .trust_server_certs(true)
        .session_retry_limit(1);

    let mut tester = Tester::new_custom_client(default_server(), client).await;

    let result = tester
        .connect(
            SecurityPolicy::Aes128Sha256RsaOaep,
            MessageSecurityMode::SignAndEncrypt,
            IdentityToken::Anonymous,
        )
        .await;

    match result {
        Err(e) => assert_eq!(
            e.status(),
            StatusCode::BadCertificateUriInvalid,
            "expected BadCertificateUriInvalid, got {e:?}"
        ),
        Ok((session, evt_loop)) => {
            // Connection setup may return Ok and surface the rejection during
            // session activation in the event loop. The session must never reach
            // the connected state.
            let _h = evt_loop.spawn();
            let connected =
                tokio::time::timeout(Duration::from_secs(5), session.wait_for_connection()).await;
            assert!(
                connected.is_err(),
                "session with mismatched cert URI must not connect"
            );
        }
    }
}

/// N2: connecting to a black-holed (unroutable) address must honor the configured
/// connect timeout and return an error promptly, instead of hanging forever.
/// 192.0.2.0/24 is TEST-NET-1 (RFC 5737), reserved and unrouted.
#[tokio::test]
async fn connect_to_black_holed_address_times_out() {
    let _ = env_logger::try_init();

    let mut client = ClientBuilder::new()
        .application_name("integration_client")
        .application_uri(format!("urn:{}", hostname()))
        .trust_server_certs(true)
        .connect_timeout(Duration::from_millis(500))
        .session_retry_limit(0)
        .client()
        .expect("client builds");

    // Outer bound well above connect_timeout: if the connect hangs (the N2 bug),
    // this elapses and the test fails instead of hanging the suite.
    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        client.connect_to_matching_endpoint(
            (
                "opc.tcp://192.0.2.1:4840/",
                SecurityPolicy::None.to_str(),
                MessageSecurityMode::None,
            ),
            IdentityToken::Anonymous,
        ),
    )
    .await;

    let connect_result = outcome.expect("connect must not hang past the outer timeout bound");
    assert!(
        connect_result.is_err(),
        "connecting to a black-holed address must return an error"
    );
}

/// DoS protection: the server caps the number of concurrent sessions. A `CreateSession`
/// beyond `max_sessions` must be rejected with `Bad_TooManySessions` rather than exhausting
/// server resources.
#[tokio::test]
async fn too_many_sessions_is_rejected() {
    let mut server = default_server();
    server.limits_mut().max_sessions = 2;
    let mut tester = Tester::new(server, false).await;

    // Hold two live sessions so they stay registered on the server.
    let mut held = Vec::new();
    for _ in 0..2 {
        let (session, handle) = tester
            .connect(
                SecurityPolicy::None,
                MessageSecurityMode::None,
                IdentityToken::Anonymous,
            )
            .await
            .unwrap();
        let h = handle.spawn();
        tokio::time::timeout(Duration::from_secs(10), session.wait_for_connection())
            .await
            .unwrap();
        held.push((session, h));
    }

    // The third session must be rejected with BadTooManySessions.
    let result = tester
        .connect(
            SecurityPolicy::None,
            MessageSecurityMode::None,
            IdentityToken::Anonymous,
        )
        .await;
    match result {
        Err(e) => assert_eq!(
            e.status(),
            StatusCode::BadTooManySessions,
            "expected BadTooManySessions, got {e:?}"
        ),
        Ok((session, handle)) => {
            let _h = handle.spawn();
            assert!(
                tokio::time::timeout(Duration::from_secs(3), session.wait_for_connection())
                    .await
                    .is_err(),
                "third session wrongly connected past max_sessions"
            );
        }
    }
}

/// Anti-hijack (Part 4 §5.6): every request is bound to its session's secure channel
/// (`validate_secure_channel_id`). A request bearing one session's authentication token but
/// arriving on a DIFFERENT secure channel must be rejected with `Bad_SecureChannelIdInvalid`, so a
/// stolen or sniffed token cannot be replayed over an attacker's own channel.
#[tokio::test]
async fn session_token_used_on_another_channel_is_rejected() {
    let (mut tester, _nm, session_a) = setup().await;

    // A second, independent session on its own secure channel.
    let (session_b, lp_b) = tester
        .connect(
            SecurityPolicy::None,
            MessageSecurityMode::None,
            IdentityToken::Anonymous,
        )
        .await
        .unwrap();
    lp_b.spawn();
    tokio::time::timeout(Duration::from_secs(10), session_b.wait_for_connection())
        .await
        .unwrap();

    let service_level = ReadValueId::from(<VariableId as Into<NodeId>>::into(
        VariableId::Server_ServiceLevel,
    ));

    // A Read carrying session A's authentication token, but sent over session B's channel.
    let hijack = Read::new(&session_a)
        .node(service_level.clone())
        .send(session_b.channel())
        .await;
    match hijack {
        Err(e) => assert_eq!(
            e.status(),
            StatusCode::BadSecureChannelIdInvalid,
            "cross-channel token use must be rejected, got {e:?}"
        ),
        Ok(_) => panic!("a session token replayed on another channel was wrongly accepted"),
    }

    // Each session still works correctly on its own channel.
    Read::new(&session_a)
        .node(service_level.clone())
        .send(session_a.channel())
        .await
        .unwrap();
    Read::new(&session_b)
        .node(service_level)
        .send(session_b.channel())
        .await
        .unwrap();
}
