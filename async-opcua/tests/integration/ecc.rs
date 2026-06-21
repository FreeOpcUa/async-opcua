//! End-to-end ECC secure-channel loopback (feature 012, US3).
//!
//! Authored by Claude as the independent gate for the codex-implemented ECC
//! OpenSecureChannel orchestration: a real client opens an ECC secure channel to
//! a real server over loopback (ephemeral ECDH + HKDF keys, ECDSA-signed
//! handshake) and makes a service call in both Sign and SignAndEncrypt modes,
//! for both NIST curves. Plus negatives: channel renewal and a tampered/cross
//! configuration must not succeed.

use std::time::Duration;

use opcua::{
    client::{IdentityToken, Session},
    crypto::{ecc::EccCurve, SecurityPolicy},
    types::{MessageSecurityMode, NodeId, ReadValueId, TimestampsToReturn, VariableId},
};

use crate::utils::Tester;

async fn read_service_level(session: &Session) {
    let values = session
        .read(
            &[ReadValueId::from(<VariableId as Into<NodeId>>::into(
                VariableId::Server_ServiceLevel,
            ))],
            TimestampsToReturn::Both,
            0.0,
        )
        .await
        .unwrap();
    assert_eq!(values.len(), 1);
}

async fn ecc_connect_and_read(curve: EccCurve, policy: SecurityPolicy, mode: MessageSecurityMode) {
    let mut tester = Tester::new_ecc(curve).await;
    let (session, handle) = tester
        .connect(policy, mode, IdentityToken::Anonymous)
        .await
        .unwrap();
    let _h = handle.spawn();

    tokio::time::timeout(Duration::from_secs(20), session.wait_for_connection())
        .await
        .unwrap();

    // A signed (and possibly encrypted) service call over the ECC channel.
    let values = session
        .read(
            &[ReadValueId::from(<VariableId as Into<NodeId>>::into(
                VariableId::Server_ServiceLevel,
            ))],
            TimestampsToReturn::Both,
            0.0,
        )
        .await
        .unwrap();
    assert_eq!(values.len(), 1);
}

#[tokio::test]
async fn ecc_nistp256_sign() {
    ecc_connect_and_read(
        EccCurve::P256,
        SecurityPolicy::EccNistP256,
        MessageSecurityMode::Sign,
    )
    .await;
}

#[tokio::test]
async fn ecc_nistp256_sign_and_encrypt() {
    ecc_connect_and_read(
        EccCurve::P256,
        SecurityPolicy::EccNistP256,
        MessageSecurityMode::SignAndEncrypt,
    )
    .await;
}

#[tokio::test]
async fn ecc_nistp384_sign() {
    ecc_connect_and_read(
        EccCurve::P384,
        SecurityPolicy::EccNistP384,
        MessageSecurityMode::Sign,
    )
    .await;
}

#[tokio::test]
async fn ecc_nistp384_sign_and_encrypt() {
    ecc_connect_and_read(
        EccCurve::P384,
        SecurityPolicy::EccNistP384,
        MessageSecurityMode::SignAndEncrypt,
    )
    .await;
}

/// Channel renewal: with a short channel lifetime the client renews the secure
/// channel mid-session (a fresh ephemeral ECDH + re-derived keys); traffic must
/// continue on the renewed channel.
#[tokio::test]
async fn ecc_nistp256_channel_renewal() {
    let mut tester = Tester::new_ecc_with_channel_lifetime(EccCurve::P256, 1500).await;
    let (session, handle) = tester
        .connect(
            SecurityPolicy::EccNistP256,
            MessageSecurityMode::SignAndEncrypt,
            IdentityToken::Anonymous,
        )
        .await
        .unwrap();
    let _h = handle.spawn();

    tokio::time::timeout(Duration::from_secs(20), session.wait_for_connection())
        .await
        .unwrap();
    read_service_level(&session).await;

    // Sleep well past the 1.5s channel lifetime so at least one renewal fires.
    tokio::time::sleep(Duration::from_millis(2500)).await;

    // The renewed channel must still carry signed/encrypted traffic.
    read_service_level(&session).await;
}

/// Negotiation is curve-strict: a server offering only `ECC_nistP256` must not
/// let a client establish an `ECC_nistP384` channel.
#[tokio::test]
async fn ecc_wrong_curve_is_not_negotiated() {
    let mut tester = Tester::new_ecc(EccCurve::P256).await;
    let result = tester
        .connect(
            SecurityPolicy::EccNistP384,
            MessageSecurityMode::Sign,
            IdentityToken::Anonymous,
        )
        .await;

    match result {
        // Rejected at connect time (no matching endpoint) — the expected outcome.
        Err(_) => {}
        // If a session object is returned it must never actually connect.
        Ok((session, handle)) => {
            let _h = handle.spawn();
            assert!(
                tokio::time::timeout(Duration::from_secs(3), session.wait_for_connection())
                    .await
                    .is_err(),
                "client wrongly negotiated ECC_nistP384 against a P256-only server"
            );
        }
    }
}
