//! Feature 020 — OPC UA conformance SMOKE (Tier 2 "biggest lever").
//!
//! This is a runnable, CI/Linux PROXY for the OPC Foundation Compliance Test Tool (UACTT), which is a
//! proprietary Windows GUI tool that cannot run here. It drives OUR server with OUR client across the
//! full matrix of (security policy × security mode × identity-token type) and exercises the core
//! conformance service areas on each connection: Session/SecureChannel (connect + activate), Attribute
//! (Read), View (Browse), and Subscription/MonitoredItem (a data change). It also asserts that bad
//! credentials are rejected.
//!
//! COVERAGE / LIMITATIONS (US4): this uses our own client, so it is NOT an independent conformance
//! authority — it is a regression/smoke proxy. It exercises Security, SecureChannel/Session, Attribute
//! Read, View/Browse, and Subscription. It does NOT cover: independent protocol-conformance judging,
//! Write/AddNodes across the matrix (Write is covered comprehensively by `write.rs` over a secured
//! channel), Method Call, Discovery/LDS, or Audit events — those are the real UACTT's job. ECC is
//! exercised against a separate server instance (a single server cert cannot serve both RSA and ECC).
//! See `docs/ctt-conformance.md` for running the real UACTT.

use std::time::Duration;

use opcua::{
    client::{IdentityToken, Session},
    crypto::SecurityPolicy,
    types::{
        AttributeId, BrowseDescription, BrowseDirection, MessageSecurityMode,
        MonitoredItemCreateRequest, MonitoringMode, MonitoringParameters, NodeClass, NodeId,
        ObjectId, ReadValueId, ReferenceTypeId, StatusCode, TimestampsToReturn, VariableId,
        Variant,
    },
};
use tokio::time::timeout;

use crate::utils::{client_user_token, client_x509_token, ChannelNotifications, Tester};

/// The core conformance service surface exercised on every valid matrix cell.
async fn exercise_core_services(session: &Session) {
    // Attribute service: Read Server_ServiceLevel (present on every server).
    let values = session
        .read(
            &[ReadValueId::from(<VariableId as Into<NodeId>>::into(
                VariableId::Server_ServiceLevel,
            ))],
            TimestampsToReturn::Both,
            0.0,
        )
        .await
        .expect("Read should succeed");
    assert_eq!(values.len(), 1, "Read returns one value");

    // View service: Browse the Server object.
    let browse = session
        .browse(
            &[BrowseDescription {
                node_id: ObjectId::Server.into(),
                browse_direction: BrowseDirection::Forward,
                reference_type_id: ReferenceTypeId::References.into(),
                include_subtypes: true,
                node_class_mask: 0,
                result_mask: 0x3f,
            }],
            1000,
            None,
        )
        .await
        .expect("Browse should succeed");
    assert_eq!(browse.len(), 1, "Browse returns one result");

    // Subscription service: subscribe to a changing variable and receive a data change.
    let (notifs, mut data, _) = ChannelNotifications::new();
    let sub_id = session
        .create_subscription(Duration::from_millis(100), 100, 20, 1000, 0, true, notifs)
        .await
        .expect("CreateSubscription should succeed");
    session
        .create_monitored_items(
            sub_id,
            TimestampsToReturn::Both,
            vec![MonitoredItemCreateRequest {
                item_to_monitor: ReadValueId {
                    node_id: VariableId::Server_ServerStatus_CurrentTime.into(),
                    attribute_id: AttributeId::Value as u32,
                    ..Default::default()
                },
                monitoring_mode: MonitoringMode::Reporting,
                requested_parameters: MonitoringParameters {
                    sampling_interval: 0.0,
                    queue_size: 10,
                    discard_oldest: true,
                    ..Default::default()
                },
            }],
        )
        .await
        .expect("CreateMonitoredItems should succeed");
    timeout(Duration::from_secs(10), data.recv())
        .await
        .expect("a data change must arrive within 10s")
        .expect("subscription channel must stay open");
}

/// The identity-token types offered by a server profile, paired with a display name.
fn tokens(include_x509: bool) -> Vec<(&'static str, IdentityToken)> {
    let mut v = vec![
        ("anonymous", IdentityToken::Anonymous),
        ("user-password", client_user_token()),
    ];
    if include_x509 {
        v.push(("x509", client_x509_token().expect("x509 token")));
    }
    v
}

#[tokio::test]
async fn trusted_x509_user_token_activates() {
    let mut tester = Tester::new(crate::utils::test_server(), false).await;
    let (session, handle) = tester
        .connect(
            SecurityPolicy::None,
            MessageSecurityMode::None,
            client_x509_token().expect("x509 token"),
        )
        .await
        .expect("trusted configured X.509 user token should connect");
    let _h = handle.spawn();
    timeout(Duration::from_secs(20), session.wait_for_connection())
        .await
        .expect("trusted X.509 user token should activate before timeout");
    exercise_core_services(&session).await;
    let _ = session.disconnect().await;
}

/// Run + exercise every valid (policy, mode) × token cell against `tester`, then disconnect.
async fn run_matrix(
    tester: &mut Tester,
    cells: &[(SecurityPolicy, MessageSecurityMode)],
    include_x509: bool,
    label: &str,
) {
    for (policy, mode) in cells {
        for (token_name, token) in tokens(include_x509) {
            let (session, handle) =
                tester
                    .connect(*policy, *mode, token)
                    .await
                    .unwrap_or_else(|e| {
                        panic!("[{label}] connect {policy:?}/{mode:?}/{token_name} failed: {e}")
                    });
            let _h = handle.spawn();
            timeout(Duration::from_secs(20), session.wait_for_connection())
                .await
                .unwrap_or_else(|_| {
                    panic!("[{label}] activate {policy:?}/{mode:?}/{token_name} timed out")
                });
            exercise_core_services(&session).await;
            let _ = session.disconnect().await;
        }
    }
}

/// US1: the full RSA-family matrix (None + RSA policies × modes) × every identity-token type.
#[tokio::test]
async fn conformance_smoke_rsa_matrix() {
    let mut tester = Tester::new(crate::utils::test_server(), false).await;
    let cells = [
        (SecurityPolicy::None, MessageSecurityMode::None),
        (SecurityPolicy::Basic128Rsa15, MessageSecurityMode::Sign),
        (
            SecurityPolicy::Basic128Rsa15,
            MessageSecurityMode::SignAndEncrypt,
        ),
        (SecurityPolicy::Basic256, MessageSecurityMode::Sign),
        (
            SecurityPolicy::Basic256,
            MessageSecurityMode::SignAndEncrypt,
        ),
        (SecurityPolicy::Basic256Sha256, MessageSecurityMode::Sign),
        (
            SecurityPolicy::Basic256Sha256,
            MessageSecurityMode::SignAndEncrypt,
        ),
        (
            SecurityPolicy::Aes128Sha256RsaOaep,
            MessageSecurityMode::Sign,
        ),
        (
            SecurityPolicy::Aes128Sha256RsaOaep,
            MessageSecurityMode::SignAndEncrypt,
        ),
        (
            SecurityPolicy::Aes256Sha256RsaPss,
            MessageSecurityMode::Sign,
        ),
        (
            SecurityPolicy::Aes256Sha256RsaPss,
            MessageSecurityMode::SignAndEncrypt,
        ),
    ];
    run_matrix(&mut tester, &cells, /* include_x509 */ true, "rsa").await;
}

/// US1 (FR-002): bad credentials must be rejected — a UserName token with the wrong password must not
/// produce a connected session.
#[tokio::test]
async fn conformance_smoke_rejects_bad_password() {
    let mut tester = Tester::new(crate::utils::test_server(), false).await;
    let bad = IdentityToken::UserName(
        crate::utils::CLIENT_USERPASS_ID.to_owned(),
        "definitely-the-wrong-password".into(),
    );
    let result = tester
        .connect(
            SecurityPolicy::Basic256Sha256,
            MessageSecurityMode::SignAndEncrypt,
            bad,
        )
        .await;
    match result {
        Err(_) => {} // rejected at connect — acceptable
        Ok((session, handle)) => {
            let _h = handle.spawn();
            // Must NOT reach a connected state with a bad password.
            assert!(
                timeout(Duration::from_secs(3), session.wait_for_connection())
                    .await
                    .is_err(),
                "a wrong password must not yield a connected session"
            );
        }
    }
}

#[tokio::test]
async fn namespace_metadata_property_nodes_are_variables() {
    let mut tester = Tester::new(crate::utils::test_server(), false).await;
    let (session, handle) = tester.connect_default().await.unwrap();
    let _h = handle.spawn();
    timeout(Duration::from_secs(20), session.wait_for_connection())
        .await
        .expect("anonymous session should activate before timeout");

    let metadata_refs = session
        .browse(
            &[BrowseDescription {
                node_id: ObjectId::Server_Namespaces.into(),
                browse_direction: BrowseDirection::Forward,
                reference_type_id: ReferenceTypeId::HasComponent.into(),
                include_subtypes: false,
                node_class_mask: NodeClass::Object as u32,
                result_mask: 0x3f,
            }],
            1000,
            None,
        )
        .await
        .expect("Server.Namespaces should be browsable");
    let metadata_node = metadata_refs[0]
        .references
        .as_ref()
        .and_then(|refs| {
            refs.iter()
                .find(|reference| reference.browse_name.name.as_ref() == "urn:rustopcuatestserver")
        })
        .expect("test namespace metadata should be browsable")
        .node_id
        .node_id
        .clone();

    let property_refs = session
        .browse(
            &[BrowseDescription {
                node_id: metadata_node,
                browse_direction: BrowseDirection::Forward,
                reference_type_id: ReferenceTypeId::HasProperty.into(),
                include_subtypes: false,
                node_class_mask: 0,
                result_mask: 0x3f,
            }],
            1000,
            None,
        )
        .await
        .expect("NamespaceMetadata properties should be browsable");
    let refs = property_refs[0]
        .references
        .as_ref()
        .expect("NamespaceMetadata should expose property references");
    let mandatory_properties = [
        "NamespaceUri",
        "NamespaceVersion",
        "NamespacePublicationDate",
        "IsNamespaceSubset",
        "StaticNodeIdTypes",
    ];
    let property_nodes = mandatory_properties
        .iter()
        .map(|property| {
            refs.iter()
                .find(|reference| reference.browse_name.name.as_ref() == *property)
                .unwrap_or_else(|| panic!("{property} metadata property should be browsable"))
                .node_id
                .node_id
                .clone()
        })
        .collect::<Vec<_>>();

    // OPC-10000-5 6.3.13 Table 22 defines NamespaceMetadata metadata properties as
    // HasProperty Variable nodes with PropertyType.
    let reads = property_nodes
        .into_iter()
        .map(|node_id| ReadValueId {
            node_id,
            attribute_id: AttributeId::NodeClass as u32,
            ..Default::default()
        })
        .collect::<Vec<_>>();
    let values = session
        .read(&reads, TimestampsToReturn::Neither, 0.0)
        .await
        .expect("NamespaceMetadata property NodeClass reads should succeed");

    for (property, value) in mandatory_properties.iter().zip(values.iter()) {
        assert_eq!(
            value.status(),
            StatusCode::Good,
            "{property} NodeClass read should succeed"
        );
        assert_eq!(
            value.value,
            Some(Variant::Int32(NodeClass::Variable as i32)),
            "{property} should expose NodeClass Variable"
        );
    }
}

/// US1: the ECC matrix (ECC_nistP256/P384 × Sign/SignAndEncrypt) × every identity-token type, against a
/// dedicated ECC server instance (single-cert constraint).
#[cfg(feature = "ecc")]
#[tokio::test]
async fn conformance_smoke_ecc_matrix() {
    use opcua::crypto::ecc::EccCurve;
    for (curve, policy) in [
        (EccCurve::P256, SecurityPolicy::EccNistP256),
        (EccCurve::P384, SecurityPolicy::EccNistP384),
    ] {
        let mut tester = Tester::new_ecc(curve).await;
        let cells = [
            (policy, MessageSecurityMode::Sign),
            (policy, MessageSecurityMode::SignAndEncrypt),
        ];
        // The ECC server profile (`ecc_server`) advertises only anonymous + user-password tokens
        // (no x509 token id), so the ECC matrix omits the x509 cell.
        run_matrix(&mut tester, &cells, /* include_x509 */ false, "ecc").await;
    }
}
