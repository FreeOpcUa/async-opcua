//! Integration tests for OAuth2 JWT rejection and FOTA cleanup.

use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use opcua_core::sync::RwLock;
use opcua_server::{
    address_space::AddressSpace,
    auth::oauth2::{validate_issued_jwt_with, JwtValidation},
    fota::{
        cleanup::{cleanup_session, register_session_file},
        file_node::{TemporaryFileNode, TemporaryFileNodeConfig},
    },
};
use opcua_types::{ByteString, NodeId, StatusCode};

fn jwt(header: &str, claims: &str) -> ByteString {
    let header = URL_SAFE_NO_PAD.encode(header);
    let claims = URL_SAFE_NO_PAD.encode(claims);
    ByteString::from(format!("{header}.{claims}.signature").as_bytes())
}

#[test]
fn rejects_invalid_oauth2_jwt_tokens() {
    let validation = JwtValidation {
        now_epoch_seconds: 1_000,
        clock_skew_seconds: 0,
        ..JwtValidation::default()
    };

    let unsigned = jwt(r#"{"alg":"none"}"#, r#"{"sub":"operator","exp":2000}"#);
    let err =
        validate_issued_jwt_with(&unsigned, validation).expect_err("unsigned JWT must be rejected");
    assert_eq!(err.status(), StatusCode::BadIdentityTokenRejected);

    let expired = jwt(r#"{"alg":"RS256"}"#, r#"{"sub":"operator","exp":999}"#);
    let err =
        validate_issued_jwt_with(&expired, validation).expect_err("expired JWT must be rejected");
    assert_eq!(err.status(), StatusCode::BadIdentityTokenRejected);
}

#[tokio::test]
async fn cleanup_deletes_session_bound_temp_file_and_nodes() {
    let (_server, handle) = opcua_server::ServerBuilder::new_anonymous("fota-integration-test")
        .build()
        .expect("test server should build");
    let info = handle.info();
    let address_space = Arc::new(RwLock::new(AddressSpace::new()));
    let session_id = NodeId::new(0, "fota-integration-session");
    let temp_path = std::env::temp_dir().join(format!(
        "async_opcua_fota_integration_{}.bin",
        std::process::id()
    ));
    std::fs::write(&temp_path, b"firmware").expect("temporary firmware file should be written");

    let file_node: TemporaryFileNode = {
        let mut address_space = address_space.write();
        TemporaryFileNode::create(
            &mut address_space,
            TemporaryFileNodeConfig::new(2, session_id.clone(), "firmware.bin"),
        )
        .expect("temporary FileType nodes should be created")
    };

    register_session_file(
        info,
        session_id.clone(),
        &address_space,
        &file_node,
        Some(temp_path.clone()),
    );
    let report = cleanup_session(info, &session_id);

    assert_eq!(report.resources, 1);
    assert_eq!(report.files, 1);
    assert_eq!(report.nodes, file_node.node_ids().len());
    assert!(!temp_path.exists());
    let address_space = address_space.read();
    for node_id in file_node.node_ids() {
        assert!(
            address_space.find(&node_id).is_none(),
            "expected cleanup to delete owned node {node_id}"
        );
    }
}
