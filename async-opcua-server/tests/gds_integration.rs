//! Integration test for GDS.
// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2026 Adam Lock

#![cfg(feature = "discovery-server-registration")]

use std::time::Duration;
use tokio::net::TcpListener;

use opcua_client::{ClientBuilder, IdentityToken};
use opcua_server::{ServerBuilder, ServerConfig, ServerEndpoint, ANONYMOUS_USER_TOKEN_ID};
use opcua_types::{
    EndpointDescription, MessageSecurityMode, NodeId, ReadValueId, TimestampsToReturn,
    UserTokenPolicy, VariableId,
};

#[tokio::test]
async fn test_zero_downtime_certificate_rotation() {
    // 1. Setup paths
    let test_dir = std::env::current_dir()
        .unwrap()
        .join("target")
        .join("test_pki_gds");
    let _ = std::fs::remove_dir_all(&test_dir);
    let server_pki_dir = test_dir.join("server_pki");
    let client_pki_dir = test_dir.join("client_pki");

    // 2. Build Server
    let mut server_config = ServerConfig::default();
    server_config.pki_dir = server_pki_dir.clone();
    server_config.create_sample_keypair = true;
    server_config.certificate_path = Some(server_pki_dir.join("own/cert.der"));
    server_config.private_key_path = Some(server_pki_dir.join("private/private.pem"));
    server_config.tcp_config.host = "127.0.0.1".to_string();
    server_config.tcp_config.port = 0; // auto-assign
    server_config.discovery_urls = vec!["opc.tcp://127.0.0.1:0/".to_string()];

    // Add endpoint so connection works
    server_config.add_endpoint(
        "none",
        ServerEndpoint::new_none("/", &[ANONYMOUS_USER_TOKEN_ID.to_string()]),
    );

    let (server, server_handle) = ServerBuilder::from_config(server_config).build().unwrap();

    // Start server in background
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        server.run_with(listener).await.unwrap();
    });

    // Let the server startup
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 3. Build client
    let mut client = ClientBuilder::new()
        .application_name("GDS Integration Client")
        .application_uri("urn:gds_integration_client")
        .pki_dir(client_pki_dir)
        .create_sample_keypair(true)
        .client()
        .unwrap();

    // Connect client 1
    let endpoint_url = format!("opc.tcp://127.0.0.1:{}/", addr.port());
    let endpoint: EndpointDescription = (
        endpoint_url.as_str(),
        "None",
        MessageSecurityMode::None,
        UserTokenPolicy::anonymous(),
    )
        .into();

    let (session1, event_loop1) = client
        .connect_to_matching_endpoint(endpoint.clone(), IdentityToken::Anonymous)
        .await
        .unwrap();
    let handle1 = event_loop1.spawn();

    session1.wait_for_connection().await;

    // Verify client 1 is connected and working
    let nodeid: NodeId = VariableId::Server_ServerStatus_State.into();
    let result = session1
        .read(
            &[ReadValueId::from(nodeid)],
            TimestampsToReturn::Neither,
            0.0,
        )
        .await
        .unwrap();
    let server_state = &result[0];
    assert!(server_state.status.unwrap().is_good());

    // 4. Generate new key and cert for server
    let mut alt_host_names = opcua_crypto::AlternateNames::new();
    alt_host_names.add_dns("localhost");
    let args = opcua_crypto::X509Data {
        key_size: 2048,
        common_name: "renewed_server".to_string(),
        organization: "renewed_org".to_string(),
        organizational_unit: "renewed_unit".to_string(),
        country: "US".to_string(),
        state: "state".to_string(),
        alt_host_names,
        certificate_duration_days: 365,
    };
    let (new_cert, new_pkey) = opcua_crypto::X509::cert_and_pkey(&args).unwrap();

    let cert_der = new_cert.to_der().unwrap();

    // PEM format for private key
    let pem = new_pkey.to_pem().unwrap();

    // Save new credentials to server files
    {
        let store = server_handle.certificate_store().read();
        opcua_crypto::gds_reload::save_new_credentials(&*store, &cert_der, pem.as_bytes()).unwrap();
    }

    // 5. Reload on Server
    server_handle.reload_certificate().unwrap();

    // 6. Verify first client connection is NOT interrupted (can still perform operations)
    let nodeid2: NodeId = VariableId::Server_ServerStatus_State.into();
    let result2 = session1
        .read(
            &[ReadValueId::from(nodeid2)],
            TimestampsToReturn::Neither,
            0.0,
        )
        .await
        .unwrap();
    let server_state2 = &result2[0];
    assert!(server_state2.status.unwrap().is_good());

    // 7. Verify new client connection receives renewed certificate
    let new_endpoints = client
        .get_server_endpoints_from_url(&endpoint_url)
        .await
        .unwrap();
    assert!(!new_endpoints.is_empty());

    let received_cert_bytes = new_endpoints[0].server_certificate.as_ref();
    assert_eq!(received_cert_bytes, cert_der.as_slice());

    // Clean up
    let _ = session1.disconnect().await;
    let _ = handle1.await;
    server_handle.cancel();
    let _ = server_task.await;
    let _ = std::fs::remove_dir_all(&test_dir);
}
