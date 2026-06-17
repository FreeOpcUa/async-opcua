//! opc.wss (OPC UA over secure WebSocket) round-trip test (feature 009 / R5 / FR-044, T089).
//!
//! Stands up a real server listening for WSS connections over a self-signed TLS cert,
//! connects a client over `opc.wss://` (TLS verification disabled for the self-signed
//! test cert), and performs a Read — proving the transport carries the full OPC UA
//! handshake + a service round-trip.
#![cfg(feature = "wss")]

use std::time::Duration;

use opcua::{
    client::{ClientBuilder, IdentityToken},
    core::config::Config,
    crypto::SecurityPolicy,
    server::ServerBuilder,
    types::{
        EndpointDescription, MessageSecurityMode, NodeId, ReadValueId, TimestampsToReturn,
        UserTokenPolicy, VariableId,
    },
};
use opcua_crypto::CertificateStore;
use tokio::net::TcpListener;

use crate::utils::hostname;

/// PEM-encode a DER certificate so the convenience `websocket_tls(cert, key)` loader
/// (which expects a PEM chain) can read it.
fn der_to_cert_pem(der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

#[tokio::test]
async fn wss_round_trip_none_policy() {
    let _ = env_logger::try_init();

    let dir = tempdir::TempDir::new("wss-test").unwrap();
    let tls_cert_der = dir.path().join("tls_cert.der");
    let tls_cert_pem = dir.path().join("tls_cert.pem");
    let tls_key_pem = dir.path().join("tls_key.pem");

    // A minimal anonymous server with a single SecurityPolicy::None endpoint — WSS
    // provides the transport security, so no OPC UA application certificate is needed.
    let server_builder = ServerBuilder::new_anonymous("wss_server").host(hostname());
    let desc = server_builder.config().application_description();
    CertificateStore::create_certificate_and_key(&desc.into(), true, &tls_cert_der, &tls_key_pem)
        .unwrap();
    std::fs::write(
        &tls_cert_pem,
        der_to_cert_pem(&std::fs::read(&tls_cert_der).unwrap()),
    )
    .unwrap();

    let listener = TcpListener::bind(format!("{}:0", hostname()))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    let url = format!("opc.wss://{}:{}/", hostname(), addr.port());
    let (server, _handle) = server_builder
        .discovery_urls(vec![url.clone()])
        .websocket_tls(&tls_cert_pem, &tls_key_pem)
        .expect("load WSS TLS cert/key")
        .build()
        .unwrap();
    let _server_task = tokio::spawn(async move { server.run_with_wss(listener).await });

    let mut client = ClientBuilder::new()
        .application_name("wss_client")
        .application_uri(&format!("urn:{}", hostname()))
        .trust_server_certs(true)
        // Self-signed test TLS cert: disable WSS/TLS verification (loud, test-only).
        .dangerously_accept_invalid_wss_certs(true)
        .session_retry_initial(Duration::from_millis(200))
        .session_retry_limit(3)
        .client()
        .unwrap();

    let mut endpoint: EndpointDescription = (
        url.as_str(),
        // connect_to_endpoint_directly parses the policy via from_uri (URI form).
        SecurityPolicy::None.to_uri(),
        MessageSecurityMode::None,
    )
        .into();
    // A directly-supplied endpoint is not rediscovered, so it must advertise the
    // user-token policies the client will use (here: anonymous).
    endpoint.user_identity_tokens = Some(vec![UserTokenPolicy::anonymous()]);

    let (session, evt_loop) = client
        .connect_to_endpoint_directly(endpoint, IdentityToken::Anonymous)
        .unwrap();
    let _h = evt_loop.spawn();

    tokio::time::timeout(Duration::from_secs(20), session.wait_for_connection())
        .await
        .expect("opc.wss session must connect within 20s");

    session
        .read(
            &[ReadValueId::from(<VariableId as Into<NodeId>>::into(
                VariableId::Server_ServiceLevel,
            ))],
            TimestampsToReturn::Both,
            0.0,
        )
        .await
        .expect("read over opc.wss must succeed");
}
