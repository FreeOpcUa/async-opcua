use std::{sync::Arc, time::Duration};

use opcua_client::{
    reverse_connect::{ReverseConnectionSource, TcpConnectorReceiver},
    transport::ReverseTcpConnector,
};
use opcua_crypto::SecurityPolicy;
use opcua_server::ReverseConnectTargetConfig;
use opcua_types::{
    EndpointDescription, MessageSecurityMode, NodeId, ReadValueId, TimestampsToReturn, VariableId,
};
use tokio::net::TcpListener;

use crate::utils::Tester;

#[tokio::test]
async fn test_reverse_connect() {
    let tester = Tester::new_default_server(false).await;

    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
    let addr = listener.local_addr().unwrap();
    // Once we disconnect, the server will immediately try to reconnect,
    // so we can use the same target for both connections.
    tester
        .handle
        .add_reverse_connect_target(ReverseConnectTargetConfig {
            address: addr,
            endpoint_url: tester.endpoint(),
            id: "test_target".to_string(),
        });

    // Creating endpoint descriptions could use some TLC...
    // We can use reverse connect to get the endpoints from the server as well,
    // by passing a ReverseTcpConnector as connector builder.
    let endpoints = tester
        .client
        .get_server_endpoints_from_url(ReverseTcpConnector::new_default(
            EndpointDescription::from((
                &tester.endpoint() as &str,
                SecurityPolicy::None.to_str(),
                MessageSecurityMode::None,
            )),
            TcpConnectorReceiver::Listener(listener.clone()),
        ))
        .await
        .unwrap();

    let (session, event_loop) = tester
        .client
        .session_builder()
        .with_connector(ReverseConnectionSource::new_listener(listener))
        .with_endpoints(endpoints)
        .connect_to_matching_endpoint((
            &tester.endpoint() as &str,
            SecurityPolicy::Aes128Sha256RsaOaep.to_str(),
            MessageSecurityMode::SignAndEncrypt,
        ))
        .unwrap()
        .build(tester.client.certificate_store().clone())
        .unwrap();

    event_loop.spawn();

    tester
        .handle
        .add_reverse_connect_target(ReverseConnectTargetConfig {
            address: addr,
            endpoint_url: tester.endpoint(),
            id: "test_target".to_string(),
        });

    tokio::time::timeout(Duration::from_secs(5), session.wait_for_connection())
        .await
        .unwrap();

    session
        .read(
            &[ReadValueId::from(<VariableId as Into<NodeId>>::into(
                VariableId::Server_ServiceLevel,
            ))],
            TimestampsToReturn::Both,
            0.0,
        )
        .await
        .unwrap();

    tester.handle.remove_reverse_connect_target("test_target");
}
