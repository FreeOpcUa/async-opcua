//! Connection limit regression tests.

use std::time::Duration;

use opcua_server::ServerBuilder;
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};

#[tokio::test]
async fn server_closes_tcp_connections_above_max_connections() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test listener should bind");
    let addr = listener.local_addr().expect("listener should have address");
    let endpoint_url = format!("opc.tcp://127.0.0.1:{}/", addr.port());

    let mut builder = ServerBuilder::new_anonymous("Connection Limit Test")
        .application_uri("urn:connection-limit-test")
        .product_uri("urn:connection-limit-test")
        .host("127.0.0.1")
        .port(addr.port())
        .discovery_urls(vec![endpoint_url]);
    builder.config_mut().max_connections = 1;

    let (server, handle) = builder
        .build()
        .expect("connection limit test server should build");
    let server_task = tokio::spawn(async move {
        server.run_with(listener).await.expect("server should run");
    });

    let _held_connection = TcpStream::connect(addr)
        .await
        .expect("first TCP client should connect");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut rejected_connection = TcpStream::connect(addr)
        .await
        .expect("second TCP client should connect before server closes it");
    let mut buf = [0; 1];
    let read = tokio::time::timeout(
        Duration::from_millis(500),
        rejected_connection.read(&mut buf),
    )
    .await
    .expect("over-limit connection should close promptly")
    .expect("read should report EOF, not a socket error");

    assert_eq!(read, 0);

    handle.cancel();
    server_task.abort();
}
