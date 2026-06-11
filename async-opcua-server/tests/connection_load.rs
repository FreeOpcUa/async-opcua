//! Spec 004 T044: load test simulating 10k concurrent connections.
//!
//! Ignored by default since it opens thousands of sockets; run manually with
//! `cargo test -p async-opcua-server --test connection_load -- --ignored`.
//! The connection count can be overridden with `CONNECTION_LOAD_COUNT`.

use std::time::Duration;

use futures::{stream::FuturesUnordered, StreamExt};
use opcua_core::comms::{
    tcp_codec::{Message, TcpCodec},
    tcp_types::HelloMessage,
};
use opcua_server::ServerBuilder;
use opcua_types::{DecodingOptions, SimpleBinaryEncodable};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
};
use tokio_util::codec::FramedRead;

const DEFAULT_CONNECTIONS: usize = 10_000;
const CONNECT_CONCURRENCY: usize = 512;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "expensive: opens 10k TCP connections, run manually (CONNECTION_LOAD_COUNT to override)"]
async fn ten_thousand_connections_complete_handshake() {
    let connections: usize = std::env::var("CONNECTION_LOAD_COUNT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_CONNECTIONS);

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("listener address");
    let endpoint_url = format!("opc.tcp://127.0.0.1:{}/", addr.port());

    let (server, handle) = ServerBuilder::new_anonymous("Connection Load Test")
        .application_uri("urn:connection-load-test")
        .product_uri("urn:connection-load-test")
        .host("127.0.0.1")
        .port(addr.port())
        .discovery_urls(vec![endpoint_url.clone()])
        .max_connections(connections + 16)
        .build()
        .expect("load test server should build");
    let server_task = tokio::spawn(async move {
        let _ = server.run_with(listener).await;
    });

    let started = std::time::Instant::now();
    let mut pending = FuturesUnordered::new();
    let mut held = Vec::with_capacity(connections);
    let mut launched = 0usize;

    while held.len() < connections {
        while launched < connections && pending.len() < CONNECT_CONCURRENCY {
            let endpoint_url = endpoint_url.clone();
            launched += 1;
            pending.push(async move {
                let mut client = TcpStream::connect(addr).await?;
                let hello = HelloMessage::new(&endpoint_url, 65_535, 65_535, 0, 0);
                client
                    .write_all(&SimpleBinaryEncodable::encode_to_vec(&hello))
                    .await?;
                let (read, write) = tokio::io::split(client);
                let mut framed = FramedRead::new(read, TcpCodec::new(DecodingOptions::default()));
                let message = tokio::time::timeout(Duration::from_secs(30), framed.next())
                    .await
                    .map_err(|_| std::io::Error::other("timed out waiting for ACK"))?;
                match message {
                    Some(Ok(Message::Acknowledge(_))) => Ok::<_, std::io::Error>((framed, write)),
                    other => Err(std::io::Error::other(format!(
                        "expected ACK, got {other:?}"
                    ))),
                }
            });
        }

        let result = pending
            .next()
            .await
            .expect("pending connections should yield");
        held.push(result.expect("connection should complete HEL/ACK handshake"));
    }

    let elapsed = started.elapsed();
    println!(
        "{connections} connections completed HEL/ACK in {elapsed:?} ({:.0} conn/s)",
        connections as f64 / elapsed.as_secs_f64()
    );
    assert_eq!(held.len(), connections);

    // Tear everything down; the server must survive the mass disconnect.
    drop(held);
    handle.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(60), server_task).await;
}
