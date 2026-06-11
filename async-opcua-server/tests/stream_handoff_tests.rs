//! Stream handoff tests.

use std::time::Duration;

use futures::StreamExt;
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

#[tokio::test]
async fn run_with_streams_accepts_externally_accepted_tcp_stream() {
    let handoff_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("handoff listener should bind");
    let addr = handoff_listener
        .local_addr()
        .expect("handoff listener should have address");
    let endpoint_url = format!("opc.tcp://127.0.0.1:{}/", addr.port());

    let builder = ServerBuilder::new_anonymous("Stream Handoff Test")
        .application_uri("urn:stream-handoff-test")
        .product_uri("urn:stream-handoff-test")
        .host("127.0.0.1")
        .port(addr.port())
        .discovery_urls(vec![endpoint_url.clone()]);
    let (server, handle) = builder
        .build()
        .expect("stream handoff test server should build");
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    let server_task = tokio::spawn(async move {
        server
            .run_with_streams(rx)
            .await
            .expect("server should run with handed-off streams");
    });

    let mut client = TcpStream::connect(addr)
        .await
        .expect("client should connect to external listener");
    let (socket, peer_addr) = handoff_listener
        .accept()
        .await
        .expect("external listener should accept client");
    tx.send((socket, peer_addr))
        .await
        .expect("accepted stream should hand off to server");

    let hello = HelloMessage::new(&endpoint_url, 65_535, 65_535, 0, 0);
    client
        .write_all(&SimpleBinaryEncodable::encode_to_vec(&hello))
        .await
        .expect("client should send HEL");

    let (read, _) = tokio::io::split(client);
    let mut framed = FramedRead::new(read, TcpCodec::new(DecodingOptions::default()));
    let message = tokio::time::timeout(Duration::from_secs(2), framed.next())
        .await
        .expect("server should respond to HEL");

    assert!(matches!(message, Some(Ok(Message::Acknowledge(_)))));

    handle.cancel();
    server_task.abort();
}
