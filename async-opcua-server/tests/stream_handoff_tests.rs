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
    sync::oneshot,
};
use tokio_util::codec::FramedRead;

struct DropToken(Option<oneshot::Sender<()>>);

impl Drop for DropToken {
    fn drop(&mut self) {
        if let Some(tx) = self.0.take() {
            let _ = tx.send(());
        }
    }
}

fn drop_token() -> (DropToken, oneshot::Receiver<()>) {
    let (tx, rx) = oneshot::channel();
    (DropToken(Some(tx)), rx)
}

async fn expect_token_drop(rx: oneshot::Receiver<()>, context: &str) {
    tokio::time::timeout(Duration::from_secs(2), rx)
        .await
        .unwrap_or_else(|_| panic!("{context} token should drop"))
        .unwrap_or_else(|_| panic!("{context} token sender should not be canceled before drop"));
}

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
    tx.send((socket, peer_addr, ()))
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

#[tokio::test]
async fn run_with_streams_drops_owned_token_when_connection_closes() {
    let handoff_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("handoff listener should bind");
    let addr = handoff_listener
        .local_addr()
        .expect("handoff listener should have address");
    let endpoint_url = format!("opc.tcp://127.0.0.1:{}/", addr.port());

    let builder = ServerBuilder::new_anonymous("Stream Handoff Token Drop Test")
        .application_uri("urn:stream-handoff-token-drop-test")
        .product_uri("urn:stream-handoff-token-drop-test")
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
    let (token, token_drop_rx) = drop_token();
    tx.send((socket, peer_addr, token))
        .await
        .expect("accepted stream should hand off to server");

    let hello = HelloMessage::new(&endpoint_url, 65_535, 65_535, 0, 0);
    client
        .write_all(&SimpleBinaryEncodable::encode_to_vec(&hello))
        .await
        .expect("client should send HEL");

    let (read, write) = tokio::io::split(client);
    let mut framed = FramedRead::new(read, TcpCodec::new(DecodingOptions::default()));
    let message = tokio::time::timeout(Duration::from_secs(2), framed.next())
        .await
        .expect("server should respond to HEL");

    assert!(matches!(message, Some(Ok(Message::Acknowledge(_)))));

    drop(framed);
    drop(write);
    expect_token_drop(token_drop_rx, "closed connection").await;

    handle.cancel();
    server_task.abort();
}

#[tokio::test]
async fn run_with_streams_drops_owned_token_when_max_connections_rejects() {
    let handoff_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("handoff listener should bind");
    let addr = handoff_listener
        .local_addr()
        .expect("handoff listener should have address");
    let endpoint_url = format!("opc.tcp://127.0.0.1:{}/", addr.port());

    let builder = ServerBuilder::new_anonymous("Stream Handoff Max Connection Test")
        .application_uri("urn:stream-handoff-max-connection-test")
        .product_uri("urn:stream-handoff-max-connection-test")
        .host("127.0.0.1")
        .port(addr.port())
        .discovery_urls(vec![endpoint_url.clone()])
        .max_connections(1);
    let (server, handle) = builder
        .build()
        .expect("stream handoff test server should build");
    let (tx, rx) = tokio::sync::mpsc::channel(2);
    let server_task = tokio::spawn(async move {
        server
            .run_with_streams(rx)
            .await
            .expect("server should run with handed-off streams");
    });

    let mut first_client = TcpStream::connect(addr)
        .await
        .expect("first client should connect to external listener");
    let (first_socket, first_peer_addr) = handoff_listener
        .accept()
        .await
        .expect("external listener should accept first client");
    let (first_token, _first_token_drop_rx) = drop_token();
    tx.send((first_socket, first_peer_addr, first_token))
        .await
        .expect("first stream should hand off to server");

    let hello = HelloMessage::new(&endpoint_url, 65_535, 65_535, 0, 0);
    first_client
        .write_all(&SimpleBinaryEncodable::encode_to_vec(&hello))
        .await
        .expect("first client should send HEL");
    let (first_read, _first_write) = tokio::io::split(first_client);
    let mut first_framed = FramedRead::new(first_read, TcpCodec::new(DecodingOptions::default()));
    let message = tokio::time::timeout(Duration::from_secs(2), first_framed.next())
        .await
        .expect("server should respond to first HEL");
    assert!(matches!(message, Some(Ok(Message::Acknowledge(_)))));

    let _second_client = TcpStream::connect(addr)
        .await
        .expect("second client should connect to external listener");
    let (second_socket, second_peer_addr) = handoff_listener
        .accept()
        .await
        .expect("external listener should accept second client");
    let (second_token, second_token_drop_rx) = drop_token();
    tx.send((second_socket, second_peer_addr, second_token))
        .await
        .expect("second stream should hand off to server");

    expect_token_drop(second_token_drop_rx, "max-connections rejected").await;

    handle.cancel();
    server_task.abort();
}
