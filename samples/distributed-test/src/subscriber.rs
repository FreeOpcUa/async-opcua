use opcua::types::{BinaryDecodable, Variant};
use opcua_pubsub::UadpNetworkMessage;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() {
    println!("Starting PLC Subscriber on PLC02...");
    // Bind to 0.0.0.0 to receive UDP messages from anywhere
    let receiver_socket = UdpSocket::bind("0.0.0.0:4840").await.unwrap();
    println!("Subscriber listening on UDP 4840...");
    let mut buf = [0u8; 4096];

    let mut messages_received = 0;
    while messages_received < 5 {
        let (len, from_addr) = receiver_socket.recv_from(&mut buf).await.unwrap();
        println!("Received UDP packet of len {} from {}", len, from_addr);

        let ctx_owned = opcua::types::ContextOwned::default();
        let ctx = ctx_owned.context();
        if let Ok(decoded_msg) = UadpNetworkMessage::decode(&mut &buf[..len], &ctx) {
            println!("Decoded message: {:?}", decoded_msg);
            messages_received += 1;
        } else {
            println!("Failed to decode message");
        }
    }
    println!("Subscriber successfully received messages!");
}
