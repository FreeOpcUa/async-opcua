//! Candidate integration tests extending async-opcua/tests/integration/adversarial.rs.
//!
//! To run inside the main suite, copy this file into `async-opcua/tests/integration/`
//! and add `mod adversarial_chunk_edges;` to `mod.rs`. It follows the existing
//! MITM style and binds only ephemeral localhost ports.

use std::{net::SocketAddr, time::Duration};

use opcua::client::IdentityToken;
use opcua::crypto::SecurityPolicy;
use opcua::types::{MessageSecurityMode, NodeId, ReadValueId, TimestampsToReturn, VariableId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::utils::{test_server, Tester};

#[derive(Clone, Copy)]
enum ChunkAttack {
    RewriteSecureChannelId,
    AbortFirstServiceChunk,
}

async fn read_ua_message<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut header = [0u8; 8];
    r.read_exact(&mut header).await?;
    let size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if size < 8 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "message size smaller than header",
        ));
    }
    let mut buf = vec![0u8; size];
    buf[..8].copy_from_slice(&header);
    r.read_exact(&mut buf[8..]).await?;
    Ok(buf)
}

async fn start_proxy(server_addr: SocketAddr, attack: ChunkAttack) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((client_conn, _)) = listener.accept().await else {
                break;
            };
            let Ok(server_conn) = TcpStream::connect(server_addr).await else {
                continue;
            };
            tokio::spawn(handle_conn(client_conn, server_conn, attack));
        }
    });
    proxy_addr
}

async fn handle_conn(client_conn: TcpStream, server_conn: TcpStream, attack: ChunkAttack) {
    let (mut client_r, mut client_w) = client_conn.into_split();
    let (mut server_r, mut server_w) = server_conn.into_split();

    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut server_r, &mut client_w).await;
    });

    let mut attacked = false;
    loop {
        let msg = match read_ua_message(&mut client_r).await {
            Ok(m) => m,
            Err(_) => break,
        };
        let is_msg = msg.len() >= 16 && &msg[0..3] == b"MSG";
        if is_msg && !attacked {
            attacked = true;
            let mut m = msg.clone();
            match attack {
                ChunkAttack::RewriteSecureChannelId => {
                    // OPC UA SecureConversation message header: bytes 8..12
                    // contain the SecureChannelId after the 8-byte TCP header.
                    m[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
                }
                ChunkAttack::AbortFirstServiceChunk => {
                    // Chunk type byte: F/C/A. An Abort during request assembly must
                    // not be treated as a normal complete service request.
                    m[3] = b'A';
                }
            }
            let _ = server_w.write_all(&m).await;
            continue;
        }

        if server_w.write_all(&msg).await.is_err() {
            break;
        }
    }
}

async fn proxied_endpoint(
    tester: &Tester,
    proxy_addr: SocketAddr,
) -> opcua::types::EndpointDescription {
    let endpoints = tester
        .client
        .get_server_endpoints_from_url(tester.endpoint().as_str())
        .await
        .unwrap();
    let mut ep = endpoints
        .into_iter()
        .find(|e| e.security_mode == MessageSecurityMode::None)
        .expect("None endpoint advertised by the server");
    ep.endpoint_url = format!("opc.tcp://127.0.0.1:{}", proxy_addr.port()).into();
    ep
}

async fn read_service_level(session: &opcua::client::Session) -> Result<(), opcua::types::Error> {
    session
        .read(
            &[ReadValueId::from(<VariableId as Into<NodeId>>::into(
                VariableId::Server_ServiceLevel,
            ))],
            TimestampsToReturn::Both,
            0.0,
        )
        .await
        .map(|_| ())
}

async fn assert_attack_rejected_and_server_survives(attack: ChunkAttack) {
    let mut tester = Tester::new(test_server(), true).await;
    let proxy_addr = start_proxy(tester.addr, attack).await;
    let ep = proxied_endpoint(&tester, proxy_addr).await;

    let (_session, lp) = tester
        .client
        .connect_to_endpoint_directly(ep, IdentityToken::Anonymous)
        .unwrap();
    let handle = lp.spawn();

    let status = tokio::time::timeout(Duration::from_secs(30), handle)
        .await
        .expect("event loop should give up once the poisoned channel is rejected")
        .expect("event loop task should not panic");
    assert!(status.is_bad(), "attack must be rejected, got {status}");

    let (session, lp) = tester
        .connect(
            SecurityPolicy::None,
            MessageSecurityMode::None,
            IdentityToken::Anonymous,
        )
        .await
        .unwrap();
    lp.spawn();
    tokio::time::timeout(Duration::from_secs(10), session.wait_for_connection())
        .await
        .unwrap();
    read_service_level(&session).await.unwrap();
}

#[tokio::test]
async fn msg_with_wrong_secure_channel_id_is_rejected() {
    assert_attack_rejected_and_server_survives(ChunkAttack::RewriteSecureChannelId).await;
}

#[tokio::test]
async fn abort_chunk_during_service_request_is_rejected_without_killing_server() {
    assert_attack_rejected_and_server_survives(ChunkAttack::AbortFirstServiceChunk).await;
}
