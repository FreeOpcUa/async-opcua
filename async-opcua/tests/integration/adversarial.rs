//! Adversarial / malicious-transport tests.
//!
//! The high-level client always speaks the protocol correctly, so these tests insert a
//! man-in-the-middle TCP proxy between the client and the real server and corrupt the byte
//! stream (replay a chunk, flip a byte) to verify the server's secure-channel defenses —
//! sequence-number validation and message integrity — actually reject malformed traffic and
//! tear the channel down, while the server itself survives the attack.

use std::net::SocketAddr;
use std::time::Duration;

use opcua::client::IdentityToken;
use opcua::crypto::SecurityPolicy;
use opcua::types::{MessageSecurityMode, NodeId, ReadValueId, TimestampsToReturn, VariableId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::utils::{client_x509_token, test_server, Tester};

/// How the proxy corrupts the first service (`MSG`) chunk of each connection.
#[derive(Clone, Copy)]
enum Attack {
    /// Forward the chunk, then forward it again — a replay with a now-stale sequence number.
    ReplayFirstMsg,
    /// Flip a byte in the chunk body before forwarding — corrupts the signature/ciphertext.
    TamperFirstMsg,
    /// Rewrite the `message_size` header field to a value larger than the negotiated maximum —
    /// a resource-exhaustion attempt the server must reject up front.
    OversizeFirstMsg,
    /// Corrupt the 3-byte message-type code so the framing is no longer a known message kind.
    BadMessageType,
    /// Rewrite the SecureChannelId (bytes 8..12, after the 8-byte TCP header) so the chunk names a
    /// different secure channel than the one the connection established — a routing/auth confusion.
    WrongSecureChannelId,
    /// Change the chunk-type byte (index 3) from final `F` to abort `A`, aborting request assembly.
    AbortFirstMsg,
}

/// Read one full OPC UA TCP message (8-byte header + body; `message_size` at bytes 4..8 covers
/// the whole message including the header).
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

/// Start a MITM proxy that forwards to `server_addr`, applying `attack` to the first `MSG` chunk
/// of every accepted connection. Returns the proxy's listen address.
async fn start_attack_proxy(server_addr: SocketAddr, attack: Attack) -> SocketAddr {
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

async fn handle_conn(client_conn: TcpStream, server_conn: TcpStream, attack: Attack) {
    let (mut client_r, mut client_w) = client_conn.into_split();
    let (mut server_r, mut server_w) = server_conn.into_split();

    // Server -> client: straight passthrough.
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut server_r, &mut client_w).await;
    });

    // Client -> server: corrupt the first MSG chunk, then pass everything else through.
    let mut attacked = false;
    loop {
        let msg = match read_ua_message(&mut client_r).await {
            Ok(m) => m,
            Err(_) => break,
        };
        let is_msg = msg.len() >= 3 && &msg[0..3] == b"MSG";

        if is_msg && !attacked {
            attacked = true;
            match attack {
                Attack::ReplayFirstMsg => {
                    if server_w.write_all(&msg).await.is_err() {
                        break;
                    }
                    // The replay: same bytes, same (now consumed) sequence number.
                    let _ = server_w.write_all(&msg).await;
                    continue;
                }
                Attack::TamperFirstMsg => {
                    let mut m = msg.clone();
                    let idx = m.len() - 5; // within the body, past the headers
                    m[idx] ^= 0xFF;
                    let _ = server_w.write_all(&m).await;
                    continue;
                }
                Attack::OversizeFirstMsg => {
                    let mut m = msg.clone();
                    // Claim a message far larger than any negotiated buffer; the real (short) body
                    // follows, but the server must reject on the declared size before reading it.
                    m[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
                    let _ = server_w.write_all(&m).await;
                    continue;
                }
                Attack::BadMessageType => {
                    let mut m = msg.clone();
                    m[0..3].copy_from_slice(b"XXX");
                    let _ = server_w.write_all(&m).await;
                    continue;
                }
                Attack::WrongSecureChannelId => {
                    let mut m = msg.clone();
                    // SecureChannelId follows the 8-byte TCP message header.
                    m[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
                    let _ = server_w.write_all(&m).await;
                    continue;
                }
                Attack::AbortFirstMsg => {
                    let mut m = msg.clone();
                    m[3] = b'A'; // F (final) -> A (abort)
                    let _ = server_w.write_all(&m).await;
                    continue;
                }
            }
        }

        if server_w.write_all(&msg).await.is_err() {
            break;
        }
    }
}

/// Fetch a server endpoint matching `mode`, then repoint it at the proxy URL.
async fn proxied_endpoint(
    tester: &Tester,
    proxy_addr: SocketAddr,
    policy: SecurityPolicy,
    mode: MessageSecurityMode,
) -> opcua::types::EndpointDescription {
    let endpoints = tester
        .client
        .get_server_endpoints_from_url(tester.endpoint().as_str())
        .await
        .unwrap();
    let mut ep = endpoints
        .into_iter()
        .find(|e| e.security_mode == mode && e.security_policy_uri.as_ref() == policy.to_uri())
        .expect("matching endpoint advertised by the server");
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

/// Drive `attack` through the proxy on a `policy`/`mode` channel and assert two things: the
/// quick-retry client never establishes a session (the server tears down every poisoned channel,
/// so the event loop gives up with a bad status), and the server survives — a normal direct
/// connection of the same `policy`/`mode` still works afterward.
async fn assert_attack_rejected_and_server_survives(
    attack: Attack,
    policy: SecurityPolicy,
    mode: MessageSecurityMode,
) {
    let mut tester = Tester::new(test_server(), true).await;
    let proxy_addr = start_attack_proxy(tester.addr, attack).await;
    let ep = proxied_endpoint(&tester, proxy_addr, policy, mode).await;

    let (_session, lp) = tester
        .client
        .connect_to_endpoint_directly(ep, IdentityToken::Anonymous)
        .unwrap();
    let handle = lp.spawn();

    let status = tokio::time::timeout(Duration::from_secs(30), handle)
        .await
        .expect("event loop should give up once the channel keeps being torn down")
        .expect("event loop task should not panic");
    assert!(status.is_bad(), "attack must be rejected, got {status}");

    // The server must survive the attack: a normal direct connection still works.
    let (session, lp) = tester
        .connect(policy, mode, IdentityToken::Anonymous)
        .await
        .unwrap();
    lp.spawn();
    tokio::time::timeout(Duration::from_secs(10), session.wait_for_connection())
        .await
        .unwrap();
    read_service_level(&session).await.unwrap();
}

/// A replayed secure-channel chunk (duplicate sequence number) must be rejected
/// (Bad_SequenceNumberInvalid), tearing the channel down; the server must survive.
#[tokio::test]
async fn replayed_chunk_is_rejected() {
    assert_attack_rejected_and_server_survives(
        Attack::ReplayFirstMsg,
        SecurityPolicy::None,
        MessageSecurityMode::None,
    )
    .await;
}

/// A tampered (bit-flipped) chunk on a Sign-and-Encrypt channel must fail integrity verification
/// (Bad_SecurityChecksFailed) and be rejected; the server must survive.
#[tokio::test]
async fn tampered_chunk_is_rejected() {
    assert_attack_rejected_and_server_survives(
        Attack::TamperFirstMsg,
        SecurityPolicy::Basic256Sha256,
        MessageSecurityMode::SignAndEncrypt,
    )
    .await;
}

/// A chunk declaring a message size larger than the negotiated maximum must be rejected up front
/// (resource-exhaustion guard) rather than allocated; the server must survive.
#[tokio::test]
async fn oversized_message_is_rejected() {
    assert_attack_rejected_and_server_survives(
        Attack::OversizeFirstMsg,
        SecurityPolicy::None,
        MessageSecurityMode::None,
    )
    .await;
}

/// A chunk with an unknown message-type code must be rejected as a framing error; the server
/// must survive.
#[tokio::test]
async fn invalid_message_type_is_rejected() {
    assert_attack_rejected_and_server_survives(
        Attack::BadMessageType,
        SecurityPolicy::None,
        MessageSecurityMode::None,
    )
    .await;
}

/// A chunk that names a different SecureChannelId than the connection's own channel must be
/// rejected (routing/authentication confusion); the server must survive.
#[tokio::test]
async fn wrong_secure_channel_id_is_rejected() {
    assert_attack_rejected_and_server_survives(
        Attack::WrongSecureChannelId,
        SecurityPolicy::None,
        MessageSecurityMode::None,
    )
    .await;
}

/// A4 proxy (deferred Tier-A item, now ripe on the MITM platform): forward everything, but flip the
/// last byte of the *second* client→server `MSG` chunk. On a `None`-mode channel the service body is
/// plaintext, the second MSG is the ActivateSession request, and its trailing field is the
/// `userTokenSignature` — so this corrupts an X509 user-token signature specifically, proving the
/// server verifies the *user* signature (not just the channel).
async fn start_activate_tamper_proxy(server_addr: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((client_conn, _)) = listener.accept().await {
            let Ok(server_conn) = TcpStream::connect(server_addr).await else {
                continue;
            };
            tokio::spawn(async move {
                let (mut client_r, mut client_w) = client_conn.into_split();
                let (mut server_r, mut server_w) = server_conn.into_split();
                tokio::spawn(async move {
                    let _ = tokio::io::copy(&mut server_r, &mut client_w).await;
                });
                let mut msg_count = 0u32;
                while let Ok(mut msg) = read_ua_message(&mut client_r).await {
                    if msg.len() >= 3 && &msg[0..3] == b"MSG" {
                        msg_count += 1;
                        // MSG #1 is CreateSession (must pass to reach ActivateSession); flip the final
                        // body byte of every MSG from #2 on so each ActivateSession attempt — including
                        // retries on this connection — stays corrupted in its trailing userTokenSignature.
                        if msg_count >= 2 {
                            let last = msg.len() - 1;
                            msg[last] ^= 0xFF;
                        }
                    }
                    if server_w.write_all(&msg).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    proxy_addr
}

/// A4 (multi-AI cross-check, deferred until the MITM harness made it cheap): a tampered X509
/// user-token signature in ActivateSession must be rejected, and the server must survive. Complements
/// `tier_a::empty_password_username_token_is_rejected` — that covers UserName, this covers X509.
#[tokio::test]
async fn tampered_x509_user_token_signature_is_rejected() {
    let mut tester = Tester::new(test_server(), true).await;
    let proxy_addr = start_activate_tamper_proxy(tester.addr).await;
    // None mode so the ActivateSession body is plaintext and the tamper reaches the user signature.
    let ep = proxied_endpoint(
        &tester,
        proxy_addr,
        SecurityPolicy::None,
        MessageSecurityMode::None,
    )
    .await;

    let (_session, lp) = tester
        .client
        .connect_to_endpoint_directly(ep, client_x509_token().expect("x509 token"))
        .unwrap();
    let handle = lp.spawn();
    let status = tokio::time::timeout(Duration::from_secs(30), handle)
        .await
        .expect("event loop should give up once the tampered ActivateSession is rejected")
        .expect("event loop task should not panic");
    assert!(
        status.is_bad(),
        "a tampered X509 user-token signature must be rejected, got {status}"
    );

    // The server must survive: a normal X509 connection still activates.
    let (session, lp) = tester
        .connect(
            SecurityPolicy::None,
            MessageSecurityMode::None,
            client_x509_token().expect("x509 token"),
        )
        .await
        .unwrap();
    lp.spawn();
    tokio::time::timeout(Duration::from_secs(10), session.wait_for_connection())
        .await
        .unwrap();
    read_service_level(&session).await.unwrap();
}

/// B3 proxy: forward everything, but the first time we see an *intermediate* chunk (chunk-type byte
/// `C` at index 3) from client to server, forward it twice — a duplicated reassembly chunk carrying a
/// now-stale sequence number. Handshake messages are single (`F`) chunks, so they pass through and the
/// session establishes; only a large multi-chunk request trips the attack.
async fn start_dup_chunk_proxy(server_addr: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((client_conn, _)) = listener.accept().await {
            let Ok(server_conn) = TcpStream::connect(server_addr).await else {
                continue;
            };
            tokio::spawn(async move {
                let (mut client_r, mut client_w) = client_conn.into_split();
                let (mut server_r, mut server_w) = server_conn.into_split();
                tokio::spawn(async move {
                    let _ = tokio::io::copy(&mut server_r, &mut client_w).await;
                });
                let mut duped = false;
                while let Ok(msg) = read_ua_message(&mut client_r).await {
                    let is_intermediate_chunk = msg.len() >= 4 && msg[3] == b'C';
                    if is_intermediate_chunk && !duped {
                        duped = true;
                        if server_w.write_all(&msg).await.is_err() {
                            break;
                        }
                        // The duplicate: same bytes, same (now consumed) sequence number.
                        let _ = server_w.write_all(&msg).await;
                        continue;
                    }
                    if server_w.write_all(&msg).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    proxy_addr
}

/// B3 (multi-AI cross-check): a duplicated chunk in a multi-chunk message's reassembly must be rejected
/// (stale sequence number) and tear the channel down; the server must survive.
#[tokio::test]
async fn duplicated_reassembly_chunk_is_rejected_and_server_survives() {
    // A client forced to chunk at the 8192-byte minimum, so a large request spans multiple chunks.
    let client = crate::utils::default_client(0, true).max_chunk_size(8192);
    let mut tester = Tester::new_custom_client(test_server(), client).await;
    let proxy_addr = start_dup_chunk_proxy(tester.addr).await;
    let ep = proxied_endpoint(
        &tester,
        proxy_addr,
        SecurityPolicy::None,
        MessageSecurityMode::None,
    )
    .await;

    let (session, lp) = tester
        .client
        .connect_to_endpoint_directly(ep, IdentityToken::Anonymous)
        .unwrap();
    let _h = lp.spawn();
    // Handshake is single-chunk, so the session establishes normally.
    tokio::time::timeout(Duration::from_secs(10), session.wait_for_connection())
        .await
        .expect("handshake (single-chunk) must complete through the proxy");

    // A Read whose single node id is a ~30 KB string forces the request body across several 8192-byte
    // chunks; the proxy duplicates the first intermediate one.
    let big_id = NodeId::new(2, "X".repeat(30_000));
    let res = tokio::time::timeout(
        Duration::from_secs(10),
        session.read(&[ReadValueId::from(big_id)], TimestampsToReturn::Both, 0.0),
    )
    .await
    .expect("the poisoned read must not hang");
    assert!(
        res.is_err(),
        "a duplicated reassembly chunk must not yield a successful read"
    );

    // The server must survive: a normal direct connection still works.
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

/// B5 (multi-AI cross-check): a slow-loris half-open handshake — TCP connections that connect but
/// never finish sending a Hello (or dribble a partial one and stall) — must be timed out and closed
/// by the server's `hello_timeout`, and must not exhaust or wedge it: a normal client still connects
/// afterward.
#[tokio::test]
async fn half_open_handshakes_time_out_and_server_survives() {
    // Short hello timeout so the test is fast; 1s is the minimum granularity (seconds).
    let mut tester = Tester::new(test_server().hello_timeout(1), true).await;

    // Open a batch of half-open connections: most send nothing, one dribbles a partial Hello prefix
    // then stalls. The server must close every one of them on the hello timeout.
    let mut conns = Vec::new();
    for i in 0..16u8 {
        let mut s = TcpStream::connect(tester.addr).await.unwrap();
        if i == 0 {
            // Dribble an incomplete (3-byte) message header, then stall — the classic slow-loris.
            let _ = s.write_all(b"HEL").await;
        }
        conns.push(s);
    }

    // The server must close each one within the hello-timeout window. Drain to EOF (the server may
    // emit a small error frame first); the timeout is the real assertion that it does not hang open.
    for mut s in conns {
        tokio::time::timeout(Duration::from_secs(5), async move {
            let mut buf = [0u8; 64];
            while let Ok(n) = s.read(&mut buf).await {
                if n == 0 {
                    break; // EOF — server closed the connection
                }
            }
        })
        .await
        .expect("server must close a half-open connection within the hello timeout");
    }

    // The server survived the slow-loris: a normal direct connection still works.
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

/// An Abort chunk in place of a final service chunk must be absorbed without killing the server.
/// Unlike the other attacks the server does not surface an error (it abandons the request and the
/// client simply never establishes), so this only asserts the safety property that matters: the
/// server stays healthy and still serves other clients.
#[tokio::test]
async fn abort_chunk_is_absorbed_and_server_survives() {
    let mut tester = Tester::new(test_server(), true).await;
    let proxy_addr = start_attack_proxy(tester.addr, Attack::AbortFirstMsg).await;
    let ep = proxied_endpoint(
        &tester,
        proxy_addr,
        SecurityPolicy::None,
        MessageSecurityMode::None,
    )
    .await;

    // One poisoned connection attempt; do not wait on it (an absorbed abort yields no error to act
    // on, so the event loop would just keep retrying).
    let (_session, lp) = tester
        .client
        .connect_to_endpoint_directly(ep, IdentityToken::Anonymous)
        .unwrap();
    let _h = lp.spawn();
    tokio::time::sleep(Duration::from_millis(500)).await; // let the abort reach the server

    // The server must survive: a normal direct connection still works.
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
