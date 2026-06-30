//! Adversarial / malicious-transport tests.
//!
//! The high-level client always speaks the protocol correctly, so these tests insert a
//! man-in-the-middle TCP proxy between the client and the real server and corrupt the byte
//! stream (replay a chunk, flip a byte) to verify the server's secure-channel defenses —
//! sequence-number validation and message integrity — actually reject malformed traffic and
//! tear the channel down, while the server itself survives the attack.

use std::{fs, net::SocketAddr, path::PathBuf, time::Duration};

use opcua::client::{ClientBuilder, IdentityToken, Session};
use opcua::crypto::{AlternateNames, CertificateStore, SecurityPolicy, X509Data, X509};
use opcua::server::ServerUserToken;
use opcua::types::{
    AttributeId, ByteString, EventFilter, ExtensionObject, MessageSecurityMode,
    MonitoredItemCreateRequest, MonitoringMode, MonitoringParameters, NodeId, NumericRange,
    ObjectId, ObjectTypeId, QualifiedName, ReadValueId, SimpleAttributeOperand, TimestampsToReturn,
    VariableId, Variant,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::utils::{
    client_x509_token, setup, test_server, ChannelNotifications, Tester, CLIENT_X509_ID,
};

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

async fn subscribe_to_certificate_audits(
    session: &Session,
) -> UnboundedReceiver<(ReadValueId, Option<Vec<Variant>>)> {
    let (notifs, _, events) = ChannelNotifications::new();
    let sub_id = session
        .create_subscription(Duration::from_millis(100), 100, 20, 1000, 0, true, notifs)
        .await
        .expect("audit subscription should be created");
    let select = ["EventType", "SourceName", "Certificate", "Status"]
        .into_iter()
        .map(|field| SimpleAttributeOperand {
            type_definition_id: NodeId::new(0, 2041),
            browse_path: Some(vec![QualifiedName::new(0, field)]),
            attribute_id: AttributeId::Value as u32,
            index_range: NumericRange::None,
        })
        .collect();
    let result = session
        .create_monitored_items(
            sub_id,
            TimestampsToReturn::Both,
            vec![MonitoredItemCreateRequest {
                item_to_monitor: ReadValueId {
                    node_id: ObjectId::Server.into(),
                    attribute_id: AttributeId::EventNotifier as u32,
                    ..Default::default()
                },
                monitoring_mode: MonitoringMode::Reporting,
                requested_parameters: MonitoringParameters {
                    sampling_interval: 0.0,
                    queue_size: 10,
                    discard_oldest: true,
                    filter: ExtensionObject::new(EventFilter {
                        select_clauses: Some(select),
                        where_clause: Default::default(),
                    }),
                    ..Default::default()
                },
            }],
        )
        .await
        .expect("audit monitored item should be created");
    assert!(result[0].result.status_code.is_good());
    events
}

async fn expect_certificate_audit(
    events: &mut UnboundedReceiver<(ReadValueId, Option<Vec<Variant>>)>,
    event_type: ObjectTypeId,
    certificate: ByteString,
) {
    let expected_type = Variant::from(NodeId::from(event_type));
    let expected_cert = Variant::from(certificate);
    for _ in 0..16 {
        let Ok(Some((_item, Some(fields)))) =
            tokio::time::timeout(Duration::from_secs(3), events.recv()).await
        else {
            break;
        };
        if fields.len() >= 4 && fields[0] == expected_type && fields[2] == expected_cert {
            assert_eq!(fields[3], Variant::Boolean(false));
            return;
        }
    }
    panic!("expected certificate audit event {event_type:?} was not delivered");
}

async fn expect_certificate_audit_source_name(
    events: &mut UnboundedReceiver<(ReadValueId, Option<Vec<Variant>>)>,
    event_type: ObjectTypeId,
    certificate: ByteString,
    source_name: &str,
) {
    let expected_type = Variant::from(NodeId::from(event_type));
    let expected_source_name = Variant::from(source_name);
    let expected_cert = Variant::from(certificate);
    for _ in 0..16 {
        let Ok(Some((_item, Some(fields)))) =
            tokio::time::timeout(Duration::from_secs(3), events.recv()).await
        else {
            break;
        };
        if fields.len() >= 4 && fields[0] == expected_type && fields[2] == expected_cert {
            assert_eq!(fields[1], expected_source_name);
            assert_eq!(fields[3], Variant::Boolean(false));
            return;
        }
    }
    panic!("expected certificate audit event {event_type:?} was not delivered");
}

async fn expect_successful_certificate_audit(
    events: &mut UnboundedReceiver<(ReadValueId, Option<Vec<Variant>>)>,
    event_type: ObjectTypeId,
    certificate: ByteString,
) {
    let expected_type = Variant::from(NodeId::from(event_type));
    let expected_source_name = Variant::from("Security/Certificate");
    let expected_cert = Variant::from(certificate);
    for _ in 0..16 {
        let Ok(Some((_item, Some(fields)))) =
            tokio::time::timeout(Duration::from_secs(3), events.recv()).await
        else {
            break;
        };
        if fields.len() >= 4 && fields[0] == expected_type && fields[2] == expected_cert {
            assert_eq!(fields[1], expected_source_name);
            assert_eq!(fields[3], Variant::Boolean(true));
            return;
        }
    }
    panic!("expected successful certificate audit event {event_type:?} was not delivered");
}

async fn x509_connect_status(
    tester: &mut Tester,
    token: IdentityToken,
) -> opcua::types::StatusCode {
    match tester
        .connect(SecurityPolicy::None, MessageSecurityMode::None, token)
        .await
    {
        Err(err) => err.status(),
        Ok((session, event_loop)) => {
            let handle = event_loop.spawn();
            if tokio::time::timeout(Duration::from_secs(5), session.wait_for_connection())
                .await
                .is_ok()
            {
                opcua::types::StatusCode::Good
            } else {
                handle
                    .await
                    .expect("X.509 connection event loop should not panic")
            }
        }
    }
}

fn zero_day_x509_user(tmp: &tempfile::TempDir) -> (IdentityToken, PathBuf, ByteString) {
    let mut alt_host_names = AlternateNames::new();
    alt_host_names.add_uri("urn:x509-zero-day-user");
    let data = X509Data {
        key_size: 2048,
        common_name: "x509-zero-day-user".to_string(),
        organization: "async-opcua tests".to_string(),
        organizational_unit: "security".to_string(),
        country: "US".to_string(),
        state: "test".to_string(),
        alt_host_names,
        certificate_duration_days: 0,
    };
    let (cert, private_key) = X509::cert_and_pkey(&data).expect("zero-day X.509 user cert");
    let cert_path = tmp.path().join("zero-day-user.der");
    fs::write(
        &cert_path,
        cert.to_der()
            .expect("zero-day X.509 user cert should encode"),
    )
    .expect("zero-day X.509 user cert should be written");
    let certificate = cert.as_byte_string();
    (
        IdentityToken::new_x509(cert, private_key),
        cert_path,
        certificate,
    )
}

fn zero_day_application_client_certificate(
    tmp: &tempfile::TempDir,
    application_uri: &str,
) -> ByteString {
    let mut alt_host_names = AlternateNames::new();
    alt_host_names.add_uri(application_uri);
    let data = X509Data {
        key_size: 2048,
        common_name: "zero-day-application-client".to_string(),
        organization: "async-opcua tests".to_string(),
        organizational_unit: "security".to_string(),
        country: "US".to_string(),
        state: "test".to_string(),
        alt_host_names,
        certificate_duration_days: 0,
    };
    let cert_path = tmp.path().join("own/cert.der");
    let private_key_path = tmp.path().join("private/private.pem");
    let (cert, _private_key) =
        CertificateStore::create_certificate_and_key(&data, true, &cert_path, &private_key_path)
            .expect("zero-day application client certificate should be written");
    cert.as_byte_string()
}

/// A4 (multi-AI cross-check): an invalid X509 user-token signature in ActivateSession must be
/// rejected distinctly from certificate validation, and the server must survive. Complements
/// `tier_a::empty_password_username_token_is_rejected` — that covers UserName, this covers X509.
#[tokio::test]
async fn tampered_x509_user_token_signature_is_rejected() {
    let mut tester = Tester::new(test_server(), true).await;

    let user_cert =
        CertificateStore::read_cert(PathBuf::from("./tests/x509/user_cert.der").as_path())
            .expect("fixture X.509 user certificate should load");
    let mut alt_host_names = AlternateNames::new();
    alt_host_names.add_uri("urn:wrong-x509-user-token-signing-key");
    let (_, wrong_private_key) = X509::cert_and_pkey(&X509Data {
        key_size: 2048,
        common_name: "wrong-x509-user-token-signing-key".to_string(),
        organization: "async-opcua test".to_string(),
        organizational_unit: "integration".to_string(),
        country: "DE".to_string(),
        state: "Berlin".to_string(),
        alt_host_names,
        certificate_duration_days: 30,
    })
    .expect("unrelated X.509 private key should be generated");
    let wrong_signature_identity = IdentityToken::new_x509(user_cert, wrong_private_key);

    let (_session, lp) = tester
        .connect(
            SecurityPolicy::None,
            MessageSecurityMode::None,
            wrong_signature_identity,
        )
        .await
        .expect("session event loop should be built before activation fails");
    let handle = lp.spawn();
    let status = tokio::time::timeout(Duration::from_secs(30), handle)
        .await
        .expect("event loop should give up once ActivateSession rejects the bad user signature")
        .expect("event loop task should not panic");
    assert_eq!(
        status,
        opcua::types::StatusCode::BadUserSignatureInvalid,
        "an invalid X509 user-token signature must be distinguishable from certificate validation"
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

#[tokio::test]
async fn open_secure_channel_invalid_certificate_audit_uses_certificate_source_name() {
    let mut tester = Tester::new(test_server().trust_client_certs(false), true).await;
    let (audit_session, audit_event_loop) = tester.connect_default().await.unwrap();
    audit_event_loop.spawn();
    tokio::time::timeout(Duration::from_secs(10), audit_session.wait_for_connection())
        .await
        .expect("audit observer session should activate");
    let mut events = subscribe_to_certificate_audits(&audit_session).await;

    let invalid_client_pki =
        tempfile::tempdir().expect("invalid OpenSecureChannel client PKI tempdir");
    let _seed_client = ClientBuilder::new()
        .application_name("invalid OpenSecureChannel certificate audit client")
        .application_uri("urn:invalid-open-secure-channel-certificate-audit-client")
        .product_uri("urn:invalid-open-secure-channel-certificate-audit-client")
        .pki_dir(invalid_client_pki.path())
        .create_sample_keypair(true)
        .trust_server_certs(true)
        .session_retry_limit(0)
        .session_retry_initial(Duration::from_millis(20))
        .client()
        .expect("seed invalid OpenSecureChannel client should build");
    drop(_seed_client);

    let cert_path = invalid_client_pki.path().join("own/cert.der");
    let mut invalid_cert_der =
        fs::read(&cert_path).expect("generated application certificate should be readable");
    let last_signature_byte = invalid_cert_der
        .last_mut()
        .expect("generated application certificate DER should not be empty");
    *last_signature_byte ^= 0x01;
    fs::write(&cert_path, &invalid_cert_der)
        .expect("invalid application certificate should be written");
    let presented_certificate = ByteString::from(invalid_cert_der);

    let endpoints = tester
        .client
        .get_server_endpoints_from_url(tester.endpoint().as_str())
        .await
        .unwrap();
    let endpoint = endpoints
        .into_iter()
        .find(|endpoint| {
            endpoint.security_policy_uri.as_ref() == SecurityPolicy::Basic256Sha256.to_uri()
                && endpoint.security_mode == MessageSecurityMode::SignAndEncrypt
        })
        .expect("secured endpoint should be advertised");
    let mut invalid_client = ClientBuilder::new()
        .application_name("invalid OpenSecureChannel certificate audit client")
        .application_uri("urn:invalid-open-secure-channel-certificate-audit-client")
        .product_uri("urn:invalid-open-secure-channel-certificate-audit-client")
        .pki_dir(invalid_client_pki.path())
        .certificate_path("own/cert.der")
        .private_key_path("private/private.pem")
        .create_sample_keypair(false)
        .trust_server_certs(true)
        .session_retry_limit(0)
        .session_retry_initial(Duration::from_millis(20))
        .client()
        .expect("invalid OpenSecureChannel client should build");

    let (_failed_session, event_loop) = invalid_client
        .connect_to_endpoint_directly(endpoint, IdentityToken::Anonymous)
        .expect("invalid OpenSecureChannel session event loop should be created");
    let status = tokio::time::timeout(Duration::from_secs(10), event_loop.run())
        .await
        .expect("OpenSecureChannel invalid-certificate rejection should complete");
    assert_eq!(status, opcua::types::StatusCode::BadSecurityChecksFailed);
    audit_session.trigger_publish_now();

    expect_certificate_audit_source_name(
        &mut events,
        ObjectTypeId::AuditCertificateInvalidEventType,
        presented_certificate,
        "Security/Certificate",
    )
    .await;
}

#[tokio::test]
async fn hard_x509_user_certificate_validation_failure_emits_audit_certificate_event() {
    let (mut tester, _nm, session) = setup().await;
    let mut events = subscribe_to_certificate_audits(&session).await;

    let user_cert =
        CertificateStore::read_cert(PathBuf::from("./tests/x509/user_cert.der").as_path())
            .expect("fixture X.509 user cert should read")
            .as_byte_string();
    let trusted_user_cert = format!("pki-server/{}/trusted/user_cert.der", tester.test_id);
    let rejected_dir = format!("pki-server/{}/rejected", tester.test_id);
    let _ = fs::remove_file(trusted_user_cert);
    let _ = fs::remove_dir_all(&rejected_dir);
    fs::create_dir_all(&rejected_dir).expect("test rejected PKI dir should be reset");

    let (_failed_session, event_loop) = tester
        .connect(
            SecurityPolicy::None,
            MessageSecurityMode::None,
            client_x509_token().expect("fixture X.509 token"),
        )
        .await
        .expect("client should reach ActivateSession before X.509 certificate validation fails");
    let handle = event_loop.spawn();
    expect_certificate_audit(
        &mut events,
        ObjectTypeId::AuditCertificateUntrustedEventType,
        user_cert,
    )
    .await;
    handle.abort();
}

#[tokio::test]
async fn suppressed_x509_user_certificate_validation_finding_emits_audit_certificate_event() {
    let tmp = tempfile::tempdir().expect("zero-day X.509 fixture tempdir");
    let (identity, cert_path, certificate) = zero_day_x509_user(&tmp);
    let server = test_server().check_cert_time(false).add_user_token(
        CLIENT_X509_ID,
        ServerUserToken::x509(CLIENT_X509_ID, &cert_path),
    );
    let mut tester = Tester::new(server, false).await;
    let (session, event_loop) = tester.connect_default().await.unwrap();
    event_loop.spawn();
    tokio::time::timeout(Duration::from_secs(20), session.wait_for_connection())
        .await
        .expect("audit observer session should activate");
    let mut events = subscribe_to_certificate_audits(&session).await;

    tokio::time::sleep(Duration::from_millis(1100)).await;
    let status = x509_connect_status(&mut tester, identity).await;
    assert_eq!(status, opcua::types::StatusCode::Good);
    expect_certificate_audit(
        &mut events,
        ObjectTypeId::AuditCertificateExpiredEventType,
        certificate,
    )
    .await;
}

#[tokio::test]
async fn create_session_with_suppressed_client_certificate_finding_emits_success_audit_event() {
    let client_pki =
        tempfile::tempdir().expect("suppressed application certificate client PKI tempdir");
    let application_uri = "urn:suppressed-client-certificate-audit-client";
    let presented_certificate =
        zero_day_application_client_certificate(&client_pki, application_uri);

    let mut tester = Tester::new(test_server().check_cert_time(false), true).await;
    let (audit_session, audit_event_loop) = tester.connect_default().await.unwrap();
    audit_event_loop.spawn();
    tokio::time::timeout(Duration::from_secs(10), audit_session.wait_for_connection())
        .await
        .expect("audit observer session should activate");
    let mut events = subscribe_to_certificate_audits(&audit_session).await;

    tokio::time::sleep(Duration::from_millis(1100)).await;
    let endpoints = tester
        .client
        .get_server_endpoints_from_url(tester.endpoint().as_str())
        .await
        .unwrap();
    let endpoint = endpoints
        .into_iter()
        .find(|endpoint| {
            endpoint.security_policy_uri.as_ref() == SecurityPolicy::Basic256Sha256.to_uri()
                && endpoint.security_mode == MessageSecurityMode::SignAndEncrypt
        })
        .expect("secured endpoint should be advertised");

    let mut expired_client = ClientBuilder::new()
        .application_name("suppressed client certificate audit client")
        .application_uri(application_uri)
        .product_uri("urn:suppressed-client-certificate-audit-client")
        .pki_dir(client_pki.path())
        .certificate_path("own/cert.der")
        .private_key_path("private/private.pem")
        .create_sample_keypair(false)
        .trust_server_certs(true)
        .session_retry_limit(0)
        .session_retry_initial(Duration::from_millis(20))
        .client()
        .expect("expired application certificate client should build");

    let (session, event_loop) = expired_client
        .connect_to_endpoint_directly(endpoint, IdentityToken::Anonymous)
        .expect("expired application certificate session event loop should be created");
    let handle = event_loop.spawn();
    tokio::time::timeout(Duration::from_secs(10), session.wait_for_connection())
        .await
        .expect("suppressed application certificate client should activate");
    read_service_level(&session).await.unwrap();
    audit_session.trigger_publish_now();

    expect_successful_certificate_audit(
        &mut events,
        ObjectTypeId::AuditCertificateExpiredEventType,
        presented_certificate,
    )
    .await;
    handle.abort();
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
