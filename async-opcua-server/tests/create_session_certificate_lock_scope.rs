//! Expected-red CreateSession certificate preflight lock-scope proof.
//!
//! OPC-10000-4 5.7.2 requires CreateSession to preserve client application
//! certificate validation while associating the new Session with the
//! SecureChannel. Certificate preflight should reject an invalid client
//! certificate/applicationUri binding before waiting for the short manager
//! commit lock.

use std::{
    sync::{atomic::Ordering, mpsc},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use opcua_client::{
    services::CreateSession, transport::TransportPollResult, ClientBuilder, IdentityToken,
    UARequest,
};
use opcua_crypto::SecurityPolicy;
use opcua_server::{ServerBuilder, ServerHandle, ANONYMOUS_USER_TOKEN_ID};
use opcua_types::{
    ApplicationDescription, ApplicationType, EndpointDescription, MessageSecurityMode, NodeId,
    StatusCode, UAString,
};
use tokio::net::TcpListener;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const LOCK_READY_TIMEOUT: Duration = Duration::from_secs(2);
const PREFLIGHT_RESPONSE_TIMEOUT: Duration = Duration::from_millis(300);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_session_preserves_certificate_error_after_preflight_split() {
    tokio::time::timeout(TEST_TIMEOUT, run_certificate_preflight_probe())
        .await
        .expect("CreateSession certificate preflight probe should not hang");
}

async fn run_certificate_preflight_probe() {
    let fixture = CreateSessionCertificateFixture::start().await;
    let lock_hold = hold_session_manager_write_lock(fixture.handle.clone());

    lock_hold
        .ready
        .recv_timeout(LOCK_READY_TIMEOUT)
        .expect("manager write lock should be held before sending CreateSession");

    let create_session_result = tokio::time::timeout(
        PREFLIGHT_RESPONSE_TIMEOUT,
        CreateSession::new_manual(
            fixture.client.certificate_store(),
            &fixture.endpoint,
            1,
            Duration::from_secs(5),
            NodeId::null(),
            fixture.channel.request_handle(),
        )
        .endpoint_url(fixture.endpoint_url.as_str())
        .client_description(ApplicationDescription {
            application_uri: UAString::from(
                "urn:async-opcua:create-session-certificate-lock-client-mismatch",
            ),
            product_uri: UAString::from("urn:async-opcua:create-session-certificate-lock-client"),
            application_type: ApplicationType::Client,
            ..Default::default()
        })
        .client_cert_from_store(fixture.client.certificate_store())
        .session_name("create-session-certificate-lock-scope")
        .session_timeout(5_000.0)
        .send(&fixture.channel),
    )
    .await;

    lock_hold
        .release
        .send(())
        .expect("manager write lock holder should still be waiting");
    lock_hold
        .thread
        .join()
        .expect("manager write lock holder should join cleanly");

    fixture.handle.cancel();
    fixture.channel_poller.abort();
    fixture.server_task.abort();

    let create_session_status = create_session_result
        .expect(
            "OPC-10000-4 5.7.2 certificate preflight should reject the invalid client certificate/applicationUri binding before waiting for the manager write lock",
        )
        .expect_err("mismatched client certificate applicationUri should reject CreateSession")
        .status();

    assert_eq!(
        create_session_status,
        StatusCode::BadCertificateUriInvalid,
        "CreateSession certificate preflight must preserve the public certificate error after the lock-scope split"
    );
}

struct LockHold {
    ready: mpsc::Receiver<()>,
    release: mpsc::Sender<()>,
    thread: thread::JoinHandle<()>,
}

fn hold_session_manager_write_lock(handle: ServerHandle) -> LockHold {
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let thread = thread::spawn(move || {
        let guard = handle.session_manager().write();
        let _ = ready_tx.send(());
        let _ = release_rx.recv();
        drop(guard);
    });

    LockHold {
        ready: ready_rx,
        release: release_tx,
        thread,
    }
}

struct CreateSessionCertificateFixture {
    handle: ServerHandle,
    endpoint_url: String,
    endpoint: EndpointDescription,
    client: opcua_client::Client,
    channel: opcua_client::AsyncSecureChannel,
    channel_poller: tokio::task::JoinHandle<()>,
    server_task: tokio::task::JoinHandle<()>,
    _temp_dir: tempfile::TempDir,
}

impl CreateSessionCertificateFixture {
    async fn start() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after Unix epoch")
            .as_nanos();
        let temp_dir = tempfile::Builder::new()
            .prefix("create-session-certificate-lock-scope")
            .tempdir()
            .expect("temporary test directory should be created");
        let server_pki = temp_dir.path().join("server-pki");
        let client_pki = temp_dir.path().join("client-pki");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("CreateSession certificate test listener should bind");
        let port = listener
            .local_addr()
            .expect("CreateSession certificate test listener should have an address")
            .port();
        let endpoint_url = format!("opc.tcp://127.0.0.1:{port}/");

        let (server, handle) = ServerBuilder::new()
            .application_name("CreateSession Certificate Lock Scope")
            .application_uri(format!(
                "urn:async-opcua:create-session-certificate-lock:{unique}"
            ))
            .product_uri("urn:async-opcua:create-session-certificate-lock")
            .host("127.0.0.1")
            .port(port)
            .pki_dir(&server_pki)
            .create_sample_keypair(true)
            .trust_client_certs(true)
            .discovery_urls(vec![endpoint_url.clone()])
            .add_endpoint(
                "secured",
                (
                    "/",
                    SecurityPolicy::Aes128Sha256RsaOaep,
                    MessageSecurityMode::SignAndEncrypt,
                    &[ANONYMOUS_USER_TOKEN_ID] as &[&str],
                ),
            )
            .build()
            .expect("CreateSession certificate test server should build");
        handle.info().port.store(port, Ordering::Relaxed);
        let server_task = tokio::spawn(async move {
            let _ = server.run_with(listener).await;
        });

        let endpoint = handle
            .info()
            .endpoints(&UAString::from(endpoint_url.as_str()), &None)
            .expect("CreateSession certificate test endpoint should be described")
            .into_iter()
            .find(|endpoint| {
                endpoint.security_policy_uri.as_ref()
                    == SecurityPolicy::Aes128Sha256RsaOaep.to_uri()
                    && endpoint.security_mode == MessageSecurityMode::SignAndEncrypt
            })
            .expect("secured CreateSession certificate test endpoint should be advertised");
        let mut client = ClientBuilder::new()
            .application_name("CreateSession Certificate Lock Scope Client")
            .application_uri(format!(
                "urn:async-opcua:create-session-certificate-lock-client:{unique}"
            ))
            .product_uri("urn:async-opcua:create-session-certificate-lock-client")
            .pki_dir(client_pki)
            .create_sample_keypair(true)
            .trust_server_certs(true)
            .session_retry_limit(0)
            .client()
            .expect("CreateSession certificate test client should build");

        let (channel, mut channel_loop) = client
            .open_secure_channel_to_endpoint_directly(endpoint.clone(), IdentityToken::Anonymous)
            .await
            .expect("CreateSession certificate test should open a secure channel");
        let channel_poller = tokio::spawn(async move {
            loop {
                if matches!(channel_loop.poll().await, TransportPollResult::Closed(_)) {
                    break;
                }
            }
        });

        Self {
            handle,
            endpoint_url,
            endpoint,
            client,
            channel,
            channel_poller,
            server_task,
            _temp_dir: temp_dir,
        }
    }
}
