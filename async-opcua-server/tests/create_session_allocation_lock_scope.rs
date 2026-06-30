//! CreateSession allocation proof.
//!
//! OPC-10000-4 5.7.2 requires CreateSession to preserve Session allocation
//! errors while associating the new Session with the SecureChannel. A split
//! preflight/commit path must re-check per-channel unactivated-session
//! allocation limits at the short commit step.

use std::{
    sync::atomic::Ordering,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use opcua_client::{
    services::CreateSession, transport::TransportPollResult, ClientBuilder, IdentityToken,
    UARequest,
};
use opcua_crypto::SecurityPolicy;
use opcua_server::{Limits, ServerBuilder, ServerHandle, ANONYMOUS_USER_TOKEN_ID};
use opcua_types::{
    ApplicationDescription, ApplicationType, EndpointDescription, MessageSecurityMode, NodeId,
    StatusCode, UAString,
};
use tokio::net::TcpListener;

const TEST_TIMEOUT: Duration = Duration::from_secs(20);
const OPEN_CHANNEL_TIMEOUT: Duration = Duration::from_secs(10);
const CREATE_SESSION_TIMEOUT: Duration = Duration::from_secs(5);
const CHANNEL_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_session_preserves_allocation_error_after_preflight_split() {
    tokio::time::timeout(TEST_TIMEOUT, run_create_session_allocation_probe())
        .await
        .expect("CreateSession allocation lock-scope probe should not hang");
}

async fn run_create_session_allocation_probe() {
    let fixture = CreateSessionAllocationFixture::start().await;

    let first_response = tokio::time::timeout(
        CREATE_SESSION_TIMEOUT,
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
            application_uri: UAString::from(fixture.client_application_uri.as_str()),
            product_uri: UAString::from("urn:create-session-allocation-first-client"),
            application_type: ApplicationType::Client,
            ..Default::default()
        })
        .client_cert_from_store(fixture.client.certificate_store())
        .session_name("unactivated-create-session-allocation")
        .session_timeout(5_000.0)
        .send(&fixture.channel),
    )
    .await
    .expect("first CreateSession should not time out")
    .expect("first CreateSession should allocate the only unactivated session slot");

    let second_result = tokio::time::timeout(
        CREATE_SESSION_TIMEOUT,
        CreateSession::new_manual(
            fixture.client.certificate_store(),
            &fixture.endpoint,
            2,
            Duration::from_secs(5),
            NodeId::null(),
            fixture.channel.request_handle(),
        )
        .endpoint_url(fixture.endpoint_url.as_str())
        .client_description(ApplicationDescription {
            application_uri: UAString::from(fixture.client_application_uri.as_str()),
            product_uri: UAString::from("urn:create-session-allocation-second-client"),
            application_type: ApplicationType::Client,
            ..Default::default()
        })
        .client_cert_from_store(fixture.client.certificate_store())
        .session_name("slot-filling-create-session-allocation")
        .session_timeout(5_000.0)
        .send(&fixture.channel),
    )
    .await;

    let second_status = second_result
        .expect("second CreateSession should finish after commit-time allocation recheck")
        .as_ref()
        .err()
        .map(|err| err.status());

    let _ = tokio::time::timeout(CHANNEL_CLOSE_TIMEOUT, fixture.channel.close_channel()).await;
    let _ = tokio::time::timeout(CHANNEL_CLOSE_TIMEOUT, fixture.channel_poller).await;
    fixture.handle.cancel();
    fixture.server_task.abort();

    assert!(
        !first_response.authentication_token.is_null(),
        "first CreateSession should publish an unactivated session token"
    );

    // OPC-10000-4 5.7.2 associates CreateSession with publishing a session and
    // authentication token. After preflight is split from commit, commit must
    // still enforce per-channel unactivated-session allocation limits.
    assert_eq!(
        second_status,
        Some(StatusCode::BadTooManySessions),
        "second CreateSession on the same channel must preserve BadTooManySessions while the first session remains unactivated"
    );
}

struct CreateSessionAllocationFixture {
    handle: ServerHandle,
    endpoint_url: String,
    client_application_uri: String,
    endpoint: EndpointDescription,
    client: opcua_client::Client,
    channel: opcua_client::AsyncSecureChannel,
    channel_poller: tokio::task::JoinHandle<()>,
    server_task: tokio::task::JoinHandle<()>,
    _temp_dir: tempfile::TempDir,
}

impl CreateSessionAllocationFixture {
    async fn start() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after Unix epoch")
            .as_nanos();
        let temp_dir = tempfile::Builder::new()
            .prefix("create-session-allocation-lock-scope")
            .tempdir()
            .expect("temporary test directory should be created");
        let server_pki = temp_dir.path().join("server-pki");
        let client_pki = temp_dir.path().join("client-pki");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("CreateSession allocation test listener should bind");
        let port = listener
            .local_addr()
            .expect("CreateSession allocation test listener should have an address")
            .port();
        let endpoint_url = format!("opc.tcp://127.0.0.1:{port}/");

        let client_application_uri =
            format!("urn:async-opcua:create-session-allocation-lock-client:{unique}");

        let (server, handle) = ServerBuilder::new()
            .application_name("CreateSession Allocation Lock Scope")
            .application_uri(format!(
                "urn:async-opcua:create-session-allocation-lock:{unique}"
            ))
            .product_uri("urn:async-opcua:create-session-allocation-lock")
            .host("127.0.0.1")
            .port(port)
            .pki_dir(&server_pki)
            .create_sample_keypair(true)
            .trust_client_certs(true)
            .limits(Limits {
                max_unactivated_sessions_per_channel: 1,
                ..Default::default()
            })
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
            .expect("CreateSession allocation test server should build");
        handle.info().port.store(port, Ordering::Relaxed);
        let server_task = tokio::spawn(async move {
            let _ = server.run_with(listener).await;
        });

        let endpoint = handle
            .info()
            .endpoints(&UAString::from(endpoint_url.as_str()), &None)
            .expect("CreateSession allocation test endpoint should be described")
            .into_iter()
            .find(|endpoint| {
                endpoint.security_policy_uri.as_ref()
                    == SecurityPolicy::Aes128Sha256RsaOaep.to_uri()
                    && endpoint.security_mode == MessageSecurityMode::SignAndEncrypt
            })
            .expect("secured CreateSession allocation test endpoint should be advertised");
        let mut client = ClientBuilder::new()
            .application_name("CreateSession Allocation Lock Scope Client")
            .application_uri(client_application_uri.clone())
            .product_uri("urn:async-opcua:create-session-allocation-lock-client")
            .pki_dir(client_pki)
            .create_sample_keypair(true)
            .trust_server_certs(true)
            .session_retry_limit(0)
            .client()
            .expect("CreateSession allocation test client should build");

        let (channel, mut channel_loop) = tokio::time::timeout(
            OPEN_CHANNEL_TIMEOUT,
            client.open_secure_channel_to_endpoint_directly(
                endpoint.clone(),
                IdentityToken::Anonymous,
            ),
        )
        .await
        .expect("CreateSession allocation OpenSecureChannel should not time out")
        .expect("CreateSession allocation test should open a secure channel");
        let channel_poller = tokio::spawn(async move {
            while !matches!(channel_loop.poll().await, TransportPollResult::Closed(_)) {}
        });

        Self {
            handle,
            endpoint_url,
            client_application_uri,
            endpoint,
            client,
            channel,
            channel_poller,
            server_task,
            _temp_dir: temp_dir,
        }
    }
}
