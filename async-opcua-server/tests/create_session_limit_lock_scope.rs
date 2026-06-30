//! CreateSession lock-scope regression tests.

use std::{sync::atomic::Ordering, time::Duration};

use opcua_client::{
    services::CreateSession, transport::TransportPollResult, ClientBuilder, IdentityToken,
    UARequest,
};
use opcua_crypto::SecurityPolicy;
use opcua_server::{
    diagnostics::NamespaceMetadata, node_manager::memory::simple_node_manager, ServerBuilder,
    ServerHandle, ANONYMOUS_USER_TOKEN_ID,
};
use opcua_types::{
    ApplicationDescription, ApplicationType, EndpointDescription, MessageSecurityMode, NodeId,
    StatusCode, UAString,
};
use tokio::net::TcpListener;

const TEST_TIMEOUT: Duration = Duration::from_secs(20);
const OPEN_CHANNEL_TIMEOUT: Duration = Duration::from_secs(10);
const FIRST_REQUEST_PAUSE_TIMEOUT: Duration = Duration::from_secs(2);
const SECOND_COMMIT_TIMEOUT: Duration = Duration::from_secs(2);
const CHANNEL_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_session_rechecks_session_limits_at_short_commit() {
    tokio::time::timeout(TEST_TIMEOUT, run_create_session_limit_recheck())
        .await
        .expect(
            "CreateSession limit recheck regression should finish without hanging the test runtime",
        );
}

async fn run_create_session_limit_recheck() {
    let temp = tempfile::Builder::new()
        .prefix("create-session-limit-lock-scope")
        .tempdir()
        .expect("temporary PKI root should be created");
    let server_pki = temp.path().join("server-pki");
    let first_client_pki = temp.path().join("first-client-pki");
    let second_client_pki = temp.path().join("second-client-pki");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("CreateSession limit test listener should bind");
    let port = listener
        .local_addr()
        .expect("CreateSession limit test listener should have an address")
        .port();
    let endpoint_url = format!("opc.tcp://127.0.0.1:{port}/");

    let (server, handle) = ServerBuilder::new()
        .application_name("CreateSession Limit Lock Scope Test Server")
        .application_uri("urn:create-session-limit-lock-scope-server")
        .product_uri("urn:create-session-limit-lock-scope-server")
        .host("127.0.0.1")
        .port(port)
        .pki_dir(&server_pki)
        .create_sample_keypair(true)
        .trust_client_certs(true)
        .max_sessions(1)
        .discovery_urls(vec![endpoint_url.clone()])
        .add_endpoint(
            "none",
            (
                "/",
                SecurityPolicy::None,
                MessageSecurityMode::None,
                &[ANONYMOUS_USER_TOKEN_ID] as &[&str],
            ),
        )
        .add_endpoint(
            "secured",
            (
                "/",
                SecurityPolicy::Aes128Sha256RsaOaep,
                MessageSecurityMode::SignAndEncrypt,
                &[ANONYMOUS_USER_TOKEN_ID] as &[&str],
            ),
        )
        .without_node_managers()
        .with_node_manager(simple_node_manager(
            NamespaceMetadata {
                namespace_uri: "urn:create-session-limit-lock-scope".to_string(),
                namespace_index: 2,
                ..Default::default()
            },
            "create-session-limit-lock-scope",
        ))
        .build()
        .expect("CreateSession limit test server should build");
    handle.info().port.store(port, Ordering::Relaxed);

    let secured_endpoint = endpoint(
        &handle,
        &endpoint_url,
        SecurityPolicy::Aes128Sha256RsaOaep,
        MessageSecurityMode::SignAndEncrypt,
    );
    let unsecured_endpoint = endpoint(
        &handle,
        &endpoint_url,
        SecurityPolicy::None,
        MessageSecurityMode::None,
    );

    let server_task = tokio::spawn(async move {
        let _ = server.run_with(listener).await;
    });

    let mut first_client = ClientBuilder::new()
        .application_name("CreateSession Limit First Client")
        .application_uri("urn:create-session-limit-first-client")
        .product_uri("urn:create-session-limit-first-client")
        .pki_dir(&first_client_pki)
        .create_sample_keypair(true)
        .trust_server_certs(true)
        .session_retry_limit(0)
        .client()
        .expect("first CreateSession limit test client should build");
    let (first_channel, mut first_channel_loop) = tokio::time::timeout(
        OPEN_CHANNEL_TIMEOUT,
        first_client.open_secure_channel_to_endpoint_directly(
            secured_endpoint.clone(),
            IdentityToken::Anonymous,
        ),
    )
    .await
    .expect("first client secured OpenSecureChannel should not time out")
    .expect("first client should open a secured channel");
    let first_channel_poller = tokio::spawn(async move {
        while !matches!(
            first_channel_loop.poll().await,
            TransportPollResult::Closed(_)
        ) {}
    });

    let mut second_client = ClientBuilder::new()
        .application_name("CreateSession Limit Second Client")
        .application_uri("urn:create-session-limit-second-client")
        .product_uri("urn:create-session-limit-second-client")
        .pki_dir(&second_client_pki)
        .create_sample_keypair(true)
        .trust_server_certs(true)
        .session_retry_limit(0)
        .client()
        .expect("second CreateSession limit test client should build");
    let (second_channel, mut second_channel_loop) = tokio::time::timeout(
        OPEN_CHANNEL_TIMEOUT,
        second_client.open_secure_channel_to_endpoint_directly(
            unsecured_endpoint.clone(),
            IdentityToken::Anonymous,
        ),
    )
    .await
    .expect("second client unsecured OpenSecureChannel should not time out")
    .expect("second client should open an unsecured channel");
    let second_channel_poller = tokio::spawn(async move {
        while !matches!(
            second_channel_loop.poll().await,
            TransportPollResult::Closed(_)
        ) {}
    });

    let certificate_store = handle.certificate_store().clone();
    let (gate_ready_tx, gate_ready_rx) = std::sync::mpsc::channel();
    let (gate_release_tx, gate_release_rx) = std::sync::mpsc::channel();
    let certificate_store_gate = std::thread::spawn(move || {
        let _guard = certificate_store.write();
        gate_ready_tx
            .send(())
            .expect("certificate-store gate readiness should be reported");
        let _ = gate_release_rx.recv();
    });
    gate_ready_rx
        .recv_timeout(OPEN_CHANNEL_TIMEOUT)
        .expect("certificate-store gate should be acquired before CreateSession starts");

    let first_endpoint_url = endpoint_url.clone();
    let first_create_session = tokio::spawn(async move {
        let result = CreateSession::new_manual(
            first_client.certificate_store(),
            &secured_endpoint,
            1,
            Duration::from_secs(5),
            NodeId::null(),
            first_channel.request_handle(),
        )
        .endpoint_url(first_endpoint_url.as_str())
        .client_description(ApplicationDescription {
            application_uri: UAString::from("urn:create-session-limit-first-client"),
            product_uri: UAString::from("urn:create-session-limit-first-client"),
            application_type: ApplicationType::Client,
            ..Default::default()
        })
        .client_cert_from_store(first_client.certificate_store())
        .session_name("paused-secured-create-session")
        .session_timeout(5_000.0)
        .send(&first_channel)
        .await;
        (result, first_channel)
    });

    let pause_deadline = tokio::time::Instant::now() + FIRST_REQUEST_PAUSE_TIMEOUT;
    let mut first_request_released_manager = false;
    while tokio::time::Instant::now() < pause_deadline {
        assert!(
            !first_create_session.is_finished(),
            "paused secured CreateSession completed before the certificate-store gate was released"
        );

        if let Some(guard) = handle.session_manager().try_write() {
            drop(guard);
            first_request_released_manager = true;
            break;
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        first_request_released_manager,
        "paused secured CreateSession did not expose a writable SessionManager before commit"
    );

    let second_create_session = tokio::time::timeout(
        SECOND_COMMIT_TIMEOUT,
        CreateSession::new_manual(
            second_client.certificate_store(),
            &unsecured_endpoint,
            2,
            Duration::from_secs(5),
            NodeId::null(),
            second_channel.request_handle(),
        )
        .endpoint_url(endpoint_url.as_str())
        .client_description(ApplicationDescription {
            application_uri: UAString::from("urn:create-session-limit-second-client"),
            product_uri: UAString::from("urn:create-session-limit-second-client"),
            application_type: ApplicationType::Client,
            ..Default::default()
        })
        .session_name("limit-filling-create-session")
        .session_timeout(5_000.0)
        .send(&second_channel),
    )
    .await;

    let second_failure = match second_create_session {
        Ok(Ok(_)) => None,
        Ok(Err(err)) => Some(format!(
            "limit-filling CreateSession returned {:?}; expected it to publish the only allowed session while the first CreateSession was paused before commit",
            err.status()
        )),
        Err(_) => Some(format!(
            "limit-filling CreateSession did not complete within {SECOND_COMMIT_TIMEOUT:?}; the paused CreateSession is still holding the SessionManager write guard instead of doing preflight work outside it"
        )),
    };

    let _ = gate_release_tx.send(());
    certificate_store_gate
        .join()
        .expect("certificate-store gate thread should not panic");

    let (first_result, first_channel) = first_create_session
        .await
        .expect("paused CreateSession task should not panic");
    let first_status = first_result.as_ref().err().map(|err| err.status());

    let _ = tokio::time::timeout(CHANNEL_CLOSE_TIMEOUT, first_channel.close_channel()).await;
    let _ = tokio::time::timeout(CHANNEL_CLOSE_TIMEOUT, second_channel.close_channel()).await;
    let _ = tokio::time::timeout(CHANNEL_CLOSE_TIMEOUT, first_channel_poller).await;
    let _ = tokio::time::timeout(CHANNEL_CLOSE_TIMEOUT, second_channel_poller).await;
    handle.cancel();
    server_task.abort();

    if let Some(message) = second_failure {
        panic!("{message}");
    }

    // OPC-10000-4 5.7.2 associates CreateSession with publishing a session and
    // authentication token. A split preflight/commit path must re-check the
    // session limit immediately before that publish step.
    assert_eq!(
        first_status,
        Some(StatusCode::BadTooManySessions),
        "paused CreateSession must re-check max_sessions at short commit after another session fills the limit"
    );
}

fn endpoint(
    handle: &ServerHandle,
    endpoint_url: &str,
    security_policy: SecurityPolicy,
    security_mode: MessageSecurityMode,
) -> EndpointDescription {
    handle
        .info()
        .endpoints(&UAString::from(endpoint_url), &None)
        .expect("test server endpoint descriptions should be available")
        .into_iter()
        .find(|endpoint| {
            endpoint.security_policy_uri.as_ref() == security_policy.to_uri()
                && endpoint.security_mode == security_mode
        })
        .expect("requested test endpoint should be advertised")
}
