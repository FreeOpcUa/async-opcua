//! Expected-red guard-release proof for normal Session request dispatch.
//!
//! OPC-10000-4 7.32 and 7.35 bind a request's authentication token to the
//! Session/SecureChannel context. Normal dispatch still only needs the
//! `SessionManager` guard for token lookup; validation and dispatch should run
//! after that guard is released.

use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant},
};

use opcua_client::{services::Read, ClientBuilder, IdentityToken, Session};
use opcua_crypto::SecurityPolicy;
use opcua_server::{session::instance::Session as ServerSession, ServerBuilder, ServerHandle};
use opcua_types::{AttributeId, MessageSecurityMode, ReadValueId, StatusCode, VariableId};
use tokio::net::TcpListener;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const SESSION_LOCK_READY_TIMEOUT: Duration = Duration::from_secs(2);
const PROBE_TIMEOUT: Duration = Duration::from_millis(350);

static NEXT_TEST_ID: AtomicUsize = AtomicUsize::new(0);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn normal_request_dispatch_drops_session_manager_guard_before_validation() {
    tokio::time::timeout(TEST_TIMEOUT, run_dispatch_guard_probe())
        .await
        .expect("normal request dispatch guard probe should not hang");
}

async fn run_dispatch_guard_probe() {
    let server = DispatchLockScopeServer::start("normal-request-dispatch").await;
    let auth_token = Read::new(server.session.as_ref())
        .header()
        .authentication_token
        .clone();
    let server_session = {
        let manager = server.handle.session_manager().read();
        manager
            .find_by_token(&auth_token)
            .expect("connected client session should be registered by authentication token")
    };
    assert_eq!(
        server_session.read().session_id(),
        &server.session.server_session_id(),
        "the server-side session should match the connected client session"
    );

    let held_session = hold_server_session_write_lock(server_session);
    held_session
        .ready
        .recv_timeout(SESSION_LOCK_READY_TIMEOUT)
        .expect("server session write lock should be held before dispatching Read");

    let read_task = {
        let session = Arc::clone(&server.session);
        tokio::spawn(async move {
            session
                .read(
                    &[ReadValueId::new(
                        VariableId::Server_ServerStatus_CurrentTime.into(),
                        AttributeId::Value,
                    )],
                    opcua_types::TimestampsToReturn::Neither,
                    0.0,
                )
                .await
        })
    };

    tokio::time::sleep(Duration::from_millis(100)).await;
    let manager_released = manager_write_available_while_validation_is_blocked(&server.handle);

    held_session
        .release
        .send(())
        .expect("server session lock holder should still be waiting");
    held_session
        .thread
        .join()
        .expect("server session lock holder should join cleanly");

    let read_values = tokio::time::timeout(Duration::from_secs(5), read_task)
        .await
        .expect("Read should finish after releasing the blocked server session")
        .expect("Read task should not panic")
        .expect("Read should preserve normal session request behavior");
    assert_eq!(read_values.len(), 1);
    assert!(
        read_values[0].status().is_good(),
        "normal Read dispatch should preserve the service result after the lock-scope split"
    );

    assert!(
        manager_released,
        "OPC-10000-4 7.32 and 7.35 require validation to preserve the RequestHeader authentication-token binding, but normal dispatch should release the SessionManager read guard after lookup and before validation/dispatch"
    );
}

fn manager_write_available_while_validation_is_blocked(handle: &ServerHandle) -> bool {
    let deadline = Instant::now() + PROBE_TIMEOUT;
    while Instant::now() < deadline {
        if let Some(guard) = handle.session_manager().try_write() {
            drop(guard);
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    false
}

struct HeldSessionLock {
    ready: mpsc::Receiver<()>,
    release: mpsc::Sender<()>,
    thread: thread::JoinHandle<()>,
}

fn hold_server_session_write_lock(
    session: Arc<opcua_core::sync::RwLock<ServerSession>>,
) -> HeldSessionLock {
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let thread = thread::spawn(move || {
        let guard = session.write();
        let _ = ready_tx.send(());
        let _ = release_rx.recv();
        drop(guard);
    });

    HeldSessionLock {
        ready: ready_rx,
        release: release_tx,
        thread,
    }
}

struct DispatchLockScopeServer {
    handle: ServerHandle,
    session: Arc<Session>,
    event_loop_task: tokio::task::JoinHandle<StatusCode>,
    server_task: tokio::task::JoinHandle<()>,
    _temp_dir: tempfile::TempDir,
}

impl DispatchLockScopeServer {
    async fn start(test_name: &str) -> Self {
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let temp_dir = tempfile::Builder::new()
            .prefix(&format!("session-dispatch-lock-scope-{test_name}-{id}-"))
            .tempdir()
            .expect("session dispatch lock-scope temporary directory should be created");
        let server_pki = temp_dir.path().join("server-pki");
        let client_pki = temp_dir.path().join("client-pki");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("session dispatch lock-scope listener should bind");
        let port = listener
            .local_addr()
            .expect("session dispatch lock-scope listener should have an address")
            .port();
        let endpoint = format!("opc.tcp://127.0.0.1:{port}/");

        let (server, handle) = ServerBuilder::new()
            .application_name("session_dispatch_lock_scope")
            .application_uri(format!("urn:async-opcua:session-dispatch-lock-scope:{id}"))
            .product_uri("urn:async-opcua:session-dispatch-lock-scope")
            .host("127.0.0.1")
            .port(port)
            .pki_dir(&server_pki)
            .create_sample_keypair(true)
            .discovery_urls(vec![endpoint.clone()])
            .add_endpoint(
                "none",
                (
                    "/",
                    SecurityPolicy::None,
                    MessageSecurityMode::None,
                    &[opcua_server::ANONYMOUS_USER_TOKEN_ID] as &[&str],
                ),
            )
            .build()
            .expect("session dispatch lock-scope server should build");
        handle.info().port.store(port, Ordering::Relaxed);
        let server_task = tokio::spawn(async move {
            server
                .run_with(listener)
                .await
                .expect("session dispatch lock-scope server should run");
        });

        let mut client = ClientBuilder::new()
            .application_name("session_dispatch_lock_scope_client")
            .application_uri(format!(
                "urn:async-opcua:session-dispatch-lock-scope-client:{id}"
            ))
            .product_uri("urn:async-opcua:session-dispatch-lock-scope-client")
            .pki_dir(client_pki)
            .create_sample_keypair(true)
            .trust_server_certs(true)
            .session_retry_initial(Duration::from_millis(100))
            .client()
            .expect("session dispatch lock-scope client should build");

        let (session, event_loop) = client
            .connect_to_matching_endpoint(
                (
                    endpoint.as_str(),
                    SecurityPolicy::None.to_str(),
                    MessageSecurityMode::None,
                ),
                IdentityToken::Anonymous,
            )
            .await
            .expect("session dispatch lock-scope client should connect");
        let event_loop_task = event_loop.spawn();

        tokio::time::timeout(Duration::from_secs(5), session.wait_for_connection())
            .await
            .expect("session dispatch lock-scope client should become connected");

        Self {
            handle,
            session,
            event_loop_task,
            server_task,
            _temp_dir: temp_dir,
        }
    }
}

impl Drop for DispatchLockScopeServer {
    fn drop(&mut self) {
        self.handle.cancel();
        self.event_loop_task.abort();
        self.server_task.abort();
    }
}
