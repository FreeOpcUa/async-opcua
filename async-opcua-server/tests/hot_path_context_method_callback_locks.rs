//! Hot-path lock tests for context-aware core method callbacks.
//!
//! OPC UA Part 4 5.12.2.2 defines the CallMethodRequest object/method invocation
//! shape; 5.12.2.4 requires a per-method CallMethodResult. This test keeps the
//! service behavior observable while proving the core method registry guard is not
//! held across the callback body.

use std::{
    sync::{Arc, Weak},
    time::Duration,
};

use opcua_client::{ClientBuilder, IdentityToken, Session};
use opcua_crypto::SecurityPolicy;
use opcua_server::{
    node_manager::memory::CoreNodeManager, ServerBuilder, ServerHandle, ANONYMOUS_USER_TOKEN_ID,
};
use opcua_types::{MessageSecurityMode, MethodId, NodeId, ObjectTypeId, StatusCode, Variant};
use tempfile::TempDir;
use tokio::net::TcpListener;

const REGISTRY_REENTER_TIMEOUT: Duration = Duration::from_secs(1);
const CALL_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn context_method_callback_runs_after_registry_guard_is_released() {
    let server = CoreMethodServer::start("context-method-registry-guard").await;

    let result = tokio::time::timeout(
        CALL_TIMEOUT,
        server.session.call_one((
            NodeId::from(ObjectTypeId::ProgramStateMachineType),
            NodeId::from(MethodId::ProgramStateMachineType_Start),
            Some(Vec::new()),
        )),
    )
    .await
    .expect("context method Call should not hang while proving registry guard release")
    .expect("Call service should return a method result");

    assert_eq!(result.status_code, StatusCode::Good);
    assert_eq!(
        result.output_arguments,
        Some(vec![Variant::from("registry guard released")])
    );
}

fn register_reentrant_guard_probe(core: &Arc<CoreNodeManager>) {
    let trigger_method = NodeId::from(MethodId::ProgramStateMachineType_Start);
    let reentrant_method = NodeId::from(MethodId::ProgramStateMachineType_Suspend);
    let core_ref = Arc::downgrade(core);

    core.inner().add_method_callback_with_context(
        trigger_method,
        move |_context, _object_id, _args| {
            let Some(core) = Weak::upgrade(&core_ref) else {
                return Err(StatusCode::BadInternalError);
            };
            let reentrant_method = reentrant_method.clone();
            let (done_tx, done_rx) = std::sync::mpsc::channel();

            std::thread::spawn(move || {
                core.inner().add_method_callback_with_context(
                    reentrant_method,
                    |_context, _object_id, _args| Ok(Vec::new()),
                );
                let _ = done_tx.send(());
            });

            done_rx
                .recv_timeout(REGISTRY_REENTER_TIMEOUT)
                .map(|()| vec![Variant::from("registry guard released")])
                .map_err(|_| StatusCode::BadTimeout)
        },
    );
}

struct CoreMethodServer {
    handle: ServerHandle,
    session: Arc<Session>,
    event_loop_task: tokio::task::JoinHandle<StatusCode>,
    server_task: tokio::task::JoinHandle<()>,
    _temp_dir: TempDir,
}

impl CoreMethodServer {
    async fn start(test_name: &str) -> Self {
        let temp_dir = tempfile::Builder::new()
            .prefix(&format!("async-opcua-{test_name}-"))
            .tempdir()
            .expect("method lock test temp dir should be created");
        let server_pki = temp_dir.path().join("server-pki");
        let client_pki = temp_dir.path().join("client-pki");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("method lock test listener should bind");
        let addr = listener
            .local_addr()
            .expect("method lock test listener address");
        let endpoint = format!("opc.tcp://127.0.0.1:{}/", addr.port());

        let (server, handle) = ServerBuilder::new()
            .application_name("hot_path_context_method_callback_locks")
            .application_uri("urn:async-opcua:hot-path-context-method-callback-locks")
            .product_uri("urn:async-opcua:hot-path-context-method-callback-locks")
            .host("127.0.0.1")
            .pki_dir(&server_pki)
            .create_sample_keypair(true)
            .discovery_urls(vec![endpoint.clone()])
            .add_endpoint(
                "none",
                (
                    "/",
                    SecurityPolicy::None,
                    MessageSecurityMode::None,
                    &[ANONYMOUS_USER_TOKEN_ID] as &[&str],
                ),
            )
            .build()
            .expect("method lock test server should build");

        let core = handle
            .node_managers()
            .get_of_type::<CoreNodeManager>()
            .expect("default core node manager should be registered");
        register_reentrant_guard_probe(&core);

        let server_task = tokio::spawn(async move {
            server
                .run_with(listener)
                .await
                .expect("method lock test server should run");
        });

        let mut client = ClientBuilder::new()
            .application_name("hot_path_context_method_callback_locks_client")
            .application_uri("urn:async-opcua:hot-path-context-method-callback-locks-client")
            .product_uri("urn:async-opcua:hot-path-context-method-callback-locks-client")
            .pki_dir(client_pki)
            .create_sample_keypair(true)
            .trust_server_certs(true)
            .session_retry_initial(Duration::from_millis(100))
            .client()
            .expect("method lock test client should build");

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
            .expect("method lock test client should connect");
        let event_loop_task = event_loop.spawn();

        tokio::time::timeout(CALL_TIMEOUT, session.wait_for_connection())
            .await
            .expect("method lock test client should become connected");

        Self {
            handle,
            session,
            event_loop_task,
            server_task,
            _temp_dir: temp_dir,
        }
    }
}

impl Drop for CoreMethodServer {
    fn drop(&mut self) {
        self.handle.cancel();
        self.server_task.abort();
        self.event_loop_task.abort();
    }
}
