//! Hot-path lock regression tests for simple in-memory method callbacks.

use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc,
    },
    time::Duration,
};

use opcua_client::{ClientBuilder, IdentityToken, Session};
use opcua_crypto::SecurityPolicy;
use opcua_server::{
    address_space::{MethodBuilder, ObjectBuilder},
    diagnostics::NamespaceMetadata,
    node_manager::memory::{simple_node_manager, SimpleNodeManager},
    ServerBuilder, ServerHandle, ANONYMOUS_USER_TOKEN_ID,
};
use opcua_types::{DataTypeId, IdType, MessageSecurityMode, NodeId, ObjectId, StatusCode, Variant};
use tokio::net::TcpListener;

const NAMESPACE_URI: &str = "urn:async-opcua:hot-path:plain-method-callback-locks";
const OBJECT_ID: &str = "CallbackObject";
const METHOD_ID: &str = "PlainEcho";
const REENTRANT_METHOD_ID: &str = "PlainEchoRegisteredFromCallback";
const MANAGER_NAME: &str = "plain-method-lock-test";

static NEXT_TEST_ID: AtomicUsize = AtomicUsize::new(0);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_method_callback_runs_after_registry_guard_is_released() {
    let server = PlainMethodServer::start("plain-method-callback-guard").await;
    let method_id = server.node_id(METHOD_ID);
    let reentrant_method_id = server.node_id(REENTRANT_METHOD_ID);
    let object_id = server.node_id(OBJECT_ID);
    let node_manager = Arc::clone(&server.node_manager);
    let (registry_write_tx, registry_write_rx) = mpsc::channel();

    server
        .node_manager
        .inner()
        .add_method_callback(method_id.clone(), move |args| {
            let node_manager = Arc::clone(&node_manager);
            let reentrant_method_id = reentrant_method_id.clone();
            let registry_write_tx = registry_write_tx.clone();
            let (done_tx, done_rx) = mpsc::channel();

            std::thread::spawn(move || {
                node_manager
                    .inner()
                    .add_method_callback(reentrant_method_id, |_args| {
                        Ok(vec![Variant::from("registered")])
                    });
                let _ = done_tx.send(());
            });

            done_rx
                .recv_timeout(Duration::from_millis(250))
                .map_err(|_| StatusCode::BadInternalError)?;
            let _ = registry_write_tx.send(());

            let Some(Variant::String(value)) = args.first() else {
                return Err(StatusCode::BadInvalidArgument);
            };

            Ok(vec![Variant::from(format!("echo: {}", value.as_ref()))])
        });

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        server.session.call_one((
            object_id,
            method_id,
            Some(vec![Variant::from("guard released")]),
        )),
    )
    .await
    .expect("Call service should not hang while executing a plain method callback")
    .expect("Call service should return one method result");

    assert_eq!(
        result.status_code,
        StatusCode::Good,
        "OPC-10000-4 5.12.2.2 and 5.12.2.4 require Call to complete with the method result; the callback must not run under the plain method registry guard"
    );
    assert_eq!(
        result.output_arguments,
        Some(vec![Variant::from("echo: guard released")])
    );
    assert!(
        registry_write_rx.try_recv().is_ok(),
        "plain method callback should be able to update the callback registry before returning"
    );
}

struct PlainMethodServer {
    handle: ServerHandle,
    node_manager: Arc<SimpleNodeManager>,
    session: Arc<Session>,
    event_loop_task: tokio::task::JoinHandle<StatusCode>,
    server_task: tokio::task::JoinHandle<()>,
    _temp_dir: TempDir,
    namespace_index: u16,
}

impl PlainMethodServer {
    async fn start(test_name: &str) -> Self {
        let temp_dir = TempDir::new(test_name);
        let server_pki = temp_dir.path.join("server-pki");
        let client_pki = temp_dir.path.join("client-pki");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("plain method lock test listener should bind");
        let addr = listener
            .local_addr()
            .expect("plain method lock test listener address");
        let endpoint = format!("opc.tcp://127.0.0.1:{}/", addr.port());
        let namespace = NamespaceMetadata {
            namespace_uri: NAMESPACE_URI.to_string(),
            static_node_id_types: Some(vec![IdType::String]),
            ..Default::default()
        };

        let (server, handle) = ServerBuilder::new()
            .application_name("hot_path_plain_method_callback_locks")
            .application_uri("urn:async-opcua:hot-path:plain-method-callback-locks")
            .product_uri("urn:async-opcua:hot-path:plain-method-callback-locks")
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
            .without_node_managers()
            .with_node_manager(simple_node_manager(namespace, MANAGER_NAME))
            .build()
            .expect("plain method lock test server should build");

        let namespace_index = handle
            .get_namespace_index(NAMESPACE_URI)
            .expect("plain method lock test namespace should be registered");
        let node_manager = handle
            .node_managers()
            .get_by_name::<SimpleNodeManager>(MANAGER_NAME)
            .expect("plain method lock test should have the named SimpleNodeManager");
        assert!(
            node_manager.namespaces().contains_key(&namespace_index),
            "SimpleNodeManager should own namespace {namespace_index}; namespaces: {:?}",
            node_manager.namespaces()
        );

        insert_plain_method_nodes(&node_manager, namespace_index);

        let server_task = tokio::spawn(async move {
            server
                .run_with(listener)
                .await
                .expect("plain method lock test server should run");
        });

        let mut client = ClientBuilder::new()
            .application_name("hot_path_plain_method_callback_locks_client")
            .application_uri("urn:async-opcua:hot-path:plain-method-callback-locks-client")
            .product_uri("urn:async-opcua:hot-path:plain-method-callback-locks-client")
            .pki_dir(client_pki)
            .create_sample_keypair(true)
            .trust_server_certs(true)
            .session_retry_initial(Duration::from_millis(100))
            .client()
            .expect("plain method lock test client should build");

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
            .expect("plain method lock test client should connect");
        let event_loop_task = event_loop.spawn();

        tokio::time::timeout(Duration::from_secs(5), session.wait_for_connection())
            .await
            .expect("plain method lock test client should become connected");

        Self {
            handle,
            node_manager,
            session,
            event_loop_task,
            server_task,
            _temp_dir: temp_dir,
            namespace_index,
        }
    }

    fn node_id(&self, id: &str) -> NodeId {
        NodeId::new(self.namespace_index, id)
    }
}

impl Drop for PlainMethodServer {
    fn drop(&mut self) {
        self.handle.cancel();
        self.server_task.abort();
        self.event_loop_task.abort();
    }
}

fn insert_plain_method_nodes(node_manager: &SimpleNodeManager, namespace_index: u16) {
    let object_id = NodeId::new(namespace_index, OBJECT_ID);
    let method_id = NodeId::new(namespace_index, METHOD_ID);
    let mut address_space = node_manager.address_space().write();

    ObjectBuilder::new(&object_id, "CallbackObject", "CallbackObject")
        .organized_by(ObjectId::ObjectsFolder)
        .insert(&mut *address_space);

    MethodBuilder::new(&method_id, "PlainEcho", "PlainEcho")
        .component_of(object_id)
        .input_args(
            &mut *address_space,
            &NodeId::new(namespace_index, "PlainEchoInputArguments"),
            &[("Value", DataTypeId::String).into()],
        )
        .output_args(
            &mut *address_space,
            &NodeId::new(namespace_index, "PlainEchoOutputArguments"),
            &[("Value", DataTypeId::String).into()],
        )
        .insert(&mut *address_space);
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(test_name: &str) -> Self {
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "async-opcua-hot-path-plain-method-{test_name}-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("plain method lock test temp dir should be created");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if Path::new(&self.path).exists() {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
