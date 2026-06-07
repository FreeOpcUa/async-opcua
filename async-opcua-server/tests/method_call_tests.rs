//! Call service integration tests for in-memory node managers.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use async_trait::async_trait;
use opcua_client::{ClientBuilder, IdentityToken, Session};
use opcua_core::sync::RwLock;
use opcua_crypto::SecurityPolicy;
use opcua_server::{
    address_space::{AddressSpace, MethodBuilder, ObjectBuilder},
    diagnostics::NamespaceMetadata,
    node_manager::{
        memory::{
            InMemoryMethodCallback, InMemoryNodeManagerBuilder, InMemoryNodeManagerImpl,
            InMemoryNodeManagerImplBuilder,
        },
        RequestContext, ServerContext,
    },
    ServerBuilder, ServerHandle, ANONYMOUS_USER_TOKEN_ID,
};
use opcua_types::{DataTypeId, IdType, MessageSecurityMode, NodeId, ObjectId, StatusCode, Variant};
use tokio::net::TcpListener;

const METHOD_NAMESPACE_URI: &str = "urn:async-opcua:method-call-tests:nodes";
const OBJECT_ID: &str = "CallbackObject";
const METHOD_ID: &str = "Echo";

static NEXT_TEST_ID: AtomicUsize = AtomicUsize::new(0);

#[tokio::test]
async fn custom_in_memory_node_manager_default_call_executes_registered_method_callback() {
    let server = MethodServer::start("custom-default-call").await;

    let result = server
        .session
        .call_one((
            NodeId::new(server.namespace_index, OBJECT_ID),
            NodeId::new(server.namespace_index, METHOD_ID),
            Some(vec![Variant::from("wort")]),
        ))
        .await
        .expect("Call service should return a method result");

    assert_eq!(result.status_code, StatusCode::Good);
    assert_eq!(
        result.output_arguments,
        Some(vec![Variant::from("echo: wort")])
    );
}

type CallbackRegistry = Arc<RwLock<HashMap<NodeId, InMemoryMethodCallback>>>;

struct CallbackNodeManagerBuilder {
    namespace_uri: String,
    callbacks: CallbackRegistry,
}

impl CallbackNodeManagerBuilder {
    fn new(namespace_uri: &str) -> Self {
        Self {
            namespace_uri: namespace_uri.to_owned(),
            callbacks: Default::default(),
        }
    }
}

impl InMemoryNodeManagerImplBuilder for CallbackNodeManagerBuilder {
    type Impl = CallbackNodeManager;

    fn build(self, context: ServerContext, address_space: &mut AddressSpace) -> Self::Impl {
        let namespace_index = context
            .type_tree
            .write()
            .namespaces_mut()
            .add_namespace(&self.namespace_uri);
        address_space.add_namespace(&self.namespace_uri, namespace_index);

        self.callbacks.write().insert(
            NodeId::new(namespace_index, METHOD_ID),
            Arc::new(|_context: &RequestContext, args: &[Variant]| {
                let Some(Variant::String(value)) = args.first() else {
                    return Err(StatusCode::BadInvalidArgument);
                };

                Ok(vec![Variant::from(format!("echo: {}", value.as_ref()))])
            }),
        );

        CallbackNodeManager {
            namespace: NamespaceMetadata {
                is_namespace_subset: Some(false),
                namespace_uri: self.namespace_uri,
                static_node_id_types: Some(vec![IdType::String]),
                namespace_index,
                ..Default::default()
            },
            callbacks: self.callbacks,
        }
    }
}

struct CallbackNodeManager {
    namespace: NamespaceMetadata,
    callbacks: CallbackRegistry,
}

impl CallbackNodeManager {
    fn node_id(&self, id: &str) -> NodeId {
        NodeId::new(self.namespace.namespace_index, id)
    }
}

#[async_trait]
impl InMemoryNodeManagerImpl for CallbackNodeManager {
    async fn init(&self, address_space: &mut AddressSpace, _context: ServerContext) {
        ObjectBuilder::new(&self.node_id(OBJECT_ID), "CallbackObject", "CallbackObject")
            .organized_by(ObjectId::ObjectsFolder)
            .insert(address_space);

        MethodBuilder::new(&self.node_id(METHOD_ID), "Echo", "Echo")
            .component_of(self.node_id(OBJECT_ID))
            .input_args(
                address_space,
                &self.node_id("EchoInputArguments"),
                &[("Value", DataTypeId::String).into()],
            )
            .output_args(
                address_space,
                &self.node_id("EchoOutputArguments"),
                &[("Value", DataTypeId::String).into()],
            )
            .insert(address_space);
    }

    fn name(&self) -> &str {
        "callback-method-test"
    }

    fn namespaces(&self) -> Vec<NamespaceMetadata> {
        vec![self.namespace.clone()]
    }

    fn method_callback(&self, method_id: &NodeId) -> Option<InMemoryMethodCallback> {
        self.callbacks.read().get(method_id).cloned()
    }
}

struct MethodServer {
    handle: ServerHandle,
    session: Arc<Session>,
    event_loop_task: tokio::task::JoinHandle<StatusCode>,
    server_task: tokio::task::JoinHandle<()>,
    _temp_dir: TempDir,
    namespace_index: u16,
}

impl MethodServer {
    async fn start(test_name: &str) -> Self {
        let temp_dir = TempDir::new(test_name);
        let server_pki = temp_dir.path.join("server-pki");
        let client_pki = temp_dir.path.join("client-pki");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("method test listener should bind");
        let addr = listener.local_addr().expect("method test listener address");
        let endpoint = format!("opc.tcp://127.0.0.1:{}/", addr.port());

        let (server, handle) = ServerBuilder::new()
            .application_name("method_call_tests")
            .application_uri("urn:async-opcua:method-call-tests")
            .product_uri("urn:async-opcua:method-call-tests")
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
            .with_node_manager(InMemoryNodeManagerBuilder::new(
                CallbackNodeManagerBuilder::new(METHOD_NAMESPACE_URI),
            ))
            .build()
            .expect("method test server should build");

        let namespace_index = handle
            .get_namespace_index(METHOD_NAMESPACE_URI)
            .expect("method test namespace should be registered");

        let server_task = tokio::spawn(async move {
            server
                .run_with(listener)
                .await
                .expect("method test server should run");
        });

        let mut client = ClientBuilder::new()
            .application_name("method_call_tests_client")
            .application_uri("urn:async-opcua:method-call-tests-client")
            .product_uri("urn:async-opcua:method-call-tests-client")
            .pki_dir(client_pki)
            .create_sample_keypair(true)
            .trust_server_certs(true)
            .session_retry_initial(Duration::from_millis(100))
            .client()
            .expect("method test client should build");

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
            .expect("method test client should connect");
        let event_loop_task = event_loop.spawn();

        tokio::time::timeout(Duration::from_secs(5), session.wait_for_connection())
            .await
            .expect("method test client should become connected");

        Self {
            handle,
            session,
            event_loop_task,
            server_task,
            _temp_dir: temp_dir,
            namespace_index,
        }
    }
}

impl Drop for MethodServer {
    fn drop(&mut self) {
        self.handle.cancel();
        self.server_task.abort();
        self.event_loop_task.abort();
    }
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(test_name: &str) -> Self {
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "async-opcua-method-call-{test_name}-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("method test temp dir should be created");
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
