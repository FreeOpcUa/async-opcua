//! Expected-red guard release proof for SimpleNodeManager Write callbacks.

use std::{
    sync::{mpsc as std_mpsc, Arc, Weak},
    time::Duration,
};

use opcua_core::sync::RwLock;
use opcua_crypto::SecurityPolicy;
use opcua_nodes::DefaultTypeTree;
use opcua_server::{
    address_space::{AddressSpace, VariableBuilder},
    authenticator::UserToken,
    diagnostics::NamespaceMetadata,
    node_manager::{
        memory::{simple_node_manager, SimpleNodeManager},
        RequestContext, RequestContextInner,
    },
    session::{
        actor::{SessionActor, SessionMessage},
        instance::Session,
    },
    IdentityToken, ServerBuilder, ServerHandle, ANONYMOUS_USER_TOKEN_ID,
};
use opcua_types::{
    AnonymousIdentityToken, ApplicationDescription, AttributeId, ByteString, DataTypeId, DataValue,
    DiagnosticBits, MessageSecurityMode, NodeId, NumericRange, StatusCode, UAString, Variant,
    WriteValue,
};
use tokio::sync::{mpsc, oneshot};

const NAMESPACE_URI: &str = "urn:async-opcua:hot-path-write-callback-locks:nodes";
const WRITE_CALLBACK_STATUS: StatusCode = StatusCode::BadOutOfService;
const GUARD_STILL_HELD_STATUS: StatusCode = StatusCode::BadRequestTimeout;
const PROBE_TIMEOUT: Duration = Duration::from_millis(250);
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_callback_runs_after_internal_guards_are_released() {
    let result = tokio::time::timeout(TEST_TIMEOUT, run_write_callback_guard_probe()).await;
    result.expect("write callback guard probe should not hang");
}

async fn run_write_callback_guard_probe() {
    let fixture = WriteCallbackFixture::new();
    let probe_node = fixture.node_id.clone();
    let registry_probe_node = fixture.registry_probe_node_id.clone();

    install_guard_probe_callback(
        &fixture.node_manager,
        &fixture.handle,
        probe_node.clone(),
        registry_probe_node,
    );

    let actor = fixture.start_actor();
    let results = write_through_actor(&actor.sender, write_value(&probe_node, 42)).await;
    terminate_actor(&actor.sender).await;

    let (status, diagnostic) = single_write_result(results);
    assert_eq!(
        status, WRITE_CALLBACK_STATUS,
        "OPC-10000-4 5.11.4.2 and 5.11.4.4 require Write to return the callback status; a different status means the callback still observed an internal guard"
    );
    assert!(
        diagnostic.is_none(),
        "diagnostics were not requested for this Write operation"
    );

    actor
        .task
        .await
        .expect("session actor task should join")
        .expect("session actor should terminate cleanly");
}

fn install_guard_probe_callback(
    node_manager: &Arc<SimpleNodeManager>,
    handle: &ServerHandle,
    probe_node: NodeId,
    registry_probe_node: NodeId,
) {
    let weak_node_manager = Arc::downgrade(node_manager);
    let address_space = Arc::clone(node_manager.address_space());
    let type_tree = Arc::clone(&handle.info().type_tree);

    node_manager
        .inner()
        .add_write_callback(probe_node, move |_value, _index_range| {
            if callback_guards_are_released(
                &weak_node_manager,
                &address_space,
                &type_tree,
                registry_probe_node.clone(),
            ) {
                WRITE_CALLBACK_STATUS
            } else {
                GUARD_STILL_HELD_STATUS
            }
        });
}

fn callback_guards_are_released(
    weak_node_manager: &Weak<SimpleNodeManager>,
    address_space: &Arc<RwLock<AddressSpace>>,
    type_tree: &Arc<RwLock<DefaultTypeTree>>,
    registry_probe_node: NodeId,
) -> bool {
    let address_space_released = address_space.try_write().is_some();
    let type_tree_released = type_tree.try_write().is_some();
    let registry_released =
        write_callback_registry_is_reentrant(weak_node_manager, registry_probe_node);

    address_space_released && type_tree_released && registry_released
}

fn write_callback_registry_is_reentrant(
    weak_node_manager: &Weak<SimpleNodeManager>,
    registry_probe_node: NodeId,
) -> bool {
    let Some(node_manager) = weak_node_manager.upgrade() else {
        return false;
    };
    let (sent, received) = std_mpsc::channel();

    std::thread::spawn(move || {
        node_manager
            .inner()
            .add_write_callback(registry_probe_node, |_value, _index_range| StatusCode::Good);
        let _ = sent.send(());
    });

    received.recv_timeout(PROBE_TIMEOUT).is_ok()
}

struct WriteCallbackFixture {
    handle: ServerHandle,
    node_manager: Arc<SimpleNodeManager>,
    node_id: NodeId,
    registry_probe_node_id: NodeId,
    context: RequestContext,
}

impl WriteCallbackFixture {
    fn new() -> Self {
        let namespace = NamespaceMetadata {
            namespace_uri: NAMESPACE_URI.to_string(),
            namespace_index: 2,
            ..Default::default()
        };
        let (_server, handle) = ServerBuilder::new_anonymous("write callback lock probe")
            .with_node_manager(simple_node_manager(namespace, "write-callback-lock-probe"))
            .build()
            .expect("test server should build");
        let namespace_index = handle
            .get_namespace_index(NAMESPACE_URI)
            .expect("test namespace should be registered");
        let node_id = NodeId::new(namespace_index, "GuardProbe");
        let registry_probe_node_id = NodeId::new(namespace_index, "GuardProbe.RegistryReentry");
        let node_manager = handle
            .node_managers()
            .get_of_type::<SimpleNodeManager>()
            .expect("test server should expose SimpleNodeManager");

        {
            let mut address_space = node_manager.address_space().write();
            VariableBuilder::new(&node_id, "GuardProbe", "GuardProbe")
                .data_type(DataTypeId::Int32)
                .value(0i32)
                .writable()
                .insert(&mut *address_space);
        }

        let context = request_context(&handle);

        Self {
            handle,
            node_manager,
            node_id,
            registry_probe_node_id,
            context,
        }
    }

    fn start_actor(&self) -> ActorHandle {
        let (sender, receiver) = mpsc::channel(4);
        let mut actor = SessionActor::new(self.context.clone(), receiver);
        let node_managers = self.handle.node_managers().clone();
        let task = tokio::spawn(async move { actor.run(node_managers).await });

        ActorHandle { sender, task }
    }
}

struct ActorHandle {
    sender: mpsc::Sender<SessionMessage>,
    task: tokio::task::JoinHandle<Result<(), opcua_server::session::errors::SessionError>>,
}

fn request_context(handle: &ServerHandle) -> RequestContext {
    let info = Arc::clone(handle.info());
    let session = Session::create(
        &info,
        NodeId::new(0, ByteString::from(vec![1u8; 32])),
        1,
        60_000,
        0,
        0,
        UAString::from("opc.tcp://localhost"),
        SecurityPolicy::None.to_str().to_string(),
        IdentityToken::Anonymous(AnonymousIdentityToken {
            policy_id: UAString::from("anonymous"),
        }),
        None,
        ByteString::null(),
        UAString::from("write-callback-lock-probe-session"),
        ApplicationDescription::default(),
        MessageSecurityMode::None,
    );

    RequestContext::new_test(Arc::new(RequestContextInner {
        session: Arc::new(RwLock::new(session)),
        session_id: 1,
        authenticator: info.authenticator.clone(),
        token: UserToken(ANONYMOUS_USER_TOKEN_ID.to_string()),
        user_roles: Arc::new(Vec::new()),
        type_tree: info.type_tree.clone(),
        type_tree_getter: info.type_tree_getter.clone(),
        subscriptions: handle.subscriptions().clone(),
        info,
    }))
}

async fn write_through_actor(
    sender: &mpsc::Sender<SessionMessage>,
    value: WriteValue,
) -> Vec<(StatusCode, Option<opcua_types::DiagnosticInfo>)> {
    let (response, received) = oneshot::channel();
    sender
        .send(SessionMessage::Write {
            values: vec![value],
            return_diagnostics: DiagnosticBits::empty(),
            response,
        })
        .await
        .expect("session actor should accept Write request");

    tokio::time::timeout(PROBE_TIMEOUT + PROBE_TIMEOUT, received)
        .await
        .expect("Write response should arrive before timeout")
        .expect("Write response channel should remain open")
        .expect("Write request should not produce a service fault")
}

async fn terminate_actor(sender: &mpsc::Sender<SessionMessage>) {
    let (acknowledge, received) = oneshot::channel();
    sender
        .send(SessionMessage::Terminate {
            reason: StatusCode::Good,
            acknowledge,
        })
        .await
        .expect("session actor should accept terminate request");
    tokio::time::timeout(PROBE_TIMEOUT + PROBE_TIMEOUT, received)
        .await
        .expect("terminate acknowledgement should arrive before timeout")
        .expect("terminate acknowledgement channel should remain open");
}

fn single_write_result(
    mut results: Vec<(StatusCode, Option<opcua_types::DiagnosticInfo>)>,
) -> (StatusCode, Option<opcua_types::DiagnosticInfo>) {
    assert_eq!(results.len(), 1, "Write should return one result");
    results
        .pop()
        .expect("one Write result should be present after length check")
}

fn write_value(node_id: &NodeId, value: i32) -> WriteValue {
    WriteValue {
        node_id: node_id.clone(),
        attribute_id: AttributeId::Value as u32,
        index_range: NumericRange::None,
        value: DataValue::new_now(Variant::from(value)),
    }
}
