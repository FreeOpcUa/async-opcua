//! Session actor concurrent load tests.

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use opcua_core::sync::RwLock;
use opcua_crypto::SecurityPolicy;
use opcua_server::{
    address_space::{AddressSpace, NodeType, VariableBuilder},
    authenticator::UserToken,
    diagnostics::NamespaceMetadata,
    metrics::METRICS,
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
    AnonymousIdentityToken, ApplicationDescription, AttributeId, ByteString, DataEncoding,
    DataTypeId, DataValue, DiagnosticBits, MessageSecurityMode, NodeId, NumericRange,
    QualifiedName, ReadValueId, StatusCode, TimestampsToReturn, UAString, Variant, WriteValue,
};
use tokio::sync::{mpsc, oneshot};

const NAMESPACE_URI: &str = "urn:async-opcua:session-actor-load:nodes";
const NAMESPACE_INDEX: u16 = 2;
const ACTOR_QUEUE_CAPACITY: usize = 256;
const CONCURRENT_TASKS: usize = 8;
const WRITES_PER_TASK: usize = 250;
const TEST_TIMEOUT: Duration = Duration::from_secs(60);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_actor_processes_concurrent_load_and_terminates_cleanly() {
    tokio::time::timeout(TEST_TIMEOUT, run_load_test())
        .await
        .expect("load test should complete well within the timeout");
}

async fn run_load_test() {
    let fixture = ActorFixture::new();

    let messages_before = METRICS.actor_messages_processed.load(Ordering::Relaxed);
    let duration_before = METRICS.actor_message_duration_ns.load(Ordering::Relaxed);

    // Drive concurrent read/write traffic from multiple tasks. Each task owns
    // one variable node, so a read issued after an acknowledged write must
    // observe that write once it has passed through the actor.
    let mut tasks = Vec::with_capacity(CONCURRENT_TASKS);
    for task_index in 0..CONCURRENT_TASKS {
        let sender = fixture.sender.clone();
        let node_id = load_node_id(task_index);
        tasks.push(tokio::spawn(async move {
            for value in 1..=WRITES_PER_TASK as i32 {
                let (response, response_rx) = oneshot::channel();
                sender
                    .send(SessionMessage::Write {
                        value: write_value(&node_id, value),
                        return_diagnostics: DiagnosticBits::empty(),
                        response,
                    })
                    .await
                    .expect("actor should accept write message");
                let (status, _) = response_rx
                    .await
                    .expect("write response should arrive")
                    .expect("write should not fault the service");
                assert!(
                    status.is_good(),
                    "write of {value} to {node_id} failed: {status}"
                );

                let (response, response_rx) = oneshot::channel();
                sender
                    .send(SessionMessage::Read {
                        node: read_value_id(&node_id),
                        max_age: 0.0,
                        timestamps_to_return: TimestampsToReturn::Neither,
                        return_diagnostics: DiagnosticBits::empty(),
                        response,
                    })
                    .await
                    .expect("actor should accept read message");
                let (data_value, _) = response_rx
                    .await
                    .expect("read response should arrive")
                    .expect("read should not fault the service");
                assert!(
                    data_value.status.unwrap_or(StatusCode::Good).is_good(),
                    "read of {node_id} failed: {:?}",
                    data_value.status
                );
                assert_eq!(
                    data_value.value,
                    Some(Variant::Int32(value)),
                    "read after acknowledged write must observe the written value"
                );
            }
        }));
    }

    for task in tasks {
        task.await.expect("load task should complete");
    }

    // Every variable must hold the final value written by its owning task.
    {
        let address_space = fixture.node_manager.address_space().read();
        for task_index in 0..CONCURRENT_TASKS {
            let node_id = load_node_id(task_index);
            assert_eq!(
                variable_value(&address_space, &node_id),
                Variant::Int32(WRITES_PER_TASK as i32),
                "final state of {node_id} must reflect the last write"
            );
        }
    }

    // The actor metrics must have advanced by at least the message volume.
    let total_messages = (CONCURRENT_TASKS * WRITES_PER_TASK * 2) as u64;
    let messages_after = METRICS.actor_messages_processed.load(Ordering::Relaxed);
    let duration_after = METRICS.actor_message_duration_ns.load(Ordering::Relaxed);
    assert!(
        messages_after - messages_before >= total_messages,
        "metrics should count all processed messages: before={messages_before}, after={messages_after}"
    );
    assert!(
        duration_after > duration_before,
        "metrics should accumulate processing time"
    );
    assert!(
        METRICS.actor_queue_depth.load(Ordering::Relaxed) <= ACTOR_QUEUE_CAPACITY,
        "queue depth gauge must stay within the channel capacity"
    );

    // Terminate the actor and verify acknowledgement and cleanup.
    let (acknowledge, acknowledged) = oneshot::channel();
    fixture
        .sender
        .send(SessionMessage::Terminate {
            reason: StatusCode::Good,
            acknowledge,
        })
        .await
        .expect("actor should accept terminate message");
    let terminated = acknowledged
        .await
        .expect("terminate acknowledgement should arrive");
    assert_eq!(terminated.session_id, fixture.session_id);
    assert_eq!(terminated.authentication_token, fixture.token);
    assert!(
        fixture.cleanup_ran.load(Ordering::SeqCst),
        "termination cleanup callback must run"
    );

    let run_result = fixture
        .actor_task
        .await
        .expect("actor task should not panic");
    assert!(
        run_result.is_ok(),
        "actor should exit cleanly on terminate: {run_result:?}"
    );
}

struct ActorFixture {
    // The server must be kept alive for the duration of the test.
    _handle: ServerHandle,
    node_manager: Arc<SimpleNodeManager>,
    sender: mpsc::Sender<SessionMessage>,
    session_id: NodeId,
    token: NodeId,
    cleanup_ran: Arc<AtomicBool>,
    actor_task: tokio::task::JoinHandle<Result<(), opcua_server::session::errors::SessionError>>,
}

impl ActorFixture {
    fn new() -> Self {
        let namespace = NamespaceMetadata {
            namespace_uri: NAMESPACE_URI.to_string(),
            namespace_index: NAMESPACE_INDEX,
            ..Default::default()
        };
        let (_server, handle) = ServerBuilder::new_anonymous("session actor load test")
            .with_node_manager(simple_node_manager(namespace, "actor-load"))
            .build()
            .expect("test server should build");
        let node_manager = handle
            .node_managers()
            .get_of_type::<SimpleNodeManager>()
            .expect("SimpleNodeManager");

        {
            let mut address_space = node_manager.address_space().write();
            for task_index in 0..CONCURRENT_TASKS {
                let node_id = load_node_id(task_index);
                let name = format!("LoadVar{task_index}");
                VariableBuilder::new(&node_id, &name, &name)
                    .data_type(DataTypeId::Int32)
                    .value(0i32)
                    .writable()
                    .insert(&mut *address_space);
            }
        }

        let info = Arc::clone(handle.info());
        let token = NodeId::new(0, ByteString::from(vec![1u8; 32]));
        let session = Session::create(
            &info,
            token.clone(),
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
            UAString::from("actor-load-session"),
            ApplicationDescription::default(),
            MessageSecurityMode::None,
        );
        let session_id = session.session_id().clone();
        let session = Arc::new(RwLock::new(session));

        let context = RequestContext::new_test(Arc::new(RequestContextInner {
            session,
            session_id: 1,
            authenticator: info.authenticator.clone(),
            token: UserToken(ANONYMOUS_USER_TOKEN_ID.to_string()),
            type_tree: info.type_tree.clone(),
            type_tree_getter: info.type_tree_getter.clone(),
            subscriptions: Arc::clone(handle.subscriptions()),
            info: Arc::clone(&info),
        }));

        let (sender, receiver) = mpsc::channel(ACTOR_QUEUE_CAPACITY);
        let cleanup_ran = Arc::new(AtomicBool::new(false));
        let cleanup_flag = Arc::clone(&cleanup_ran);
        let mut actor = SessionActor::new(context, receiver).with_termination_cleanup(move |_| {
            cleanup_flag.store(true, Ordering::SeqCst);
        });

        let node_managers = handle.node_managers().clone();
        let actor_task = tokio::spawn(async move { actor.run(node_managers).await });

        Self {
            _handle: handle,
            node_manager,
            sender,
            session_id,
            token,
            cleanup_ran,
            actor_task,
        }
    }
}

fn load_node_id(task_index: usize) -> NodeId {
    NodeId::new(NAMESPACE_INDEX, format!("LoadVar{task_index}"))
}

fn variable_value(address_space: &AddressSpace, node_id: &NodeId) -> Variant {
    let node_guard = address_space.find(node_id);
    let Some(NodeType::Variable(var)) = node_guard.as_deref() else {
        panic!("expected variable node {node_id}");
    };

    var.value(
        TimestampsToReturn::Neither,
        &NumericRange::None,
        &DataEncoding::Binary,
        0.0,
    )
    .value
    .expect("variable should have a value")
}

fn write_value(node_id: &NodeId, value: i32) -> WriteValue {
    WriteValue {
        node_id: node_id.clone(),
        attribute_id: AttributeId::Value as u32,
        index_range: NumericRange::None,
        value: DataValue::new_now(value),
    }
}

fn read_value_id(node_id: &NodeId) -> ReadValueId {
    ReadValueId {
        node_id: node_id.clone(),
        attribute_id: AttributeId::Value as u32,
        index_range: NumericRange::None,
        data_encoding: QualifiedName::null(),
    }
}
