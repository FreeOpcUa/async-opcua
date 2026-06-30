//! Hot-path lock regression tests for SimpleNodeManager Read callbacks.

use std::{
    sync::{mpsc, Arc},
    thread,
    time::Duration,
};

use opcua_core::sync::RwLock;
use opcua_crypto::SecurityPolicy;
use opcua_server::{
    address_space::{NodeType, VariableBuilder},
    authenticator::UserToken,
    diagnostics::NamespaceMetadata,
    node_manager::{
        memory::{simple_node_manager, InMemoryNodeManagerImpl, SimpleNodeManager},
        ParsedReadValueId, RequestContext, RequestContextInner,
    },
    session::instance::Session,
    IdentityToken, ServerBuilder, ServerHandle, ANONYMOUS_USER_TOKEN_ID,
};
use opcua_types::{
    AnonymousIdentityToken, ApplicationDescription, AttributeId, ByteString, DataEncoding,
    DataTypeId, DataValue, MessageSecurityMode, NodeId, NumericRange, QualifiedName, StatusCode,
    TimestampsToReturn, UAString, Variant,
};

const NAMESPACE_URI: &str = "urn:async-opcua:hot-path-read-callback-locks";
const NAMESPACE_INDEX: u16 = 2;
const REENTRY_TIMEOUT: Duration = Duration::from_secs(2);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_callback_runs_after_internal_guards_are_released() {
    let fixture = Fixture::new();
    let read_id = parsed_value_id(&fixture.read_node);
    let source_node = fixture.source_node.clone();
    let replacement_node = fixture.replacement_callback_node.clone();
    let callback_manager = Arc::clone(&fixture.node_manager);

    fixture.node_manager.inner().add_read_callback(
        fixture.read_node.clone(),
        move |_range, _timestamps, _max_age| {
            callback_manager
                .inner()
                .add_read_callback(replacement_node.clone(), |_range, _timestamps, _max_age| {
                    Ok(DataValue::new_now(7i32))
                });
            callback_manager.set_source_value(&source_node, DataValue::new_now(17i32));

            Ok(DataValue::new_now(42i32))
        },
    );

    let values = read_values_on_worker_thread(
        Arc::clone(&fixture.node_manager),
        fixture.context.clone(),
        read_id,
    )
    .recv_timeout(REENTRY_TIMEOUT)
    .expect(
        "Read callback did not finish after re-entering node-manager operations; \
         the Read path is likely still invoking callbacks while internal guards are held",
    );

    assert_eq!(values.len(), 1);
    let value = values.into_iter().next().expect("one read result");
    assert_eq!(value.status(), StatusCode::Good);
    assert_eq!(value.value, Some(Variant::from(42i32)));
    assert_eq!(
        variable_value(&fixture.node_manager, &fixture.source_node),
        Variant::from(17i32)
    );
}

struct Fixture {
    node_manager: Arc<SimpleNodeManager>,
    context: RequestContext,
    read_node: NodeId,
    source_node: NodeId,
    replacement_callback_node: NodeId,
}

impl Fixture {
    fn new() -> Self {
        let namespace = NamespaceMetadata {
            namespace_uri: NAMESPACE_URI.to_string(),
            namespace_index: NAMESPACE_INDEX,
            ..Default::default()
        };
        let (_server, handle) = ServerBuilder::new_anonymous("hot path read callback locks")
            .with_node_manager(simple_node_manager(
                namespace,
                "hot-path-read-callback-locks",
            ))
            .build()
            .expect("test server should build");
        let node_manager = handle
            .node_managers()
            .get_of_type::<SimpleNodeManager>()
            .expect("SimpleNodeManager");
        let namespace_index = handle
            .get_namespace_index(NAMESPACE_URI)
            .expect("test namespace should be registered");

        let read_node = NodeId::new(namespace_index, "ReadCallbackValue");
        let source_node = NodeId::new(namespace_index, "CallbackSourceValue");
        let replacement_callback_node = NodeId::new(namespace_index, "ReplacementCallbackValue");

        {
            let mut address_space = node_manager.address_space().write();
            add_i32_variable(
                &mut address_space,
                namespace_index,
                &read_node,
                "ReadCallbackValue",
            );
            add_i32_variable(
                &mut address_space,
                namespace_index,
                &source_node,
                "CallbackSourceValue",
            );
            add_i32_variable(
                &mut address_space,
                namespace_index,
                &replacement_callback_node,
                "ReplacementCallbackValue",
            );
        }

        let context = request_context(&handle);

        Self {
            node_manager,
            context,
            read_node,
            source_node,
            replacement_callback_node,
        }
    }
}

fn read_values_on_worker_thread(
    node_manager: Arc<SimpleNodeManager>,
    context: RequestContext,
    read_id: ParsedReadValueId,
) -> mpsc::Receiver<Vec<DataValue>> {
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("read worker runtime should build");

        let values = runtime.block_on(async move {
            let nodes = [&read_id];
            node_manager
                .inner()
                .read_values(
                    &context,
                    node_manager.address_space(),
                    &nodes,
                    0.0,
                    TimestampsToReturn::Neither,
                )
                .await
        });

        let _ = tx.send(values);
    });

    rx
}

fn request_context(handle: &ServerHandle) -> RequestContext {
    let info = Arc::clone(handle.info());
    let token = NodeId::new(0, ByteString::from(vec![1u8; 32]));
    let session = Session::create(
        &info,
        token,
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
        UAString::from("hot-path-read-callback-locks-session"),
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
        subscriptions: Arc::clone(handle.subscriptions()),
        info,
    }))
}

fn add_i32_variable(
    address_space: &mut opcua_server::address_space::AddressSpace,
    namespace_index: u16,
    node_id: &NodeId,
    name: &str,
) {
    VariableBuilder::new(node_id, QualifiedName::new(namespace_index, name), name)
        .data_type(DataTypeId::Int32)
        .value(0i32)
        .writable()
        .insert(address_space);
}

fn parsed_value_id(node_id: &NodeId) -> ParsedReadValueId {
    ParsedReadValueId {
        node_id: node_id.clone(),
        attribute_id: AttributeId::Value,
        index_range: NumericRange::None,
        data_encoding: DataEncoding::Binary,
    }
}

fn variable_value(node_manager: &SimpleNodeManager, node_id: &NodeId) -> Variant {
    let address_space = node_manager.address_space().read();
    let node = address_space.find(node_id);
    let Some(NodeType::Variable(variable)) = node.as_deref() else {
        panic!("expected variable node {node_id}");
    };

    variable
        .value(
            TimestampsToReturn::Neither,
            &NumericRange::None,
            &DataEncoding::Binary,
            0.0,
        )
        .value
        .expect("variable should have a value")
}
