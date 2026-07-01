//! Expected-red proof tests for TypeTree snapshot reads.

use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use opcua_client::{
    services::Read, ClientBuilder, IdentityToken as ClientIdentityToken, Session as ClientSession,
};
use opcua_core::{sync::RwLock, ResponseMessage};
use opcua_crypto::SecurityPolicy;
use opcua_nodes::DefaultTypeTree;
use opcua_server::{
    authenticator::UserToken,
    node_manager::{
        RequestContext, RequestContextInner, TypeTreeForUser, TypeTreeForUserStatic,
        TypeTreeReadContext,
    },
    session::instance::Session,
    IdentityToken, ServerBuilder, ServerHandle, ANONYMOUS_USER_TOKEN_ID,
};
use opcua_types::{
    AnonymousIdentityToken, ApplicationDescription, BrowseDescription, BrowseDescriptionResultMask,
    BrowseDirection, ByteString, ContentFilter, ExpandedNodeId, MessageSecurityMode, NodeClass,
    NodeId, NodeTypeDescription, ObjectId, ObjectTypeId, QueryFirstRequest, QueryFirstResponse,
    ReferenceTypeId, StatusCode, UAString, ViewDescription,
};
use tokio::net::TcpListener;

static NEXT_TEST_ID: AtomicUsize = AtomicUsize::new(0);

#[tokio::test]
async fn hot_path_reads_use_type_tree_snapshot() {
    let (_server, handle) = ServerBuilder::new_anonymous("type tree snapshot proof")
        .build()
        .expect("test server should build");
    let context = request_context(&handle);

    let type_tree_read = context.get_type_tree_for_user();

    // Browse, Query, and subscription hot paths use this default getter for OPC UA type
    // metadata; keeping the read context alive must not hold the global mutable TypeTree lock.
    assert!(
        handle.type_tree().try_write().is_some(),
        "default hot-path TypeTree reads should use a published snapshot, not the global RwLock guard"
    );

    drop(type_tree_read);
}

#[tokio::test]
async fn browse_reference_description_preserves_part4_5_9_2_2_and_7_29() {
    let server = SnapshotBrowseServer::start("browse-reference-description").await;
    let result_mask = BrowseDescriptionResultMask::RESULT_MASK_REFERENCE_TYPE
        | BrowseDescriptionResultMask::RESULT_MASK_IS_FORWARD
        | BrowseDescriptionResultMask::RESULT_MASK_NODE_CLASS
        | BrowseDescriptionResultMask::RESULT_MASK_BROWSE_NAME
        | BrowseDescriptionResultMask::RESULT_MASK_DISPLAY_NAME
        | BrowseDescriptionResultMask::RESULT_MASK_TYPE_DEFINITION;

    let results = server
        .session
        .browse(
            &[BrowseDescription {
                node_id: ObjectId::ObjectsFolder.into(),
                browse_direction: BrowseDirection::Forward,
                reference_type_id: ReferenceTypeId::Organizes.into(),
                include_subtypes: true,
                node_class_mask: 0,
                result_mask: result_mask.bits(),
            }],
            0,
            None,
        )
        .await
        .expect("Part 4 5.9.2.2 Browse request for ObjectsFolder should succeed");

    assert_eq!(results.len(), 1);
    let result = &results[0];
    assert_eq!(result.status_code, StatusCode::Good);
    assert!(
        result.continuation_point.is_null(),
        "Part 4 5.9.2.2 Browse should return the complete default ObjectsFolder result"
    );

    let references = result
        .references
        .as_ref()
        .expect("Part 4 5.9.2.2 Browse result should include references");
    let server_reference = references
        .iter()
        .find(|reference| reference.node_id == ExpandedNodeId::from(ObjectId::Server))
        .expect("Part 4 7.29 ReferenceDescription should include the Server target");

    assert_eq!(
        server_reference.reference_type_id,
        NodeId::from(ReferenceTypeId::Organizes),
        "Part 4 7.29 ReferenceDescription must preserve reference type metadata"
    );
    assert!(
        server_reference.is_forward,
        "Part 4 7.29 ReferenceDescription must preserve reference direction"
    );
    assert_eq!(
        server_reference.browse_name.namespace_index, 0,
        "Part 4 7.29 ReferenceDescription must preserve BrowseName namespace"
    );
    assert_eq!(
        server_reference.browse_name.name.to_string(),
        "Server",
        "Part 4 7.29 ReferenceDescription must preserve BrowseName"
    );
    assert_eq!(
        server_reference.display_name.text.to_string(),
        "Server",
        "Part 4 7.29 ReferenceDescription must preserve DisplayName"
    );
    assert_eq!(
        server_reference.node_class,
        NodeClass::Object,
        "Part 4 7.29 ReferenceDescription must preserve target NodeClass"
    );
    assert_eq!(
        server_reference.type_definition,
        ExpandedNodeId::from(ObjectTypeId::ServerType),
        "Part 4 7.29 ReferenceDescription must preserve object TypeDefinition"
    );
}

#[tokio::test]
async fn query_type_path_preserves_part4_b_2_3() {
    let server = SnapshotBrowseServer::start("query-type-path").await;

    let known_type = query_first(
        &server.session,
        query_request_for_type(ObjectTypeId::ServerType.into()),
    )
    .await;

    assert_eq!(known_type.response_header.service_result, StatusCode::Good);
    let data_sets = known_type
        .query_data_sets
        .as_ref()
        .expect("OPC-10000-4 B.2.3 Query should return data sets for a known type path");
    assert!(
        data_sets.iter().any(|data_set| {
            data_set.node_id == ExpandedNodeId::from(ObjectId::Server)
                && data_set.type_definition_node == ExpandedNodeId::from(ObjectTypeId::ServerType)
        }),
        "OPC-10000-4 B.2.3 Query should preserve the Server -> ServerType metadata path"
    );

    let unknown_type = query_first(
        &server.session,
        query_request_for_type(NodeId::new(0, "NotATypeDefinitionForPart4B23")),
    )
    .await;

    assert_eq!(
        unknown_type.response_header.service_result,
        StatusCode::BadInvalidArgument,
        "OPC-10000-4 B.2.3 Query should reject a non-TypeDefinitionNode request"
    );
    let unknown_parsing_results = unknown_type
        .parsing_results
        .as_ref()
        .expect("OPC-10000-4 B.2.3 Query should report the invalid type path");
    assert_eq!(
        unknown_parsing_results[0].status_code,
        StatusCode::BadNotTypeDefinition,
        "OPC-10000-4 B.2.3 Query should classify unknown non-null type ids as BadNotTypeDefinition"
    );
    assert!(
        unknown_type.query_data_sets.is_none(),
        "OPC-10000-4 B.2.3 Query should not return data sets for an invalid type path"
    );
}

#[tokio::test]
async fn published_snapshot_is_complete_after_startup() {
    let server = SnapshotBrowseServer::start("published-snapshot-complete").await;
    let snapshot = server
        .handle
        .info()
        .type_tree_snapshot()
        .expect("server startup should publish a TypeTree snapshot after type metadata init");

    assert_eq!(
        snapshot
            .namespaces()
            .get_index("http://opcfoundation.org/UA/"),
        Some(0),
        "published TypeTree snapshot should include the standard OPC UA namespace"
    );

    let server_type = NodeId::from(ObjectTypeId::ServerType);
    let base_object_type = NodeId::from(ObjectTypeId::BaseObjectType);
    let organizes = NodeId::from(ReferenceTypeId::Organizes);
    let has_subtype = NodeId::from(ReferenceTypeId::HasSubtype);
    let references = NodeId::from(ReferenceTypeId::References);

    assert_eq!(
        snapshot.get(&server_type),
        Some(NodeClass::ObjectType),
        "published TypeTree snapshot should include ServerType object metadata"
    );
    assert_eq!(
        snapshot.get(&base_object_type),
        Some(NodeClass::ObjectType),
        "published TypeTree snapshot should include BaseObjectType object metadata"
    );
    assert!(
        snapshot.is_subtype_of(&server_type, &base_object_type),
        "published TypeTree snapshot should preserve the ServerType -> BaseObjectType relationship"
    );
    assert_eq!(
        snapshot.get(&has_subtype),
        Some(NodeClass::ReferenceType),
        "published TypeTree snapshot should include HasSubtype reference metadata"
    );
    assert_eq!(
        snapshot.get(&organizes),
        Some(NodeClass::ReferenceType),
        "published TypeTree snapshot should include Organizes reference metadata"
    );
    assert!(
        snapshot.is_subtype_of(&organizes, &references),
        "published TypeTree snapshot should preserve reference-type subtype metadata"
    );
}

#[tokio::test]
async fn custom_type_tree_getter_remains_compatible() {
    let type_tree = Arc::new(RwLock::new(DefaultTypeTree::new()));
    let dynamic_calls = Arc::new(AtomicUsize::new(0));
    let static_getter_calls = Arc::new(AtomicUsize::new(0));
    let static_read_calls = Arc::new(AtomicUsize::new(0));
    let type_tree_getter = Arc::new(CountingTypeTreeGetter {
        type_tree,
        dynamic_calls: Arc::clone(&dynamic_calls),
        static_getter_calls: Arc::clone(&static_getter_calls),
        static_read_calls: Arc::clone(&static_read_calls),
    });
    let (_server, handle) = ServerBuilder::new_anonymous("custom type tree getter proof")
        .with_type_tree_getter(type_tree_getter)
        .build()
        .expect("test server should build with a custom TypeTree getter");
    let context = request_context(&handle);

    let type_tree_read = context.get_type_tree_for_user();
    assert_eq!(
        dynamic_calls.load(Ordering::SeqCst),
        1,
        "RequestContext::get_type_tree_for_user should invoke the configured custom getter"
    );
    assert!(
        type_tree_read
            .get()
            .get(&NodeId::from(ObjectTypeId::ServerType))
            .is_none(),
        "custom getter should provide the per-user TypeTree instead of the populated default tree"
    );
    drop(type_tree_read);

    let static_type_tree = context.info.type_tree_getter.get_type_tree_static(&context);
    assert_eq!(
        static_getter_calls.load(Ordering::SeqCst),
        1,
        "subscription static TypeTree path should invoke the configured custom getter"
    );

    let static_type_tree_read = static_type_tree.get_type_tree();
    assert_eq!(
        static_read_calls.load(Ordering::SeqCst),
        1,
        "static TypeTree getter should read from the configured custom TypeTree"
    );
    assert!(
        static_type_tree_read
            .get()
            .get(&NodeId::from(ObjectTypeId::ServerType))
            .is_none(),
        "static path should expose the per-user TypeTree instead of the populated default tree"
    );
}

struct CountingTypeTreeGetter {
    type_tree: Arc<RwLock<DefaultTypeTree>>,
    dynamic_calls: Arc<AtomicUsize>,
    static_getter_calls: Arc<AtomicUsize>,
    static_read_calls: Arc<AtomicUsize>,
}

impl TypeTreeForUser for CountingTypeTreeGetter {
    fn get_type_tree_for_user<'a>(
        &'a self,
        _ctx: &'a RequestContext,
    ) -> Box<dyn TypeTreeReadContext + 'a> {
        self.dynamic_calls.fetch_add(1, Ordering::SeqCst);
        Box::new(self.type_tree.read())
    }

    fn get_type_tree_static(&self, _ctx: &RequestContext) -> Arc<dyn TypeTreeForUserStatic> {
        self.static_getter_calls.fetch_add(1, Ordering::SeqCst);
        Arc::new(CountingStaticTypeTree {
            type_tree: Arc::clone(&self.type_tree),
            read_calls: Arc::clone(&self.static_read_calls),
        })
    }
}

struct CountingStaticTypeTree {
    type_tree: Arc<RwLock<DefaultTypeTree>>,
    read_calls: Arc<AtomicUsize>,
}

impl TypeTreeForUserStatic for CountingStaticTypeTree {
    fn get_type_tree<'a>(&'a self) -> Box<dyn TypeTreeReadContext + 'a> {
        self.read_calls.fetch_add(1, Ordering::SeqCst);
        Box::new(self.type_tree.read())
    }
}

async fn query_first(
    session: &ClientSession,
    mut request: QueryFirstRequest,
) -> QueryFirstResponse {
    request.request_header = Read::new(session).header().clone();
    let response = session
        .channel()
        .send(request, Duration::from_secs(5))
        .await
        .expect("snapshot QueryFirst request should complete");

    match response {
        ResponseMessage::QueryFirst(response) => *response,
        other => panic!(
            "unexpected snapshot QueryFirst response: {}",
            other.type_name()
        ),
    }
}

fn query_request_for_type(type_definition_node: NodeId) -> QueryFirstRequest {
    QueryFirstRequest {
        view: ViewDescription::default(),
        node_types: Some(vec![NodeTypeDescription {
            type_definition_node: ExpandedNodeId::new(type_definition_node),
            include_sub_types: true,
            data_to_return: Some(Vec::new()),
        }]),
        filter: ContentFilter::default(),
        max_data_sets_to_return: 10,
        max_references_to_return: 10,
        ..Default::default()
    }
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
        UAString::from("type-tree-snapshot-proof-session"),
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

struct SnapshotBrowseServer {
    handle: ServerHandle,
    session: Arc<ClientSession>,
    event_loop_task: tokio::task::JoinHandle<StatusCode>,
    server_task: tokio::task::JoinHandle<()>,
    _temp_dir: TempDir,
}

impl SnapshotBrowseServer {
    async fn start(test_name: &str) -> Self {
        let temp_dir = TempDir::new(test_name);
        let server_pki = temp_dir.path.join("server-pki");
        let client_pki = temp_dir.path.join("client-pki");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("snapshot browse test listener should bind");
        let addr = listener
            .local_addr()
            .expect("snapshot browse listener address");
        let endpoint = format!("opc.tcp://127.0.0.1:{}/", addr.port());

        let (server, handle) = ServerBuilder::new()
            .application_name("type_tree_snapshot_browse")
            .application_uri("urn:async-opcua:type-tree-snapshot-browse")
            .product_uri("urn:async-opcua:type-tree-snapshot-browse")
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
            .expect("snapshot browse test server should build");

        let server_task = tokio::spawn(async move {
            server
                .run_with(listener)
                .await
                .expect("snapshot browse test server should run");
        });

        let mut client = ClientBuilder::new()
            .application_name("type_tree_snapshot_browse_client")
            .application_uri("urn:async-opcua:type-tree-snapshot-browse-client")
            .product_uri("urn:async-opcua:type-tree-snapshot-browse-client")
            .pki_dir(client_pki)
            .create_sample_keypair(true)
            .trust_server_certs(true)
            .session_retry_initial(Duration::from_millis(100))
            .client()
            .expect("snapshot browse test client should build");

        let (session, event_loop) = client
            .connect_to_matching_endpoint(
                (
                    endpoint.as_str(),
                    SecurityPolicy::None.to_str(),
                    MessageSecurityMode::None,
                ),
                ClientIdentityToken::Anonymous,
            )
            .await
            .expect("snapshot browse test client should connect");
        let event_loop_task = event_loop.spawn();

        tokio::time::timeout(Duration::from_secs(5), session.wait_for_connection())
            .await
            .expect("snapshot browse test client should become connected");

        Self {
            handle,
            session,
            event_loop_task,
            server_task,
            _temp_dir: temp_dir,
        }
    }
}

impl Drop for SnapshotBrowseServer {
    fn drop(&mut self) {
        self.handle.cancel();
        self.event_loop_task.abort();
        self.server_task.abort();
    }
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(test_name: &str) -> Self {
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::current_dir()
            .expect("current directory")
            .join("target")
            .join("type_tree_snapshot_tests")
            .join(format!("{test_name}-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temporary snapshot browse dir should be created");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
