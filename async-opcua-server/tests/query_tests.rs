//! Query service integration tests.

use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use async_trait::async_trait;
use opcua_client::{services::Read, ClientBuilder, IdentityToken, Session};
use opcua_core::ResponseMessage;
use opcua_crypto::SecurityPolicy;
use opcua_server::{
    address_space::{
        AccessLevel, AddressSpace, ObjectBuilder, ObjectTypeBuilder, VariableBuilder,
        VariableTypeBuilder,
    },
    authenticator::{AuthManager, UserToken},
    diagnostics::NamespaceMetadata,
    node_manager::memory::{simple_node_manager, SimpleNodeManager},
    ServerBuilder, ServerEndpoint, ServerHandle, ANONYMOUS_USER_TOKEN_ID,
};
use opcua_types::{
    AttributeId, ContentFilter, ContentFilterElement, DataTypeId, ExpandedNodeId, FilterOperator,
    MessageSecurityMode, NodeId, NumericRange, ObjectId, ObjectTypeId, Operand, QualifiedName,
    QueryDataDescription, QueryDataSet, QueryFirstRequest, QueryFirstResponse, QueryNextRequest,
    QueryNextResponse, ReferenceTypeId, RelativePath, RelativePathElement, StatusCode, UAString,
    UserTokenPolicy, UserTokenType, VariableTypeId, Variant, ViewDescription,
};
use tokio::net::TcpListener;

const QUERY_NAMESPACE_URI: &str = "urn:async-opcua:query-tests:nodes";

static NEXT_TEST_ID: AtomicUsize = AtomicUsize::new(0);

struct QueryServer {
    handle: ServerHandle,
    session: Arc<Session>,
    event_loop_task: tokio::task::JoinHandle<StatusCode>,
    server_task: tokio::task::JoinHandle<()>,
    _temp_dir: TempDir,
    namespace_index: u16,
    fermenter_type: NodeId,
    controller_type: NodeId,
    matching_fermenter: NodeId,
    nonmatching_fermenter: NodeId,
    sensor_type: NodeId,
    readable_sensor: NodeId,
    denied_sensor: NodeId,
}

impl QueryServer {
    async fn start(test_name: &str) -> Self {
        Self::start_with_authenticator(test_name, None).await
    }

    async fn start_with_authenticator(
        test_name: &str,
        authenticator: Option<Arc<dyn AuthManager>>,
    ) -> Self {
        let temp_dir = TempDir::new(test_name);
        let server_pki = temp_dir.path.join("server-pki");
        let client_pki = temp_dir.path.join("client-pki");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("query test listener should bind");
        let addr = listener.local_addr().expect("query test listener address");
        let endpoint = format!("opc.tcp://127.0.0.1:{}/", addr.port());

        let namespace = NamespaceMetadata {
            namespace_uri: QUERY_NAMESPACE_URI.to_string(),
            namespace_index: 2,
            ..Default::default()
        };

        let mut builder = ServerBuilder::new()
            .application_name("query_tests")
            .application_uri("urn:async-opcua:query-tests")
            .product_uri("urn:async-opcua:query-tests")
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
            .with_node_manager(simple_node_manager(namespace, "query-test"));
        if let Some(authenticator) = authenticator {
            builder = builder.with_authenticator(authenticator);
        }
        let (server, handle) = builder.build().expect("query test server should build");

        let node_manager = handle
            .node_managers()
            .get_of_type::<SimpleNodeManager>()
            .expect("query test simple node manager");
        let graph = add_query_graph(&handle, &node_manager);

        let server_task = tokio::spawn(async move {
            server
                .run_with(listener)
                .await
                .expect("query test server should run");
        });

        let mut client = ClientBuilder::new()
            .application_name("query_tests_client")
            .application_uri("urn:async-opcua:query-tests-client")
            .product_uri("urn:async-opcua:query-tests-client")
            .pki_dir(client_pki)
            .create_sample_keypair(true)
            .trust_server_certs(true)
            .session_retry_initial(Duration::from_millis(100))
            .client()
            .expect("query test client should build");

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
            .expect("query test client should connect");
        let event_loop_task = event_loop.spawn();

        tokio::time::timeout(Duration::from_secs(5), session.wait_for_connection())
            .await
            .expect("query test client should become connected");

        Self {
            handle,
            session,
            event_loop_task,
            server_task,
            _temp_dir: temp_dir,
            namespace_index: graph.namespace_index,
            fermenter_type: graph.fermenter_type,
            controller_type: graph.controller_type,
            matching_fermenter: graph.matching_fermenter,
            nonmatching_fermenter: graph.nonmatching_fermenter,
            sensor_type: graph.sensor_type,
            readable_sensor: graph.readable_sensor,
            denied_sensor: graph.denied_sensor,
        }
    }
}

impl Drop for QueryServer {
    fn drop(&mut self) {
        self.handle.cancel();
        self.event_loop_task.abort();
        self.server_task.abort();
    }
}

struct QueryGraph {
    namespace_index: u16,
    fermenter_type: NodeId,
    controller_type: NodeId,
    matching_fermenter: NodeId,
    nonmatching_fermenter: NodeId,
    sensor_type: NodeId,
    readable_sensor: NodeId,
    denied_sensor: NodeId,
}

struct QueryReadDenyAuthenticator {
    denied_node: NodeId,
}

#[async_trait]
impl AuthManager for QueryReadDenyAuthenticator {
    async fn authenticate_anonymous_token(
        &self,
        _endpoint: &ServerEndpoint,
    ) -> Result<(), opcua_types::Error> {
        Ok(())
    }

    fn effective_user_access_level(
        &self,
        _token: &UserToken,
        user_access_level: AccessLevel,
        node_id: &NodeId,
    ) -> AccessLevel {
        if node_id == &self.denied_node {
            AccessLevel::empty()
        } else {
            user_access_level
        }
    }

    fn user_token_policies(&self, _endpoint: &ServerEndpoint) -> Vec<UserTokenPolicy> {
        vec![UserTokenPolicy {
            policy_id: UAString::from("anonymous"),
            token_type: UserTokenType::Anonymous,
            issued_token_type: UAString::null(),
            issuer_endpoint_url: UAString::null(),
            security_policy_uri: UAString::null(),
        }]
    }
}

fn add_query_graph(handle: &ServerHandle, node_manager: &SimpleNodeManager) -> QueryGraph {
    let namespace_index = handle
        .get_namespace_index(QUERY_NAMESPACE_URI)
        .expect("query namespace should be registered");

    let fermenter_type = NodeId::new(namespace_index, "FermenterType");
    let controller_type = NodeId::new(namespace_index, "ControllerType");
    let fermenter_type_batch_id = NodeId::new(namespace_index, "FermenterType.BatchId");
    let matching_fermenter = NodeId::new(namespace_index, "Fermenter-101");
    let nonmatching_fermenter = NodeId::new(namespace_index, "Fermenter-102");
    let matching_batch_id = NodeId::new(namespace_index, "Fermenter-101.BatchId");
    let nonmatching_batch_id = NodeId::new(namespace_index, "Fermenter-102.BatchId");
    let controller = NodeId::new(namespace_index, "Controller-101");
    let sensor_type = NodeId::new(namespace_index, "SensorType");
    let readable_sensor = NodeId::new(namespace_index, "Sensor-Allowed");
    let denied_sensor = NodeId::new(namespace_index, "Sensor-Denied");

    {
        let mut address_space = node_manager.address_space().write();
        add_query_types(
            &mut address_space,
            namespace_index,
            &fermenter_type,
            &controller_type,
            &fermenter_type_batch_id,
        );
        add_query_sensor_type(&mut address_space, namespace_index, &sensor_type);
        add_fermenter(
            &mut address_space,
            namespace_index,
            &matching_fermenter,
            &fermenter_type,
            &matching_batch_id,
            "FV-101",
        );
        add_fermenter(
            &mut address_space,
            namespace_index,
            &nonmatching_fermenter,
            &fermenter_type,
            &nonmatching_batch_id,
            "FV-102",
        );
        ObjectBuilder::new(
            &controller,
            QualifiedName::new(namespace_index, "Controller-101"),
            "Controller 101",
        )
        .has_type_definition(controller_type.clone())
        .component_of(matching_fermenter.clone())
        .insert(&mut *address_space);
        add_sensor(
            &mut address_space,
            namespace_index,
            &readable_sensor,
            &sensor_type,
            12.5,
        );
        add_sensor(
            &mut address_space,
            namespace_index,
            &denied_sensor,
            &sensor_type,
            99.9,
        );

        address_space.load_into_type_tree(&mut handle.type_tree().write());
    }

    QueryGraph {
        namespace_index,
        fermenter_type,
        controller_type,
        matching_fermenter,
        nonmatching_fermenter,
        sensor_type,
        readable_sensor,
        denied_sensor,
    }
}

fn add_query_types(
    address_space: &mut AddressSpace,
    namespace_index: u16,
    fermenter_type: &NodeId,
    controller_type: &NodeId,
    fermenter_type_batch_id: &NodeId,
) {
    ObjectTypeBuilder::new(
        fermenter_type,
        QualifiedName::new(namespace_index, "FermenterType"),
        "FermenterType",
    )
    .subtype_of(ObjectTypeId::BaseObjectType)
    .insert(address_space);

    VariableBuilder::new(
        fermenter_type_batch_id,
        QualifiedName::new(namespace_index, "BatchId"),
        "BatchId",
    )
    .data_type(DataTypeId::String)
    .value("")
    .has_type_definition(VariableTypeId::PropertyType)
    .property_of(fermenter_type.clone())
    .insert(address_space);

    ObjectTypeBuilder::new(
        controller_type,
        QualifiedName::new(namespace_index, "ControllerType"),
        "ControllerType",
    )
    .subtype_of(ObjectTypeId::BaseObjectType)
    .insert(address_space);
}

fn add_query_sensor_type(
    address_space: &mut AddressSpace,
    namespace_index: u16,
    sensor_type: &NodeId,
) {
    VariableTypeBuilder::new(
        sensor_type,
        QualifiedName::new(namespace_index, "SensorType"),
        "SensorType",
    )
    .data_type(DataTypeId::Double)
    .subtype_of(VariableTypeId::BaseDataVariableType)
    .insert(address_space);
}

fn add_fermenter(
    address_space: &mut AddressSpace,
    namespace_index: u16,
    fermenter: &NodeId,
    fermenter_type: &NodeId,
    batch_id: &NodeId,
    batch: &str,
) {
    ObjectBuilder::new(
        fermenter,
        QualifiedName::new(namespace_index, fermenter.identifier.to_string()),
        fermenter.identifier.to_string(),
    )
    .has_type_definition(fermenter_type.clone())
    .organized_by(ObjectId::ObjectsFolder)
    .insert(address_space);

    VariableBuilder::new(
        batch_id,
        QualifiedName::new(namespace_index, "BatchId"),
        "BatchId",
    )
    .data_type(DataTypeId::String)
    .value(batch)
    .has_type_definition(VariableTypeId::PropertyType)
    .property_of(fermenter.clone())
    .insert(address_space);
}

fn add_sensor(
    address_space: &mut AddressSpace,
    namespace_index: u16,
    sensor: &NodeId,
    sensor_type: &NodeId,
    value: f64,
) {
    VariableBuilder::new(
        sensor,
        QualifiedName::new(namespace_index, sensor.identifier.to_string()),
        sensor.identifier.to_string(),
    )
    .data_type(DataTypeId::Double)
    .value(value)
    .has_type_definition(sensor_type.clone())
    .organized_by(ObjectId::ObjectsFolder)
    .insert(address_space);
}

#[tokio::test]
async fn query_first_returns_nodes_matching_related_to_filter_with_attributes() {
    let server = QueryServer::start("related-to").await;
    let response = query_first(
        &server.session,
        complex_related_query(
            server.namespace_index,
            &server.fermenter_type,
            &server.controller_type,
        ),
    )
    .await;

    assert_eq!(response.response_header.service_result, StatusCode::Good);
    assert!(response.continuation_point.is_null());

    let data_sets = response
        .query_data_sets
        .expect("query should return matching data sets");
    assert_eq!(
        data_sets.len(),
        1,
        "unexpected query data sets: {data_sets:#?}"
    );

    assert_query_result(
        &data_sets[0],
        &server.matching_fermenter,
        &server.fermenter_type,
        "FV-101",
    );
}

#[tokio::test]
async fn query_first_filters_out_unreadable_result_nodes() {
    let denied_node = NodeId::new(2, "Sensor-Denied");
    let server = QueryServer::start_with_authenticator(
        "authorized-results",
        Some(Arc::new(QueryReadDenyAuthenticator { denied_node })),
    )
    .await;

    let response = query_first(&server.session, sensor_query(&server.sensor_type)).await;

    assert_eq!(response.response_header.service_result, StatusCode::Good);
    assert!(response.continuation_point.is_null());

    let data_sets = response
        .query_data_sets
        .expect("query should return readable data sets");
    assert_eq!(
        data_sets.len(),
        1,
        "query should omit unreadable nodes: {data_sets:#?}"
    );
    assert_eq!(
        data_sets[0].node_id,
        ExpandedNodeId::new(server.readable_sensor.clone())
    );
    assert_ne!(
        data_sets[0].node_id,
        ExpandedNodeId::new(server.denied_sensor.clone())
    );
    assert_eq!(
        data_sets[0].values.as_deref(),
        Some(&[Variant::from(12.5f64)] as &[_])
    );
}

#[tokio::test]
async fn query_next_returns_next_page_from_continuation_point() {
    let server = QueryServer::start("query-next").await;
    let first = query_first(
        &server.session,
        paged_fermenter_query(server.namespace_index, &server.fermenter_type),
    )
    .await;

    assert_eq!(first.response_header.service_result, StatusCode::Good);
    assert!(!first.continuation_point.is_null());

    let mut data_sets = first
        .query_data_sets
        .expect("QueryFirst should return the first page");
    assert_eq!(data_sets.len(), 1);

    let next = query_next(&server.session, false, first.continuation_point).await;

    assert_eq!(next.response_header.service_result, StatusCode::Good);
    assert!(next.revised_continuation_point.is_null());

    let next_data_sets = next
        .query_data_sets
        .expect("QueryNext should return the second page");
    assert_eq!(next_data_sets.len(), 1);
    data_sets.extend(next_data_sets);

    assert_eq!(data_sets.len(), 2);
    assert!(data_sets.iter().any(|data_set| query_result_matches(
        data_set,
        &server.matching_fermenter,
        &server.fermenter_type,
        "FV-101",
    )));
    assert!(data_sets.iter().any(|data_set| query_result_matches(
        data_set,
        &server.nonmatching_fermenter,
        &server.fermenter_type,
        "FV-102",
    )));
}

async fn query_first(session: &Session, mut request: QueryFirstRequest) -> QueryFirstResponse {
    request.request_header = Read::new(session).header().clone();
    let response = session
        .channel()
        .send(request, Duration::from_secs(5))
        .await
        .expect("QueryFirst request should complete");

    match response {
        ResponseMessage::QueryFirst(response) => *response,
        other => panic!("unexpected QueryFirst response: {}", other.type_name()),
    }
}

async fn query_next(
    session: &Session,
    release_continuation_point: bool,
    continuation_point: opcua_types::ContinuationPoint,
) -> QueryNextResponse {
    let request = QueryNextRequest {
        request_header: Read::new(session).header().clone(),
        release_continuation_point,
        continuation_point,
    };
    let response = session
        .channel()
        .send(request, Duration::from_secs(5))
        .await
        .expect("QueryNext request should complete");

    match response {
        ResponseMessage::QueryNext(response) => *response,
        other => panic!("unexpected QueryNext response: {}", other.type_name()),
    }
}

fn complex_related_query(
    namespace_index: u16,
    fermenter_type: &NodeId,
    controller_type: &NodeId,
) -> QueryFirstRequest {
    QueryFirstRequest {
        view: ViewDescription::default(),
        node_types: Some(vec![NodeTypeDescriptionBuilder::new(fermenter_type)
            .return_batch_id(namespace_index)
            .build()]),
        filter: related_to_filter(fermenter_type, controller_type),
        max_data_sets_to_return: 10,
        max_references_to_return: 10,
        ..Default::default()
    }
}

fn sensor_query(sensor_type: &NodeId) -> QueryFirstRequest {
    QueryFirstRequest {
        view: ViewDescription::default(),
        node_types: Some(vec![NodeTypeDescriptionBuilder::new(sensor_type)
            .return_value()
            .build()]),
        filter: ContentFilter::default(),
        max_data_sets_to_return: 10,
        max_references_to_return: 10,
        ..Default::default()
    }
}

fn paged_fermenter_query(namespace_index: u16, fermenter_type: &NodeId) -> QueryFirstRequest {
    QueryFirstRequest {
        view: ViewDescription::default(),
        node_types: Some(vec![NodeTypeDescriptionBuilder::new(fermenter_type)
            .return_batch_id(namespace_index)
            .build()]),
        filter: ContentFilter::default(),
        max_data_sets_to_return: 1,
        max_references_to_return: 10,
        ..Default::default()
    }
}

struct NodeTypeDescriptionBuilder {
    type_definition_node: ExpandedNodeId,
    data_to_return: Vec<QueryDataDescription>,
}

impl NodeTypeDescriptionBuilder {
    fn new(type_definition_node: &NodeId) -> Self {
        Self {
            type_definition_node: ExpandedNodeId::new(type_definition_node.clone()),
            data_to_return: Vec::new(),
        }
    }

    fn return_batch_id(mut self, namespace_index: u16) -> Self {
        self.data_to_return.push(QueryDataDescription {
            relative_path: RelativePath {
                elements: Some(vec![RelativePathElement {
                    reference_type_id: ReferenceTypeId::HasProperty.into(),
                    is_inverse: false,
                    include_subtypes: true,
                    target_name: QualifiedName::new(namespace_index, "BatchId"),
                }]),
            },
            attribute_id: AttributeId::Value as u32,
            index_range: NumericRange::None,
        });
        self
    }

    fn return_value(mut self) -> Self {
        self.data_to_return.push(QueryDataDescription {
            relative_path: RelativePath { elements: None },
            attribute_id: AttributeId::Value as u32,
            index_range: NumericRange::None,
        });
        self
    }

    fn build(self) -> opcua_types::NodeTypeDescription {
        opcua_types::NodeTypeDescription {
            type_definition_node: self.type_definition_node,
            include_sub_types: true,
            data_to_return: Some(self.data_to_return),
        }
    }
}

fn related_to_filter(fermenter_type: &NodeId, controller_type: &NodeId) -> ContentFilter {
    ContentFilter {
        elements: Some(vec![ContentFilterElement::from((
            FilterOperator::RelatedTo,
            vec![
                Operand::literal(fermenter_type.clone()),
                Operand::literal(controller_type.clone()),
                Operand::literal(NodeId::from(ReferenceTypeId::HasComponent)),
                Operand::literal(1u32),
                Operand::literal(true),
                Operand::literal(true),
            ],
        ))]),
    }
}

fn assert_query_result(
    data_set: &QueryDataSet,
    expected_node: &NodeId,
    expected_type: &NodeId,
    expected_batch: &str,
) {
    assert_eq!(
        data_set.node_id,
        ExpandedNodeId::new(expected_node.clone()),
        "query returned the wrong target node"
    );
    assert_eq!(
        data_set.type_definition_node,
        ExpandedNodeId::new(expected_type.clone()),
        "query returned the wrong target type"
    );
    assert_eq!(
        data_set.values.as_deref(),
        Some(&[Variant::from(expected_batch)] as &[_]),
        "query returned the wrong selected attribute values"
    );
}

fn query_result_matches(
    data_set: &QueryDataSet,
    expected_node: &NodeId,
    expected_type: &NodeId,
    expected_batch: &str,
) -> bool {
    data_set.node_id == ExpandedNodeId::new(expected_node.clone())
        && data_set.type_definition_node == ExpandedNodeId::new(expected_type.clone())
        && data_set.values.as_deref() == Some(&[Variant::from(expected_batch)] as &[_])
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
            .join("query_tests")
            .join(format!("{test_name}-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temporary query test dir should be created");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
