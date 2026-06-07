//! Historical data access integration tests.

use std::{
    collections::HashSet,
    path::PathBuf,
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc,
    },
    time::Duration,
};

use chrono::Duration as ChronoDuration;
use opcua_client::{ClientBuilder, HistoryReadAction, IdentityToken, Session};
use opcua_crypto::SecurityPolicy;
use opcua_history_sqlite::SqliteHistoryBackend;
use opcua_server::{
    address_space::{AccessLevel, EventNotifier, ObjectBuilder, VariableBuilder},
    aggregates::engine::{aggregate_average, aggregate_maximum, aggregate_minimum},
    diagnostics::NamespaceMetadata,
    history::HistoryStorageBackend,
    node_manager::memory::{simple_node_manager, SimpleNodeManager},
    ServerBuilder, ServerHandle, ANONYMOUS_USER_TOKEN_ID,
};
use opcua_types::{
    AggregateConfiguration, ByteString, DataTypeId, DataValue, DateTime, EventFilter, HistoryData,
    HistoryEvent, HistoryReadValueId, MessageSecurityMode, NodeId, NumericRange, PerformUpdateType,
    QualifiedName, ReadAnnotationDataDetails, ReadEventDetails, ReadProcessedDetails, StatusCode,
    TimestampsToReturn, Variant,
};
use tokio::net::TcpListener;

static TEST_COUNTER: AtomicU16 = AtomicU16::new(0);
const HISTORY_NAMESPACE_URI: &str = "urn:async-opcua:history-tests:nodes";

struct HistoryServer {
    handle: ServerHandle,
    node_manager: Arc<SimpleNodeManager>,
    session: Arc<Session>,
    backend: Arc<SqliteHistoryBackend>,
    namespace_index: u16,
    pki_dirs: Vec<PathBuf>,
}

impl Drop for HistoryServer {
    fn drop(&mut self) {
        self.handle.cancel();
        for dir in &self.pki_dirs {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

async fn setup_history_server(test_name: &str) -> HistoryServer {
    let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test server listener");
    let addr = listener.local_addr().expect("test server address");
    let endpoint = format!("opc.tcp://127.0.0.1:{}/", addr.port());
    let temp_base = std::env::temp_dir().join(format!("async-opcua-{test_name}-{id}"));
    let server_pki = temp_base.join("server-pki");
    let client_pki = temp_base.join("client-pki");

    let namespace = NamespaceMetadata {
        namespace_uri: HISTORY_NAMESPACE_URI.to_string(),
        namespace_index: 2,
        ..Default::default()
    };

    let server = ServerBuilder::new()
        .application_name("history_tests")
        .application_uri("urn:async-opcua:history-tests")
        .product_uri("urn:async-opcua:history-tests")
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
        .max_array_length(100_000)
        .max_message_size(64 * 1024 * 1024)
        .max_chunk_count(64)
        .with_node_manager(simple_node_manager(namespace, "history-test"));

    let (server, handle) = server.build().expect("build test server");
    tokio::spawn(server.run_with(listener));

    let node_manager = handle
        .node_managers()
        .get_of_type::<SimpleNodeManager>()
        .expect("SimpleNodeManager");
    let backend = Arc::new(SqliteHistoryBackend::new_in_memory().expect("history backend"));
    node_manager.inner().set_history_backend(backend.clone());

    let mut client = ClientBuilder::new()
        .application_name("history_tests_client")
        .application_uri("urn:async-opcua:history-tests-client")
        .product_uri("urn:async-opcua:history-tests-client")
        .pki_dir(&client_pki)
        .create_sample_keypair(true)
        .trust_server_certs(true)
        .session_retry_initial(Duration::from_millis(100))
        .max_array_length(100_000)
        .max_message_size(64 * 1024 * 1024)
        .max_chunk_count(64)
        .client()
        .expect("build test client");

    let (session, event_loop) = client
        .connect_to_matching_endpoint(
            (
                &endpoint as &str,
                SecurityPolicy::None.to_str(),
                MessageSecurityMode::None,
            ),
            IdentityToken::Anonymous,
        )
        .await
        .expect("connect test client");
    event_loop.spawn();
    tokio::time::timeout(Duration::from_secs(5), session.wait_for_connection())
        .await
        .expect("wait for connection");
    let namespace_index = handle
        .get_namespace_index(HISTORY_NAMESPACE_URI)
        .expect("history namespace");

    HistoryServer {
        handle,
        node_manager,
        session,
        backend,
        namespace_index,
        pki_dirs: vec![temp_base],
    }
}

fn add_historical_variable(node_manager: &SimpleNodeManager, node_id: &NodeId) {
    let mut space = node_manager.address_space().write();
    let variable = VariableBuilder::new(node_id, "HistoricalValue", "HistoricalValue")
        .data_type(DataTypeId::Double)
        .historizing(true)
        .value(0.0f64)
        .access_level(
            AccessLevel::HISTORY_READ
                | AccessLevel::HISTORY_WRITE
                | AccessLevel::CURRENT_READ
                | AccessLevel::CURRENT_WRITE,
        )
        .user_access_level(
            AccessLevel::HISTORY_READ
                | AccessLevel::HISTORY_WRITE
                | AccessLevel::CURRENT_READ
                | AccessLevel::CURRENT_WRITE,
        )
        .build();
    space.insert(variable, None::<&[(_, &NodeId, _)]>);
}

fn add_historical_event_object(node_manager: &SimpleNodeManager, node_id: &NodeId) {
    let mut space = node_manager.address_space().write();
    let object = ObjectBuilder::new(node_id, "HistoricalEventSource", "HistoricalEventSource")
        .event_notifier(EventNotifier::HISTORY_READ)
        .build();
    space.insert(object, None::<&[(_, &NodeId, _)]>);
}

fn data_value(value: f64, timestamp: DateTime) -> DataValue {
    DataValue {
        value: Some(Variant::Double(value)),
        status: Some(StatusCode::Good),
        source_timestamp: Some(timestamp),
        server_timestamp: Some(timestamp),
        ..Default::default()
    }
}

fn source_ticks(value: &DataValue) -> i64 {
    value.source_timestamp.expect("source timestamp").ticks()
}

fn double_value(value: &DataValue) -> f64 {
    match value.value.as_ref().expect("value") {
        Variant::Double(value) => *value,
        other => panic!("expected Double, got {other:?}"),
    }
}

fn history_read_value_id(
    node_id: NodeId,
    continuation_point: Option<ByteString>,
) -> HistoryReadValueId {
    HistoryReadValueId {
        node_id,
        index_range: NumericRange::None,
        data_encoding: QualifiedName::null(),
        continuation_point: continuation_point.unwrap_or_default(),
    }
}

async fn read_processed_values(
    session: &Session,
    node_id: NodeId,
    aggregate_type: NodeId,
    start_time: DateTime,
    end_time: DateTime,
    processing_interval: f64,
) -> Vec<DataValue> {
    let results = session
        .history_read(
            HistoryReadAction::ReadProcessedDetails(ReadProcessedDetails {
                start_time,
                end_time,
                processing_interval,
                aggregate_type: Some(vec![aggregate_type]),
                aggregate_configuration: AggregateConfiguration::default(),
            }),
            TimestampsToReturn::Both,
            false,
            &[history_read_value_id(node_id, None)],
        )
        .await
        .expect("processed history read");

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status_code, StatusCode::Good);
    let history_data = results[0]
        .history_data
        .clone()
        .into_inner_as::<HistoryData>()
        .expect("HistoryData");
    history_data.data_values.unwrap_or_default()
}

#[tokio::test]
async fn test_history_read_100k_page_reads() {
    let server = setup_history_server("page-reads").await;
    let node_id = NodeId::new(server.namespace_index, "PageReadValue");
    add_historical_variable(&server.node_manager, &node_id);

    let base_time = DateTime::from((2026, 6, 6, 0, 0, 0));
    let values: Vec<_> = (0..100_000)
        .map(|i| data_value(i as f64, DateTime::from(base_time.ticks() + i as i64)))
        .collect();
    let update_statuses = server
        .backend
        .update_data(&node_id, PerformUpdateType::Insert, values)
        .await
        .expect("insert history values");
    assert_eq!(update_statuses.len(), 100_000);
    assert!(update_statuses
        .iter()
        .all(|status| *status == StatusCode::GoodEntryInserted));

    let mut retrieved = Vec::with_capacity(100_000);
    let mut seen = HashSet::with_capacity(100_000);
    let mut continuation_point = None;
    loop {
        let (mut page, next) = server
            .session
            .history_read_raw(
                node_id.clone(),
                base_time,
                DateTime::from(base_time.ticks() + 100_000),
                10_000,
                false,
                continuation_point,
            )
            .await
            .expect("history page read");
        for value in &page {
            assert!(seen.insert(source_ticks(value)), "duplicate timestamp");
        }
        retrieved.append(&mut page);
        if next.is_none() {
            break;
        }
        continuation_point = next;
    }

    assert_eq!(retrieved.len(), 100_000);
    assert_eq!(seen.len(), 100_000);
    for (i, value) in retrieved.iter().enumerate() {
        assert_eq!(source_ticks(value), base_time.ticks() + i as i64);
        assert_eq!(double_value(value), i as f64);
    }
}

#[tokio::test]
async fn test_history_read_reversed_intervals() {
    let server = setup_history_server("reversed").await;
    let node_id = NodeId::new(server.namespace_index, "ReversedValue");
    add_historical_variable(&server.node_manager, &node_id);

    let base_time = DateTime::from((2026, 6, 6, 1, 0, 0));
    let values: Vec<_> = (0..6)
        .map(|i| data_value(i as f64, base_time + ChronoDuration::seconds(i)))
        .collect();
    server
        .backend
        .update_data(&node_id, PerformUpdateType::Insert, values)
        .await
        .expect("insert reversed interval values");

    let start_time = base_time + ChronoDuration::seconds(5);
    let end_time = base_time + ChronoDuration::seconds(1);
    let (values, continuation_point) = server
        .session
        .history_read_raw(node_id, start_time, end_time, 10, false, None)
        .await
        .expect("read reversed interval");

    assert!(continuation_point.is_none());
    assert_eq!(
        values.iter().map(double_value).collect::<Vec<_>>(),
        vec![5.0, 4.0, 3.0, 2.0]
    );
    assert!(values
        .windows(2)
        .all(|pair| source_ticks(&pair[0]) > source_ticks(&pair[1])));
    assert_eq!(
        source_ticks(values.first().expect("first")),
        start_time.ticks()
    );
    assert_eq!(
        source_ticks(values.last().expect("last")),
        (base_time + ChronoDuration::seconds(2)).ticks()
    );
}

#[tokio::test]
async fn test_history_read_aggregates() {
    let server = setup_history_server("aggregates").await;
    let node_id = NodeId::new(server.namespace_index, "AggregateValue");
    add_historical_variable(&server.node_manager, &node_id);

    let start_time = DateTime::from((2026, 6, 6, 2, 0, 0));
    let values = vec![
        data_value(10.0, start_time),
        data_value(20.0, start_time + ChronoDuration::seconds(5)),
        data_value(5.0, start_time + ChronoDuration::seconds(10)),
        data_value(15.0, start_time + ChronoDuration::seconds(15)),
    ];
    server
        .backend
        .update_data(&node_id, PerformUpdateType::Insert, values)
        .await
        .expect("insert aggregate values");

    let end_time = start_time + ChronoDuration::seconds(20);
    let interval_ms = 10_000.0;
    let averages = read_processed_values(
        &server.session,
        node_id.clone(),
        aggregate_average(),
        start_time,
        end_time,
        interval_ms,
    )
    .await;
    let minimums = read_processed_values(
        &server.session,
        node_id.clone(),
        aggregate_minimum(),
        start_time,
        end_time,
        interval_ms,
    )
    .await;
    let maximums = read_processed_values(
        &server.session,
        node_id,
        aggregate_maximum(),
        start_time,
        end_time,
        interval_ms,
    )
    .await;

    assert_eq!(averages.len(), 2);
    assert_eq!(minimums.len(), 2);
    assert_eq!(maximums.len(), 2);
    assert_eq!(
        averages.iter().map(double_value).collect::<Vec<_>>(),
        vec![15.0, 10.0]
    );
    assert_eq!(
        minimums.iter().map(double_value).collect::<Vec<_>>(),
        vec![10.0, 5.0]
    );
    assert_eq!(
        maximums.iter().map(double_value).collect::<Vec<_>>(),
        vec![20.0, 15.0]
    );
}

#[tokio::test]
async fn test_history_read_events_empty_result() {
    let server = setup_history_server("events").await;
    let node_id = NodeId::new(server.namespace_index, "HistoricalEventSource");
    add_historical_event_object(&server.node_manager, &node_id);

    let results = server
        .session
        .history_read(
            HistoryReadAction::ReadEventDetails(ReadEventDetails {
                num_values_per_node: 10,
                start_time: DateTime::from((2026, 6, 6, 3, 0, 0)),
                end_time: DateTime::from((2026, 6, 6, 4, 0, 0)),
                filter: EventFilter::default(),
            }),
            TimestampsToReturn::Both,
            false,
            &[history_read_value_id(node_id, None)],
        )
        .await
        .expect("event history read");

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status_code, StatusCode::Good);
    let history_event = results[0]
        .history_data
        .clone()
        .into_inner_as::<HistoryEvent>()
        .expect("HistoryEvent");
    assert!(history_event.events.unwrap_or_default().is_empty());
}

#[tokio::test]
async fn test_history_read_annotations_empty_result() {
    let server = setup_history_server("annotations").await;
    let node_id = NodeId::new(server.namespace_index, "AnnotatedValue");
    add_historical_variable(&server.node_manager, &node_id);
    let req_time = DateTime::from((2026, 6, 6, 5, 0, 0));

    let results = server
        .session
        .history_read(
            HistoryReadAction::ReadAnnotationDataDetails(ReadAnnotationDataDetails {
                req_times: Some(vec![req_time]),
            }),
            TimestampsToReturn::Both,
            false,
            &[history_read_value_id(node_id, None)],
        )
        .await
        .expect("annotation history read");

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status_code, StatusCode::Good);
    let history_data = results[0]
        .history_data
        .clone()
        .into_inner_as::<HistoryData>()
        .expect("HistoryData");
    assert!(history_data.data_values.unwrap_or_default().is_empty());
}
