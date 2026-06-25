//! SQLite history migration and query behavior tests.

use std::sync::Mutex;

use opcua_history_sqlite::{
    migration::run_migrations,
    query::{fetch_bounds, fetch_interval},
    SqliteHistoryBackend,
};
use opcua_server::{aggregates::engine::aggregate_average, history::HistoryStorageBackend};
use opcua_types::{
    BinaryEncodable, ContextOwned, DataValue, DateTime, EventFilter, HistoryEventFieldList, NodeId,
    PerformUpdateType, StatusCode, Variant,
};
use rusqlite::{params, Connection};

static SQL_TRACES: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn record_sql_trace(sql: &str) {
    SQL_TRACES
        .lock()
        .expect("sql traces lock")
        .push(sql.to_string());
}

fn insert_value(conn: &Connection, node_id: &str, ticks: i64, value: f64) {
    let data_value = DataValue::new_at(Variant::from(value), DateTime::from(ticks));
    let ctx_owned = ContextOwned::default();
    let blob = data_value.encode_to_vec(&ctx_owned.context());

    conn.execute(
        "INSERT INTO historical_data (
            node_id,
            source_timestamp,
            server_timestamp,
            value_blob,
            status_code
        ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![node_id, ticks, ticks, blob, StatusCode::Good.bits() as i64],
    )
    .expect("insert historical data");
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

#[test]
fn run_migrations_creates_historical_data_table_and_query_index() {
    let conn = Connection::open_in_memory().expect("open database");

    run_migrations(&conn).expect("run migrations");

    let table_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'historical_data'",
            [],
            |row| row.get(0),
        )
        .expect("query table");
    let index_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_historical_data_query'",
            [],
            |row| row.get(0),
        )
        .expect("query index");

    assert_eq!(table_count, 1);
    assert_eq!(index_count, 1);
}

#[test]
fn fetch_interval_uses_half_open_bounds_and_requested_order() {
    let conn = Connection::open_in_memory().expect("open database");
    run_migrations(&conn).expect("run migrations");
    let node_id = "ns=2;s=Temperature";
    for ticks in [100_i64, 200, 300] {
        insert_value(&conn, node_id, ticks, ticks as f64);
    }

    let forward =
        fetch_interval(&conn, node_id, 100, 300, true, None, 100).expect("fetch forward interval");
    let reverse =
        fetch_interval(&conn, node_id, 300, 100, false, None, 100).expect("fetch reverse interval");

    assert_eq!(
        forward.iter().map(source_ticks).collect::<Vec<_>>(),
        vec![100, 200]
    );
    assert_eq!(
        reverse.iter().map(source_ticks).collect::<Vec<_>>(),
        vec![300, 200]
    );
}

#[test]
fn fetch_bounds_finds_adjacent_values() {
    let conn = Connection::open_in_memory().expect("open database");
    run_migrations(&conn).expect("run migrations");
    let node_id = "ns=2;s=Temperature";
    for ticks in [100_i64, 200, 300] {
        insert_value(&conn, node_id, ticks, ticks as f64);
    }

    let previous = fetch_bounds(&conn, node_id, 250, true)
        .expect("fetch previous bound")
        .expect("previous bound");
    let next = fetch_bounds(&conn, node_id, 250, false)
        .expect("fetch next bound")
        .expect("next bound");

    assert_eq!(source_ticks(&previous), 200);
    assert_eq!(source_ticks(&next), 300);
}

#[tokio::test]
async fn sqlite_backend_read_processed_computes_aggregates() {
    let backend = SqliteHistoryBackend::new_in_memory().expect("history backend");
    let node_id = NodeId::new(2, "AggregateValue");
    let start_time = DateTime::from((2026, 6, 6, 2, 0, 0));
    let values = vec![
        DataValue::new_at(Variant::from(10.0), start_time),
        DataValue::new_at(
            Variant::from(20.0),
            DateTime::from(start_time.ticks() + 5_000_000),
        ),
    ];
    let statuses = backend
        .update_data(&node_id, PerformUpdateType::Insert, values)
        .await
        .expect("insert data");
    assert_eq!(
        statuses,
        vec![StatusCode::GoodEntryInserted, StatusCode::GoodEntryInserted]
    );

    let (processed, continuation_point) = backend
        .read_processed(
            &node_id,
            start_time,
            DateTime::from(start_time.ticks() + 10_000_000),
            10_000.0,
            &aggregate_average(),
            &opcua_types::AggregateConfiguration::default(),
            None,
        )
        .await
        .expect("read processed");

    assert!(continuation_point.is_none());
    assert_eq!(processed.len(), 1);
    assert_eq!(double_value(&processed[0]), 15.0);
}

#[tokio::test]
async fn sqlite_backend_read_raw_modified_bounds_first_page_query_and_continuation_order() {
    const VALUE_COUNT: usize = 3_000;
    const PAGE_SIZE: u32 = 10;

    let backend = SqliteHistoryBackend::new_in_memory().expect("history backend");
    let node_id = NodeId::new(2, "BoundedHistoryValue");
    let start_time = DateTime::from((2026, 6, 6, 0, 0, 0));
    let values = (0..VALUE_COUNT)
        .map(|offset| {
            DataValue::new_at(
                Variant::from(offset as f64),
                DateTime::from(start_time.ticks() + offset as i64),
            )
        })
        .collect::<Vec<_>>();

    let statuses = backend
        .update_data(&node_id, PerformUpdateType::Insert, values)
        .await
        .expect("insert data");
    assert!(statuses
        .iter()
        .all(|status| *status == StatusCode::GoodEntryInserted));

    {
        SQL_TRACES.lock().expect("sql traces lock").clear();
        let connection = backend.connection();
        let mut conn = connection.lock();
        conn.trace(Some(record_sql_trace));
    }

    let (first_page, continuation_point) = backend
        .read_raw_modified(
            &node_id,
            start_time,
            DateTime::from(start_time.ticks() + VALUE_COUNT as i64),
            PAGE_SIZE,
            false,
            None,
        )
        .await
        .expect("read first page");

    assert_eq!(first_page.len(), PAGE_SIZE as usize);
    assert_eq!(
        first_page.iter().map(source_ticks).collect::<Vec<_>>(),
        (0..PAGE_SIZE as i64)
            .map(|offset| start_time.ticks() + offset)
            .collect::<Vec<_>>()
    );
    let continuation_point = continuation_point.expect("continuation point");

    let (remaining, next_continuation_point) = backend
        .read_raw_modified(
            &node_id,
            start_time,
            DateTime::from(start_time.ticks() + VALUE_COUNT as i64),
            VALUE_COUNT as u32,
            false,
            Some(continuation_point),
        )
        .await
        .expect("read continuation page");

    assert!(next_continuation_point.is_none());
    assert_eq!(remaining.len(), VALUE_COUNT - PAGE_SIZE as usize);

    let all_ticks = first_page
        .iter()
        .chain(remaining.iter())
        .map(source_ticks)
        .collect::<Vec<_>>();
    assert_eq!(
        all_ticks,
        (0..VALUE_COUNT as i64)
            .map(|offset| start_time.ticks() + offset)
            .collect::<Vec<_>>()
    );

    let interval_queries = SQL_TRACES
        .lock()
        .expect("sql traces lock")
        .iter()
        .filter(|sql| {
            sql.contains("FROM historical_data")
                && sql.contains("source_timestamp >=")
                && sql.contains("ORDER BY source_timestamp ASC")
        })
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        interval_queries
            .iter()
            .any(|sql| sql.to_ascii_uppercase().contains("LIMIT")),
        "first page interval query must be SQL-bounded with LIMIT; observed queries: {interval_queries:#?}"
    );
}

#[tokio::test]
async fn sqlite_backend_read_events_returns_empty_history_events() {
    let backend = SqliteHistoryBackend::new_in_memory().expect("history backend");
    let node_id = NodeId::new(2, "EventSource");

    let (events, continuation_point) = backend
        .read_events(
            &node_id,
            DateTime::from((2026, 6, 6, 0, 0, 0)),
            DateTime::from((2026, 6, 6, 1, 0, 0)),
            10,
            &EventFilter::default(),
            None,
        )
        .await
        .expect("read events");

    assert!(continuation_point.is_none());
    assert_eq!(events, Vec::<HistoryEventFieldList>::new());
}

#[tokio::test]
async fn sqlite_backend_read_annotations_returns_empty_history_data() {
    let backend = SqliteHistoryBackend::new_in_memory().expect("history backend");
    let node_id = NodeId::new(2, "AnnotatedValue");

    let (annotations, continuation_point) = backend
        .read_annotations(&node_id, &[DateTime::from((2026, 6, 6, 0, 0, 0))], None)
        .await
        .expect("read annotations");

    assert!(continuation_point.is_none());
    assert!(annotations.is_empty());
}
