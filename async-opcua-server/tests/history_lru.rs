//! Regression coverage for bounded SQLite history reads.

use opcua_history_sqlite::SqliteHistoryBackend;
use opcua_server::history::HistoryStorageBackend;
use opcua_types::{DataValue, DateTime, NodeId, PerformUpdateType, StatusCode, Variant};

#[tokio::test]
async fn test_history_backend_uses_bounded_continuation_cursor() {
    let backend = SqliteHistoryBackend::new_in_memory().expect("history backend");
    let node_id = NodeId::new(1, "temperature");
    let start_time = DateTime::from((2026, 6, 20, 0, 0, 0));
    let values = (0..3)
        .map(|offset| {
            DataValue::new_at(
                Variant::from(offset as f64),
                DateTime::from(start_time.ticks() + offset),
            )
        })
        .collect::<Vec<_>>();

    let statuses = backend
        .update_data(&node_id, PerformUpdateType::Insert, values)
        .await
        .expect("insert historical values");
    assert!(statuses
        .iter()
        .all(|status| *status == StatusCode::GoodEntryInserted));

    let (first_page, modification_infos, continuation_point) = backend
        .read_raw_modified(
            &node_id,
            start_time,
            DateTime::from(start_time.ticks() + 10),
            1,
            false,
            false,
            None,
        )
        .await
        .expect("read first page");

    assert!(modification_infos.is_empty());
    assert_eq!(first_page.len(), 1);
    assert_eq!(
        first_page[0].source_timestamp.expect("source timestamp"),
        start_time
    );
    let continuation_point = continuation_point.expect("continuation point");

    // US1 intentionally replaced full-interval result caching with a keyset
    // cursor. A continuation read must query the remaining rows, not replay a
    // materialized full result set that can grow without bound.
    {
        let conn = backend.connection();
        let conn_lock = conn.lock();
        conn_lock
            .execute(
                "DELETE FROM historical_data
                 WHERE node_id = ?1 AND source_timestamp > ?2",
                (&node_id.to_string(), start_time.ticks()),
            )
            .expect("delete remaining historical values");
    }

    let (remaining, modification_infos, next_continuation_point) = backend
        .read_raw_modified(
            &node_id,
            start_time,
            DateTime::from(start_time.ticks() + 10),
            10,
            false,
            false,
            Some(continuation_point.clone()),
        )
        .await
        .expect("read continuation page");

    assert!(modification_infos.is_empty());
    assert!(remaining.is_empty());
    assert!(next_continuation_point.is_none());

    let error = backend
        .read_raw_modified(
            &node_id,
            start_time,
            DateTime::from(start_time.ticks() + 10),
            10,
            false,
            false,
            Some(continuation_point),
        )
        .await;
    assert_eq!(error, Err(StatusCode::BadContinuationPointInvalid));
}
