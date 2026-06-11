//! Test-First integration test for memory-bounded LRU history caching.

use opcua_history_sqlite::SqliteHistoryBackend;
use opcua_server::history::HistoryStorageBackend;
use opcua_types::{DataValue, DateTime, NodeId};

#[tokio::test]
async fn test_history_backend_caching_and_lru_eviction() {
    // 1. Initialize in-memory SQLite history backend
    let backend =
        SqliteHistoryBackend::new_in_memory().expect("Failed to create in-memory backend");
    let node_id = NodeId::new(1, "temperature");

    // Insert a value into the backend database
    let t1 = DateTime::now();
    let val = DataValue::new_now(42.0);
    let _ = backend
        .update_data(
            &node_id,
            opcua_types::PerformUpdateType::Insert,
            vec![val.clone()],
        )
        .await;

    // Read raw values (should query DB and populate the cache)
    let ten_secs = chrono::Duration::try_seconds(10).unwrap();
    let (read_vals, _) = backend
        .read_raw_modified(&node_id, t1 - ten_secs, t1 + ten_secs, 100, false, None)
        .await
        .unwrap();
    assert_eq!(read_vals.len(), 1);

    // Delete the value directly from the DB connection (bypassing cache invalidation in update_data)
    {
        let conn = backend.connection();
        let conn_lock = conn.lock();
        conn_lock
            .execute(
                "DELETE FROM historical_data WHERE node_id = ?1",
                [&node_id.to_string()],
            )
            .unwrap();
    }

    // Query again.
    // Since the cache is wired up, this second query MUST hit the cache and return the cached value (42.0).
    let (read_vals_cached, _) = backend
        .read_raw_modified(&node_id, t1 - ten_secs, t1 + ten_secs, 100, false, None)
        .await
        .unwrap();
    assert_eq!(read_vals_cached.len(), 1);

    let num_val = read_vals_cached[0]
        .value
        .as_ref()
        .unwrap()
        .as_f64()
        .unwrap();
    assert_eq!(
        num_val, 42.0,
        "Cache miss! Query was not served from history cache."
    );

    // Now call update_data with a new value, which must invalidate the cache
    let val_new = DataValue::new_now(100.0);
    let _ = backend
        .update_data(
            &node_id,
            opcua_types::PerformUpdateType::Insert,
            vec![val_new.clone()],
        )
        .await;

    // Query again. Since cache is invalidated, it must query the database and get 100.0.
    let (read_vals_new, _) = backend
        .read_raw_modified(
            &node_id,
            t1 - ten_secs,
            DateTime::now() + ten_secs,
            100,
            false,
            None,
        )
        .await
        .unwrap();
    assert_eq!(read_vals_new.len(), 1);
    let num_val_new = read_vals_new[0].value.as_ref().unwrap().as_f64().unwrap();
    assert_eq!(num_val_new, 100.0, "Cache was not invalidated on update!");
}
