//! Independent US1 tests for the sqlite HistoryUpdate `UpdateData` result matrix.
//! Anchored to OPC UA Part 11 §6.8.2 / Part 4 §11.7.2 result codes, not to the implementation.

use opcua_history_sqlite::SqliteHistoryBackend;
use opcua_server::history::HistoryStorageBackend;
use opcua_types::{DataValue, DateTime, NodeId, PerformUpdateType, StatusCode, Variant};

fn at(ticks: i64, v: f64) -> DataValue {
    DataValue::new_at(Variant::from(v), DateTime::from(ticks))
}

fn node() -> NodeId {
    NodeId::new(2, "HistUpdVar")
}

async fn read_all(backend: &SqliteHistoryBackend, node_id: &NodeId) -> Vec<DataValue> {
    let (values, _modinfos, _cp) = backend
        .read_raw_modified(
            node_id,
            DateTime::from(0),
            DateTime::from(i64::MAX),
            1000,
            false,
            None,
        )
        .await
        .expect("read raw");
    values
}

fn double(v: &DataValue) -> f64 {
    match v.value.as_ref().expect("value") {
        Variant::Double(d) => *d,
        other => panic!("expected Double, got {other:?}"),
    }
}

#[tokio::test]
async fn insert_inserts_then_rejects_duplicate() {
    let b = SqliteHistoryBackend::new_in_memory().unwrap();
    let n = node();
    // Insert into empty slot → GoodEntryInserted.
    let r = b
        .update_data(&n, PerformUpdateType::Insert, vec![at(100, 1.0)])
        .await
        .unwrap();
    assert_eq!(r, vec![StatusCode::GoodEntryInserted]);
    // Insert over the existing slot → BadEntryExists, original unchanged.
    let r = b
        .update_data(&n, PerformUpdateType::Insert, vec![at(100, 9.0)])
        .await
        .unwrap();
    assert_eq!(r, vec![StatusCode::BadEntryExists]);
    let vals = read_all(&b, &n).await;
    assert_eq!(vals.len(), 1);
    assert_eq!(double(&vals[0]), 1.0, "rejected Insert must not overwrite");
}

#[tokio::test]
async fn replace_requires_existing_entry() {
    let b = SqliteHistoryBackend::new_in_memory().unwrap();
    let n = node();
    // Replace with nothing present → BadNoEntryExists, nothing stored.
    let r = b
        .update_data(&n, PerformUpdateType::Replace, vec![at(100, 5.0)])
        .await
        .unwrap();
    assert_eq!(r, vec![StatusCode::BadNoEntryExists]);
    assert!(read_all(&b, &n).await.is_empty());
    // Seed then Replace → GoodEntryReplaced, value updated.
    b.update_data(&n, PerformUpdateType::Insert, vec![at(100, 1.0)])
        .await
        .unwrap();
    let r = b
        .update_data(&n, PerformUpdateType::Replace, vec![at(100, 7.0)])
        .await
        .unwrap();
    assert_eq!(r, vec![StatusCode::GoodEntryReplaced]);
    let vals = read_all(&b, &n).await;
    assert_eq!(double(&vals[0]), 7.0);
}

#[tokio::test]
async fn update_inserts_or_replaces() {
    let b = SqliteHistoryBackend::new_in_memory().unwrap();
    let n = node();
    // Update with nothing present → GoodEntryInserted.
    let r = b
        .update_data(&n, PerformUpdateType::Update, vec![at(100, 1.0)])
        .await
        .unwrap();
    assert_eq!(r, vec![StatusCode::GoodEntryInserted]);
    // Update over existing → GoodEntryReplaced.
    let r = b
        .update_data(&n, PerformUpdateType::Update, vec![at(100, 2.0)])
        .await
        .unwrap();
    assert_eq!(r, vec![StatusCode::GoodEntryReplaced]);
    assert_eq!(double(&read_all(&b, &n).await[0]), 2.0);
}

#[tokio::test]
async fn remove_deletes_present_entry_only() {
    let b = SqliteHistoryBackend::new_in_memory().unwrap();
    let n = node();
    // Remove absent → BadNoEntryExists.
    let r = b
        .update_data(&n, PerformUpdateType::Remove, vec![at(100, 0.0)])
        .await
        .unwrap();
    assert_eq!(r, vec![StatusCode::BadNoEntryExists]);
    // Seed then Remove → Good, entry gone.
    b.update_data(&n, PerformUpdateType::Insert, vec![at(100, 1.0)])
        .await
        .unwrap();
    let r = b
        .update_data(&n, PerformUpdateType::Remove, vec![at(100, 0.0)])
        .await
        .unwrap();
    assert_eq!(r, vec![StatusCode::Good]);
    assert!(
        read_all(&b, &n).await.is_empty(),
        "Remove must delete the raw value"
    );
}

#[tokio::test]
async fn empty_batch_and_duplicate_timestamps_do_not_panic() {
    let b = SqliteHistoryBackend::new_in_memory().unwrap();
    let n = node();
    // Empty value array → empty result vec, no panic.
    let r = b
        .update_data(&n, PerformUpdateType::Insert, vec![])
        .await
        .unwrap();
    assert!(r.is_empty());
    // Two values at the SAME timestamp in one Insert batch → first inserts, second sees it exists.
    let r = b
        .update_data(
            &n,
            PerformUpdateType::Insert,
            vec![at(100, 1.0), at(100, 2.0)],
        )
        .await
        .unwrap();
    assert_eq!(
        r,
        vec![StatusCode::GoodEntryInserted, StatusCode::BadEntryExists]
    );
    assert_eq!(read_all(&b, &n).await.len(), 1);
}
