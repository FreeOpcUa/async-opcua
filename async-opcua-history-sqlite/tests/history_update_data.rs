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

// ---- US3: DeleteRawModified + DeleteAtTime (Part 11 §6.9.2 / §6.9.3) ----

#[tokio::test]
async fn delete_raw_modified_removes_range_and_reports_no_data() {
    let b = SqliteHistoryBackend::new_in_memory().unwrap();
    let n = node();
    b.update_data(
        &n,
        PerformUpdateType::Insert,
        vec![at(100, 1.0), at(200, 2.0), at(300, 3.0)],
    )
    .await
    .unwrap();
    // Delete [100, 300) → removes 100 and 200, leaves 300 → Good.
    let r = b
        .delete_raw_modified(&n, false, DateTime::from(100), DateTime::from(300))
        .await
        .unwrap();
    assert_eq!(r, StatusCode::Good);
    let left: Vec<f64> = read_all(&b, &n).await.iter().map(double).collect();
    assert_eq!(left, vec![3.0]);
    // Delete an empty range → BadNoData.
    let r = b
        .delete_raw_modified(&n, false, DateTime::from(1000), DateTime::from(2000))
        .await
        .unwrap();
    assert_eq!(r, StatusCode::BadNoData);
}

#[tokio::test]
async fn delete_modified_branch_leaves_raw_untouched() {
    let b = SqliteHistoryBackend::new_in_memory().unwrap();
    let n = node();
    b.update_data(&n, PerformUpdateType::Insert, vec![at(100, 1.0)])
        .await
        .unwrap();
    // Replace creates a modified (superseded) entry at tick 100.
    b.update_data(&n, PerformUpdateType::Replace, vec![at(100, 2.0)])
        .await
        .unwrap();
    // Deleting the modified branch over the range removes the superseded entry → Good.
    let r = b
        .delete_raw_modified(&n, true, DateTime::from(0), DateTime::from(1000))
        .await
        .unwrap();
    assert_eq!(r, StatusCode::Good);
    // Raw value is untouched (still the replacement 2.0).
    assert_eq!(double(&read_all(&b, &n).await[0]), 2.0);
    // Deleting modified again over the same range → nothing left → BadNoData.
    let r = b
        .delete_raw_modified(&n, true, DateTime::from(0), DateTime::from(1000))
        .await
        .unwrap();
    assert_eq!(r, StatusCode::BadNoData);
}

#[tokio::test]
async fn delete_at_time_per_timestamp_results() {
    let b = SqliteHistoryBackend::new_in_memory().unwrap();
    let n = node();
    b.update_data(
        &n,
        PerformUpdateType::Insert,
        vec![at(100, 1.0), at(300, 3.0)],
    )
    .await
    .unwrap();
    // [present 100, absent 200, present 300] → [Good, BadNoEntryExists, Good].
    let r = b
        .delete_at_time(
            &n,
            vec![
                DateTime::from(100),
                DateTime::from(200),
                DateTime::from(300),
            ],
        )
        .await
        .unwrap();
    assert_eq!(
        r,
        vec![
            StatusCode::Good,
            StatusCode::BadNoEntryExists,
            StatusCode::Good
        ]
    );
    assert!(
        read_all(&b, &n).await.is_empty(),
        "both present entries removed"
    );
}

#[tokio::test]
async fn delete_edges_do_not_panic() {
    let b = SqliteHistoryBackend::new_in_memory().unwrap();
    let n = node();
    // Empty timestamp list → empty vec.
    assert!(b.delete_at_time(&n, vec![]).await.unwrap().is_empty());
    // Inverted range → BadNoData, no panic.
    assert_eq!(
        b.delete_raw_modified(&n, false, DateTime::from(500), DateTime::from(100))
            .await
            .unwrap(),
        StatusCode::BadNoData
    );
}

// ---- US4: modified-history read (Part 11 §6.5) ----

async fn read_modified(
    b: &SqliteHistoryBackend,
    n: &NodeId,
) -> (Vec<DataValue>, Vec<opcua_types::ModificationInfo>) {
    let (values, infos, _cp) = b
        .read_raw_modified(
            n,
            DateTime::from(0),
            DateTime::from(i64::MAX),
            1000,
            false,
            true,
            None,
        )
        .await
        .expect("read modified");
    (values, infos)
}

#[tokio::test]
async fn replace_is_readable_as_modified_replace() {
    use opcua_types::HistoryUpdateType;
    let b = SqliteHistoryBackend::new_in_memory().unwrap();
    let n = node();
    b.update_data(&n, PerformUpdateType::Insert, vec![at(100, 1.0)])
        .await
        .unwrap();
    b.update_data(&n, PerformUpdateType::Replace, vec![at(100, 2.0)])
        .await
        .unwrap();
    let (vals, infos) = read_modified(&b, &n).await;
    assert_eq!(vals.len(), 1);
    assert_eq!(
        double(&vals[0]),
        1.0,
        "modified read returns the superseded value"
    );
    assert_eq!(infos[0].update_type, HistoryUpdateType::Replace);
    // Raw read still returns the live (replacement) value, unaffected.
    assert_eq!(double(&read_all(&b, &n).await[0]), 2.0);
}

#[tokio::test]
async fn delete_at_time_is_readable_as_modified_delete() {
    use opcua_types::HistoryUpdateType;
    let b = SqliteHistoryBackend::new_in_memory().unwrap();
    let n = node();
    b.update_data(&n, PerformUpdateType::Insert, vec![at(100, 7.0)])
        .await
        .unwrap();
    b.delete_at_time(&n, vec![DateTime::from(100)])
        .await
        .unwrap();
    let (vals, infos) = read_modified(&b, &n).await;
    assert_eq!(vals.len(), 1);
    assert_eq!(double(&vals[0]), 7.0);
    assert_eq!(infos[0].update_type, HistoryUpdateType::Delete);
}

#[tokio::test]
async fn update_data_remove_records_modified_delete() {
    use opcua_types::HistoryUpdateType;
    let b = SqliteHistoryBackend::new_in_memory().unwrap();
    let n = node();
    b.update_data(&n, PerformUpdateType::Insert, vec![at(100, 5.0)])
        .await
        .unwrap();
    b.update_data(&n, PerformUpdateType::Remove, vec![at(100, 0.0)])
        .await
        .unwrap();
    let (vals, infos) = read_modified(&b, &n).await;
    assert_eq!(
        vals.len(),
        1,
        "UpdateData Remove must also record a modified Delete entry"
    );
    assert_eq!(double(&vals[0]), 5.0);
    assert_eq!(infos[0].update_type, HistoryUpdateType::Delete);
}

#[tokio::test]
async fn never_modified_value_has_no_modified_entry() {
    let b = SqliteHistoryBackend::new_in_memory().unwrap();
    let n = node();
    b.update_data(&n, PerformUpdateType::Insert, vec![at(100, 1.0)])
        .await
        .unwrap();
    let (vals, _infos) = read_modified(&b, &n).await;
    assert!(
        vals.is_empty(),
        "an unmodified value has no modified-history entry"
    );
    assert_eq!(double(&read_all(&b, &n).await[0]), 1.0);
}
