//! Independent US2 tests for `InMemoryDataHistory` — the UpdateData result matrix must match the
//! sqlite backend (Part 11 §6.8.2 / Part 4 §11.7.2), plus raw read order and no-panic edges.

use opcua_server::history::{HistoryStorageBackend, InMemoryDataHistory};
use opcua_types::{DataValue, DateTime, NodeId, PerformUpdateType, StatusCode, Variant};

fn at(ticks: i64, v: f64) -> DataValue {
    DataValue::new_at(Variant::from(v), DateTime::from(ticks))
}

fn node() -> NodeId {
    NodeId::new(2, "InMemHistVar")
}

async fn read_all(b: &InMemoryDataHistory, n: &NodeId) -> Vec<DataValue> {
    let (values, modinfos, _cp) = b
        .read_raw_modified(
            n,
            DateTime::from(0),
            DateTime::from(i64::MAX),
            1000,
            false,
            None,
        )
        .await
        .expect("read raw");
    assert!(
        modinfos.is_empty(),
        "raw read must not return ModificationInfo"
    );
    values
}

fn double(v: &DataValue) -> f64 {
    match v.value.as_ref().expect("value") {
        Variant::Double(d) => *d,
        other => panic!("expected Double, got {other:?}"),
    }
}

#[tokio::test]
async fn raw_read_returns_values_in_time_order() {
    let b = InMemoryDataHistory::new();
    let n = node();
    // Insert out of order; read back must be ascending by timestamp.
    b.update_data(
        &n,
        PerformUpdateType::Insert,
        vec![at(300, 3.0), at(100, 1.0), at(200, 2.0)],
    )
    .await
    .unwrap();
    let vals = read_all(&b, &n).await;
    let got: Vec<f64> = vals.iter().map(double).collect();
    assert_eq!(got, vec![1.0, 2.0, 3.0]);
}

#[tokio::test]
async fn update_data_matrix_matches_sqlite_semantics() {
    let b = InMemoryDataHistory::new();
    let n = node();
    // Insert empty → GoodEntryInserted; Insert over existing → BadEntryExists (unchanged).
    assert_eq!(
        b.update_data(&n, PerformUpdateType::Insert, vec![at(100, 1.0)])
            .await
            .unwrap(),
        vec![StatusCode::GoodEntryInserted]
    );
    assert_eq!(
        b.update_data(&n, PerformUpdateType::Insert, vec![at(100, 9.0)])
            .await
            .unwrap(),
        vec![StatusCode::BadEntryExists]
    );
    assert_eq!(double(&read_all(&b, &n).await[0]), 1.0);

    // Replace present → GoodEntryReplaced; Replace absent → BadNoEntryExists.
    assert_eq!(
        b.update_data(&n, PerformUpdateType::Replace, vec![at(100, 7.0)])
            .await
            .unwrap(),
        vec![StatusCode::GoodEntryReplaced]
    );
    assert_eq!(
        b.update_data(&n, PerformUpdateType::Replace, vec![at(999, 0.0)])
            .await
            .unwrap(),
        vec![StatusCode::BadNoEntryExists]
    );
    assert_eq!(double(&read_all(&b, &n).await[0]), 7.0);

    // Update new → GoodEntryInserted; Update overwrite → GoodEntryReplaced.
    assert_eq!(
        b.update_data(&n, PerformUpdateType::Update, vec![at(200, 5.0)])
            .await
            .unwrap(),
        vec![StatusCode::GoodEntryInserted]
    );
    assert_eq!(
        b.update_data(&n, PerformUpdateType::Update, vec![at(200, 6.0)])
            .await
            .unwrap(),
        vec![StatusCode::GoodEntryReplaced]
    );

    // Remove present → Good; Remove absent → BadNoEntryExists.
    assert_eq!(
        b.update_data(&n, PerformUpdateType::Remove, vec![at(100, 0.0)])
            .await
            .unwrap(),
        vec![StatusCode::Good]
    );
    assert_eq!(
        b.update_data(&n, PerformUpdateType::Remove, vec![at(100, 0.0)])
            .await
            .unwrap(),
        vec![StatusCode::BadNoEntryExists]
    );
    // 100 removed, 200 remains.
    let vals = read_all(&b, &n).await;
    assert_eq!(vals.len(), 1);
    assert_eq!(double(&vals[0]), 6.0);
}

#[tokio::test]
async fn empty_batch_and_inverted_range_do_not_panic() {
    let b = InMemoryDataHistory::new();
    let n = node();
    assert!(b
        .update_data(&n, PerformUpdateType::Insert, vec![])
        .await
        .unwrap()
        .is_empty());
    b.update_data(&n, PerformUpdateType::Insert, vec![at(100, 1.0)])
        .await
        .unwrap();
    // start > end → empty, no panic.
    let (vals, _m, _cp) = b
        .read_raw_modified(
            &n,
            DateTime::from(500),
            DateTime::from(100),
            1000,
            false,
            None,
        )
        .await
        .unwrap();
    assert!(vals.is_empty());
}

#[tokio::test]
async fn unknown_node_reads_empty() {
    let b = InMemoryDataHistory::new();
    // Never panics, returns empty for a node with no history.
    assert!(read_all(&b, &NodeId::new(5, "nope")).await.is_empty());
}

// ---- US3: DeleteRawModified + DeleteAtTime, parity with the sqlite backend ----

#[tokio::test]
async fn delete_raw_modified_removes_range_and_reports_no_data() {
    let b = InMemoryDataHistory::new();
    let n = node();
    b.update_data(
        &n,
        PerformUpdateType::Insert,
        vec![at(100, 1.0), at(200, 2.0), at(300, 3.0)],
    )
    .await
    .unwrap();
    let r = b
        .delete_raw_modified(&n, false, DateTime::from(100), DateTime::from(300))
        .await
        .unwrap();
    assert_eq!(r, StatusCode::Good);
    let left: Vec<f64> = read_all(&b, &n).await.iter().map(double).collect();
    assert_eq!(left, vec![3.0]);
    let r = b
        .delete_raw_modified(&n, false, DateTime::from(1000), DateTime::from(2000))
        .await
        .unwrap();
    assert_eq!(r, StatusCode::BadNoData);
}

#[tokio::test]
async fn delete_modified_branch_leaves_raw_untouched() {
    let b = InMemoryDataHistory::new();
    let n = node();
    b.update_data(&n, PerformUpdateType::Insert, vec![at(100, 1.0)])
        .await
        .unwrap();
    b.update_data(&n, PerformUpdateType::Replace, vec![at(100, 2.0)])
        .await
        .unwrap();
    let r = b
        .delete_raw_modified(&n, true, DateTime::from(0), DateTime::from(1000))
        .await
        .unwrap();
    assert_eq!(r, StatusCode::Good);
    assert_eq!(double(&read_all(&b, &n).await[0]), 2.0);
    let r = b
        .delete_raw_modified(&n, true, DateTime::from(0), DateTime::from(1000))
        .await
        .unwrap();
    assert_eq!(r, StatusCode::BadNoData);
}

#[tokio::test]
async fn delete_at_time_per_timestamp_results() {
    let b = InMemoryDataHistory::new();
    let n = node();
    b.update_data(
        &n,
        PerformUpdateType::Insert,
        vec![at(100, 1.0), at(300, 3.0)],
    )
    .await
    .unwrap();
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
    assert!(read_all(&b, &n).await.is_empty());
}

#[tokio::test]
async fn delete_edges_do_not_panic() {
    let b = InMemoryDataHistory::new();
    let n = node();
    assert!(b.delete_at_time(&n, vec![]).await.unwrap().is_empty());
    assert_eq!(
        b.delete_raw_modified(&n, false, DateTime::from(500), DateTime::from(100))
            .await
            .unwrap(),
        StatusCode::BadNoData
    );
    // Unknown node delete_at_time → all BadNoEntryExists.
    assert_eq!(
        b.delete_at_time(&NodeId::new(9, "x"), vec![DateTime::from(1)])
            .await
            .unwrap(),
        vec![StatusCode::BadNoEntryExists]
    );
}
