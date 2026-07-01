//! SQLite history scaling gate tests.
//! T105 anchors backend continuation-point behavior to OPC-10000-11 6.3.

use opcua_history_sqlite::SqliteHistoryBackend;
use opcua_server::history::HistoryStorageBackend;
use opcua_types::{DataValue, DateTime, NodeId, PerformUpdateType, StatusCode, Variant};
use std::sync::Arc;
use tokio::sync::Barrier;

fn value_at(ticks: i64, value: f64) -> DataValue {
    DataValue::new_at(Variant::from(value), DateTime::from(ticks))
}

fn source_ticks(value: &DataValue) -> i64 {
    value.source_timestamp.expect("source timestamp").ticks()
}

fn source_ticks_and_double(value: &DataValue) -> (i64, f64) {
    let double = match value.value.as_ref().expect("value") {
        Variant::Double(value) => *value,
        other => panic!("expected Double value, got {other:?}"),
    };

    (source_ticks(value), double)
}

async fn seed_values(
    backend: &SqliteHistoryBackend,
    node_id: &NodeId,
    base_ticks: i64,
    count: usize,
) {
    let values = (0..count)
        .map(|offset| value_at(base_ticks + offset as i64, offset as f64))
        .collect::<Vec<_>>();
    let statuses = backend
        .update_data(node_id, PerformUpdateType::Insert, values)
        .await
        .expect("insert historical values");

    assert_eq!(statuses, vec![StatusCode::GoodEntryInserted; count]);
}

async fn read_nodes_to_read_ticks(
    backend: &SqliteHistoryBackend,
    nodes_to_read: &[NodeId],
    start_time: DateTime,
    end_time: DateTime,
) -> Vec<Vec<i64>> {
    let mut results = Vec::with_capacity(nodes_to_read.len());

    for node_id in nodes_to_read {
        let (values, modification_infos, continuation_point) = backend
            .read_raw_modified(node_id, start_time, end_time, 0, false, false, None)
            .await
            .expect("read history node");

        assert!(modification_infos.is_empty());
        assert!(continuation_point.is_none());
        results.push(values.iter().map(source_ticks).collect());
    }

    results
}

#[tokio::test]
async fn history_lock_scaling_opc_10000_11_6_3_continuation_points_page_resume_and_reject_reuse() {
    const PAGE_SIZE: u32 = 2;
    const VALUE_COUNT: usize = 5;
    const NODE_A_START: i64 = 10_000;
    const NODE_B_START: i64 = 20_000;

    let backend = SqliteHistoryBackend::new_in_memory().expect("history backend");
    let node_a = NodeId::new(2, "ContinuationPointA");
    let node_b = NodeId::new(2, "ContinuationPointB");
    seed_values(&backend, &node_a, NODE_A_START, VALUE_COUNT).await;
    seed_values(&backend, &node_b, NODE_B_START, VALUE_COUNT).await;

    let (first_page, modification_infos, continuation_point) = backend
        .read_raw_modified(
            &node_a,
            DateTime::from(NODE_A_START),
            DateTime::from(NODE_A_START + VALUE_COUNT as i64),
            PAGE_SIZE,
            false,
            false,
            None,
        )
        .await
        .expect("read first page");

    assert!(modification_infos.is_empty());
    assert_eq!(
        first_page.iter().map(source_ticks).collect::<Vec<_>>(),
        vec![NODE_A_START, NODE_A_START + 1]
    );
    let continuation_point = continuation_point.expect("page-limited read returns continuation");

    let (second_page, modification_infos, next_continuation_point) = backend
        .read_raw_modified(
            &node_b,
            DateTime::from(NODE_B_START),
            DateTime::from(NODE_B_START + VALUE_COUNT as i64),
            PAGE_SIZE,
            false,
            false,
            Some(continuation_point.clone()),
        )
        .await
        .expect("read continuation page");

    assert!(modification_infos.is_empty());
    assert_eq!(
        second_page.iter().map(source_ticks).collect::<Vec<_>>(),
        vec![NODE_A_START + 2, NODE_A_START + 3],
        "resume must continue the original node/history stream carried by the token"
    );
    let next_continuation_point =
        next_continuation_point.expect("second limited page returns continuation");

    let reused = backend
        .read_raw_modified(
            &node_a,
            DateTime::from(NODE_A_START),
            DateTime::from(NODE_A_START + VALUE_COUNT as i64),
            PAGE_SIZE,
            false,
            false,
            Some(continuation_point),
        )
        .await;
    assert_eq!(reused, Err(StatusCode::BadContinuationPointInvalid));

    backend
        .release_continuation_point(next_continuation_point.clone())
        .await
        .expect("release continuation point");
    let released = backend
        .read_raw_modified(
            &node_a,
            DateTime::from(NODE_A_START),
            DateTime::from(NODE_A_START + VALUE_COUNT as i64),
            PAGE_SIZE,
            false,
            false,
            Some(next_continuation_point),
        )
        .await;
    assert_eq!(released, Err(StatusCode::BadContinuationPointInvalid));

    let invalid = backend
        .read_raw_modified(
            &node_a,
            DateTime::from(NODE_A_START),
            DateTime::from(NODE_A_START + VALUE_COUNT as i64),
            PAGE_SIZE,
            false,
            false,
            Some(b"not-a-valid-continuation-point".to_vec()),
        )
        .await;
    assert_eq!(invalid, Err(StatusCode::BadContinuationPointInvalid));
}

#[tokio::test]
async fn history_lock_scaling_opc_10000_4_5_11_3_2_nodes_to_read_preserves_request_order_and_node_isolation(
) {
    const VALUE_COUNT: usize = 3;
    const NODE_A_START: i64 = 30_000;
    const NODE_B_START: i64 = 40_000;
    const NODE_C_START: i64 = 50_000;

    let backend = SqliteHistoryBackend::new_in_memory().expect("history backend");
    let node_a = NodeId::new(2, "NodesToReadA");
    let node_b = NodeId::new(2, "NodesToReadB");
    let node_c = NodeId::new(2, "NodesToReadC");
    seed_values(&backend, &node_a, NODE_A_START, VALUE_COUNT).await;
    seed_values(&backend, &node_b, NODE_B_START, VALUE_COUNT).await;
    seed_values(&backend, &node_c, NODE_C_START, VALUE_COUNT).await;

    let nodes_to_read = vec![
        node_b.clone(),
        node_a.clone(),
        node_c.clone(),
        node_a.clone(),
    ];
    let results = read_nodes_to_read_ticks(
        &backend,
        &nodes_to_read,
        DateTime::from(NODE_A_START),
        DateTime::from(NODE_C_START + VALUE_COUNT as i64),
    )
    .await;

    assert_eq!(
        results,
        vec![
            vec![NODE_B_START, NODE_B_START + 1, NODE_B_START + 2],
            vec![NODE_A_START, NODE_A_START + 1, NODE_A_START + 2],
            vec![NODE_C_START, NODE_C_START + 1, NODE_C_START + 2],
            vec![NODE_A_START, NODE_A_START + 1, NODE_A_START + 2],
        ],
        "HistoryRead nodesToRead results must follow request order and keep each node history isolated"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn history_lock_scaling_concurrent_raw_reads_return_node_specific_values_without_leakage() {
    const VALUE_COUNT: usize = 4;
    const NODE_COUNT: usize = 4;
    const READ_REPETITIONS: usize = 3;

    let backend = Arc::new(SqliteHistoryBackend::new_in_memory().expect("history backend"));
    let nodes = (0..NODE_COUNT)
        .map(|index| {
            (
                NodeId::new(2, format!("ConcurrentRead{index}")),
                60_000 + (index as i64 * 1_000),
            )
        })
        .collect::<Vec<_>>();

    for (node_id, base_ticks) in &nodes {
        seed_values(&backend, node_id, *base_ticks, VALUE_COUNT).await;
    }

    let task_count = NODE_COUNT * READ_REPETITIONS;
    let barrier = Arc::new(Barrier::new(task_count));
    let mut tasks = tokio::task::JoinSet::new();

    for repetition in 0..READ_REPETITIONS {
        for (node_id, base_ticks) in nodes.iter().cloned() {
            let backend = backend.clone();
            let barrier = barrier.clone();
            tasks.spawn(async move {
                barrier.wait().await;

                let (values, modification_infos, continuation_point) = backend
                    .read_raw_modified(
                        &node_id,
                        DateTime::from(0),
                        DateTime::from(100_000),
                        0,
                        false,
                        false,
                        None,
                    )
                    .await
                    .expect("concurrent read succeeds");

                assert!(
                    modification_infos.is_empty(),
                    "raw read must not leak modified-history metadata for {node_id:?}"
                );
                assert!(
                    continuation_point.is_none(),
                    "unbounded concurrent read must not leak a continuation point for {node_id:?}"
                );

                let expected = (0..VALUE_COUNT)
                    .map(|offset| (base_ticks + offset as i64, offset as f64))
                    .collect::<Vec<_>>();
                let actual = values
                    .iter()
                    .map(source_ticks_and_double)
                    .collect::<Vec<_>>();
                assert_eq!(
                    actual, expected,
                    "concurrent read {repetition} returned values from the wrong node/history stream"
                );
            });
        }
    }

    while let Some(result) = tasks.join_next().await {
        result.expect("concurrent read task joins");
    }
}

#[tokio::test]
async fn history_lock_scaling_write_during_continuation_read_preserves_ordered_visibility() {
    const PAGE_SIZE: u32 = 2;
    const BASE_TICKS: i64 = 70_000;
    const VALUE_COUNT: usize = 4;
    const INSERT_TICKS: i64 = BASE_TICKS + 2;
    const INSERT_VALUE: f64 = 42.0;

    let backend = SqliteHistoryBackend::new_in_memory().expect("history backend");
    let node_id = NodeId::new(2, "WriteDuringContinuationRead");
    let initial_values = vec![
        value_at(BASE_TICKS, 0.0),
        value_at(BASE_TICKS + 1, 1.0),
        value_at(BASE_TICKS + 3, 3.0),
        value_at(BASE_TICKS + 4, 4.0),
    ];
    let statuses = backend
        .update_data(&node_id, PerformUpdateType::Insert, initial_values)
        .await
        .expect("insert initial historical values");
    assert_eq!(statuses, vec![StatusCode::GoodEntryInserted; VALUE_COUNT]);

    let (first_page, modification_infos, continuation_point) = backend
        .read_raw_modified(
            &node_id,
            DateTime::from(BASE_TICKS),
            DateTime::from(BASE_TICKS + 5),
            PAGE_SIZE,
            false,
            false,
            None,
        )
        .await
        .expect("read first page before write");

    assert!(modification_infos.is_empty());
    assert_eq!(
        first_page
            .iter()
            .map(source_ticks_and_double)
            .collect::<Vec<_>>(),
        vec![(BASE_TICKS, 0.0), (BASE_TICKS + 1, 1.0)]
    );
    let first_page_before_write = first_page
        .iter()
        .map(source_ticks_and_double)
        .collect::<Vec<_>>();
    let continuation_point = continuation_point.expect("page-limited read returns continuation");

    let write_statuses = backend
        .update_data(
            &node_id,
            PerformUpdateType::Insert,
            vec![value_at(INSERT_TICKS, INSERT_VALUE)],
        )
        .await
        .expect("insert value while continuation is held");
    assert_eq!(write_statuses, vec![StatusCode::GoodEntryInserted]);
    assert_eq!(
        first_page
            .iter()
            .map(source_ticks_and_double)
            .collect::<Vec<_>>(),
        first_page_before_write,
        "completed page returned before the write must remain stable"
    );

    let (second_page, modification_infos, next_continuation_point) = backend
        .read_raw_modified(
            &node_id,
            DateTime::from(BASE_TICKS),
            DateTime::from(BASE_TICKS + 5),
            PAGE_SIZE,
            false,
            false,
            Some(continuation_point),
        )
        .await
        .expect("resume continuation page after write");

    assert!(modification_infos.is_empty());
    assert_eq!(
        second_page
            .iter()
            .map(source_ticks_and_double)
            .collect::<Vec<_>>(),
        vec![(INSERT_TICKS, INSERT_VALUE), (BASE_TICKS + 3, 3.0)],
        "current SQLite connection serialization makes the post-page write visible to the resumed read in timestamp order"
    );
    let next_continuation_point =
        next_continuation_point.expect("second limited page returns continuation");

    let (third_page, modification_infos, final_continuation_point) = backend
        .read_raw_modified(
            &node_id,
            DateTime::from(BASE_TICKS),
            DateTime::from(BASE_TICKS + 5),
            PAGE_SIZE,
            false,
            false,
            Some(next_continuation_point),
        )
        .await
        .expect("read final continuation page");

    assert!(modification_infos.is_empty());
    assert_eq!(
        third_page
            .iter()
            .map(source_ticks_and_double)
            .collect::<Vec<_>>(),
        vec![(BASE_TICKS + 4, 4.0)]
    );
    assert!(final_continuation_point.is_none());

    let (all_values, modification_infos, continuation_point) = backend
        .read_raw_modified(
            &node_id,
            DateTime::from(BASE_TICKS),
            DateTime::from(BASE_TICKS + 5),
            0,
            false,
            false,
            None,
        )
        .await
        .expect("read all values after write");

    assert!(modification_infos.is_empty());
    assert!(continuation_point.is_none());
    assert_eq!(
        all_values
            .iter()
            .map(source_ticks_and_double)
            .collect::<Vec<_>>(),
        vec![
            (BASE_TICKS, 0.0),
            (BASE_TICKS + 1, 1.0),
            (INSERT_TICKS, INSERT_VALUE),
            (BASE_TICKS + 3, 3.0),
            (BASE_TICKS + 4, 4.0),
        ],
        "a later read must include the written value in source-timestamp order"
    );
}
