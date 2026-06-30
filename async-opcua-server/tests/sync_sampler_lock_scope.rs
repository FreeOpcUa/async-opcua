//! Expected-red guard release proof for `SyncSampler` sampling.
//!
//! OPC-10000-4 5.13.1.2 and 5.13.1.5 define monitored-item sampling intervals
//! and queues. Slow sampling work must not delay monitored-item add, update, or
//! removal on the sampler map mutex.

use std::{
    sync::{mpsc, Arc},
    thread,
    time::Duration,
};

use opcua_server::{node_manager::SyncSampler, MonitoredItemHandle, ServerBuilder};
use opcua_types::{AttributeId, DataValue, MonitoringMode, NodeId};

const SAMPLER_START_TIMEOUT: Duration = Duration::from_secs(2);
const MAP_OPERATION_TIMEOUT: Duration = Duration::from_millis(250);
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sync_sampler_does_not_hold_sampler_mutex_while_sampling() {
    tokio::time::timeout(TEST_TIMEOUT, run_sampler_mutex_scope_probe())
        .await
        .expect("sync sampler mutex scope probe should not hang");
}

async fn run_sampler_mutex_scope_probe() {
    let (_server, handle) = ServerBuilder::new_anonymous("sync sampler lock scope")
        .build()
        .expect("test server should build");
    let sampler = Arc::new(SyncSampler::new());
    let node_id = NodeId::new(2, "SlowSampledValue");
    let attribute = AttributeId::Value;
    let first_handle = MonitoredItemHandle {
        subscription_id: 1,
        monitored_item_id: 1,
    };
    let second_handle = MonitoredItemHandle {
        subscription_id: 1,
        monitored_item_id: 2,
    };
    let (sample_started_tx, sample_started_rx) = mpsc::channel();
    let (release_sample_tx, release_sample_rx) = mpsc::channel();

    sampler.add_sampler(
        node_id.clone(),
        attribute,
        move || {
            let _ = sample_started_tx.send(());
            let _ = release_sample_rx.recv();
            Some(DataValue::new_now(123i32))
        },
        MonitoringMode::Reporting,
        first_handle,
        Duration::ZERO,
    );

    sampler.run(
        Duration::from_millis(10),
        Arc::clone(handle.subscriptions()),
    );

    sample_started_rx
        .recv_timeout(SAMPLER_START_TIMEOUT)
        .expect("slow sampler did not start; the test cannot prove sampler map mutex scope");

    let (operations_done_tx, operations_done_rx) = mpsc::channel();
    let operation_sampler = Arc::clone(&sampler);
    let operation_node_id = node_id.clone();
    let operation_thread = thread::spawn(move || {
        operation_sampler.update_sampler(
            &operation_node_id,
            attribute,
            first_handle,
            Duration::from_millis(1),
        );
        operation_sampler.add_sampler(
            operation_node_id.clone(),
            attribute,
            || Some(DataValue::new_now(456i32)),
            MonitoringMode::Reporting,
            second_handle,
            Duration::from_millis(1),
        );
        operation_sampler.remove_sampler(&operation_node_id, attribute, second_handle);
        let _ = operations_done_tx.send(());
    });

    let operations_completed = operations_done_rx
        .recv_timeout(MAP_OPERATION_TIMEOUT)
        .is_ok();

    let _ = release_sample_tx.send(());
    operation_thread
        .join()
        .expect("sampler map operation thread should join after releasing the slow sample");

    assert!(
        operations_completed,
        "OPC-10000-4 5.13.1.2 and 5.13.1.5 require monitored-item sampling and queue updates to remain responsive; add/update/remove did not complete while a slow sampler was running, so sampling is likely still holding the sampler map mutex"
    );
}
