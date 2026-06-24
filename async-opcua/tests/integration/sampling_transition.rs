//! C3 (multi-AI cross-check, `specs/multi-ai-test-suites/UNIFIED-PROTOCOL.md`): Sampling -> Reporting
//! monitoring-mode transition queue semantics (Part 4 §5.13.1.3). A MonitoredItem created in Sampling
//! mode samples and queues values without reporting; transitioning it to Reporting must deliver the
//! queued samples in order — the initial create-value followed by subsequent changes — with none lost
//! and no duplicated/stale value. `set_monitoring_mode` does not clear the queue, so the accumulated
//! history is flushed on the next tick. This pins that behaviour.

use std::time::Duration;

use opcua::{
    server::address_space::{AccessLevel, VariableBuilder},
    types::{
        AttributeId, DataTypeId, DataValue, MonitoredItemCreateRequest, MonitoringMode,
        MonitoringParameters, ObjectId, ReadValueId, ReferenceTypeId, StatusCode,
        TimestampsToReturn, VariableTypeId, Variant,
    },
};
use opcua_client::{
    services::{CreateMonitoredItems, CreateSubscription, Publish, SetMonitoringMode},
    UARequest,
};
use tokio::time::sleep;

use crate::utils::setup;

#[tokio::test]
async fn sampling_to_reporting_flushes_queued_samples_in_order() {
    let (tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        VariableBuilder::new(&id, "SampThenReport", "SampThenReport")
            .value(0i32)
            .data_type(DataTypeId::Int32)
            .access_level(AccessLevel::CURRENT_READ)
            .user_access_level(AccessLevel::CURRENT_READ)
            .build()
            .into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        Some(&VariableTypeId::BaseDataVariableType.into()),
        Vec::new(),
    );

    let sub = CreateSubscription::new(&session)
        .publishing_interval(Duration::from_millis(50))
        .max_lifetime_count(1000)
        .max_keep_alive_count(10)
        .max_notifications_per_publish(1000)
        .priority(0)
        .publishing_enabled(true)
        .send(session.channel())
        .await
        .unwrap();

    let created = CreateMonitoredItems::new(sub.subscription_id, &session)
        .item(MonitoredItemCreateRequest {
            item_to_monitor: ReadValueId {
                node_id: id.clone(),
                attribute_id: AttributeId::Value as u32,
                ..Default::default()
            },
            monitoring_mode: MonitoringMode::Sampling,
            requested_parameters: MonitoringParameters {
                client_handle: 7,
                sampling_interval: 100.0,
                queue_size: 10,
                discard_oldest: true,
                ..Default::default()
            },
        })
        .timestamps_to_return(TimestampsToReturn::Both)
        .send(session.channel())
        .await
        .unwrap();
    let item_id = created.results[0].result.monitored_item_id;
    assert_eq!(created.results[0].result.status_code, StatusCode::Good);

    // Change the value while Sampling (queued, not reported).
    sleep(Duration::from_millis(130)).await;
    nm.set_value(
        tester.handle.subscriptions(),
        &id,
        None,
        DataValue::new_now(5i32),
    )
    .unwrap();
    sleep(Duration::from_millis(130)).await;

    // Transition to Reporting.
    SetMonitoringMode::new(sub.subscription_id, MonitoringMode::Reporting, &session)
        .monitored_item_ids(vec![item_id])
        .send(session.channel())
        .await
        .unwrap();

    let publish = Publish::new(&session)
        .timeout(Duration::from_secs(2))
        .send(session.channel())
        .await
        .unwrap();
    let (data_changes, _) = publish
        .notification_message
        .into_notifications()
        .expect("transition to Reporting must publish the queued samples");
    let delivered: Vec<i32> = data_changes
        .iter()
        .flat_map(|dc| dc.monitored_items.clone().unwrap_or_default())
        .map(|i| match i.value.value {
            Some(Variant::Int32(v)) => v,
            ref other => panic!("expected Int32, got {other:?}"),
        })
        .collect();

    // The initial create-value (0) sampled while in Sampling mode, then the change (5), in order —
    // the unchanged re-samples in between are filtered out, so neither is lost nor stale-duplicated.
    assert_eq!(
        delivered,
        [0, 5],
        "Sampling->Reporting must flush the queued create-value then the change, in order"
    );
}
