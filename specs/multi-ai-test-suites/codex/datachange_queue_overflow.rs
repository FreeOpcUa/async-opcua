//! Candidate integration test for async-opcua/tests/integration/subscriptions.rs.
//!
//! To run inside the main suite, copy this file into `async-opcua/tests/integration/`
//! and add `mod datachange_queue_overflow;` to `mod.rs`. It uses the existing
//! integration-test fixture and raw Publish calls so the client does not drain the
//! queue before the overflow condition is observable.

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
    services::{CreateMonitoredItems, CreateSubscription, Publish, SetPublishingMode},
    UARequest,
};

use crate::utils::setup;

#[tokio::test]
async fn datachange_queue_overflow_sets_single_overflow_bit_at_publish_boundary() {
    // OPC UA Part 4 1.05 §5.13.1.5 / §5.13.2: when a data-change queue overflows with
    // discardOldest=TRUE, the next retained value carries the Overflow info bit. This
    // checks the service-level DataChangeNotification after batching/encoding, not only
    // the local MonitoredItem queue implementation.
    let (tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        VariableBuilder::new(&id, "OverflowValue", "OverflowValue")
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
        .publishing_enabled(false)
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
            monitoring_mode: MonitoringMode::Reporting,
            requested_parameters: MonitoringParameters {
                client_handle: 42,
                sampling_interval: 0.0,
                queue_size: 2,
                discard_oldest: true,
                ..Default::default()
            },
        })
        .timestamps_to_return(TimestampsToReturn::Both)
        .send(session.channel())
        .await
        .unwrap();
    assert_eq!(created.results.len(), 1);
    assert_eq!(created.results[0].result.status_code, StatusCode::Good);

    for value in [1i32, 2, 3] {
        nm.set_value(
            tester.handle.subscriptions(),
            &id,
            None,
            DataValue::new_now(value),
        )
        .unwrap();
    }

    SetPublishingMode::new(true, &session)
        .subscription_ids(vec![sub.subscription_id])
        .send(session.channel())
        .await
        .unwrap();

    let publish = Publish::new(&session)
        .timeout(Duration::from_secs(2))
        .send(session.channel())
        .await
        .unwrap();
    let data_changes = publish
        .notification_message
        .into_notifications()
        .expect("expected queued data-change notifications after enabling publishing")
        .0;
    assert_eq!(data_changes.len(), 1);

    let items = data_changes[0]
        .monitored_items
        .as_ref()
        .expect("data-change notification should contain monitored items");
    let observed: Vec<_> = items
        .iter()
        .map(|item| {
            let value = match item.value.value {
                Some(Variant::Int32(v)) => v,
                ref other => panic!("expected Int32 data value, got {other:?}"),
            };
            let overflow = item.value.status().overflow();
            (value, overflow)
        })
        .collect();

    assert_eq!(
        observed,
        vec![(2, true), (3, false)],
        "discardOldest overflow should retain the last two values and flag only the oldest retained value"
    );
}
