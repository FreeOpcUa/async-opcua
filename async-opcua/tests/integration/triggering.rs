//! C1 (multi-AI cross-check, `specs/multi-ai-test-suites/UNIFIED-PROTOCOL.md`): SetTriggering positive
//! delivery + link removal (Part 4 §5.12.1.6). A Reporting item, when it reports, flushes the queued
//! notifications of linked Sampling items; removing the link stops that. Adapted from the Codex
//! candidate against the existing server implementation (`triggered_items` / `set_triggering`).

use std::time::Duration;

use opcua::{
    server::address_space::{AccessLevel, VariableBuilder},
    types::{
        AttributeId, DataTypeId, DataValue, MonitoredItemCreateRequest, MonitoringMode,
        MonitoringParameters, ObjectId, ReadValueId, ReferenceTypeId, StatusCode,
        TimestampsToReturn, VariableTypeId, Variant,
    },
};
use tokio::time::{sleep, timeout};

use crate::utils::{setup, ChannelNotifications};

fn int32_item(
    node_id: opcua::types::NodeId,
    mode: MonitoringMode,
    client_handle: u32,
) -> MonitoredItemCreateRequest {
    MonitoredItemCreateRequest {
        item_to_monitor: ReadValueId {
            node_id,
            attribute_id: AttributeId::Value as u32,
            ..Default::default()
        },
        monitoring_mode: mode,
        requested_parameters: MonitoringParameters {
            client_handle,
            sampling_interval: 0.0,
            queue_size: 10,
            discard_oldest: true,
            ..Default::default()
        },
    }
}

#[tokio::test]
async fn set_triggering_delivers_queued_sampling_item() {
    // Part 4 §5.12.5: a Reporting item can trigger a linked Sampling item, causing
    // queued linked notifications to be sent when the trigger item reports.
    let (tester, nm, session) = setup().await;

    let trigger_id = nm.inner().next_node_id();
    let linked_id = nm.inner().next_node_id();
    for (id, name, value) in [
        (&trigger_id, "TriggeringSource", 0i32),
        (&linked_id, "TriggeredSamplingTarget", 100i32),
    ] {
        nm.inner().add_node(
            nm.address_space(),
            tester.handle.type_tree(),
            VariableBuilder::new(id, name, name)
                .value(value)
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
    }

    let (notifs, mut data, _) = ChannelNotifications::new();
    let sub_id = session
        .create_subscription(Duration::from_millis(50), 100, 20, 1000, 0, true, notifs)
        .await
        .unwrap();

    let created = session
        .create_monitored_items(
            sub_id,
            TimestampsToReturn::Both,
            vec![
                int32_item(trigger_id.clone(), MonitoringMode::Reporting, 1),
                int32_item(linked_id.clone(), MonitoringMode::Sampling, 2),
            ],
        )
        .await
        .unwrap();
    assert_eq!(created.len(), 2);
    assert_eq!(created[0].result.status_code, StatusCode::Good);
    assert_eq!(created[1].result.status_code, StatusCode::Good);
    let trigger_item = created[0].result.monitored_item_id;
    let linked_item = created[1].result.monitored_item_id;

    // Drain the initial Reporting value from the trigger item before installing
    // the trigger link. The Sampling item must not report just because it was created.
    let (rv, dv) = timeout(Duration::from_secs(2), data.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rv.node_id, trigger_id);
    assert_eq!(dv.value, Some(Variant::Int32(0)));
    assert!(
        timeout(Duration::from_millis(250), data.recv())
            .await
            .is_err(),
        "Sampling item must stay queued until its trigger reports"
    );

    let (add, remove) = session
        .set_triggering(sub_id, trigger_item, &[linked_item], &[])
        .await
        .unwrap();
    assert_eq!(add.unwrap(), vec![StatusCode::Good]);
    // No links removed: the server returns either None or an empty result list for the remove side.
    assert!(remove.is_none_or(|r| r.is_empty()));

    nm.set_value(
        tester.handle.subscriptions(),
        &linked_id,
        None,
        DataValue::new_now(101i32),
    )
    .unwrap();
    sleep(Duration::from_millis(100)).await;
    assert!(
        timeout(Duration::from_millis(250), data.recv())
            .await
            .is_err(),
        "updating only the linked Sampling item must not publish it"
    );

    nm.set_value(
        tester.handle.subscriptions(),
        &trigger_id,
        None,
        DataValue::new_now(1i32),
    )
    .unwrap();

    // The trigger reporting flushes the linked Sampling item's queued notifications. That queue also
    // holds the linked item's initial sample (100), so drain until we have seen the trigger's value
    // and the linked item's latest value (101) — proving the link delivered.
    let mut saw_trigger = false;
    let mut saw_linked_latest = false;
    while !(saw_trigger && saw_linked_latest) {
        let (rv, dv) = timeout(Duration::from_secs(2), data.recv())
            .await
            .expect("triggering must deliver both the trigger and the linked item")
            .unwrap();
        if rv.node_id == trigger_id && dv.value == Some(Variant::Int32(1)) {
            saw_trigger = true;
        }
        if rv.node_id == linked_id && dv.value == Some(Variant::Int32(101)) {
            saw_linked_latest = true;
        }
    }
}

#[tokio::test]
async fn set_triggering_remove_link_stops_triggered_delivery() {
    // Part 4 §5.12.5: removing a trigger link must remove the server-side link,
    // not only the client's local subscription cache.
    let (tester, nm, session) = setup().await;

    let trigger_id = nm.inner().next_node_id();
    let linked_id = nm.inner().next_node_id();
    for (id, name, value) in [
        (&trigger_id, "RemoveTriggerSource", 0i32),
        (&linked_id, "RemoveTriggeredTarget", 10i32),
    ] {
        nm.inner().add_node(
            nm.address_space(),
            tester.handle.type_tree(),
            VariableBuilder::new(id, name, name)
                .value(value)
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
    }

    let (notifs, mut data, _) = ChannelNotifications::new();
    let sub_id = session
        .create_subscription(Duration::from_millis(50), 100, 20, 1000, 0, true, notifs)
        .await
        .unwrap();
    let created = session
        .create_monitored_items(
            sub_id,
            TimestampsToReturn::Both,
            vec![
                int32_item(trigger_id.clone(), MonitoringMode::Reporting, 1),
                int32_item(linked_id.clone(), MonitoringMode::Sampling, 2),
            ],
        )
        .await
        .unwrap();
    let trigger_item = created[0].result.monitored_item_id;
    let linked_item = created[1].result.monitored_item_id;

    // Drain initial trigger value before installing/removing the trigger link.
    let _ = timeout(Duration::from_secs(2), data.recv()).await.unwrap();
    assert!(
        timeout(Duration::from_millis(250), data.recv())
            .await
            .is_err(),
        "Sampling item must not report before it is linked"
    );

    session
        .set_triggering(sub_id, trigger_item, &[linked_item], &[])
        .await
        .unwrap();
    session
        .set_triggering(sub_id, trigger_item, &[], &[linked_item])
        .await
        .unwrap();

    nm.set_value(
        tester.handle.subscriptions(),
        &linked_id,
        None,
        DataValue::new_now(11i32),
    )
    .unwrap();
    nm.set_value(
        tester.handle.subscriptions(),
        &trigger_id,
        None,
        DataValue::new_now(1i32),
    )
    .unwrap();

    let (rv, dv) = timeout(Duration::from_secs(2), data.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rv.node_id, trigger_id);
    assert_eq!(dv.value, Some(Variant::Int32(1)));
    assert!(
        timeout(Duration::from_millis(300), data.recv())
            .await
            .is_err(),
        "removed trigger link must not deliver the linked Sampling item"
    );
}
