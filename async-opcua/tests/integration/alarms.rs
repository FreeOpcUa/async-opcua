use std::{sync::Arc, time::Duration};

use crate::utils::{default_server, ChannelNotifications, Tester};
use opcua::{
    server::{
        address_space::AddressSpace,
        node_manager::memory::{simple_node_manager, SimpleNodeManager},
    },
    types::{
        AttributeId, CallMethodRequest, LocalizedText, MonitoredItemCreateRequest, MonitoringMode,
        MonitoringParameters, NodeId, ObjectId, ReadValueId, StatusCode, TimestampsToReturn,
        Variant,
    },
};
use opcua_client::alarms::client::{get_alarm_event_select_clauses, parse_alarm_event};
use opcua_core::events::AlarmEvent;
use opcua_server::namespace::register_alarm_condition;
use opcua_types::{EventFilter, ExtensionObject};
use tokio::time::timeout;

pub async fn setup_alarms() -> (Tester, Arc<SimpleNodeManager>, Arc<opcua_client::Session>) {
    let namespace = opcua::server::diagnostics::NamespaceMetadata {
        namespace_uri: "urn:rustopcuatestserver".to_owned(),
        namespace_index: 2,
        ..Default::default()
    };
    let simple_mgr = simple_node_manager(namespace, "test");
    let server = default_server().with_node_manager(simple_mgr);
    let mut tester = Tester::new(server, false).await;
    let nm = tester
        .handle
        .node_managers()
        .get_of_type::<SimpleNodeManager>()
        .expect("SimpleNodeManager not found");
    let (session, lp) = tester.connect_default().await.unwrap();
    lp.spawn();
    timeout(Duration::from_secs(2), session.wait_for_connection())
        .await
        .unwrap();

    (tester, nm, session)
}

#[tokio::test]
async fn test_alarm_trigger_and_acknowledge() {
    let (tester, nm, session) = setup_alarms().await;

    // 1. Create a source node in the AddressSpace
    let source_node_id = NodeId::new(2, "MyDevice");
    {
        let mut space = nm.address_space().write();
        let source_node = opcua::server::address_space::ObjectBuilder::new(
            &source_node_id,
            "MyDevice",
            "MyDevice",
        )
        .component_of(ObjectId::ObjectsFolder)
        .event_notifier(opcua::server::address_space::EventNotifier::SUBSCRIBE_TO_EVENTS)
        .build();
        space.insert::<_, NodeId>(source_node, None);
    }

    // 2. Register the Alarm Condition state machine
    let state_machine = register_alarm_condition(
        nm.address_space(),
        &nm,
        "Device1",
        "Temperature",
        source_node_id.clone(),
        "Temperature alarm",
    );

    // 3. Create client-side subscription for events
    let (notifs, _, mut events) = ChannelNotifications::new();
    let sub_id = session
        .create_subscription(Duration::from_millis(100), 100, 20, 1000, 0, true, notifs)
        .await
        .unwrap();

    let select_clauses = get_alarm_event_select_clauses();

    session
        .create_monitored_items(
            sub_id,
            TimestampsToReturn::Both,
            vec![MonitoredItemCreateRequest {
                item_to_monitor: ReadValueId {
                    node_id: source_node_id.clone(),
                    attribute_id: AttributeId::EventNotifier as u32,
                    ..Default::default()
                },
                monitoring_mode: MonitoringMode::Reporting,
                requested_parameters: MonitoringParameters {
                    sampling_interval: 0.0,
                    queue_size: 10,
                    discard_oldest: true,
                    filter: ExtensionObject::new(EventFilter {
                        select_clauses: Some(select_clauses),
                        where_clause: opcua_types::ContentFilter::default(),
                    }),
                    ..Default::default()
                },
            }],
        )
        .await
        .unwrap();

    // 4. Trigger Alarm state transition to Active
    let event = {
        let mut space = nm.address_space().write();
        trigger_alarm_transition(
            &mut space,
            &state_machine,
            true,
            800,
            LocalizedText::new("en", "High temperature!"),
        )
        .unwrap()
        .expect("Expected transition to generate an event")
    };

    // 5. Dispatch Event
    {
        let wrapper = opcua::server::alarms::ServerAlarmEvent { event: &event };
        tester
            .handle
            .subscriptions()
            .notify_events(std::iter::once((
                &wrapper as &dyn opcua::nodes::Event,
                &event.source_node,
            )));
    }

    // 6. Receive and assert Event on the client
    let (_r1, v1) = timeout(Duration::from_secs(2), events.recv())
        .await
        .unwrap()
        .unwrap();
    let fields = v1.unwrap();
    println!("Received Event Fields: {:?}", fields);
    let alarm_event = parse_alarm_event(&fields).expect("Failed to parse alarm event");

    assert!(alarm_event.active_state);
    assert!(!alarm_event.acked_state);
    assert!(!alarm_event.confirmed_state);
    assert_eq!(alarm_event.severity, 800);
    assert_eq!(alarm_event.message.text.as_ref(), "High temperature!");

    // 7. Acknowledge the alarm via Method call
    let base_s = format!("Alarm_{}_{}", "Device1", "Temperature");
    let ack_method_id = NodeId::new(2, format!("{}_Acknowledge", base_s));

    let response = session
        .call_one(CallMethodRequest {
            object_id: state_machine.condition_id.clone(),
            method_id: ack_method_id,
            input_arguments: Some(vec![
                Variant::from(opcua::types::ByteString::from(alarm_event.event_id.clone())),
                Variant::from(LocalizedText::new("en", "Acknowledged by integration test")),
            ]),
        })
        .await
        .unwrap();
    assert_eq!(response.status_code, StatusCode::Good);

    // Verify server address space update
    {
        let space = nm.address_space().read();
        assert!(state_machine.get_acked(&space));
        assert!(state_machine.get_active(&space));
        assert!(!state_machine.get_confirmed(&space));
    }

    // 8. Receive and assert the Acknowledged Event notification
    let (_r2, v2) = timeout(Duration::from_secs(2), events.recv())
        .await
        .unwrap()
        .unwrap();
    let fields2 = v2.unwrap();
    let ack_event = parse_alarm_event(&fields2).expect("Failed to parse acknowledgment event");

    assert!(ack_event.active_state);
    assert!(ack_event.acked_state);
    assert!(!ack_event.confirmed_state);

    // 9. Confirm the alarm via Method call
    let confirm_method_id = NodeId::new(2, format!("{}_Confirm", base_s));

    let response2 = session
        .call_one(CallMethodRequest {
            object_id: state_machine.condition_id.clone(),
            method_id: confirm_method_id,
            input_arguments: Some(vec![
                Variant::from(opcua::types::ByteString::from(ack_event.event_id.clone())),
                Variant::from(LocalizedText::new("en", "Confirmed by integration test")),
            ]),
        })
        .await
        .unwrap();
    assert_eq!(response2.status_code, StatusCode::Good);

    // Verify server address space update
    {
        let space = nm.address_space().read();
        assert!(state_machine.get_confirmed(&space));
        assert!(state_machine.get_acked(&space));
    }

    // 10. Receive and assert the Confirmed Event notification
    let (_r3, v3) = timeout(Duration::from_secs(2), events.recv())
        .await
        .unwrap()
        .unwrap();
    let fields3 = v3.unwrap();
    let confirm_event = parse_alarm_event(&fields3).expect("Failed to parse confirmation event");

    assert!(confirm_event.active_state);
    assert!(confirm_event.acked_state);
    assert!(confirm_event.confirmed_state);
}

// Helper to access transition triggers in testing
fn trigger_alarm_transition(
    address_space: &mut AddressSpace,
    state_machine: &opcua::server::alarms::ConditionStateMachine,
    active: bool,
    severity: u16,
    message: LocalizedText,
) -> Result<Option<AlarmEvent>, StatusCode> {
    opcua::server::alarms::transitions::trigger_alarm_transition(
        address_space,
        state_machine,
        active,
        severity,
        message,
    )
}

/// Part 9 AcknowledgeableConditionType: the Acknowledge/Confirm state guards. The happy-path test
/// covers the valid Active -> Ack -> Confirm flow; this locks in the error paths:
/// Confirm-before-Acknowledge -> Bad_InvalidState, double-Acknowledge ->
/// Bad_ConditionBranchAlreadyAcked, double-Confirm -> Bad_ConditionBranchAlreadyConfirmed.
/// (Note: the server does not validate the EventId argument, so these are pure state-machine guards.)
#[tokio::test]
async fn alarm_acknowledge_confirm_error_paths() {
    let (_tester, nm, session) = setup_alarms().await;

    let source_node_id = NodeId::new(2, "ErrDevice");
    {
        let mut space = nm.address_space().write();
        let source = opcua::server::address_space::ObjectBuilder::new(
            &source_node_id,
            "ErrDevice",
            "ErrDevice",
        )
        .component_of(ObjectId::ObjectsFolder)
        .event_notifier(opcua::server::address_space::EventNotifier::SUBSCRIBE_TO_EVENTS)
        .build();
        space.insert::<_, NodeId>(source, None);
    }

    let state_machine = register_alarm_condition(
        nm.address_space(),
        &nm,
        "ErrDev",
        "Temp",
        source_node_id.clone(),
        "alarm",
    );

    // Drive the condition to Active so it is acknowledgeable.
    let event = {
        let mut space = nm.address_space().write();
        trigger_alarm_transition(
            &mut space,
            &state_machine,
            true,
            800,
            LocalizedText::new("en", "active"),
        )
        .unwrap()
        .expect("transition should generate an event")
    };
    let event_id = opcua::types::ByteString::from(event.event_id.clone());

    let base_s = "Alarm_ErrDev_Temp";
    let ack_id = NodeId::new(2, format!("{base_s}_Acknowledge"));
    let confirm_id = NodeId::new(2, format!("{base_s}_Confirm"));

    let call = |method_id: NodeId| {
        let session = session.clone();
        let condition_id = state_machine.condition_id.clone();
        let event_id = event_id.clone();
        async move {
            session
                .call_one(CallMethodRequest {
                    object_id: condition_id,
                    method_id,
                    input_arguments: Some(vec![
                        Variant::from(event_id),
                        Variant::from(LocalizedText::new("en", "c")),
                    ]),
                })
                .await
                .unwrap()
                .status_code
        }
    };

    // Confirm before Acknowledge -> Bad_InvalidState (not yet acknowledged).
    assert_eq!(call(confirm_id.clone()).await, StatusCode::BadInvalidState);

    // Acknowledge once -> Good; acknowledging again -> Bad_ConditionBranchAlreadyAcked.
    assert_eq!(call(ack_id.clone()).await, StatusCode::Good);
    assert_eq!(
        call(ack_id.clone()).await,
        StatusCode::BadConditionBranchAlreadyAcked
    );

    // Confirm once -> Good; confirming again -> Bad_ConditionBranchAlreadyConfirmed.
    assert_eq!(call(confirm_id.clone()).await, StatusCode::Good);
    assert_eq!(
        call(confirm_id).await,
        StatusCode::BadConditionBranchAlreadyConfirmed
    );
}
