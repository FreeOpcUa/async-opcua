use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use crate::utils::{default_server, ChannelNotifications, Tester};
use chrono::TimeDelta;
use opcua::client::HistoryReadAction;
use opcua::{
    server::{
        address_space::{AccessLevel, AddressSpace, VariableBuilder},
        node_manager::memory::{simple_node_manager, CoreNodeManager, SimpleNodeManager},
    },
    types::{
        AttributeId, BrowsePath, ByteString, CallMethodRequest, DataValue, LocalizedText, MethodId,
        MonitoredItemCreateRequest, MonitoringMode, MonitoringParameters, NodeId, ObjectId,
        ObjectTypeId, QualifiedName, ReadValueId, ReferenceTypeId, RelativePath,
        RelativePathElement, StatusCode, TimestampsToReturn, Variant, WriteValue,
    },
};
use opcua_client::alarms::client::{get_alarm_event_select_clauses, parse_alarm_event};
use opcua_core::events::AlarmEvent;
use opcua_server::alarms::{
    register_condition_methods, register_dialog_condition_methods, ConditionRegistry,
    DialogCondition, DialogRegistry, DiscreteAlarm, DiscreteAlarmKind, LimitAlarm, LimitConfig,
    LimitDef, LimitMode, ShelvingState,
};
use opcua_server::history::InMemoryEventHistory;
use opcua_server::namespace::{
    register_alarm_condition, register_discrete_alarm, register_limit_alarm,
    register_limit_alarm_checked,
};
use opcua_types::{
    DataTypeId, DateTime, EventFilter, ExtensionObject, HistoryEvent, HistoryReadValueId, Range,
    ReadEventDetails, VariableTypeId,
};
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

    // 2. Register the Alarm Condition state machine, and wire the standard ns0 Acknowledge/Confirm
    //    (i=9111/i=9113) on the core node manager via the condition registry.
    let core_nm = tester
        .handle
        .node_managers()
        .get_of_type::<CoreNodeManager>()
        .expect("CoreNodeManager not found");
    let state_machine = register_alarm_condition(
        nm.address_space(),
        &nm,
        "Device1",
        "Temperature",
        source_node_id.clone(),
        "Temperature alarm",
    );
    let registry = ConditionRegistry::new();
    registry.register(state_machine.clone());
    register_condition_methods(&core_nm, registry, nm.address_space().clone());

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

    // 7. Acknowledge the alarm via the standard type Method (i=9111) on the condition instance.
    let response = session
        .call_one(CallMethodRequest {
            object_id: state_machine.condition_id.clone(),
            method_id: MethodId::AcknowledgeableConditionType_Acknowledge.into(),
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

    // 9. Confirm the alarm via the standard type Method (i=9113).
    let response2 = session
        .call_one(CallMethodRequest {
            object_id: state_machine.condition_id.clone(),
            method_id: MethodId::AcknowledgeableConditionType_Confirm.into(),
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
    let (tester, nm, session) = setup_alarms().await;
    let core_nm = tester
        .handle
        .node_managers()
        .get_of_type::<CoreNodeManager>()
        .expect("CoreNodeManager not found");

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
    let registry = ConditionRegistry::new();
    registry.register(state_machine.clone());
    register_condition_methods(&core_nm, registry, nm.address_space().clone());

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

    let ack_id: NodeId = MethodId::AcknowledgeableConditionType_Acknowledge.into();
    let confirm_id: NodeId = MethodId::AcknowledgeableConditionType_Confirm.into();

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

    // An unknown EventId is rejected with Bad_EventIdUnknown, before the state guards (Part 9 §5.5.2).
    let bogus = session
        .call_one(CallMethodRequest {
            object_id: state_machine.condition_id.clone(),
            method_id: ack_id.clone(),
            input_arguments: Some(vec![
                Variant::from(opcua::types::ByteString::from(vec![0xAAu8; 16])),
                Variant::from(LocalizedText::new("en", "wrong id")),
            ]),
        })
        .await
        .unwrap();
    assert_eq!(bogus.status_code, StatusCode::BadEventIdUnknown);

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

// ---------------------------------------------------------------------------
// ConditionRefresh (Part 9 §5.5.7) / ConditionRefresh2 (§5.5.8) — A&C subscriber
// end-to-end. Independent of the implementation; anchored to the spec behavior:
// a refresh delivers RefreshStartEvent (i=2787) -> the current event of every
// retained condition -> RefreshEndEvent (i=2788), to the requesting subscription.
// ---------------------------------------------------------------------------

const REFRESH_START_EVENT_TYPE: u32 = 2787;
const REFRESH_END_EVENT_TYPE: u32 = 2788;

fn make_event_source(nm: &SimpleNodeManager, id: &str) -> NodeId {
    let source_node_id = NodeId::new(2, id);
    let mut space = nm.address_space().write();
    let source = opcua::server::address_space::ObjectBuilder::new(&source_node_id, id, id)
        .component_of(ObjectId::ObjectsFolder)
        .event_notifier(opcua::server::address_space::EventNotifier::SUBSCRIBE_TO_EVENTS)
        .build();
    space.insert::<_, NodeId>(source, None);
    source_node_id
}

async fn add_event_item(session: &opcua_client::Session, sub_id: u32, source: &NodeId) -> u32 {
    let res = session
        .create_monitored_items(
            sub_id,
            TimestampsToReturn::Both,
            vec![MonitoredItemCreateRequest {
                item_to_monitor: ReadValueId {
                    node_id: source.clone(),
                    attribute_id: AttributeId::EventNotifier as u32,
                    ..Default::default()
                },
                monitoring_mode: MonitoringMode::Reporting,
                requested_parameters: MonitoringParameters {
                    sampling_interval: 0.0,
                    queue_size: 100,
                    discard_oldest: true,
                    filter: ExtensionObject::new(EventFilter {
                        select_clauses: Some(get_alarm_event_select_clauses()),
                        where_clause: opcua_types::ContentFilter::default(),
                    }),
                    ..Default::default()
                },
            }],
        )
        .await
        .unwrap();
    assert_eq!(res[0].result.status_code, StatusCode::Good);
    res[0].result.monitored_item_id
}

/// Drain events until the RefreshEndEvent marker, returning every parsed event in order
/// together with the ReadValueId identifying which monitored item received it.
async fn collect_until_refresh_end(
    events: &mut tokio::sync::mpsc::UnboundedReceiver<(ReadValueId, Option<Vec<Variant>>)>,
) -> Vec<(ReadValueId, AlarmEvent)> {
    let mut out = Vec::new();
    loop {
        let (rvid, fields) = timeout(Duration::from_secs(3), events.recv())
            .await
            .expect("timed out waiting for refresh burst")
            .expect("event channel closed");
        let parsed =
            parse_alarm_event(&fields.expect("event without fields")).expect("parse event");
        let is_end = parsed.event_type == NodeId::new(0, REFRESH_END_EVENT_TYPE);
        out.push((rvid, parsed));
        if is_end {
            break;
        }
    }
    out
}

fn is_marker(e: &AlarmEvent) -> bool {
    e.event_type == NodeId::new(0, REFRESH_START_EVENT_TYPE)
        || e.event_type == NodeId::new(0, REFRESH_END_EVENT_TYPE)
}

/// The key proof: a client that subscribes AFTER an alarm is already active still learns about it,
/// because ConditionRefresh replays the retained condition. No broadcast is done before subscribing.
#[tokio::test]
async fn condition_refresh_delivers_retained_alarm_to_late_subscriber() {
    let (tester, nm, session) = setup_alarms().await;
    let core_nm = tester
        .handle
        .node_managers()
        .get_of_type::<CoreNodeManager>()
        .expect("CoreNodeManager not found");
    let source = make_event_source(&nm, "RefreshDevice");
    let sm = register_alarm_condition(
        nm.address_space(),
        &nm,
        "RefDev",
        "Temp",
        source.clone(),
        "alarm",
    );

    let registry = ConditionRegistry::new();
    registry.register(sm.clone());
    register_condition_methods(&core_nm, registry, nm.address_space().clone());

    // Alarm becomes Active BEFORE the client subscribes, and we deliberately do NOT broadcast it.
    {
        let mut space = nm.address_space().write();
        trigger_alarm_transition(&mut space, &sm, true, 700, LocalizedText::new("en", "high"))
            .unwrap()
            .expect("transition should produce an event");
    }
    {
        let space = nm.address_space().read();
        assert!(
            sm.get_retain(&space),
            "an active condition must be retained"
        );
    }

    let (notifs, _dv, mut events) = ChannelNotifications::new();
    let sub_id = session
        .create_subscription(Duration::from_millis(100), 100, 20, 1000, 0, true, notifs)
        .await
        .unwrap();
    let _item = add_event_item(&session, sub_id, &source).await;

    // Late subscriber catches up via ConditionRefresh.
    session
        .refresh_conditions(sub_id)
        .await
        .expect("refresh_conditions should succeed");

    let burst = collect_until_refresh_end(&mut events).await;
    assert_eq!(
        burst.first().unwrap().1.event_type,
        NodeId::new(0, REFRESH_START_EVENT_TYPE),
        "first event must be RefreshStart"
    );
    assert_eq!(
        burst.last().unwrap().1.event_type,
        NodeId::new(0, REFRESH_END_EVENT_TYPE),
        "last event must be RefreshEnd"
    );
    let cond = burst
        .iter()
        .find(|(_, e)| !is_marker(e))
        .expect("the retained condition must be replayed between the markers");
    assert!(cond.1.active_state, "replayed condition should be active");
    assert_eq!(
        cond.1.severity, 700,
        "replayed condition keeps its severity"
    );
}

/// ConditionRefresh2 delivers the burst to ONE monitored item, not the whole subscription.
#[tokio::test]
async fn condition_refresh2_targets_a_single_monitored_item() {
    let (tester, nm, session) = setup_alarms().await;
    let core_nm = tester
        .handle
        .node_managers()
        .get_of_type::<CoreNodeManager>()
        .expect("CoreNodeManager not found");
    let source_a = make_event_source(&nm, "Dev2A");
    let source_b = make_event_source(&nm, "Dev2B");
    let sm = register_alarm_condition(
        nm.address_space(),
        &nm,
        "Dev2A",
        "Temp",
        source_a.clone(),
        "alarm",
    );
    let registry = ConditionRegistry::new();
    registry.register(sm.clone());
    register_condition_methods(&core_nm, registry, nm.address_space().clone());

    {
        let mut space = nm.address_space().write();
        trigger_alarm_transition(&mut space, &sm, true, 500, LocalizedText::new("en", "a"))
            .unwrap()
            .expect("transition event");
    }

    let (notifs, _dv, mut events) = ChannelNotifications::new();
    let sub_id = session
        .create_subscription(Duration::from_millis(100), 100, 20, 1000, 0, true, notifs)
        .await
        .unwrap();
    let _item_a = add_event_item(&session, sub_id, &source_a).await;
    let item_b = add_event_item(&session, sub_id, &source_b).await;

    session
        .refresh_conditions_for_item(sub_id, item_b)
        .await
        .expect("refresh_conditions_for_item should succeed");

    let burst = collect_until_refresh_end(&mut events).await;
    assert!(
        burst.iter().any(|(_, e)| !is_marker(e)),
        "the retained condition should be replayed"
    );
    for (rvid, _e) in &burst {
        assert_eq!(
            rvid.node_id, source_b,
            "ConditionRefresh2 must deliver only to the targeted monitored item (source B)"
        );
    }
}

/// An unknown SubscriptionId is rejected per Part 9 §5.5.7.
#[tokio::test]
async fn condition_refresh_rejects_unknown_subscription() {
    let (tester, nm, session) = setup_alarms().await;
    let core_nm = tester
        .handle
        .node_managers()
        .get_of_type::<CoreNodeManager>()
        .expect("CoreNodeManager not found");
    register_condition_methods(
        &core_nm,
        ConditionRegistry::new(),
        nm.address_space().clone(),
    );

    let resp = session
        .call_one(CallMethodRequest {
            object_id: ObjectTypeId::ConditionType.into(),
            method_id: MethodId::ConditionType_ConditionRefresh.into(),
            input_arguments: Some(vec![Variant::from(999_999u32)]),
        })
        .await
        .unwrap();
    assert_eq!(resp.status_code, StatusCode::BadSubscriptionIdInvalid);
}

/// With no retained conditions, refresh still brackets an (empty) burst with Start/End markers,
/// so the client learns "nothing currently retained".
#[tokio::test]
async fn condition_refresh_with_no_retained_conditions_is_empty() {
    let (tester, nm, session) = setup_alarms().await;
    let core_nm = tester
        .handle
        .node_managers()
        .get_of_type::<CoreNodeManager>()
        .expect("CoreNodeManager not found");
    let source = make_event_source(&nm, "QuietDevice");
    // Empty registry: no conditions to replay, so the burst is just the Start/End brackets.
    register_condition_methods(
        &core_nm,
        ConditionRegistry::new(),
        nm.address_space().clone(),
    );

    let (notifs, _dv, mut events) = ChannelNotifications::new();
    let sub_id = session
        .create_subscription(Duration::from_millis(100), 100, 20, 1000, 0, true, notifs)
        .await
        .unwrap();
    let _item = add_event_item(&session, sub_id, &source).await;

    session.refresh_conditions(sub_id).await.expect("refresh");

    let burst = collect_until_refresh_end(&mut events).await;
    assert_eq!(burst.len(), 2, "only RefreshStart + RefreshEnd expected");
    assert_eq!(
        burst[0].1.event_type,
        NodeId::new(0, REFRESH_START_EVENT_TYPE)
    );
    assert_eq!(
        burst[1].1.event_type,
        NodeId::new(0, REFRESH_END_EVENT_TYPE)
    );
}

/// The thin client helpers acknowledge_condition / confirm_condition drive the same transitions
/// as the raw Call path.
#[tokio::test]
async fn alarm_client_helpers_acknowledge_and_confirm() {
    let (tester, nm, session) = setup_alarms().await;
    let core_nm = tester
        .handle
        .node_managers()
        .get_of_type::<CoreNodeManager>()
        .expect("CoreNodeManager not found");
    let source = make_event_source(&nm, "HelperDevice");
    let sm = register_alarm_condition(
        nm.address_space(),
        &nm,
        "Helper",
        "Temp",
        source.clone(),
        "alarm",
    );
    // Wire the standard ns0 Acknowledge/Confirm (i=9111/i=9113) on the core node manager so the thin
    // client helpers (which call the standard type method ids) resolve this condition by object id.
    let registry = ConditionRegistry::new();
    registry.register(sm.clone());
    register_condition_methods(&core_nm, registry, nm.address_space().clone());

    let (notifs, _dv, mut events) = ChannelNotifications::new();
    let sub_id = session
        .create_subscription(Duration::from_millis(100), 100, 20, 1000, 0, true, notifs)
        .await
        .unwrap();
    let _item = add_event_item(&session, sub_id, &source).await;

    let event = {
        let mut space = nm.address_space().write();
        trigger_alarm_transition(&mut space, &sm, true, 600, LocalizedText::new("en", "x"))
            .unwrap()
            .expect("transition event")
    };
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

    let (_r, v) = timeout(Duration::from_secs(2), events.recv())
        .await
        .unwrap()
        .unwrap();
    let ae = parse_alarm_event(&v.unwrap()).unwrap();

    session
        .acknowledge_condition(
            &sm.condition_id,
            ByteString::from(ae.event_id.clone()),
            LocalizedText::new("en", "ack via helper"),
        )
        .await
        .expect("acknowledge_condition should succeed");
    {
        let space = nm.address_space().read();
        assert!(sm.get_acked(&space), "helper should have acknowledged");
    }

    let (_r2, v2) = timeout(Duration::from_secs(2), events.recv())
        .await
        .unwrap()
        .unwrap();
    let ack = parse_alarm_event(&v2.unwrap()).unwrap();

    session
        .confirm_condition(
            &sm.condition_id,
            ByteString::from(ack.event_id.clone()),
            LocalizedText::new("en", "confirm via helper"),
        )
        .await
        .expect("confirm_condition should succeed");
    {
        let space = nm.address_space().read();
        assert!(sm.get_confirmed(&space), "helper should have confirmed");
    }
}

// ---------------------------------------------------------------------------
// Process limit alarms (Part 9 §5.8.18–§5.8.20) — ExclusiveLimitAlarmType /
// NonExclusiveLimitAlarmType driven from a value via update_value, composing the
// existing condition lifecycle. The pure threshold/deadband logic is covered by
// async-opcua-server/tests/limit_evaluator.rs; these assert the end-to-end wiring.
// ---------------------------------------------------------------------------

/// Apply a new process value to a limit alarm and dispatch the resulting condition event (if any),
/// the same way an application would.
fn drive_limit(alarm: &LimitAlarm, nm: &SimpleNodeManager, tester: &Tester, value: f64) {
    let event = {
        let mut space = nm.address_space().write();
        alarm.update_value(&mut space, value)
    };
    if let Some(ev) = event {
        let wrapper = opcua::server::alarms::ServerAlarmEvent { event: &ev };
        tester
            .handle
            .subscriptions()
            .notify_events(std::iter::once((
                &wrapper as &dyn opcua::nodes::Event,
                &ev.source_node,
            )));
    }
}

async fn recv_alarm(
    events: &mut tokio::sync::mpsc::UnboundedReceiver<(ReadValueId, Option<Vec<Variant>>)>,
) -> AlarmEvent {
    let (_r, v) = timeout(Duration::from_secs(2), events.recv())
        .await
        .expect("timed out waiting for a condition event")
        .expect("event channel closed");
    parse_alarm_event(&v.expect("event without fields")).expect("parse alarm event")
}

/// Resolve a browse path from `start` (all hierarchical, ns0 names) and read the target's Value.
async fn read_value_via_path(
    session: &opcua_client::Session,
    start: &NodeId,
    names: &[&str],
) -> Option<Variant> {
    let elements = names
        .iter()
        .map(|n| RelativePathElement {
            reference_type_id: ReferenceTypeId::HierarchicalReferences.into(),
            is_inverse: false,
            include_subtypes: true,
            target_name: QualifiedName::new(0, *n),
        })
        .collect();
    let r = session
        .translate_browse_paths_to_node_ids(&[BrowsePath {
            starting_node: start.clone(),
            relative_path: RelativePath {
                elements: Some(elements),
            },
        }])
        .await
        .unwrap();
    let targets = r[0].targets.clone().unwrap_or_default();
    assert!(
        !targets.is_empty(),
        "browse path {names:?} resolved to nothing"
    );
    let node_id = targets[0].target_id.node_id.clone();
    let dvs = session
        .read(
            &[ReadValueId {
                node_id,
                attribute_id: AttributeId::Value as u32,
                ..Default::default()
            }],
            TimestampsToReturn::Neither,
            0.0,
        )
        .await
        .unwrap();
    dvs[0].value.clone()
}

fn exclusive_level_cfg() -> LimitConfig {
    LimitConfig::new(LimitMode::Exclusive)
        .with_high(LimitDef {
            value: 100.0,
            deadband: 5.0,
            severity: 400,
        })
        .with_high_high(LimitDef {
            value: 110.0,
            deadband: 5.0,
            severity: 700,
        })
        .build()
        .expect("valid config")
}

/// Exclusive limit alarm: bands drive the condition event severity, the LimitState exposes the
/// active state, and Acknowledge (via the standard type method) works on it.
#[tokio::test]
async fn limit_alarm_exclusive_drives_bands_acks_and_exposes_limit_state() {
    let (tester, nm, session) = setup_alarms().await;
    let core_nm = tester
        .handle
        .node_managers()
        .get_of_type::<CoreNodeManager>()
        .expect("CoreNodeManager not found");
    let source = make_event_source(&nm, "LevelSensor");
    let alarm = register_limit_alarm(
        nm.address_space(),
        &nm,
        "Tank",
        "Level",
        source.clone(),
        exclusive_level_cfg(),
    );
    let condition_id = alarm.condition_state_machine().condition_id.clone();
    let registry = ConditionRegistry::new();
    registry.register(alarm.condition_state_machine());
    register_condition_methods(&core_nm, registry, nm.address_space().clone());

    let (notifs, _dv, mut events) = ChannelNotifications::new();
    let sub_id = session
        .create_subscription(Duration::from_millis(100), 100, 20, 1000, 0, true, notifs)
        .await
        .unwrap();
    let _item = add_event_item(&session, sub_id, &source).await;

    // High band -> severity 400.
    drive_limit(&alarm, &nm, &tester, 105.0);
    let e = recv_alarm(&mut events).await;
    assert!(e.active_state);
    assert_eq!(e.severity, 400);

    // Escalate to HighHigh -> severity 700.
    drive_limit(&alarm, &nm, &tester, 115.0);
    let e = recv_alarm(&mut events).await;
    assert!(e.active_state);
    assert_eq!(e.severity, 700);

    // The exclusive LimitState exposes the active sub-state (HighHigh = i=9329).
    match read_value_via_path(
        &session,
        &condition_id,
        &["LimitState", "CurrentState", "Id"],
    )
    .await
    {
        Some(Variant::NodeId(n)) => assert_eq!(*n, NodeId::new(0, 9329)),
        other => panic!("LimitState.CurrentState.Id = {other:?}, expected HighHigh (9329)"),
    }

    // Acknowledge the active limit alarm via the standard type method.
    session
        .acknowledge_condition(
            &condition_id,
            ByteString::from(e.event_id.clone()),
            LocalizedText::new("en", "ack limit alarm"),
        )
        .await
        .expect("acknowledge_condition on a limit alarm should succeed");
    {
        let space = nm.address_space().read();
        assert!(
            alarm.condition_state_machine().get_acked(&space),
            "limit alarm should be acknowledged"
        );
    }
    // Acknowledge dispatches its own (still-active, now-acked) event; consume it.
    let ack_ev = recv_alarm(&mut events).await;
    assert!(ack_ev.active_state && ack_ev.acked_state);

    // Return to normal -> inactive.
    drive_limit(&alarm, &nm, &tester, 50.0);
    let e = recv_alarm(&mut events).await;
    assert!(!e.active_state, "value back in range clears the alarm");
}

/// NonExclusive limit alarm: above HighHigh, BOTH HighHighState and HighState read active.
#[tokio::test]
async fn limit_alarm_non_exclusive_activates_independent_states() {
    let (tester, nm, session) = setup_alarms().await;
    let core_nm = tester
        .handle
        .node_managers()
        .get_of_type::<CoreNodeManager>()
        .expect("CoreNodeManager not found");
    let source = make_event_source(&nm, "PressureSensor");
    let cfg = LimitConfig::new(LimitMode::NonExclusive)
        .with_high(LimitDef {
            value: 100.0,
            deadband: 5.0,
            severity: 400,
        })
        .with_high_high(LimitDef {
            value: 110.0,
            deadband: 5.0,
            severity: 700,
        })
        .build()
        .expect("valid config");
    let alarm = register_limit_alarm(
        nm.address_space(),
        &nm,
        "Vat",
        "Pressure",
        source.clone(),
        cfg,
    );
    let condition_id = alarm.condition_state_machine().condition_id.clone();
    let registry = ConditionRegistry::new();
    registry.register(alarm.condition_state_machine());
    register_condition_methods(&core_nm, registry, nm.address_space().clone());

    let (notifs, _dv, mut events) = ChannelNotifications::new();
    let sub_id = session
        .create_subscription(Duration::from_millis(100), 100, 20, 1000, 0, true, notifs)
        .await
        .unwrap();
    let _item = add_event_item(&session, sub_id, &source).await;

    drive_limit(&alarm, &nm, &tester, 115.0);
    let e = recv_alarm(&mut events).await;
    assert!(e.active_state);
    assert_eq!(
        e.severity, 700,
        "non-exclusive severity is the highest active limit"
    );

    // Both High and HighHigh states are active simultaneously.
    match read_value_via_path(&session, &condition_id, &["HighHighState", "Id"]).await {
        Some(Variant::Boolean(b)) => assert!(b, "HighHighState should be active"),
        other => panic!("HighHighState.Id = {other:?}"),
    }
    match read_value_via_path(&session, &condition_id, &["HighState", "Id"]).await {
        Some(Variant::Boolean(b)) => assert!(b, "HighState should also be active"),
        other => panic!("HighState.Id = {other:?}"),
    }
}

/// A late subscriber learns about an already-active limit alarm via ConditionRefresh.
#[tokio::test]
async fn limit_alarm_conditionrefresh_replays_active_limit() {
    let (tester, nm, session) = setup_alarms().await;
    let core_nm = tester
        .handle
        .node_managers()
        .get_of_type::<CoreNodeManager>()
        .expect("CoreNodeManager not found");
    let source = make_event_source(&nm, "FlowSensor");
    let alarm = register_limit_alarm(
        nm.address_space(),
        &nm,
        "Line",
        "Flow",
        source.clone(),
        exclusive_level_cfg(),
    );
    let registry = ConditionRegistry::new();
    registry.register(alarm.condition_state_machine());
    register_condition_methods(&core_nm, registry, nm.address_space().clone());

    // Drive into the HighHigh band BEFORE subscribing, without broadcasting.
    {
        let mut space = nm.address_space().write();
        let _ = alarm.update_value(&mut space, 115.0);
    }

    let (notifs, _dv, mut events) = ChannelNotifications::new();
    let sub_id = session
        .create_subscription(Duration::from_millis(100), 100, 20, 1000, 0, true, notifs)
        .await
        .unwrap();
    let _item = add_event_item(&session, sub_id, &source).await;

    session
        .refresh_conditions(sub_id)
        .await
        .expect("refresh_conditions should succeed");

    let burst = collect_until_refresh_end(&mut events).await;
    let cond = burst
        .iter()
        .find(|(_, e)| !is_marker(e))
        .expect("the retained limit alarm must be replayed");
    assert!(cond.1.active_state);
    assert_eq!(
        cond.1.severity, 700,
        "replayed limit alarm keeps its HighHigh severity"
    );
}

// ---------------------------------------------------------------------------
// Measurement (not a CI gate): how long does ConditionRefresh hold the per-session
// subscription lock while it replays N retained conditions? This sizes the
// "lock-held-over-unbounded-work" invariant before choosing a fix.
// Run with: cargo test -p async-opcua --test integration_tests
//   bench_condition_refresh_lock_hold -- --ignored --nocapture
// ---------------------------------------------------------------------------
#[tokio::test]
#[ignore = "perf measurement; run manually with --ignored --nocapture"]
async fn bench_condition_refresh_lock_hold_scaling() {
    println!("\n--- ConditionRefresh server-side cost vs retained-condition count ---");
    for &n in &[100usize, 500, 1000, 2000] {
        let (tester, nm, session) = setup_alarms().await;
        let core_nm = tester
            .handle
            .node_managers()
            .get_of_type::<CoreNodeManager>()
            .expect("CoreNodeManager not found");
        let source = make_event_source(&nm, "BenchSource");

        // Register N active (retained) conditions.
        let registry = ConditionRegistry::new();
        for i in 0..n {
            let sm = register_alarm_condition(
                nm.address_space(),
                &nm,
                "Bench",
                &format!("C{i}"),
                source.clone(),
                "bench alarm",
            );
            {
                let mut space = nm.address_space().write();
                trigger_alarm_transition(&mut space, &sm, true, 500, LocalizedText::new("en", "x"))
                    .unwrap();
            }
            registry.register(sm);
        }
        register_condition_methods(&core_nm, registry, nm.address_space().clone());

        let (notifs, _dv, mut events) = ChannelNotifications::new();
        let sub_id = session
            .create_subscription(Duration::from_millis(100), 100, 20, 5000, 0, true, notifs)
            .await
            .unwrap();
        let _item = add_event_item(&session, sub_id, &source).await;

        // The Call does not return until the server-side refresh (build + deliver under the
        // per-session lock) completes, so this end-to-end time is dominated by the lock-held work.
        let t0 = Instant::now();
        session.refresh_conditions(sub_id).await.unwrap();
        let elapsed = t0.elapsed();

        // Drain the burst so it doesn't bleed into the next iteration.
        let _ = timeout(
            Duration::from_secs(5),
            collect_until_refresh_end(&mut events),
        )
        .await;

        println!(
            "N={n:>5} retained conditions -> refresh_conditions {:>8.2?}  ({:>6.1} us/condition)",
            elapsed,
            elapsed.as_micros() as f64 / n as f64
        );
    }
    println!("--- end ---\n");
}

// ---------------------------------------------------------------------------
// AC1: DiscreteAlarm / OffNormalAlarm — active when the value deviates from the
// configured normal state, composing the same condition lifecycle as limit alarms.
// ---------------------------------------------------------------------------

/// Apply a discrete value to an OffNormal/Trip alarm and dispatch the resulting event (if any).
fn drive_discrete(alarm: &DiscreteAlarm, nm: &SimpleNodeManager, tester: &Tester, value: Variant) {
    let event = {
        let mut space = nm.address_space().write();
        alarm.update_value(&mut space, value)
    };
    if let Some(ev) = event {
        let wrapper = opcua::server::alarms::ServerAlarmEvent { event: &ev };
        tester
            .handle
            .subscriptions()
            .notify_events(std::iter::once((
                &wrapper as &dyn opcua::nodes::Event,
                &ev.source_node,
            )));
    }
}

#[tokio::test]
async fn offnormal_alarm_activates_off_normal_and_acks() {
    let (tester, nm, session) = setup_alarms().await;
    let core_nm = tester
        .handle
        .node_managers()
        .get_of_type::<CoreNodeManager>()
        .expect("CoreNodeManager not found");
    let source = make_event_source(&nm, "Pump");
    // Normal state = false (e.g. "not tripped").
    let alarm = register_discrete_alarm(
        nm.address_space(),
        &nm,
        "Pump",
        "State",
        source.clone(),
        DiscreteAlarmKind::OffNormal,
        Variant::Boolean(false),
    );
    let condition_id = alarm.condition_state_machine().condition_id.clone();
    let registry = ConditionRegistry::new();
    registry.register(alarm.condition_state_machine());
    register_condition_methods(&core_nm, registry, nm.address_space().clone());

    let (notifs, _dv, mut events) = ChannelNotifications::new();
    let sub_id = session
        .create_subscription(Duration::from_millis(100), 100, 20, 1000, 0, true, notifs)
        .await
        .unwrap();
    let _item = add_event_item(&session, sub_id, &source).await;

    // Deviate from normal -> Active, typed as OffNormalAlarmType (i=10637).
    drive_discrete(&alarm, &nm, &tester, Variant::Boolean(true));
    let e = recv_alarm(&mut events).await;
    assert!(e.active_state, "off-normal value should activate the alarm");
    assert!(!e.acked_state);
    assert_eq!(e.event_type, NodeId::new(0, 10637));
    assert!(e.severity > 0);

    // Acknowledge via the standard type method.
    session
        .acknowledge_condition(
            &condition_id,
            ByteString::from(e.event_id.clone()),
            LocalizedText::new("en", "ack off-normal"),
        )
        .await
        .expect("acknowledge_condition on an off-normal alarm should succeed");
    let ack_ev = recv_alarm(&mut events).await;
    assert!(ack_ev.active_state && ack_ev.acked_state);

    // Return to normal -> Inactive.
    drive_discrete(&alarm, &nm, &tester, Variant::Boolean(false));
    let e = recv_alarm(&mut events).await;
    assert!(!e.active_state, "value back to normal clears the alarm");
}

// ---------------------------------------------------------------------------
// AC2: ShelvedStateMachine — operator shelving via Call methods, and the
// SuppressedOrShelved gating flag (Part 9 §5.8.17 / §5.8.2).
// ---------------------------------------------------------------------------

async fn call_shelve(
    session: &opcua_client::Session,
    shelving_id: &NodeId,
    method: MethodId,
    args: Option<Vec<Variant>>,
) -> StatusCode {
    session
        .call_one(CallMethodRequest {
            object_id: shelving_id.clone(),
            method_id: method.into(),
            input_arguments: args,
        })
        .await
        .unwrap()
        .status_code
}

#[tokio::test]
async fn shelving_transitions_and_suppressed_or_shelved() {
    let (tester, nm, session) = setup_alarms().await;
    let core_nm = tester
        .handle
        .node_managers()
        .get_of_type::<CoreNodeManager>()
        .expect("CoreNodeManager not found");
    let source = make_event_source(&nm, "Dev");
    let sm = register_alarm_condition(nm.address_space(), &nm, "Dev", "Temp", source, "Temp alarm");
    let registry = ConditionRegistry::new();
    registry.register(sm.clone());
    register_condition_methods(&core_nm, registry, nm.address_space().clone());
    let shelving_id = sm.shelving_state_id.clone();

    let state = |sm: &opcua_server::alarms::ConditionStateMachine| {
        let space = nm.address_space().read();
        (
            sm.get_shelving_state(&space),
            sm.get_suppressed_or_shelved(&space),
        )
    };

    // Initially Unshelved; Unshelve is invalid -> BadConditionNotShelved.
    assert_eq!(state(&sm), (ShelvingState::Unshelved, false));
    assert_eq!(
        call_shelve(
            &session,
            &shelving_id,
            MethodId::ShelvedStateMachineType_Unshelve,
            None
        )
        .await,
        StatusCode::BadConditionNotShelved
    );

    // OneShotShelve -> Good; state OneShotShelved; SuppressedOrShelved = true.
    assert_eq!(
        call_shelve(
            &session,
            &shelving_id,
            MethodId::ShelvedStateMachineType_OneShotShelve,
            None
        )
        .await,
        StatusCode::Good
    );
    assert_eq!(state(&sm), (ShelvingState::OneShotShelved, true));

    // OneShotShelve again -> BadConditionAlreadyShelved.
    assert_eq!(
        call_shelve(
            &session,
            &shelving_id,
            MethodId::ShelvedStateMachineType_OneShotShelve,
            None
        )
        .await,
        StatusCode::BadConditionAlreadyShelved
    );

    // TimedShelve with a valid duration -> Good; state TimedShelved.
    assert_eq!(
        call_shelve(
            &session,
            &shelving_id,
            MethodId::ShelvedStateMachineType_TimedShelve,
            Some(vec![Variant::Double(5_000.0)]),
        )
        .await,
        StatusCode::Good
    );
    assert_eq!(state(&sm).0, ShelvingState::TimedShelved);

    // Unshelve -> Good; back to Unshelved; SuppressedOrShelved clears.
    assert_eq!(
        call_shelve(
            &session,
            &shelving_id,
            MethodId::ShelvedStateMachineType_Unshelve,
            None
        )
        .await,
        StatusCode::Good
    );
    assert_eq!(state(&sm), (ShelvingState::Unshelved, false));
}

// ---------------------------------------------------------------------------
// AC3: condition branching (Part 9 §5.5 / §B.1.3) — an Active+Unacked condition
// that deactivates spawns a branch preserving the unacked state, which is
// replayed by ConditionRefresh and acknowledged/confirmed by its own EventId.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn condition_branch_preserves_unacked_state_and_resolves_independently() {
    let (tester, nm, session) = setup_alarms().await;
    let core_nm = tester
        .handle
        .node_managers()
        .get_of_type::<CoreNodeManager>()
        .expect("CoreNodeManager not found");
    let source = make_event_source(&nm, "Branchy");
    let alarm = register_discrete_alarm(
        nm.address_space(),
        &nm,
        "Branchy",
        "State",
        source.clone(),
        DiscreteAlarmKind::OffNormal,
        Variant::Boolean(false),
    );
    let sm = alarm.condition_state_machine();
    let registry = ConditionRegistry::new();
    registry.register(sm.clone());
    register_condition_methods(&core_nm, registry, nm.address_space().clone());

    let (notifs, _dv, mut events) = ChannelNotifications::new();
    let sub_id = session
        .create_subscription(Duration::from_millis(100), 100, 20, 1000, 0, true, notifs)
        .await
        .unwrap();
    let _item = add_event_item(&session, sub_id, &source).await;

    // Active (and left unacknowledged).
    drive_discrete(&alarm, &nm, &tester, Variant::Boolean(true));
    let active = recv_alarm(&mut events).await;
    assert!(active.active_state && !active.acked_state);

    // Deactivate while still unacked -> a branch preserves the prior active-unacked state.
    drive_discrete(&alarm, &nm, &tester, Variant::Boolean(false));
    let _trunk_inactive = recv_alarm(&mut events).await;

    let branch = {
        let branches = sm.retained_branches();
        assert_eq!(
            branches.len(),
            1,
            "a branch should preserve the unacked activation"
        );
        assert!(
            branches[0].active && !branches[0].acked,
            "branch holds the active, unacked state"
        );
        branches[0].clone()
    };

    // ConditionRefresh replays BOTH the inactive trunk and the active branch.
    session
        .refresh_conditions(sub_id)
        .await
        .expect("refresh_conditions should succeed");
    let burst = collect_until_refresh_end(&mut events).await;
    let body: Vec<&AlarmEvent> = burst
        .iter()
        .map(|(_, e)| e)
        .filter(|e| {
            e.event_type != NodeId::new(0, REFRESH_START_EVENT_TYPE)
                && e.event_type != NodeId::new(0, REFRESH_END_EVENT_TYPE)
        })
        .collect();
    assert!(
        body.iter().any(|e| e.active_state),
        "branch (active) replayed"
    );
    assert!(
        body.iter().any(|e| !e.active_state),
        "trunk (inactive) replayed"
    );

    // Acknowledge the BRANCH by its own EventId -> acked, still retained (unconfirmed).
    session
        .acknowledge_condition(
            &sm.condition_id,
            ByteString::from(branch.event_id.clone()),
            LocalizedText::new("en", "ack branch"),
        )
        .await
        .expect("acknowledge of a branch should succeed");
    {
        let b = sm.retained_branches();
        assert_eq!(b.len(), 1);
        assert!(b[0].acked && !b[0].confirmed);
    }

    // Confirm the branch -> fully resolved -> dropped.
    let confirm = session
        .call_one(CallMethodRequest {
            object_id: sm.condition_id.clone(),
            method_id: MethodId::AcknowledgeableConditionType_Confirm.into(),
            input_arguments: Some(vec![
                Variant::from(ByteString::from(branch.event_id.clone())),
                Variant::from(LocalizedText::new("en", "confirm branch")),
            ]),
        })
        .await
        .unwrap();
    assert_eq!(confirm.status_code, StatusCode::Good);
    assert!(
        sm.retained_branches().is_empty(),
        "a fully acked+confirmed branch is dropped"
    );
}

// ---------------------------------------------------------------------------
// AC4: limit alarms validated against the source AnalogItem's EURange
// (Part 8 §5.3.2.3 EURange / Part 9 §5.8.18 LimitAlarmType).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn limit_alarm_validates_against_analog_item_eurange() {
    let (_tester, nm, _session) = setup_alarms().await;

    // An AnalogItem source variable with EURange [0, 100].
    let source_id = NodeId::new(2, "AnalogSrc");
    {
        use opcua::server::address_space::{ReferenceDirection, VariableBuilder};
        let mut space = nm.address_space().write();
        let src = VariableBuilder::new(&source_id, "AnalogSrc", "AnalogSrc")
            .data_type(DataTypeId::Double)
            .has_type_definition(VariableTypeId::AnalogItemType)
            .build();
        space.insert::<_, NodeId>(src, None);

        let eurange_id = NodeId::new(2, "AnalogSrc_EURange");
        let eurange = VariableBuilder::new(&eurange_id, "EURange", "EURange")
            .data_type(DataTypeId::Range)
            .value(Variant::from(ExtensionObject::new(Range {
                low: 0.0,
                high: 100.0,
            })))
            .build();
        space.insert(
            eurange,
            Some(&[(&source_id, &NodeId::new(0, 46), ReferenceDirection::Inverse)]),
        );
    }

    let within = LimitConfig::new(LimitMode::Exclusive)
        .with_high(LimitDef {
            value: 80.0,
            deadband: 1.0,
            severity: 400,
        })
        .with_high_high(LimitDef {
            value: 95.0,
            deadband: 1.0,
            severity: 700,
        });
    assert!(
        register_limit_alarm_checked(
            nm.address_space(),
            &nm,
            "Tank",
            "Level",
            source_id.clone(),
            within
        )
        .is_ok(),
        "limits inside EURange [0,100] should register"
    );

    let out_of_range = LimitConfig::new(LimitMode::Exclusive).with_high_high(LimitDef {
        value: 150.0, // > EURange high 100
        deadband: 1.0,
        severity: 700,
    });
    assert_eq!(
        register_limit_alarm_checked(
            nm.address_space(),
            &nm,
            "Tank2",
            "Level2",
            source_id.clone(),
            out_of_range,
        )
        .unwrap_err(),
        StatusCode::BadOutOfRange,
        "a limit above EURange high must be rejected"
    );
}

/// Part 9 §5.5.2 AddComment: adds a comment to the condition and REPORTS a new event carrying that
/// comment WITHOUT changing AckedState/ActiveState/ConfirmedState; an unknown EventId is rejected.
#[tokio::test]
async fn alarm_add_comment_reports_without_state_change() {
    let (tester, nm, session) = setup_alarms().await;

    let source_node_id = NodeId::new(2, "CommentDevice");
    {
        let mut space = nm.address_space().write();
        let source_node = opcua::server::address_space::ObjectBuilder::new(
            &source_node_id,
            "CommentDevice",
            "CommentDevice",
        )
        .component_of(ObjectId::ObjectsFolder)
        .event_notifier(opcua::server::address_space::EventNotifier::SUBSCRIBE_TO_EVENTS)
        .build();
        space.insert::<_, NodeId>(source_node, None);
    }

    let core_nm = tester
        .handle
        .node_managers()
        .get_of_type::<CoreNodeManager>()
        .expect("CoreNodeManager not found");
    let state_machine = register_alarm_condition(
        nm.address_space(),
        &nm,
        "Device1",
        "Temperature",
        source_node_id.clone(),
        "Temperature alarm",
    );
    let registry = ConditionRegistry::new();
    registry.register(state_machine.clone());
    register_condition_methods(&core_nm, registry, nm.address_space().clone());

    let (notifs, _, mut events) = ChannelNotifications::new();
    let sub_id = session
        .create_subscription(Duration::from_millis(100), 100, 20, 1000, 0, true, notifs)
        .await
        .unwrap();
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
                        select_clauses: Some(get_alarm_event_select_clauses()),
                        where_clause: opcua_types::ContentFilter::default(),
                    }),
                    ..Default::default()
                },
            }],
        )
        .await
        .unwrap();

    // Trigger Active (unacknowledged).
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
        .expect("transition event")
    };
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
    let (_r1, v1) = timeout(Duration::from_secs(2), events.recv())
        .await
        .unwrap()
        .unwrap();
    let active = parse_alarm_event(&v1.unwrap()).expect("active event");
    assert!(active.active_state && !active.acked_state);

    // An unknown EventId is rejected before anything is reported.
    let bogus = session
        .call_one(CallMethodRequest {
            object_id: state_machine.condition_id.clone(),
            method_id: MethodId::ConditionType_AddComment.into(),
            input_arguments: Some(vec![
                Variant::from(opcua::types::ByteString::from(vec![0xDE, 0xAD])),
                Variant::from(LocalizedText::new("en", "nope")),
            ]),
        })
        .await
        .unwrap();
    assert_eq!(bogus.status_code, StatusCode::BadEventIdUnknown);

    // AddComment on the current EventId succeeds.
    let response = session
        .call_one(CallMethodRequest {
            object_id: state_machine.condition_id.clone(),
            method_id: MethodId::ConditionType_AddComment.into(),
            input_arguments: Some(vec![
                Variant::from(opcua::types::ByteString::from(active.event_id.clone())),
                Variant::from(LocalizedText::new("en", "Operator note")),
            ]),
        })
        .await
        .unwrap();
    assert_eq!(response.status_code, StatusCode::Good);

    // The reported comment event carries the comment and does NOT change ack/confirm/active state.
    let (_r2, v2) = timeout(Duration::from_secs(2), events.recv())
        .await
        .unwrap()
        .unwrap();
    let comment_event = parse_alarm_event(&v2.unwrap()).expect("comment event");
    assert_eq!(comment_event.message.text.as_ref(), "Operator note");
    assert!(comment_event.active_state, "still active");
    assert!(
        !comment_event.acked_state,
        "AddComment must not acknowledge"
    );
    assert!(!comment_event.confirmed_state);

    // Server state is unchanged by AddComment.
    {
        let space = nm.address_space().read();
        assert!(
            !state_machine.get_acked(&space),
            "AddComment left acked unchanged"
        );
        assert!(state_machine.get_active(&space));
    }
}

/// Part 9 §5.6 DialogConditionType: an active dialog is ended by Respond (DialogState -> Inactive,
/// LastResponse recorded); Respond on an inactive dialog or with an out-of-range index is rejected.
#[tokio::test]
async fn dialog_condition_respond_ends_dialog_and_validates() {
    let (tester, nm, session) = setup_alarms().await;

    let source_node_id = NodeId::new(2, "DialogDevice");
    {
        let mut space = nm.address_space().write();
        let source_node = opcua::server::address_space::ObjectBuilder::new(
            &source_node_id,
            "DialogDevice",
            "DialogDevice",
        )
        .component_of(ObjectId::ObjectsFolder)
        .event_notifier(opcua::server::address_space::EventNotifier::SUBSCRIBE_TO_EVENTS)
        .build();
        space.insert::<_, NodeId>(source_node, None);
    }

    let core_nm = tester
        .handle
        .node_managers()
        .get_of_type::<CoreNodeManager>()
        .expect("CoreNodeManager not found");

    let dialog = {
        let mut space = nm.address_space().write();
        DialogCondition::create_in_address_space(
            &mut space,
            2,
            "Device1",
            "Restart",
            source_node_id.clone(),
            LocalizedText::new("en", "Restart the device?"),
            vec![
                LocalizedText::new("en", "Yes"),
                LocalizedText::new("en", "No"),
            ],
            1, // default response
            0, // ok response
            1, // cancel response
        )
    };
    let condition_id = dialog.condition_state_machine().condition_id.clone();

    let registry = DialogRegistry::new();
    registry.register(dialog.clone());
    register_dialog_condition_methods(&core_nm, registry, nm.address_space().clone());

    // Activate the dialog (it is shown to the operator).
    {
        let mut space = nm.address_space().write();
        let _ = dialog.activate(&mut space);
        assert!(
            dialog.get_dialog_state_active(&space),
            "dialog should be active after activate"
        );
    }

    // Respond with a valid option (index 0 = "Yes") ends the dialog.
    let resp = session
        .call_one(CallMethodRequest {
            object_id: condition_id.clone(),
            method_id: MethodId::DialogConditionType_Respond.into(),
            input_arguments: Some(vec![Variant::Int32(0)]),
        })
        .await
        .unwrap();
    assert_eq!(resp.status_code, StatusCode::Good);
    {
        let space = nm.address_space().read();
        assert!(
            !dialog.get_dialog_state_active(&space),
            "Respond must end the dialog"
        );
    }

    // Respond again on the now-inactive dialog -> BadDialogNotActive.
    let inactive = session
        .call_one(CallMethodRequest {
            object_id: condition_id.clone(),
            method_id: MethodId::DialogConditionType_Respond.into(),
            input_arguments: Some(vec![Variant::Int32(0)]),
        })
        .await
        .unwrap();
    assert_eq!(inactive.status_code, StatusCode::BadDialogNotActive);

    // Re-activate, then respond with an out-of-range index -> BadDialogResponseInvalid.
    {
        let mut space = nm.address_space().write();
        let _ = dialog.activate(&mut space);
    }
    let oob = session
        .call_one(CallMethodRequest {
            object_id: condition_id,
            method_id: MethodId::DialogConditionType_Respond.into(),
            input_arguments: Some(vec![Variant::Int32(5)]),
        })
        .await
        .unwrap();
    assert_eq!(oob.status_code, StatusCode::BadDialogResponseInvalid);
}

fn make_condition_event(source: &NodeId, message: &str, severity: u16) -> AlarmEvent {
    AlarmEvent {
        event_id: format!("evt-{message}").into_bytes(),
        event_type: NodeId::new(0, 2915),
        source_node: source.clone(),
        source_name: "HistDevice".to_string(),
        time: DateTime::now(),
        message: LocalizedText::new("en", message),
        severity,
        condition_id: NodeId::new(2, "HistCondition"),
        branch_id: NodeId::null(),
        condition_name: "HistCondition".to_string(),
        active_state: true,
        acked_state: false,
        confirmed_state: false,
        retain: true,
    }
}

/// Part 9 condition history: recorded condition events are returned by HistoryRead (ReadEventDetails)
/// with the requested select clauses applied.
#[tokio::test]
async fn condition_event_history_read_returns_recorded_events() {
    let (_tester, nm, session) = setup_alarms().await;

    let source = NodeId::new(2, "HistDevice");
    {
        let mut space = nm.address_space().write();
        let source_node =
            opcua::server::address_space::ObjectBuilder::new(&source, "HistDevice", "HistDevice")
                .component_of(ObjectId::ObjectsFolder)
                .event_notifier(
                    opcua::server::address_space::EventNotifier::SUBSCRIBE_TO_EVENTS
                        | opcua::server::address_space::EventNotifier::HISTORY_READ,
                )
                .build();
        space.insert::<_, NodeId>(source_node, None);
    }

    // Record two condition events into the in-memory event historian and wire it as the backend.
    let history = std::sync::Arc::new(InMemoryEventHistory::new());
    history.record_event(source.clone(), make_condition_event(&source, "first", 100));
    history.record_event(source.clone(), make_condition_event(&source, "second", 200));
    nm.inner().set_history_backend(history);

    let action = HistoryReadAction::ReadEventDetails(ReadEventDetails {
        num_values_per_node: 10,
        start_time: DateTime::now() - TimeDelta::try_seconds(1000).unwrap(),
        end_time: DateTime::now() + TimeDelta::try_seconds(1000).unwrap(),
        filter: EventFilter {
            select_clauses: Some(get_alarm_event_select_clauses()),
            where_clause: opcua_types::ContentFilter::default(),
        },
    });

    let r = session
        .history_read(
            action,
            TimestampsToReturn::Both,
            false,
            &[HistoryReadValueId {
                node_id: source.clone(),
                ..Default::default()
            }],
        )
        .await
        .unwrap();

    assert_eq!(r.len(), 1);
    assert_eq!(r[0].status_code, StatusCode::Good);
    let events = r[0]
        .history_data
        .inner_as::<HistoryEvent>()
        .expect("HistoryEvent")
        .events
        .clone()
        .unwrap_or_default();
    assert_eq!(events.len(), 2, "both recorded condition events returned");

    // The select clauses round-trip back into parseable alarm events (in ascending time order).
    let messages: Vec<String> = events
        .iter()
        .filter_map(|e| e.event_fields.as_ref())
        .filter_map(|f| parse_alarm_event(f))
        .map(|e| e.message.text.as_ref().to_string())
        .collect();
    assert!(messages.contains(&"first".to_string()));
    assert!(messages.contains(&"second".to_string()));
}

// ---------------------------------------------------------------------------
// US1 — automatic alarm source monitoring (Part 9 §5.8.2 InputNode / §4.4).
// A limit alarm bound to a writable source Variable auto-fires when that variable's
// Value is written — no manual update_value (contrast drive_limit above).
// ---------------------------------------------------------------------------

fn make_writable_double(nm: &SimpleNodeManager, id: &str) -> NodeId {
    let nid = NodeId::new(2, id);
    let mut space = nm.address_space().write();
    let var = VariableBuilder::new(&nid, id, id)
        .data_type(DataTypeId::Double)
        .value(0.0f64)
        .access_level(AccessLevel::CURRENT_READ | AccessLevel::CURRENT_WRITE)
        .user_access_level(AccessLevel::CURRENT_READ | AccessLevel::CURRENT_WRITE)
        .component_of(ObjectId::ObjectsFolder)
        .build();
    space.insert::<_, NodeId>(var, None);
    nid
}

fn write_double(node: &NodeId, v: f64) -> WriteValue {
    WriteValue {
        node_id: node.clone(),
        attribute_id: AttributeId::Value as u32,
        index_range: Default::default(),
        value: DataValue::new_now(v),
    }
}

/// Create a limit alarm, bind it to `input` as its InputNode, register its condition methods, and
/// register it for automatic source monitoring. Returns the alarm handle (for state reads).
fn monitor_limit_alarm(
    nm: &SimpleNodeManager,
    core_nm: &CoreNodeManager,
    device: &str,
    event_source: &NodeId,
    input: &NodeId,
    cfg: LimitConfig,
) -> Arc<LimitAlarm> {
    let mut alarm = register_limit_alarm(
        nm.address_space(),
        nm,
        device,
        "Level",
        event_source.clone(),
        cfg,
    );
    alarm.set_source_node(input.clone());
    let registry = ConditionRegistry::new();
    registry.register(alarm.condition_state_machine());
    register_condition_methods(core_nm, registry, nm.address_space().clone());
    let alarm = Arc::new(alarm);
    nm.inner()
        .alarm_source_registry()
        .register(input.clone(), alarm.clone());
    alarm
}

async fn sub_with_events(
    session: &opcua_client::Session,
    source: &NodeId,
) -> tokio::sync::mpsc::UnboundedReceiver<(ReadValueId, Option<Vec<Variant>>)> {
    let (notifs, _dv, events) = ChannelNotifications::new();
    let sub_id = session
        .create_subscription(Duration::from_millis(100), 100, 20, 1000, 0, true, notifs)
        .await
        .unwrap();
    let _item = add_event_item(session, sub_id, source).await;
    events
}

#[tokio::test]
async fn limit_alarm_auto_fires_on_source_write() {
    let (tester, nm, session) = setup_alarms().await;
    let core_nm = tester
        .handle
        .node_managers()
        .get_of_type::<CoreNodeManager>()
        .unwrap();
    let event_source = make_event_source(&nm, "AutoSrc13");
    let input = make_writable_double(&nm, "AutoIn13");
    monitor_limit_alarm(
        &nm,
        &core_nm,
        "AutoTank13",
        &event_source,
        &input,
        exclusive_level_cfg(),
    );
    let mut events = sub_with_events(&session, &event_source).await;

    let r = session.write(&[write_double(&input, 105.0)]).await.unwrap();
    assert_eq!(r[0], StatusCode::Good, "the write itself succeeds");
    let e = recv_alarm(&mut events).await;
    assert!(
        e.active_state,
        "writing above High auto-activates the alarm"
    );
    assert_eq!(e.severity, 400);
}

#[tokio::test]
async fn limit_alarm_auto_clears_on_source_write_back_in_range() {
    let (tester, nm, session) = setup_alarms().await;
    let core_nm = tester
        .handle
        .node_managers()
        .get_of_type::<CoreNodeManager>()
        .unwrap();
    let event_source = make_event_source(&nm, "AutoSrc14");
    let input = make_writable_double(&nm, "AutoIn14");
    monitor_limit_alarm(
        &nm,
        &core_nm,
        "AutoTank14",
        &event_source,
        &input,
        exclusive_level_cfg(),
    );
    let mut events = sub_with_events(&session, &event_source).await;

    session.write(&[write_double(&input, 105.0)]).await.unwrap();
    assert!(recv_alarm(&mut events).await.active_state);
    // Back well within limits (deadband cleared) → inactive.
    session.write(&[write_double(&input, 50.0)]).await.unwrap();
    assert!(
        !recv_alarm(&mut events).await.active_state,
        "in-range write clears the alarm"
    );
}

#[tokio::test]
async fn two_alarms_on_one_source_both_auto_evaluate() {
    let (tester, nm, session) = setup_alarms().await;
    let core_nm = tester
        .handle
        .node_managers()
        .get_of_type::<CoreNodeManager>()
        .unwrap();
    let src_a = make_event_source(&nm, "AutoSrc15a");
    let src_b = make_event_source(&nm, "AutoSrc15b");
    let input = make_writable_double(&nm, "AutoIn15");
    let alarm_a = monitor_limit_alarm(
        &nm,
        &core_nm,
        "TankA15",
        &src_a,
        &input,
        exclusive_level_cfg(),
    );
    let alarm_b = monitor_limit_alarm(
        &nm,
        &core_nm,
        "TankB15",
        &src_b,
        &input,
        exclusive_level_cfg(),
    );

    session.write(&[write_double(&input, 105.0)]).await.unwrap();
    // One write re-evaluated both alarms (Part 9 §4.4): both conditions are Active.
    let space = nm.address_space().read();
    assert!(alarm_a.condition_state_machine().get_active(&space));
    assert!(alarm_b.condition_state_machine().get_active(&space));
}

#[tokio::test]
async fn write_to_unbound_source_does_not_fire() {
    let (_tester, nm, session) = setup_alarms().await;
    // An event-notifier to subscribe on, plus a separate writable variable with NO alarm bound.
    let event_source = make_event_source(&nm, "UnboundSrc16");
    let plain = make_writable_double(&nm, "Unbound16");
    let mut events = sub_with_events(&session, &event_source).await;
    session.write(&[write_double(&plain, 999.0)]).await.unwrap();
    // No alarm bound to this source → no event within a generous window.
    let got = timeout(Duration::from_millis(500), events.recv()).await;
    assert!(
        got.is_err(),
        "writing a source with no bound alarm emits nothing"
    );
}

#[tokio::test]
async fn disabled_alarm_does_not_auto_fire() {
    let (tester, nm, session) = setup_alarms().await;
    let core_nm = tester
        .handle
        .node_managers()
        .get_of_type::<CoreNodeManager>()
        .unwrap();
    let event_source = make_event_source(&nm, "AutoSrc17");
    let input = make_writable_double(&nm, "AutoIn17");
    let alarm = monitor_limit_alarm(
        &nm,
        &core_nm,
        "AutoTank17",
        &event_source,
        &input,
        exclusive_level_cfg(),
    );
    {
        let mut space = nm.address_space().write();
        alarm
            .condition_state_machine()
            .set_enabled(&mut space, false);
    }
    let mut events = sub_with_events(&session, &event_source).await;
    session.write(&[write_double(&input, 105.0)]).await.unwrap();
    let got = timeout(Duration::from_millis(500), events.recv()).await;
    assert!(
        got.is_err(),
        "a disabled alarm does not auto-fire (Part 9 §5.5.2)"
    );
}

#[tokio::test]
async fn programmatic_set_source_value_auto_fires() {
    let (tester, nm, session) = setup_alarms().await;
    let core_nm = tester
        .handle
        .node_managers()
        .get_of_type::<CoreNodeManager>()
        .unwrap();
    let event_source = make_event_source(&nm, "AutoSrc18a");
    let input = make_writable_double(&nm, "AutoIn18a");
    monitor_limit_alarm(
        &nm,
        &core_nm,
        "AutoTank18a",
        &event_source,
        &input,
        exclusive_level_cfg(),
    );
    let mut events = sub_with_events(&session, &event_source).await;

    // FR-011: a programmatic server-side set (not via the Write service) also drives the alarm.
    nm.inner()
        .set_source_value(&input, DataValue::new_now(105.0f64));
    assert!(recv_alarm(&mut events).await.active_state);
}

#[tokio::test]
async fn non_numeric_source_write_does_not_panic_or_fire() {
    let (tester, nm, session) = setup_alarms().await;
    let core_nm = tester
        .handle
        .node_managers()
        .get_of_type::<CoreNodeManager>()
        .unwrap();
    let event_source = make_event_source(&nm, "AutoSrc18");
    // A BaseDataType source accepts a non-numeric value, so it reaches the re-eval hook.
    let input = NodeId::new(2, "AutoIn18");
    {
        let mut space = nm.address_space().write();
        let var = VariableBuilder::new(&input, "AutoIn18", "AutoIn18")
            .data_type(DataTypeId::BaseDataType)
            .value(0.0f64)
            .access_level(AccessLevel::CURRENT_READ | AccessLevel::CURRENT_WRITE)
            .user_access_level(AccessLevel::CURRENT_READ | AccessLevel::CURRENT_WRITE)
            .component_of(ObjectId::ObjectsFolder)
            .build();
        space.insert::<_, NodeId>(var, None);
    }
    monitor_limit_alarm(
        &nm,
        &core_nm,
        "AutoTank18",
        &event_source,
        &input,
        exclusive_level_cfg(),
    );
    let mut events = sub_with_events(&session, &event_source).await;

    // Write a String to the bound source: the write path must not panic, and source_value_as_f64
    // returns None (no usable numeric) → no alarm event (Constitution IV; the value is unusable).
    let wv = WriteValue {
        node_id: input.clone(),
        attribute_id: AttributeId::Value as u32,
        index_range: Default::default(),
        value: DataValue::new_now("not a number"),
    };
    let _ = session.write(&[wv]).await.unwrap(); // no panic regardless of write status
    let got = timeout(Duration::from_millis(500), events.recv()).await;
    assert!(
        got.is_err(),
        "a non-numeric source value triggers no alarm event"
    );
}

// ---------------------------------------------------------------------------
// US2 / US3 — browsable binding + one-call configuration helper.
// monitor_alarm_source sets the InputNode property + HasCondition reference + registers
// the source→alarm index in one call (Part 9 §5.8.2 / §4.4).
// ---------------------------------------------------------------------------

fn bind_via_helper(
    nm: &SimpleNodeManager,
    device: &str,
    event_source: &NodeId,
    input: &NodeId,
    cfg: LimitConfig,
) -> (Arc<LimitAlarm>, NodeId) {
    let alarm = register_limit_alarm(
        nm.address_space(),
        nm,
        device,
        "Level",
        event_source.clone(),
        cfg,
    );
    let condition_id = alarm.condition_state_machine().condition_id.clone();
    let alarm = nm.monitor_alarm_source(input, alarm);
    (alarm, condition_id)
}

#[tokio::test]
async fn monitor_alarm_source_one_call_drives_alarm() {
    let (_tester, nm, session) = setup_alarms().await;
    let event_source = make_event_source(&nm, "BrSrc24");
    let input = make_writable_double(&nm, "BrIn24");
    bind_via_helper(
        &nm,
        "BrTank24",
        &event_source,
        &input,
        exclusive_level_cfg(),
    );
    let mut events = sub_with_events(&session, &event_source).await;
    // One-call binding: a source write drives the alarm with no further setup.
    session.write(&[write_double(&input, 105.0)]).await.unwrap();
    assert!(recv_alarm(&mut events).await.active_state);
}

#[tokio::test]
async fn input_node_property_reads_back_the_source() {
    let (_tester, nm, session) = setup_alarms().await;
    let event_source = make_event_source(&nm, "BrSrc21");
    let input = make_writable_double(&nm, "BrIn21");
    let (_alarm, condition_id) = bind_via_helper(
        &nm,
        "BrTank21",
        &event_source,
        &input,
        exclusive_level_cfg(),
    );
    // Part 9 §5.8.2: the AlarmConditionType InputNode property resolves to the source variable.
    match read_value_via_path(&session, &condition_id, &["InputNode"]).await {
        Some(Variant::NodeId(n)) => assert_eq!(*n, input),
        other => panic!("InputNode = {other:?}, expected {input:?}"),
    }
}

#[tokio::test]
async fn source_has_condition_reference_to_alarm() {
    let (_tester, nm, _session) = setup_alarms().await;
    let event_source = make_event_source(&nm, "BrSrc22");
    let input = make_writable_double(&nm, "BrIn22");
    let (_alarm, condition_id) = bind_via_helper(
        &nm,
        "BrTank22",
        &event_source,
        &input,
        exclusive_level_cfg(),
    );
    // Part 9 §4.4: the source node HasCondition the bound alarm.
    let space = nm.address_space().read();
    assert!(
        space.has_reference(&input, &condition_id, ReferenceTypeId::HasCondition),
        "the source variable must reference the alarm via HasCondition"
    );
}

// ---------------------------------------------------------------------------
// US4 — opt-in periodic sampling. For out-of-band source changes (not via Write),
// a per-binding sampling interval polls the InputNode and re-evaluates (Part 9 §4.4).
// ---------------------------------------------------------------------------

/// Change a source variable's Value directly in the address space, bypassing the node-manager
/// Write path — so ONLY the sampler (if any) will notice. Mirrors an out-of-band source update.
fn set_value_out_of_band(nm: &SimpleNodeManager, id: &NodeId, v: f64) {
    let mut guard = nm.address_space().write();
    let space: &mut AddressSpace = &mut guard;
    if let Some(mut node) = space.find_mut(id) {
        if let opcua::nodes::NodeType::Variable(ref mut var) = &mut *node {
            let _ = var.set_value(&opcua_types::NumericRange::None, Variant::from(v));
        }
    };
}

fn bind_sampled(
    nm: &SimpleNodeManager,
    device: &str,
    event_source: &NodeId,
    input: &NodeId,
    cfg: LimitConfig,
    interval: Duration,
) -> (Arc<LimitAlarm>, NodeId) {
    let alarm = register_limit_alarm(
        nm.address_space(),
        nm,
        device,
        "Level",
        event_source.clone(),
        cfg,
    );
    let condition_id = alarm.condition_state_machine().condition_id.clone();
    let alarm = nm.monitor_alarm_source_sampled(input, alarm, interval);
    (alarm, condition_id)
}

#[tokio::test]
async fn sampled_alarm_fires_on_out_of_band_change() {
    let (_tester, nm, session) = setup_alarms().await;
    let event_source = make_event_source(&nm, "SampSrc29");
    let input = make_writable_double(&nm, "SampIn29");
    bind_sampled(
        &nm,
        "SampTank29",
        &event_source,
        &input,
        exclusive_level_cfg(),
        Duration::from_millis(100),
    );
    let mut events = sub_with_events(&session, &event_source).await;
    // Out-of-band change (no Write dispatch): the sampler must pick it up within ~one interval.
    set_value_out_of_band(&nm, &input, 105.0);
    let got = timeout(Duration::from_secs(2), recv_alarm(&mut events))
        .await
        .expect("the sampler activates the alarm within one interval");
    assert!(got.active_state);
}

#[tokio::test]
async fn unsampled_alarm_ignores_out_of_band_until_write() {
    let (_tester, nm, session) = setup_alarms().await;
    let event_source = make_event_source(&nm, "SampSrc30");
    let input = make_writable_double(&nm, "SampIn30");
    // Bound WITHOUT sampling (write-driven only).
    bind_via_helper(
        &nm,
        "SampTank30",
        &event_source,
        &input,
        exclusive_level_cfg(),
    );
    let mut events = sub_with_events(&session, &event_source).await;
    // Out-of-band change is invisible to the write-driven path: no event.
    set_value_out_of_band(&nm, &input, 105.0);
    let none = timeout(Duration::from_millis(500), events.recv()).await;
    assert!(
        none.is_err(),
        "without sampling, an out-of-band change emits nothing"
    );
    // A real Write through the node manager re-evaluates and fires.
    session.write(&[write_double(&input, 106.0)]).await.unwrap();
    let got = timeout(Duration::from_secs(2), recv_alarm(&mut events))
        .await
        .expect("a Write drives the alarm");
    assert!(got.active_state);
}

// ---------------------------------------------------------------------------
// US5 — source monitoring generalizes across alarm types: NonExclusiveLimitAlarmType
// (the shared LimitAlarm in NonExclusive mode) and the discrete / off-normal alarm.
// ---------------------------------------------------------------------------

fn nonexclusive_level_cfg() -> LimitConfig {
    LimitConfig::new(LimitMode::NonExclusive)
        .with_high(LimitDef {
            value: 100.0,
            deadband: 5.0,
            severity: 400,
        })
        .with_high_high(LimitDef {
            value: 110.0,
            deadband: 5.0,
            severity: 700,
        })
        .build()
        .expect("valid config")
}

#[tokio::test]
async fn nonexclusive_limit_alarm_auto_fires_on_source_write() {
    let (_tester, nm, session) = setup_alarms().await;
    let event_source = make_event_source(&nm, "NeSrc33");
    let input = make_writable_double(&nm, "NeIn33");
    bind_via_helper(
        &nm,
        "NeTank33",
        &event_source,
        &input,
        nonexclusive_level_cfg(),
    );
    let mut events = sub_with_events(&session, &event_source).await;
    // Part 9 §5.8.19–§5.8.20: a value past HighHigh auto-activates without a manual update_value.
    session.write(&[write_double(&input, 115.0)]).await.unwrap();
    let got = timeout(Duration::from_secs(2), recv_alarm(&mut events))
        .await
        .expect("a NonExclusiveLimitAlarm auto-fires on a source write");
    assert!(got.active_state);
}

#[tokio::test]
async fn discrete_alarm_auto_fires_on_source_write() {
    let (_tester, nm, session) = setup_alarms().await;
    let event_source = make_event_source(&nm, "DiscSrc34");
    let input = make_writable_double(&nm, "DiscIn34");
    // OffNormalAlarmType with NormalState = 0.0; any other value is off-normal (Part 9 §5.8.4).
    let alarm = register_discrete_alarm(
        nm.address_space(),
        &nm,
        "DiscPump34",
        "State",
        event_source.clone(),
        DiscreteAlarmKind::OffNormal,
        Variant::from(0.0f64),
    );
    // Write-driven binding: the written InputNode → the discrete alarm.
    nm.inner()
        .alarm_source_registry()
        .register(input.clone(), Arc::new(alarm));
    let mut events = sub_with_events(&session, &event_source).await;
    session.write(&[write_double(&input, 1.0)]).await.unwrap();
    let got = timeout(Duration::from_secs(2), recv_alarm(&mut events))
        .await
        .expect("a discrete/off-normal alarm auto-fires on a source write");
    assert!(got.active_state);
}
