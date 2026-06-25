//! State machine transition logic and verification rules for Alarms.

use crate::address_space::AddressSpace;
use crate::alarms::state_machine::ConditionStateMachine;
use opcua_core::events::AlarmEvent;
use opcua_types::{DateTime, LocalizedText, NodeId, StatusCode};

/// Triggers a state transition of an Alarm (Active <-> Inactive) when monitored values change.
/// Returns the generated `AlarmEvent` on successful transition.
pub fn trigger_alarm_transition(
    address_space: &mut AddressSpace,
    state_machine: &ConditionStateMachine,
    active: bool,
    severity: u16,
    message: LocalizedText,
) -> Result<Option<AlarmEvent>, StatusCode> {
    if !state_machine.get_enabled(address_space) {
        return Ok(None);
    }

    let prev_active = state_machine.get_active(address_space);
    if prev_active == active {
        return Ok(None);
    }

    // Update state machine variables
    state_machine.set_active(address_space, active);
    state_machine.set_severity(address_space, severity);
    state_machine.set_message(address_space, message.clone());

    if active {
        // Active transitions reset Acknowledged and Confirmed states
        state_machine.set_acked(address_space, false);
        state_machine.set_confirmed(address_space, false);
    }

    let acked = state_machine.get_acked(address_space);
    let confirmed = state_machine.get_confirmed(address_space);
    let retain = active || !acked || !confirmed;
    state_machine.set_retain(address_space, retain);

    let event_id = uuid::Uuid::new_v4().as_bytes().to_vec();
    // This EventId identifies the condition's current acknowledgeable state; Acknowledge/Confirm
    // validate the client-supplied EventId against it (Part 9 §5.5.2). The ack/confirm notifications
    // reuse this same EventId, so it stays current until the next transition.
    state_machine.set_current_event_id(&event_id);
    let event = AlarmEvent {
        event_id,
        event_type: NodeId::new(0, 2915), // AlarmConditionType
        source_node: state_machine.source_node_id.clone(),
        source_name: state_machine.condition_name.clone(),
        time: DateTime::now(),
        message,
        severity,
        condition_id: state_machine.condition_id.clone(),
        branch_id: NodeId::null(),
        condition_name: state_machine.condition_name.clone(),
        active_state: active,
        acked_state: acked,
        confirmed_state: confirmed,
        retain,
    };

    Ok(Some(event))
}

/// Acknowledges an active Alarm. Sets `acked_state` to true and updates standard properties.
pub fn acknowledge_alarm(
    address_space: &mut AddressSpace,
    state_machine: &ConditionStateMachine,
    comment: LocalizedText,
) -> Result<Option<AlarmEvent>, StatusCode> {
    if !state_machine.get_enabled(address_space) {
        return Err(StatusCode::BadConditionDisabled);
    }

    if state_machine.get_acked(address_space) {
        return Err(StatusCode::BadConditionBranchAlreadyAcked);
    }

    state_machine.set_acked(address_space, true);

    let active = state_machine.get_active(address_space);
    let confirmed = state_machine.get_confirmed(address_space);
    let retain = active || !confirmed;
    state_machine.set_retain(address_space, retain);

    let severity = state_machine.get_severity(address_space);
    let text = format!("Acknowledged: {}", comment.text);
    let message = LocalizedText::new("en", &text);
    state_machine.set_message(address_space, message.clone());

    let event_id = uuid::Uuid::new_v4().as_bytes().to_vec();
    let event = AlarmEvent {
        event_id,
        event_type: NodeId::new(0, 2915),
        source_node: state_machine.source_node_id.clone(),
        source_name: state_machine.condition_name.clone(),
        time: DateTime::now(),
        message,
        severity,
        condition_id: state_machine.condition_id.clone(),
        branch_id: NodeId::null(),
        condition_name: state_machine.condition_name.clone(),
        active_state: active,
        acked_state: true,
        confirmed_state: confirmed,
        retain,
    };

    Ok(Some(event))
}

/// Confirms an acknowledged Alarm. Sets `confirmed_state` to true and updates standard properties.
pub fn confirm_alarm(
    address_space: &mut AddressSpace,
    state_machine: &ConditionStateMachine,
    comment: LocalizedText,
) -> Result<Option<AlarmEvent>, StatusCode> {
    if !state_machine.get_enabled(address_space) {
        return Err(StatusCode::BadConditionDisabled);
    }

    if !state_machine.get_acked(address_space) {
        return Err(StatusCode::BadInvalidState);
    }

    if state_machine.get_confirmed(address_space) {
        return Err(StatusCode::BadConditionBranchAlreadyConfirmed);
    }

    state_machine.set_confirmed(address_space, true);

    let active = state_machine.get_active(address_space);
    let retain = active; // Retain only if still active
    state_machine.set_retain(address_space, retain);

    let severity = state_machine.get_severity(address_space);
    let text = format!("Confirmed: {}", comment.text);
    let message = LocalizedText::new("en", &text);
    state_machine.set_message(address_space, message.clone());

    let event_id = uuid::Uuid::new_v4().as_bytes().to_vec();
    let event = AlarmEvent {
        event_id,
        event_type: NodeId::new(0, 2915),
        source_node: state_machine.source_node_id.clone(),
        source_name: state_machine.condition_name.clone(),
        time: DateTime::now(),
        message,
        severity,
        condition_id: state_machine.condition_id.clone(),
        branch_id: NodeId::null(),
        condition_name: state_machine.condition_name.clone(),
        active_state: active,
        acked_state: true,
        confirmed_state: true,
        retain,
    };

    Ok(Some(event))
}
