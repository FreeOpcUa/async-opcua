//! Client-side Alarm and Condition (Part 9) event parsing and subscription helpers.

use opcua_core::events::AlarmEvent;
use opcua_types::{
    AttributeId, DateTime, LocalizedText, NodeId, NumericRange, QualifiedName,
    SimpleAttributeOperand, Variant,
};

/// Builds the standard list of `SimpleAttributeOperand` select clauses for subscribing to Alarm events.
/// The order of returned fields matches the parsing logic in `parse_alarm_event`.
pub fn get_alarm_event_select_clauses() -> Vec<SimpleAttributeOperand> {
    let base_event_type = NodeId::new(0, 2041); // BaseEventType

    let fields = vec![
        (base_event_type.clone(), vec!["EventId"]),
        (base_event_type.clone(), vec!["EventType"]),
        (base_event_type.clone(), vec!["SourceNode"]),
        (base_event_type.clone(), vec!["SourceName"]),
        (base_event_type.clone(), vec!["Time"]),
        (base_event_type.clone(), vec!["Message"]),
        (base_event_type.clone(), vec!["Severity"]),
        (base_event_type.clone(), vec!["ConditionId"]),
        (base_event_type.clone(), vec!["ConditionName"]),
        (base_event_type.clone(), vec!["ActiveState", "Id"]),
        (base_event_type.clone(), vec!["AckedState", "Id"]),
        (base_event_type.clone(), vec!["ConfirmedState", "Id"]),
        (base_event_type.clone(), vec!["Retain"]),
    ];

    fields
        .into_iter()
        .map(|(type_id, path)| SimpleAttributeOperand {
            type_definition_id: type_id,
            browse_path: Some(path.into_iter().map(|s| QualifiedName::new(0, s)).collect()),
            attribute_id: AttributeId::Value as u32,
            index_range: NumericRange::None,
        })
        .collect()
}

/// Parses standard Alarm event select clause variant fields back into a flat `AlarmEvent` structure.
pub fn parse_alarm_event(event_fields: &[Variant]) -> Option<AlarmEvent> {
    if event_fields.len() < 12 {
        return None;
    }

    let event_id = match &event_fields[0] {
        Variant::ByteString(ref b) => b.as_ref().to_vec(),
        _ => return None,
    };
    let event_type = match &event_fields[1] {
        Variant::NodeId(ref id) => (**id).clone(),
        _ => return None,
    };
    let source_node = match &event_fields[2] {
        Variant::NodeId(ref id) => (**id).clone(),
        _ => return None,
    };
    let source_name = match &event_fields[3] {
        Variant::String(ref s) => s.as_ref().to_string(),
        _ => String::new(),
    };
    let time = match &event_fields[4] {
        Variant::DateTime(ref t) => **t,
        _ => DateTime::now(),
    };
    let message = match &event_fields[5] {
        Variant::LocalizedText(ref t) => (**t).clone(),
        _ => LocalizedText::null(),
    };
    let severity = match &event_fields[6] {
        Variant::UInt16(v) => *v,
        Variant::Int16(v) => *v as u16,
        Variant::Int32(v) => *v as u16,
        _ => 100u16,
    };
    let condition_id = match &event_fields[7] {
        Variant::NodeId(ref id) => (**id).clone(),
        _ => NodeId::null(),
    };
    let condition_name = match &event_fields[8] {
        Variant::String(ref s) => s.as_ref().to_string(),
        _ => String::new(),
    };
    let active_state = match &event_fields[9] {
        Variant::Boolean(b) => *b,
        _ => false,
    };
    let acked_state = match &event_fields[10] {
        Variant::Boolean(b) => *b,
        _ => false,
    };
    let confirmed_state = match &event_fields[11] {
        Variant::Boolean(b) => *b,
        _ => false,
    };
    let retain = if event_fields.len() > 12 {
        match &event_fields[12] {
            Variant::Boolean(b) => *b,
            _ => true,
        }
    } else {
        true
    };

    Some(AlarmEvent {
        event_id,
        event_type,
        source_node,
        source_name,
        time,
        message,
        severity,
        condition_id,
        condition_name,
        active_state,
        acked_state,
        confirmed_state,
        retain,
    })
}
