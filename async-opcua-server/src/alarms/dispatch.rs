//! Event routing and dispatching of Alarm events to MonitoredItem subscription buffers.

use crate::server::Server;
use opcua_core::events::AlarmEvent;
use opcua_nodes::{Event, EventField};
use opcua_types::{AttributeId, DateTime, NodeId, NumericRange, QualifiedName, UAString, Variant};

/// Server wrapper of `AlarmEvent` implementing `opcua_nodes::Event` to allow dispatching to OPC UA subscriptions.
pub struct ServerAlarmEvent<'a> {
    /// Reference to the underlying AlarmEvent
    pub event: &'a AlarmEvent,
}

impl<'a> Event for ServerAlarmEvent<'a> {
    fn time(&self) -> &DateTime {
        &self.event.time
    }

    fn event_type_id(&self) -> &NodeId {
        &self.event.event_type
    }

    fn get_field(
        &self,
        _type_definition_id: &NodeId,
        attribute_id: AttributeId,
        _index_range: &NumericRange,
        browse_path: &[QualifiedName],
    ) -> Variant {
        self.get_value(attribute_id, _index_range, browse_path)
    }
}

impl<'a> EventField for ServerAlarmEvent<'a> {
    fn get_value(
        &self,
        attribute_id: AttributeId,
        _index_range: &NumericRange,
        remaining_path: &[QualifiedName],
    ) -> Variant {
        if attribute_id != AttributeId::Value {
            return Variant::Empty;
        }
        if remaining_path.is_empty() {
            return Variant::Empty;
        }

        let first_name = remaining_path[0].name.as_ref();

        // 2-level path: e.g., ["ActiveState", "Id"]
        if remaining_path.len() == 2 {
            let second_name = remaining_path[1].name.as_ref();
            if second_name == "Id" {
                match first_name {
                    "ActiveState" => return Variant::from(self.event.active_state),
                    "AckedState" => return Variant::from(self.event.acked_state),
                    "ConfirmedState" => return Variant::from(self.event.confirmed_state),
                    "EnabledState" => return Variant::from(true),
                    _ => {}
                }
            }
        }

        // 1-level path: e.g., ["Severity"]
        if remaining_path.len() == 1 {
            match first_name {
                "EventId" => {
                    return Variant::from(opcua_types::ByteString::from(
                        self.event.event_id.clone(),
                    ))
                }
                "EventType" => return Variant::from(self.event.event_type.clone()),
                "SourceNode" => return Variant::from(self.event.source_node.clone()),
                "SourceName" => {
                    return Variant::from(UAString::from(self.event.source_name.clone()))
                }
                "Time" => return Variant::from(self.event.time.clone()),
                "ReceiveTime" => return Variant::from(self.event.time.clone()),
                "Message" => return Variant::from(self.event.message.clone()),
                "Severity" => return Variant::from(self.event.severity),
                "ConditionId" => return Variant::from(self.event.condition_id.clone()),
                "ConditionName" => {
                    return Variant::from(UAString::from(self.event.condition_name.clone()))
                }
                "Retain" => return Variant::from(self.event.retain),
                "ActiveState" => return Variant::from(self.event.active_state),
                "AckedState" => return Variant::from(self.event.acked_state),
                "ConfirmedState" => return Variant::from(self.event.confirmed_state),
                "EnabledState" => return Variant::from(true),
                _ => {}
            }
        }

        Variant::Empty
    }
}

/// Routes and dispatches an `AlarmEvent` to the active subscription buffers on the server.
pub fn dispatch_alarm_event(server: &Server, alarm_event: &AlarmEvent) {
    let wrapper = ServerAlarmEvent { event: alarm_event };
    let subscriptions = server.subscriptions();

    // Emitting on the source node (the device or monitored variable generating the alarm)
    let items = std::iter::once((&wrapper as &dyn Event, &alarm_event.source_node));
    subscriptions.notify_events(items);
}
