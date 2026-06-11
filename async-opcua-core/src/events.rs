//! Alarms and Conditions event structures.
//! Provides unified definitions for client-side event parsing and server-side event dispatching.

use opcua_types::{DateTime, LocalizedText, NodeId};

/// A flat, developer-friendly representation of an OPC UA Alarm/Condition Event.
/// This simplifies handling condition events across the server-client boundary.
#[derive(Debug, Clone, PartialEq)]
pub struct AlarmEvent {
    /// Unique identifier for the event instance.
    pub event_id: Vec<u8>,
    /// NodeId of the event type (e.g., AlarmConditionType).
    pub event_type: NodeId,
    /// The node that generated the event.
    pub source_node: NodeId,
    /// Display name of the event source.
    pub source_name: String,
    /// Time when the event occurred.
    pub time: DateTime,
    /// Human-readable message describing the event.
    pub message: LocalizedText,
    /// Urgency of the event (1 to 1000).
    pub severity: u16,
    /// NodeId of the condition instance in the address space.
    pub condition_id: NodeId,
    /// Human-readable name of the condition.
    pub condition_name: String,
    /// Current active state (true = active/exceeded, false = normal).
    pub active_state: bool,
    /// Current acknowledgment state (true = acknowledged, false = unacknowledged).
    pub acked_state: bool,
    /// Current confirmation state (true = confirmed, false = unconfirmed).
    pub confirmed_state: bool,
    /// Whether the server is retaining this condition.
    pub retain: bool,
}

impl AlarmEvent {
    /// Creates a new `AlarmEvent` with default/initial settings.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_id: Vec<u8>,
        event_type: NodeId,
        source_node: NodeId,
        source_name: String,
        time: DateTime,
        message: LocalizedText,
        severity: u16,
        condition_id: NodeId,
        condition_name: String,
    ) -> Self {
        Self {
            event_id,
            event_type,
            source_node,
            source_name,
            time,
            message,
            severity,
            condition_id,
            condition_name,
            active_state: false,
            acked_state: false,
            confirmed_state: false,
            retain: true,
        }
    }
}
