//! OPC UA Part 9 condition refresh marker events.

use opcua_nodes::{BaseEventType, Event, EventField};
use opcua_types::{
    AttributeId, ByteString, DateTime, NodeId, NumericRange, ObjectId, ObjectTypeId, QualifiedName,
    UAString, Variant,
};
use uuid::Uuid;

const SOURCE_NAME: &str = "Server";
const START_MESSAGE: &str = "Condition refresh started";
const END_MESSAGE: &str = "Condition refresh finished";

/// Marker event emitted before a ConditionRefresh replay burst.
#[derive(Clone)]
pub struct RefreshStartEvent {
    base: BaseEventType,
}

impl RefreshStartEvent {
    /// Creates a new `RefreshStartEvent` with a fresh EventId and current timestamps.
    pub fn new() -> Self {
        Self {
            base: new_refresh_marker(ObjectTypeId::RefreshStartEventType, START_MESSAGE),
        }
    }
}

impl Default for RefreshStartEvent {
    fn default() -> Self {
        Self::new()
    }
}

/// Marker event emitted after a ConditionRefresh replay burst.
#[derive(Clone)]
pub struct RefreshEndEvent {
    base: BaseEventType,
}

impl RefreshEndEvent {
    /// Creates a new `RefreshEndEvent` with a fresh EventId and current timestamps.
    pub fn new() -> Self {
        Self {
            base: new_refresh_marker(ObjectTypeId::RefreshEndEventType, END_MESSAGE),
        }
    }
}

impl Default for RefreshEndEvent {
    fn default() -> Self {
        Self::new()
    }
}

fn new_refresh_marker(event_type: ObjectTypeId, message: &str) -> BaseEventType {
    let now = DateTime::now();
    BaseEventType::new(
        event_type,
        ByteString::from(Uuid::new_v4().as_bytes().as_slice()),
        message,
        now,
    )
    .set_source_node(ObjectId::Server.into())
    .set_source_name(UAString::from(SOURCE_NAME))
    .set_severity(0)
}

fn get_refresh_marker_value(
    base: &BaseEventType,
    attribute_id: AttributeId,
    index_range: &NumericRange,
    remaining_path: &[QualifiedName],
) -> Variant {
    if attribute_id != AttributeId::Value || remaining_path.is_empty() {
        return Variant::Empty;
    }

    let first_name = remaining_path[0].name.as_ref();

    if remaining_path.len() == 2 {
        let second_name = remaining_path[1].name.as_ref();
        if second_name == "Id" {
            match first_name {
                "ActiveState" | "AckedState" | "ConfirmedState" => {
                    return Variant::from(false);
                }
                "EnabledState" => return Variant::from(true),
                _ => {}
            }
        }
    }

    if remaining_path.len() == 1 {
        match first_name {
            "ConditionId" => return Variant::from(NodeId::null()),
            "ConditionName" => return Variant::from(UAString::from("")),
            "Retain" => return Variant::from(false),
            "ActiveState" | "AckedState" | "ConfirmedState" => return Variant::from(false),
            "EnabledState" => return Variant::from(true),
            _ => return base.get_value(attribute_id, index_range, remaining_path),
        }
    }

    Variant::Empty
}

macro_rules! impl_refresh_marker_event {
    ($event:ty) => {
        impl Event for $event {
            fn clone_box(&self) -> Box<dyn Event + Send> {
                Box::new(self.clone())
            }

            fn time(&self) -> &DateTime {
                &self.base.time
            }

            fn event_type_id(&self) -> &NodeId {
                &self.base.event_type
            }

            fn get_field(
                &self,
                _type_definition_id: &NodeId,
                attribute_id: AttributeId,
                index_range: &NumericRange,
                browse_path: &[QualifiedName],
            ) -> Variant {
                self.get_value(attribute_id, index_range, browse_path)
            }
        }

        impl EventField for $event {
            fn get_value(
                &self,
                attribute_id: AttributeId,
                index_range: &NumericRange,
                remaining_path: &[QualifiedName],
            ) -> Variant {
                get_refresh_marker_value(&self.base, attribute_id, index_range, remaining_path)
            }
        }
    };
}

impl_refresh_marker_event!(RefreshStartEvent);
impl_refresh_marker_event!(RefreshEndEvent);
