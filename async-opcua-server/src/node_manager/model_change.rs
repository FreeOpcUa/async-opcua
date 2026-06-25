use opcua_nodes::{Event, EventField};
use opcua_types::{
    Array, AttributeId, ByteString, DateTime, ExtensionObject, LocalizedText,
    ModelChangeStructureDataType, NodeId, NumericRange, ObjectId, ObjectTypeId, QualifiedName,
    UAString, Variant, VariantScalarTypeId,
};

const SOURCE_NAME: &str = "Server";
const SEVERITY: u16 = 1;

/// Server-originated `GeneralModelChangeEventType` notification.
#[derive(Clone)]
pub struct GeneralModelChangeEvent {
    /// Unique event identifier.
    pub event_id: Vec<u8>,
    /// Event timestamp.
    pub time: DateTime,
    /// Localized event message.
    pub message: LocalizedText,
    /// Model changes reported by this event.
    pub changes: Vec<ModelChangeStructureDataType>,
    event_type: NodeId,
}

impl GeneralModelChangeEvent {
    /// Creates a new general model-change event for the supplied changes.
    pub fn new(changes: Vec<ModelChangeStructureDataType>) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().as_bytes().to_vec(),
            time: DateTime::now(),
            message: LocalizedText::new("en", "Model changed"),
            changes,
            event_type: NodeId::from(ObjectTypeId::GeneralModelChangeEventType),
        }
    }
}

impl Event for GeneralModelChangeEvent {
    fn clone_box(&self) -> Box<dyn Event + Send> {
        Box::new(self.clone())
    }

    fn time(&self) -> &DateTime {
        &self.time
    }

    fn event_type_id(&self) -> &NodeId {
        &self.event_type
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

impl EventField for GeneralModelChangeEvent {
    fn get_value(
        &self,
        attribute_id: AttributeId,
        _index_range: &NumericRange,
        remaining_path: &[QualifiedName],
    ) -> Variant {
        if attribute_id != AttributeId::Value || remaining_path.len() != 1 {
            return Variant::Empty;
        }

        match remaining_path[0].name.as_ref() {
            "EventId" => Variant::from(ByteString::from(self.event_id.clone())),
            "EventType" => Variant::from(self.event_type.clone()),
            "SourceNode" => Variant::from(NodeId::from(ObjectId::Server)),
            "SourceName" => Variant::from(UAString::from(SOURCE_NAME)),
            "Time" => Variant::from(self.time),
            "ReceiveTime" => Variant::from(self.time),
            "Message" => Variant::from(self.message.clone()),
            "Severity" => Variant::from(SEVERITY),
            "Changes" => {
                let changes = self
                    .changes
                    .iter()
                    .cloned()
                    .map(ExtensionObject::from_message)
                    .map(Variant::from)
                    .collect::<Vec<_>>();
                Array::new(VariantScalarTypeId::ExtensionObject, changes)
                    .map(|array| Variant::Array(Box::new(array)))
                    .unwrap_or(Variant::Empty)
            }
            _ => Variant::Empty,
        }
    }
}
