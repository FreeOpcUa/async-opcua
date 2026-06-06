use crate::NamespaceMap;
use opcua_types::{
    event_field::EventField, AttributeId, ByteString, DateTime, LocalizedText, NodeId,
    NumericRange, ObjectTypeId, QualifiedName, TimeZoneDataType, UAString, Variant,
};

/// Trait implemented by all events.
///
/// This is used repeatedly when publishing event notifications to
/// clients.
pub trait Event: EventField {
    /// Get a field from the event. Should return [`Variant::Empty`]
    /// if the field is not valid for the event.
    fn get_field(
        &self,
        type_definition_id: &NodeId,
        attribute_id: AttributeId,
        index_range: &NumericRange,
        browse_path: &[QualifiedName],
    ) -> Variant;

    /// Get the `Time` of this event.
    fn time(&self) -> &DateTime;

    /// Get the event type ID of this event.
    fn event_type_id(&self) -> &NodeId;
}

#[derive(Debug, Default)]
/// This corresponds to BaseEventType definition in OPC UA Part 5
pub struct BaseEventType {
    /// A unique identifier for an event, e.g. a GUID in a byte string
    pub event_id: ByteString,
    /// Event type describes the type of event
    pub event_type: NodeId,
    /// Source node identifies the node that the event originated from or null.
    pub source_node: NodeId,
    /// Source name provides the description of the source of the event,
    /// e.g. the display of the event source
    pub source_name: UAString,
    /// Time provides the time the event occurred. As close
    /// to the event generator as possible.
    pub time: DateTime,
    /// Receive time provides the time the OPC UA server received
    /// the event from the underlying device of another server.
    pub receive_time: DateTime,
    /// Local time (optional) is a structure containing
    /// the offset and daylightsaving flag.
    pub local_time: Option<TimeZoneDataType>,
    /// Message provides a human readable localizable text description
    /// of the event.
    pub message: LocalizedText,
    /// Severity is an indication of the urgency of the event. Values from 1 to 1000, with 1 as the lowest
    /// severity and 1000 being the highest. A value of 1000 would indicate an event of catastrophic nature.
    ///
    /// Guidance:
    ///
    /// * 801-1000 - High
    /// * 601-800 - Medium High
    /// * 401-600 - Medium
    /// * 201-400 - Medium Low
    /// * 1-200 - Low
    pub severity: u16,
    /// Condition Class Id specifies in which domain this Event is used.
    pub condition_class_id: Option<NodeId>,
    /// Condition class name specifies the name of the condition class of this event, if set.
    pub condition_class_name: Option<LocalizedText>,
    /// ConditionSubClassId specifies additional classes that apply to the Event.
    /// It is the NodeId of the corresponding subtype of BaseConditionClassType.
    pub condition_sub_class_id: Option<Vec<NodeId>>,
    /// Condition sub class name specifies the names of additional classes that apply to the event.
    pub condition_sub_class_name: Option<Vec<LocalizedText>>,
}

impl Event for BaseEventType {
    fn time(&self) -> &DateTime {
        &self.time
    }

    fn get_field(
        &self,
        type_definition_id: &NodeId,
        attribute_id: AttributeId,
        index_range: &NumericRange,
        browse_path: &[QualifiedName],
    ) -> Variant {
        if type_definition_id == &ObjectTypeId::BaseEventType {
            self.get_value(attribute_id, index_range, browse_path)
        } else {
            Variant::Empty
        }
    }

    fn event_type_id(&self) -> &NodeId {
        &self.event_type
    }
}

impl EventField for BaseEventType {
    fn get_value(
        &self,
        attribute_id: AttributeId,
        index_range: &NumericRange,
        remaining_path: &[QualifiedName],
    ) -> Variant {
        if remaining_path.len() != 1 || attribute_id != AttributeId::Value {
            // Field is not from base event type.
            return Variant::Empty;
        }
        let field = &remaining_path[0];
        if field.namespace_index != 0 {
            return Variant::Empty;
        }
        match field.name.as_ref() {
            "EventId" => self.event_id.get_value(attribute_id, index_range, &[]),
            "EventType" => self.event_type.get_value(attribute_id, index_range, &[]),
            "SourceNode" => self.source_node.get_value(attribute_id, index_range, &[]),
            "SourceName" => self.source_name.get_value(attribute_id, index_range, &[]),
            "Time" => self.time.get_value(attribute_id, index_range, &[]),
            "ReceiveTime" => self.receive_time.get_value(attribute_id, index_range, &[]),
            "LocalTime" => self.local_time.get_value(attribute_id, index_range, &[]),
            "Message" => self.message.get_value(attribute_id, index_range, &[]),
            "Severity" => self.severity.get_value(attribute_id, index_range, &[]),
            "ConditionClassId" => self
                .condition_class_id
                .get_value(attribute_id, index_range, &[]),
            "ConditionClassName" => {
                self.condition_class_name
                    .get_value(attribute_id, index_range, &[])
            }
            "ConditionSubClassId" => {
                self.condition_sub_class_id
                    .get_value(attribute_id, index_range, &[])
            }
            "ConditionSubClassName" => {
                self.condition_sub_class_name
                    .get_value(attribute_id, index_range, &[])
            }
            _ => Variant::Empty,
        }
    }
}

impl BaseEventType {
    /// Create a new event with `Time` set to current time.
    pub fn new_now(
        type_id: impl Into<NodeId>,
        event_id: ByteString,
        message: impl Into<LocalizedText>,
    ) -> Self {
        let time = DateTime::now();
        Self::new(type_id, event_id, message, time)
    }

    /// Create a new event.
    pub fn new(
        type_id: impl Into<NodeId>,
        event_id: ByteString,
        message: impl Into<LocalizedText>,
        time: DateTime,
    ) -> Self {
        Self {
            event_id,
            event_type: type_id.into(),
            message: message.into(),
            time,
            receive_time: time,
            ..Default::default()
        }
    }

    /// Create a new event, resolving the event type ID.
    pub fn new_event(
        type_id: impl Into<NodeId>,
        event_id: ByteString,
        message: impl Into<LocalizedText>,
        _namespace: &NamespaceMap,
        time: DateTime,
    ) -> Self {
        Self::new(type_id, event_id, message, time)
    }

    /// Set the event source node.
    pub fn set_source_node(mut self, source_node: NodeId) -> Self {
        self.source_node = source_node;
        self
    }

    /// Set the event source name.
    pub fn set_source_name(mut self, source_name: UAString) -> Self {
        self.source_name = source_name;
        self
    }

    /// Set the event receive time.
    pub fn set_receive_time(mut self, receive_time: DateTime) -> Self {
        self.receive_time = receive_time;
        self
    }

    /// Set the event severity.
    pub fn set_severity(mut self, severity: u16) -> Self {
        self.severity = severity;
        self
    }
}

pub use method_event_field::MethodEventField;

mod method_event_field {
    use opcua_macros::EventField;
    use opcua_types::NodeId;

    mod opcua {
        pub(super) use crate as nodes;
        pub(super) use opcua_types as types;
    }
    #[derive(Default, EventField, Debug)]
    /// A field of an event that references a method.
    pub struct MethodEventField {
        /// Method node ID.
        pub node_id: NodeId,
    }
}

#[cfg(test)]
mod tests {
    use crate::NamespaceMap;

    mod opcua {
        pub(super) use crate as nodes;
        pub(super) use opcua_types as types;
    }

    use crate::{BaseEventType, Event, EventField};
    use opcua_types::event_field::PlaceholderEventField;
    use opcua_types::{
        AttributeId, ByteString, EUInformation, KeyValuePair, LocalizedText, NodeId, NumericRange,
        ObjectTypeId, QualifiedName, StatusCode, UAString, Variant,
    };
    #[derive(Event)]
    #[opcua(identifier = "s=myevent", namespace = "uri:my:namespace")]
    struct BasicValueEvent {
        base: BaseEventType,
        own_namespace_index: u16,
        // Some primitives
        float: f32,
        double: f64,
        string: String,
        status: StatusCode,
        // Option
        int: Option<i64>,
        int2: Option<u64>,
        // Vec
        vec: Vec<i64>,
        // OptVec
        optvec: Option<Vec<i32>>,
        // Complex type with message info
        kvp: KeyValuePair,
        euinfo: EUInformation,
    }

    fn namespace_map() -> NamespaceMap {
        let mut map = NamespaceMap::new();
        map.add_namespace("uri:my:namespace");
        map
    }

    fn get(id: &NodeId, evt: &dyn Event, field: &str) -> Variant {
        evt.get_field(id, AttributeId::Value, &NumericRange::None, &[field.into()])
    }

    fn get_nested(id: &NodeId, evt: &dyn Event, fields: &[&str]) -> Variant {
        let fields: Vec<QualifiedName> = fields.iter().map(|f| (*f).into()).collect();
        evt.get_field(id, AttributeId::Value, &NumericRange::None, &fields)
    }

    #[test]
    fn test_basic_values() {
        let namespaces = namespace_map();
        let mut evt = BasicValueEvent::new_event_now(
            BasicValueEvent::event_type_id(&namespaces),
            ByteString::from_base64("dGVzdA==").unwrap(),
            "Some message",
            &namespaces,
        );
        evt.float = 1.0;
        evt.double = 2.0;
        evt.string = "foo".to_owned();
        evt.status = StatusCode::BadMaxAgeInvalid;
        evt.kvp = KeyValuePair {
            key: "Key".into(),
            value: 123.into(),
        };
        evt.int = None;
        evt.int2 = Some(5);
        evt.vec = vec![1, 2, 3];
        evt.optvec = Some(vec![3, 2, 1]);
        evt.euinfo = EUInformation {
            namespace_uri: "uri:my:namespace".into(),
            unit_id: 15,
            display_name: "Some unit".into(),
            description: "Some unit desc".into(),
        };
        let id = BasicValueEvent::event_type_id(&namespaces);

        // Get for some other event
        assert_eq!(
            evt.get_field(
                &ObjectTypeId::ProgressEventType.into(),
                AttributeId::Value,
                &NumericRange::None,
                &["Message".into()],
            ),
            Variant::Empty
        );
        // Get a field that doesn't exist
        assert_eq!(
            evt.get_field(
                &id,
                AttributeId::Value,
                &NumericRange::None,
                &["FooBar".into()],
            ),
            Variant::Empty
        );
        // Get a child of a field without children
        assert_eq!(
            evt.get_field(
                &id,
                AttributeId::Value,
                &NumericRange::None,
                &["Float".into(), "Child".into()],
            ),
            Variant::Empty
        );
        // Get a non-value attribute
        assert_eq!(
            evt.get_field(
                &id,
                AttributeId::NodeId,
                &NumericRange::None,
                &["Float".into()],
            ),
            Variant::Empty
        );

        // Test equality for each field
        assert_eq!(get(&id, &evt, "Float"), Variant::from(1f32));
        assert_eq!(get(&id, &evt, "Double"), Variant::from(2.0));
        assert_eq!(get(&id, &evt, "String"), Variant::from("foo"));
        assert_eq!(
            get(&id, &evt, "Status"),
            Variant::from(StatusCode::BadMaxAgeInvalid)
        );
        let kvp: KeyValuePair = match get(&id, &evt, "Kvp") {
            Variant::ExtensionObject(o) => *o.into_inner_as().unwrap(),
            _ => panic!("Wrong variant type"),
        };
        assert_eq!(kvp.key, "Key".into());
        assert_eq!(kvp.value, 123.into());

        assert_eq!(get(&id, &evt, "Int"), Variant::Empty);
        assert_eq!(get(&id, &evt, "Int2"), Variant::from(5u64));
        assert_eq!(get(&id, &evt, "Vec"), Variant::from(vec![1i64, 2i64, 3i64]));
        assert_eq!(
            get(&id, &evt, "Optvec"),
            Variant::from(vec![3i32, 2i32, 1i32])
        );
        let euinfo: EUInformation = match get(&id, &evt, "Euinfo") {
            Variant::ExtensionObject(o) => *o.into_inner_as().unwrap(),
            _ => panic!("Wrong variant type"),
        };
        assert_eq!(euinfo.namespace_uri.as_ref(), "uri:my:namespace");
        assert_eq!(euinfo.unit_id, 15);
        assert_eq!(euinfo.display_name, "Some unit".into());
        assert_eq!(euinfo.description, "Some unit desc".into());
    }

    #[derive(EventField, Default, Debug)]
    struct ComplexEventField {
        float: f32,
    }

    #[derive(EventField, Default, Debug)]
    struct SubComplexEventField {
        base: ComplexEventField,
        node_id: NodeId,
        #[opcua(rename = "gnirtS")]
        string: UAString,
        #[opcua(ignore)]
        data: i32,
    }

    #[derive(EventField, Default, Debug)]
    struct ComplexVariable {
        node_id: NodeId,
        value: i32,
        id: u32,
        #[opcua(placeholder)]
        extra: PlaceholderEventField<i32>,
    }

    #[derive(Event)]
    #[opcua(identifier = "s=mynestedevent", namespace = "uri:my:namespace")]
    struct NestedEvent {
        base: BasicValueEvent,
        own_namespace_index: u16,
        complex: ComplexEventField,
        sub_complex: SubComplexEventField,
        var: ComplexVariable,
        #[opcua(ignore)]
        ignored: i32,
        #[opcua(rename = "Fancy Name")]
        renamed: String,
        #[opcua(placeholder)]
        extra_fields: PlaceholderEventField<SubComplexEventField>,
    }

    #[test]
    fn test_nested_values() {
        let namespaces = namespace_map();
        let mut evt = NestedEvent::new_event_now(
            NestedEvent::event_type_id(&namespaces),
            ByteString::from_base64("dGVzdA==").unwrap(),
            "Some message",
            &namespaces,
        );
        let id = NestedEvent::event_type_id(&namespaces);
        evt.base.float = 2f32;
        evt.complex.float = 3f32;
        evt.sub_complex.base.float = 4f32;
        evt.sub_complex.string = "foo".into();
        evt.sub_complex.data = 15;
        evt.ignored = 16;
        evt.renamed = "bar".to_owned();
        evt.sub_complex.node_id = NodeId::new(0, 15);
        evt.var.node_id = NodeId::new(0, 16);
        evt.var.value = 20;

        // Get field from middle event type
        assert_eq!(get(&id, &evt, "Float"), Variant::from(2f32));
        // Get from grandparent
        assert_eq!(
            get(&id, &evt, "Message"),
            Variant::from(LocalizedText::from("Some message"))
        );
        // Ignored fields should be skipped
        assert_eq!(get(&id, &evt, "Ignored"), Variant::Empty);
        assert_eq!(
            get_nested(&id, &evt, &["SubComplex", "Data"]),
            Variant::Empty
        );
        // Get renamed
        assert_eq!(get(&id, &evt, "Fancy Name"), Variant::from("bar"));
        assert_eq!(
            get_nested(&id, &evt, &["SubComplex", "gnirtS"]),
            Variant::from("foo")
        );
        // Get complex
        assert_eq!(
            get_nested(&id, &evt, &["Complex", "Float"]),
            Variant::from(3f32)
        );
        assert_eq!(
            get_nested(&id, &evt, &["SubComplex", "Float"]),
            Variant::from(4f32)
        );

        // Get node IDs
        assert_eq!(
            evt.get_field(
                &id,
                AttributeId::NodeId,
                &NumericRange::None,
                &["SubComplex".into()],
            ),
            Variant::from(NodeId::new(0, 15))
        );
        assert_eq!(
            evt.get_field(
                &id,
                AttributeId::NodeId,
                &NumericRange::None,
                &["Var".into()],
            ),
            Variant::from(NodeId::new(0, 16))
        );
        assert_eq!(
            evt.get_field(
                &id,
                AttributeId::Value,
                &NumericRange::None,
                &["Var".into()],
            ),
            Variant::from(20i32)
        );

        let name = QualifiedName::new(1, "Extra1");
        // Get from placeholders
        evt.extra_fields
            .insert_field(name.clone(), SubComplexEventField::default());
        evt.extra_fields.get_field_mut(&name).unwrap().base.float = 20f32;
        let name = QualifiedName::new(1, "Extra2");
        evt.extra_fields
            .insert_field(name.clone(), SubComplexEventField::default());
        evt.extra_fields.get_field_mut(&name).unwrap().base.float = 21f32;

        assert_eq!(
            evt.get_field(
                &id,
                AttributeId::Value,
                &NumericRange::None,
                &[QualifiedName::new(1, "Extra1"), "Float".into()],
            ),
            Variant::from(20f32)
        );
        assert_eq!(
            evt.get_field(
                &id,
                AttributeId::Value,
                &NumericRange::None,
                &[QualifiedName::new(1, "Extra2"), "Float".into()],
            ),
            Variant::from(21f32)
        );
        assert_eq!(
            evt.get_field(
                &id,
                AttributeId::Value,
                &NumericRange::None,
                &[QualifiedName::new(1, "Extra3"), "Float".into()],
            ),
            Variant::Empty
        );

        evt.var.extra.insert_field("Magic".into(), 15);
        assert_eq!(
            evt.get_field(
                &id,
                AttributeId::Value,
                &NumericRange::None,
                &["Var".into(), "Magic".into()],
            ),
            Variant::from(15)
        );
    }
}
