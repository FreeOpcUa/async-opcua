// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Contains the implementation of `Object` and `ObjectBuilder`.

use opcua_types::{
    AttributeId, AttributesMask, DataEncoding, DataValue, NumericRange, ObjectAttributes,
    ObjectTypeId, StatusCode, TimestampsToReturn, Variant,
};
use tracing::error;

use crate::FromAttributesError;

use super::{base::Base, node::Node, node::NodeBase, EventNotifier};

node_builder_impl!(ObjectBuilder, Object);
node_builder_impl_component_of!(ObjectBuilder);
node_builder_impl_property_of!(ObjectBuilder);

impl ObjectBuilder {
    /// Get whether this is building an object with `FolderType` as the
    /// type definition.
    pub fn is_folder(self) -> Self {
        self.has_type_definition(ObjectTypeId::FolderType)
    }

    /// Set the event notifier of the object.
    pub fn event_notifier(mut self, event_notifier: EventNotifier) -> Self {
        self.node.set_event_notifier(event_notifier);
        self
    }

    /// Set the write mask of the object.
    pub fn write_mask(mut self, write_mask: WriteMask) -> Self {
        self.node.set_write_mask(write_mask);
        self
    }

    /// Add a `HasTypeDefinition` reference to the given object type.
    pub fn has_type_definition(self, type_id: impl Into<NodeId>) -> Self {
        self.reference(
            type_id,
            ReferenceTypeId::HasTypeDefinition,
            ReferenceDirection::Forward,
        )
    }

    /// Add a `HasEventSource` reference to the given node.
    pub fn has_event_source(self, source_id: impl Into<NodeId>) -> Self {
        self.reference(
            source_id,
            ReferenceTypeId::HasEventSource,
            ReferenceDirection::Forward,
        )
    }
}

/// An `Object` is a type of node within the `AddressSpace`.
#[derive(Debug)]
pub struct Object {
    pub(super) base: Base,
    pub(super) event_notifier: EventNotifier,
}

impl Default for Object {
    fn default() -> Self {
        Self {
            base: Base::new(NodeClass::Object, &NodeId::null(), "", ""),
            event_notifier: EventNotifier::empty(),
        }
    }
}

node_base_impl!(Object);

impl Node for Object {
    fn get_attribute_max_age(
        &self,
        timestamps_to_return: TimestampsToReturn,
        attribute_id: AttributeId,
        index_range: &NumericRange,
        data_encoding: &DataEncoding,
        max_age: f64,
    ) -> Option<DataValue> {
        match attribute_id {
            AttributeId::EventNotifier => Some(self.event_notifier().bits().into()),
            _ => self.base.get_attribute_max_age(
                timestamps_to_return,
                attribute_id,
                index_range,
                data_encoding,
                max_age,
            ),
        }
    }

    fn set_attribute(
        &mut self,
        attribute_id: AttributeId,
        value: Variant,
    ) -> Result<(), StatusCode> {
        match attribute_id {
            AttributeId::EventNotifier => {
                if let Variant::Byte(v) = value {
                    self.set_event_notifier(EventNotifier::from_bits_truncate(v));
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            _ => self.base.set_attribute(attribute_id, value),
        }
    }
}

impl Object {
    /// Create a new object.
    pub fn new(
        node_id: &NodeId,
        browse_name: impl Into<QualifiedName>,
        display_name: impl Into<LocalizedText>,
        event_notifier: EventNotifier,
    ) -> Object {
        Object {
            base: Base::new(NodeClass::Object, node_id, browse_name, display_name),
            event_notifier,
        }
    }

    /// Create a new object with all attributes, may change if
    /// new attributes are added to the OPC-UA standard.
    pub fn new_full(base: Base, event_notifier: EventNotifier) -> Self {
        Self {
            base,
            event_notifier,
        }
    }

    /// Create a new object from [ObjectAttributes].
    pub fn from_attributes(
        node_id: &NodeId,
        browse_name: impl Into<QualifiedName>,
        attributes: ObjectAttributes,
    ) -> Result<Self, FromAttributesError> {
        let mandatory_attributes = AttributesMask::DISPLAY_NAME | AttributesMask::EVENT_NOTIFIER;

        let mask = AttributesMask::from_bits(attributes.specified_attributes)
            .ok_or(FromAttributesError::InvalidMask)?;
        if mask.contains(mandatory_attributes) {
            let event_notifier = EventNotifier::from_bits_truncate(attributes.event_notifier);
            let mut node = Self::new(
                node_id,
                browse_name,
                attributes.display_name,
                event_notifier,
            );
            if mask.contains(AttributesMask::DESCRIPTION) {
                node.set_description(attributes.description);
            }
            if mask.contains(AttributesMask::WRITE_MASK) {
                node.set_write_mask(WriteMask::from_bits_truncate(attributes.write_mask));
            }
            if mask.contains(AttributesMask::USER_WRITE_MASK) {
                node.set_user_write_mask(WriteMask::from_bits_truncate(attributes.user_write_mask));
            }
            Ok(node)
        } else {
            error!("Object cannot be created from attributes - missing mandatory values");
            Err(FromAttributesError::MissingMandatoryValues)
        }
    }

    /// Get whether this object is valid.
    pub fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    /// Get the event notifier status of this object.
    pub fn event_notifier(&self) -> EventNotifier {
        self.event_notifier
    }

    /// Set the event notifier status of this object.
    pub fn set_event_notifier(&mut self, event_notifier: EventNotifier) {
        self.event_notifier = event_notifier;
    }
}
