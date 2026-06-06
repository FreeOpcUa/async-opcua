// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Contains the implementation of `View` and `ViewBuilder`.
use opcua_types::{
    AttributeId, AttributesMask, DataEncoding, DataValue, NumericRange, StatusCode,
    TimestampsToReturn, Variant, ViewAttributes,
};
use tracing::error;

use crate::FromAttributesError;

use super::{base::Base, node::Node, node::NodeBase, EventNotifier};

node_builder_impl!(ViewBuilder, View);

node_builder_impl_generates_event!(ViewBuilder);

impl ViewBuilder {
    /// Set whether the view contains no loops.
    pub fn contains_no_loops(mut self, contains_no_loops: bool) -> Self {
        self.node.set_contains_no_loops(contains_no_loops);
        self
    }

    /// Set view event notifier.
    pub fn event_notifier(mut self, event_notifier: EventNotifier) -> Self {
        self.node.set_event_notifier(event_notifier);
        self
    }

    /// Set view write mask.
    pub fn write_mask(mut self, write_mask: WriteMask) -> Self {
        self.node.set_write_mask(write_mask);
        self
    }
}

/// A `View` is a type of node within the `AddressSpace`.
#[derive(Debug)]
pub struct View {
    pub(super) base: Base,
    pub(super) event_notifier: EventNotifier,
    pub(super) contains_no_loops: bool,
}

impl Default for View {
    fn default() -> Self {
        Self {
            base: Base::new(NodeClass::View, &NodeId::null(), "", ""),
            event_notifier: EventNotifier::empty(),
            contains_no_loops: true,
        }
    }
}

node_base_impl!(View);

impl Node for View {
    fn get_attribute_max_age(
        &self,
        timestamps_to_return: TimestampsToReturn,
        attribute_id: AttributeId,
        index_range: &NumericRange,
        data_encoding: &DataEncoding,
        max_age: f64,
    ) -> Option<DataValue> {
        match attribute_id {
            AttributeId::EventNotifier => Some(Variant::from(self.event_notifier().bits()).into()),
            AttributeId::ContainsNoLoops => Some(Variant::from(self.contains_no_loops()).into()),
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
            AttributeId::ContainsNoLoops => {
                if let Variant::Boolean(v) = value {
                    self.set_contains_no_loops(v);
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            _ => self.base.set_attribute(attribute_id, value),
        }
    }
}

impl View {
    /// Create a new view.
    pub fn new(
        node_id: &NodeId,
        browse_name: impl Into<QualifiedName>,
        display_name: impl Into<LocalizedText>,
        event_notifier: EventNotifier,
        contains_no_loops: bool,
    ) -> View {
        View {
            base: Base::new(NodeClass::View, node_id, browse_name, display_name),
            event_notifier,
            contains_no_loops,
        }
    }

    /// Create a new view from the full `Base` node.
    pub fn new_full(base: Base, event_notifier: EventNotifier, contains_no_loops: bool) -> Self {
        Self {
            base,
            event_notifier,
            contains_no_loops,
        }
    }

    /// Create a new view from [ViewAttributes].
    pub fn from_attributes(
        node_id: &NodeId,
        browse_name: impl Into<QualifiedName>,
        attributes: ViewAttributes,
    ) -> Result<Self, FromAttributesError> {
        let mandatory_attributes = AttributesMask::DISPLAY_NAME
            | AttributesMask::EVENT_NOTIFIER
            | AttributesMask::CONTAINS_NO_LOOPS;
        let mask = AttributesMask::from_bits_truncate(attributes.specified_attributes);
        if mask.contains(mandatory_attributes) {
            let event_notifier = EventNotifier::from_bits_truncate(attributes.event_notifier);
            let mut node = Self::new(
                node_id,
                browse_name,
                attributes.display_name,
                event_notifier,
                attributes.contains_no_loops,
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
            error!("View cannot be created from attributes - missing mandatory values");
            Err(FromAttributesError::MissingMandatoryValues)
        }
    }

    /// Check whether this node is valid.
    pub fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    /// Get the event notifier of this view.
    pub fn event_notifier(&self) -> EventNotifier {
        self.event_notifier
    }

    /// Set the event notifier of this view.
    pub fn set_event_notifier(&mut self, event_notifier: EventNotifier) {
        self.event_notifier = event_notifier;
    }

    /// Get the `ContainsNoLoops` attribute of this view.
    pub fn contains_no_loops(&self) -> bool {
        self.contains_no_loops
    }

    /// Set the `ContainsNoLoops` attribute on this view.
    pub fn set_contains_no_loops(&mut self, contains_no_loops: bool) {
        self.contains_no_loops = contains_no_loops
    }
}
