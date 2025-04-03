// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Contains the implementation of `ReferenceType` and `ReferenceTypeBuilder`.

use opcua_types::{
    AttributeId, AttributesMask, DataEncoding, DataValue, NumericRange, ReferenceTypeAttributes,
    StatusCode, TimestampsToReturn, Variant,
};
use tracing::error;

use crate::FromAttributesError;

use super::{base::Base, node::Node, node::NodeBase};

node_builder_impl!(ReferenceTypeBuilder, ReferenceType);
node_builder_impl_subtype!(ReferenceTypeBuilder);

impl ReferenceTypeBuilder {
    /// Set the `IsAbstract` attribute of this reference type,
    /// indicating whether references in the instance hierarchy
    /// are allowed to use this reference type.
    pub fn is_abstract(mut self, is_abstract: bool) -> Self {
        self.node.set_is_abstract(is_abstract);
        self
    }

    /// Set the write mask of this type.
    pub fn write_mask(mut self, write_mask: WriteMask) -> Self {
        self.node.set_write_mask(write_mask);
        self
    }

    /// Set whether references of this type are symmetric, meaning
    /// they have the same name in both directions.
    pub fn symmetric(mut self, symmetric: bool) -> Self {
        self.node.set_symmetric(symmetric);
        self
    }

    /// Set the inverse name of this reference type.
    pub fn inverse_name(mut self, inverse_name: impl Into<LocalizedText>) -> Self {
        self.node.set_inverse_name(inverse_name.into());
        self
    }
}

/// A `ReferenceType` is a type of node within the `AddressSpace`.
#[derive(Debug)]
pub struct ReferenceType {
    pub(super) base: Base,
    pub(super) symmetric: bool,
    pub(super) is_abstract: bool,
    pub(super) inverse_name: Option<LocalizedText>,
}

impl Default for ReferenceType {
    fn default() -> Self {
        Self {
            base: Base::new(NodeClass::ReferenceType, &NodeId::null(), "", ""),
            symmetric: false,
            is_abstract: false,
            inverse_name: None,
        }
    }
}

node_base_impl!(ReferenceType);

impl Node for ReferenceType {
    fn get_attribute_max_age(
        &self,
        timestamps_to_return: TimestampsToReturn,
        attribute_id: AttributeId,
        index_range: &NumericRange,
        data_encoding: &DataEncoding,
        max_age: f64,
    ) -> Option<DataValue> {
        match attribute_id {
            AttributeId::Symmetric => Some(self.symmetric().into()),
            AttributeId::IsAbstract => Some(self.is_abstract().into()),
            AttributeId::InverseName => self.inverse_name().map(|v| v.into()),
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
            AttributeId::Symmetric => {
                if let Variant::Boolean(v) = value {
                    self.symmetric = v;
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            AttributeId::IsAbstract => {
                if let Variant::Boolean(v) = value {
                    self.is_abstract = v;
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            AttributeId::InverseName => {
                if let Variant::LocalizedText(v) = value {
                    self.inverse_name = Some(*v);
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            _ => self.base.set_attribute(attribute_id, value),
        }
    }
}

impl ReferenceType {
    /// Create a new reference type.
    pub fn new(
        node_id: &NodeId,
        browse_name: impl Into<QualifiedName>,
        display_name: impl Into<LocalizedText>,
        inverse_name: Option<LocalizedText>,
        symmetric: bool,
        is_abstract: bool,
    ) -> ReferenceType {
        ReferenceType {
            base: Base::new(NodeClass::ReferenceType, node_id, browse_name, display_name),
            symmetric,
            is_abstract,
            inverse_name,
        }
    }

    /// Create a new reference type with all attributes, may change if
    /// new attributes are added to the OPC-UA standard.
    pub fn new_full(
        base: Base,
        symmetric: bool,
        is_abstract: bool,
        inverse_name: Option<LocalizedText>,
    ) -> Self {
        Self {
            base,
            symmetric,
            is_abstract,
            inverse_name,
        }
    }

    /// Create a new reference type from [ReferenceTypeAttributes].
    pub fn from_attributes(
        node_id: &NodeId,
        browse_name: impl Into<QualifiedName>,
        attributes: ReferenceTypeAttributes,
    ) -> Result<Self, FromAttributesError> {
        let mandatory_attributes =
            AttributesMask::DISPLAY_NAME | AttributesMask::IS_ABSTRACT | AttributesMask::SYMMETRIC;
        let mask = AttributesMask::from_bits(attributes.specified_attributes)
            .ok_or(FromAttributesError::InvalidMask)?;
        if mask.contains(mandatory_attributes) {
            let mut node = Self::new(
                node_id,
                browse_name,
                attributes.display_name,
                None,
                false,
                false,
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
            if mask.contains(AttributesMask::IS_ABSTRACT) {
                node.set_is_abstract(attributes.is_abstract);
            }
            if mask.contains(AttributesMask::SYMMETRIC) {
                node.set_symmetric(attributes.is_abstract);
            }
            if mask.contains(AttributesMask::INVERSE_NAME) {
                node.set_inverse_name(attributes.inverse_name);
            }
            Ok(node)
        } else {
            error!("ReferenceType cannot be created from attributes - missing mandatory values");
            Err(FromAttributesError::MissingMandatoryValues)
        }
    }

    /// Get whether this reference type is valid.
    pub fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    /// Get whether this reference type is symmetric.
    pub fn symmetric(&self) -> bool {
        self.symmetric
    }

    /// Set whether this reference type is symmetric.
    pub fn set_symmetric(&mut self, symmetric: bool) {
        self.symmetric = symmetric;
    }

    /// Get whether this reference type is abstract.
    pub fn is_abstract(&self) -> bool {
        self.is_abstract
    }

    /// Get whether this reference type is abstract.
    pub fn set_is_abstract(&mut self, is_abstract: bool) {
        self.is_abstract = is_abstract;
    }

    /// Get the inverse name of this reference type.
    pub fn inverse_name(&self) -> Option<LocalizedText> {
        self.inverse_name.clone()
    }

    /// Set the inverse name of this reference type.
    pub fn set_inverse_name(&mut self, inverse_name: LocalizedText) {
        self.inverse_name = Some(inverse_name);
    }
}
