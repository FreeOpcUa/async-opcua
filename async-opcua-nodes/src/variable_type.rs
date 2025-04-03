// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Contains the implementation of `VariableType` and `VariableTypeBuilder`.

use opcua_types::{
    AttributeId, AttributesMask, DataEncoding, DataValue, NumericRange, StatusCode,
    TimestampsToReturn, TryFromVariant, VariableTypeAttributes, Variant,
};
use tracing::error;

use crate::FromAttributesError;

use super::{base::Base, node::Node, node::NodeBase};

node_builder_impl!(VariableTypeBuilder, VariableType);

node_builder_impl_generates_event!(VariableTypeBuilder);
node_builder_impl_subtype!(VariableTypeBuilder);

impl VariableTypeBuilder {
    /// Set whether the variable type is abstract, meaning
    /// it cannot be used by nodes in the instance hierarchy.
    pub fn is_abstract(mut self, is_abstract: bool) -> Self {
        self.node.set_is_abstract(is_abstract);
        self
    }

    /// Set the variable type write mask.
    pub fn write_mask(mut self, write_mask: WriteMask) -> Self {
        self.node.set_write_mask(write_mask);
        self
    }

    /// Set the base data type for instances of this type.
    pub fn data_type(mut self, data_type: impl Into<NodeId>) -> Self {
        self.node.set_data_type(data_type);
        self
    }

    /// Set the default value for instances of this type.
    pub fn value(mut self, value: impl Into<Variant>) -> Self {
        self.node.set_value(value);
        self
    }

    /// Set the array dimensions of this type.
    pub fn array_dimensions(mut self, array_dimensions: &[u32]) -> Self {
        self.node.set_array_dimensions(array_dimensions);
        self
    }

    /// Set the value rank of this type.
    pub fn value_rank(mut self, value_rank: i32) -> Self {
        self.node.set_value_rank(value_rank);
        self
    }
}

/// A `VariableType` is a type of node within the `AddressSpace`.
#[derive(Debug)]
pub struct VariableType {
    pub(super) base: Base,
    pub(super) data_type: NodeId,
    pub(super) is_abstract: bool,
    pub(super) value_rank: i32,
    pub(super) value: Option<DataValue>,
    pub(super) array_dimensions: Option<Vec<u32>>,
}

impl Default for VariableType {
    fn default() -> Self {
        Self {
            base: Base::new(NodeClass::VariableType, &NodeId::null(), "", ""),
            data_type: NodeId::null(),
            is_abstract: false,
            value_rank: -1,
            value: None,
            array_dimensions: None,
        }
    }
}

node_base_impl!(VariableType);

impl Node for VariableType {
    fn get_attribute_max_age(
        &self,
        timestamps_to_return: TimestampsToReturn,
        attribute_id: AttributeId,
        index_range: &NumericRange,
        data_encoding: &DataEncoding,
        max_age: f64,
    ) -> Option<DataValue> {
        match attribute_id {
            AttributeId::Value => self.value().cloned(),
            AttributeId::DataType => Some(self.data_type().clone().into()),
            AttributeId::IsAbstract => Some(self.is_abstract().into()),
            AttributeId::ValueRank => Some(self.value_rank().into()),
            // Optional attributes
            AttributeId::ArrayDimensions => self.array_dimensions().map(DataValue::value_only),
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
            AttributeId::DataType => {
                if let Variant::NodeId(v) = value {
                    self.set_data_type(*v);
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            AttributeId::IsAbstract => {
                if let Variant::Boolean(v) = value {
                    self.set_is_abstract(v);
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            AttributeId::ValueRank => {
                if let Variant::Int32(v) = value {
                    self.set_value_rank(v);
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            AttributeId::Value => {
                self.set_value(value);
                Ok(())
            }
            AttributeId::ArrayDimensions => {
                let array_dimensions = <Vec<u32>>::try_from_variant(value);
                if let Ok(array_dimensions) = array_dimensions {
                    self.set_array_dimensions(&array_dimensions);
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            _ => self.base.set_attribute(attribute_id, value),
        }
    }
}

impl VariableType {
    /// Create a new variable type node.
    pub fn new(
        node_id: &NodeId,
        browse_name: impl Into<QualifiedName>,
        display_name: impl Into<LocalizedText>,
        data_type: NodeId,
        is_abstract: bool,
        value_rank: i32,
    ) -> VariableType {
        VariableType {
            base: Base::new(NodeClass::VariableType, node_id, browse_name, display_name),
            data_type,
            is_abstract,
            value_rank,
            value: None,
            array_dimensions: None,
        }
    }

    /// Create a new variable type with all attributes, may change if
    /// new attributes are added to the OPC-UA standard.
    pub fn new_full(
        base: Base,
        data_type: NodeId,
        is_abstract: bool,
        value_rank: i32,
        value: Option<DataValue>,
        array_dimensions: Option<Vec<u32>>,
    ) -> Self {
        Self {
            base,
            data_type,
            is_abstract,
            value,
            value_rank,
            array_dimensions,
        }
    }

    /// Create a new variable type from [VariableTypeAttributes].
    pub fn from_attributes(
        node_id: &NodeId,
        browse_name: impl Into<QualifiedName>,
        attributes: VariableTypeAttributes,
    ) -> Result<Self, FromAttributesError> {
        let mandatory_attributes = AttributesMask::DISPLAY_NAME
            | AttributesMask::IS_ABSTRACT
            | AttributesMask::DATA_TYPE
            | AttributesMask::VALUE_RANK;
        let mask = AttributesMask::from_bits(attributes.specified_attributes)
            .ok_or(FromAttributesError::InvalidMask)?;
        if mask.contains(mandatory_attributes) {
            let mut node = Self::new(
                node_id,
                browse_name,
                attributes.display_name,
                attributes.data_type,
                attributes.is_abstract,
                attributes.value_rank,
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
            if mask.contains(AttributesMask::VALUE) {
                node.set_value(attributes.value);
            }
            if mask.contains(AttributesMask::ARRAY_DIMENSIONS) {
                node.set_array_dimensions(attributes.array_dimensions.unwrap().as_slice());
            }
            Ok(node)
        } else {
            error!("VariableType cannot be created from attributes - missing mandatory values");
            Err(FromAttributesError::MissingMandatoryValues)
        }
    }

    /// Get whether this type is valid.
    pub fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    /// Get the data type of this variable type.
    pub fn data_type(&self) -> &NodeId {
        &self.data_type
    }

    /// Set the data type of this variable type.
    pub fn set_data_type(&mut self, data_type: impl Into<NodeId>) {
        self.data_type = data_type.into();
    }

    /// Get the `IsAbstract` attribute for this variable type.
    pub fn is_abstract(&self) -> bool {
        self.is_abstract
    }

    /// Set the `IsAbstract` attribute for this variable type.
    pub fn set_is_abstract(&mut self, is_abstract: bool) {
        self.is_abstract = is_abstract;
    }

    /// Get the value rank of this variable type.
    pub fn value_rank(&self) -> i32 {
        self.value_rank
    }

    /// Set the value rank of this variable type.
    pub fn set_value_rank(&mut self, value_rank: i32) {
        self.value_rank = value_rank;
    }

    /// Get the array dimensions of this type.
    pub fn array_dimensions(&self) -> Option<Vec<u32>> {
        self.array_dimensions.clone()
    }

    /// Set the array dimensions of this type.
    pub fn set_array_dimensions(&mut self, array_dimensions: &[u32]) {
        self.array_dimensions = Some(array_dimensions.to_vec());
    }

    /// Get the default value for instances of this type.
    pub fn value(&self) -> Option<&DataValue> {
        self.value.as_ref()
    }

    /// Set the default value for instances of this type.
    pub fn set_value(&mut self, value: impl Into<Variant>) {
        self.value = Some(DataValue::new_now(value));
    }

    /// Set the default value for instances of this type to
    /// a full data value.
    pub fn set_data_value(&mut self, value: DataValue) {
        self.value = Some(value);
    }
}
