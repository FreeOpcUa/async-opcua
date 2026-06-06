// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Contains the implementation of `Method` and `MethodBuilder`.

use opcua_types::{
    AttributeId, AttributesMask, DataEncoding, DataTypeAttributes, DataTypeDefinition, DataValue,
    NumericRange, StatusCode, TimestampsToReturn, Variant,
};
use tracing::error;

use crate::FromAttributesError;

use super::{base::Base, node::Node, node::NodeBase};

node_builder_impl!(DataTypeBuilder, DataType);
node_builder_impl_subtype!(DataTypeBuilder);

impl DataTypeBuilder {
    /// Set whether the data type is abstract, meaning
    /// it cannot be used by nodes in the instance hierarchy.
    pub fn is_abstract(mut self, is_abstract: bool) -> Self {
        self.node.set_is_abstract(is_abstract);
        self
    }

    /// Set the data type write mask.
    pub fn write_mask(mut self, write_mask: WriteMask) -> Self {
        self.node.set_write_mask(write_mask);
        self
    }

    /// Set the data type definition.
    pub fn data_type_definition(mut self, data_type_definition: DataTypeDefinition) -> Self {
        self.node
            .set_data_type_definition(Some(data_type_definition));
        self
    }
}

/// A `DataType` is a type of node within the `AddressSpace`.
#[derive(Debug)]
pub struct DataType {
    pub(super) base: Base,
    pub(super) is_abstract: bool,
    pub(super) data_type_definition: Option<DataTypeDefinition>,
}

impl Default for DataType {
    fn default() -> Self {
        Self {
            base: Base::new(NodeClass::DataType, &NodeId::null(), "", ""),
            is_abstract: false,
            data_type_definition: None,
        }
    }
}

node_base_impl!(DataType);

impl Node for DataType {
    fn get_attribute_max_age(
        &self,
        timestamps_to_return: TimestampsToReturn,
        attribute_id: AttributeId,
        index_range: &NumericRange,
        data_encoding: &DataEncoding,
        max_age: f64,
    ) -> Option<DataValue> {
        match attribute_id {
            AttributeId::IsAbstract => Some(self.is_abstract().into()),
            AttributeId::DataTypeDefinition => self.data_type_definition.as_ref().map(|dt| {
                let v: Variant = dt.clone().into();
                v.into()
            }),
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
            AttributeId::IsAbstract => {
                if let Variant::Boolean(v) = value {
                    self.set_is_abstract(v);
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            AttributeId::DataTypeDefinition => {
                if matches!(value, Variant::Empty) {
                    self.set_data_type_definition(None);
                    Ok(())
                } else if let Variant::ExtensionObject(v) = value {
                    let def = DataTypeDefinition::from_extension_object(v)?;
                    self.set_data_type_definition(Some(def));
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            _ => self.base.set_attribute(attribute_id, value),
        }
    }
}

impl DataType {
    /// Create a new data type.
    pub fn new(
        node_id: &NodeId,
        browse_name: impl Into<QualifiedName>,
        display_name: impl Into<LocalizedText>,
        is_abstract: bool,
    ) -> DataType {
        DataType {
            base: Base::new(NodeClass::DataType, node_id, browse_name, display_name),
            is_abstract,
            data_type_definition: None,
        }
    }

    /// Create a new data type with all attributes, may change if
    /// new attributes are added to the OPC-UA standard.
    pub fn new_full(
        base: Base,
        is_abstract: bool,
        data_type_definition: Option<DataTypeDefinition>,
    ) -> Self {
        Self {
            base,
            is_abstract,
            data_type_definition,
        }
    }

    /// Create a new data type from [DataTypeAttributes].
    pub fn from_attributes(
        node_id: &NodeId,
        browse_name: impl Into<QualifiedName>,
        attributes: DataTypeAttributes,
    ) -> Result<Self, FromAttributesError> {
        let mask = AttributesMask::from_bits(attributes.specified_attributes)
            .ok_or(FromAttributesError::InvalidMask)?;
        if mask.contains(AttributesMask::DISPLAY_NAME | AttributesMask::IS_ABSTRACT) {
            let mut node = Self::new(
                node_id,
                browse_name,
                attributes.display_name,
                attributes.is_abstract,
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
            error!("DataType cannot be created from attributes - missing mandatory values");
            Err(FromAttributesError::MissingMandatoryValues)
        }
    }

    /// Get whether this data type is valid.
    pub fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    /// Get the `IsAbstract` attribute for this data type.
    pub fn is_abstract(&self) -> bool {
        self.is_abstract
    }

    /// Set the `IsAbstract` attribute for this data type.
    pub fn set_is_abstract(&mut self, is_abstract: bool) {
        self.is_abstract = is_abstract;
    }

    /// Set the data type definition of this data type.
    pub fn set_data_type_definition(&mut self, data_type_definition: Option<DataTypeDefinition>) {
        self.data_type_definition = data_type_definition;
    }

    /// Get the data type definition of this data type.
    pub fn data_type_definition(&self) -> Option<&DataTypeDefinition> {
        self.data_type_definition.as_ref()
    }
}
