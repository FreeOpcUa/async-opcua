// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Contains the implementation of `Method` and `MethodBuilder`.

use opcua_types::{
    Argument, AttributeId, AttributesMask, DataEncoding, DataTypeId, DataValue, ExtensionObject,
    MethodAttributes, NumericRange, StatusCode, TimestampsToReturn, VariableTypeId, Variant,
    VariantScalarTypeId,
};
use tracing::error;

use crate::{FromAttributesError, NodeInsertTarget};

use super::{
    base::Base,
    node::{Node, NodeBase},
    variable::VariableBuilder,
};

node_builder_impl!(MethodBuilder, Method);
node_builder_impl_component_of!(MethodBuilder);
node_builder_impl_generates_event!(MethodBuilder);

impl MethodBuilder {
    /// Specify output arguments from the method. This will create an OutputArguments
    /// variable child of the method which describes the out parameters.
    pub fn output_args(
        self,
        address_space: &mut impl NodeInsertTarget,
        node_id: &NodeId,
        arguments: &[Argument],
    ) -> Self {
        self.insert_args(node_id, "OutputArguments", address_space, arguments);
        self
    }

    /// Specify input arguments to the method. This will create an InputArguments
    /// variable child of the method which describes the in parameters.
    pub fn input_args(
        self,
        address_space: &mut impl NodeInsertTarget,
        node_id: &NodeId,
        arguments: &[Argument],
    ) -> Self {
        self.insert_args(node_id, "InputArguments", address_space, arguments);
        self
    }

    /// Set whether this method is executable, meaning it can be
    /// called by users at all.
    pub fn executable(mut self, executable: bool) -> Self {
        self.node.set_executable(executable);
        self
    }

    /// Set whether this method is executable by the current user.
    /// This value is usually modified by the server depending on the
    /// user asking for it.
    pub fn user_executable(mut self, executable: bool) -> Self {
        self.node.set_user_executable(executable);
        self
    }

    /// Set the write mask for this method.
    pub fn write_mask(mut self, write_mask: WriteMask) -> Self {
        self.node.set_write_mask(write_mask);
        self
    }

    fn args_to_variant(arguments: &[Argument]) -> Variant {
        let arguments = arguments
            .iter()
            .map(|arg| Variant::from(ExtensionObject::from_message(arg.clone())))
            .collect::<Vec<Variant>>();
        Variant::from((VariantScalarTypeId::ExtensionObject, arguments))
    }

    fn insert_args(
        &self,
        node_id: &NodeId,
        args_name: &str,
        address_space: &mut impl NodeInsertTarget,
        arguments: &[Argument],
    ) {
        let fn_node_id = self.node.node_id();
        let args_value = Self::args_to_variant(arguments);
        VariableBuilder::new(node_id, args_name, args_name)
            .property_of(fn_node_id)
            .has_type_definition(VariableTypeId::PropertyType)
            .data_type(DataTypeId::Argument)
            .value_rank(1)
            .array_dimensions(&[arguments.len() as u32])
            .value(args_value)
            .insert(address_space);
    }
}

/// A `Method` is a type of node within the `AddressSpace`.
#[derive(Debug)]
pub struct Method {
    pub(super) base: Base,
    pub(super) executable: bool,
    pub(super) user_executable: bool,
}

impl Default for Method {
    fn default() -> Self {
        Self {
            base: Base::new(NodeClass::Method, &NodeId::null(), "", ""),
            executable: false,
            user_executable: false,
        }
    }
}

node_base_impl!(Method);

impl Node for Method {
    fn get_attribute_max_age(
        &self,
        timestamps_to_return: TimestampsToReturn,
        attribute_id: AttributeId,
        index_range: &NumericRange,
        data_encoding: &DataEncoding,
        max_age: f64,
    ) -> Option<DataValue> {
        match attribute_id {
            AttributeId::Executable => Some(self.executable().into()),
            AttributeId::UserExecutable => Some(self.user_executable().into()),
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
            AttributeId::Executable => {
                if let Variant::Boolean(v) = value {
                    self.set_executable(v);
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            AttributeId::UserExecutable => {
                if let Variant::Boolean(v) = value {
                    self.set_user_executable(v);
                    Ok(())
                } else {
                    Err(StatusCode::BadTypeMismatch)
                }
            }
            _ => self.base.set_attribute(attribute_id, value),
        }
    }
}

impl Method {
    /// Create a new method.
    pub fn new(
        node_id: &NodeId,
        browse_name: impl Into<QualifiedName>,
        display_name: impl Into<LocalizedText>,
        executable: bool,
        user_executable: bool,
    ) -> Method {
        Method {
            base: Base::new(NodeClass::Method, node_id, browse_name, display_name),
            executable,
            user_executable,
        }
    }

    /// Create a new method with all attributes, may change if
    /// new attributes are added to the OPC-UA standard.
    pub fn new_full(base: Base, executable: bool, user_executable: bool) -> Self {
        Self {
            base,
            executable,
            user_executable,
        }
    }

    /// Create a new method from [MethodAttributes].
    pub fn from_attributes(
        node_id: &NodeId,
        browse_name: impl Into<QualifiedName>,
        attributes: MethodAttributes,
    ) -> Result<Self, FromAttributesError> {
        let mandatory_attributes = AttributesMask::DISPLAY_NAME
            | AttributesMask::EXECUTABLE
            | AttributesMask::USER_EXECUTABLE;
        let mask = AttributesMask::from_bits(attributes.specified_attributes)
            .ok_or(FromAttributesError::InvalidMask)?;
        if mask.contains(mandatory_attributes) {
            let mut node = Self::new(
                node_id,
                browse_name,
                attributes.display_name,
                attributes.executable,
                attributes.user_executable,
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
            error!("Method cannot be created from attributes - missing mandatory values");
            Err(FromAttributesError::MissingMandatoryValues)
        }
    }

    /// Get whether this method is valid.
    pub fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    /// Get whether this method is executable.
    pub fn executable(&self) -> bool {
        self.executable
    }

    /// Set whether this method is executable.
    pub fn set_executable(&mut self, executable: bool) {
        self.executable = executable;
    }

    /// Get whether this method is executable by the current user by default.
    pub fn user_executable(&self) -> bool {
        // User executable cannot be true unless executable is true
        self.executable && self.user_executable
    }

    /// Set whether this method is executable by the current user by default.
    pub fn set_user_executable(&mut self, user_executable: bool) {
        self.user_executable = user_executable;
    }
}
