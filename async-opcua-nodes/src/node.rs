// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

use opcua_types::{
    status_code::StatusCode, AttributeId, DataEncoding, DataValue, LocalizedText, NodeClass,
    NodeId, NumericRange, QualifiedName, TimestampsToReturn, Variant, WriteMask,
};

use super::{DataType, Method, Object, ObjectType, ReferenceType, Variable, VariableType, View};

/// The `NodeType` enum enumerates the different OPC-UA node classes.
#[derive(Debug)]
pub enum NodeType {
    /// Objects are general structural nodes without special meaning.
    Object(Box<Object>),
    /// Object types define properties of object nodes.
    ObjectType(Box<ObjectType>),
    /// Reference types define properties of references.
    ReferenceType(Box<ReferenceType>),
    /// Variables are nodes with a current value that can be stored historically.
    Variable(Box<Variable>),
    /// Variable types define properties of variable nodes.
    VariableType(Box<VariableType>),
    /// Views are pre-defined subsets of the address space.
    View(Box<View>),
    /// Data types define different types used by variables.
    DataType(Box<DataType>),
    /// Methods are nodes that can be called with the `Call` service.
    Method(Box<Method>),
}

/// Trait for types that have a node ID.
pub trait HasNodeId {
    /// Get the node ID of this item.
    fn node_id(&self) -> &NodeId;
}

impl HasNodeId for NodeType {
    fn node_id(&self) -> &NodeId {
        self.as_node().node_id()
    }
}

impl NodeType {
    /// Get a reference to this as dyn [Node].
    pub fn as_node<'a>(&'a self) -> &'a (dyn Node + 'a) {
        match self {
            NodeType::Object(value) => value.as_ref(),
            NodeType::ObjectType(value) => value.as_ref(),
            NodeType::ReferenceType(value) => value.as_ref(),
            NodeType::Variable(value) => value.as_ref(),
            NodeType::VariableType(value) => value.as_ref(),
            NodeType::View(value) => value.as_ref(),
            NodeType::DataType(value) => value.as_ref(),
            NodeType::Method(value) => value.as_ref(),
        }
    }

    /// Get a reference to this as mut dyn [Node].
    pub fn as_mut_node(&mut self) -> &mut dyn Node {
        match self {
            NodeType::Object(ref mut value) => value.as_mut(),
            NodeType::ObjectType(ref mut value) => value.as_mut(),
            NodeType::ReferenceType(ref mut value) => value.as_mut(),
            NodeType::Variable(ref mut value) => value.as_mut(),
            NodeType::VariableType(ref mut value) => value.as_mut(),
            NodeType::View(ref mut value) => value.as_mut(),
            NodeType::DataType(ref mut value) => value.as_mut(),
            NodeType::Method(ref mut value) => value.as_mut(),
        }
    }

    /// Returns the [`NodeClass`] of this `NodeType`.
    pub fn node_class(&self) -> NodeClass {
        match self {
            NodeType::Object(_) => NodeClass::Object,
            NodeType::ObjectType(_) => NodeClass::ObjectType,
            NodeType::ReferenceType(_) => NodeClass::ReferenceType,
            NodeType::Variable(_) => NodeClass::Variable,
            NodeType::VariableType(_) => NodeClass::VariableType,
            NodeType::View(_) => NodeClass::View,
            NodeType::DataType(_) => NodeClass::DataType,
            NodeType::Method(_) => NodeClass::Method,
        }
    }
}

/// Implemented within a macro for all Node types. Functions that return a result in an Option
/// do so because the attribute is optional and not necessarily there.
pub trait NodeBase {
    /// Returns the node class - Object, ObjectType, Method, DataType, ReferenceType, Variable, VariableType or View
    fn node_class(&self) -> NodeClass;

    /// Returns the node's `NodeId`
    fn node_id(&self) -> &NodeId;

    /// Returns the node's browse name
    fn browse_name(&self) -> &QualifiedName;

    /// Returns the node's display name
    fn display_name(&self) -> &LocalizedText;

    /// Sets the node's display name
    fn set_display_name(&mut self, display_name: LocalizedText);

    /// Get the description of this node.
    fn description(&self) -> Option<&LocalizedText>;

    /// Set the description of this node.
    fn set_description(&mut self, description: LocalizedText);

    /// Get the write mask of this node.
    fn write_mask(&self) -> Option<WriteMask>;

    /// Set the write mask of this node.
    fn set_write_mask(&mut self, write_mask: WriteMask);

    /// Get the user write mask for this node.
    fn user_write_mask(&self) -> Option<WriteMask>;

    /// Set the user write mask for this node.
    fn set_user_write_mask(&mut self, write_mask: WriteMask);
}

/// Implemented by each node type's to provide a generic way to set or get attributes, e.g.
/// from the Attributes service set. Internal callers could call the setter / getter on the node
/// if they have access to them.
pub trait Node: NodeBase {
    /// Finds the attribute and value. The param `max_age` is a hint in milliseconds:
    ///
    /// * value 0, server shall attempt to read a new value from the data source
    /// * value >= i32::max(), sever shall attempt to get a cached value
    ///
    /// If there is a getter registered with the node, then the getter will interpret
    /// `max_age` how it sees fit.
    fn get_attribute_max_age(
        &self,
        timestamps_to_return: TimestampsToReturn,
        attribute_id: AttributeId,
        index_range: &NumericRange,
        data_encoding: &DataEncoding,
        max_age: f64,
    ) -> Option<DataValue>;

    /// Finds the attribute and value.
    fn get_attribute(
        &self,
        timestamps_to_return: TimestampsToReturn,
        attribute_id: AttributeId,
        index_range: &NumericRange,
        data_encoding: &DataEncoding,
    ) -> Option<DataValue> {
        self.get_attribute_max_age(
            timestamps_to_return,
            attribute_id,
            index_range,
            data_encoding,
            0f64,
        )
    }

    /// Sets the attribute with the new value
    fn set_attribute(
        &mut self,
        attribute_id: AttributeId,
        value: Variant,
    ) -> Result<(), StatusCode>;
}
