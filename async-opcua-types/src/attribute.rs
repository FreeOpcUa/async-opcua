// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! The [`AttributeId`] enum, identifying OPC UA node attributes by a numeric value.
//!
//! Defined in Part 4, Figure B.7

// Attributes sometimes required and sometimes optional

use std::{error::Error, fmt};

use tracing::debug;

#[derive(Debug)]
/// Error returned when working with an Attribute ID.
pub struct AttributeIdError;

impl fmt::Display for AttributeIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AttributeIdError")
    }
}

impl Error for AttributeIdError {}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
#[repr(u32)]
/// Node attribute ID, from the OPC UA standard.
pub enum AttributeId {
    /// Node ID.
    NodeId = 1,
    /// Node class.
    NodeClass = 2,
    /// Browse name.
    BrowseName = 3,
    /// Display name.
    DisplayName = 4,
    /// Description.
    Description = 5,
    /// Write mask.
    WriteMask = 6,
    /// User write mask.
    UserWriteMask = 7,
    /// Is abstract.
    IsAbstract = 8,
    /// Is symmetric, applies to reference types.
    Symmetric = 9,
    /// Inverse name of reference type.
    InverseName = 10,
    /// For views, contains no loops.
    ContainsNoLoops = 11,
    /// Whether this object can produce events.
    EventNotifier = 12,
    /// Variable value.
    Value = 13,
    /// Data type.
    DataType = 14,
    /// Variable value rank.
    ValueRank = 15,
    /// Variable array dimensions.
    ArrayDimensions = 16,
    /// Variable access level.
    AccessLevel = 17,
    /// Variable user access level.
    UserAccessLevel = 18,
    /// Variable minimum sampling interval.
    MinimumSamplingInterval = 19,
    /// Whether a variable stores history.
    Historizing = 20,
    /// Whether this method is executable.
    Executable = 21,
    /// Whether this method is executable by the current user.
    UserExecutable = 22,
    /// Data type definition.
    DataTypeDefinition = 23,
    /// Role permissions.
    RolePermissions = 24,
    /// User role permissions.
    UserRolePermissions = 25,
    /// Access restrictions.
    AccessRestrictions = 26,
    /// Access level extension.
    AccessLevelEx = 27,
}

impl AttributeId {
    /// Try to get this attribute ID from a 32 bit integer.
    pub fn from_u32(attribute_id: u32) -> Result<AttributeId, AttributeIdError> {
        let attribute_id = match attribute_id {
            1 => AttributeId::NodeId,
            2 => AttributeId::NodeClass,
            3 => AttributeId::BrowseName,
            4 => AttributeId::DisplayName,
            5 => AttributeId::Description,
            6 => AttributeId::WriteMask,
            7 => AttributeId::UserWriteMask,
            8 => AttributeId::IsAbstract,
            9 => AttributeId::Symmetric,
            10 => AttributeId::InverseName,
            11 => AttributeId::ContainsNoLoops,
            12 => AttributeId::EventNotifier,
            13 => AttributeId::Value,
            14 => AttributeId::DataType,
            15 => AttributeId::ValueRank,
            16 => AttributeId::ArrayDimensions,
            17 => AttributeId::AccessLevel,
            18 => AttributeId::UserAccessLevel,
            19 => AttributeId::MinimumSamplingInterval,
            20 => AttributeId::Historizing,
            21 => AttributeId::Executable,
            22 => AttributeId::UserExecutable,
            23 => AttributeId::DataTypeDefinition,
            24 => AttributeId::RolePermissions,
            25 => AttributeId::UserRolePermissions,
            26 => AttributeId::AccessRestrictions,
            27 => AttributeId::AccessLevelEx,
            _ => {
                debug!("Invalid attribute id {}", attribute_id);
                return Err(AttributeIdError);
            }
        };
        Ok(attribute_id)
    }
}
