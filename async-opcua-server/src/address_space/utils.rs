use crate::node_manager::{ParsedReadValueId, ParsedWriteValue, RequestContext, ServerContext};
use opcua_nodes::TypeTree;
use opcua_types::{
    AttributeId, DataEncoding, DataTypeId, DataValue, DateTime, NumericRange, StatusCode,
    TimestampsToReturn, Variant, WriteMask,
};
use tracing::debug;

use super::{AccessLevel, AddressSpace, HasNodeId, NodeType, Variable};

/// Validate that the user given by `context` can read the value
/// of the given node.
pub fn is_readable(context: &RequestContext, node: &NodeType) -> Result<(), StatusCode> {
    if !user_access_level(context, node).contains(AccessLevel::CURRENT_READ) {
        Err(StatusCode::BadUserAccessDenied)
    } else {
        Ok(())
    }
}

/// Validate that the user given by `context` can write to the
/// attribute given by `attribute_id`.
pub fn is_writable(
    context: &RequestContext,
    node: &NodeType,
    attribute_id: AttributeId,
) -> Result<(), StatusCode> {
    if let (NodeType::Variable(_), AttributeId::Value) = (node, attribute_id) {
        if !user_access_level(context, node).contains(AccessLevel::CURRENT_WRITE) {
            return Err(StatusCode::BadUserAccessDenied);
        }

        Ok(())
    } else {
        let mask_value = match attribute_id {
            // The default address space does not support modifying node class or node id,
            // Custom node managers are allowed to.
            AttributeId::BrowseName => WriteMask::BROWSE_NAME,
            AttributeId::DisplayName => WriteMask::DISPLAY_NAME,
            AttributeId::Description => WriteMask::DESCRIPTION,
            AttributeId::WriteMask => WriteMask::WRITE_MASK,
            AttributeId::UserWriteMask => WriteMask::USER_WRITE_MASK,
            AttributeId::IsAbstract => WriteMask::IS_ABSTRACT,
            AttributeId::Symmetric => WriteMask::SYMMETRIC,
            AttributeId::InverseName => WriteMask::INVERSE_NAME,
            AttributeId::ContainsNoLoops => WriteMask::CONTAINS_NO_LOOPS,
            AttributeId::EventNotifier => WriteMask::EVENT_NOTIFIER,
            AttributeId::Value => WriteMask::VALUE_FOR_VARIABLE_TYPE,
            AttributeId::DataType => WriteMask::DATA_TYPE,
            AttributeId::ValueRank => WriteMask::VALUE_RANK,
            AttributeId::ArrayDimensions => WriteMask::ARRAY_DIMENSIONS,
            AttributeId::AccessLevel => WriteMask::ACCESS_LEVEL,
            AttributeId::UserAccessLevel => WriteMask::USER_ACCESS_LEVEL,
            AttributeId::MinimumSamplingInterval => WriteMask::MINIMUM_SAMPLING_INTERVAL,
            AttributeId::Historizing => WriteMask::HISTORIZING,
            AttributeId::Executable => WriteMask::EXECUTABLE,
            AttributeId::UserExecutable => WriteMask::USER_EXECUTABLE,
            AttributeId::DataTypeDefinition => WriteMask::DATA_TYPE_DEFINITION,
            AttributeId::RolePermissions => WriteMask::ROLE_PERMISSIONS,
            AttributeId::AccessRestrictions => WriteMask::ACCESS_RESTRICTIONS,
            AttributeId::AccessLevelEx => WriteMask::ACCESS_LEVEL_EX,
            _ => return Err(StatusCode::BadNotWritable),
        };

        let write_mask = node.as_node().write_mask();
        if write_mask.is_none() || write_mask.is_some_and(|wm| !wm.contains(mask_value)) {
            return Err(StatusCode::BadNotWritable);
        }
        Ok(())
    }
}

/// Get the effective user access level for `node`.
pub fn user_access_level(context: &RequestContext, node: &NodeType) -> AccessLevel {
    let user_access_level = if let NodeType::Variable(ref node) = node {
        node.user_access_level()
    } else {
        AccessLevel::CURRENT_READ
    };
    context.authenticator.effective_user_access_level(
        &context.token,
        user_access_level,
        node.node_id(),
    )
}

/// Validate that the user given by `context` is allowed to read
/// the value of `node`.
pub fn validate_node_read(
    node: &NodeType,
    context: &RequestContext,
    node_to_read: &ParsedReadValueId,
) -> Result<(), StatusCode> {
    is_readable(context, node)?;

    if node_to_read.attribute_id != AttributeId::Value
        && node_to_read.index_range != NumericRange::None
    {
        return Err(StatusCode::BadIndexRangeDataMismatch);
    }

    if !is_supported_data_encoding(&node_to_read.data_encoding) {
        debug!(
            "read_node_value result for read node id {}, attribute {:?} is invalid data encoding",
            node_to_read.node_id, node_to_read.attribute_id
        );
        return Err(StatusCode::BadDataEncodingInvalid);
    }

    Ok(())
}

/// Validate `value`, verifying that it can be written as the value of
/// `variable`.
pub fn validate_value_to_write(
    variable: &Variable,
    value: &Variant,
    type_tree: &dyn TypeTree,
) -> Result<(), StatusCode> {
    let value_rank = variable.value_rank();
    let node_data_type = variable.data_type();

    if matches!(value, Variant::Empty) {
        return Ok(());
    }

    if let Some(value_data_type) = value.data_type() {
        let Some(data_type) = value_data_type.try_resolve(type_tree.namespaces()) else {
            return Err(StatusCode::BadTypeMismatch);
        };
        // Value is scalar, check if the data type matches
        let data_type_matches = type_tree.is_subtype_of(&data_type, &node_data_type);

        if !data_type_matches {
            if value.is_array() {
                return Err(StatusCode::BadTypeMismatch);
            }
            // Check if the value to write is a byte string and the receiving node type a byte array.
            // This code is a mess just for some weird edge case in the spec that a write from
            // a byte string to a byte array should succeed
            match value {
                Variant::ByteString(_) => {
                    if node_data_type == DataTypeId::Byte {
                        match value_rank {
                            -2 | -3 | 1 => Ok(()),
                            _ => Err(StatusCode::BadTypeMismatch),
                        }
                    } else {
                        Err(StatusCode::BadTypeMismatch)
                    }
                }
                _ => Ok(()),
            }
        } else {
            Ok(())
        }
    } else {
        Err(StatusCode::BadTypeMismatch)
    }
}

/// Validate that the user given by `context` can write to the attribute given
/// by `node_to_write` on `node`.
pub fn validate_node_write(
    node: &NodeType,
    context: &RequestContext,
    node_to_write: &ParsedWriteValue,
    type_tree: &dyn TypeTree,
) -> Result<(), StatusCode> {
    is_writable(context, node, node_to_write.attribute_id)?;

    if node_to_write.attribute_id != AttributeId::Value && node_to_write.index_range.has_range() {
        return Err(StatusCode::BadWriteNotSupported);
    }

    let Some(value) = node_to_write.value.value.as_ref() else {
        return Err(StatusCode::BadTypeMismatch);
    };

    // TODO: We should do type validation for every attribute, not just value.
    if let (NodeType::Variable(var), AttributeId::Value) = (node, node_to_write.attribute_id) {
        validate_value_to_write(var, value, type_tree)?;
    }

    Ok(())
}

/// Return `true` if we support the given data encoding.
///
/// We currently only support `Binary`.
pub fn is_supported_data_encoding(data_encoding: &DataEncoding) -> bool {
    matches!(data_encoding, DataEncoding::Binary)
}

/// Invoke `Read` for the given `node_to_read` on `node`.
///
/// This can return a data value containing an error if validation failed.
pub fn read_node_value(
    node: &NodeType,
    context: &RequestContext,
    node_to_read: &ParsedReadValueId,
    max_age: f64,
    timestamps_to_return: TimestampsToReturn,
) -> DataValue {
    let mut result_value = DataValue::null();

    let Some(attribute) = node.as_node().get_attribute_max_age(
        timestamps_to_return,
        node_to_read.attribute_id,
        &node_to_read.index_range,
        &node_to_read.data_encoding,
        max_age,
    ) else {
        result_value.status = Some(StatusCode::BadAttributeIdInvalid);
        return result_value;
    };

    let value = if node_to_read.attribute_id == AttributeId::UserAccessLevel {
        match attribute.value {
            Some(Variant::Byte(val)) => {
                let access_level = AccessLevel::from_bits_truncate(val);
                let access_level = context.authenticator.effective_user_access_level(
                    &context.token,
                    access_level,
                    node.node_id(),
                );
                Some(Variant::from(access_level.bits()))
            }
            Some(v) => Some(v),
            _ => None,
        }
    } else {
        attribute.value
    };

    let value = if node_to_read.attribute_id == AttributeId::UserExecutable {
        match value {
            Some(Variant::Boolean(val)) => Some(Variant::from(
                val && context
                    .authenticator
                    .is_user_executable(&context.token, node.node_id()),
            )),
            r => r,
        }
    } else {
        value
    };

    result_value.value = value;
    result_value.status = attribute.status;
    if matches!(node, NodeType::Variable(_)) && node_to_read.attribute_id == AttributeId::Value {
        match timestamps_to_return {
            TimestampsToReturn::Source => {
                result_value.source_timestamp = attribute.source_timestamp;
                result_value.source_picoseconds = attribute.source_picoseconds;
            }
            TimestampsToReturn::Server => {
                result_value.server_timestamp = attribute.server_timestamp;
                result_value.server_picoseconds = attribute.server_picoseconds;
            }
            TimestampsToReturn::Both => {
                result_value.source_timestamp = attribute.source_timestamp;
                result_value.source_picoseconds = attribute.source_picoseconds;
                result_value.server_timestamp = attribute.server_timestamp;
                result_value.server_picoseconds = attribute.server_picoseconds;
            }
            TimestampsToReturn::Neither | TimestampsToReturn::Invalid => {
                // Nothing needs to change
            }
        }
    }
    result_value
}

/// Invoke `Write` for the given `node_to_write` on `node`.
pub fn write_node_value(
    node: &mut NodeType,
    node_to_write: &ParsedWriteValue,
) -> Result<(), StatusCode> {
    let now = DateTime::now();
    if node_to_write.attribute_id == AttributeId::Value {
        if let NodeType::Variable(variable) = node {
            return variable.set_value_range(
                node_to_write.value.value.clone().unwrap_or_default(),
                &node_to_write.index_range,
                node_to_write.value.status.unwrap_or_default(),
                &now,
                &node_to_write.value.source_timestamp.unwrap_or(now),
            );
        }
    }
    node.as_mut_node().set_attribute(
        node_to_write.attribute_id,
        node_to_write.value.value.clone().unwrap_or_default(),
    )
}

/// Add the given list of namespaces to the type tree in `context` and
/// `address_space`.
pub fn add_namespaces(
    context: &ServerContext,
    address_space: &mut AddressSpace,
    namespaces: &[&str],
) -> Vec<u16> {
    let mut type_tree = context.type_tree.write();
    let mut res = Vec::new();
    for ns in namespaces {
        let idx = type_tree.namespaces_mut().add_namespace(ns);
        address_space.add_namespace(ns, idx);
        res.push(idx);
    }
    res
}
