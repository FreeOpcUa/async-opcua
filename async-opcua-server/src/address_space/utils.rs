use crate::{
    node_manager::{ParsedReadValueId, ParsedWriteValue, RequestContext, ServerContext},
    rbac,
};
use opcua_nodes::TypeTree;
use opcua_types::{
    AttributeId, DataEncoding, DataTypeId, DataValue, DateTime, NodeId, NumericRange,
    PermissionType, RolePermissionType, StatusCode, TimestampsToReturn, Variant,
    VariantScalarTypeId, VariantTypeId, WriteMask,
};
use tracing::debug;

use super::{AccessLevel, AddressSpace, HasNodeId, NodeType, Variable};

/// Validate that the user given by `context` can read the value
/// of the given node.
pub fn is_readable(context: &RequestContext, node: &NodeType) -> Result<(), StatusCode> {
    if !authenticator_user_access_level(context, node).contains(AccessLevel::CURRENT_READ)
        || !rbac::decision::authorize_ctx(context, node, PermissionType::Read)
    {
        Err(StatusCode::BadUserAccessDenied)
    } else {
        Ok(())
    }
}

fn is_attribute_readable(context: &RequestContext, node: &NodeType) -> Result<(), StatusCode> {
    if authenticator_user_access_level(context, node).contains(AccessLevel::CURRENT_READ) {
        Ok(())
    } else {
        Err(StatusCode::BadUserAccessDenied)
    }
}

/// Validate that the user given by `context` can write to the
/// attribute given by `attribute_id`.
pub fn is_writable(
    context: &RequestContext,
    node: &NodeType,
    attribute_id: AttributeId,
) -> Result<(), StatusCode> {
    crate::services::node_access::validate_write_access(context)?;

    if let (NodeType::Variable(_), AttributeId::Value) = (node, attribute_id) {
        if !authenticator_user_access_level(context, node).contains(AccessLevel::CURRENT_WRITE) {
            return Err(StatusCode::BadUserAccessDenied);
        }

        if !rbac::decision::authorize_ctx(context, node, PermissionType::Write) {
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

        let required = rbac::decision::permission_for_write_attribute(attribute_id);
        if !rbac::decision::authorize_ctx(context, node, required) {
            return Err(StatusCode::BadUserAccessDenied);
        }

        Ok(())
    }
}

/// Get the effective user access level for `node`.
pub fn user_access_level(context: &RequestContext, node: &NodeType) -> AccessLevel {
    let mut access_level = authenticator_user_access_level(context, node);
    if node.as_node().role_permissions().is_some() {
        if !rbac::decision::authorize_ctx(context, node, PermissionType::Read) {
            access_level.remove(AccessLevel::CURRENT_READ);
        }
        if !rbac::decision::authorize_ctx(context, node, PermissionType::Write) {
            access_level.remove(AccessLevel::CURRENT_WRITE);
        }
    }
    access_level
}

fn authenticator_user_access_level(context: &RequestContext, node: &NodeType) -> AccessLevel {
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
    crate::services::node_access::validate_read_access(context)?;
    if node_to_read.attribute_id == AttributeId::Value {
        is_readable(context, node)?;
    } else {
        is_attribute_readable(context, node)?;
    }

    if node_to_read.attribute_id != AttributeId::Value
        && matches!(
            node_to_read.data_encoding,
            DataEncoding::XML | DataEncoding::JSON
        )
    {
        debug!(
            "read_node_value result for read node id {}, attribute {:?} is invalid data encoding",
            node_to_read.node_id, node_to_read.attribute_id
        );
        return Err(StatusCode::BadDataEncodingInvalid);
    }

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
    has_index_range: bool,
) -> Result<(), StatusCode> {
    let node_data_type = variable.data_type();

    validate_value_data_type_to_write(
        &node_data_type,
        variable.value_rank(),
        value,
        type_tree,
        has_index_range,
    )
}

// Part 4 §5.11.4 / Part 3 §5.6: the written value's array-ness must match the node's ValueRank.
// Skipped when an index range is present, since that writes a sub-section (e.g. a scalar element
// of an array) rather than replacing the whole value.
fn validate_value_rank_to_write(
    value_rank: i32,
    is_array: bool,
    has_index_range: bool,
) -> Result<(), StatusCode> {
    if has_index_range {
        return Ok(());
    }
    let ok = match value_rank {
        // ScalarOrOneDimension / Any: either a scalar or an array is acceptable.
        -3 | -2 => true,
        // Scalar: the value must not be an array.
        -1 => !is_array,
        // 0 (OneOrMoreDimensions), 1, 2, ...: an array is required.
        _ => is_array,
    };
    if ok {
        Ok(())
    } else {
        Err(StatusCode::BadTypeMismatch)
    }
}

fn validate_value_data_type_to_write(
    node_data_type: &NodeId,
    value_rank: i32,
    value: &Variant,
    type_tree: &dyn TypeTree,
    has_index_range: bool,
) -> Result<(), StatusCode> {
    if matches!(value, Variant::Empty) {
        return Ok(());
    }

    if let Some(value_data_type) = value.data_type() {
        let Some(data_type) = value_data_type.try_resolve(type_tree.namespaces()) else {
            return Err(StatusCode::BadTypeMismatch);
        };
        // Value is scalar, check if the data type matches
        let data_type_matches = type_tree.is_subtype_of(&data_type, node_data_type);

        if !data_type_matches {
            if value.is_array() {
                return Err(StatusCode::BadTypeMismatch);
            }
            // Check if the value to write is a byte string and the receiving node type a byte array.
            // This code is a mess just for some weird edge case in the spec that a write from
            // a byte string to a byte array should succeed
            match value {
                Variant::ByteString(_) => {
                    if node_data_type
                        .as_data_type_id()
                        .is_ok_and(|data_type| data_type == DataTypeId::Byte)
                    {
                        match value_rank {
                            -2 | -3 | 1 => Ok(()),
                            _ => Err(StatusCode::BadTypeMismatch),
                        }
                    } else {
                        Err(StatusCode::BadTypeMismatch)
                    }
                }
                // Part 4 §5.11.4: a scalar value whose data type is neither the node's
                // data type nor a subtype of it is a type mismatch.
                _ => Err(StatusCode::BadTypeMismatch),
            }
        } else {
            // Data type matches; the value's array-ness must also match the node's ValueRank.
            validate_value_rank_to_write(value_rank, value.is_array(), has_index_range)
        }
    } else {
        Err(StatusCode::BadTypeMismatch)
    }
}

fn validate_attribute_value_to_write(
    attribute_id: AttributeId,
    value: &Variant,
) -> Result<(), StatusCode> {
    let valid = match attribute_id {
        AttributeId::Value => true,
        AttributeId::NodeId | AttributeId::DataType => {
            is_scalar_attribute_value(value, VariantScalarTypeId::NodeId)
        }
        AttributeId::NodeClass | AttributeId::ValueRank => {
            is_scalar_attribute_value(value, VariantScalarTypeId::Int32)
        }
        AttributeId::BrowseName => {
            is_scalar_attribute_value(value, VariantScalarTypeId::QualifiedName)
        }
        AttributeId::DisplayName | AttributeId::Description | AttributeId::InverseName => {
            is_scalar_attribute_value(value, VariantScalarTypeId::LocalizedText)
        }
        AttributeId::WriteMask | AttributeId::UserWriteMask | AttributeId::AccessLevelEx => {
            is_scalar_attribute_value(value, VariantScalarTypeId::UInt32)
        }
        AttributeId::IsAbstract
        | AttributeId::Symmetric
        | AttributeId::ContainsNoLoops
        | AttributeId::Historizing
        | AttributeId::Executable
        | AttributeId::UserExecutable => {
            is_scalar_attribute_value(value, VariantScalarTypeId::Boolean)
        }
        AttributeId::EventNotifier | AttributeId::AccessLevel | AttributeId::UserAccessLevel => {
            is_scalar_attribute_value(value, VariantScalarTypeId::Byte)
        }
        AttributeId::ArrayDimensions => {
            is_array_attribute_value(value, VariantScalarTypeId::UInt32)
        }
        AttributeId::MinimumSamplingInterval => {
            is_scalar_attribute_value(value, VariantScalarTypeId::Double)
        }
        AttributeId::DataTypeDefinition => {
            value.is_empty()
                || is_scalar_attribute_value(value, VariantScalarTypeId::ExtensionObject)
        }
        AttributeId::RolePermissions | AttributeId::UserRolePermissions => {
            is_array_attribute_value(value, VariantScalarTypeId::ExtensionObject)
        }
        AttributeId::AccessRestrictions => {
            is_scalar_attribute_value(value, VariantScalarTypeId::UInt16)
        }
    };

    if valid {
        Ok(())
    } else {
        Err(StatusCode::BadTypeMismatch)
    }
}

fn is_scalar_attribute_value(value: &Variant, expected: VariantScalarTypeId) -> bool {
    value.type_id() == VariantTypeId::Scalar(expected)
}

fn is_array_attribute_value(value: &Variant, expected: VariantScalarTypeId) -> bool {
    matches!(value.type_id(), VariantTypeId::Array(actual, _) if actual == expected)
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

    validate_attribute_value_to_write(node_to_write.attribute_id, value)?;

    if node_to_write.attribute_id == AttributeId::Value {
        match node {
            NodeType::Variable(var) => validate_value_to_write(
                var,
                value,
                type_tree,
                node_to_write.index_range.has_range(),
            )?,
            NodeType::VariableType(var_type) => validate_value_data_type_to_write(
                var_type.data_type(),
                var_type.value_rank(),
                value,
                type_tree,
                node_to_write.index_range.has_range(),
            )?,
            _ => {}
        }
    }

    Ok(())
}

/// Return `true` if we support the given data encoding.
///
pub fn is_supported_data_encoding(data_encoding: &DataEncoding) -> bool {
    matches!(
        data_encoding,
        DataEncoding::Binary | DataEncoding::XML | DataEncoding::JSON
    )
}

fn compute_user_role_permissions(
    role_permissions: &[RolePermissionType],
    user_roles: &[NodeId],
) -> Vec<RolePermissionType> {
    let mut merged: Vec<RolePermissionType> = Vec::new();

    for role_permission in role_permissions {
        if !user_roles
            .iter()
            .any(|role_id| role_id == &role_permission.role_id)
        {
            continue;
        }

        if let Some(existing) = merged
            .iter_mut()
            .find(|existing| existing.role_id == role_permission.role_id)
        {
            existing.permissions |= role_permission.permissions;
        } else {
            merged.push(role_permission.clone());
        }
    }

    merged
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

    if node_to_read.attribute_id == AttributeId::UserRolePermissions {
        result_value.value = node.as_node().role_permissions().map(|role_permissions| {
            Variant::from(compute_user_role_permissions(
                role_permissions,
                context.user_roles(),
            ))
        });
        return result_value;
    }

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
            Some(Variant::Byte(_)) => Some(Variant::from(user_access_level(context, node).bits())),
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
                    .is_user_executable(&context.token, node.node_id())
                    && rbac::decision::authorize_ctx(context, node, PermissionType::Call),
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

    let value = node_to_write.value.value.clone().unwrap_or_default();
    validate_attribute_value_to_write(node_to_write.attribute_id, &value)?;

    node.as_mut_node()
        .set_attribute(node_to_write.attribute_id, value)
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use opcua_core::sync::RwLock;
    use opcua_nodes::Method;
    use opcua_types::{
        AnonymousIdentityToken, ApplicationDescription, ByteString, MessageSecurityMode,
        PermissionType, RolePermissionType, UAString,
    };

    use crate::{
        authenticator::UserToken,
        identity_token::IdentityToken,
        node_manager::{ParsedReadValueId, RequestContext, RequestContextInner},
        session::instance::Session,
        ServerBuilder,
    };

    use super::*;

    fn request_context() -> RequestContext {
        request_context_with_roles(Vec::new())
    }

    fn request_context_with_roles(user_roles: Vec<NodeId>) -> RequestContext {
        let (_server, handle) = ServerBuilder::new_anonymous("test")
            .build()
            .expect("test server should build");
        let info = handle.info().clone();
        let session = Session::create(
            &info,
            NodeId::new(0, 1),
            1,
            60_000,
            0,
            0,
            UAString::from("opc.tcp://localhost"),
            opcua_crypto::SecurityPolicy::None.to_str().to_string(),
            IdentityToken::Anonymous(AnonymousIdentityToken {
                policy_id: UAString::from("anonymous"),
            }),
            None,
            ByteString::null(),
            UAString::from("test"),
            ApplicationDescription::default(),
            MessageSecurityMode::None,
        );

        let session = Arc::new(RwLock::new(session));
        let user_roles = Arc::new(user_roles);

        RequestContext {
            current_node_manager_index: 0,
            inner: Arc::new(RequestContextInner {
                session,
                session_id: 1,
                authenticator: info.authenticator.clone(),
                token: UserToken("anonymous".to_string()),
                user_roles,
                type_tree: info.type_tree.clone(),
                type_tree_getter: info.type_tree_getter.clone(),
                subscriptions: handle.subscriptions().clone(),
                info,
            }),
        }
    }

    fn read_value_id(node_id: &NodeId) -> ParsedReadValueId {
        ParsedReadValueId {
            node_id: node_id.clone(),
            attribute_id: AttributeId::Value,
            index_range: NumericRange::None,
            data_encoding: DataEncoding::Binary,
        }
    }

    fn user_access_level_id(node_id: &NodeId) -> ParsedReadValueId {
        ParsedReadValueId {
            node_id: node_id.clone(),
            attribute_id: AttributeId::UserAccessLevel,
            index_range: NumericRange::None,
            data_encoding: DataEncoding::Binary,
        }
    }

    fn user_executable_id(node_id: &NodeId) -> ParsedReadValueId {
        ParsedReadValueId {
            node_id: node_id.clone(),
            attribute_id: AttributeId::UserExecutable,
            index_range: NumericRange::None,
            data_encoding: DataEncoding::Binary,
        }
    }

    fn role_permission(role_id: &NodeId, permissions: PermissionType) -> RolePermissionType {
        RolePermissionType {
            role_id: role_id.clone(),
            permissions,
        }
    }

    fn variable_with_user_access_level(user_access_level: AccessLevel) -> NodeType {
        let mut variable = Variable::new(&NodeId::new(1, "test"), "test", "test", 1i32);
        variable.set_user_access_level(user_access_level);
        NodeType::Variable(Box::new(variable))
    }

    fn executable_method() -> NodeType {
        NodeType::Method(Box::new(Method::new(
            &NodeId::new(1, "method"),
            "method",
            "method",
            true,
            true,
        )))
    }

    fn write_value_id(node_id: &NodeId, value: Variant) -> ParsedWriteValue {
        ParsedWriteValue {
            node_id: node_id.clone(),
            attribute_id: AttributeId::Value,
            index_range: NumericRange::None,
            value: DataValue::value_only(value),
        }
    }

    fn read_node_through_address_space(context: &RequestContext, node: NodeType) -> DataValue {
        let node_id = node.node_id().clone();
        let node_to_read = read_value_id(&node_id);
        let mut address_space = AddressSpace::new();
        address_space.add_namespace("urn:test", 1);
        assert!(address_space.insert(node, Option::<&[(&NodeId, &NodeId, _)]>::None));

        address_space.read(context, &node_to_read, 0.0, TimestampsToReturn::Neither)
    }

    #[tokio::test]
    async fn validate_node_read_rejects_xml_and_json_encoding_for_non_value_attributes() {
        let context = request_context();
        let node = NodeType::Variable(Box::new(Variable::new(
            &NodeId::new(1, "test"),
            "test",
            "test",
            1i32,
        )));

        for (data_encoding, index_range) in [
            (DataEncoding::XML, NumericRange::None),
            (DataEncoding::JSON, NumericRange::Index(0)),
        ] {
            let node_to_read = ParsedReadValueId {
                node_id: node.node_id().clone(),
                attribute_id: AttributeId::DisplayName,
                index_range,
                data_encoding,
            };

            assert_eq!(
                validate_node_read(&node, &context, &node_to_read),
                Err(StatusCode::BadDataEncodingInvalid)
            );
        }
    }

    #[tokio::test]
    async fn value_read_denied_without_read_role_returns_user_access_denied() {
        let context = request_context();
        let operator = NodeId::new(0, "Operator");
        let mut node = variable_with_user_access_level(AccessLevel::CURRENT_READ);
        node.as_mut_node()
            .set_role_permissions(vec![role_permission(&operator, PermissionType::Write)]);

        let result = read_node_through_address_space(&context, node);

        assert_eq!(result.status, Some(StatusCode::BadUserAccessDenied));
        assert!(result.value.is_none());
    }

    #[tokio::test]
    async fn unconfigured_value_read_remains_permissive() {
        let context = request_context();
        let node = variable_with_user_access_level(AccessLevel::CURRENT_READ);

        let result = read_node_through_address_space(&context, node);

        assert_eq!(result.status, Some(StatusCode::Good));
        assert_eq!(result.value, Some(Variant::from(1i32)));
    }

    #[tokio::test]
    async fn value_write_denied_without_write_role_returns_user_access_denied_and_leaves_value() {
        let context = request_context();
        let operator = NodeId::new(0, "Operator");
        let mut node =
            variable_with_user_access_level(AccessLevel::CURRENT_READ | AccessLevel::CURRENT_WRITE);
        node.as_mut_node()
            .set_role_permissions(vec![role_permission(&operator, PermissionType::Read)]);
        let node_to_write = write_value_id(node.node_id(), Variant::from(2i32));

        let type_tree = context.get_type_tree_for_user();
        let validation = validate_node_write(&node, &context, &node_to_write, type_tree.get());
        if validation.is_ok() {
            write_node_value(&mut node, &node_to_write)
                .expect("write should apply before RBAC enforcement");
        }

        assert_eq!(validation, Err(StatusCode::BadUserAccessDenied));
        let value = read_node_value(
            &node,
            &context,
            &read_value_id(node.node_id()),
            0.0,
            TimestampsToReturn::Neither,
        );
        assert_eq!(value.value, Some(Variant::from(1i32)));
    }

    #[tokio::test]
    async fn value_write_allowed_with_write_role() {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles(vec![operator.clone()]);
        let mut node =
            variable_with_user_access_level(AccessLevel::CURRENT_READ | AccessLevel::CURRENT_WRITE);
        node.as_mut_node()
            .set_role_permissions(vec![role_permission(&operator, PermissionType::Write)]);
        let node_to_write = write_value_id(node.node_id(), Variant::from(2i32));

        let type_tree = context.get_type_tree_for_user();
        assert_eq!(
            validate_node_write(&node, &context, &node_to_write, type_tree.get()),
            Ok(())
        );
    }

    #[tokio::test]
    async fn unconfigured_value_write_remains_permissive() {
        let context = request_context();
        let mut node =
            variable_with_user_access_level(AccessLevel::CURRENT_READ | AccessLevel::CURRENT_WRITE);
        let node_to_write = write_value_id(node.node_id(), Variant::from(2i32));

        let type_tree = context.get_type_tree_for_user();
        assert_eq!(
            validate_node_write(&node, &context, &node_to_write, type_tree.get()),
            Ok(())
        );
        write_node_value(&mut node, &node_to_write).expect("unconfigured write should apply");

        let value = read_node_value(
            &node,
            &context,
            &read_value_id(node.node_id()),
            0.0,
            TimestampsToReturn::Neither,
        );
        assert_eq!(value.value, Some(Variant::from(2i32)));
    }

    #[tokio::test]
    async fn role_permissions_attribute_write_requires_write_role_permissions() {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles(vec![operator.clone()]);
        let mut node =
            variable_with_user_access_level(AccessLevel::CURRENT_READ | AccessLevel::CURRENT_WRITE);
        node.as_mut_node()
            .set_write_mask(WriteMask::ROLE_PERMISSIONS);
        node.as_mut_node()
            .set_role_permissions(vec![role_permission(
                &operator,
                PermissionType::WriteAttribute,
            )]);

        assert_eq!(
            is_writable(&context, &node, AttributeId::RolePermissions),
            Err(StatusCode::BadUserAccessDenied)
        );

        node.as_mut_node()
            .set_role_permissions(vec![role_permission(
                &operator,
                PermissionType::WriteRolePermissions,
            )]);
        assert_eq!(
            is_writable(&context, &node, AttributeId::RolePermissions),
            Ok(())
        );
    }

    #[tokio::test]
    async fn display_name_attribute_write_requires_write_attribute() {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles(vec![operator.clone()]);
        let mut node =
            variable_with_user_access_level(AccessLevel::CURRENT_READ | AccessLevel::CURRENT_WRITE);
        node.as_mut_node().set_write_mask(WriteMask::DISPLAY_NAME);
        node.as_mut_node()
            .set_role_permissions(vec![role_permission(
                &operator,
                PermissionType::WriteRolePermissions,
            )]);

        assert_eq!(
            is_writable(&context, &node, AttributeId::DisplayName),
            Err(StatusCode::BadUserAccessDenied)
        );

        node.as_mut_node()
            .set_role_permissions(vec![role_permission(
                &operator,
                PermissionType::WriteAttribute,
            )]);
        assert_eq!(
            is_writable(&context, &node, AttributeId::DisplayName),
            Ok(())
        );
    }

    #[tokio::test]
    async fn access_restrictions_attribute_write_requires_write_attribute() {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles(vec![operator.clone()]);
        let mut node =
            variable_with_user_access_level(AccessLevel::CURRENT_READ | AccessLevel::CURRENT_WRITE);
        node.as_mut_node()
            .set_write_mask(WriteMask::ACCESS_RESTRICTIONS);
        node.as_mut_node()
            .set_role_permissions(vec![role_permission(
                &operator,
                PermissionType::WriteRolePermissions,
            )]);

        assert_eq!(
            is_writable(&context, &node, AttributeId::AccessRestrictions),
            Err(StatusCode::BadUserAccessDenied)
        );

        node.as_mut_node()
            .set_role_permissions(vec![role_permission(
                &operator,
                PermissionType::WriteAttribute,
            )]);
        assert_eq!(
            is_writable(&context, &node, AttributeId::AccessRestrictions),
            Ok(())
        );
    }

    #[tokio::test]
    async fn unconfigured_attribute_write_remains_permissive_when_write_mask_allows() {
        let context = request_context();
        let mut node =
            variable_with_user_access_level(AccessLevel::CURRENT_READ | AccessLevel::CURRENT_WRITE);
        node.as_mut_node().set_write_mask(WriteMask::DISPLAY_NAME);

        assert_eq!(
            is_writable(&context, &node, AttributeId::DisplayName),
            Ok(())
        );
    }

    #[tokio::test]
    async fn user_access_level_clears_current_read_when_role_lacks_read() {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles(vec![operator.clone()]);
        let mut node =
            variable_with_user_access_level(AccessLevel::CURRENT_READ | AccessLevel::CURRENT_WRITE);
        node.as_mut_node()
            .set_role_permissions(vec![role_permission(&operator, PermissionType::Write)]);

        let access_level = user_access_level(&context, &node);

        assert!(!access_level.contains(AccessLevel::CURRENT_READ));
        assert!(access_level.contains(AccessLevel::CURRENT_WRITE));
    }

    #[tokio::test]
    async fn user_access_level_clears_current_write_when_role_lacks_write() {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles(vec![operator.clone()]);
        let mut node =
            variable_with_user_access_level(AccessLevel::CURRENT_READ | AccessLevel::CURRENT_WRITE);
        node.as_mut_node()
            .set_role_permissions(vec![role_permission(&operator, PermissionType::Read)]);

        let access_level = user_access_level(&context, &node);

        assert!(access_level.contains(AccessLevel::CURRENT_READ));
        assert!(!access_level.contains(AccessLevel::CURRENT_WRITE));
    }

    #[tokio::test]
    async fn user_access_level_leaves_unconfigured_node_unchanged() {
        let context = request_context();
        let node =
            variable_with_user_access_level(AccessLevel::CURRENT_READ | AccessLevel::CURRENT_WRITE);

        let access_level = user_access_level(&context, &node);

        assert!(access_level.contains(AccessLevel::CURRENT_READ));
        assert!(access_level.contains(AccessLevel::CURRENT_WRITE));
    }

    #[tokio::test]
    async fn read_user_access_level_attribute_reflects_role_permissions() {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles(vec![operator.clone()]);
        let mut node =
            variable_with_user_access_level(AccessLevel::CURRENT_READ | AccessLevel::CURRENT_WRITE);
        node.as_mut_node()
            .set_role_permissions(vec![role_permission(&operator, PermissionType::Read)]);
        let node_to_read = user_access_level_id(node.node_id());

        let value = read_node_value(
            &node,
            &context,
            &node_to_read,
            0.0,
            TimestampsToReturn::Neither,
        );

        assert_eq!(
            value.value,
            Some(Variant::from(AccessLevel::CURRENT_READ.bits()))
        );
    }

    #[tokio::test]
    async fn read_user_executable_attribute_reflects_call_role_permissions() {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles(vec![operator.clone()]);
        let mut node = executable_method();
        node.as_mut_node()
            .set_role_permissions(vec![role_permission(&operator, PermissionType::Read)]);
        let node_to_read = user_executable_id(node.node_id());

        let value = read_node_value(
            &node,
            &context,
            &node_to_read,
            0.0,
            TimestampsToReturn::Neither,
        );

        assert_eq!(value.value, Some(Variant::from(false)));
    }

    #[tokio::test]
    async fn read_user_executable_attribute_allows_unconfigured_method() {
        let context = request_context();
        let node = executable_method();
        let node_to_read = user_executable_id(node.node_id());

        let value = read_node_value(
            &node,
            &context,
            &node_to_read,
            0.0,
            TimestampsToReturn::Neither,
        );

        assert_eq!(value.value, Some(Variant::from(true)));
    }

    #[test]
    fn user_role_permissions_filters_to_session_roles_and_unions_duplicates() {
        let role_a = NodeId::new(0, "RoleA");
        let role_b = NodeId::new(0, "RoleB");
        let role_c = NodeId::new(0, "RoleC");
        let role_permissions = vec![
            RolePermissionType {
                role_id: role_a.clone(),
                permissions: PermissionType::Browse,
            },
            RolePermissionType {
                role_id: role_c.clone(),
                permissions: PermissionType::Call,
            },
            RolePermissionType {
                role_id: role_a.clone(),
                permissions: PermissionType::Read,
            },
            RolePermissionType {
                role_id: role_b.clone(),
                permissions: PermissionType::Write,
            },
        ];
        let user_roles = vec![role_a.clone(), role_b.clone()];

        let filtered = compute_user_role_permissions(&role_permissions, &user_roles);

        assert_eq!(
            filtered,
            vec![
                RolePermissionType {
                    role_id: role_a,
                    permissions: PermissionType::Browse | PermissionType::Read,
                },
                RolePermissionType {
                    role_id: role_b,
                    permissions: PermissionType::Write,
                },
            ]
        );
    }
}
