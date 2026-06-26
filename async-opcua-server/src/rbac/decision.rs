//! Central RolePermissions authorization decisions.
//!
//! A node with no effective RolePermissions is permissive for backwards compatibility. Once a
//! RolePermissions list applies, authorization fails closed unless the union of the session's
//! matching role grants contains the required [`PermissionType`] bit.

use crate::{
    address_space::NodeType, node_manager::RequestContext, rbac::defaults::NamespaceDefaults,
};
use opcua_types::{
    AccessRestrictionType, AttributeId, MessageSecurityMode, NodeId, PermissionType,
    RolePermissionType, StatusCode,
};

/// Returns the RolePermissions list currently effective for `node`.
#[must_use]
pub(crate) fn effective_role_permissions<'a>(
    namespace_defaults: &'a NamespaceDefaults,
    node: &'a NodeType,
) -> Option<&'a [RolePermissionType]> {
    if let Some(role_permissions) = node.as_node().role_permissions() {
        return Some(role_permissions);
    }

    namespace_defaults.role_permissions(node.as_node().node_id().namespace)
}

/// Returns `true` if `user_roles` grant `required` in the effective RolePermissions list.
///
/// `None` means the node has no RolePermissions configured, so access remains governed by the
/// existing AccessLevel/Executable checks and is permitted here. `Some(_)` means a RolePermissions
/// list applies and the decision fails closed when no listed role matches the session roles.
#[must_use]
pub(crate) fn authorize(
    user_roles: &[NodeId],
    effective: Option<&[RolePermissionType]>,
    required: PermissionType,
) -> bool {
    let Some(role_permissions) = effective else {
        return true;
    };

    let granted = role_permissions
        .iter()
        .filter(|role_permission| {
            user_roles
                .iter()
                .any(|role_id| role_id == &role_permission.role_id)
        })
        .fold(PermissionType::empty(), |granted, role_permission| {
            granted | role_permission.permissions
        });

    granted.contains(required)
}

/// Context-taking wrapper for node authorization decisions.
#[must_use]
pub(crate) fn authorize_ctx(
    context: &RequestContext,
    node: &NodeType,
    required: PermissionType,
) -> bool {
    authorize(
        context.user_roles(),
        effective_role_permissions(&context.info().namespace_defaults, node),
        required,
    )
}

/// Returns the AccessRestrictions currently effective for `node`.
#[must_use]
pub(crate) fn effective_access_restrictions(
    namespace_defaults: &NamespaceDefaults,
    node: &NodeType,
) -> Option<AccessRestrictionType> {
    node.as_node()
        .access_restrictions()
        .or_else(|| namespace_defaults.access_restrictions(node.as_node().node_id().namespace))
}

/// Returns `true` if the session roles may receive Events from an event source.
///
/// `None` means the source node could not be resolved or has no RolePermissions configured, so
/// event delivery remains permissive for backwards compatibility.
#[must_use]
pub(crate) fn event_receive_allowed(
    user_roles: &[NodeId],
    source_role_permissions: Option<&[RolePermissionType]>,
) -> bool {
    authorize(
        user_roles,
        source_role_permissions,
        PermissionType::ReceiveEvents,
    )
}

/// Validate a node's AccessRestrictions against the channel message security mode.
pub(crate) fn access_restrictions_ok(
    restrictions: Option<AccessRestrictionType>,
    security_mode: MessageSecurityMode,
) -> Result<(), StatusCode> {
    let Some(restrictions) = restrictions else {
        return Ok(());
    };

    if restrictions.contains(AccessRestrictionType::EncryptionRequired)
        && security_mode != MessageSecurityMode::SignAndEncrypt
    {
        return Err(StatusCode::BadSecurityModeInsufficient);
    }

    if restrictions.contains(AccessRestrictionType::SigningRequired)
        && !matches!(
            security_mode,
            MessageSecurityMode::Sign | MessageSecurityMode::SignAndEncrypt
        )
    {
        return Err(StatusCode::BadSecurityModeInsufficient);
    }

    if restrictions.contains(AccessRestrictionType::SessionRequired) {
        // TODO sessionless: enforce SessionRequired on sessionless invocation paths.
    }

    Ok(())
}

/// Context-taking wrapper for AccessRestrictions decisions.
pub(crate) fn access_restrictions_ok_ctx(
    context: &RequestContext,
    node: &NodeType,
) -> Result<(), StatusCode> {
    access_restrictions_ok(
        effective_access_restrictions(&context.info().namespace_defaults, node),
        context.security_mode(),
    )
}

/// Permission required to read an attribute.
#[must_use]
pub(crate) fn permission_for_attribute(attribute_id: AttributeId) -> PermissionType {
    permission_for_read_attribute(attribute_id)
}

/// Permission required to read an attribute with the Read service.
#[must_use]
pub(crate) fn permission_for_read_attribute(attribute_id: AttributeId) -> PermissionType {
    match attribute_id {
        AttributeId::Value => PermissionType::Read,
        AttributeId::RolePermissions | AttributeId::UserRolePermissions => {
            PermissionType::ReadRolePermissions
        }
        _ => PermissionType::Browse,
    }
}

/// Permission required to write an attribute with the Write service.
#[must_use]
pub(crate) fn permission_for_write_attribute(attribute_id: AttributeId) -> PermissionType {
    match attribute_id {
        AttributeId::Value => PermissionType::Write,
        AttributeId::RolePermissions => PermissionType::WriteRolePermissions,
        AttributeId::Historizing => PermissionType::WriteHistorizing,
        _ => PermissionType::WriteAttribute,
    }
}

/// Permission required to browse nodes/references.
#[must_use]
pub(crate) fn permission_for_browse() -> PermissionType {
    PermissionType::Browse
}

/// Permission required to call a Method node.
#[must_use]
pub(crate) fn permission_for_call() -> PermissionType {
    PermissionType::Call
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::defaults::NamespaceDefaults;
    use opcua_nodes::{EventNotifier, Object};
    use opcua_types::{
        AccessRestrictionType, LocalizedText, MessageSecurityMode, QualifiedName, StatusCode,
    };

    fn role(id: &'static str) -> NodeId {
        NodeId::new(0, id)
    }

    fn grant(role_id: &NodeId, permissions: PermissionType) -> RolePermissionType {
        RolePermissionType {
            role_id: role_id.clone(),
            permissions,
        }
    }

    fn object_node(namespace: u16, name: &'static str) -> NodeType {
        Object::new(
            &NodeId::new(namespace, name),
            QualifiedName::new(namespace, name),
            LocalizedText::new("", name),
            EventNotifier::empty(),
        )
        .into()
    }

    #[test]
    fn authorize_permits_unconfigured_permissions() {
        let user_roles = [role("Operator")];

        let allowed = authorize(&user_roles, None, PermissionType::Read);

        assert!(allowed);
    }

    #[test]
    fn effective_role_permissions_falls_back_to_namespace_default() {
        let mut defaults = NamespaceDefaults::default();
        let operator = role("Operator");
        let namespace_permissions = vec![grant(&operator, PermissionType::Read)];
        defaults.set_role_permissions(2, namespace_permissions.clone());
        let node = object_node(2, "Unconfigured");

        let effective = effective_role_permissions(&defaults, &node);

        assert_eq!(effective, Some(namespace_permissions.as_slice()));
    }

    #[test]
    fn effective_role_permissions_prefers_node_value_over_namespace_default() {
        let mut defaults = NamespaceDefaults::default();
        let operator = role("Operator");
        let observer = role("Observer");
        defaults.set_role_permissions(2, vec![grant(&operator, PermissionType::Read)]);
        let mut node = object_node(2, "Configured");
        node.as_mut_node()
            .set_role_permissions(vec![grant(&observer, PermissionType::Browse)]);

        let effective = effective_role_permissions(&defaults, &node);

        assert_eq!(
            effective,
            Some([grant(&observer, PermissionType::Browse)].as_slice())
        );
    }

    #[test]
    fn effective_role_permissions_is_none_without_node_or_namespace_value() {
        let defaults = NamespaceDefaults::default();
        let node = object_node(3, "Open");

        let effective = effective_role_permissions(&defaults, &node);

        assert!(effective.is_none());
    }

    #[test]
    fn authorize_denies_when_permissions_exclude_user_roles() {
        let user_roles = [role("Observer")];
        let operator = role("Operator");
        let permissions = [grant(&operator, PermissionType::Read)];

        let allowed = authorize(&user_roles, Some(&permissions), PermissionType::Read);

        assert!(!allowed);
    }

    #[test]
    fn authorize_permits_when_required_bit_is_granted() {
        let observer = role("Observer");
        let user_roles = [observer.clone()];
        let permissions = [grant(
            &observer,
            PermissionType::Read | PermissionType::Browse,
        )];

        let allowed = authorize(&user_roles, Some(&permissions), PermissionType::Read);

        assert!(allowed);
    }

    #[test]
    fn authorize_denies_when_required_bit_is_absent() {
        let observer = role("Observer");
        let user_roles = [observer.clone()];
        let permissions = [grant(&observer, PermissionType::Browse)];

        let allowed = authorize(&user_roles, Some(&permissions), PermissionType::Read);

        assert!(!allowed);
    }

    #[test]
    fn authorize_permits_union_across_two_roles() {
        let observer = role("Observer");
        let operator = role("Operator");
        let user_roles = [observer.clone(), operator.clone()];
        let permissions = [
            grant(&observer, PermissionType::Browse),
            grant(&operator, PermissionType::Write),
        ];

        let allowed = authorize(&user_roles, Some(&permissions), PermissionType::Write);

        assert!(allowed);
    }

    #[test]
    fn event_receive_allowed_permits_unconfigured_source_permissions() {
        let user_roles = [role("Observer")];

        let allowed = event_receive_allowed(&user_roles, None);

        assert!(allowed);
    }

    #[test]
    fn event_receive_allowed_denies_when_receive_events_is_not_granted() {
        let observer = role("Observer");
        let permissions = [grant(&observer, PermissionType::Read)];
        let user_roles = [observer];

        let allowed = event_receive_allowed(&user_roles, Some(&permissions));

        assert!(!allowed);
    }

    #[test]
    fn event_receive_allowed_permits_when_receive_events_is_granted() {
        let observer = role("Observer");
        let permissions = [grant(&observer, PermissionType::ReceiveEvents)];
        let user_roles = [observer];

        let allowed = event_receive_allowed(&user_roles, Some(&permissions));

        assert!(allowed);
    }

    #[test]
    fn access_restrictions_permit_unconfigured_node_for_all_security_modes() {
        for security_mode in [
            MessageSecurityMode::None,
            MessageSecurityMode::Sign,
            MessageSecurityMode::SignAndEncrypt,
        ] {
            assert_eq!(access_restrictions_ok(None, security_mode), Ok(()));
        }
    }

    #[test]
    fn access_restrictions_require_encryption_when_requested() {
        let restrictions = Some(AccessRestrictionType::EncryptionRequired);

        assert_eq!(
            access_restrictions_ok(restrictions, MessageSecurityMode::None),
            Err(StatusCode::BadSecurityModeInsufficient)
        );
        assert_eq!(
            access_restrictions_ok(restrictions, MessageSecurityMode::Sign),
            Err(StatusCode::BadSecurityModeInsufficient)
        );
        assert_eq!(
            access_restrictions_ok(restrictions, MessageSecurityMode::SignAndEncrypt),
            Ok(())
        );
    }

    #[test]
    fn access_restrictions_require_signing_when_requested() {
        let restrictions = Some(AccessRestrictionType::SigningRequired);

        assert_eq!(
            access_restrictions_ok(restrictions, MessageSecurityMode::None),
            Err(StatusCode::BadSecurityModeInsufficient)
        );
        assert_eq!(
            access_restrictions_ok(restrictions, MessageSecurityMode::Sign),
            Ok(())
        );
        assert_eq!(
            access_restrictions_ok(restrictions, MessageSecurityMode::SignAndEncrypt),
            Ok(())
        );
    }

    #[test]
    fn access_restrictions_session_required_is_permitted_on_session_path() {
        let restrictions = Some(AccessRestrictionType::SessionRequired);

        for security_mode in [
            MessageSecurityMode::None,
            MessageSecurityMode::Sign,
            MessageSecurityMode::SignAndEncrypt,
        ] {
            assert_eq!(access_restrictions_ok(restrictions, security_mode), Ok(()));
        }
    }

    #[test]
    fn effective_access_restrictions_falls_back_to_namespace_default() {
        let mut defaults = NamespaceDefaults::default();
        defaults.set_access_restrictions(2, AccessRestrictionType::EncryptionRequired);
        let node = object_node(2, "EncryptedByDefault");

        let effective = effective_access_restrictions(&defaults, &node);

        assert_eq!(effective, Some(AccessRestrictionType::EncryptionRequired));
    }

    #[test]
    fn effective_access_restrictions_prefers_node_value_over_namespace_default() {
        let mut defaults = NamespaceDefaults::default();
        defaults.set_access_restrictions(2, AccessRestrictionType::EncryptionRequired);
        let mut node = object_node(2, "SignedOnly");
        node.as_mut_node()
            .set_access_restrictions(AccessRestrictionType::SigningRequired);

        let effective = effective_access_restrictions(&defaults, &node);

        assert_eq!(effective, Some(AccessRestrictionType::SigningRequired));
    }
}
