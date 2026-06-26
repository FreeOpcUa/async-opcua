//! Central RolePermissions authorization decisions.
//!
//! A node with no effective RolePermissions is permissive for backwards compatibility. Once a
//! RolePermissions list applies, authorization fails closed unless the union of the session's
//! matching role grants contains the required [`PermissionType`] bit.

use crate::{address_space::NodeType, node_manager::RequestContext};
use opcua_types::{AttributeId, NodeId, PermissionType, RolePermissionType};

/// Returns the RolePermissions list currently effective for `node`.
#[must_use]
pub(crate) fn effective_role_permissions(node: &NodeType) -> Option<&[RolePermissionType]> {
    // TODO US6: namespace default fallback.
    node.as_node().role_permissions()
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
        effective_role_permissions(node),
        required,
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

    fn role(id: &'static str) -> NodeId {
        NodeId::new(0, id)
    }

    fn grant(role_id: &NodeId, permissions: PermissionType) -> RolePermissionType {
        RolePermissionType {
            role_id: role_id.clone(),
            permissions,
        }
    }

    #[test]
    fn authorize_permits_unconfigured_permissions() {
        let user_roles = [role("Operator")];

        let allowed = authorize(&user_roles, None, PermissionType::Read);

        assert!(allowed);
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
}
