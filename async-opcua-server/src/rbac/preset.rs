//! Opt-in role permission presets.
//!
//! The secure preset maps the well-known role suggestions from OPC UA Part 3,
//! 4.9.2, Table 2, to the concrete PermissionType bits defined by Part 3,
//! 8.55, Table 38.

use opcua_types::{PermissionType, RolePermissionType};

use super::WellKnownRole;

/// Suggested namespace default permissions for the standard well-known roles.
pub fn secure_well_known_permissions() -> Vec<RolePermissionType> {
    vec![
        role_permission(WellKnownRole::Anonymous, anonymous_permissions()),
        role_permission(
            WellKnownRole::AuthenticatedUser,
            authenticated_user_permissions(),
        ),
        role_permission(WellKnownRole::Observer, observer_permissions()),
        role_permission(WellKnownRole::Operator, operator_permissions()),
        role_permission(WellKnownRole::Engineer, engineer_permissions()),
        role_permission(WellKnownRole::Supervisor, supervisor_permissions()),
        role_permission(WellKnownRole::ConfigureAdmin, configure_admin_permissions()),
        role_permission(WellKnownRole::SecurityAdmin, security_admin_permissions()),
    ]
}

/// Anonymous can browse/read only, including the RolePermissions attribute.
pub fn anonymous_permissions() -> PermissionType {
    PermissionType::Browse | PermissionType::Read | PermissionType::ReadRolePermissions
}

/// Authenticated users can browse/read non-security-related nodes.
pub fn authenticated_user_permissions() -> PermissionType {
    anonymous_permissions()
}

/// Observer can browse, read current values, read history, and receive events.
pub fn observer_permissions() -> PermissionType {
    PermissionType::Browse
        | PermissionType::Read
        | PermissionType::ReadHistory
        | PermissionType::ReceiveEvents
}

/// Operator adds live value writes and method calls to Observer permissions.
pub fn operator_permissions() -> PermissionType {
    observer_permissions() | PermissionType::Write | PermissionType::Call
}

/// Engineer adds configuration and history-write permissions to Operator.
pub fn engineer_permissions() -> PermissionType {
    operator_permissions()
        | PermissionType::WriteAttribute
        | PermissionType::WriteHistorizing
        | PermissionType::InsertHistory
        | PermissionType::ModifyHistory
        | PermissionType::DeleteHistory
}

/// Supervisor has the broad operational read/write/call/event baseline.
pub fn supervisor_permissions() -> PermissionType {
    operator_permissions()
}

/// ConfigureAdmin can change non-security-related configuration.
pub fn configure_admin_permissions() -> PermissionType {
    PermissionType::Browse
        | PermissionType::Read
        | PermissionType::Write
        | PermissionType::WriteAttribute
        | PermissionType::AddNode
        | PermissionType::DeleteNode
        | PermissionType::AddReference
        | PermissionType::RemoveReference
}

/// SecurityAdmin can read and write security-related role permissions.
pub fn security_admin_permissions() -> PermissionType {
    PermissionType::Browse
        | PermissionType::Read
        | PermissionType::ReadRolePermissions
        | PermissionType::WriteRolePermissions
}

fn role_permission(role: WellKnownRole, permissions: PermissionType) -> RolePermissionType {
    RolePermissionType {
        role_id: role.node_id(),
        permissions,
    }
}
