//! Role-based access control / authorization (OPC UA Part 3 §4.8–4.9, Part 5, Part 18).
//!
//! Permissive-by-default: a node with no RolePermissions (and no applicable namespace default) is not
//! role-restricted, preserving pre-feature behaviour. Enforcement (US3+) is opt-in and fail-closed
//! where it applies. This module currently provides identity→role resolution (US2) and the central
//! RolePermissions decision helper (US3). Namespace defaults are added in later user stories.

#![allow(dead_code)]

use opcua_types::{NodeId, ObjectId};

pub(crate) mod decision;
pub(crate) mod defaults;
pub(crate) mod resolver;
#[cfg(feature = "generated-address-space")]
pub(crate) mod role_management;
pub(crate) mod rules;

/// Standard OPC UA well-known roles used by RoleSet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum WellKnownRole {
    /// Anonymous role.
    Anonymous,
    /// AuthenticatedUser role.
    AuthenticatedUser,
    /// Observer role.
    Observer,
    /// Operator role.
    Operator,
    /// Engineer role.
    Engineer,
    /// Supervisor role.
    Supervisor,
    /// ConfigureAdmin role.
    ConfigureAdmin,
    /// SecurityAdmin role.
    SecurityAdmin,
}

impl WellKnownRole {
    pub(crate) const ALL: [Self; 8] = [
        Self::Anonymous,
        Self::AuthenticatedUser,
        Self::Observer,
        Self::Operator,
        Self::Engineer,
        Self::Supervisor,
        Self::ConfigureAdmin,
        Self::SecurityAdmin,
    ];

    /// Returns the standard namespace 0 NodeId for this well-known role.
    pub(crate) fn node_id(self) -> NodeId {
        match self {
            Self::Anonymous => ObjectId::WellKnownRole_Anonymous.into(),
            Self::AuthenticatedUser => ObjectId::WellKnownRole_AuthenticatedUser.into(),
            Self::Observer => ObjectId::WellKnownRole_Observer.into(),
            Self::Operator => ObjectId::WellKnownRole_Operator.into(),
            Self::Engineer => ObjectId::WellKnownRole_Engineer.into(),
            Self::Supervisor => ObjectId::WellKnownRole_Supervisor.into(),
            Self::ConfigureAdmin => ObjectId::WellKnownRole_ConfigureAdmin.into(),
            Self::SecurityAdmin => ObjectId::WellKnownRole_SecurityAdmin.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opcua_types::{NodeId, ObjectId};

    #[test]
    fn well_known_roles_use_standard_node_ids() {
        let roles = [
            (WellKnownRole::Anonymous, ObjectId::WellKnownRole_Anonymous),
            (
                WellKnownRole::AuthenticatedUser,
                ObjectId::WellKnownRole_AuthenticatedUser,
            ),
            (WellKnownRole::Observer, ObjectId::WellKnownRole_Observer),
            (WellKnownRole::Operator, ObjectId::WellKnownRole_Operator),
            (WellKnownRole::Engineer, ObjectId::WellKnownRole_Engineer),
            (
                WellKnownRole::Supervisor,
                ObjectId::WellKnownRole_Supervisor,
            ),
            (
                WellKnownRole::ConfigureAdmin,
                ObjectId::WellKnownRole_ConfigureAdmin,
            ),
            (
                WellKnownRole::SecurityAdmin,
                ObjectId::WellKnownRole_SecurityAdmin,
            ),
        ];

        for (role, object_id) in roles {
            assert_eq!(role.node_id(), NodeId::from(object_id));
        }
    }
}
