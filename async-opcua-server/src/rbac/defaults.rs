use std::collections::BTreeMap;

use opcua_types::{AccessRestrictionType, RolePermissionType};

use crate::config::NamespaceDefaultConfig;

/// Per-namespace default RBAC attributes.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct NamespaceDefaults {
    defaults: BTreeMap<u16, NamespaceDefaultPermissions>,
}

/// Default RBAC attributes for one namespace.
///
/// `DefaultUserRolePermissions` is not stored here. Like `UserRolePermissions`, it is computed
/// per session from the effective role permissions and the session's resolved role set.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct NamespaceDefaultPermissions {
    default_role_permissions: Option<Vec<RolePermissionType>>,
    default_access_restrictions: Option<AccessRestrictionType>,
}

impl NamespaceDefaults {
    pub(crate) fn from_config(config_defaults: &BTreeMap<u16, NamespaceDefaultConfig>) -> Self {
        let defaults = config_defaults
            .iter()
            .map(|(namespace, defaults)| {
                (
                    *namespace,
                    NamespaceDefaultPermissions {
                        default_role_permissions: defaults.default_role_permissions.clone(),
                        default_access_restrictions: defaults.default_access_restrictions,
                    },
                )
            })
            .collect();

        Self { defaults }
    }

    pub(crate) fn role_permissions(&self, namespace: u16) -> Option<&[RolePermissionType]> {
        self.defaults
            .get(&namespace)
            .and_then(|defaults| defaults.default_role_permissions.as_deref())
    }

    pub(crate) fn access_restrictions(&self, namespace: u16) -> Option<AccessRestrictionType> {
        self.defaults
            .get(&namespace)
            .and_then(|defaults| defaults.default_access_restrictions)
    }

    pub(crate) fn set_role_permissions(
        &mut self,
        namespace: u16,
        role_permissions: Vec<RolePermissionType>,
    ) {
        self.defaults
            .entry(namespace)
            .or_default()
            .default_role_permissions = Some(role_permissions);
    }

    pub(crate) fn set_access_restrictions(
        &mut self,
        namespace: u16,
        access_restrictions: AccessRestrictionType,
    ) {
        self.defaults
            .entry(namespace)
            .or_default()
            .default_access_restrictions = Some(access_restrictions);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opcua_types::{NodeId, PermissionType};

    fn grant(role_id: NodeId, permissions: PermissionType) -> RolePermissionType {
        RolePermissionType {
            role_id,
            permissions,
        }
    }

    #[test]
    fn namespace_defaults_are_empty_by_default() {
        let defaults = NamespaceDefaults::default();

        assert!(defaults.role_permissions(2).is_none());
        assert!(defaults.access_restrictions(2).is_none());
    }

    #[test]
    fn namespace_defaults_store_role_permissions_by_namespace() {
        let mut defaults = NamespaceDefaults::default();
        let role_permissions = vec![grant(NodeId::new(0, "Operator"), PermissionType::Read)];

        defaults.set_role_permissions(2, role_permissions.clone());

        assert_eq!(
            defaults.role_permissions(2),
            Some(role_permissions.as_slice())
        );
        assert!(defaults.role_permissions(3).is_none());
    }

    #[test]
    fn namespace_defaults_store_access_restrictions_by_namespace() {
        let mut defaults = NamespaceDefaults::default();

        defaults.set_access_restrictions(2, AccessRestrictionType::SigningRequired);

        assert_eq!(
            defaults.access_restrictions(2),
            Some(AccessRestrictionType::SigningRequired)
        );
        assert!(defaults.access_restrictions(3).is_none());
    }

    #[test]
    fn namespace_defaults_are_built_from_config() {
        let role_permissions = vec![grant(NodeId::new(0, "Operator"), PermissionType::Read)];
        let mut config_defaults = BTreeMap::new();
        config_defaults.insert(
            2,
            NamespaceDefaultConfig {
                default_role_permissions: Some(role_permissions.clone()),
                default_access_restrictions: Some(AccessRestrictionType::EncryptionRequired),
            },
        );

        let defaults = NamespaceDefaults::from_config(&config_defaults);

        assert_eq!(
            defaults.role_permissions(2),
            Some(role_permissions.as_slice())
        );
        assert_eq!(
            defaults.access_restrictions(2),
            Some(AccessRestrictionType::EncryptionRequired)
        );
    }
}
