use std::collections::BTreeMap;

use opcua_types::NodeId;

use crate::config::ServerUserToken;

use super::{rules::IdentityMappingRule, WellKnownRole};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResolvedIdentityKind {
    Anonymous,
    UserName(String),
    X509Thumbprint(String),
    IssuedToken {
        group_ids: Vec<String>,
        role_ids: Vec<NodeId>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedIdentity {
    pub(crate) kind: ResolvedIdentityKind,
    pub(crate) application_uri: Option<String>,
    pub(crate) endpoint_url: Option<String>,
}

impl ResolvedIdentity {
    pub(crate) fn anonymous(
        application_uri: Option<impl Into<String>>,
        endpoint_url: Option<impl Into<String>>,
    ) -> Self {
        Self {
            kind: ResolvedIdentityKind::Anonymous,
            application_uri: application_uri.map(Into::into),
            endpoint_url: endpoint_url.map(Into::into),
        }
    }

    pub(crate) fn username(
        username: impl Into<String>,
        application_uri: Option<impl Into<String>>,
        endpoint_url: Option<impl Into<String>>,
    ) -> Self {
        Self {
            kind: ResolvedIdentityKind::UserName(username.into()),
            application_uri: application_uri.map(Into::into),
            endpoint_url: endpoint_url.map(Into::into),
        }
    }

    pub(crate) fn x509_thumbprint(
        thumbprint: impl Into<String>,
        application_uri: Option<impl Into<String>>,
        endpoint_url: Option<impl Into<String>>,
    ) -> Self {
        Self {
            kind: ResolvedIdentityKind::X509Thumbprint(thumbprint.into()),
            application_uri: application_uri.map(Into::into),
            endpoint_url: endpoint_url.map(Into::into),
        }
    }

    pub(crate) fn issued_token<GroupIds, GroupId, RoleIds>(
        group_ids: GroupIds,
        role_ids: RoleIds,
        application_uri: Option<impl Into<String>>,
        endpoint_url: Option<impl Into<String>>,
    ) -> Self
    where
        GroupIds: IntoIterator<Item = GroupId>,
        GroupId: Into<String>,
        RoleIds: IntoIterator<Item = NodeId>,
    {
        Self {
            kind: ResolvedIdentityKind::IssuedToken {
                group_ids: group_ids.into_iter().map(Into::into).collect(),
                role_ids: role_ids.into_iter().collect(),
            },
            application_uri: application_uri.map(Into::into),
            endpoint_url: endpoint_url.map(Into::into),
        }
    }

    fn is_anonymous(&self) -> bool {
        matches!(self.kind, ResolvedIdentityKind::Anonymous)
    }
}

#[derive(Debug, Clone)]
struct RoleRules {
    node_id: NodeId,
    identity_rules: Vec<IdentityMappingRule>,
}

/// Resolves activated session identities to granted OPC UA role NodeIds.
#[derive(Debug, Clone)]
pub(crate) struct RoleResolver {
    roles: Vec<RoleRules>,
}

impl Default for RoleResolver {
    fn default() -> Self {
        let mut roles = Vec::with_capacity(WellKnownRole::ALL.len());
        for role in WellKnownRole::ALL {
            let identity_rules = match role {
                WellKnownRole::Anonymous => vec![IdentityMappingRule::AnonymousIdentity],
                WellKnownRole::AuthenticatedUser => vec![IdentityMappingRule::AuthenticatedUser],
                WellKnownRole::Observer
                | WellKnownRole::Operator
                | WellKnownRole::Engineer
                | WellKnownRole::Supervisor
                | WellKnownRole::ConfigureAdmin
                | WellKnownRole::SecurityAdmin => Vec::new(),
            };
            roles.push(RoleRules {
                node_id: role.node_id(),
                identity_rules,
            });
        }

        Self { roles }
    }
}

impl RoleResolver {
    pub(crate) fn from_user_tokens(user_tokens: &BTreeMap<String, ServerUserToken>) -> Self {
        let mut resolver = Self::default();

        for token in user_tokens.values().filter(|token| !token.roles.is_empty()) {
            let rule = if token.is_user_pass() {
                Some(IdentityMappingRule::UserName(token.user.clone()))
            } else if token.is_x509() {
                token
                    .thumbprint
                    .as_ref()
                    .map(|thumbprint| IdentityMappingRule::Thumbprint(thumbprint.as_hex_string()))
            } else {
                None
            };

            let Some(rule) = rule else {
                continue;
            };

            for role in &token.roles {
                resolver.add_mapping(role.clone(), rule.clone());
            }
        }

        resolver
    }

    pub(crate) fn add_mapping(&mut self, role_node_id: NodeId, rule: IdentityMappingRule) {
        if let Some(role) = self
            .roles
            .iter_mut()
            .find(|role| role.node_id == role_node_id)
        {
            role.identity_rules.push(rule);
        } else {
            self.roles.push(RoleRules {
                node_id: role_node_id,
                identity_rules: vec![rule],
            });
        }
    }

    pub(crate) fn resolve(&self, identity: &ResolvedIdentity) -> Vec<NodeId> {
        if identity.is_anonymous() {
            return vec![WellKnownRole::Anonymous.node_id()];
        }

        let anonymous = WellKnownRole::Anonymous.node_id();
        let authenticated_user = WellKnownRole::AuthenticatedUser.node_id();
        let mut granted = Vec::new();

        for role in &self.roles {
            if role.node_id == anonymous || role.node_id == authenticated_user {
                continue;
            }

            if role
                .identity_rules
                .iter()
                .any(|rule| Self::matches_rule(rule, identity))
            {
                push_unique(&mut granted, role.node_id.clone());
            }
        }

        push_unique(&mut granted, authenticated_user);
        granted
    }

    fn matches_rule(rule: &IdentityMappingRule, identity: &ResolvedIdentity) -> bool {
        match (rule, &identity.kind) {
            (IdentityMappingRule::AnonymousIdentity, ResolvedIdentityKind::Anonymous) => true,
            (IdentityMappingRule::AuthenticatedUser, kind) => {
                !matches!(kind, ResolvedIdentityKind::Anonymous)
            }
            (IdentityMappingRule::UserName(expected), ResolvedIdentityKind::UserName(actual)) => {
                expected == actual
            }
            (
                IdentityMappingRule::Thumbprint(expected),
                ResolvedIdentityKind::X509Thumbprint(actual),
            ) => expected.eq_ignore_ascii_case(actual),
            (
                IdentityMappingRule::Role(expected),
                ResolvedIdentityKind::IssuedToken { role_ids, .. },
            ) => role_ids.contains(expected),
            (
                IdentityMappingRule::GroupId(expected),
                ResolvedIdentityKind::IssuedToken { group_ids, .. },
            ) => group_ids.contains(expected),
            (IdentityMappingRule::Application(expected), _) => identity
                .application_uri
                .as_deref()
                .is_some_and(|actual| actual == expected),
            _ => false,
        }
    }
}

fn push_unique(values: &mut Vec<NodeId>, value: NodeId) {
    if !values.contains(&value) {
        values.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerUserToken;
    use crate::rbac::{rules::IdentityMappingRule, WellKnownRole};
    use std::collections::BTreeMap;

    #[test]
    fn anonymous_resolves_to_anonymous_only() {
        let resolver = RoleResolver::default();
        let identity = ResolvedIdentity::anonymous(None::<&str>, Some("opc.tcp://localhost:4840"));

        let roles = resolver.resolve(&identity);

        assert_eq!(roles, vec![WellKnownRole::Anonymous.node_id()]);
    }

    #[test]
    fn username_rule_grants_role_and_authenticated_user() {
        let operator = WellKnownRole::Operator.node_id();
        let mut resolver = RoleResolver::default();
        resolver.add_mapping(
            operator.clone(),
            IdentityMappingRule::UserName("alice".into()),
        );
        let identity = ResolvedIdentity::username(
            "alice",
            Some("urn:client"),
            Some("opc.tcp://localhost:4840"),
        );

        let roles = resolver.resolve(&identity);

        assert_eq!(
            roles,
            vec![operator, WellKnownRole::AuthenticatedUser.node_id()]
        );
    }

    #[test]
    fn thumbprint_rule_grants_role_and_authenticated_user() {
        let security_admin = WellKnownRole::SecurityAdmin.node_id();
        let mut resolver = RoleResolver::default();
        resolver.add_mapping(
            security_admin.clone(),
            IdentityMappingRule::Thumbprint("AB12CD".into()),
        );
        let identity = ResolvedIdentity::x509_thumbprint(
            "AB12CD",
            Some("urn:client"),
            Some("opc.tcp://localhost:4840"),
        );

        let roles = resolver.resolve(&identity);

        assert_eq!(
            roles,
            vec![security_admin, WellKnownRole::AuthenticatedUser.node_id()]
        );
    }

    #[test]
    fn non_matching_authenticated_identity_gets_authenticated_user() {
        let mut resolver = RoleResolver::default();
        resolver.add_mapping(
            WellKnownRole::Engineer.node_id(),
            IdentityMappingRule::UserName("engineer".into()),
        );
        let identity = ResolvedIdentity::username(
            "operator",
            Some("urn:client"),
            Some("opc.tcp://localhost:4840"),
        );

        let roles = resolver.resolve(&identity);

        assert_eq!(roles, vec![WellKnownRole::AuthenticatedUser.node_id()]);
    }

    #[test]
    fn issued_token_group_rule_grants_role() {
        let observer = WellKnownRole::Observer.node_id();
        let mut resolver = RoleResolver::default();
        resolver.add_mapping(observer.clone(), IdentityMappingRule::GroupId("ops".into()));
        let identity = ResolvedIdentity::issued_token(
            ["ops"],
            std::iter::empty(),
            Some("urn:client"),
            Some("opc.tcp://localhost:4840"),
        );

        let roles = resolver.resolve(&identity);

        assert_eq!(
            roles,
            vec![observer, WellKnownRole::AuthenticatedUser.node_id()]
        );
    }

    #[test]
    fn configured_username_token_roles_build_resolver_mapping() {
        let operator = WellKnownRole::Operator.node_id();
        let token =
            ServerUserToken::user_pass("alice", "correct-password").with_roles([operator.clone()]);
        let resolver =
            RoleResolver::from_user_tokens(&BTreeMap::from([("alice-token".to_string(), token)]));
        let identity = ResolvedIdentity::username(
            "alice",
            Some("urn:client"),
            Some("opc.tcp://localhost:4840"),
        );

        let roles = resolver.resolve(&identity);

        assert_eq!(
            roles,
            vec![operator, WellKnownRole::AuthenticatedUser.node_id()]
        );
    }

    #[test]
    fn configured_x509_token_roles_build_resolver_mapping() {
        let security_admin = WellKnownRole::SecurityAdmin.node_id();
        let thumbprint =
            opcua_crypto::Thumbprint::new(&[1; opcua_crypto::Thumbprint::THUMBPRINT_SIZE])
                .expect("test thumbprint should be valid");
        let thumbprint_hex = thumbprint.as_hex_string();
        let token = ServerUserToken {
            user: "security-admin".to_string(),
            x509: Some("users/security-admin.der".to_string()),
            thumbprint: Some(thumbprint),
            roles: vec![security_admin.clone()],
            ..Default::default()
        };
        let resolver = RoleResolver::from_user_tokens(&BTreeMap::from([(
            "security-admin-token".to_string(),
            token,
        )]));
        let identity = ResolvedIdentity::x509_thumbprint(
            thumbprint_hex,
            Some("urn:client"),
            Some("opc.tcp://localhost:4840"),
        );

        let roles = resolver.resolve(&identity);

        assert_eq!(
            roles,
            vec![security_admin, WellKnownRole::AuthenticatedUser.node_id()]
        );
    }
}
