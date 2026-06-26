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
    applications: RoleApplicationFilter,
    endpoints: RoleEndpointFilter,
}

impl RoleRules {
    fn new(node_id: NodeId, identity_rules: Vec<IdentityMappingRule>) -> Self {
        Self {
            node_id,
            identity_rules,
            applications: RoleApplicationFilter::default(),
            endpoints: RoleEndpointFilter::default(),
        }
    }
}

#[derive(Debug, Clone)]
struct RoleApplicationFilter {
    applications: Vec<String>,
    exclude: bool,
}

impl Default for RoleApplicationFilter {
    fn default() -> Self {
        Self {
            applications: Vec::new(),
            exclude: true,
        }
    }
}

impl RoleApplicationFilter {
    fn allows(&self, application_uri: Option<&str>) -> bool {
        if self.applications.is_empty() {
            return true;
        }

        let matches = application_uri
            .is_some_and(|actual| self.applications.iter().any(|expected| expected == actual));
        if self.exclude {
            !matches
        } else {
            matches
        }
    }

    fn add(&mut self, application_uri: String) -> bool {
        if self
            .applications
            .iter()
            .any(|candidate| candidate == &application_uri)
        {
            return false;
        }

        self.applications.push(application_uri);
        true
    }

    fn remove(&mut self, application_uri: &str) -> bool {
        let Some(index) = self
            .applications
            .iter()
            .position(|candidate| candidate == application_uri)
        else {
            return false;
        };

        self.applications.remove(index);
        true
    }
}

#[derive(Debug, Clone)]
struct RoleEndpointFilter {
    endpoint_urls: Vec<String>,
    exclude: bool,
}

impl Default for RoleEndpointFilter {
    fn default() -> Self {
        Self {
            endpoint_urls: Vec::new(),
            exclude: true,
        }
    }
}

impl RoleEndpointFilter {
    fn allows(&self, endpoint_url: Option<&str>) -> bool {
        if self.endpoint_urls.is_empty() {
            return true;
        }

        let matches = endpoint_url
            .is_some_and(|actual| self.endpoint_urls.iter().any(|expected| expected == actual));
        if self.exclude {
            !matches
        } else {
            matches
        }
    }

    fn add(&mut self, endpoint_url: String) -> bool {
        if self
            .endpoint_urls
            .iter()
            .any(|candidate| candidate == &endpoint_url)
        {
            return false;
        }

        self.endpoint_urls.push(endpoint_url);
        true
    }

    fn remove(&mut self, endpoint_url: &str) -> bool {
        let Some(index) = self
            .endpoint_urls
            .iter()
            .position(|candidate| candidate == endpoint_url)
        else {
            return false;
        };

        self.endpoint_urls.remove(index);
        true
    }
}

/// Resolves activated session identities to granted OPC UA role NodeIds.
#[derive(Debug, Clone)]
pub(crate) struct RoleResolver {
    roles: Vec<RoleRules>,
    runtime_roles: Vec<NodeId>,
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
            roles.push(RoleRules::new(role.node_id(), identity_rules));
        }

        Self {
            roles,
            runtime_roles: Vec::new(),
        }
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

    pub(crate) fn register_role(&mut self, role_node_id: NodeId) {
        if self.roles.iter().any(|role| role.node_id == role_node_id) {
            push_unique(&mut self.runtime_roles, role_node_id);
            return;
        }

        self.roles
            .push(RoleRules::new(role_node_id.clone(), Vec::new()));
        push_unique(&mut self.runtime_roles, role_node_id);
    }

    pub(crate) fn remove_role(&mut self, role_node_id: &NodeId) -> bool {
        if !self.is_runtime_role(role_node_id) {
            return false;
        }

        let Some(index) = self
            .roles
            .iter()
            .position(|role| &role.node_id == role_node_id)
        else {
            return false;
        };

        self.roles.remove(index);
        self.runtime_roles.retain(|role| role != role_node_id);
        true
    }

    pub(crate) fn contains_role(&self, role_node_id: &NodeId) -> bool {
        self.roles.iter().any(|role| &role.node_id == role_node_id)
    }

    pub(crate) fn is_runtime_role(&self, role_node_id: &NodeId) -> bool {
        self.runtime_roles.iter().any(|role| role == role_node_id)
    }

    pub(crate) fn add_mapping(&mut self, role_node_id: NodeId, rule: IdentityMappingRule) {
        if let Some(role) = self
            .roles
            .iter_mut()
            .find(|role| role.node_id == role_node_id)
        {
            role.identity_rules.push(rule);
        } else {
            self.roles.push(RoleRules::new(role_node_id, vec![rule]));
        }
    }

    pub(crate) fn remove_mapping(
        &mut self,
        role_node_id: &NodeId,
        rule: &IdentityMappingRule,
    ) -> bool {
        let Some(role) = self
            .roles
            .iter_mut()
            .find(|role| &role.node_id == role_node_id)
        else {
            return false;
        };

        let Some(index) = role
            .identity_rules
            .iter()
            .position(|candidate| candidate == rule)
        else {
            return false;
        };

        role.identity_rules.remove(index);
        true
    }

    pub(crate) fn add_application(
        &mut self,
        role_node_id: &NodeId,
        application_uri: String,
    ) -> bool {
        let Some(role) = self
            .roles
            .iter_mut()
            .find(|role| &role.node_id == role_node_id)
        else {
            return false;
        };

        role.applications.add(application_uri)
    }

    pub(crate) fn remove_application(
        &mut self,
        role_node_id: &NodeId,
        application_uri: &str,
    ) -> bool {
        let Some(role) = self
            .roles
            .iter_mut()
            .find(|role| &role.node_id == role_node_id)
        else {
            return false;
        };

        role.applications.remove(application_uri)
    }

    pub(crate) fn add_endpoint(&mut self, role_node_id: &NodeId, endpoint_url: String) -> bool {
        let Some(role) = self
            .roles
            .iter_mut()
            .find(|role| &role.node_id == role_node_id)
        else {
            return false;
        };

        role.endpoints.add(endpoint_url)
    }

    pub(crate) fn remove_endpoint(&mut self, role_node_id: &NodeId, endpoint_url: &str) -> bool {
        let Some(role) = self
            .roles
            .iter_mut()
            .find(|role| &role.node_id == role_node_id)
        else {
            return false;
        };

        role.endpoints.remove(endpoint_url)
    }

    pub(crate) fn resolve(&self, identity: &ResolvedIdentity) -> Vec<NodeId> {
        if identity.is_anonymous() {
            let anonymous = WellKnownRole::Anonymous.node_id();
            return self
                .roles
                .iter()
                .find(|role| role.node_id == anonymous)
                .filter(|role| role.allows_application(identity.application_uri.as_deref()))
                .filter(|role| role.allows_endpoint(identity.endpoint_url.as_deref()))
                .map(|_| vec![anonymous])
                .unwrap_or_default();
        }

        let anonymous = WellKnownRole::Anonymous.node_id();
        let authenticated_user = WellKnownRole::AuthenticatedUser.node_id();
        let mut granted = Vec::new();
        let mut grant_authenticated_user = false;

        for role in &self.roles {
            if role.node_id == anonymous {
                continue;
            }

            if role
                .identity_rules
                .iter()
                .any(|rule| Self::matches_rule(rule, identity))
                && role.allows_application(identity.application_uri.as_deref())
                && role.allows_endpoint(identity.endpoint_url.as_deref())
            {
                if role.node_id == authenticated_user {
                    grant_authenticated_user = true;
                } else {
                    push_unique(&mut granted, role.node_id.clone());
                }
            }
        }

        if grant_authenticated_user {
            push_unique(&mut granted, authenticated_user);
        }
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

impl RoleRules {
    fn allows_application(&self, application_uri: Option<&str>) -> bool {
        self.applications.allows(application_uri)
    }

    fn allows_endpoint(&self, endpoint_url: Option<&str>) -> bool {
        self.endpoints.allows(endpoint_url)
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

    #[test]
    fn runtime_role_can_be_registered_and_removed() {
        let dynamic_role = NodeId::new(1, "RuntimeRole");
        let mut resolver = RoleResolver::default();

        resolver.register_role(dynamic_role.clone());
        resolver.add_mapping(
            dynamic_role.clone(),
            IdentityMappingRule::UserName("operator".into()),
        );

        let identity = ResolvedIdentity::username(
            "operator",
            Some("urn:client"),
            Some("opc.tcp://localhost:4840"),
        );
        assert!(resolver.resolve(&identity).contains(&dynamic_role));

        assert!(resolver.remove_role(&dynamic_role));

        assert!(!resolver.resolve(&identity).contains(&dynamic_role));
    }

    #[test]
    fn remove_mapping_retracts_identity_rule() {
        let operator = WellKnownRole::Operator.node_id();
        let mut resolver = RoleResolver::default();
        let rule = IdentityMappingRule::UserName("operator".into());
        resolver.add_mapping(operator.clone(), rule.clone());
        let identity = ResolvedIdentity::username(
            "operator",
            Some("urn:client"),
            Some("opc.tcp://localhost:4840"),
        );
        assert!(resolver.resolve(&identity).contains(&operator));

        assert!(resolver.remove_mapping(&operator, &rule));

        assert!(!resolver.resolve(&identity).contains(&operator));
        assert!(!resolver.remove_mapping(&operator, &rule));
    }

    #[test]
    fn application_filter_excludes_configured_application_uri() {
        let operator = WellKnownRole::Operator.node_id();
        let mut resolver = RoleResolver::default();
        resolver.add_mapping(
            operator.clone(),
            IdentityMappingRule::UserName("operator".into()),
        );
        let blocked_identity = ResolvedIdentity::username(
            "operator",
            Some("urn:blocked-client"),
            Some("opc.tcp://localhost:4840"),
        );
        let other_identity = ResolvedIdentity::username(
            "operator",
            Some("urn:other-client"),
            Some("opc.tcp://localhost:4840"),
        );

        assert!(resolver.resolve(&blocked_identity).contains(&operator));

        assert!(resolver.add_application(&operator, "urn:blocked-client".to_string()));

        assert!(!resolver.resolve(&blocked_identity).contains(&operator));
        assert!(resolver.resolve(&other_identity).contains(&operator));

        assert!(resolver.remove_application(&operator, "urn:blocked-client"));

        assert!(resolver.resolve(&blocked_identity).contains(&operator));
        assert!(!resolver.remove_application(&operator, "urn:blocked-client"));
    }

    #[test]
    fn endpoint_filter_excludes_configured_endpoint_url() {
        let operator = WellKnownRole::Operator.node_id();
        let mut resolver = RoleResolver::default();
        resolver.add_mapping(
            operator.clone(),
            IdentityMappingRule::UserName("operator".into()),
        );
        let blocked_identity = ResolvedIdentity::username(
            "operator",
            Some("urn:client"),
            Some("opc.tcp://blocked.example:4840"),
        );
        let other_identity = ResolvedIdentity::username(
            "operator",
            Some("urn:client"),
            Some("opc.tcp://allowed.example:4840"),
        );

        assert!(resolver.resolve(&blocked_identity).contains(&operator));

        assert!(resolver.add_endpoint(&operator, "opc.tcp://blocked.example:4840".to_string()));

        assert!(!resolver.resolve(&blocked_identity).contains(&operator));
        assert!(resolver.resolve(&other_identity).contains(&operator));

        assert!(resolver.remove_endpoint(&operator, "opc.tcp://blocked.example:4840"));

        assert!(resolver.resolve(&blocked_identity).contains(&operator));
        assert!(!resolver.remove_endpoint(&operator, "opc.tcp://blocked.example:4840"));
    }
}
