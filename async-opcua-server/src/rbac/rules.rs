use std::str::FromStr;

use opcua_types::{IdentityCriteriaType, IdentityMappingRuleType, NodeId, StatusCode, UAString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Runtime representation of Part 18 IdentityMappingRuleType criteria used for role resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityMappingRule {
    /// Matches anonymous identities.
    AnonymousIdentity,
    /// Matches any successfully authenticated non-anonymous identity.
    AuthenticatedUser,
    /// Matches a user-name identity by user name.
    UserName(String),
    /// Matches an X.509 identity by certificate thumbprint.
    Thumbprint(String),
    /// Matches an identity that has already been granted the referenced role.
    #[serde(
        serialize_with = "serialize_node_id",
        deserialize_with = "deserialize_node_id"
    )]
    Role(NodeId),
    /// Matches an issued-token identity by group identifier.
    GroupId(String),
    /// Matches a client application URI.
    Application(String),
}

/// Error returned when a generated identity mapping rule cannot be represented by the runtime model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityMappingRuleConversionError {
    /// The generated rule used a criteria type that is not supported by the runtime resolver.
    UnsupportedCriteriaType(IdentityCriteriaType),
    /// The generated role criteria could not be parsed as a NodeId.
    InvalidRoleNodeId(StatusCode),
}

impl IdentityMappingRule {
    /// Creates a rule that matches anonymous identities.
    pub fn anonymous() -> Self {
        Self::AnonymousIdentity
    }

    /// Creates a rule that matches any successfully authenticated non-anonymous identity.
    pub fn authenticated_user() -> Self {
        Self::AuthenticatedUser
    }

    /// Creates a rule that matches a user-name identity by user name.
    pub fn user_name(user_name: impl Into<String>) -> Self {
        Self::UserName(user_name.into())
    }

    /// Creates a rule that matches an X.509 identity by certificate thumbprint.
    pub fn thumbprint(thumbprint: impl Into<String>) -> Self {
        Self::Thumbprint(thumbprint.into())
    }

    /// Creates a rule that matches an identity already granted the referenced role.
    pub fn role(role_node_id: NodeId) -> Self {
        Self::Role(role_node_id)
    }

    /// Creates a rule that matches an issued-token identity by group identifier.
    pub fn group_id(group_id: impl Into<String>) -> Self {
        Self::GroupId(group_id.into())
    }

    /// Creates a rule that matches a client application URI.
    pub fn application(application_uri: impl Into<String>) -> Self {
        Self::Application(application_uri.into())
    }

    pub(crate) fn criteria_type(&self) -> IdentityCriteriaType {
        match self {
            Self::AnonymousIdentity => IdentityCriteriaType::Anonymous,
            Self::AuthenticatedUser => IdentityCriteriaType::AuthenticatedUser,
            Self::UserName(_) => IdentityCriteriaType::UserName,
            Self::Thumbprint(_) => IdentityCriteriaType::Thumbprint,
            Self::Role(_) => IdentityCriteriaType::Role,
            Self::GroupId(_) => IdentityCriteriaType::GroupId,
            Self::Application(_) => IdentityCriteriaType::Application,
        }
    }

    fn criteria(&self) -> UAString {
        match self {
            Self::AnonymousIdentity | Self::AuthenticatedUser => UAString::null(),
            Self::UserName(value)
            | Self::Thumbprint(value)
            | Self::GroupId(value)
            | Self::Application(value) => UAString::from(value.as_str()),
            Self::Role(value) => UAString::from(value.to_string()),
        }
    }
}

fn serialize_node_id<S>(node_id: &NodeId, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    node_id.to_string().serialize(serializer)
}

fn deserialize_node_id<'de, D>(deserializer: D) -> Result<NodeId, D::Error>
where
    D: Deserializer<'de>,
{
    let node_id = String::deserialize(deserializer)?;
    NodeId::from_str(&node_id).map_err(serde::de::Error::custom)
}

impl From<&IdentityMappingRule> for IdentityCriteriaType {
    fn from(value: &IdentityMappingRule) -> Self {
        value.criteria_type()
    }
}

impl From<IdentityMappingRule> for IdentityCriteriaType {
    fn from(value: IdentityMappingRule) -> Self {
        Self::from(&value)
    }
}

impl From<&IdentityMappingRule> for IdentityMappingRuleType {
    fn from(value: &IdentityMappingRule) -> Self {
        Self {
            criteria_type: value.criteria_type(),
            criteria: value.criteria(),
        }
    }
}

impl From<IdentityMappingRule> for IdentityMappingRuleType {
    fn from(value: IdentityMappingRule) -> Self {
        Self::from(&value)
    }
}

impl TryFrom<&IdentityMappingRuleType> for IdentityMappingRule {
    type Error = IdentityMappingRuleConversionError;

    fn try_from(value: &IdentityMappingRuleType) -> Result<Self, Self::Error> {
        let criteria = value.criteria.as_ref();
        match value.criteria_type {
            IdentityCriteriaType::Anonymous => Ok(Self::AnonymousIdentity),
            IdentityCriteriaType::AuthenticatedUser => Ok(Self::AuthenticatedUser),
            IdentityCriteriaType::UserName => Ok(Self::UserName(criteria.into())),
            IdentityCriteriaType::Thumbprint => Ok(Self::Thumbprint(criteria.into())),
            IdentityCriteriaType::Role => NodeId::from_str(criteria)
                .map(Self::Role)
                .map_err(Self::Error::InvalidRoleNodeId),
            IdentityCriteriaType::GroupId => Ok(Self::GroupId(criteria.into())),
            IdentityCriteriaType::Application => Ok(Self::Application(criteria.into())),
            IdentityCriteriaType::X509Subject | IdentityCriteriaType::TrustedApplication => {
                Err(Self::Error::UnsupportedCriteriaType(value.criteria_type))
            }
        }
    }
}

impl TryFrom<IdentityMappingRuleType> for IdentityMappingRule {
    type Error = IdentityMappingRuleConversionError;

    fn try_from(value: IdentityMappingRuleType) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opcua_types::{IdentityCriteriaType, IdentityMappingRuleType, NodeId, UAString};

    #[test]
    fn generated_rule_converts_to_runtime_rule() {
        let generated = IdentityMappingRuleType {
            criteria_type: IdentityCriteriaType::UserName,
            criteria: UAString::from("operator"),
        };

        let rule = IdentityMappingRule::try_from(generated);

        assert_eq!(rule, Ok(IdentityMappingRule::UserName("operator".into())));
    }

    #[test]
    fn runtime_role_rule_converts_to_generated_node_id_string() {
        let generated =
            IdentityMappingRuleType::from(IdentityMappingRule::Role(NodeId::new(0, 15680)));

        assert_eq!(generated.criteria_type, IdentityCriteriaType::Role);
        assert_eq!(generated.criteria, "i=15680");
    }
}
