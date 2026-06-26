use std::str::FromStr;

use opcua_types::{IdentityCriteriaType, IdentityMappingRuleType, NodeId, StatusCode, UAString};

/// Runtime representation of Part 18 IdentityMappingRuleType criteria used for role resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IdentityMappingRule {
    AnonymousIdentity,
    AuthenticatedUser,
    UserName(String),
    Thumbprint(String),
    Role(NodeId),
    GroupId(String),
    Application(String),
}

/// Error returned when a generated identity mapping rule cannot be represented by the runtime model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentityMappingRuleConversionError {
    UnsupportedCriteriaType(IdentityCriteriaType),
    InvalidRoleNodeId(StatusCode),
}

impl IdentityMappingRule {
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
