use opcua_crypto::SecurityPolicy;
use opcua_types::StatusCode;

/// Validates whether a secure-channel security policy is allowed by server configuration.
pub fn validate_security_policy(
    policy: SecurityPolicy,
    allow_legacy_crypto: bool,
) -> Result<(), StatusCode> {
    if policy.is_deprecated() && !allow_legacy_crypto {
        Err(StatusCode::BadSecurityPolicyRejected)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_deprecated_security_policy_by_default() {
        let result = validate_security_policy(SecurityPolicy::Basic256, false);

        assert_eq!(result, Err(StatusCode::BadSecurityPolicyRejected));
    }

    #[test]
    fn allows_deprecated_security_policy_when_legacy_crypto_is_enabled() {
        let result = validate_security_policy(SecurityPolicy::Basic256, true);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn accepts_modern_security_policy_by_default() {
        let result = validate_security_policy(SecurityPolicy::Aes256Sha256RsaPss, false);

        assert_eq!(result, Ok(()));
    }
}
