//! OAuth2 identity validation traits and claim profiles.

use opcua_types::status_code::StatusCode;

pub mod jwt_validator;

pub use jwt_validator::LocalOAuth2Validator;

/// Claims extracted from a validated OAuth2 identity token.
#[derive(Debug, Clone)]
pub struct ClaimProfile {
    /// Stable username or subject for the authenticated identity.
    pub username: String,
    /// Role names granted to the authenticated identity.
    pub roles: Vec<String>,
    /// Permission names granted to the authenticated identity.
    pub permissions: Vec<String>,
}

/// Validates OAuth2 JWT issued identity tokens and maps them to local claims.
pub trait OAuth2IdentityValidator: Send + Sync {
    /// Validates a JWT and returns its claim profile.
    fn validate_token(&self, token_jwt: &str) -> Result<ClaimProfile, StatusCode>;
}
