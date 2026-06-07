#![allow(unreachable_pub)]

use opcua_crypto::identity::ClaimProfile;

/// Authorization properties derived from a validated session identity token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAuthorizationProfile {
    /// Authenticated username or subject.
    pub username: String,
    /// Role names from the validated identity token.
    pub roles: Vec<String>,
    /// Permission names from the validated identity token.
    pub permissions: Vec<String>,
    /// Whether the session has administrator privileges.
    pub is_admin: bool,
    /// Whether the session has operator privileges.
    pub is_operator: bool,
    /// Whether the session has read-only observer privileges.
    pub is_observer: bool,
}

impl SessionAuthorizationProfile {
    /// Maps OAuth2 claim values into the session authorization profile.
    pub fn from_claims(claims: &ClaimProfile) -> Self {
        let mut is_admin = false;
        let mut is_operator = false;
        let mut is_observer = false;
        for role in &claims.roles {
            match role.to_lowercase().as_str() {
                "admin" | "administrator" => is_admin = true,
                "operator" | "worker" => is_operator = true,
                "observer" | "viewer" | "user" => is_observer = true,
                _ => {}
            }
        }
        Self {
            username: claims.username.clone(),
            roles: claims.roles.clone(),
            permissions: claims.permissions.clone(),
            is_admin,
            is_operator,
            is_observer,
        }
    }

    /// Returns whether the profile may read nodes.
    pub fn can_read(&self) -> bool {
        self.is_admin || self.is_operator || self.is_observer
    }

    /// Returns whether the profile may write nodes.
    pub fn can_write(&self) -> bool {
        self.is_admin || self.is_operator
    }
}
