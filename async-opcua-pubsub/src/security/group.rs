//! Runtime PubSub security group key material.

use std::time::Duration;

use opcua_crypto::{random, AesKey};
use opcua_types::{Error, StatusCode};

/// Default HMAC-SHA256 signing key length in bytes.
pub const DEFAULT_SIGNING_KEY_LENGTH: usize = 32;
/// Default AES-256 encryption key length in bytes.
pub const DEFAULT_ENCRYPTION_KEY_LENGTH: usize = 32;
/// Default PubSub key nonce length in bytes.
pub const DEFAULT_KEY_NONCE_LENGTH: usize = 32;

/// Symmetric key material used to secure PubSub NetworkMessages.
#[derive(Debug)]
pub struct SecurityKeySet {
    signing_key: Vec<u8>,
    encryption_key: AesKey,
    key_nonce: Vec<u8>,
}

impl SecurityKeySet {
    /// Creates a key set from caller-provided key material.
    pub fn from_parts(
        signing_key: Vec<u8>,
        encryption_key: Vec<u8>,
        key_nonce: Vec<u8>,
    ) -> Result<Self, Error> {
        if signing_key.is_empty() {
            return Err(invalid_argument("signing key must not be empty"));
        }

        if encryption_key.is_empty() {
            return Err(invalid_argument("encryption key must not be empty"));
        }

        if key_nonce.is_empty() {
            return Err(invalid_argument("key nonce must not be empty"));
        }

        Ok(Self {
            signing_key,
            encryption_key: AesKey::new(encryption_key),
            key_nonce,
        })
    }

    /// Generates a default key set suitable for AES-256 PubSub security.
    pub fn generate() -> Self {
        Self {
            signing_key: random_bytes(DEFAULT_SIGNING_KEY_LENGTH),
            encryption_key: AesKey::new(random_bytes(DEFAULT_ENCRYPTION_KEY_LENGTH)),
            key_nonce: random_bytes(DEFAULT_KEY_NONCE_LENGTH),
        }
    }

    /// Returns the symmetric signing key bytes.
    pub fn signing_key(&self) -> &[u8] {
        &self.signing_key
    }

    /// Returns the symmetric AES encryption key.
    pub fn encryption_key(&self) -> &AesKey {
        &self.encryption_key
    }

    /// Returns the key nonce bytes.
    pub fn key_nonce(&self) -> &[u8] {
        &self.key_nonce
    }
}

impl Clone for SecurityKeySet {
    fn clone(&self) -> Self {
        Self {
            signing_key: self.signing_key.clone(),
            encryption_key: AesKey::new(self.encryption_key.value().to_vec()),
            key_nonce: self.key_nonce.clone(),
        }
    }
}

impl PartialEq for SecurityKeySet {
    fn eq(&self, other: &Self) -> bool {
        self.signing_key == other.signing_key
            && self.encryption_key.value() == other.encryption_key.value()
            && self.key_nonce == other.key_nonce
    }
}

impl Eq for SecurityKeySet {}

/// Runtime PubSub security group with current and next symmetric keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityGroup {
    group_id: String,
    current_key: SecurityKeySet,
    next_key: SecurityKeySet,
    key_lifetime: Duration,
}

impl SecurityGroup {
    /// Creates a security group with generated current and next key sets.
    pub fn new(group_id: impl Into<String>, key_lifetime: Duration) -> Result<Self, Error> {
        Self::with_key_sets(
            group_id,
            SecurityKeySet::generate(),
            SecurityKeySet::generate(),
            key_lifetime,
        )
    }

    /// Creates a security group from caller-provided current and next key sets.
    pub fn with_key_sets(
        group_id: impl Into<String>,
        current_key: SecurityKeySet,
        next_key: SecurityKeySet,
        key_lifetime: Duration,
    ) -> Result<Self, Error> {
        let group_id = group_id.into();

        if group_id.trim().is_empty() {
            return Err(invalid_argument("security group id must not be empty"));
        }

        if key_lifetime.is_zero() {
            return Err(invalid_argument(
                "security group key lifetime must be greater than zero",
            ));
        }

        Ok(Self {
            group_id,
            current_key,
            next_key,
            key_lifetime,
        })
    }

    /// Returns the security group identifier.
    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    /// Returns the current key set used by publishers and subscribers.
    pub fn current_key_set(&self) -> &SecurityKeySet {
        &self.current_key
    }

    /// Returns the next key set staged for rotation.
    pub fn next_key_set(&self) -> &SecurityKeySet {
        &self.next_key
    }

    /// Returns the current AES encryption key.
    pub fn current_key(&self) -> &AesKey {
        self.current_key.encryption_key()
    }

    /// Returns the next AES encryption key.
    pub fn next_key(&self) -> &AesKey {
        self.next_key.encryption_key()
    }

    /// Returns the configured lifetime for each generated key.
    pub fn key_lifetime(&self) -> Duration {
        self.key_lifetime
    }

    /// Promotes the staged next key set and generates a new staged key set.
    pub fn rotate_key_sets(&mut self) {
        self.current_key = std::mem::replace(&mut self.next_key, SecurityKeySet::generate());
    }
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    random::bytes(&mut bytes);
    bytes
}

fn invalid_argument(message: &'static str) -> Error {
    Error::new(StatusCode::BadInvalidArgument, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_rejects_zero_key_lifetime() {
        let error = SecurityGroup::new("group-1", Duration::ZERO).unwrap_err();

        assert_eq!(error.status(), StatusCode::BadInvalidArgument);
    }

    #[test]
    fn new_generates_current_and_next_key_sets() {
        let group = SecurityGroup::new("group-1", Duration::from_secs(60)).unwrap();

        assert_eq!(group.group_id(), "group-1");
        assert_eq!(group.key_lifetime(), Duration::from_secs(60));
        assert_eq!(
            group.current_key_set().signing_key().len(),
            DEFAULT_SIGNING_KEY_LENGTH
        );
        assert_eq!(
            group.current_key_set().encryption_key().value().len(),
            DEFAULT_ENCRYPTION_KEY_LENGTH
        );
        assert_eq!(
            group.current_key_set().key_nonce().len(),
            DEFAULT_KEY_NONCE_LENGTH
        );
        assert_eq!(
            group.next_key_set().encryption_key().value().len(),
            DEFAULT_ENCRYPTION_KEY_LENGTH
        );
    }

    #[test]
    fn key_set_clone_preserves_key_material() {
        let key_set = SecurityKeySet::from_parts(vec![1; 32], vec![2; 32], vec![3; 32]).unwrap();

        assert_eq!(key_set.clone(), key_set);
    }
}
