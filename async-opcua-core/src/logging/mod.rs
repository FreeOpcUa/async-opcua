//! Logging and security-by-default tracing helpers.
//! Includes utilities for masking sensitive credentials and hashing OAuth2 tokens.

use sha2::{Digest, Sha256};

/// Log message redaction helpers.
pub mod redact;

pub use redact::redact_log_message;

/// Redacts sensitive information like passwords or private keys by replacing them with a placeholder.
pub fn mask_sensitive(value: &str) -> String {
    if value.is_empty() {
        String::new()
    } else {
        "[REDACTED]".to_string()
    }
}

/// Computes a SHA-256 hash of a JWT (OAuth2) token to safely trace/log identity without exposing the token payload.
pub fn hash_jwt(token: &str) -> String {
    if token.is_empty() {
        return "empty_token".to_string();
    }
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_sensitive() {
        assert_eq!(mask_sensitive("my_super_secret_password"), "[REDACTED]");
        assert_eq!(mask_sensitive(""), "");
    }

    #[test]
    fn test_hash_jwt() {
        let token = "header.payload.signature";
        let hash = hash_jwt(token);
        assert_ne!(hash, token);
        assert_eq!(hash.len(), 64); // SHA-256 hex length is 64 characters
        assert_eq!(hash_jwt(""), "empty_token");
    }
}
