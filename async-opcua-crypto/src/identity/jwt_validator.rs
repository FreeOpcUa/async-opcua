//! Local OAuth2 JWT validation backed by a configured issuer certificate.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use opcua_types::status_code::StatusCode;
use serde_json::Value;

use crate::X509;

use super::{ClaimProfile, OAuth2IdentityValidator};

/// OAuth2 identity validator that verifies RS256 JWTs against one configured issuer certificate.
pub struct LocalOAuth2Validator {
    issuer_cert: X509,
    issuer: String,
    audience: String,
}

impl LocalOAuth2Validator {
    /// Creates a local OAuth2 validator using the supplied issuer certificate.
    #[must_use]
    pub fn new(issuer: String, audience: String, issuer_cert: X509) -> Self {
        Self {
            issuer_cert,
            issuer,
            audience,
        }
    }

    fn reject<T>() -> Result<T, StatusCode> {
        Err(StatusCode::BadIdentityTokenRejected)
    }

    fn strip_bearer_prefix(token_jwt: &str) -> &str {
        let token = token_jwt.trim();
        token
            .strip_prefix("Bearer ")
            .or_else(|| token.strip_prefix("bearer "))
            .unwrap_or(token)
            .trim()
    }

    fn decode_jwt_part(part: &str) -> Result<Vec<u8>, StatusCode> {
        BASE64_URL_SAFE_NO_PAD
            .decode(part)
            .map_err(|_| StatusCode::BadIdentityTokenRejected)
    }

    fn parse_json_part(part: &str) -> Result<Value, StatusCode> {
        let decoded = Self::decode_jwt_part(part)?;
        serde_json::from_slice(&decoded).map_err(|_| StatusCode::BadIdentityTokenRejected)
    }

    fn validate_algorithm(header: &Value) -> Result<(), StatusCode> {
        if header.get("alg").and_then(Value::as_str) == Some("RS256") {
            Ok(())
        } else {
            Self::reject()
        }
    }

    fn validate_issuer(&self, payload: &Value) -> Result<(), StatusCode> {
        if payload.get("iss").and_then(Value::as_str) == Some(self.issuer.as_str()) {
            Ok(())
        } else {
            Self::reject()
        }
    }

    fn validate_audience(&self, payload: &Value) -> Result<(), StatusCode> {
        match payload.get("aud") {
            Some(Value::String(audience)) if audience == &self.audience => Ok(()),
            Some(Value::Array(audiences))
                if audiences
                    .iter()
                    .any(|audience| audience.as_str() == Some(self.audience.as_str())) =>
            {
                Ok(())
            }
            _ => Self::reject(),
        }
    }

    fn numeric_date_claim(payload: &Value, name: &str) -> Option<i64> {
        payload
            .get(name)
            .and_then(|value| {
                value
                    .as_i64()
                    .or_else(|| value.as_u64().map(|value| value as i64))
            })
            .filter(|value| *value >= 0)
    }

    fn validate_expiration(payload: &Value) -> Result<(), StatusCode> {
        let exp =
            Self::numeric_date_claim(payload, "exp").ok_or(StatusCode::BadIdentityTokenRejected)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| StatusCode::BadIdentityTokenRejected)?
            .as_secs() as i64;

        if exp <= now {
            return Self::reject();
        }

        if let Some(nbf) = Self::numeric_date_claim(payload, "nbf") {
            if now < nbf {
                return Self::reject();
            }
        }

        Ok(())
    }

    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<(), StatusCode> {
        let public_key = self
            .issuer_cert
            .public_key()
            .map_err(|_| StatusCode::BadIdentityTokenRejected)?;
        if public_key.verify_sha256(data, signature).unwrap_or(false) {
            return Ok(());
        }

        Self::reject()
    }

    fn string_claim(payload: &Value, names: &[&str]) -> Option<String> {
        names
            .iter()
            .find_map(|name| payload.get(*name).and_then(Value::as_str))
            .map(ToString::to_string)
    }

    fn string_list_claim(payload: &Value, name: &str) -> Vec<String> {
        match payload.get(name) {
            Some(Value::String(value)) => vec![value.clone()],
            Some(Value::Array(values)) => values
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect(),
            _ => Vec::new(),
        }
    }

    fn permissions(payload: &Value) -> Vec<String> {
        let permissions = Self::string_list_claim(payload, "permissions");
        if !permissions.is_empty() {
            return permissions;
        }

        payload
            .get("scope")
            .and_then(Value::as_str)
            .map(|scope| scope.split_whitespace().map(ToString::to_string).collect())
            .unwrap_or_default()
    }

    fn claim_profile(payload: &Value) -> Result<ClaimProfile, StatusCode> {
        let username = Self::string_claim(payload, &["username", "preferred_username", "sub"])
            .ok_or(StatusCode::BadIdentityTokenRejected)?;

        Ok(ClaimProfile {
            username,
            roles: Self::string_list_claim(payload, "roles"),
            permissions: Self::permissions(payload),
        })
    }
}

impl OAuth2IdentityValidator for LocalOAuth2Validator {
    fn validate_token(&self, token_jwt: &str) -> Result<ClaimProfile, StatusCode> {
        let token = Self::strip_bearer_prefix(token_jwt);
        let parts = token.split('.').collect::<Vec<_>>();
        let [header_part, payload_part, signature_part] = parts.as_slice() else {
            return Self::reject();
        };

        let header = Self::parse_json_part(header_part)?;
        Self::validate_algorithm(&header)?;

        let payload = Self::parse_json_part(payload_part)?;
        self.validate_issuer(&payload)?;
        self.validate_audience(&payload)?;
        Self::validate_expiration(&payload)?;

        let signature = Self::decode_jwt_part(signature_part)?;
        let data = format!("{header_part}.{payload_part}");
        self.verify_signature(data.as_bytes(), &signature)?;

        Self::claim_profile(&payload)
    }
}
