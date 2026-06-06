//! OAuth2/JWT helpers for OPC UA issued identity tokens.

use std::collections::BTreeMap;

use base64::{
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use opcua_core::logging::hash_jwt;
use opcua_types::{ByteString, Error, StatusCode};
use serde::Deserialize;
use serde_json::Value;

/// Decoded JWT header fields relevant to server-side validation.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct JwtHeader {
    /// Signing algorithm declared by the token.
    pub alg: String,
    /// Optional key id used by external authenticators/JWKS caches.
    #[serde(default)]
    pub kid: Option<String>,
    /// Optional token type.
    #[serde(default)]
    pub typ: Option<String>,
}

/// Decoded JWT claims used for OAuth2 session identity validation.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct JwtClaims {
    /// Subject claim used as the stable user identity.
    #[serde(default)]
    pub sub: Option<String>,
    /// Issuer claim.
    #[serde(default)]
    pub iss: Option<String>,
    /// Audience claim.
    #[serde(default)]
    pub aud: Option<Value>,
    /// Expiration time, as a Unix timestamp.
    #[serde(default)]
    pub exp: Option<i64>,
    /// Not-before time, as a Unix timestamp.
    #[serde(default)]
    pub nbf: Option<i64>,
    /// Issued-at time, as a Unix timestamp.
    #[serde(default)]
    pub iat: Option<i64>,
    /// JWT id.
    #[serde(default)]
    pub jti: Option<String>,
    /// OAuth2 scope claim.
    #[serde(default)]
    pub scope: Option<String>,
    /// Additional vendor-specific claims.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Validated issued JWT token.
#[derive(Debug, Clone, PartialEq)]
pub struct IssuedJwt {
    raw: String,
    header: JwtHeader,
    claims: JwtClaims,
}

impl IssuedJwt {
    /// Raw compact JWT string without a `Bearer ` prefix.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// SHA-256 hash of the raw JWT suitable for logs.
    pub fn token_hash(&self) -> String {
        hash_jwt(&self.raw)
    }

    /// Decoded JWT header.
    pub fn header(&self) -> &JwtHeader {
        &self.header
    }

    /// Decoded JWT claims.
    pub fn claims(&self) -> &JwtClaims {
        &self.claims
    }

    /// Return the normalized JWT as OPC UA token bytes.
    pub fn token_data(&self) -> ByteString {
        ByteString::from(self.raw.as_bytes())
    }
}

/// JWT claim validation settings.
#[derive(Debug, Clone, Copy)]
pub struct JwtValidation {
    /// Current Unix timestamp.
    pub now_epoch_seconds: i64,
    /// Allowed clock skew in seconds.
    pub clock_skew_seconds: i64,
    /// Require an expiration claim.
    pub require_expiration: bool,
    /// Require a subject claim.
    pub require_subject: bool,
}

impl Default for JwtValidation {
    fn default() -> Self {
        Self {
            now_epoch_seconds: chrono::Utc::now().timestamp(),
            clock_skew_seconds: 60,
            require_expiration: true,
            require_subject: true,
        }
    }
}

/// Parse and validate an OPC UA issued identity token as a compact JWT.
///
/// This validates JWT structure and registered time/identity claims before a custom
/// [`crate::authenticator::AuthManager`] performs issuer, audience, key, and signature trust checks.
pub fn validate_issued_jwt(token_data: &ByteString) -> Result<IssuedJwt, Error> {
    validate_issued_jwt_with(token_data, JwtValidation::default())
}

/// Parse and validate an OPC UA issued identity token as a compact JWT.
pub fn validate_issued_jwt_with(
    token_data: &ByteString,
    validation: JwtValidation,
) -> Result<IssuedJwt, Error> {
    let raw = token_string(token_data)?;
    let (header, claims) = parse_jwt(&raw)?;
    validate_header(&header)?;
    validate_claims(&claims, validation)?;

    Ok(IssuedJwt {
        raw,
        header,
        claims,
    })
}

fn token_string(token_data: &ByteString) -> Result<String, Error> {
    if token_data.is_null_or_empty() {
        return Err(invalid("issued identity token is empty"));
    }

    let raw = std::str::from_utf8(token_data.as_ref())
        .map_err(|_| invalid("issued identity token is not valid UTF-8"))?
        .trim();

    let raw = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .unwrap_or(raw)
        .trim();

    if raw.is_empty() {
        return Err(invalid("issued identity token is empty"));
    }

    Ok(raw.to_owned())
}

fn parse_jwt(raw: &str) -> Result<(JwtHeader, JwtClaims), Error> {
    let parts = raw.split('.').collect::<Vec<_>>();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(invalid("issued identity token is not a compact JWT"));
    }

    let header = decode_json::<JwtHeader>(parts[0], "JWT header")?;
    let claims = decode_json::<JwtClaims>(parts[1], "JWT claims")?;
    Ok((header, claims))
}

fn validate_header(header: &JwtHeader) -> Result<(), Error> {
    if header.alg.trim().is_empty() || header.alg.eq_ignore_ascii_case("none") {
        return Err(rejected("issued JWT uses an unsupported signing algorithm"));
    }
    Ok(())
}

fn validate_claims(claims: &JwtClaims, validation: JwtValidation) -> Result<(), Error> {
    if validation.require_subject && claims.sub.as_deref().map(str::is_empty).unwrap_or(true) {
        return Err(rejected("issued JWT is missing a subject claim"));
    }

    let skew = validation.clock_skew_seconds.max(0);
    let now = validation.now_epoch_seconds;

    match claims.exp {
        Some(exp) if exp.saturating_add(skew) < now => {
            return Err(rejected("issued JWT has expired"));
        }
        Some(_) => {}
        None if validation.require_expiration => {
            return Err(rejected("issued JWT is missing an expiration claim"));
        }
        None => {}
    }

    if let Some(nbf) = claims.nbf {
        if nbf.saturating_sub(skew) > now {
            return Err(rejected("issued JWT is not valid yet"));
        }
    }

    if let Some(iat) = claims.iat {
        if iat.saturating_sub(skew) > now {
            return Err(rejected("issued JWT issued-at claim is in the future"));
        }
    }

    Ok(())
}

fn decode_json<T>(input: &str, label: &str) -> Result<T, Error>
where
    T: for<'de> Deserialize<'de>,
{
    let bytes = decode_base64_url(input).map_err(|_| invalid(format!("invalid {label}")))?;
    serde_json::from_slice(&bytes).map_err(|_| invalid(format!("invalid {label} JSON")))
}

fn decode_base64_url(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| URL_SAFE.decode(input))
}

fn invalid(message: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Error {
    Error::new(StatusCode::BadIdentityTokenInvalid, message)
}

fn rejected(message: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Error {
    Error::new(StatusCode::BadIdentityTokenRejected, message)
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    use super::*;

    fn jwt(header: &str, claims: &str) -> ByteString {
        let header = URL_SAFE_NO_PAD.encode(header);
        let claims = URL_SAFE_NO_PAD.encode(claims);
        ByteString::from(format!("{header}.{claims}.signature").as_bytes())
    }

    #[test]
    fn validates_compact_jwt_claims() {
        let token = jwt(
            r#"{"alg":"RS256","kid":"key-1","typ":"JWT"}"#,
            r#"{"sub":"operator","exp":2000,"nbf":900,"iat":900,"scope":"fota:write"}"#,
        );

        let issued = validate_issued_jwt_with(
            &token,
            JwtValidation {
                now_epoch_seconds: 1000,
                ..JwtValidation::default()
            },
        )
        .expect("valid JWT should parse");

        assert_eq!(issued.header().kid.as_deref(), Some("key-1"));
        assert_eq!(issued.claims().sub.as_deref(), Some("operator"));
        assert_eq!(issued.token_hash().len(), 64);
    }

    #[test]
    fn rejects_expired_jwt() {
        let token = jwt(r#"{"alg":"RS256"}"#, r#"{"sub":"operator","exp":900}"#);

        let err = validate_issued_jwt_with(
            &token,
            JwtValidation {
                now_epoch_seconds: 1000,
                clock_skew_seconds: 0,
                ..JwtValidation::default()
            },
        )
        .expect_err("expired JWT should fail");

        assert_eq!(err.status(), StatusCode::BadIdentityTokenRejected);
    }

    #[test]
    fn rejects_unsigned_jwt() {
        let token = jwt(r#"{"alg":"none"}"#, r#"{"sub":"operator","exp":2000}"#);

        let err = validate_issued_jwt_with(
            &token,
            JwtValidation {
                now_epoch_seconds: 1000,
                ..JwtValidation::default()
            },
        )
        .expect_err("unsigned JWT should fail");

        assert_eq!(err.status(), StatusCode::BadIdentityTokenRejected);
    }
}
