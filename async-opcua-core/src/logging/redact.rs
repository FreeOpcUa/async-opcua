//! Redaction helpers for log messages.

use regex::{Captures, Regex};
use std::sync::OnceLock;

const REDACTED: &str = "[REDACTED]";

const PRIVATE_KEY_BLOCK_PATTERN: &str =
    r#"(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----"#;

const SENSITIVE_FIELD_PATTERN: &str = r#"(?i)(?P<prefix>["']?\b(?:passwords?|passwds?|pwds?|passcodes?|tokens?|access[_ -]?tokens?|refresh[_ -]?tokens?|id[_ -]?tokens?|jwts?|client[_ -]?nonces?|server[_ -]?nonces?|nonces?|signatures?|secrets?|client[_ -]?secrets?|private[_ -]?keys?|api[_ -]?keys?)\b["']?\s*(?:=|:)\s*)(?:"(?P<double>[^"]*)"|'(?P<single>[^']*)'|(?P<bearer>Bearer\s+[^\s,;}\]\)]+)|(?P<already>\[REDACTED\])|(?P<bare>[^\s,;&}\]\)]+))"#;

const BEARER_TOKEN_PATTERN: &str = r#"(?i)(?P<prefix>\bBearer\s+)(?P<token>(?:[A-Za-z0-9._~+/=-]+\.){2}[A-Za-z0-9._~+/=-]+|[A-Za-z0-9._~+/=-]{20,})"#;

/// Redacts sensitive fields from a log message.
pub fn redact_log_message(msg: &str) -> String {
    let private_keys_redacted = match private_key_block_regex() {
        Some(re) => re.replace_all(msg, REDACTED).into_owned(),
        None => msg.to_string(),
    };

    let redacted = match sensitive_field_regex() {
        Some(re) => re
            .replace_all(&private_keys_redacted, |captures: &Captures<'_>| {
                let prefix = captures
                    .name("prefix")
                    .map(|matched| matched.as_str())
                    .unwrap_or_default();

                if captures.name("double").is_some() {
                    format!(r#"{prefix}"{REDACTED}""#)
                } else if captures.name("single").is_some() {
                    format!("{prefix}'{REDACTED}'")
                } else {
                    format!("{prefix}{REDACTED}")
                }
            })
            .into_owned(),
        None => msg.to_string(),
    };

    match bearer_token_regex() {
        Some(re) => re
            .replace_all(&redacted, |captures: &Captures<'_>| {
                let prefix = captures
                    .name("prefix")
                    .map(|matched| matched.as_str())
                    .unwrap_or_default();
                format!("{prefix}{REDACTED}")
            })
            .into_owned(),
        None => redacted,
    }
}

fn private_key_block_regex() -> Option<&'static Regex> {
    // Feature 049: intentionally process-global - immutable init-once regex cache (applies to all RE statics here).
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(PRIVATE_KEY_BLOCK_PATTERN).ok())
        .as_ref()
}

fn sensitive_field_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(SENSITIVE_FIELD_PATTERN).ok())
        .as_ref()
}

fn bearer_token_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(BEARER_TOKEN_PATTERN).ok())
        .as_ref()
}

#[cfg(test)]
mod tests {
    use super::redact_log_message;

    #[test]
    fn redacts_common_password_and_token_formats() {
        let msg = r#"user=alice password=secret token: "header.payload.signature" status=ok"#;

        assert_eq!(
            redact_log_message(msg),
            r#"user=alice password=[REDACTED] token: "[REDACTED]" status=ok"#
        );
    }

    #[test]
    fn redacts_sensitive_keys_case_insensitively() {
        let msg = r#"PASSWORD='hunter2' ClientNonce=abcdef Signature: deadbeef"#;

        assert_eq!(
            redact_log_message(msg),
            r#"PASSWORD='[REDACTED]' ClientNonce=[REDACTED] Signature: [REDACTED]"#
        );
    }

    #[test]
    fn redacts_json_style_secret_and_private_key_fields() {
        let msg = r#"{"clientSecret":"s3cr3t","private_key":"-----BEGIN PRIVATE KEY-----","endpoint":"opc.tcp://localhost:4840"}"#;

        assert_eq!(
            redact_log_message(msg),
            r#"{"clientSecret":"[REDACTED]","private_key":"[REDACTED]","endpoint":"opc.tcp://localhost:4840"}"#
        );
    }

    #[test]
    fn redacts_unquoted_pem_private_key_values() {
        let msg =
            "private_key=-----BEGIN PRIVATE KEY-----abc123-----END PRIVATE KEY----- endpoint=opc.tcp://localhost:4840";

        assert_eq!(
            redact_log_message(msg),
            "private_key=[REDACTED] endpoint=opc.tcp://localhost:4840"
        );
    }

    #[test]
    fn redacts_bearer_jwt_without_touching_other_fields() {
        let msg =
            "authorization=Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature node=ns=2;i=42";

        assert_eq!(
            redact_log_message(msg),
            "authorization=Bearer [REDACTED] node=ns=2;i=42"
        );
    }

    #[test]
    fn leaves_non_sensitive_fields_untouched() {
        let msg = "username=alice endpoint=opc.tcp://localhost:4840 tokenization=enabled status=ok";

        assert_eq!(redact_log_message(msg), msg);
    }
}
