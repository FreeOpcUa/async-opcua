// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

use opcua_types::{
    match_extension_object_owned, AnonymousIdentityToken, ExtensionObject, IssuedIdentityToken,
    UAString, UserNameIdentityToken, X509IdentityToken,
};

pub(crate) const POLICY_ID_ANONYMOUS: &str = "anonymous";
pub(crate) const POLICY_ID_USER_PASS_NONE: &str = "userpass_none";
pub(crate) const POLICY_ID_USER_PASS_RSA_15: &str = "userpass_rsa_15";
pub(crate) const POLICY_ID_USER_PASS_RSA_OAEP: &str = "userpass_rsa_oaep";
pub(crate) const POLICY_ID_USER_PASS_RSA_OAEP_SHA256: &str = "userpass_rsa_oaep_sha256";
pub(crate) const POLICY_ID_ISSUED_TOKEN_NONE: &str = "userpass_none";
pub(crate) const POLICY_ID_ISSUED_TOKEN_RSA_15: &str = "userpass_rsa_15";
pub(crate) const POLICY_ID_ISSUED_TOKEN_RSA_OAEP: &str = "userpass_rsa_oaep";
pub(crate) const POLICY_ID_ISSUED_TOKEN_RSA_OAEP_SHA256: &str = "userpass_rsa_oaep_sha256";
pub(crate) const POLICY_ID_X509: &str = "x509";

/// Identity token representation on the server, decoded from the client.
pub enum IdentityToken {
    /// No identity token specified at all.
    None,
    /// Identity token for anonymous access.
    Anonymous(AnonymousIdentityToken),
    /// Identity token for user name and password.
    UserName(UserNameIdentityToken),
    /// Identity token for X.509 certificate.
    X509(X509IdentityToken),
    /// Identity token for an issued identity token, i.e. OAuth.
    IssuedToken(IssuedIdentityToken),
    /// Invalid identity token with some unknown structure.
    Invalid(ExtensionObject),
}

impl IdentityToken {
    /// Decode an identity token from an extension object received from the client.
    /// Returns `Invalid` if decoding failed.
    pub fn new(o: ExtensionObject) -> Self {
        if o.is_null() {
            // Treat as anonymous
            IdentityToken::Anonymous(AnonymousIdentityToken {
                policy_id: UAString::from(POLICY_ID_ANONYMOUS),
            })
        } else {
            match_extension_object_owned!(o,
                v: AnonymousIdentityToken => Self::Anonymous(v),
                v: UserNameIdentityToken => Self::UserName(v),
                v: X509IdentityToken => Self::X509(v),
                v: IssuedIdentityToken => Self::IssuedToken(v),
                _ => Self::Invalid(o)
            )
        }
    }
}
