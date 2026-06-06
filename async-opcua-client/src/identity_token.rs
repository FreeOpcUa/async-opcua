use std::{path::Path, sync::Arc};

use async_trait::async_trait;
use opcua_crypto::{CertificateStore, PrivateKey, X509};
use opcua_types::{ByteString, Error, StatusCode};

#[async_trait]
/// Source for an issued token. Since each re-authentication when using
/// issued tokens may require a new token.
pub trait IssuedTokenSource: Send + Sync {
    /// Get a valid issued token. This may be a cached token,
    /// or a new one if the cache is empty or expired.
    async fn get_issued_token(&self) -> Result<ByteString, Error>;
}

#[async_trait]
impl IssuedTokenSource for ByteString {
    async fn get_issued_token(&self) -> Result<ByteString, Error> {
        Ok(self.clone())
    }
}

/// Wrapper for an issued token source.
#[derive(Clone)]
pub struct IssuedTokenWrapper(pub(crate) Arc<dyn IssuedTokenSource>);

impl IssuedTokenWrapper {
    /// Create a new issued token wrapper from a reference to an issued token source.
    pub fn new(token_source: Arc<dyn IssuedTokenSource>) -> Self {
        Self(token_source)
    }

    /// Create a new issued token wrapper.
    pub fn new_source(token_source: impl IssuedTokenSource + 'static) -> Self {
        Self(Arc::new(token_source))
    }
}

impl std::fmt::Debug for IssuedTokenWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("IssuedTokenSource").finish()
    }
}

#[derive(Clone)]
/// A wrapper around a password as string. This intentionally implements
/// debug in a way that does not expose the password.
pub struct Password(pub String);

impl Password {
    /// Create a new password from a string.
    pub fn new(password: impl Into<String>) -> Self {
        Password(password.into())
    }
}

impl<T> From<T> for Password
where
    T: Into<String>,
{
    fn from(value: T) -> Self {
        Password(value.into())
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Password").field(&"*****").finish()
    }
}

#[derive(Debug, Clone)]
/// Client-side identity token representation.
pub enum IdentityToken {
    /// Anonymous identity token
    Anonymous,
    /// User name and a password
    UserName(String, Password),
    /// X5090 cert and private key.
    X509(Box<X509>, Box<PrivateKey>),
    /// Issued token
    IssuedToken(IssuedTokenWrapper),
}

impl IdentityToken {
    /// Create a new anonymous identity token.
    pub fn new_anonymous() -> Self {
        IdentityToken::Anonymous
    }
    /// Create a new user name identity token.
    pub fn new_user_name(user_name: impl Into<String>, password: impl Into<Password>) -> Self {
        IdentityToken::UserName(user_name.into(), password.into())
    }

    /// Create a new x509 identity token.
    pub fn new_x509(cert: X509, private_key: PrivateKey) -> Self {
        IdentityToken::X509(Box::new(cert), Box::new(private_key))
    }

    /// Create a new x509 identity token from a path to a certificate and private key.
    pub fn new_x509_path(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Result<Self, Error> {
        let cert = CertificateStore::read_cert(cert_path.as_ref())
            .map_err(|e| Error::new(StatusCode::Bad, e))?;
        let private_key = CertificateStore::read_pkey(key_path.as_ref())
            .map_err(|e| Error::new(StatusCode::Bad, e))?;
        Ok(IdentityToken::X509(Box::new(cert), Box::new(private_key)))
    }

    /// Create a new issued token based identity token.
    pub fn new_issued_token(token_source: impl IssuedTokenSource + 'static) -> Self {
        IdentityToken::IssuedToken(IssuedTokenWrapper::new_source(token_source))
    }

    /// Create a new issued token based identity token from a shared reference.
    pub fn new_issued_token_arc(token_source: Arc<dyn IssuedTokenSource>) -> Self {
        IdentityToken::IssuedToken(IssuedTokenWrapper::new(token_source))
    }
}
