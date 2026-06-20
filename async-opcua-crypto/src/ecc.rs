//! ECC support for OPC UA Part 6 §6.8 security policies.
//!
//! This module intentionally exposes only the foundational API surface for
//! `ECC_nistP256` and `ECC_nistP384`. The cryptographic implementations are
//! added by the follow-up ECC primitive tasks.

#[cfg(feature = "ecc")]
use opcua_types::{Error, StatusCode};

#[cfg(feature = "ecc")]
use crate::{AesDerivedKeys, PrivateKey, PublicKey, SecurityPolicy};

#[cfg(feature = "ecc")]
fn not_implemented(operation: &str) -> Error {
    Error::new(
        StatusCode::BadNotImplemented,
        format!("{operation} is not implemented for ECC security policies yet"),
    )
}

/// NIST curve selected by an OPC UA Part 6 §6.8 ECC security policy.
#[cfg(feature = "ecc")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EccCurve {
    /// NIST P-256 / secp256r1.
    P256,
    /// NIST P-384 / secp384r1.
    P384,
}

#[cfg(feature = "ecc")]
impl EccCurve {
    /// Maps an OPC UA ECC security policy to the NIST curve specified by Part 6 §6.8.
    ///
    /// # Errors
    ///
    /// Returns `BadSecurityPolicyRejected` when the policy is not an ECC NIST policy.
    pub fn from_security_policy(policy: SecurityPolicy) -> Result<Self, Error> {
        match policy {
            SecurityPolicy::EccNistP256 => Ok(Self::P256),
            SecurityPolicy::EccNistP384 => Ok(Self::P384),
            _ => Err(Error::new(
                StatusCode::BadSecurityPolicyRejected,
                format!("{policy} is not an ECC NIST security policy"),
            )),
        }
    }

    /// Encoded public key length for Part 6 §6.8 `X || Y` points.
    #[must_use]
    pub fn encoded_public_key_len(self) -> usize {
        match self {
            Self::P256 => 64,
            Self::P384 => 96,
        }
    }

    /// Raw ECDSA signature length for Part 6 §6.8 `r || s` signatures.
    #[must_use]
    pub fn raw_signature_len(self) -> usize {
        match self {
            Self::P256 => 64,
            Self::P384 => 96,
        }
    }
}

/// Ephemeral EC private key for OPC UA Part 6 §6.8 ECDH.
#[cfg(feature = "ecc")]
#[derive(Debug)]
pub struct EphemeralPrivateKey {
    curve: EccCurve,
}

#[cfg(feature = "ecc")]
impl EphemeralPrivateKey {
    /// Returns the NIST curve for this private key.
    #[must_use]
    pub fn curve(&self) -> EccCurve {
        self.curve
    }
}

/// EC public key carried as `X || Y` during the Part 6 §6.8 handshake.
#[cfg(feature = "ecc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EccPublicKey {
    curve: EccCurve,
    encoded: Vec<u8>,
}

#[cfg(feature = "ecc")]
impl EccPublicKey {
    /// Returns the NIST curve for this public key.
    #[must_use]
    pub fn curve(&self) -> EccCurve {
        self.curve
    }

    /// Returns the Part 6 §6.8 `X || Y` public key bytes.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }
}

/// Ephemeral key pair used for one OPC UA Part 6 §6.8 secure-channel open.
#[cfg(feature = "ecc")]
#[derive(Debug)]
pub struct EphemeralKeyPair {
    private_key: EphemeralPrivateKey,
    public_key: EccPublicKey,
}

#[cfg(feature = "ecc")]
impl EphemeralKeyPair {
    /// Returns the private half consumed by ECDH.
    #[must_use]
    pub fn private_key(&self) -> &EphemeralPrivateKey {
        &self.private_key
    }

    /// Returns the public half sent as `X || Y`.
    #[must_use]
    pub fn public_key(&self) -> &EccPublicKey {
        &self.public_key
    }
}

/// Client/server key sets derived from an ECC ECDH shared secret via Part 6 §6.8 HKDF.
#[cfg(feature = "ecc")]
#[derive(Debug)]
pub struct SecurityKeys {
    /// Keys used to secure messages sent by the client.
    pub client: AesDerivedKeys,
    /// Keys used to secure messages sent by the server.
    pub server: AesDerivedKeys,
}

/// Generates an ephemeral EC key pair for the Part 6 §6.8 secure-channel handshake.
///
/// # Errors
///
/// Always returns `BadNotImplemented` until the ECC primitive task implements key generation.
#[cfg(feature = "ecc")]
pub fn generate_ephemeral_keypair(_curve: EccCurve) -> Result<EphemeralKeyPair, Error> {
    Err(not_implemented("ECC ephemeral key generation"))
}

/// Encodes an EC public key as Part 6 §6.8 `X || Y` bytes.
///
/// # Errors
///
/// Always returns `BadNotImplemented` until the ECC primitive task implements public-key encoding.
#[cfg(feature = "ecc")]
pub fn encode_public_key(_public_key: &EccPublicKey) -> Result<Vec<u8>, Error> {
    Err(not_implemented("ECC public key encoding"))
}

/// Decodes an EC public key from Part 6 §6.8 `X || Y` bytes.
///
/// # Errors
///
/// Always returns `BadNotImplemented` until the ECC primitive task implements public-key decoding.
#[cfg(feature = "ecc")]
pub fn decode_public_key(_curve: EccCurve, _encoded: &[u8]) -> Result<EccPublicKey, Error> {
    Err(not_implemented("ECC public key decoding"))
}

/// Computes the Part 6 §6.8 ECDH shared secret for an ephemeral key exchange.
///
/// # Errors
///
/// Always returns `BadNotImplemented` until the ECC primitive task implements ECDH.
#[cfg(feature = "ecc")]
pub fn ecdh_shared_secret(
    _private_key: &EphemeralPrivateKey,
    _peer_public_key: &EccPublicKey,
) -> Result<Vec<u8>, Error> {
    Err(not_implemented("ECC ECDH shared secret derivation"))
}

/// Produces a raw Part 6 §6.8 ECDSA signature encoded as `r || s`.
///
/// # Errors
///
/// Always returns `BadNotImplemented` until the ECC primitive task implements ECDSA signing.
#[cfg(feature = "ecc")]
pub fn ecdsa_sign(
    _policy: SecurityPolicy,
    _signing_key: &PrivateKey,
    _data: &[u8],
) -> Result<Vec<u8>, Error> {
    Err(not_implemented("ECDSA signing"))
}

/// Verifies a raw Part 6 §6.8 ECDSA signature encoded as `r || s`.
///
/// # Errors
///
/// Always returns `BadNotImplemented` until the ECC primitive task implements ECDSA verification.
#[cfg(feature = "ecc")]
pub fn ecdsa_verify(
    _policy: SecurityPolicy,
    _verification_key: &PublicKey,
    _data: &[u8],
    _signature: &[u8],
) -> Result<(), Error> {
    Err(not_implemented("ECDSA signature verification"))
}

/// Derives Part 6 §6.8 client/server `SecurityKeys` from an ECDH shared secret with HKDF.
///
/// # Errors
///
/// Always returns `BadNotImplemented` until the ECC primitive task implements HKDF derivation.
#[cfg(feature = "ecc")]
pub fn derive_keys(
    _policy: SecurityPolicy,
    _shared_secret: &[u8],
    _client_nonce: &[u8],
    _server_nonce: &[u8],
) -> Result<SecurityKeys, Error> {
    Err(not_implemented("ECC HKDF key derivation"))
}
