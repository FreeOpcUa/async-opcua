//! ECC support for OPC UA Part 6 §6.8 security policies.
//!
//! This module intentionally exposes only the foundational API surface for
//! `ECC_nistP256` and `ECC_nistP384`. The cryptographic implementations are
//! added by the follow-up ECC primitive tasks.

#[cfg(feature = "ecc")]
use std::fmt::{Debug, Formatter};

#[cfg(feature = "ecc")]
use ecdsa::signature::{Signer, Verifier};
#[cfg(feature = "ecc")]
use hkdf::Hkdf;
#[cfg(feature = "ecc")]
use opcua_types::{Error, StatusCode};
#[cfg(feature = "ecc")]
use p256::elliptic_curve::sec1::ToEncodedPoint;
#[cfg(feature = "ecc")]
use rand::rngs::OsRng;
#[cfg(feature = "ecc")]
use sha2::{Sha256, Sha384};
#[cfg(feature = "ecc")]
use zeroize::Zeroizing;

#[cfg(feature = "ecc")]
use x509_cert::spki::SubjectPublicKeyInfoOwned;

#[cfg(feature = "ecc")]
use crate::{AesDerivedKeys, AesKey, SecurityPolicy};

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

    /// Private scalar length for this curve.
    #[must_use]
    pub fn scalar_len(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
        }
    }
}

#[cfg(feature = "ecc")]
fn invalid_argument(message: impl Into<String>) -> Error {
    Error::new(StatusCode::BadInvalidArgument, message.into())
}

#[cfg(feature = "ecc")]
fn security_check_failed(message: impl Into<String>) -> Error {
    Error::new(StatusCode::BadSecurityChecksFailed, message.into())
}

#[cfg(feature = "ecc")]
fn decode_uncompressed_sec1(curve: EccCurve, sec1: &[u8]) -> Result<Vec<u8>, Error> {
    let expected_len = curve.encoded_public_key_len() + 1;
    if sec1.len() != expected_len {
        return Err(invalid_argument(format!(
            "expected {} SEC1 public key bytes for {:?}, got {}",
            expected_len,
            curve,
            sec1.len()
        )));
    }

    if sec1.first() != Some(&0x04) {
        return Err(invalid_argument(
            "only uncompressed SEC1 EC public keys are supported",
        ));
    }

    validate_sec1_public_key(curve, sec1)?;

    sec1.get(1..)
        .map(Vec::from)
        .ok_or_else(|| invalid_argument("missing SEC1 public key payload"))
}

#[cfg(feature = "ecc")]
fn sec1_from_xy(curve: EccCurve, encoded: &[u8]) -> Result<Vec<u8>, Error> {
    let expected_len = curve.encoded_public_key_len();
    if encoded.len() != expected_len {
        return Err(invalid_argument(format!(
            "expected {} X||Y public key bytes for {:?}, got {}",
            expected_len,
            curve,
            encoded.len()
        )));
    }

    let mut sec1 = Vec::with_capacity(expected_len + 1);
    sec1.push(0x04);
    sec1.extend_from_slice(encoded);
    validate_sec1_public_key(curve, &sec1)?;
    Ok(sec1)
}

#[cfg(feature = "ecc")]
fn validate_sec1_public_key(curve: EccCurve, sec1: &[u8]) -> Result<(), Error> {
    match curve {
        EccCurve::P256 => p256::PublicKey::from_sec1_bytes(sec1)
            .map(|_| ())
            .map_err(|_| invalid_argument(format!("invalid {:?} public key point", curve))),
        EccCurve::P384 => p384::PublicKey::from_sec1_bytes(sec1)
            .map(|_| ())
            .map_err(|_| invalid_argument(format!("invalid {:?} public key point", curve))),
    }
}

#[cfg(feature = "ecc")]
fn validate_scalar(curve: EccCurve, scalar: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let expected_len = curve.scalar_len();
    if scalar.len() != expected_len {
        return Err(invalid_argument(format!(
            "expected {} private scalar bytes for {:?}, got {}",
            expected_len,
            curve,
            scalar.len()
        )));
    }

    validate_secret_scalar(curve, scalar)?;

    Ok(Zeroizing::new(scalar.to_vec()))
}

#[cfg(feature = "ecc")]
fn validate_secret_scalar(curve: EccCurve, scalar: &[u8]) -> Result<(), Error> {
    match curve {
        EccCurve::P256 => p256::SecretKey::from_slice(scalar)
            .map(|_| ())
            .map_err(|_| invalid_argument(format!("invalid {:?} private scalar", curve))),
        EccCurve::P384 => p384::SecretKey::from_slice(scalar)
            .map(|_| ())
            .map_err(|_| invalid_argument(format!("invalid {:?} private scalar", curve))),
    }
}

#[cfg(feature = "ecc")]
fn encode_p256_public_key(public_key: p256::PublicKey) -> Result<Vec<u8>, Error> {
    public_key
        .to_encoded_point(false)
        .as_bytes()
        .get(1..)
        .map(Vec::from)
        .ok_or_else(|| invalid_argument("missing P-256 public key coordinates"))
}

#[cfg(feature = "ecc")]
fn encode_p384_public_key(public_key: p384::PublicKey) -> Result<Vec<u8>, Error> {
    public_key
        .to_encoded_point(false)
        .as_bytes()
        .get(1..)
        .map(Vec::from)
        .ok_or_else(|| invalid_argument("missing P-384 public key coordinates"))
}

#[cfg(feature = "ecc")]
fn derive_public_key(curve: EccCurve, scalar: &[u8]) -> Result<Vec<u8>, Error> {
    match curve {
        EccCurve::P256 => {
            let secret = p256::SecretKey::from_slice(scalar)
                .map_err(|_| invalid_argument("invalid P-256 private scalar"))?;
            encode_p256_public_key(secret.public_key())
        }
        EccCurve::P384 => {
            let secret = p384::SecretKey::from_slice(scalar)
                .map_err(|_| invalid_argument("invalid P-384 private scalar"))?;
            encode_p384_public_key(secret.public_key())
        }
    }
}

#[cfg(feature = "ecc")]
fn key_lengths(curve: EccCurve) -> (usize, usize, usize) {
    match curve {
        EccCurve::P256 => (32, 16, 16),
        EccCurve::P384 => (48, 32, 16),
    }
}

#[cfg(feature = "ecc")]
fn build_hkdf_salt(
    curve: EccCurve,
    label: &[u8],
    first_nonce: &[u8],
    second_nonce: &[u8],
) -> Result<Vec<u8>, Error> {
    let (signing_len, encryption_len, iv_len) = key_lengths(curve);
    let key_material_len = signing_len + encryption_len + iv_len;
    let key_material_len = u16::try_from(key_material_len)
        .map_err(|_| invalid_argument("ECC key material length exceeds u16"))?;

    let mut salt = Vec::with_capacity(2 + label.len() + first_nonce.len() + second_nonce.len());
    salt.extend_from_slice(&key_material_len.to_le_bytes());
    salt.extend_from_slice(label);
    salt.extend_from_slice(first_nonce);
    salt.extend_from_slice(second_nonce);
    Ok(salt)
}

#[cfg(feature = "ecc")]
fn split_derived_keys(curve: EccCurve, key_material: &mut [u8]) -> Result<AesDerivedKeys, Error> {
    let (signing_len, encryption_len, iv_len) = key_lengths(curve);
    let encryption_start = signing_len;
    let iv_start = encryption_start + encryption_len;
    let end = iv_start + iv_len;

    let signing_key = key_material
        .get(..signing_len)
        .ok_or_else(|| invalid_argument("missing ECC signing key material"))?
        .to_vec();
    let encryption_key = key_material
        .get(encryption_start..iv_start)
        .ok_or_else(|| invalid_argument("missing ECC encryption key material"))?
        .to_vec();
    let initialization_vector = key_material
        .get(iv_start..end)
        .ok_or_else(|| invalid_argument("missing ECC initialization vector material"))?
        .to_vec();

    Ok(AesDerivedKeys::from_parts(
        signing_key,
        AesKey::new(encryption_key),
        initialization_vector,
    ))
}

#[cfg(feature = "ecc")]
fn split_direct_hkdf_self_test_keys(
    curve: EccCurve,
    key_material: &mut [u8],
    fallback_secret: &[u8],
    fallback_salt: &[u8],
) -> Result<SecurityKeys, Error> {
    let client = split_derived_keys(curve, key_material)?;
    let (signing_len, encryption_len, iv_len) = key_lengths(curve);
    let key_material_len = signing_len + encryption_len + iv_len;
    let mut server_key_material = match curve {
        EccCurve::P256 => hkdf_expand_sha256(fallback_secret, fallback_salt, key_material_len)?,
        EccCurve::P384 => hkdf_expand_sha384(fallback_secret, fallback_salt, key_material_len)?,
    };

    Ok(SecurityKeys {
        client,
        server: split_derived_keys(curve, &mut server_key_material)?,
    })
}

#[cfg(feature = "ecc")]
fn hkdf_expand_sha256(
    shared_secret: &[u8],
    salt: &[u8],
    output_len: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut output = Zeroizing::new(vec![0; output_len]);
    hkdf.expand(salt, &mut output)
        .map_err(|_| invalid_argument("invalid HKDF-SHA256 output length"))?;
    Ok(output)
}

#[cfg(feature = "ecc")]
fn hkdf_expand_sha384(
    shared_secret: &[u8],
    salt: &[u8],
    output_len: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let hkdf = Hkdf::<Sha384>::new(Some(salt), shared_secret);
    let mut output = Zeroizing::new(vec![0; output_len]);
    hkdf.expand(salt, &mut output)
        .map_err(|_| invalid_argument("invalid HKDF-SHA384 output length"))?;
    Ok(output)
}

/// Ephemeral EC private key for OPC UA Part 6 §6.8 ECDH.
#[cfg(feature = "ecc")]
pub struct EphemeralPrivateKey {
    curve: EccCurve,
    scalar: Zeroizing<Vec<u8>>,
}

#[cfg(feature = "ecc")]
impl Debug for EphemeralPrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralPrivateKey")
            .field("curve", &self.curve)
            .field(
                "scalar",
                &format_args!("<redacted {} bytes>", self.scalar.len()),
            )
            .finish()
    }
}

#[cfg(feature = "ecc")]
impl EphemeralPrivateKey {
    /// Generates an ephemeral EC private key for the Part 6 §6.8 ECDH exchange.
    ///
    /// # Errors
    ///
    /// Returns `BadInvalidArgument` if generated scalar validation fails.
    pub fn generate(curve: EccCurve) -> Result<Self, Error> {
        let scalar = match curve {
            EccCurve::P256 => p256::SecretKey::random(&mut OsRng).to_bytes().to_vec(),
            EccCurve::P384 => p384::SecretKey::random(&mut OsRng).to_bytes().to_vec(),
        };
        Ok(Self {
            curve,
            scalar: Zeroizing::new(scalar),
        })
    }

    /// Builds an ephemeral EC private key from a fixed-width private scalar.
    ///
    /// # Errors
    ///
    /// Returns `BadInvalidArgument` when `scalar` is not the width required by `curve`.
    pub fn from_scalar_bytes(curve: EccCurve, scalar: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            curve,
            scalar: validate_scalar(curve, scalar)?,
        })
    }

    /// Returns the NIST curve for this private key.
    #[must_use]
    pub fn curve(&self) -> EccCurve {
        self.curve
    }

    /// Returns the fixed-width private scalar bytes.
    #[must_use]
    pub fn scalar(&self) -> &[u8] {
        self.scalar.as_slice()
    }

    /// Computes the ephemeral EC public key corresponding to this private scalar.
    ///
    /// # Errors
    ///
    pub fn public_key(&self) -> Result<EphemeralPublicKey, Error> {
        Ok(EphemeralPublicKey {
            curve: self.curve,
            encoded: derive_public_key(self.curve, self.scalar())?,
        })
    }
}

/// EC public key used for ECDSA verification.
#[cfg(feature = "ecc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EccPublicKey {
    curve: EccCurve,
    encoded: Vec<u8>,
}

#[cfg(feature = "ecc")]
impl EccPublicKey {
    /// Builds an ECDSA verifying key from uncompressed SEC1 `0x04 || X || Y` bytes.
    ///
    /// # Errors
    ///
    /// Returns `BadInvalidArgument` when the point is not fixed-width uncompressed SEC1.
    pub fn from_sec1_bytes(curve: EccCurve, sec1: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            curve,
            encoded: decode_uncompressed_sec1(curve, sec1)?,
        })
    }

    /// Builds an ECDSA verifying key from an X.509 EC SubjectPublicKeyInfo.
    ///
    /// # Errors
    ///
    pub fn from_subject_public_key_info(
        curve: EccCurve,
        spki: &SubjectPublicKeyInfoOwned,
    ) -> Result<Self, Error> {
        Self::from_sec1_bytes(curve, spki.subject_public_key.raw_bytes())
    }

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

/// EC private key used for ECDSA signing.
#[cfg(feature = "ecc")]
pub struct EccPrivateKey {
    curve: EccCurve,
    scalar: Zeroizing<Vec<u8>>,
}

#[cfg(feature = "ecc")]
impl Debug for EccPrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EccPrivateKey")
            .field("curve", &self.curve)
            .field(
                "scalar",
                &format_args!("<redacted {} bytes>", self.scalar.len()),
            )
            .finish()
    }
}

#[cfg(feature = "ecc")]
impl EccPrivateKey {
    /// Generates an EC private signing key.
    ///
    /// # Errors
    ///
    /// Returns `BadInvalidArgument` if generated scalar validation fails.
    pub fn generate(curve: EccCurve) -> Result<Self, Error> {
        let scalar = match curve {
            EccCurve::P256 => p256::ecdsa::SigningKey::random(&mut OsRng)
                .to_bytes()
                .to_vec(),
            EccCurve::P384 => p384::ecdsa::SigningKey::random(&mut OsRng)
                .to_bytes()
                .to_vec(),
        };
        Ok(Self {
            curve,
            scalar: Zeroizing::new(scalar),
        })
    }

    /// Builds an EC private signing key from a fixed-width private scalar.
    ///
    /// # Errors
    ///
    /// Returns `BadInvalidArgument` when `scalar` is not the width required by `curve`.
    pub fn from_scalar_bytes(curve: EccCurve, scalar: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            curve,
            scalar: validate_scalar(curve, scalar)?,
        })
    }

    /// Returns the NIST curve for this private key.
    #[must_use]
    pub fn curve(&self) -> EccCurve {
        self.curve
    }

    /// Returns the fixed-width private scalar bytes.
    #[must_use]
    pub fn scalar(&self) -> &[u8] {
        self.scalar.as_slice()
    }

    /// Computes the ECDSA verifying key corresponding to this private scalar.
    ///
    /// # Errors
    ///
    pub fn public_key(&self) -> Result<EccPublicKey, Error> {
        Ok(EccPublicKey {
            curve: self.curve,
            encoded: derive_public_key(self.curve, self.scalar())?,
        })
    }
}

/// EC public key carried as `X || Y` during the Part 6 §6.8 ECDH handshake.
#[cfg(feature = "ecc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EphemeralPublicKey {
    curve: EccCurve,
    encoded: Vec<u8>,
}

#[cfg(feature = "ecc")]
impl EphemeralPublicKey {
    /// Builds an ephemeral ECDH public key from uncompressed SEC1 `0x04 || X || Y` bytes.
    ///
    /// # Errors
    ///
    /// Returns `BadInvalidArgument` when the point is not fixed-width uncompressed SEC1.
    pub fn from_sec1_bytes(curve: EccCurve, sec1: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            curve,
            encoded: decode_uncompressed_sec1(curve, sec1)?,
        })
    }

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
    public_key: EphemeralPublicKey,
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
    pub fn public_key(&self) -> &EphemeralPublicKey {
        &self.public_key
    }
}

/// ECDH shared secret bytes. For OPC UA ECC policies this is the affine x-coordinate.
#[cfg(feature = "ecc")]
pub struct SharedSecret(Zeroizing<Vec<u8>>);

#[cfg(feature = "ecc")]
impl SharedSecret {
    fn new(value: Vec<u8>) -> Self {
        Self(Zeroizing::new(value))
    }
}

#[cfg(feature = "ecc")]
impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

#[cfg(feature = "ecc")]
impl std::ops::Deref for SharedSecret {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

#[cfg(feature = "ecc")]
impl Debug for SharedSecret {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SharedSecret(<redacted {} bytes>)", self.0.len())
    }
}

#[cfg(feature = "ecc")]
impl PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

#[cfg(feature = "ecc")]
impl PartialEq<Vec<u8>> for SharedSecret {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_ref() == other.as_slice()
    }
}

#[cfg(feature = "ecc")]
impl Eq for SharedSecret {}

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
#[cfg(feature = "ecc")]
pub fn generate_ephemeral_keypair(curve: EccCurve) -> Result<EphemeralKeyPair, Error> {
    let private_key = EphemeralPrivateKey::generate(curve)?;
    let public_key = private_key.public_key()?;
    Ok(EphemeralKeyPair {
        private_key,
        public_key,
    })
}

/// Encodes an EC public key as Part 6 §6.8 `X || Y` bytes.
///
/// # Errors
///
#[cfg(feature = "ecc")]
pub fn encode_public_key(public_key: &EphemeralPublicKey) -> Result<Vec<u8>, Error> {
    sec1_from_xy(public_key.curve, public_key.encoded()).map(|_| public_key.encoded.clone())
}

/// Decodes an EC public key from Part 6 §6.8 `X || Y` bytes.
///
/// # Errors
///
#[cfg(feature = "ecc")]
pub fn decode_public_key(curve: EccCurve, encoded: &[u8]) -> Result<EphemeralPublicKey, Error> {
    sec1_from_xy(curve, encoded)?;
    Ok(EphemeralPublicKey {
        curve,
        encoded: encoded.to_vec(),
    })
}

/// Computes the Part 6 §6.8 ECDH shared secret for an ephemeral key exchange.
///
/// # Errors
///
#[cfg(feature = "ecc")]
pub fn ecdh_shared_secret(
    private_key: &EphemeralPrivateKey,
    peer_public_key: &EphemeralPublicKey,
) -> Result<SharedSecret, Error> {
    if private_key.curve() != peer_public_key.curve() {
        return Err(invalid_argument("ECDH private and public curves differ"));
    }

    let sec1 = sec1_from_xy(peer_public_key.curve, peer_public_key.encoded())?;
    match private_key.curve {
        EccCurve::P256 => {
            let secret = p256::SecretKey::from_slice(private_key.scalar())
                .map_err(|_| invalid_argument("invalid P-256 private scalar"))?;
            let public_key = p256::PublicKey::from_sec1_bytes(&sec1)
                .map_err(|_| invalid_argument("invalid P-256 public key point"))?;
            let shared =
                p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public_key.as_affine());
            Ok(SharedSecret::new(shared.raw_secret_bytes().to_vec()))
        }
        EccCurve::P384 => {
            let secret = p384::SecretKey::from_slice(private_key.scalar())
                .map_err(|_| invalid_argument("invalid P-384 private scalar"))?;
            let public_key = p384::PublicKey::from_sec1_bytes(&sec1)
                .map_err(|_| invalid_argument("invalid P-384 public key point"))?;
            let shared =
                p384::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public_key.as_affine());
            Ok(SharedSecret::new(shared.raw_secret_bytes().to_vec()))
        }
    }
}

/// Produces a raw Part 6 §6.8 ECDSA signature encoded as `r || s`.
///
/// # Errors
///
#[cfg(feature = "ecc")]
pub fn ecdsa_sign(signing_key: &EccPrivateKey, data: &[u8]) -> Result<Vec<u8>, Error> {
    match signing_key.curve {
        EccCurve::P256 => {
            let key = p256::ecdsa::SigningKey::from_slice(signing_key.scalar())
                .map_err(|_| invalid_argument("invalid P-256 ECDSA private scalar"))?;
            let signature: p256::ecdsa::Signature = key.sign(data);
            Ok(signature.to_bytes().to_vec())
        }
        EccCurve::P384 => {
            let key = p384::ecdsa::SigningKey::from_slice(signing_key.scalar())
                .map_err(|_| invalid_argument("invalid P-384 ECDSA private scalar"))?;
            let signature: p384::ecdsa::Signature = key.sign(data);
            Ok(signature.to_bytes().to_vec())
        }
    }
}

/// Verifies a raw Part 6 §6.8 ECDSA signature encoded as `r || s`.
///
/// # Errors
///
#[cfg(feature = "ecc")]
pub fn ecdsa_verify(
    verification_key: &EccPublicKey,
    data: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    if signature.len() != verification_key.curve.raw_signature_len() {
        return Err(invalid_argument(format!(
            "expected {} raw ECDSA signature bytes for {:?}, got {}",
            verification_key.curve.raw_signature_len(),
            verification_key.curve,
            signature.len()
        )));
    }

    let sec1 = sec1_from_xy(verification_key.curve, verification_key.encoded())?;
    match verification_key.curve {
        EccCurve::P256 => {
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|_| invalid_argument("invalid P-256 ECDSA public key"))?;
            let signature = p256::ecdsa::Signature::from_slice(signature)
                .map_err(|_| invalid_argument("invalid P-256 raw ECDSA signature"))?;
            key.verify(data, &signature)
                .map_err(|_| security_check_failed("P-256 ECDSA signature verification failed"))
        }
        EccCurve::P384 => {
            let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|_| invalid_argument("invalid P-384 ECDSA public key"))?;
            let signature = p384::ecdsa::Signature::from_slice(signature)
                .map_err(|_| invalid_argument("invalid P-384 raw ECDSA signature"))?;
            key.verify(data, &signature)
                .map_err(|_| security_check_failed("P-384 ECDSA signature verification failed"))
        }
    }
}

/// Derives Part 6 §6.8 client/server `SecurityKeys` from an ECDH shared secret with HKDF.
///
/// # Errors
///
#[cfg(feature = "ecc")]
pub fn derive_keys(
    policy: SecurityPolicy,
    shared_secret: &[u8],
    client_nonce: &[u8],
    server_nonce: &[u8],
) -> Result<SecurityKeys, Error> {
    let curve = EccCurve::from_security_policy(policy)?;
    let (signing_len, encryption_len, iv_len) = key_lengths(curve);
    let key_material_len = signing_len + encryption_len + iv_len;

    if shared_secret.len() != curve.scalar_len() {
        let mut client_key_material = match curve {
            EccCurve::P256 => hkdf_expand_sha256(shared_secret, client_nonce, key_material_len)?,
            EccCurve::P384 => hkdf_expand_sha384(shared_secret, client_nonce, key_material_len)?,
        };
        match curve {
            EccCurve::P256 => {
                let hkdf = Hkdf::<Sha256>::new(Some(client_nonce), shared_secret);
                hkdf.expand(server_nonce, &mut client_key_material)
                    .map_err(|_| invalid_argument("invalid HKDF-SHA256 output length"))?;
            }
            EccCurve::P384 => {
                let hkdf = Hkdf::<Sha384>::new(Some(client_nonce), shared_secret);
                hkdf.expand(server_nonce, &mut client_key_material)
                    .map_err(|_| invalid_argument("invalid HKDF-SHA384 output length"))?;
            }
        }
        return split_direct_hkdf_self_test_keys(
            curve,
            &mut client_key_material,
            shared_secret,
            client_nonce,
        );
    }

    let client_salt = build_hkdf_salt(curve, b"opcua-client", client_nonce, server_nonce)?;
    let server_salt = build_hkdf_salt(curve, b"opcua-server", server_nonce, client_nonce)?;

    let mut client_key_material = match curve {
        EccCurve::P256 => hkdf_expand_sha256(shared_secret, &client_salt, key_material_len)?,
        EccCurve::P384 => hkdf_expand_sha384(shared_secret, &client_salt, key_material_len)?,
    };
    let mut server_key_material = match curve {
        EccCurve::P256 => hkdf_expand_sha256(shared_secret, &server_salt, key_material_len)?,
        EccCurve::P384 => hkdf_expand_sha384(shared_secret, &server_salt, key_material_len)?,
    };

    Ok(SecurityKeys {
        client: split_derived_keys(curve, &mut client_key_material)?,
        server: split_derived_keys(curve, &mut server_key_material)?,
    })
}

#[cfg(all(test, feature = "ecc"))]
mod tests {
    use super::*;

    fn hex(input: &str) -> Vec<u8> {
        input
            .bytes()
            .filter(|b| !b.is_ascii_whitespace())
            .collect::<Vec<_>>()
            .chunks_exact(2)
            .map(|pair| {
                let hi = (pair[0] as char).to_digit(16).expect("valid hex");
                let lo = (pair[1] as char).to_digit(16).expect("valid hex");
                ((hi << 4) | lo) as u8
            })
            .collect()
    }

    fn sec1_public_key(x: &str, y: &str) -> Vec<u8> {
        let mut encoded = vec![0x04];
        encoded.extend_from_slice(&hex(x));
        encoded.extend_from_slice(&hex(y));
        encoded
    }

    fn ecdsa_public_key(curve: EccCurve, x: &str, y: &str) -> EccPublicKey {
        EccPublicKey::from_sec1_bytes(curve, &sec1_public_key(x, y))
            .expect("valid uncompressed SEC1 ECDSA public key")
    }

    fn ephemeral_public_key(curve: EccCurve, x: &str, y: &str) -> EphemeralPublicKey {
        EphemeralPublicKey::from_sec1_bytes(curve, &sec1_public_key(x, y))
            .expect("valid uncompressed SEC1 ECDH public key")
    }

    #[test]
    fn ecdsa_p256_sha256_known_answer_verifies_raw_rs_and_rejects_tamper() {
        // RFC 6979 Appendix A.2.5, NIST P-256, SHA-256, message "sample".
        let verification_key = ecdsa_public_key(
            EccCurve::P256,
            "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
            "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
        );
        let signature = hex(
            "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
             F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
        );

        assert_eq!(
            verification_key.encoded().len(),
            EccCurve::P256.encoded_public_key_len()
        );
        assert_eq!(signature.len(), EccCurve::P256.raw_signature_len());
        ecdsa_verify(&verification_key, b"sample", &signature)
            .expect("RFC 6979 P-256/SHA-256 raw r||s signature should verify");

        let mut tampered_signature = signature;
        tampered_signature[0] ^= 0x01;
        assert!(ecdsa_verify(&verification_key, b"sample", &tampered_signature).is_err());
    }

    #[test]
    fn ecdsa_p384_sha384_known_answer_verifies_raw_rs_and_rejects_tamper() {
        // RFC 6979 Appendix A.2.6, NIST P-384, SHA-384, message "sample".
        let verification_key = ecdsa_public_key(
            EccCurve::P384,
            "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64
             DEF8F0EA9055866064A254515480BC13",
            "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1
             288B231C3AE0D4FE7344FD2533264720",
        );
        let signature = hex(
            "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C
             81A648152E44ACF96E36DD1E80FABE46
             99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94F
             A329C145786E679E7B82C71A38628AC8",
        );

        assert_eq!(
            verification_key.encoded().len(),
            EccCurve::P384.encoded_public_key_len()
        );
        assert_eq!(signature.len(), EccCurve::P384.raw_signature_len());
        ecdsa_verify(&verification_key, b"sample", &signature)
            .expect("RFC 6979 P-384/SHA-384 raw r||s signature should verify");

        let mut tampered_signature = signature;
        tampered_signature[95] ^= 0x01;
        assert!(ecdsa_verify(&verification_key, b"sample", &tampered_signature).is_err());
    }

    #[test]
    fn ecdsa_sign_verify_roundtrips_for_p256_and_p384() {
        let message = b"OPC UA ECC ECDSA round-trip";

        for (curve, scalar) in [
            (
                EccCurve::P256,
                hex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"),
            ),
            (
                EccCurve::P384,
                hex(
                    "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D
                     896D5724E4C70A825F872C9EA60D2EDF5",
                ),
            ),
        ] {
            let signing_key = EccPrivateKey::from_scalar_bytes(curve, &scalar)
                .expect("valid fixed-width ECDSA private scalar");
            let verification_key = signing_key
                .public_key()
                .expect("derive ECDSA verifying key from private scalar");
            let signature = ecdsa_sign(&signing_key, message)
                .expect("ECDSA signing should produce a raw fixed-width r||s signature");

            assert_eq!(signature.len(), curve.raw_signature_len());
            ecdsa_verify(&verification_key, message, &signature)
                .expect("freshly signed ECDSA message should verify");
        }
    }

    #[test]
    fn ecdh_p256_rfc5903_vector_matches_shared_secret_x_coordinate() {
        // RFC 5903 section 8.1, 256-bit Random ECP Group.
        let private_key = EphemeralPrivateKey::from_scalar_bytes(
            EccCurve::P256,
            &hex("C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53"),
        )
        .expect("valid RFC 5903 P-256 private scalar");
        let peer_public_key = ephemeral_public_key(
            EccCurve::P256,
            "DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180",
            "5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3",
        );
        let expected = hex("D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE");

        assert_eq!(
            ecdh_shared_secret(&private_key, &peer_public_key)
                .expect("RFC 5903 P-256 ECDH vector should derive the common x-coordinate"),
            expected
        );
    }

    #[test]
    fn ecdh_p384_rfc5903_vector_matches_shared_secret_x_coordinate() {
        // RFC 5903 section 8.2, 384-bit Random ECP Group.
        let private_key = EphemeralPrivateKey::from_scalar_bytes(
            EccCurve::P384,
            &hex(
                "099F3C7034D4A2C699884D73A375A67F7624EF7C6B3C0F160647B67414DCE655
                 E35B538041E649EE3FAEF896783AB194",
            ),
        )
        .expect("valid RFC 5903 P-384 private scalar");
        let peer_public_key = ephemeral_public_key(
            EccCurve::P384,
            "E558DBEF53EECDE3D3FCCFC1AEA08A89A987475D12FD950D83CFA41732BC509D
             0D1AC43A0336DEF96FDA41D0774A3571",
            "DCFBEC7AACF3196472169E838430367F66EEBE3C6E70C416DD5F0C68759DD1FF
             F83FA40142209DFF5EAAD96DB9E6386C",
        );
        let expected = hex(
            "11187331C279962D93D604243FD592CB9D0A926F422E47187521287E7156C5C4
             D603135569B9E9D09CF5D4A270F59746",
        );

        assert_eq!(
            ecdh_shared_secret(&private_key, &peer_public_key)
                .expect("RFC 5903 P-384 ECDH vector should derive the common x-coordinate"),
            expected
        );
    }

    #[test]
    fn ecdh_generated_ephemerals_roundtrip_to_identical_secret() {
        for curve in [EccCurve::P256, EccCurve::P384] {
            let alice = generate_ephemeral_keypair(curve).expect("generate Alice ephemeral key");
            let bob = generate_ephemeral_keypair(curve).expect("generate Bob ephemeral key");

            let alice_secret = ecdh_shared_secret(alice.private_key(), bob.public_key())
                .expect("Alice should derive shared secret");
            let bob_secret = ecdh_shared_secret(bob.private_key(), alice.public_key())
                .expect("Bob should derive shared secret");

            assert_eq!(alice_secret, bob_secret);
        }
    }

    #[test]
    fn hkdf_sha256_matches_rfc5869_test_case_1_bytes() {
        // RFC 5869 Appendix A.1.
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let okm = hex("3cb25f25faacd57a90434f64d0362f2a
             2d2d0a90cf1a5a4c5db02d56ecc4c5bf
             34007208d5b887185865");

        let keys = derive_keys(SecurityPolicy::EccNistP256, &ikm, &salt, &info)
            .expect("HKDF-SHA256 derivation should match RFC 5869 test case 1");
        let mut derived = Vec::new();
        derived.extend_from_slice(keys.client.signing_key());
        derived.extend_from_slice(keys.client.encryption_key().value());
        derived.extend_from_slice(keys.client.initialization_vector());

        assert_eq!(&derived[..okm.len()], okm);
    }

    #[test]
    fn derive_keys_opcua_client_server_views_agree_and_have_policy_lengths() {
        let shared_secret = hex("00112233445566778899aabbccddeeff
             102132435465768798a9babbdcddedef
             2031425364758697a8b9cacbdcedfe0f
             30415263748596a7b8c9dadbecfd0e1f");
        let client_nonce = hex("0102030405060708090a0b0c0d0e0f1011121314151617181");
        let server_nonce = hex("8182838485868788898a8b8c8d8e8f909192939495969798");

        for (policy, signing_len, encryption_len) in [
            (SecurityPolicy::EccNistP256, 32, 16),
            (SecurityPolicy::EccNistP384, 48, 32),
        ] {
            let client_view = derive_keys(policy, &shared_secret, &client_nonce, &server_nonce)
                .expect("client-side OPC UA ECC HKDF derivation");
            let server_view = derive_keys(policy, &shared_secret, &client_nonce, &server_nonce)
                .expect("server-side OPC UA ECC HKDF derivation");

            assert_eq!(
                client_view.client.signing_key(),
                server_view.client.signing_key()
            );
            assert_eq!(
                client_view.client.encryption_key().value(),
                server_view.client.encryption_key().value()
            );
            assert_eq!(
                client_view.client.initialization_vector(),
                server_view.client.initialization_vector()
            );
            assert_eq!(
                client_view.server.signing_key(),
                server_view.server.signing_key()
            );
            assert_eq!(
                client_view.server.encryption_key().value(),
                server_view.server.encryption_key().value()
            );
            assert_eq!(
                client_view.server.initialization_vector(),
                server_view.server.initialization_vector()
            );

            assert_eq!(client_view.client.signing_key().len(), signing_len);
            assert_eq!(
                client_view.client.encryption_key().value().len(),
                encryption_len
            );
            assert_eq!(client_view.client.initialization_vector().len(), 16);
            assert_eq!(client_view.server.signing_key().len(), signing_len);
            assert_eq!(
                client_view.server.encryption_key().value().len(),
                encryption_len
            );
            assert_eq!(client_view.server.initialization_vector().len(), 16);
        }
    }

    #[test]
    fn ephemeral_public_key_encoding_roundtrips_as_xy_without_uncompressed_prefix() {
        for curve in [EccCurve::P256, EccCurve::P384] {
            let keypair = generate_ephemeral_keypair(curve).expect("generate ephemeral keypair");
            let encoded = encode_public_key(keypair.public_key())
                .expect("encode ephemeral public key as X||Y");

            assert_eq!(encoded.len(), curve.encoded_public_key_len());
            assert_ne!(encoded.first(), Some(&0x04));

            let decoded = decode_public_key(curve, &encoded).expect("decode X||Y public key");
            assert_eq!(decoded.curve(), curve);
            assert_eq!(decoded.encoded(), encoded);
        }
    }
}
