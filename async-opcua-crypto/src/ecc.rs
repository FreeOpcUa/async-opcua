//! ECC support for OPC UA Part 6 §6.8 security policies.
//!
//! This module intentionally exposes only the foundational API surface for
//! `ECC_nistP256` and `ECC_nistP384`. The cryptographic implementations are
//! added by the follow-up ECC primitive tasks.

#[cfg(feature = "ecc")]
use std::fmt::{Debug, Formatter};
#[cfg(feature = "ecc")]
use std::io::Cursor;

#[cfg(feature = "ecc")]
use ecdsa::signature::{Signer, Verifier};
#[cfg(feature = "ecc")]
use hkdf::Hkdf;
#[cfg(feature = "ecc")]
use opcua_types::{
    AdditionalParametersType, BinaryDecodable, BinaryEncodable, ByteString, Context, ContextOwned,
    DateTime, EphemeralKeyType, Error, ExtensionObject, KeyValuePair, NodeId, QualifiedName,
    StatusCode, UAString, Variant,
};
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
use crate::{AesDerivedKeys, AesKey, PrivateKey, SecurityPolicy, X509};

/// NIST curve selected by an OPC UA Part 6 §6.8 ECC security policy.
#[cfg(feature = "ecc")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EccCurve {
    /// NIST P-256 / secp256r1.
    P256,
    /// NIST P-384 / secp384r1.
    P384,
}

/// Part 6 §6.8.2 server EphemeralKey lifecycle decision at Create/ActivateSession.
#[cfg(feature = "ecc")]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EcdhKeyAction {
    /// No `ECDHPolicyUri` requested and no key previously issued — preserve today's null-header flow.
    None,
    /// The requested `ECDHPolicyUri` is not a supported ECC policy — `Bad_SecurityPolicyRejected`.
    Reject,
    /// Issue a fresh EphemeralKey for this policy (client requested it, or the previous key was consumed).
    Issue(SecurityPolicy),
    /// Client sent no `ECDHPolicyUri` and the previously-issued key is unused — keep using it.
    Retain,
}

#[cfg(feature = "ecc")]
impl Eq for EcdhKeyAction {}

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

/// Build the request-side AdditionalHeader carrying the chosen `ECDHPolicyUri` (Part 6 Table 70).
#[cfg(feature = "ecc")]
pub fn build_ecdh_policy_request(ecdh_policy_uri: &str) -> ExtensionObject {
    ExtensionObject::from_message(AdditionalParametersType {
        parameters: Some(vec![KeyValuePair {
            key: QualifiedName::new(0, "ECDHPolicyUri"),
            value: Variant::from(UAString::from(ecdh_policy_uri)),
        }]),
    })
}

/// Read the requested `ECDHPolicyUri` from a request AdditionalHeader. None if absent/malformed.
#[cfg(feature = "ecc")]
pub fn read_ecdh_policy_uri(additional_header: &ExtensionObject) -> Option<String> {
    let params = additional_header.inner_as::<AdditionalParametersType>()?;
    let kv = params
        .parameters
        .as_ref()?
        .iter()
        .find(|kv| kv.key.namespace_index == 0 && kv.key.name == "ECDHPolicyUri")?;

    match &kv.value {
        Variant::String(s) if !s.is_empty() => Some(s.as_ref().to_string()),
        _ => None,
    }
}

/// Build the response-side AdditionalHeader carrying the issued `ECDHKey` (Part 6 Table 70).
#[cfg(feature = "ecc")]
pub fn build_ecdh_key_response(key: EphemeralKeyType) -> ExtensionObject {
    ExtensionObject::from_message(AdditionalParametersType {
        parameters: Some(vec![KeyValuePair {
            key: QualifiedName::new(0, "ECDHKey"),
            value: Variant::from(ExtensionObject::from_message(key)),
        }]),
    })
}

/// Build the response AdditionalHeader conveying a StatusCode for `ECDHKey` when an EphemeralKey
/// could not be issued (Part 6 §6.8.2: a StatusCode is returned in place of the key).
#[cfg(feature = "ecc")]
pub fn build_ecdh_key_error(status: StatusCode) -> ExtensionObject {
    ExtensionObject::from_message(AdditionalParametersType {
        parameters: Some(vec![KeyValuePair {
            key: QualifiedName::new(0, "ECDHKey"),
            value: Variant::from(status),
        }]),
    })
}

/// Read the issued `ECDHKey` (`EphemeralKeyType`) from a response AdditionalHeader. None if absent/malformed.
#[cfg(feature = "ecc")]
pub fn read_ecdh_key(additional_header: &ExtensionObject) -> Option<EphemeralKeyType> {
    let params = additional_header.inner_as::<AdditionalParametersType>()?;
    let kv = params
        .parameters
        .as_ref()?
        .iter()
        .find(|kv| kv.key.namespace_index == 0 && kv.key.name == "ECDHKey")?;

    match &kv.value {
        Variant::ExtensionObject(eo) => eo.inner_as::<EphemeralKeyType>().cloned(),
        _ => None,
    }
}

/// Decide the §6.8.2 EphemeralKey action from the requested `ECDHPolicyUri`, the policy of any
/// previously-issued key, and whether that previous key has been consumed (anti-replay).
///
/// - `Some(uri)` naming a supported ECC policy → `Issue(policy)` (an explicit request always wins).
/// - `Some(uri)` that is non-ECC or unparseable → `Reject`.
/// - `None` + no previous key → `None`.
/// - `None` + previous key consumed → `Issue(previous_policy)` (never reuse a consumed key).
/// - `None` + previous key unused → `Retain`.
#[cfg(feature = "ecc")]
#[must_use]
pub fn decide_ecdh_key_action(
    requested_uri: Option<&str>,
    previous_policy: Option<SecurityPolicy>,
    previous_key_consumed: bool,
) -> EcdhKeyAction {
    match requested_uri {
        Some(uri) => match SecurityPolicy::from_uri(uri) {
            policy @ (SecurityPolicy::EccNistP256 | SecurityPolicy::EccNistP384) => {
                EcdhKeyAction::Issue(policy)
            }
            _ => EcdhKeyAction::Reject,
        },
        None => match previous_policy {
            None => EcdhKeyAction::None,
            Some(previous) if previous_key_consumed => EcdhKeyAction::Issue(previous),
            Some(_) => EcdhKeyAction::Retain,
        },
    }
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
#[derive(Clone)]
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

    /// Encodes this EC private key as PKCS#8 DER.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored scalar cannot be represented as a curve private key.
    pub fn to_pkcs8_der(&self) -> rsa::pkcs8::Result<rsa::pkcs8::SecretDocument> {
        use rsa::pkcs8::EncodePrivateKey;

        match self.curve {
            EccCurve::P256 => p256::SecretKey::from_slice(self.scalar())
                .map_err(|_| rsa::pkcs8::Error::KeyMalformed)?
                .to_pkcs8_der(),
            EccCurve::P384 => p384::SecretKey::from_slice(self.scalar())
                .map_err(|_| rsa::pkcs8::Error::KeyMalformed)?
                .to_pkcs8_der(),
        }
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
    /// Splits the key pair into its private and public halves.
    #[must_use]
    pub fn into_parts(self) -> (EphemeralPrivateKey, EphemeralPublicKey) {
        (self.private_key, self.public_key)
    }

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

/// Derived symmetric material for an `EccEncryptedSecret` (Part 6 §6.8.3, Table 71).
/// For ECC there is NO derived signing key — integrity is an asymmetric signature — so only the
/// AES EncryptingKey and the InitializationVector are derived.
#[cfg(feature = "ecc")]
pub struct EccSecretKeys {
    /// AES key for the payload (AES-128-CBC for P-256, AES-256-CBC for P-384).
    pub encrypting_key: AesKey,
    /// AES-CBC initialization vector (16 bytes).
    pub iv: Vec<u8>,
}

/// Parsed Part 4 §7.40.2.5 `EccEncryptedSecret` envelope (Table 186). The `encrypted_payload` is the
/// AES-CBC ciphertext blob (Nonce|Secret|Padding|PaddingSize, encrypted); `signature` is the trailing
/// asymmetric (ECDSA r||s) signature. Crypto is handled by the encrypt/decrypt callers — this is pure
/// serialization.
#[cfg(feature = "ecc")]
#[allow(dead_code)]
pub(crate) struct EccEncryptedSecret {
    pub(crate) security_policy_uri: String,
    pub(crate) certificate: ByteString,
    pub(crate) signing_time: DateTime,
    pub(crate) sender_public_key: ByteString,
    pub(crate) receiver_public_key: ByteString,
    pub(crate) encrypted_payload: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

#[cfg(feature = "ecc")]
#[allow(dead_code)]
impl EccEncryptedSecret {
    /// Serialize everything covered by the Signature (Figure 39): the full envelope up to but NOT
    /// including the trailing Signature bytes. (The `Length` field still counts the Signature.)
    pub(crate) fn encode_data_to_sign(&self) -> Result<Vec<u8>, Error> {
        let ctx = ContextOwned::default();
        let ctx = ctx.context();
        let key_data = self.encode_key_data(&ctx)?;
        let body_len = self.body_len(key_data.len())?;

        let envelope_prefix_len = NodeId::new(0, 17546u32).byte_len(&ctx) + 1 + 4;
        let data_to_sign_len = envelope_prefix_len + body_len - self.signature.len();
        let mut buf = Vec::with_capacity(data_to_sign_len);
        NodeId::new(0, 17546u32).encode(&mut buf, &ctx)?;
        1u8.encode(&mut buf, &ctx)?;
        i32::try_from(body_len)
            .map_err(|_| invalid_argument("EccEncryptedSecret body length exceeds i32"))?
            .encode(&mut buf, &ctx)?;
        self.encode_body_to_sign(&mut buf, &ctx, &key_data)?;
        Ok(buf)
    }

    /// Full serialized envelope = `encode_data_to_sign()` followed by `self.signature`.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut buf = self.encode_data_to_sign()?;
        buf.extend_from_slice(&self.signature);
        Ok(buf)
    }

    /// Parse a full envelope from attacker-controlled bytes. Bounds every length; never panics.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let ctx = ContextOwned::default();
        let ctx = ctx.context();
        let mut cursor = Cursor::new(bytes);

        let _type_id = NodeId::decode(&mut cursor, &ctx)?;
        let encoding_mask = u8::decode(&mut cursor, &ctx)?;
        if encoding_mask != 1 {
            return Err(invalid_argument(format!(
                "unsupported EccEncryptedSecret encoding mask {encoding_mask}"
            )));
        }

        let length = i32::decode(&mut cursor, &ctx)?;
        if length < 0 {
            return Err(invalid_argument(format!(
                "negative EccEncryptedSecret body length {length}"
            )));
        }
        let length = usize::try_from(length)
            .map_err(|_| invalid_argument("EccEncryptedSecret body length cannot fit usize"))?;
        let body_start = usize::try_from(cursor.position())
            .map_err(|_| invalid_argument("EccEncryptedSecret cursor position cannot fit usize"))?;
        let body_end = body_start
            .checked_add(length)
            .ok_or_else(|| invalid_argument("EccEncryptedSecret body length overflows"))?;
        let body = bytes
            .get(body_start..body_end)
            .ok_or_else(|| invalid_argument("EccEncryptedSecret body exceeds input length"))?;
        let mut body_cursor = Cursor::new(body);

        let security_policy_uri = UAString::decode(&mut body_cursor, &ctx)?;
        if security_policy_uri.is_null() {
            return Err(invalid_argument(
                "EccEncryptedSecret SecurityPolicyUri cannot be null",
            ));
        }
        let security_policy_uri = security_policy_uri.as_ref().to_string();
        let certificate = ByteString::decode(&mut body_cursor, &ctx)?;
        let signing_time = DateTime::decode(&mut body_cursor, &ctx)?;
        let key_data_len = usize::from(u16::decode(&mut body_cursor, &ctx)?);

        let key_data_start = usize::try_from(body_cursor.position())
            .map_err(|_| invalid_argument("EccEncryptedSecret cursor position cannot fit usize"))?;
        let key_data_end = key_data_start
            .checked_add(key_data_len)
            .ok_or_else(|| invalid_argument("EccEncryptedSecret KeyData length overflows"))?;
        let key_data = body
            .get(key_data_start..key_data_end)
            .ok_or_else(|| invalid_argument("EccEncryptedSecret KeyData exceeds body length"))?;
        let mut key_cursor = Cursor::new(key_data);
        let sender_public_key = ByteString::decode(&mut key_cursor, &ctx)?;
        let receiver_public_key = ByteString::decode(&mut key_cursor, &ctx)?;
        if usize::try_from(key_cursor.position())
            .map_err(|_| invalid_argument("EccEncryptedSecret cursor position cannot fit usize"))?
            != key_data_len
        {
            return Err(invalid_argument(
                "EccEncryptedSecret KeyData contains trailing bytes",
            ));
        }

        let remaining = body
            .get(key_data_end..)
            .ok_or_else(|| invalid_argument("EccEncryptedSecret payload start exceeds body"))?;
        let signature_len =
            EccCurve::from_security_policy(SecurityPolicy::from_uri(&security_policy_uri))?
                .raw_signature_len();
        if remaining.len() < signature_len {
            return Err(invalid_argument(format!(
                "EccEncryptedSecret payload and signature length {} is shorter than signature length {}",
                remaining.len(),
                signature_len
            )));
        }
        let payload_len = remaining.len() - signature_len;
        let encrypted_payload = remaining
            .get(..payload_len)
            .ok_or_else(|| invalid_argument("EccEncryptedSecret encrypted payload is missing"))?
            .to_vec();
        let signature = remaining
            .get(payload_len..)
            .ok_or_else(|| invalid_argument("EccEncryptedSecret signature is missing"))?
            .to_vec();

        Ok(Self {
            security_policy_uri,
            certificate,
            signing_time,
            sender_public_key,
            receiver_public_key,
            encrypted_payload,
            signature,
        })
    }

    fn encode_key_data(&self, ctx: &Context<'_>) -> Result<Vec<u8>, Error> {
        let mut key_data = Vec::with_capacity(
            self.sender_public_key.byte_len(ctx) + self.receiver_public_key.byte_len(ctx),
        );
        self.sender_public_key.encode(&mut key_data, ctx)?;
        self.receiver_public_key.encode(&mut key_data, ctx)?;
        Ok(key_data)
    }

    fn body_len(&self, key_data_len: usize) -> Result<usize, Error> {
        let signature_len =
            EccCurve::from_security_policy(SecurityPolicy::from_uri(&self.security_policy_uri))?
                .raw_signature_len();

        self.security_policy_uri
            .len()
            .checked_add(self.certificate.as_ref().len())
            .and_then(|len| len.checked_add(self.encrypted_payload.len()))
            .and_then(|len| len.checked_add(signature_len))
            .and_then(|len| len.checked_add(key_data_len))
            .and_then(|len| len.checked_add(4 + 4 + 8 + 2))
            .ok_or_else(|| invalid_argument("EccEncryptedSecret body length overflows"))
    }

    fn encode_body_to_sign(
        &self,
        buf: &mut Vec<u8>,
        ctx: &Context<'_>,
        key_data: &[u8],
    ) -> Result<(), Error> {
        UAString::from(self.security_policy_uri.as_str()).encode(buf, ctx)?;
        self.certificate.encode(buf, ctx)?;
        self.signing_time.encode(buf, ctx)?;
        u16::try_from(key_data.len())
            .map_err(|_| invalid_argument("EccEncryptedSecret KeyData length exceeds u16"))?
            .encode(buf, ctx)?;
        buf.extend_from_slice(key_data);
        buf.extend_from_slice(&self.encrypted_payload);
        Ok(())
    }
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

/// Signs an ECC EphemeralKey's encoded `publicKey` bytes with the application-instance key, using the
/// asymmetric signature algorithm of `security_policy` (OPC UA Part 4 §7.15). Returns the signature.
#[cfg(feature = "ecc")]
pub fn sign_ephemeral_public_key(
    security_policy: SecurityPolicy,
    signing_key: &PrivateKey,
    public_key: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut signature =
        vec![0u8; EccCurve::from_security_policy(security_policy)?.raw_signature_len()];
    let len = security_policy.asymmetric_sign(signing_key, public_key, &mut signature)?;
    signature.truncate(len);
    Ok(signature)
}

/// Generate and sign a server ECC EphemeralKey for the requested `ecdh_policy_uri` (Part 6 §6.8.2).
/// Returns the keypair (the server retains the private half) and the `EphemeralKeyType` to return to
/// the client. A non-ECC / unknown policy is rejected (`Bad_SecurityPolicyRejected`, surfaced by
/// `EccCurve::from_security_policy`).
#[cfg(feature = "ecc")]
pub fn issue_server_ephemeral_key(
    ecdh_policy_uri: &str,
    server_signing_key: &PrivateKey,
) -> Result<(EphemeralKeyPair, EphemeralKeyType), Error> {
    let policy = SecurityPolicy::from_uri(ecdh_policy_uri);
    let curve = EccCurve::from_security_policy(policy)?;
    let keypair = generate_ephemeral_keypair(curve)?;
    let public_key = encode_public_key(keypair.public_key())?;
    let signature = sign_ephemeral_public_key(policy, server_signing_key, &public_key)?;
    let ephemeral_key = EphemeralKeyType {
        public_key: ByteString::from(public_key),
        signature: ByteString::from(signature),
    };
    Ok((keypair, ephemeral_key))
}

/// Verifies the signature over an ECC EphemeralKey's `publicKey` bytes against the signer's
/// certificate, using the asymmetric signature algorithm of `security_policy` (Part 4 §7.15).
#[cfg(feature = "ecc")]
pub fn verify_ephemeral_public_key(
    security_policy: SecurityPolicy,
    signer_cert: &X509,
    public_key: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    let verification_key = signer_cert.public_key()?;
    security_policy.asymmetric_verify_signature(&verification_key, public_key, signature)
}

/// Read the server's `ECDHKey` from a response AdditionalHeader, verify its signature against the
/// server certificate (Part 4 §7.15), and return the decoded ephemeral public key. `Ok(None)` if no
/// `ECDHKey` is present; `Err` if a key is present but its signature or curve point is invalid.
#[cfg(feature = "ecc")]
pub fn read_and_verify_server_ephemeral_key(
    additional_header: &ExtensionObject,
    security_policy: SecurityPolicy,
    server_cert: &X509,
) -> Result<Option<EphemeralPublicKey>, Error> {
    let Some(ephemeral_key) = read_ecdh_key(additional_header) else {
        return Ok(None);
    };
    verify_ephemeral_public_key(
        security_policy,
        server_cert,
        ephemeral_key.public_key.as_ref(),
        ephemeral_key.signature.as_ref(),
    )?;
    let curve = EccCurve::from_security_policy(security_policy)?;
    let public_key = decode_public_key(curve, ephemeral_key.public_key.as_ref())?;
    Ok(Some(public_key))
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

/// Verifies a DER `Ecdsa-Sig-Value` signature used by X.509 certificates and CRLs.
///
/// Uses the curve-canonical hash for verification. The caller is responsible for
/// confirming the signature-algorithm OID matches the issuer curve.
///
/// # Errors
///
#[cfg(feature = "ecc")]
pub fn ecdsa_verify_der(
    verification_key: &EccPublicKey,
    data: &[u8],
    der_signature: &[u8],
) -> Result<(), Error> {
    let sec1 = sec1_from_xy(verification_key.curve, verification_key.encoded())?;
    match verification_key.curve {
        EccCurve::P256 => {
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|_| invalid_argument("invalid P-256 ECDSA public key"))?;
            let signature = p256::ecdsa::Signature::from_der(der_signature)
                .map_err(|_| invalid_argument("invalid P-256 DER ECDSA signature"))?;
            key.verify(data, &signature)
                .map_err(|_| security_check_failed("P-256 ECDSA signature verification failed"))
        }
        EccCurve::P384 => {
            let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|_| invalid_argument("invalid P-384 ECDSA public key"))?;
            let signature = p384::ecdsa::Signature::from_der(der_signature)
                .map_err(|_| invalid_argument("invalid P-384 DER ECDSA signature"))?;
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

    // Fail closed: the only valid IKM is the ECDH shared secret, i.e. the curve
    // field-element x-coordinate (32 B P-256 / 48 B P-384). Reject anything else
    // rather than deriving keys from a malformed secret.
    if shared_secret.len() != curve.scalar_len() {
        return Err(invalid_argument(format!(
            "ECC shared secret must be {} bytes for {:?}, got {}",
            curve.scalar_len(),
            curve,
            shared_secret.len()
        )));
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

#[cfg(feature = "ecc")]
fn split_secret_keys(
    encryption_len: usize,
    iv_len: usize,
    key_material: &[u8],
) -> Result<EccSecretKeys, Error> {
    let iv_start = encryption_len;
    let end = iv_start + iv_len;

    let encrypting_key = key_material
        .get(..encryption_len)
        .ok_or_else(|| invalid_argument("missing ECC secret encryption key material"))?
        .to_vec();
    let iv = key_material
        .get(iv_start..end)
        .ok_or_else(|| invalid_argument("missing ECC secret initialization vector material"))?
        .to_vec();

    Ok(EccSecretKeys {
        encrypting_key: AesKey::new(encrypting_key),
        iv,
    })
}

/// Part 6 §6.8.3 KDF for an `EccEncryptedSecret`. Derives the EncryptingKey + IV via RFC 5869 HKDF:
///   SecretSalt = L (u16 little-endian) | UTF8("opcua-secret") | sender_public_key | receiver_public_key
///   PRK  = HMAC-Hash(SecretSalt, shared_secret)       // Extract; IKM = ECDH shared secret (x-coord)
///   OKM  = HKDF-Expand(PRK, Info = SecretSalt, L)      // Info equals the Salt
///   EncryptingKey = OKM[0 .. EncryptionKeyLength]; InitializationVector = OKM[EncryptionKeyLength .. EncryptionKeyLength+IvLength]
/// where L = EncryptionKeyLength + IvLength. Hash per curve: SHA-256 for P-256, SHA-384 for P-384.
/// Per-curve lengths come from the existing `key_lengths(curve)` -> (signing, enc, iv): P-256 (32,16,16)
/// => EncryptionKeyLength=16 (AES-128); P-384 (48,32,16) => EncryptionKeyLength=32 (AES-256); IV=16 both.
/// The signing length is IGNORED here (no derived signing key for ECC).
///
/// Fail closed: reject a `shared_secret` whose length != the curve x-coordinate size
/// (`curve.scalar_len()`), exactly as `derive_keys` does.
///
/// # Errors
///
/// Returns `BadInvalidArgument` when the shared secret length is not valid for the curve, when the
/// requested output length cannot be encoded by the specification, or when HKDF output is invalid.
#[cfg(feature = "ecc")]
pub fn derive_secret_keys(
    curve: EccCurve,
    shared_secret: &[u8],
    sender_public_key: &[u8],
    receiver_public_key: &[u8],
) -> Result<EccSecretKeys, Error> {
    let (_, encryption_len, iv_len) = key_lengths(curve);
    let output_len = encryption_len + iv_len;

    if shared_secret.len() != curve.scalar_len() {
        return Err(invalid_argument(format!(
            "ECC shared secret must be {} bytes for {:?}, got {}",
            curve.scalar_len(),
            curve,
            shared_secret.len()
        )));
    }

    let output_len_u16 = u16::try_from(output_len)
        .map_err(|_| invalid_argument("ECC secret key material length exceeds u16"))?;
    let mut salt = Vec::with_capacity(
        2 + b"opcua-secret".len() + sender_public_key.len() + receiver_public_key.len(),
    );
    salt.extend_from_slice(&output_len_u16.to_le_bytes());
    salt.extend_from_slice(b"opcua-secret");
    salt.extend_from_slice(sender_public_key);
    salt.extend_from_slice(receiver_public_key);

    let key_material = match curve {
        EccCurve::P256 => hkdf_expand_sha256(shared_secret, &salt, output_len)?,
        EccCurve::P384 => hkdf_expand_sha384(shared_secret, &salt, output_len)?,
    };

    split_secret_keys(encryption_len, iv_len, &key_material)
}

/// Encrypt `secret` as a Part 4 §7.40.2.5 `EccEncryptedSecret` for the receiver's ECC EphemeralKey.
/// Generates a fresh sender (client) EphemeralKey, derives the AES key+IV via the §6.8.3 KDF from
/// ECDH(sender_private, receiver_public), AES-CBC encrypts the payload (Nonce|Secret|Padding|PadSize),
/// and appends an asymmetric (ECDSA) signature over the envelope computed with `signing_key`.
/// Returns the serialized envelope bytes. `signing_cert` populates the envelope `Certificate` field.
#[cfg(feature = "ecc")]
pub fn ecc_encrypt_secret(
    security_policy: SecurityPolicy,
    server_nonce: &[u8],
    receiver_ephemeral_public_key: &EphemeralPublicKey,
    signing_key: &PrivateKey,
    signing_cert: &X509,
    secret: &[u8],
) -> Result<Vec<u8>, Error> {
    let curve = EccCurve::from_security_policy(security_policy)?;
    if receiver_ephemeral_public_key.curve() != curve {
        return Err(invalid_argument(
            "EccEncryptedSecret receiver public key curve mismatch",
        ));
    }

    let sender_kp = generate_ephemeral_keypair(curve)?;
    let sender_pub_bytes = encode_public_key(sender_kp.public_key())?;
    let receiver_pub_bytes = encode_public_key(receiver_ephemeral_public_key)?;
    let shared = ecdh_shared_secret(sender_kp.private_key(), receiver_ephemeral_public_key)?;
    let keys = derive_secret_keys(curve, &shared, &sender_pub_bytes, &receiver_pub_bytes)?;

    let plaintext = build_secret_payload(&keys, server_nonce, secret)?;
    let encrypted_payload = encrypt_secret_payload(curve, &keys, &plaintext)?;

    let mut env = EccEncryptedSecret {
        security_policy_uri: security_policy.to_uri().to_string(),
        certificate: signing_cert.as_byte_string(),
        signing_time: DateTime::now(),
        sender_public_key: ByteString::from(sender_pub_bytes),
        receiver_public_key: ByteString::from(receiver_pub_bytes),
        encrypted_payload,
        signature: Vec::new(),
    };

    let to_sign = env.encode_data_to_sign()?;
    let mut signature = vec![0u8; curve.raw_signature_len()];
    let len = security_policy.asymmetric_sign(signing_key, &to_sign, &mut signature)?;
    signature.truncate(len);
    env.signature = signature;

    env.encode()
}

#[cfg(feature = "ecc")]
fn build_secret_payload(
    keys: &EccSecretKeys,
    server_nonce: &[u8],
    secret: &[u8],
) -> Result<Vec<u8>, Error> {
    let block = keys.iv.len();
    if block == 0 {
        return Err(invalid_argument(
            "EccEncryptedSecret initialization vector is empty",
        ));
    }

    let server_nonce_len = payload_byte_string_len(server_nonce)?;
    let secret_len = payload_byte_string_len(secret)?;
    let data_len = 4usize
        .checked_add(server_nonce_len)
        .and_then(|len| len.checked_add(4))
        .and_then(|len| len.checked_add(secret_len))
        .and_then(|len| len.checked_add(2))
        .ok_or_else(|| invalid_argument("EccEncryptedSecret payload length overflows"))?;
    let mut pad = if data_len % block == 0 {
        0
    } else {
        block - data_len % block
    };
    if pad + secret.len() < block {
        pad += block;
    }

    let plaintext_len = data_len
        .checked_add(pad)
        .ok_or_else(|| invalid_argument("EccEncryptedSecret plaintext length overflows"))?;
    let mut plaintext = Vec::with_capacity(plaintext_len);
    encode_payload_byte_string(&mut plaintext, server_nonce)?;
    encode_payload_byte_string(&mut plaintext, secret)?;
    plaintext.extend(std::iter::repeat_n((pad as u16 & 0xff) as u8, pad));
    plaintext.extend_from_slice(&(pad as u16).to_le_bytes());

    if plaintext.len() != plaintext_len || !plaintext.len().is_multiple_of(block) {
        return Err(invalid_argument(
            "EccEncryptedSecret plaintext is not full AES-CBC blocks",
        ));
    }

    Ok(plaintext)
}

#[cfg(feature = "ecc")]
fn payload_byte_string_len(value: &[u8]) -> Result<usize, Error> {
    i32::try_from(value.len())
        .map_err(|_| invalid_argument("EccEncryptedSecret ByteString length exceeds i32"))?;
    Ok(value.len())
}

#[cfg(feature = "ecc")]
fn encode_payload_byte_string(buf: &mut Vec<u8>, value: &[u8]) -> Result<(), Error> {
    let len = i32::try_from(value.len())
        .map_err(|_| invalid_argument("EccEncryptedSecret ByteString length exceeds i32"))?;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(value);
    Ok(())
}

#[cfg(feature = "ecc")]
fn encrypt_secret_payload(
    curve: EccCurve,
    keys: &EccSecretKeys,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    const AES_BLOCK_LEN: usize = 16;

    if plaintext.is_empty() || !plaintext.len().is_multiple_of(AES_BLOCK_LEN) {
        return Err(invalid_argument(
            "EccEncryptedSecret plaintext is not full AES-CBC blocks",
        ));
    }
    if keys.iv.len() != AES_BLOCK_LEN {
        return Err(invalid_argument(
            "EccEncryptedSecret initialization vector is not 16 bytes",
        ));
    }

    let mut ciphertext = vec![0u8; plaintext.len()];
    match curve {
        EccCurve::P256 => {
            if keys.encrypting_key.value().len() != 16 {
                return Err(invalid_argument(
                    "EccEncryptedSecret AES-128 key is not 16 bytes",
                ));
            }
            keys.encrypting_key
                .encrypt_aes128_cbc(plaintext, &keys.iv, &mut ciphertext)?;
        }
        EccCurve::P384 => {
            if keys.encrypting_key.value().len() != 32 {
                return Err(invalid_argument(
                    "EccEncryptedSecret AES-256 key is not 32 bytes",
                ));
            }
            keys.encrypting_key
                .encrypt_aes256_cbc(plaintext, &keys.iv, &mut ciphertext)?;
        }
    }

    Ok(ciphertext)
}

/// Decrypt an `EccEncryptedSecret` (Part 4 §7.40.2.5) and return the plaintext Secret.
///
/// Verifies the asymmetric (ECDSA) signature against `signer_cert` BEFORE decrypting (§6.8.3), derives
/// the AES key+IV via the §6.8.3 KDF from ECDH(`server_ephemeral_private`, SenderPublicKey), AES-CBC
/// decrypts the payload, verifies the padding, and checks the embedded Nonce equals `server_nonce`.
///
/// FAIL-CLOSED: every failure (malformed bytes, policy mismatch, bad signature, wrong receiver key,
/// AES/padding error, wrong nonce) returns the SAME uniform error and NEVER panics.
///
/// # Errors
///
/// Returns `BadIdentityTokenRejected` for every rejection cause.
#[cfg(feature = "ecc")]
pub fn ecc_decrypt_secret(
    security_policy: SecurityPolicy,
    encrypted: &[u8],
    server_nonce: &[u8],
    server_ephemeral_private: &EphemeralPrivateKey,
    signer_cert: &X509,
) -> Result<ByteString, Error> {
    ecc_decrypt_secret_inner(
        security_policy,
        encrypted,
        server_nonce,
        server_ephemeral_private,
        signer_cert,
    )
    .map_err(|_| {
        Error::new(
            StatusCode::BadIdentityTokenRejected,
            "identity token rejected",
        )
    })
}

#[cfg(feature = "ecc")]
fn ecc_decrypt_secret_inner(
    security_policy: SecurityPolicy,
    encrypted: &[u8],
    server_nonce: &[u8],
    server_ephemeral_private: &EphemeralPrivateKey,
    signer_cert: &X509,
) -> Result<ByteString, Error> {
    let env = EccEncryptedSecret::decode(encrypted)?;
    if SecurityPolicy::from_uri(&env.security_policy_uri) != security_policy {
        return Err(security_check_failed(
            "EccEncryptedSecret security policy mismatch",
        ));
    }
    let curve = EccCurve::from_security_policy(security_policy)?;

    let to_sign = env.encode_data_to_sign()?;
    let verify_key = signer_cert.public_key()?;
    security_policy.asymmetric_verify_signature(&verify_key, &to_sign, &env.signature)?;

    let server_public_key = server_ephemeral_private.public_key()?;
    let server_public_key = encode_public_key(&server_public_key)?;
    if server_public_key.as_slice() != env.receiver_public_key.as_ref() {
        return Err(security_check_failed(
            "EccEncryptedSecret receiver public key mismatch",
        ));
    }

    let sender_pub = decode_public_key(curve, env.sender_public_key.as_ref())?;
    let shared = ecdh_shared_secret(server_ephemeral_private, &sender_pub)?;
    let keys = derive_secret_keys(
        curve,
        &shared,
        env.sender_public_key.as_ref(),
        env.receiver_public_key.as_ref(),
    )?;

    let plaintext = decrypt_secret_payload(curve, &keys, &env.encrypted_payload)?;
    let (nonce, secret) = parse_secret_payload(&plaintext)?;
    if nonce.as_ref() != server_nonce {
        return Err(security_check_failed("EccEncryptedSecret nonce mismatch"));
    }

    Ok(secret)
}

#[cfg(feature = "ecc")]
fn decrypt_secret_payload(
    curve: EccCurve,
    keys: &EccSecretKeys,
    encrypted_payload: &[u8],
) -> Result<Vec<u8>, Error> {
    const AES_BLOCK_LEN: usize = 16;

    if encrypted_payload.is_empty() || !encrypted_payload.len().is_multiple_of(AES_BLOCK_LEN) {
        return Err(invalid_argument(
            "EccEncryptedSecret encrypted payload is not full AES-CBC blocks",
        ));
    }
    if keys.iv.len() != AES_BLOCK_LEN {
        return Err(invalid_argument(
            "EccEncryptedSecret initialization vector is not 16 bytes",
        ));
    }

    let mut plaintext = vec![0u8; encrypted_payload.len()];
    match curve {
        EccCurve::P256 => {
            if keys.encrypting_key.value().len() != 16 {
                return Err(invalid_argument(
                    "EccEncryptedSecret AES-128 key is not 16 bytes",
                ));
            }
            keys.encrypting_key
                .decrypt_aes128_cbc(encrypted_payload, &keys.iv, &mut plaintext)?;
        }
        EccCurve::P384 => {
            if keys.encrypting_key.value().len() != 32 {
                return Err(invalid_argument(
                    "EccEncryptedSecret AES-256 key is not 32 bytes",
                ));
            }
            keys.encrypting_key
                .decrypt_aes256_cbc(encrypted_payload, &keys.iv, &mut plaintext)?;
        }
    }

    Ok(plaintext)
}

#[cfg(feature = "ecc")]
fn parse_secret_payload(plaintext: &[u8]) -> Result<(ByteString, ByteString), Error> {
    let size_offset = plaintext
        .len()
        .checked_sub(2)
        .ok_or_else(|| invalid_argument("EccEncryptedSecret payload is missing padding size"))?;
    let pad_size_bytes = plaintext
        .get(size_offset..)
        .ok_or_else(|| invalid_argument("EccEncryptedSecret payload padding size is missing"))?;
    let pad_size = u16::from_le_bytes(
        pad_size_bytes
            .try_into()
            .map_err(|_| invalid_argument("EccEncryptedSecret padding size is malformed"))?,
    );
    let pad_size = usize::from(pad_size);
    let payload_end = size_offset
        .checked_sub(pad_size)
        .ok_or_else(|| invalid_argument("EccEncryptedSecret padding exceeds payload length"))?;
    let padding = plaintext
        .get(payload_end..size_offset)
        .ok_or_else(|| invalid_argument("EccEncryptedSecret padding is malformed"))?;
    let expected_padding_byte = (pad_size & 0xff) as u8;
    if !padding.iter().all(|byte| *byte == expected_padding_byte) {
        return Err(invalid_argument(
            "EccEncryptedSecret padding bytes are malformed",
        ));
    }

    let payload = plaintext
        .get(..payload_end)
        .ok_or_else(|| invalid_argument("EccEncryptedSecret payload is malformed"))?;
    let mut offset = 0usize;
    let nonce = parse_payload_byte_string(payload, &mut offset)?;
    let secret = parse_payload_byte_string(payload, &mut offset)?;
    if offset != payload.len() {
        return Err(invalid_argument(
            "EccEncryptedSecret payload contains trailing bytes",
        ));
    }

    Ok((nonce, secret))
}

#[cfg(feature = "ecc")]
fn parse_payload_byte_string(payload: &[u8], offset: &mut usize) -> Result<ByteString, Error> {
    let len_end = offset
        .checked_add(4)
        .ok_or_else(|| invalid_argument("EccEncryptedSecret ByteString offset overflows"))?;
    let len_bytes = payload
        .get(*offset..len_end)
        .ok_or_else(|| invalid_argument("EccEncryptedSecret ByteString length is missing"))?;
    let len = i32::from_le_bytes(
        len_bytes
            .try_into()
            .map_err(|_| invalid_argument("EccEncryptedSecret ByteString length is malformed"))?,
    );
    *offset = len_end;

    if len == -1 {
        return Ok(ByteString::null());
    }
    if len < -1 {
        return Err(invalid_argument(
            "EccEncryptedSecret ByteString length is negative",
        ));
    }

    let len = usize::try_from(len)
        .map_err(|_| invalid_argument("EccEncryptedSecret ByteString length cannot fit usize"))?;
    let value_end = offset
        .checked_add(len)
        .ok_or_else(|| invalid_argument("EccEncryptedSecret ByteString value overflows"))?;
    let value = payload
        .get(*offset..value_end)
        .ok_or_else(|| invalid_argument("EccEncryptedSecret ByteString value exceeds payload"))?;
    *offset = value_end;

    Ok(ByteString::from(value))
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
            // The shared secret IKM is exactly the curve field-element size.
            let curve = EccCurve::from_security_policy(policy).unwrap();
            let secret = &shared_secret[..curve.scalar_len()];
            let client_view = derive_keys(policy, secret, &client_nonce, &server_nonce)
                .expect("client-side OPC UA ECC HKDF derivation");
            let server_view = derive_keys(policy, secret, &client_nonce, &server_nonce)
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
