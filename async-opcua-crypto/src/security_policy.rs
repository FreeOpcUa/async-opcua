// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Security policy is the symmetric, asymmetric encryption / decryption + signing / verification
//! algorithms to use and enforce for the current session.
use std::fmt;
use std::str::FromStr;

use tracing::error;

use opcua_types::{constants, ByteString, Error, StatusCode};

use crate::{
    policy::{PaddingInfo, SecurityPolicyImpl},
    KeySize, PrivateKey, PublicKey,
};

use super::random;

use crate::policy::{aes::*, AesDerivedKeys, AesPolicy, NonePolicy};

// Policy dispatch is only entered after callers reject Unknown.
#[allow(clippy::panic)]
fn panic_unknown_security_policy() -> ! {
    panic!("Unknown security policy")
}

#[cfg(not(feature = "legacy-crypto"))]
// Entry points must reject unsupported legacy policies before dispatch.
#[allow(clippy::panic)]
fn panic_unsupported_legacy_policy() -> ! {
    panic!(
        "BUG: a cryptographic operation was invoked for a legacy security policy in a build without the 'legacy-crypto' feature. Entry points must reject unsupported policies (SecurityPolicy::ensure_supported) before any crypto call."
    );
}

fn ecc_not_implemented_error(operation: &str) -> Error {
    Error::new(
        StatusCode::BadNotImplemented,
        format!("{operation} is not implemented for ECC security policies yet"),
    )
}

#[cfg(feature = "ecc")]
macro_rules! call_with_ecc_symmetric_policy {
    ($r:expr, |$x:ident| $t:expr) => {
        match $r {
            Self::EccNistP256 => {
                type $x = AesPolicy<EccNistP256Symmetric>;
                $t
            }
            Self::EccNistP384 => {
                type $x = AesPolicy<EccNistP384Symmetric>;
                $t
            }
            _ => unreachable!("caller must pass an ECC security policy"),
        }
    };
}

macro_rules! call_with_policy {
    (_inner $r:expr, $($p:ident: $ty:ty,)+ |$x:ident| $t:expr) => {
        match $r {
            $(
                Self::$p => {
                    type $x = $ty;
                    #[allow(unused_braces)]
                    $t
                }
            )*
            Self::Unknown => panic_unknown_security_policy(),
        }
    };

    ($r:expr, |$x:ident| $t:expr) => {
        match $r {
            Self::None => {
                type $x = NonePolicy;
                $t
            }
            Self::Aes128Sha256RsaOaep => {
                type $x = AesPolicy<Aes128Sha256RsaOaep>;
                $t
            }
            Self::Basic256Sha256 => {
                type $x = AesPolicy<Basic256Sha256>;
                $t
            }
            Self::Aes256Sha256RsaPss => {
                type $x = AesPolicy<Aes256Sha256RsaPss>;
                $t
            }
            Self::PubSubAes128Ctr => {
                type $x = AesPolicy<PubSubAes128Ctr>;
                $t
            }
            Self::PubSubAes256Ctr => {
                type $x = AesPolicy<PubSubAes256Ctr>;
                $t
            }
            #[cfg(feature = "legacy-crypto")]
            Self::Basic128Rsa15 => {
                type $x = AesPolicy<Basic128Rsa15>;
                $t
            }
            #[cfg(feature = "legacy-crypto")]
            Self::Basic256 => {
                type $x = AesPolicy<Basic256>;
                $t
            }
            #[cfg(not(feature = "legacy-crypto"))]
            Self::Basic128Rsa15 | Self::Basic256 => {
                panic_unsupported_legacy_policy();
            }
            Self::EccNistP256 | Self::EccNistP384 => panic_unknown_security_policy(),
            Self::Unknown => panic_unknown_security_policy(),
        }
    };
}

/// SecurityPolicy implies what encryption and signing algorithms and their relevant key strengths
/// are used during an encrypted session.
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum SecurityPolicy {
    /// Security policy is unknown, this is generally an error.
    Unknown,
    /// No security.
    None,
    /// AES128/SHA256 RSA-OAEP.
    Aes128Sha256RsaOaep,
    /// Basic256/SHA256
    Basic256Sha256,
    /// AES256/SHA256 RSA-PSS
    Aes256Sha256RsaPss,
    /// PubSub AES128-CTR.
    PubSubAes128Ctr,
    /// PubSub AES256-CTR.
    PubSubAes256Ctr,
    /// Basic128. Note that this security policy is deprecated.
    Basic128Rsa15,
    /// Basic256.
    Basic256,
    /// ECC NIST P-256.
    EccNistP256,
    /// ECC NIST P-384.
    EccNistP384,
}

impl fmt::Display for SecurityPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl FromStr for SecurityPolicy {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            constants::SECURITY_POLICY_NONE | constants::SECURITY_POLICY_NONE_URI => {
                SecurityPolicy::None
            }
            // Legacy policies are always recognizable so they can be
            // named in errors and rejected deliberately, even in builds
            // without the legacy-crypto feature.
            constants::SECURITY_POLICY_BASIC_128_RSA_15
            | constants::SECURITY_POLICY_BASIC_128_RSA_15_URI => SecurityPolicy::Basic128Rsa15,
            constants::SECURITY_POLICY_BASIC_256 | constants::SECURITY_POLICY_BASIC_256_URI => {
                SecurityPolicy::Basic256
            }
            constants::SECURITY_POLICY_ECC_NIST_P256
            | constants::SECURITY_POLICY_ECC_NIST_P256_URI => SecurityPolicy::EccNistP256,
            constants::SECURITY_POLICY_ECC_NIST_P384
            | constants::SECURITY_POLICY_ECC_NIST_P384_URI => SecurityPolicy::EccNistP384,
            crate::policy::aes::Basic256Sha256::SECURITY_POLICY
            | crate::policy::aes::Basic256Sha256::SECURITY_POLICY_URI => {
                SecurityPolicy::Basic256Sha256
            }
            crate::policy::aes::Aes128Sha256RsaOaep::SECURITY_POLICY
            | crate::policy::aes::Aes128Sha256RsaOaep::SECURITY_POLICY_URI => {
                SecurityPolicy::Aes128Sha256RsaOaep
            }
            crate::policy::aes::Aes256Sha256RsaPss::SECURITY_POLICY
            | crate::policy::aes::Aes256Sha256RsaPss::SECURITY_POLICY_URI => {
                SecurityPolicy::Aes256Sha256RsaPss
            }
            crate::policy::aes::PubSubAes128Ctr::SECURITY_POLICY
            | crate::policy::aes::PubSubAes128Ctr::SECURITY_POLICY_URI => {
                SecurityPolicy::PubSubAes128Ctr
            }
            crate::policy::aes::PubSubAes256Ctr::SECURITY_POLICY
            | crate::policy::aes::PubSubAes256Ctr::SECURITY_POLICY_URI => {
                SecurityPolicy::PubSubAes256Ctr
            }
            _ => {
                error!("Specified security policy \"{}\" is not recognized", s);
                SecurityPolicy::Unknown
            }
        })
    }
}

impl From<SecurityPolicy> for String {
    fn from(v: SecurityPolicy) -> String {
        v.to_str().to_string()
    }
}

impl SecurityPolicy {
    /// Get the security policy URI from this policy.
    ///
    /// This will panic if the security policy is `Unknown`.
    pub fn to_uri(&self) -> &'static str {
        match self {
            SecurityPolicy::Basic128Rsa15 => constants::SECURITY_POLICY_BASIC_128_RSA_15_URI,
            SecurityPolicy::Basic256 => constants::SECURITY_POLICY_BASIC_256_URI,
            SecurityPolicy::EccNistP256 => constants::SECURITY_POLICY_ECC_NIST_P256_URI,
            SecurityPolicy::EccNistP384 => constants::SECURITY_POLICY_ECC_NIST_P384_URI,
            _ => call_with_policy!(self, |T| T::uri()),
        }
    }

    /// Returns true if the security policy is supported. It might be recognized but be unsupported by the implementation
    pub fn is_supported(&self) -> bool {
        match self {
            SecurityPolicy::None
            | SecurityPolicy::Basic256Sha256
            | SecurityPolicy::Aes128Sha256RsaOaep
            | SecurityPolicy::Aes256Sha256RsaPss
            | SecurityPolicy::PubSubAes128Ctr
            | SecurityPolicy::PubSubAes256Ctr => true,
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 => {
                cfg!(feature = "legacy-crypto")
            }
            SecurityPolicy::EccNistP256 | SecurityPolicy::EccNistP384 => {
                cfg!(feature = "ecc")
            }
            SecurityPolicy::Unknown => false,
        }
    }

    /// Returns an error if this policy cannot be used by this build,
    /// e.g. a legacy policy in a build without the `legacy-crypto`
    /// feature, or `Unknown`. Entry points must call this before invoking
    /// any cryptographic operation on the policy.
    pub fn ensure_supported(&self) -> Result<(), Error> {
        if self.is_supported() {
            Ok(())
        } else {
            Err(Error::new(
                StatusCode::BadSecurityPolicyRejected,
                format!("Security policy {self} is not supported by this build"),
            ))
        }
    }

    /// Returns true if the security policy has been deprecated by the OPC UA specification
    pub fn is_deprecated(&self) -> bool {
        // Since 1.04 because SHA-1 is no longer considered safe.
        // Answered directly so it works in every build; this is the single
        // source of truth for "is this policy legacy".
        matches!(
            self,
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256
        )
    }

    /// Get a string representation of this policy.
    ///
    /// `Unknown` returns `"Unknown"` rather than panicking, so this method and
    /// the `Display` impl that calls it are safe to use on any policy value —
    /// including while formatting a rejection error for an unrecognized policy
    /// (see `ensure_supported`).
    pub fn to_str(&self) -> &'static str {
        match self {
            SecurityPolicy::Unknown => "Unknown",
            SecurityPolicy::Basic128Rsa15 => constants::SECURITY_POLICY_BASIC_128_RSA_15,
            SecurityPolicy::Basic256 => constants::SECURITY_POLICY_BASIC_256,
            SecurityPolicy::EccNistP256 => constants::SECURITY_POLICY_ECC_NIST_P256,
            SecurityPolicy::EccNistP384 => constants::SECURITY_POLICY_ECC_NIST_P384,
            _ => call_with_policy!(self, |T| T::as_str()),
        }
    }

    /// Get the asymmetric encryption algorithm for this security policy.
    ///
    /// This will panic if the security policy is `Unknown` or `None`.
    pub fn asymmetric_encryption_algorithm(&self) -> Option<&'static str> {
        match self {
            SecurityPolicy::EccNistP256 | SecurityPolicy::EccNistP384 => None,
            _ => call_with_policy!(self, |T| T::asymmetric_encryption_algorithm()),
        }
    }

    /// Get the asymmetric signature algorithm for this security policy.
    ///
    /// This will panic if the security policy is `Unknown` or `None`.
    pub fn asymmetric_signature_algorithm(&self) -> &'static str {
        match self {
            SecurityPolicy::EccNistP256 => crate::algorithms::DSIG_ECDSA_SHA256,
            SecurityPolicy::EccNistP384 => crate::algorithms::DSIG_ECDSA_SHA384,
            _ => call_with_policy!(self, |T| T::asymmetric_signature_algorithm()),
        }
    }

    /// Plaintext block size in bytes.
    ///
    /// This will panic if the security policy is `Unknown` or `None`.
    pub fn plain_block_size(&self) -> usize {
        match self {
            SecurityPolicy::EccNistP256 | SecurityPolicy::EccNistP384 => 16,
            _ => call_with_policy!(self, |T| T::plain_text_block_size()),
        }
    }

    /// Signature size in bytes.
    ///
    /// This will panic if the security policy is `Unknown`.
    pub fn symmetric_signature_size(&self) -> usize {
        match self {
            SecurityPolicy::EccNistP256 => 32,
            SecurityPolicy::EccNistP384 => 48,
            _ => call_with_policy!(self, |T| T::symmetric_signature_size()),
        }
    }

    /// Asymmetric signature size in bytes for a signing/verification key.
    pub fn asymmetric_signature_size(&self, key: &PublicKey) -> usize {
        match self {
            SecurityPolicy::EccNistP256 => 64,
            SecurityPolicy::EccNistP384 => 96,
            _ => key.size(),
        }
    }

    /// Tests if the supplied key length is valid for this policy
    pub fn is_valid_keylength(&self, keylength: usize) -> bool {
        match self {
            SecurityPolicy::EccNistP256 => keylength == 256,
            SecurityPolicy::EccNistP384 => keylength == 384,
            _ => call_with_policy!(self, |T| T::is_valid_key_length(keylength)),
        }
    }

    /// Returns true when `oid` is an acceptable X.509 certificate **signature algorithm**
    /// for this security policy's Part 4 §6.1.3 Security-Policy Check. Used together with
    /// `is_valid_keylength` to validate a certificate against the negotiated policy.
    pub fn is_valid_certificate_signature_algorithm(
        &self,
        oid: &const_oid::ObjectIdentifier,
    ) -> bool {
        match self {
            SecurityPolicy::EccNistP256 => *oid == const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
            SecurityPolicy::EccNistP384 => *oid == const_oid::db::rfc5912::ECDSA_WITH_SHA_384,
            SecurityPolicy::Basic256Sha256
            | SecurityPolicy::Aes128Sha256RsaOaep
            | SecurityPolicy::Aes256Sha256RsaPss
            | SecurityPolicy::PubSubAes128Ctr
            | SecurityPolicy::PubSubAes256Ctr => {
                *oid == const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION
                    || *oid == const_oid::db::rfc5912::ID_RSASSA_PSS
            }
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 => {
                *oid == const_oid::db::rfc5912::SHA_1_WITH_RSA_ENCRYPTION
                    || *oid == const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION
                    || *oid == const_oid::db::rfc5912::ID_RSASSA_PSS
            }
            SecurityPolicy::None | SecurityPolicy::Unknown => false,
        }
    }

    /// Creates a random nonce in a bytestring with a length appropriate for the policy
    pub fn random_nonce(&self) -> ByteString {
        match self {
            SecurityPolicy::None => ByteString::null(),
            _ => random::byte_string(self.secure_channel_nonce_length()),
        }
    }

    /// Length of the secure channel nonce for this security policy.
    pub fn secure_channel_nonce_length(&self) -> usize {
        if matches!(self, SecurityPolicy::Unknown) {
            // Fallback, but this probably isn't valid and will fail shortly.
            return 32;
        }

        match self {
            SecurityPolicy::EccNistP256 => 64,
            SecurityPolicy::EccNistP384 => 96,
            _ => call_with_policy!(self, |T| T::nonce_length()),
        }
    }

    /// Get the security policy from the given URI. Returns `Unknown`
    /// if the URI does not match any known policy.
    pub fn from_uri(uri: &str) -> SecurityPolicy {
        match uri {
            constants::SECURITY_POLICY_NONE_URI => SecurityPolicy::None,
            // Always recognizable; see from_str.
            constants::SECURITY_POLICY_BASIC_128_RSA_15_URI => SecurityPolicy::Basic128Rsa15,
            constants::SECURITY_POLICY_BASIC_256_URI => SecurityPolicy::Basic256,
            constants::SECURITY_POLICY_ECC_NIST_P256_URI => SecurityPolicy::EccNistP256,
            constants::SECURITY_POLICY_ECC_NIST_P384_URI => SecurityPolicy::EccNistP384,
            crate::policy::aes::Basic256Sha256::SECURITY_POLICY_URI => {
                SecurityPolicy::Basic256Sha256
            }
            crate::policy::aes::Aes128Sha256RsaOaep::SECURITY_POLICY_URI => {
                SecurityPolicy::Aes128Sha256RsaOaep
            }
            crate::policy::aes::Aes256Sha256RsaPss::SECURITY_POLICY_URI => {
                SecurityPolicy::Aes256Sha256RsaPss
            }
            crate::policy::aes::PubSubAes128Ctr::SECURITY_POLICY_URI => {
                SecurityPolicy::PubSubAes128Ctr
            }
            crate::policy::aes::PubSubAes256Ctr::SECURITY_POLICY_URI => {
                SecurityPolicy::PubSubAes256Ctr
            }
            _ => {
                error!(
                    "Specified security policy uri \"{}\" is not recognized",
                    uri
                );
                SecurityPolicy::Unknown
            }
        }
    }

    /// Returns whether the security policy uses legacy sequence numbers.
    pub fn legacy_sequence_numbers(&self) -> bool {
        match self {
            SecurityPolicy::EccNistP256 | SecurityPolicy::EccNistP384 => false,
            _ => call_with_policy!(self, |T| T::uses_legacy_sequence_numbers()),
        }
    }

    /// Returns true for ECC NIST secure-channel policies.
    #[must_use]
    pub fn is_ecc(&self) -> bool {
        matches!(
            self,
            SecurityPolicy::EccNistP256 | SecurityPolicy::EccNistP384
        )
    }

    /// Part 6
    /// 6.7.5
    /// Deriving keys Once the SecureChannel is established the Messages are signed and encrypted with
    /// keys derived from the Nonces exchanged in the OpenSecureChannel call. These keys are derived
    /// by passing the Nonces to a pseudo-random function which produces a sequence of bytes from a
    /// set of inputs. A pseudo-random function is represented by the following function declaration:
    ///
    /// ```c++
    /// Byte[] PRF( Byte[] secret,  Byte[] seed,  i32 length,  i32 offset)
    /// ```
    ///
    /// Where length is the number of bytes to return and offset is a number of bytes from the beginning of the sequence.
    ///
    /// The lengths of the keys that need to be generated depend on the SecurityPolicy used for the channel.
    /// The following information is specified by the SecurityPolicy:
    ///
    /// a) SigningKeyLength (from the DerivedSignatureKeyLength);
    /// b) EncryptingKeyLength (implied by the SymmetricEncryptionAlgorithm);
    /// c) EncryptingBlockSize (implied by the SymmetricEncryptionAlgorithm).
    ///
    /// The parameters passed to the pseudo random function are specified in Table 33.
    ///
    /// Table 33 – Cryptography key generation parameters
    ///
    /// Key | Secret | Seed | Length | Offset
    /// ClientSigningKey | ServerNonce | ClientNonce | SigningKeyLength | 0
    /// ClientEncryptingKey | ServerNonce | ClientNonce | EncryptingKeyLength | SigningKeyLength
    /// ClientInitializationVector | ServerNonce | ClientNonce | EncryptingBlockSize | SigningKeyLength + EncryptingKeyLength
    /// ServerSigningKey | ClientNonce | ServerNonce | SigningKeyLength | 0
    /// ServerEncryptingKey | ClientNonce | ServerNonce | EncryptingKeyLength | SigningKeyLength
    /// ServerInitializationVector | ClientNonce | ServerNonce | EncryptingBlockSize | SigningKeyLength + EncryptingKeyLength
    ///
    /// The Client keys are used to secure Messages sent by the Client. The Server keys
    /// are used to secure Messages sent by the Server.
    ///
    pub fn make_secure_channel_keys(&self, secret: &[u8], seed: &[u8]) -> AesDerivedKeys {
        match self {
            SecurityPolicy::EccNistP256 | SecurityPolicy::EccNistP384 => {
                unreachable!("ECC secure channels derive keys via ECDH/HKDF, not the nonce PRF")
            }
            _ => call_with_policy!(self, |T| T::derive_secure_channel_keys(secret, seed)),
        }
    }

    /// Produce a signature of the data using an asymmetric key. Stores the signature in the supplied
    /// `signature` buffer. Returns the size of the signature within that buffer.
    pub fn asymmetric_sign(
        &self,
        signing_key: &PrivateKey,
        data: &[u8],
        signature: &mut [u8],
    ) -> Result<usize, Error> {
        match self {
            #[cfg(feature = "ecc")]
            SecurityPolicy::EccNistP256 | SecurityPolicy::EccNistP384 => {
                let signing_key = signing_key.ecc_key().ok_or_else(|| {
                    Error::new(
                        StatusCode::BadSecurityChecksFailed,
                        "ECDSA signing requires an EC private key",
                    )
                })?;
                let signed = crate::ecc::ecdsa_sign(signing_key, data)?;
                let dst = signature.get_mut(..signed.len()).ok_or_else(|| {
                    Error::new(
                        StatusCode::BadSecurityChecksFailed,
                        "ECDSA signature buffer is too small",
                    )
                })?;
                dst.copy_from_slice(&signed);
                Ok(signed.len())
            }
            #[cfg(not(feature = "ecc"))]
            SecurityPolicy::EccNistP256 | SecurityPolicy::EccNistP384 => {
                Err(ecc_not_implemented_error("ECDSA signing"))
            }
            _ => call_with_policy!(self, |T| {
                T::asymmetric_sign(signing_key, data, signature)
            }),
        }
    }

    /// Verifies a signature of the data using an asymmetric key. In a debugging scenario, the
    /// signing key can also be supplied so that the supplied signature can be compared to a freshly
    /// generated signature.
    pub fn asymmetric_verify_signature(
        &self,
        verification_key: &PublicKey,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        match self {
            #[cfg(feature = "ecc")]
            SecurityPolicy::EccNistP256 | SecurityPolicy::EccNistP384 => {
                let verification_key = verification_key.ecc_key().ok_or_else(|| {
                    Error::new(
                        StatusCode::BadSecurityChecksFailed,
                        "ECDSA verification requires an EC public key",
                    )
                })?;
                crate::ecc::ecdsa_verify(verification_key, data, signature).map_err(|err| {
                    Error::new(
                        StatusCode::BadSecurityChecksFailed,
                        format!("ECDSA signature verification failed: {err}"),
                    )
                })
            }
            #[cfg(not(feature = "ecc"))]
            SecurityPolicy::EccNistP256 | SecurityPolicy::EccNistP384 => {
                Err(ecc_not_implemented_error("ECDSA signature verification"))
            }
            _ => call_with_policy!(self, |T| {
                T::asymmetric_verify_signature(verification_key, data, signature)
            }),
        }
    }

    /// Get information about message padding for symmetric encryption using this policy.
    pub fn symmetric_padding_info(&self) -> PaddingInfo {
        match self {
            SecurityPolicy::EccNistP256 | SecurityPolicy::EccNistP384 => PaddingInfo {
                block_size: 16,
                minimum_padding: 1,
            },
            _ => call_with_policy!(self, |T| T::symmetric_padding_info()),
        }
    }

    /// Get information about message padding for asymmetric encryption using this policy,
    /// requires the public key of the receiver.
    pub fn asymmetric_padding_info(&self, remote_key: &PublicKey) -> PaddingInfo {
        match self {
            SecurityPolicy::EccNistP256 | SecurityPolicy::EccNistP384 => PaddingInfo {
                block_size: 0,
                minimum_padding: 0,
            },
            _ => call_with_policy!(self, |T| T::asymmetric_padding_info(remote_key)),
        }
    }

    /// Calculate the size of the cipher text for asymmetric encryption.
    pub fn calculate_cipher_text_size(&self, plain_text_size: usize, key: &PublicKey) -> usize {
        match self {
            SecurityPolicy::EccNistP256 | SecurityPolicy::EccNistP384 => 0,
            _ => call_with_policy!(self, |T| {
                T::calculate_cipher_text_size(plain_text_size, key)
            }),
        }
    }

    /// Encrypts a message using the supplied encryption key, returns the encrypted size. Destination
    /// buffer must be large enough to hold encrypted bytes including any padding.
    pub fn asymmetric_encrypt(
        &self,
        encryption_key: &PublicKey,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, Error> {
        match self {
            SecurityPolicy::EccNistP256 | SecurityPolicy::EccNistP384 => {
                Err(ecc_not_implemented_error("ECC asymmetric encryption"))
            }
            _ => call_with_policy!(self, |T| {
                T::asymmetric_encrypt(encryption_key, src, dst)
            }),
        }
    }

    /// Decrypts a message whose thumbprint matches the x509 cert and private key pair.
    ///
    /// Returns the number of decrypted bytes
    pub fn asymmetric_decrypt(
        &self,
        decryption_key: &PrivateKey,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, Error> {
        match self {
            SecurityPolicy::EccNistP256 | SecurityPolicy::EccNistP384 => {
                Err(ecc_not_implemented_error("ECC asymmetric decryption"))
            }
            _ => call_with_policy!(self, |T| {
                T::asymmetric_decrypt(decryption_key, src, dst)
            }),
        }
    }

    /// Produce a signature of some data using the supplied symmetric key. Signing algorithm is determined
    /// by the security policy. Signature is stored in the supplied `signature` argument.
    pub fn symmetric_sign(
        &self,
        keys: &AesDerivedKeys,
        data: &[u8],
        signature: &mut [u8],
    ) -> Result<(), Error> {
        match self {
            #[cfg(feature = "ecc")]
            SecurityPolicy::EccNistP256 | SecurityPolicy::EccNistP384 => {
                call_with_ecc_symmetric_policy!(self, |T| T::symmetric_sign(keys, data, signature))
            }
            #[cfg(not(feature = "ecc"))]
            SecurityPolicy::EccNistP256 | SecurityPolicy::EccNistP384 => {
                Err(ecc_not_implemented_error("ECC symmetric signing"))
            }
            _ => call_with_policy!(self, |T| T::symmetric_sign(keys, data, signature)),
        }
    }

    /// Verify the signature of a data block using the supplied symmetric key.
    pub fn symmetric_verify_signature(
        &self,
        keys: &AesDerivedKeys,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        match self {
            #[cfg(feature = "ecc")]
            SecurityPolicy::EccNistP256 | SecurityPolicy::EccNistP384 => {
                call_with_ecc_symmetric_policy!(self, |T| {
                    T::symmetric_verify_signature(keys, data, signature)
                })
            }
            #[cfg(not(feature = "ecc"))]
            SecurityPolicy::EccNistP256 | SecurityPolicy::EccNistP384 => Err(
                ecc_not_implemented_error("ECC symmetric signature verification"),
            ),
            _ => call_with_policy!(self, |T| {
                T::symmetric_verify_signature(keys, data, signature)
            }),
        }
    }

    /// Encrypt the supplied data using the supplied key storing the result in the destination.
    pub fn symmetric_encrypt(
        &self,
        keys: &AesDerivedKeys,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, Error> {
        match self {
            #[cfg(feature = "ecc")]
            SecurityPolicy::EccNistP256 | SecurityPolicy::EccNistP384 => {
                call_with_ecc_symmetric_policy!(self, |T| T::symmetric_encrypt(keys, src, dst))
            }
            #[cfg(not(feature = "ecc"))]
            SecurityPolicy::EccNistP256 | SecurityPolicy::EccNistP384 => {
                Err(ecc_not_implemented_error("ECC symmetric encryption"))
            }
            _ => call_with_policy!(self, |T| T::symmetric_encrypt(keys, src, dst)),
        }
    }

    /// Decrypts the supplied data using the supplied key storing the result in the destination.
    pub fn symmetric_decrypt(
        &self,
        keys: &AesDerivedKeys,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, Error> {
        match self {
            #[cfg(feature = "ecc")]
            SecurityPolicy::EccNistP256 | SecurityPolicy::EccNistP384 => {
                call_with_ecc_symmetric_policy!(self, |T| T::symmetric_decrypt(keys, src, dst))
            }
            #[cfg(not(feature = "ecc"))]
            SecurityPolicy::EccNistP256 | SecurityPolicy::EccNistP384 => {
                Err(ecc_not_implemented_error("ECC symmetric decryption"))
            }
            _ => call_with_policy!(self, |T| T::symmetric_decrypt(keys, src, dst)),
        }
    }

    /// Get the key length used for symmetric encryption.
    pub fn encrypting_key_length(&self) -> usize {
        match self {
            SecurityPolicy::EccNistP256 => 16,
            SecurityPolicy::EccNistP384 => 32,
            _ => call_with_policy!(self, |T| T::encrypting_key_length()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SecurityPolicy;
    use opcua_types::StatusCode;

    /// Issue #18: `to_str()` / `Display` must not panic on `Unknown`, and the
    /// `ensure_supported()` rejection path (which `format!`s the policy via
    /// `Display`) must return a clean `Err` rather than aborting the process.
    #[test]
    fn unknown_policy_is_rejected_not_panicked() {
        // from_uri maps an unrecognized URI to Unknown (the documented error variant).
        let policy = SecurityPolicy::from_uri("not-a-real-policy-uri");
        assert_eq!(policy, SecurityPolicy::Unknown);

        // to_str + Display must yield a fallback string, not panic.
        assert_eq!(SecurityPolicy::Unknown.to_str(), "Unknown");
        assert_eq!(format!("{}", SecurityPolicy::Unknown), "Unknown");

        // ensure_supported must return a recoverable error (it formats the policy
        // via Display while building the message — previously the abort site).
        let err = SecurityPolicy::Unknown
            .ensure_supported()
            .expect_err("Unknown policy must be rejected, not supported");
        assert_eq!(err.status(), StatusCode::BadSecurityPolicyRejected);
    }

    /// Feature 012 / US5 (SC-005): with the `ecc` feature OFF, the ECC policies
    /// must still be *recognized* (so they can be named and rejected
    /// deliberately) but report **unsupported** and fail closed, while RSA/None
    /// are unaffected.
    #[cfg(not(feature = "ecc"))]
    #[test]
    fn ecc_policies_recognized_but_unsupported_when_feature_off() {
        // Recognized — not silently downgraded to Unknown.
        assert_eq!(
            SecurityPolicy::from_uri(super::constants::SECURITY_POLICY_ECC_NIST_P256_URI),
            SecurityPolicy::EccNistP256
        );
        assert_eq!(
            SecurityPolicy::from_uri(super::constants::SECURITY_POLICY_ECC_NIST_P384_URI),
            SecurityPolicy::EccNistP384
        );

        // Unsupported in this build, and ensure_supported fails closed.
        assert!(!SecurityPolicy::EccNistP256.is_supported());
        assert!(!SecurityPolicy::EccNistP384.is_supported());
        assert_eq!(
            SecurityPolicy::EccNistP256
                .ensure_supported()
                .expect_err("ECC must be unsupported without the feature")
                .status(),
            StatusCode::BadSecurityPolicyRejected
        );

        // RSA/None remain supported.
        assert!(SecurityPolicy::None.is_supported());
        assert!(SecurityPolicy::Basic256Sha256.is_supported());
        assert!(SecurityPolicy::Aes256Sha256RsaPss.is_supported());
    }
}
