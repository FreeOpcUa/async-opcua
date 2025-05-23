// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Security policy is the symmetric, asymmetric encryption / decryption + signing / verification
//! algorithms to use and enforce for the current session.
use std::fmt;
use std::str::FromStr;

use tracing::error;

use opcua_types::{constants, status_code::StatusCode, ByteString, Error};

use super::{
    aeskey::AesKey,
    hash,
    pkey::{PrivateKey, PublicKey, RsaPadding},
    random, SHA1_SIZE, SHA256_SIZE,
};

/// Trait for a security policy supported by the library.
pub trait SecurityPolicyConstants {
    /// The name of the policy.
    const SECURITY_POLICY: &'static str;
    /// The URI of the policy, as defined in the OPC-UA standard.
    const SECURITY_POLICY_URI: &'static str;

    /// The algorithm used for symmetric signing.
    const SYMMETRIC_SIGNATURE_ALGORITHM: &'static str;
    /// The algorithm used for asymmetric signing.
    const ASYMMETRIC_SIGNATURE_ALGORITHM: &'static str;
    /// The algorithm used for asymmetric encryption.
    const ASYMMETRIC_ENCRYPTION_ALGORITHM: &'static str;
    /// The length of the derived signature key in bits.
    const DERIVED_SIGNATURE_KEY_LENGTH: usize;
    /// The length of the asymmetric key in bits.
    const ASYMMETRIC_KEY_LENGTH: (usize, usize);
}

// These are constants that govern the different encryption / signing modes for OPC UA. In some
// cases these algorithm string constants will be passed over the wire and code needs to test the
// string to see if the algorithm is supported.

/// Aes128-Sha256-RsaOaep security policy
///
///   AsymmetricEncryptionAlgorithm_RSA-PKCS15-SHA2-256
///   AsymmetricSignatureAlgorithm_RSA-OAEP-SHA1
///   CertificateSignatureAlgorithm_RSA-PKCS15-SHA2-256
///   KeyDerivationAlgorithm_P-SHA2-256
///   SymmetricEncryptionAlgorithm_AES128-CBC
///   SymmetricSignatureAlgorithm_HMAC-SHA2-256
///
/// # Limits
///
///   DerivedSignatureKeyLength – 256 bits
///   AsymmetricKeyLength - 2048-4096 bits
///   SecureChannelNonceLength - 32 bytes
pub struct Aes128Sha256RsaOaep;
impl SecurityPolicyConstants for Aes128Sha256RsaOaep {
    const SECURITY_POLICY: &str = "Aes128-Sha256-RsaOaep";
    const SECURITY_POLICY_URI: &str =
        "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep";

    const SYMMETRIC_SIGNATURE_ALGORITHM: &str = crate::algorithms::DSIG_HMAC_SHA256;
    const ASYMMETRIC_SIGNATURE_ALGORITHM: &str = crate::algorithms::DSIG_RSA_SHA256;
    const ASYMMETRIC_ENCRYPTION_ALGORITHM: &str = crate::algorithms::ENC_RSA_OAEP;
    const DERIVED_SIGNATURE_KEY_LENGTH: usize = 256;
    const ASYMMETRIC_KEY_LENGTH: (usize, usize) = (2048, 4096);
}

/// Aes256-Sha256-RsaPss security policy
///
///   AsymmetricEncryptionAlgorithm_RSA-OAEP-SHA2-256
///   AsymmetricSignatureAlgorithm_RSA-PSS -SHA2-256
///   CertificateSignatureAlgorithm_ RSA-PKCS15-SHA2-256
///   KeyDerivationAlgorithm_P-SHA2-256
///   SymmetricEncryptionAlgorithm_AES256-CBC
///   SymmetricSignatureAlgorithm_HMAC-SHA2-256
///
/// # Limits
///
///   DerivedSignatureKeyLength – 256 bits
///   AsymmetricKeyLength - 2048-4096 bits
///   SecureChannelNonceLength - 32 bytes
pub struct Aes256Sha256RsaPss;
impl SecurityPolicyConstants for Aes256Sha256RsaPss {
    const SECURITY_POLICY: &str = "Aes256-Sha256-RsaPss";
    const SECURITY_POLICY_URI: &str =
        "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss";

    const SYMMETRIC_SIGNATURE_ALGORITHM: &str = crate::algorithms::DSIG_HMAC_SHA256;
    const ASYMMETRIC_SIGNATURE_ALGORITHM: &str = crate::algorithms::DSIG_RSA_PSS_SHA2_256;
    const ASYMMETRIC_ENCRYPTION_ALGORITHM: &str = crate::algorithms::ENC_RSA_OAEP_SHA256;
    const DERIVED_SIGNATURE_KEY_LENGTH: usize = 256;
    const ASYMMETRIC_KEY_LENGTH: (usize, usize) = (2048, 4096);
}

/// Basic256Sha256 security policy
///
///   AsymmetricEncryptionAlgorithm_RSA-OAEP-SHA1
///   AsymmetricSignatureAlgorithm_RSA-PKCS15-SHA2-256
///   CertificateSignatureAlgorithm_RSA-PKCS15-SHA2-256
///   KeyDerivationAlgorithm_P-SHA2-256
///   SymmetricEncryptionAlgorithm_AES256-CBC
///   SymmetricSignatureAlgorithm_HMAC-SHA2-256
///
/// # Limits
///
///   DerivedSignatureKeyLength – 256 bits
///   AsymmetricKeyLength - 2048-4096 bits
///   SecureChannelNonceLength - 32 bytes
pub struct Basic256Sha256;
impl SecurityPolicyConstants for Basic256Sha256 {
    const SECURITY_POLICY: &str = "Basic256Sha256";
    const SECURITY_POLICY_URI: &str = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256";

    const SYMMETRIC_SIGNATURE_ALGORITHM: &str = crate::algorithms::DSIG_HMAC_SHA256;
    const ASYMMETRIC_SIGNATURE_ALGORITHM: &str = crate::algorithms::DSIG_RSA_SHA256;
    const ASYMMETRIC_ENCRYPTION_ALGORITHM: &str = crate::algorithms::ENC_RSA_OAEP;
    const DERIVED_SIGNATURE_KEY_LENGTH: usize = 256;
    const ASYMMETRIC_KEY_LENGTH: (usize, usize) = (2048, 4096);
}

/// Basic128Rsa15 security policy (deprecated in OPC UA 1.04)
///
/// * AsymmetricSignatureAlgorithm – [RsaSha1](http://www.w3.org/2000/09/xmldsig#rsa-sha1).
/// * AsymmetricEncryptionAlgorithm – [Rsa15](http://www.w3.org/2001/04/xmlenc#rsa-1_5).
/// * SymmetricSignatureAlgorithm – [HmacSha1](http://www.w3.org/2000/09/xmldsig#hmac-sha1).
/// * SymmetricEncryptionAlgorithm – [Aes128](http://www.w3.org/2001/04/xmlenc#aes128-cbc).
/// * KeyDerivationAlgorithm – [PSha1](http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha1).
///
/// # Limits
///
///   DerivedSignatureKeyLength – 128 bits
///   AsymmetricKeyLength - 1024-2048 bits
///   SecureChannelNonceLength - 16 bytes
pub struct Basic128Rsa15;
impl SecurityPolicyConstants for Basic128Rsa15 {
    const SECURITY_POLICY: &str = "Basic128Rsa15";
    const SECURITY_POLICY_URI: &str = "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15";

    const SYMMETRIC_SIGNATURE_ALGORITHM: &str = crate::algorithms::DSIG_HMAC_SHA1;
    const ASYMMETRIC_SIGNATURE_ALGORITHM: &str = crate::algorithms::DSIG_RSA_SHA1;
    const ASYMMETRIC_ENCRYPTION_ALGORITHM: &str = crate::algorithms::ENC_RSA_15;
    const DERIVED_SIGNATURE_KEY_LENGTH: usize = 128;
    const ASYMMETRIC_KEY_LENGTH: (usize, usize) = (1024, 2048);
}

/// Basic256 security policy (deprecated in OPC UA 1.04)
///
/// * AsymmetricSignatureAlgorithm – [RsaSha1](http://www.w3.org/2000/09/xmldsig#rsa-sha1).
/// * AsymmetricEncryptionAlgorithm – [RsaOaep](http://www.w3.org/2001/04/xmlenc#rsa-oaep).
/// * SymmetricSignatureAlgorithm – [HmacSha1](http://www.w3.org/2000/09/xmldsig#hmac-sha1).
/// * SymmetricEncryptionAlgorithm – [Aes256](http://www.w3.org/2001/04/xmlenc#aes256-cbc).
/// * KeyDerivationAlgorithm – [PSha1](http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha1).
///
/// # Limits
///
///   DerivedSignatureKeyLength – 192 bits
///   AsymmetricKeyLength - 1024-2048 bits
///   SecureChannelNonceLength - 32 bytes
pub struct Basic256;
impl SecurityPolicyConstants for Basic256 {
    const SECURITY_POLICY: &str = "Basic256";
    const SECURITY_POLICY_URI: &str = "http://opcfoundation.org/UA/SecurityPolicy#Basic256";

    const SYMMETRIC_SIGNATURE_ALGORITHM: &str = crate::algorithms::DSIG_HMAC_SHA1;
    const ASYMMETRIC_SIGNATURE_ALGORITHM: &str = crate::algorithms::DSIG_RSA_SHA1;
    const ASYMMETRIC_ENCRYPTION_ALGORITHM: &str = crate::algorithms::ENC_RSA_OAEP;
    const DERIVED_SIGNATURE_KEY_LENGTH: usize = 192;
    const ASYMMETRIC_KEY_LENGTH: (usize, usize) = (1024, 2048);
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
    /// Basic128. Note that this security policy is deprecated.
    Basic128Rsa15,
    /// Basic256.
    Basic256,
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
            Basic128Rsa15::SECURITY_POLICY | Basic128Rsa15::SECURITY_POLICY_URI => {
                SecurityPolicy::Basic128Rsa15
            }
            Basic256::SECURITY_POLICY | Basic256::SECURITY_POLICY_URI => SecurityPolicy::Basic256,
            Basic256Sha256::SECURITY_POLICY | Basic256Sha256::SECURITY_POLICY_URI => {
                SecurityPolicy::Basic256Sha256
            }
            Aes128Sha256RsaOaep::SECURITY_POLICY | Aes128Sha256RsaOaep::SECURITY_POLICY_URI => {
                SecurityPolicy::Aes128Sha256RsaOaep
            }
            Aes256Sha256RsaPss::SECURITY_POLICY | Aes256Sha256RsaPss::SECURITY_POLICY_URI => {
                SecurityPolicy::Aes256Sha256RsaPss
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
            SecurityPolicy::None => constants::SECURITY_POLICY_NONE_URI,
            SecurityPolicy::Basic128Rsa15 => Basic128Rsa15::SECURITY_POLICY_URI,
            SecurityPolicy::Basic256 => Basic256::SECURITY_POLICY_URI,
            SecurityPolicy::Basic256Sha256 => Basic256Sha256::SECURITY_POLICY_URI,
            SecurityPolicy::Aes128Sha256RsaOaep => Aes128Sha256RsaOaep::SECURITY_POLICY_URI,
            SecurityPolicy::Aes256Sha256RsaPss => Aes256Sha256RsaPss::SECURITY_POLICY_URI,
            _ => {
                panic!("Shouldn't be turning an unknown policy into a uri");
            }
        }
    }

    /// Returns true if the security policy is supported. It might be recognized but be unsupported by the implementation
    pub fn is_supported(&self) -> bool {
        matches!(
            self,
            SecurityPolicy::None
                | SecurityPolicy::Basic128Rsa15
                | SecurityPolicy::Basic256
                | SecurityPolicy::Basic256Sha256
                | SecurityPolicy::Aes128Sha256RsaOaep
                | SecurityPolicy::Aes256Sha256RsaPss
        )
    }

    /// Returns true if the security policy has been deprecated by the OPC UA specification
    pub fn is_deprecated(&self) -> bool {
        // Since 1.04 because SHA-1 is no longer considered safe
        matches!(
            self,
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256
        )
    }

    /// Get a string representation of this policy.
    ///
    /// This will panic if the security policy is `Unknown`.
    pub fn to_str(&self) -> &'static str {
        match self {
            SecurityPolicy::None => constants::SECURITY_POLICY_NONE,
            SecurityPolicy::Basic128Rsa15 => Basic128Rsa15::SECURITY_POLICY,
            SecurityPolicy::Basic256 => Basic256::SECURITY_POLICY,
            SecurityPolicy::Basic256Sha256 => Basic256Sha256::SECURITY_POLICY,
            SecurityPolicy::Aes128Sha256RsaOaep => Aes128Sha256RsaOaep::SECURITY_POLICY,
            SecurityPolicy::Aes256Sha256RsaPss => Aes256Sha256RsaPss::SECURITY_POLICY,
            _ => {
                panic!("Shouldn't be turning an unknown policy into a string");
            }
        }
    }

    /// Get the asymmetric encryption algorithm for this security policy.
    ///
    /// This will panic if the security policy is `Unknown` or `None`.
    pub fn asymmetric_encryption_algorithm(&self) -> Option<&'static str> {
        Some(match self {
            SecurityPolicy::Basic128Rsa15 => Basic128Rsa15::ASYMMETRIC_ENCRYPTION_ALGORITHM,
            SecurityPolicy::Basic256 => Basic256::ASYMMETRIC_ENCRYPTION_ALGORITHM,
            SecurityPolicy::Basic256Sha256 => Basic256Sha256::ASYMMETRIC_ENCRYPTION_ALGORITHM,
            SecurityPolicy::Aes128Sha256RsaOaep => {
                Aes128Sha256RsaOaep::ASYMMETRIC_ENCRYPTION_ALGORITHM
            }
            SecurityPolicy::Aes256Sha256RsaPss => {
                Aes256Sha256RsaPss::ASYMMETRIC_ENCRYPTION_ALGORITHM
            }
            _ => {
                return None;
            }
        })
    }

    /// Get the asymmetric signature algorithm for this security policy.
    ///
    /// This will panic if the security policy is `Unknown` or `None`.
    pub fn asymmetric_signature_algorithm(&self) -> &'static str {
        match self {
            SecurityPolicy::Basic128Rsa15 => Basic128Rsa15::ASYMMETRIC_SIGNATURE_ALGORITHM,
            SecurityPolicy::Basic256 => Basic256::ASYMMETRIC_SIGNATURE_ALGORITHM,
            SecurityPolicy::Basic256Sha256 => Basic256Sha256::ASYMMETRIC_SIGNATURE_ALGORITHM,
            SecurityPolicy::Aes128Sha256RsaOaep => {
                Aes128Sha256RsaOaep::ASYMMETRIC_SIGNATURE_ALGORITHM
            }
            SecurityPolicy::Aes256Sha256RsaPss => {
                Aes256Sha256RsaPss::ASYMMETRIC_SIGNATURE_ALGORITHM
            }
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    /// Get the symmetric signature algorithm for this security policy.
    ///
    /// This will panic if the security policy is `Unknown` or `None`.
    pub fn symmetric_signature_algorithm(&self) -> &'static str {
        match self {
            SecurityPolicy::Basic128Rsa15 => Basic128Rsa15::SYMMETRIC_SIGNATURE_ALGORITHM,
            SecurityPolicy::Basic256 => Basic256::SYMMETRIC_SIGNATURE_ALGORITHM,
            SecurityPolicy::Basic256Sha256 => Basic256Sha256::SYMMETRIC_SIGNATURE_ALGORITHM,
            SecurityPolicy::Aes128Sha256RsaOaep => {
                Aes128Sha256RsaOaep::SYMMETRIC_SIGNATURE_ALGORITHM
            }
            SecurityPolicy::Aes256Sha256RsaPss => Aes256Sha256RsaPss::SYMMETRIC_SIGNATURE_ALGORITHM,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    /// Plaintext block size in bytes.
    ///
    /// This will panic if the security policy is `Unknown` or `None`.
    pub fn plain_block_size(&self) -> usize {
        match self {
            SecurityPolicy::Basic128Rsa15
            | SecurityPolicy::Basic256
            | SecurityPolicy::Basic256Sha256
            | SecurityPolicy::Aes128Sha256RsaOaep
            | SecurityPolicy::Aes256Sha256RsaPss => 16,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    /// Signature size in bytes.
    ///
    /// This will panic if the security policy is `Unknown`.
    pub fn symmetric_signature_size(&self) -> usize {
        match self {
            SecurityPolicy::None => 0,
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 => SHA1_SIZE,
            SecurityPolicy::Basic256Sha256
            | SecurityPolicy::Aes128Sha256RsaOaep
            | SecurityPolicy::Aes256Sha256RsaPss => SHA256_SIZE,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    /// Returns the derived signature key (not the signature) size in bytes.
    ///
    /// This will panic if the security policy is `Unknown` or `None`.
    pub fn derived_signature_key_size(&self) -> usize {
        let length = match self {
            SecurityPolicy::Basic128Rsa15 => Basic128Rsa15::DERIVED_SIGNATURE_KEY_LENGTH,
            SecurityPolicy::Basic256 => Basic256::DERIVED_SIGNATURE_KEY_LENGTH,
            SecurityPolicy::Basic256Sha256 => Basic256Sha256::DERIVED_SIGNATURE_KEY_LENGTH,
            SecurityPolicy::Aes128Sha256RsaOaep => {
                Aes128Sha256RsaOaep::DERIVED_SIGNATURE_KEY_LENGTH
            }
            SecurityPolicy::Aes256Sha256RsaPss => Aes256Sha256RsaPss::DERIVED_SIGNATURE_KEY_LENGTH,
            _ => {
                panic!("Invalid policy");
            }
        };
        length / 8
    }

    /// Returns the min and max (inclusive) key length in bits
    pub fn min_max_asymmetric_keylength(&self) -> (usize, usize) {
        match self {
            SecurityPolicy::Basic128Rsa15 => Basic128Rsa15::ASYMMETRIC_KEY_LENGTH,
            SecurityPolicy::Basic256 => Basic256::ASYMMETRIC_KEY_LENGTH,
            SecurityPolicy::Basic256Sha256 => Basic256Sha256::ASYMMETRIC_KEY_LENGTH,
            SecurityPolicy::Aes128Sha256RsaOaep => Aes128Sha256RsaOaep::ASYMMETRIC_KEY_LENGTH,
            SecurityPolicy::Aes256Sha256RsaPss => Aes256Sha256RsaPss::ASYMMETRIC_KEY_LENGTH,
            _ => {
                panic!("Invalid policy");
            }
        }
    }

    /// Tests if the supplied key length is valid for this policy
    pub fn is_valid_keylength(&self, keylength: usize) -> bool {
        let min_max = self.min_max_asymmetric_keylength();
        keylength >= min_max.0 && keylength <= min_max.1
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
        match self {
            SecurityPolicy::Basic128Rsa15 => 16,
            SecurityPolicy::Basic256
            | SecurityPolicy::Basic256Sha256
            | SecurityPolicy::Aes128Sha256RsaOaep
            | SecurityPolicy::Aes256Sha256RsaPss => 32,
            // The nonce can be used for password or X509 authentication
            // even when the security policy is None.
            // see https://github.com/advisories/GHSA-pq4w-qm9g-qx68
            SecurityPolicy::None | SecurityPolicy::Unknown => 32,
        }
    }

    /// Get the security policy from the given URI. Returns `Unknown`
    /// if the URI does not match any known policy.
    pub fn from_uri(uri: &str) -> SecurityPolicy {
        match uri {
            constants::SECURITY_POLICY_NONE_URI => SecurityPolicy::None,
            Basic128Rsa15::SECURITY_POLICY_URI => SecurityPolicy::Basic128Rsa15,
            Basic256::SECURITY_POLICY_URI => SecurityPolicy::Basic256,
            Basic256Sha256::SECURITY_POLICY_URI => SecurityPolicy::Basic256Sha256,
            Aes128Sha256RsaOaep::SECURITY_POLICY_URI => SecurityPolicy::Aes128Sha256RsaOaep,
            Aes256Sha256RsaPss::SECURITY_POLICY_URI => SecurityPolicy::Aes256Sha256RsaPss,
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
        // All the ones we currently support do...
        true
    }

    /// Pseudo random function is used as a key derivation algorithm. It creates pseudo random bytes
    /// from a secret and seed specified by the parameters.
    fn prf(&self, secret: &[u8], seed: &[u8], length: usize, offset: usize) -> Vec<u8> {
        // P_SHA1 or P_SHA256
        let result = match self {
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 => {
                hash::p_sha1(secret, seed, offset + length)
            }
            SecurityPolicy::Basic256Sha256
            | SecurityPolicy::Aes128Sha256RsaOaep
            | SecurityPolicy::Aes256Sha256RsaPss => hash::p_sha256(secret, seed, offset + length),
            _ => {
                panic!("Invalid policy");
            }
        };
        result[offset..(offset + length)].to_vec()
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
    pub fn make_secure_channel_keys(
        &self,
        secret: &[u8],
        seed: &[u8],
    ) -> (Vec<u8>, AesKey, Vec<u8>) {
        // Work out the length of stuff
        let signing_key_length = self.derived_signature_key_size();
        let (encrypting_key_length, encrypting_block_size) = match self {
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Aes128Sha256RsaOaep => (16, 16),
            SecurityPolicy::Basic256
            | SecurityPolicy::Basic256Sha256
            | SecurityPolicy::Aes256Sha256RsaPss => (32, 16),
            _ => {
                panic!("Invalid policy");
            }
        };

        let signing_key = self.prf(secret, seed, signing_key_length, 0);
        let encrypting_key = self.prf(secret, seed, encrypting_key_length, signing_key_length);
        let encrypting_key = AesKey::new(*self, &encrypting_key);
        let iv = self.prf(
            secret,
            seed,
            encrypting_block_size,
            signing_key_length + encrypting_key_length,
        );

        (signing_key, encrypting_key, iv)
    }

    /// Produce a signature of the data using an asymmetric key. Stores the signature in the supplied
    /// `signature` buffer. Returns the size of the signature within that buffer.
    pub fn asymmetric_sign(
        &self,
        signing_key: &PrivateKey,
        data: &[u8],
        signature: &mut [u8],
    ) -> Result<usize, Error> {
        let result = match self {
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 => {
                signing_key.sign_sha1(data, signature)?
            }
            SecurityPolicy::Basic256Sha256 | SecurityPolicy::Aes128Sha256RsaOaep => {
                signing_key.sign_sha256(data, signature)?
            }
            SecurityPolicy::Aes256Sha256RsaPss => signing_key.sign_sha256_pss(data, signature)?,
            _ => {
                panic!("Invalid policy");
            }
        };
        Ok(result)
    }

    /// Verifies a signature of the data using an asymmetric key. In a debugging scenario, the
    /// signing key can also be supplied so that the supplied signature can be compared to a freshly
    /// generated signature.
    pub fn asymmetric_verify_signature(
        &self,
        verification_key: &PublicKey,
        data: &[u8],
        signature: &[u8],
        #[allow(unused)] their_private_key: Option<PrivateKey>,
    ) -> Result<(), Error> {
        // Asymmetric verify signature against supplied certificate
        let result = match self {
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 => {
                verification_key.verify_sha1(data, signature)?
            }
            SecurityPolicy::Basic256Sha256 | SecurityPolicy::Aes128Sha256RsaOaep => {
                verification_key.verify_sha256(data, signature)?
            }
            SecurityPolicy::Aes256Sha256RsaPss => {
                verification_key.verify_sha256_pss(data, signature)?
            }
            _ => {
                panic!("Invalid policy");
            }
        };
        if result {
            Ok(())
        } else {
            // For debugging / unit testing purposes we might have a their_key to see the source of the error
            #[cfg(debug_assertions)]
            if let Some(their_key) = their_private_key {
                use crate::pkey::KeySize;
                use tracing::trace;
                // Calculate the signature using their key, see what we were expecting versus theirs
                let mut their_signature = vec![0u8; their_key.size()];
                self.asymmetric_sign(&their_key, data, their_signature.as_mut_slice())?;
                trace!(
                    "Using their_key, signature should be {:?}",
                    &their_signature
                );
            }
            Err(Error::new(
                StatusCode::BadSecurityChecksFailed,
                "Signature mismatch",
            ))
        }
    }

    /// Returns the padding algorithm used for this security policy for asymettric encryption
    /// and decryption.
    pub fn asymmetric_encryption_padding(&self) -> Option<RsaPadding> {
        Some(match self {
            SecurityPolicy::Basic128Rsa15 => RsaPadding::Pkcs1,
            SecurityPolicy::Basic256
            | SecurityPolicy::Basic256Sha256
            | SecurityPolicy::Aes128Sha256RsaOaep => RsaPadding::OaepSha1,
            // PSS uses OAEP-SHA256 for encryption, but PSS for signing
            SecurityPolicy::Aes256Sha256RsaPss => RsaPadding::OaepSha256,
            _ => {
                return None;
            }
        })
    }

    /// Encrypts a message using the supplied encryption key, returns the encrypted size. Destination
    /// buffer must be large enough to hold encrypted bytes including any padding.
    pub fn asymmetric_encrypt(
        &self,
        encryption_key: &PublicKey,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, Error> {
        let padding = self.asymmetric_encryption_padding().ok_or_else(|| {
            Error::new(
                StatusCode::BadSecurityPolicyRejected,
                "Security policy does not support asymmetric encryption",
            )
        })?;
        encryption_key
            .public_encrypt(src, dst, padding)
            .map_err(|e| Error::new(StatusCode::BadUnexpectedError, e))
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
        let padding = self.asymmetric_encryption_padding().ok_or_else(|| {
            Error::new(
                StatusCode::BadSecurityPolicyRejected,
                "Security policy does not support asymmetric encryption",
            )
        })?;
        decryption_key
            .private_decrypt(src, dst, padding)
            .map_err(|e| Error::new(StatusCode::BadSecurityChecksFailed, e))
    }

    /// Produce a signature of some data using the supplied symmetric key. Signing algorithm is determined
    /// by the security policy. Signature is stored in the supplied `signature` argument.
    pub fn symmetric_sign(
        &self,
        key: &[u8],
        data: &[u8],
        signature: &mut [u8],
    ) -> Result<(), StatusCode> {
        match self {
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 => {
                hash::hmac_sha1(key, data, signature)
            }
            SecurityPolicy::Basic256Sha256
            | SecurityPolicy::Aes128Sha256RsaOaep
            | SecurityPolicy::Aes256Sha256RsaPss => hash::hmac_sha256(key, data, signature),
            _ => {
                panic!("Unsupported policy")
            }
        }
    }

    /// Verify the signature of a data block using the supplied symmetric key.
    pub fn symmetric_verify_signature(
        &self,
        key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, Error> {
        // Verify the signature using SHA-1 / SHA-256 HMAC
        let verified = match self {
            SecurityPolicy::Basic128Rsa15 | SecurityPolicy::Basic256 => {
                hash::verify_hmac_sha1(key, data, signature)
            }
            SecurityPolicy::Basic256Sha256
            | SecurityPolicy::Aes128Sha256RsaOaep
            | SecurityPolicy::Aes256Sha256RsaPss => hash::verify_hmac_sha256(key, data, signature),
            _ => {
                panic!("Unsupported policy")
            }
        };
        if verified {
            Ok(verified)
        } else {
            error!("Signature invalid {:?}", signature);
            Err(Error::new(
                StatusCode::BadSecurityChecksFailed,
                format!("Signature invalid: {signature:?}"),
            ))
        }
    }

    /// Encrypt the supplied data using the supplied key storing the result in the destination.
    pub fn symmetric_encrypt(
        &self,
        key: &AesKey,
        iv: &[u8],
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, Error> {
        key.encrypt(src, iv, dst)
    }

    /// Decrypts the supplied data using the supplied key storing the result in the destination.
    pub fn symmetric_decrypt(
        &self,
        key: &AesKey,
        iv: &[u8],
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, Error> {
        key.decrypt(src, iv, dst)
    }
}
