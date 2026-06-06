// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Security policy is the symmetric, asymmetric encryption / decryption + signing / verification
//! algorithms to use and enforce for the current session.
use std::fmt;
use std::str::FromStr;

use tracing::error;

use opcua_types::{constants, ByteString, Error};

use crate::{
    policy::{PaddingInfo, SecurityPolicyImpl},
    PrivateKey, PublicKey,
};

use super::random;

use crate::policy::{aes::*, AesDerivedKeys, AesPolicy, NonePolicy};

macro_rules! call_with_policy {
    (_inner $r:expr, $($p:ident: $ty:ty,)+ |$x:ident| $t:tt) => {
        match $r {
            $(
                Self::$p => {
                    type $x = $ty;
                    #[allow(unused_braces)]
                    $t
                }
            )*
            Self::Unknown => panic!("Unknown security policy"),
        }
    };

    ($r:expr, |$x:ident| $t:tt) => {
        call_with_policy!(_inner $r,
            None: NonePolicy,
            Aes128Sha256RsaOaep: AesPolicy<Aes128Sha256RsaOaep>,
            Basic256Sha256: AesPolicy<Basic256Sha256>,
            Aes256Sha256RsaPss: AesPolicy<Aes256Sha256RsaPss>,
            Basic128Rsa15: AesPolicy<Basic128Rsa15>,
            Basic256: AesPolicy<Basic256>,
            |$x| $t
        )
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
        call_with_policy!(self, |T| { T::uri() })
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
        call_with_policy!(self, |T| { T::is_deprecated() })
    }

    /// Get a string representation of this policy.
    ///
    /// This will panic if the security policy is `Unknown`.
    pub fn to_str(&self) -> &'static str {
        call_with_policy!(self, |T| { T::as_str() })
    }

    /// Get the asymmetric encryption algorithm for this security policy.
    ///
    /// This will panic if the security policy is `Unknown` or `None`.
    pub fn asymmetric_encryption_algorithm(&self) -> Option<&'static str> {
        call_with_policy!(self, |T| { T::asymmetric_encryption_algorithm() })
    }

    /// Get the asymmetric signature algorithm for this security policy.
    ///
    /// This will panic if the security policy is `Unknown` or `None`.
    pub fn asymmetric_signature_algorithm(&self) -> &'static str {
        call_with_policy!(self, |T| { T::asymmetric_signature_algorithm() })
    }

    /// Plaintext block size in bytes.
    ///
    /// This will panic if the security policy is `Unknown` or `None`.
    pub fn plain_block_size(&self) -> usize {
        call_with_policy!(self, |T| { T::plain_text_block_size() })
    }

    /// Signature size in bytes.
    ///
    /// This will panic if the security policy is `Unknown`.
    pub fn symmetric_signature_size(&self) -> usize {
        call_with_policy!(self, |T| { T::symmetric_signature_size() })
    }

    /// Tests if the supplied key length is valid for this policy
    pub fn is_valid_keylength(&self, keylength: usize) -> bool {
        call_with_policy!(self, |T| { T::is_valid_key_length(keylength) })
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

        call_with_policy!(self, |T| { T::nonce_length() })
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
        call_with_policy!(self, |T| { T::uses_legacy_sequence_numbers() })
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
        call_with_policy!(self, |T| { T::derive_secure_channel_keys(secret, seed) })
    }

    /// Produce a signature of the data using an asymmetric key. Stores the signature in the supplied
    /// `signature` buffer. Returns the size of the signature within that buffer.
    pub fn asymmetric_sign(
        &self,
        signing_key: &PrivateKey,
        data: &[u8],
        signature: &mut [u8],
    ) -> Result<usize, Error> {
        call_with_policy!(self, |T| {
            T::asymmetric_sign(signing_key, data, signature)
        })
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
        call_with_policy!(self, |T| {
            T::asymmetric_verify_signature(verification_key, data, signature)
        })
    }

    /// Get information about message padding for symmetric encryption using this policy.
    pub fn symmetric_padding_info(&self) -> PaddingInfo {
        call_with_policy!(self, |T| { T::symmetric_padding_info() })
    }

    /// Get information about message padding for asymmetric encryption using this policy,
    /// requires the public key of the receiver.
    pub fn asymmetric_padding_info(&self, remote_key: &PublicKey) -> PaddingInfo {
        call_with_policy!(self, |T| { T::asymmetric_padding_info(remote_key) })
    }

    /// Calculate the size of the cipher text for asymmetric encryption.
    pub fn calculate_cipher_text_size(&self, plain_text_size: usize, key: &PublicKey) -> usize {
        call_with_policy!(self, |T| {
            T::calculate_cipher_text_size(plain_text_size, key)
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
        call_with_policy!(self, |T| {
            T::asymmetric_encrypt(encryption_key, src, dst)
        })
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
        call_with_policy!(self, |T| {
            T::asymmetric_decrypt(decryption_key, src, dst)
        })
    }

    /// Produce a signature of some data using the supplied symmetric key. Signing algorithm is determined
    /// by the security policy. Signature is stored in the supplied `signature` argument.
    pub fn symmetric_sign(
        &self,
        keys: &AesDerivedKeys,
        data: &[u8],
        signature: &mut [u8],
    ) -> Result<(), Error> {
        call_with_policy!(self, |T| { T::symmetric_sign(keys, data, signature) })
    }

    /// Verify the signature of a data block using the supplied symmetric key.
    pub fn symmetric_verify_signature(
        &self,
        keys: &AesDerivedKeys,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        call_with_policy!(self, |T| {
            T::symmetric_verify_signature(keys, data, signature)
        })
    }

    /// Encrypt the supplied data using the supplied key storing the result in the destination.
    pub fn symmetric_encrypt(
        &self,
        keys: &AesDerivedKeys,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, Error> {
        call_with_policy!(self, |T| { T::symmetric_encrypt(keys, src, dst) })
    }

    /// Decrypts the supplied data using the supplied key storing the result in the destination.
    pub fn symmetric_decrypt(
        &self,
        keys: &AesDerivedKeys,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, Error> {
        call_with_policy!(self, |T| { T::symmetric_decrypt(keys, src, dst) })
    }

    /// Get the key length used for symmetric encryption.
    pub fn encrypting_key_length(&self) -> usize {
        call_with_policy!(self, |T| { T::encrypting_key_length() })
    }
}
