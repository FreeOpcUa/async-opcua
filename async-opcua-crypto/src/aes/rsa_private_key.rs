// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Asymmetric encryption / decryption, signing / verification wrapper.
use std::{
    self,
    fmt::{self, Debug, Formatter},
    result::Result,
};

use rsa::pkcs1;
use rsa::pkcs1v15;
use rsa::pkcs8;
use rsa::pss;
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};

use x509_cert::spki::SubjectPublicKeyInfoOwned;

use opcua_types::{status_code::StatusCode, Error};

use crate::policy::rsa::RsaAsymmetricEncryptionAlgorithm;

#[derive(Debug)]
/// Error from working with a private key.
pub struct PKeyError;

impl fmt::Display for PKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PKeyError")
    }
}

impl std::error::Error for PKeyError {}

impl From<pkcs8::Error> for PKeyError {
    fn from(_err: pkcs8::Error) -> Self {
        PKeyError
    }
}

impl From<pkcs1::Error> for PKeyError {
    fn from(_err: pkcs1::Error) -> Self {
        PKeyError
    }
}

impl From<rsa::Error> for PKeyError {
    fn from(_err: rsa::Error) -> Self {
        PKeyError
    }
}

/// This is a wrapper around an asymmetric key pair. Since the PKey is either
/// a public or private key so we have to differentiate that as well.
#[derive(Clone)]
pub struct PKey<T> {
    pub(crate) value: T,
}

/// A public key
pub type PublicKey = PKey<RsaPublicKey>;
/// A private key
pub type PrivateKey = PKey<RsaPrivateKey>;

impl<T> Debug for PKey<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // This impl will not write out the key, but it exists to keep structs happy
        // that contain a key as a field
        write!(f, "[pkey]")
    }
}

/// Trait for computing the key size of a private key.
pub trait KeySize {
    /// Length in bits.
    fn bit_length(&self) -> usize {
        self.size() * 8
    }

    /// Length in bytes.
    fn size(&self) -> usize;

    /// Get the cipher text block size.
    fn cipher_text_block_size(&self) -> usize {
        self.size()
    }
}

/// Get the cipher block size with given data size and padding.
pub(crate) fn calculate_cipher_text_size<T: RsaAsymmetricEncryptionAlgorithm>(
    key_size: usize,
    data_size: usize,
) -> usize {
    let plain_text_block_size = T::get_plaintext_block_size(key_size);
    let block_count = if data_size.is_multiple_of(plain_text_block_size) {
        data_size / plain_text_block_size
    } else {
        (data_size / plain_text_block_size) + 1
    };

    block_count * key_size
}

impl KeySize for PrivateKey {
    /// Length in bits
    fn size(&self) -> usize {
        use rsa::traits::PublicKeyParts;
        self.value.size()
    }
}

impl PrivateKey {
    /// Generate a new private key with the given length in bits.
    pub fn new(bit_length: u32) -> Result<PrivateKey, rsa::Error> {
        let mut rng = rand::rng();

        let key = RsaPrivateKey::new(&mut rng, bit_length as usize)?;
        Ok(PKey { value: key })
    }

    /// Read a private key from the given path.
    pub fn read_pem_file(path: &std::path::Path) -> Result<PrivateKey, PKeyError> {
        use pkcs8::DecodePrivateKey;
        use rsa::pkcs1::DecodeRsaPrivateKey;

        let r = RsaPrivateKey::read_pkcs8_pem_file(path);
        match r {
            Err(_) => {
                let val = RsaPrivateKey::read_pkcs1_pem_file(path)?;
                Ok(PKey { value: val })
            }
            Ok(val) => Ok(PKey { value: val }),
        }
    }

    /// Create a private key from a pem file loaded into a byte array.
    pub fn from_pem(bytes: &[u8]) -> Result<PrivateKey, PKeyError> {
        use pkcs8::DecodePrivateKey;
        use rsa::pkcs1::DecodeRsaPrivateKey;

        let converted = std::str::from_utf8(bytes);
        match converted {
            Err(_) => Err(PKeyError),
            Ok(pem) => {
                let r = RsaPrivateKey::from_pkcs8_pem(pem);
                match r {
                    Err(_) => {
                        let val = RsaPrivateKey::from_pkcs1_pem(pem)?;
                        Ok(PKey { value: val })
                    }
                    Ok(val) => Ok(PKey { value: val }),
                }
            }
        }
    }

    /// Serialize the private key to a der file.
    pub fn to_der(&self) -> pkcs8::Result<pkcs8::SecretDocument> {
        use pkcs8::EncodePrivateKey;

        self.value.to_pkcs8_der()
    }

    /// Get the public key info for this private key.
    pub fn public_key_to_info(&self) -> x509_cert::spki::Result<SubjectPublicKeyInfoOwned> {
        use rsa::pkcs8::EncodePublicKey;
        SubjectPublicKeyInfoOwned::try_from(
            self.value
                .to_public_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
        )
    }

    /// Create a public key based on this private key.
    pub fn to_public_key(&self) -> PublicKey {
        PublicKey {
            value: self.value.to_public_key(),
        }
    }

    /// Signs the data using RSA-SHA1
    pub fn sign_sha1(&self, data: &[u8], signature: &mut [u8]) -> Result<usize, Error> {
        let mut rng = rand::rng();
        let signing_key = pkcs1v15::SigningKey::<sha1::Sha1>::new(self.value.clone());
        match signing_key.try_sign_with_rng(&mut rng, data) {
            Err(e) => Err(Error::new(StatusCode::BadUnexpectedError, e)),
            Ok(signed) => {
                let val = signed.to_vec();
                signature.copy_from_slice(&val);
                Ok(val.len())
            }
        }
    }

    /// Signs the data using RSA-SHA256
    pub fn sign_sha256(&self, data: &[u8], signature: &mut [u8]) -> Result<usize, Error> {
        let mut rng = rand::rng();
        let signing_key = pkcs1v15::SigningKey::<sha2::Sha256>::new(self.value.clone());
        match signing_key.try_sign_with_rng(&mut rng, data) {
            Err(e) => Err(Error::new(StatusCode::BadUnexpectedError, e)),
            Ok(signed) => {
                let val = signed.to_vec();
                signature.copy_from_slice(&val);
                Ok(val.len())
            }
        }
    }

    /// Signs the data using RSA-SHA256-PSS
    pub fn sign_sha256_pss(&self, data: &[u8], signature: &mut [u8]) -> Result<usize, Error> {
        let mut rng = rand::rng();
        let signing_key = pss::BlindedSigningKey::<sha2::Sha256>::new(self.value.clone());
        match signing_key.try_sign_with_rng(&mut rng, data) {
            Err(e) => Err(Error::new(StatusCode::BadUnexpectedError, e)),
            Ok(signed) => {
                let val = signed.to_vec();
                signature.copy_from_slice(&val);
                Ok(val.len())
            }
        }
    }

    pub(crate) fn private_decrypt<T: RsaAsymmetricEncryptionAlgorithm>(
        &self,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, PKeyError> {
        let cipher_text_block_size = self.cipher_text_block_size();
        // Decrypt the data
        let mut src_idx = 0;
        let mut dst_idx = 0;

        let src_len = src.len();
        while src_idx < src_len {
            let src_end_index = src_idx + cipher_text_block_size;

            // Decrypt and advance
            dst_idx += {
                let src = &src[src_idx..src_end_index];
                let dst = &mut dst[dst_idx..(dst_idx + cipher_text_block_size)];

                let padding = T::get_padding();
                let decrypted = self.value.decrypt(padding, src)?;

                let size = decrypted.len();
                if size == dst.len() {
                    dst.copy_from_slice(&decrypted);
                } else {
                    dst[0..size].copy_from_slice(&decrypted);
                }
                size
            };
            src_idx = src_end_index;
        }
        Ok(dst_idx)
    }
}

impl KeySize for PublicKey {
    /// Length in bits
    fn size(&self) -> usize {
        use rsa::traits::PublicKeyParts;
        self.value.size()
    }
}

impl PublicKey {
    /// Verifies the data using RSA-SHA1
    pub fn verify_sha1(&self, data: &[u8], signature: &[u8]) -> Result<bool, Error> {
        let verifying_key = pkcs1v15::VerifyingKey::<sha1::Sha1>::new(self.value.clone());
        let r = pkcs1v15::Signature::try_from(signature);
        match r {
            Err(e) => Err(Error::new(StatusCode::BadUnexpectedError, e)),
            Ok(val) => match verifying_key.verify(data, &val) {
                Err(_) => Ok(false),
                _ => Ok(true),
            },
        }
    }

    /// Verifies the data using RSA-SHA256
    pub fn verify_sha256(&self, data: &[u8], signature: &[u8]) -> Result<bool, Error> {
        let verifying_key = pkcs1v15::VerifyingKey::<sha2::Sha256>::new(self.value.clone());
        let r = pkcs1v15::Signature::try_from(signature);
        match r {
            Err(e) => Err(Error::new(StatusCode::BadUnexpectedError, e)),
            Ok(val) => match verifying_key.verify(data, &val) {
                Err(_) => Ok(false),
                _ => Ok(true),
            },
        }
    }

    /// Verifies the data using RSA-SHA256-PSS
    pub fn verify_sha256_pss(&self, data: &[u8], signature: &[u8]) -> Result<bool, Error> {
        let verifying_key = pss::VerifyingKey::<sha2::Sha256>::new(self.value.clone());
        let r = pss::Signature::try_from(signature);
        match r {
            Err(e) => Err(Error::new(StatusCode::BadUnexpectedError, e)),
            Ok(val) => match verifying_key.verify(data, &val) {
                Err(_) => Ok(false),
                _ => Ok(true),
            },
        }
    }

    /// Encrypts data from src to dst using the specified padding and returns the size of encrypted
    /// data in bytes or an error.
    pub(crate) fn public_encrypt<T: RsaAsymmetricEncryptionAlgorithm>(
        &self,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, PKeyError> {
        let cipher_text_block_size = self.cipher_text_block_size();
        let plain_text_block_size = T::get_plaintext_block_size(self.size());

        let mut rng = rand::rng();

        let mut src_idx = 0;
        let mut dst_idx = 0;

        let src_len = src.len();
        while src_idx < src_len {
            let bytes_to_encrypt = if src_len < plain_text_block_size {
                src_len
            } else if (src_len - src_idx) < plain_text_block_size {
                src_len - src_idx
            } else {
                plain_text_block_size
            };

            let src_end_index = src_idx + bytes_to_encrypt;

            // Encrypt data, advance dst index by number of bytes after encrypted
            dst_idx += {
                let src = &src[src_idx..src_end_index];

                let padding = T::get_padding();
                let encrypted = self.value.encrypt(&mut rng, padding, src)?;
                dst[dst_idx..(dst_idx + cipher_text_block_size)].copy_from_slice(&encrypted);
                encrypted.len()
            };

            // Src advances by bytes to encrypt
            src_idx = src_end_index;
        }

        Ok(dst_idx)
    }
}
