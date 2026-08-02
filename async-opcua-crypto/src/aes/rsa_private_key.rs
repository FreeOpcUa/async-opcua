// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Asymmetric encryption / decryption, signing / verification wrapper.
use std::{
    self,
    fmt::{self, Debug, Formatter},
    result::Result,
};

use openssl::{
    encrypt::{Decrypter, Encrypter},
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{PKey as OpensslPKey, Private, Public},
    rsa::Rsa,
    sign::{Signer as OpensslSigner, Verifier as OpensslVerifier},
};

use x509_cert::spki::SubjectPublicKeyInfoOwned;

use opcua_types::{status_code::StatusCode, Error};

use crate::policy::aes::{AesAsymmetricEncryptionAlgorithm, RsaPadding};

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

impl From<ErrorStack> for PKeyError {
    fn from(_err: ErrorStack) -> Self {
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
pub type PublicKey = PKey<OpensslPKey<Public>>;
/// A private key
pub type PrivateKey = PKey<OpensslPKey<Private>>;

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
pub(crate) fn calculate_cipher_text_size<T: AesAsymmetricEncryptionAlgorithm>(
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

/// Translate a padding scheme into the (openssl padding, optional OAEP/MGF1 digest) pair
/// needed to configure an `openssl::encrypt::{Encrypter, Decrypter}`.
fn openssl_padding(padding: RsaPadding) -> (openssl::rsa::Padding, Option<MessageDigest>) {
    match padding {
        RsaPadding::Pkcs1v15 => (openssl::rsa::Padding::PKCS1, None),
        RsaPadding::OaepSha1 => (openssl::rsa::Padding::PKCS1_OAEP, Some(MessageDigest::sha1())),
        RsaPadding::OaepSha256 => (
            openssl::rsa::Padding::PKCS1_OAEP,
            Some(MessageDigest::sha256()),
        ),
    }
}

impl KeySize for PrivateKey {
    /// Length in bits
    fn size(&self) -> usize {
        self.value.size()
    }
}

impl PrivateKey {
    /// Generate a new private key with the given length in bits.
    pub fn new(bit_length: u32) -> Result<PrivateKey, PKeyError> {
        let rsa = Rsa::generate(bit_length)?;
        let key = OpensslPKey::from_rsa(rsa)?;
        Ok(PKey { value: key })
    }

    /// Read a private key from the given path.
    pub fn read_pem_file(path: &std::path::Path) -> Result<PrivateKey, PKeyError> {
        let bytes = std::fs::read(path).map_err(|_| PKeyError)?;
        Self::from_pem(&bytes)
    }

    /// Create a private key from a pem file loaded into a byte array.
    pub fn from_pem(bytes: &[u8]) -> Result<PrivateKey, PKeyError> {
        // OpenSSL's generic private key PEM reader transparently handles both
        // PKCS#1 ("RSA PRIVATE KEY") and PKCS#8 ("PRIVATE KEY") encodings.
        let key = OpensslPKey::private_key_from_pem(bytes)?;
        Ok(PKey { value: key })
    }

    /// Serialize the private key to a der file.
    pub fn to_der(&self) -> pkcs8::Result<pkcs8::SecretDocument> {
        let pem = self
            .value
            .private_key_to_pem_pkcs8()
            .map_err(|_| pkcs8::Error::KeyMalformed)?;
        let pem = std::str::from_utf8(&pem).map_err(|_| pkcs8::Error::KeyMalformed)?;
        let (_, doc) = pkcs8::Document::from_pem(pem)?;
        Ok(doc.into())
    }

    /// Get the public key info for this private key.
    pub fn public_key_to_info(&self) -> x509_cert::spki::Result<SubjectPublicKeyInfoOwned> {
        let der = self
            .value
            .public_key_to_der()
            .map_err(|_| x509_cert::spki::Error::KeyMalformed)?;
        SubjectPublicKeyInfoOwned::try_from(der.as_slice())
    }

    /// Create a public key based on this private key.
    pub fn to_public_key(&self) -> PublicKey {
        let der = self
            .value
            .public_key_to_der()
            .expect("failed to derive public key DER from private key");
        let value = OpensslPKey::public_key_from_der(&der)
            .expect("failed to parse derived public key DER");
        PublicKey { value }
    }

    fn sign_pkcs1v15(
        &self,
        digest: MessageDigest,
        data: &[u8],
        signature: &mut [u8],
    ) -> Result<usize, Error> {
        let mut signer = OpensslSigner::new(digest, &self.value)
            .map_err(|e| Error::new(StatusCode::BadUnexpectedError, e))?;
        signer
            .set_rsa_padding(openssl::rsa::Padding::PKCS1)
            .map_err(|e| Error::new(StatusCode::BadUnexpectedError, e))?;
        signer
            .update(data)
            .map_err(|e| Error::new(StatusCode::BadUnexpectedError, e))?;
        signer
            .sign(signature)
            .map_err(|e| Error::new(StatusCode::BadUnexpectedError, e))
    }

    /// Signs the data using RSA-SHA1
    pub fn sign_sha1(&self, data: &[u8], signature: &mut [u8]) -> Result<usize, Error> {
        self.sign_pkcs1v15(MessageDigest::sha1(), data, signature)
    }

    /// Signs the data using RSA-SHA256
    pub fn sign_sha256(&self, data: &[u8], signature: &mut [u8]) -> Result<usize, Error> {
        self.sign_pkcs1v15(MessageDigest::sha256(), data, signature)
    }

    /// Signs the data using RSA-SHA256-PSS
    pub fn sign_sha256_pss(&self, data: &[u8], signature: &mut [u8]) -> Result<usize, Error> {
        let mut signer = OpensslSigner::new(MessageDigest::sha256(), &self.value)
            .map_err(|e| Error::new(StatusCode::BadUnexpectedError, e))?;
        signer
            .set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)
            .map_err(|e| Error::new(StatusCode::BadUnexpectedError, e))?;
        signer
            .set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)
            .map_err(|e| Error::new(StatusCode::BadUnexpectedError, e))?;
        signer
            .update(data)
            .map_err(|e| Error::new(StatusCode::BadUnexpectedError, e))?;
        signer
            .sign(signature)
            .map_err(|e| Error::new(StatusCode::BadUnexpectedError, e))
    }

    pub(crate) fn private_decrypt<T: AesAsymmetricEncryptionAlgorithm>(
        &self,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, PKeyError> {
        let cipher_text_block_size = self.cipher_text_block_size();
        let (padding, oaep_digest) = openssl_padding(T::get_padding());

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

                let mut decrypter = Decrypter::new(&self.value)?;
                decrypter.set_rsa_padding(padding)?;
                if let Some(digest) = oaep_digest {
                    decrypter.set_rsa_oaep_md(digest)?;
                    decrypter.set_rsa_mgf1_md(digest)?;
                }

                let mut decrypted = vec![0u8; cipher_text_block_size];
                let size = decrypter.decrypt(src, &mut decrypted)?;

                if size == dst.len() {
                    dst.copy_from_slice(&decrypted[..size]);
                } else {
                    dst[0..size].copy_from_slice(&decrypted[..size]);
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
        self.value.size()
    }
}

impl PublicKey {
    fn verify_pkcs1v15(
        &self,
        digest: MessageDigest,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, Error> {
        let mut verifier = OpensslVerifier::new(digest, &self.value)
            .map_err(|e| Error::new(StatusCode::BadUnexpectedError, e))?;
        verifier
            .set_rsa_padding(openssl::rsa::Padding::PKCS1)
            .map_err(|e| Error::new(StatusCode::BadUnexpectedError, e))?;
        verifier
            .update(data)
            .map_err(|e| Error::new(StatusCode::BadUnexpectedError, e))?;
        Ok(verifier.verify(signature).unwrap_or(false))
    }

    /// Verifies the data using RSA-SHA1
    pub fn verify_sha1(&self, data: &[u8], signature: &[u8]) -> Result<bool, Error> {
        self.verify_pkcs1v15(MessageDigest::sha1(), data, signature)
    }

    /// Verifies the data using RSA-SHA256
    pub fn verify_sha256(&self, data: &[u8], signature: &[u8]) -> Result<bool, Error> {
        self.verify_pkcs1v15(MessageDigest::sha256(), data, signature)
    }

    /// Verifies the data using RSA-SHA256-PSS
    pub fn verify_sha256_pss(&self, data: &[u8], signature: &[u8]) -> Result<bool, Error> {
        let mut verifier = OpensslVerifier::new(MessageDigest::sha256(), &self.value)
            .map_err(|e| Error::new(StatusCode::BadUnexpectedError, e))?;
        verifier
            .set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)
            .map_err(|e| Error::new(StatusCode::BadUnexpectedError, e))?;
        verifier
            .set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)
            .map_err(|e| Error::new(StatusCode::BadUnexpectedError, e))?;
        verifier
            .update(data)
            .map_err(|e| Error::new(StatusCode::BadUnexpectedError, e))?;
        Ok(verifier.verify(signature).unwrap_or(false))
    }

    /// Encrypts data from src to dst using the specified padding and returns the size of encrypted
    /// data in bytes or an error.
    pub(crate) fn public_encrypt<T: AesAsymmetricEncryptionAlgorithm>(
        &self,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, PKeyError> {
        let cipher_text_block_size = self.cipher_text_block_size();
        let plain_text_block_size = T::get_plaintext_block_size(self.size());
        let (padding, oaep_digest) = openssl_padding(T::get_padding());

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

                let mut encrypter = Encrypter::new(&self.value)?;
                encrypter.set_rsa_padding(padding)?;
                if let Some(digest) = oaep_digest {
                    encrypter.set_rsa_oaep_md(digest)?;
                    encrypter.set_rsa_mgf1_md(digest)?;
                }

                let encrypted_len = dst[dst_idx..(dst_idx + cipher_text_block_size)].len();
                let mut encrypted = vec![0u8; encrypted_len];
                let size = encrypter.encrypt(src, &mut encrypted)?;
                dst[dst_idx..(dst_idx + cipher_text_block_size)].copy_from_slice(&encrypted);
                size
            };

            // Src advances by bytes to encrypt
            src_idx = src_end_index;
        }

        Ok(dst_idx)
    }
}
