// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Asymmetric encryption / decryption, signing / verification wrapper.
use std::{
    self,
    fmt::{self, Debug, Formatter},
    result::Result,
};

#[cfg(feature = "aws-lc-rs")]
use aws_lc_rs::rsa as aws_rsa;
use rsa::pkcs1;
use rsa::pkcs1v15;
use rsa::pkcs8;
use rsa::pss;
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey as RsaPublicKeyInner};

use x509_cert::spki::SubjectPublicKeyInfoOwned;

use opcua_types::{status_code::StatusCode, Error};

use crate::policy::aes::{AesAsymmetricEncryptionAlgorithm, RsaPrivateDecryptPadding};

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
#[allow(dead_code)]
pub struct PKey<T> {
    pub(crate) value: T,
}

/// A public key
#[derive(Clone)]
pub struct PublicKey {
    pub(crate) value: PublicKeyKind,
}

#[derive(Clone)]
pub(crate) enum PublicKeyKind {
    Rsa(RsaPublicKeyInner),
    #[cfg(feature = "ecc")]
    Ecc(crate::ecc::EccPublicKey),
}
/// A private key
#[derive(Clone)]
pub struct PrivateKey {
    pub(crate) value: PrivateKeyKind,
}

#[derive(Clone)]
pub(crate) enum PrivateKeyKind {
    Rsa(Box<RsaPrivateKey>),
    #[cfg(feature = "ecc")]
    Ecc(crate::ecc::EccPrivateKey),
}

impl<T> Debug for PKey<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // This impl will not write out the key, but it exists to keep structs happy
        // that contain a key as a field
        write!(f, "[pkey]")
    }
}

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[pkey]")
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
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

impl KeySize for PrivateKey {
    /// Length in bits
    fn size(&self) -> usize {
        use rsa::traits::PublicKeyParts;
        match &self.value {
            PrivateKeyKind::Rsa(key) => key.size(),
            #[cfg(feature = "ecc")]
            PrivateKeyKind::Ecc(key) => key.curve().raw_signature_len(),
        }
    }
}

impl PrivateKey {
    /// Generate a new private key with the given length in bits.
    pub fn new(bit_length: u32) -> Result<PrivateKey, rsa::Error> {
        let mut rng = rand::thread_rng();

        let key = RsaPrivateKey::new(&mut rng, bit_length as usize)?;
        Ok(Self {
            value: PrivateKeyKind::Rsa(Box::new(key)),
        })
    }

    /// Create a private key wrapper from an EC key.
    #[cfg(feature = "ecc")]
    #[must_use]
    pub fn from_ecc(key: crate::ecc::EccPrivateKey) -> PrivateKey {
        Self {
            value: PrivateKeyKind::Ecc(key),
        }
    }

    /// Read a private key from the given path.
    pub fn read_pem_file(path: &std::path::Path) -> Result<PrivateKey, PKeyError> {
        use pkcs8::DecodePrivateKey;
        use rsa::pkcs1::DecodeRsaPrivateKey;

        let r = RsaPrivateKey::read_pkcs8_pem_file(path);
        match r {
            Err(_) => match RsaPrivateKey::read_pkcs1_pem_file(path) {
                Err(_) => {
                    #[cfg(feature = "ecc")]
                    {
                        let pem = std::fs::read_to_string(path).map_err(|_| PKeyError)?;
                        Self::ecc_key_from_pkcs8_pem(&pem)
                    }
                    #[cfg(not(feature = "ecc"))]
                    {
                        Err(PKeyError)
                    }
                }
                Ok(val) => Ok(Self {
                    value: PrivateKeyKind::Rsa(Box::new(val)),
                }),
            },
            Ok(val) => Ok(Self {
                value: PrivateKeyKind::Rsa(Box::new(val)),
            }),
        }
    }

    fn rsa_key(&self) -> Result<&RsaPrivateKey, Error> {
        match &self.value {
            PrivateKeyKind::Rsa(key) => Ok(key.as_ref()),
            #[cfg(feature = "ecc")]
            PrivateKeyKind::Ecc(_) => Err(Error::new(
                StatusCode::BadSecurityChecksFailed,
                "RSA operation requested for an EC private key",
            )),
        }
    }

    #[cfg(not(feature = "aws-lc-rs"))]
    fn rsa_key_for_decrypt(&self) -> Result<&RsaPrivateKey, PKeyError> {
        match &self.value {
            PrivateKeyKind::Rsa(key) => Ok(key.as_ref()),
            #[cfg(feature = "ecc")]
            PrivateKeyKind::Ecc(_) => Err(PKeyError),
        }
    }

    /// Returns the inner EC private key when this key is EC.
    #[cfg(feature = "ecc")]
    #[must_use]
    pub fn ecc_key(&self) -> Option<&crate::ecc::EccPrivateKey> {
        match &self.value {
            PrivateKeyKind::Rsa(_) => None,
            PrivateKeyKind::Ecc(key) => Some(key),
        }
    }

    pub(crate) fn rsa_key_for_x509(&self) -> Result<&RsaPrivateKey, PKeyError> {
        match &self.value {
            PrivateKeyKind::Rsa(key) => Ok(key.as_ref()),
            #[cfg(feature = "ecc")]
            PrivateKeyKind::Ecc(_) => Err(PKeyError),
        }
    }

    fn rsa_key_for_pkcs8(&self) -> pkcs8::Result<&RsaPrivateKey> {
        match &self.value {
            PrivateKeyKind::Rsa(key) => Ok(key),
            #[cfg(feature = "ecc")]
            PrivateKeyKind::Ecc(_) => Err(pkcs8::Error::KeyMalformed),
        }
    }

    #[cfg(feature = "ecc")]
    #[allow(clippy::panic)]
    fn ecc_public_key_from_validated_private_key(
        key: &crate::ecc::EccPrivateKey,
    ) -> crate::ecc::EccPublicKey {
        let Ok(public_key) = key.public_key() else {
            unreachable!("validated EC private scalar must derive a public key");
        };
        public_key
    }

    #[cfg(feature = "ecc")]
    fn ecc_public_key_to_info(
        key: &crate::ecc::EccPrivateKey,
    ) -> x509_cert::spki::Result<SubjectPublicKeyInfoOwned> {
        match key.curve() {
            crate::ecc::EccCurve::P256 => {
                let signing_key = p256::ecdsa::SigningKey::from_slice(key.scalar())
                    .map_err(|_| x509_cert::spki::Error::KeyMalformed)?;
                SubjectPublicKeyInfoOwned::from_key(*signing_key.verifying_key())
            }
            crate::ecc::EccCurve::P384 => {
                let signing_key = p384::ecdsa::SigningKey::from_slice(key.scalar())
                    .map_err(|_| x509_cert::spki::Error::KeyMalformed)?;
                SubjectPublicKeyInfoOwned::from_key(*signing_key.verifying_key())
            }
        }
    }

    #[cfg(feature = "ecc")]
    fn ecc_key_from_pkcs8_pem(pem: &str) -> Result<PrivateKey, PKeyError> {
        use pkcs8::DecodePrivateKey;

        if let Ok(secret) = p256::SecretKey::from_pkcs8_pem(pem) {
            return crate::ecc::EccPrivateKey::from_scalar_bytes(
                crate::ecc::EccCurve::P256,
                secret.to_bytes().as_slice(),
            )
            .map(Self::from_ecc)
            .map_err(|_| PKeyError);
        }

        let secret = p384::SecretKey::from_pkcs8_pem(pem).map_err(|_| PKeyError)?;
        crate::ecc::EccPrivateKey::from_scalar_bytes(
            crate::ecc::EccCurve::P384,
            secret.to_bytes().as_slice(),
        )
        .map(Self::from_ecc)
        .map_err(|_| PKeyError)
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
                    Err(_) => match RsaPrivateKey::from_pkcs1_pem(pem) {
                        Err(_) => {
                            #[cfg(feature = "ecc")]
                            {
                                Self::ecc_key_from_pkcs8_pem(pem)
                            }
                            #[cfg(not(feature = "ecc"))]
                            {
                                Err(PKeyError)
                            }
                        }
                        Ok(val) => Ok(Self {
                            value: PrivateKeyKind::Rsa(Box::new(val)),
                        }),
                    },
                    Ok(val) => Ok(Self {
                        value: PrivateKeyKind::Rsa(Box::new(val)),
                    }),
                }
            }
        }
    }

    /// Serialize the private key to a der file.
    pub fn to_der(&self) -> pkcs8::Result<pkcs8::SecretDocument> {
        use pkcs8::EncodePrivateKey;

        match &self.value {
            PrivateKeyKind::Rsa(_) => self.rsa_key_for_pkcs8()?.to_pkcs8_der(),
            #[cfg(feature = "ecc")]
            PrivateKeyKind::Ecc(key) => key.to_pkcs8_der(),
        }
    }

    /// Serialize the private key to a PEM string.
    pub fn to_pem(&self) -> Result<String, String> {
        use rsa::pkcs8;
        use x509_cert::der::pem::PemLabel;
        let doc = self
            .to_der()
            .map_err(|e| format!("Failed to convert to DER: {e:?}"))?;
        let pem = doc
            .to_pem(rsa::pkcs8::PrivateKeyInfo::PEM_LABEL, pkcs8::LineEnding::CR)
            .map_err(|e| format!("Failed to convert to PEM: {e:?}"))?;
        Ok(pem.to_string())
    }

    /// Get the public key info for this private key.
    pub fn public_key_to_info(&self) -> x509_cert::spki::Result<SubjectPublicKeyInfoOwned> {
        use rsa::pkcs8::EncodePublicKey;
        // Public-key DER encoding from an in-memory RSA key is an internal invariant here.
        #[allow(clippy::unwrap_used)]
        match &self.value {
            PrivateKeyKind::Rsa(key) => {
                let public_key_der = key.to_public_key().to_public_key_der().unwrap();
                SubjectPublicKeyInfoOwned::try_from(public_key_der.as_bytes())
            }
            #[cfg(feature = "ecc")]
            PrivateKeyKind::Ecc(key) => Self::ecc_public_key_to_info(key),
        }
    }

    /// Create a public key based on this private key.
    pub fn to_public_key(&self) -> PublicKey {
        match &self.value {
            PrivateKeyKind::Rsa(key) => PublicKey {
                value: PublicKeyKind::Rsa(key.to_public_key()),
            },
            #[cfg(feature = "ecc")]
            PrivateKeyKind::Ecc(key) => PublicKey {
                value: PublicKeyKind::Ecc(Self::ecc_public_key_from_validated_private_key(key)),
            },
        }
    }

    /// Signs the data using RSA-SHA1
    pub fn sign_sha1(&self, data: &[u8], signature: &mut [u8]) -> Result<usize, Error> {
        let mut rng = rand::thread_rng();
        let signing_key = pkcs1v15::SigningKey::<sha1::Sha1>::new(self.rsa_key()?.clone());
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
        let mut rng = rand::thread_rng();
        let signing_key = pkcs1v15::SigningKey::<sha2::Sha256>::new(self.rsa_key()?.clone());
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
        let mut rng = rand::thread_rng();
        let signing_key = pss::BlindedSigningKey::<sha2::Sha256>::new(self.rsa_key()?.clone());
        match signing_key.try_sign_with_rng(&mut rng, data) {
            Err(e) => Err(Error::new(StatusCode::BadUnexpectedError, e)),
            Ok(signed) => {
                let val = signed.to_vec();
                signature.copy_from_slice(&val);
                Ok(val.len())
            }
        }
    }

    pub(crate) fn private_decrypt<T: AesAsymmetricEncryptionAlgorithm>(
        &self,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, PKeyError> {
        #[cfg(not(feature = "aws-lc-rs"))]
        let key = self.rsa_key_for_decrypt()?;
        let cipher_text_block_size = self.cipher_text_block_size();
        // Reject non-block-aligned ciphertext: the per-block loop below slices
        // `src[i..i+block]`, which would read out of bounds (panic) on a crafted
        // OpenSecureChannel chunk whose encrypted span is not a whole multiple of the
        // block size. Empty `src` is a multiple of the block size and the loop simply
        // no-ops (returns 0), so it stays allowed.
        if cipher_text_block_size == 0 || !src.len().is_multiple_of(cipher_text_block_size) {
            return Err(PKeyError);
        }
        #[cfg(feature = "aws-lc-rs")]
        let decrypting_key = self.aws_lc_private_decrypting_key()?;
        let padding = T::get_private_decrypt_padding();
        // Decrypt the data
        let mut src_idx: usize = 0;
        let mut dst_idx: usize = 0;

        let src_len = src.len();
        while src_idx < src_len {
            let src_end_index = src_idx + cipher_text_block_size;

            // Decrypt and advance
            dst_idx += {
                let src = src.get(src_idx..src_end_index).ok_or(PKeyError)?;
                let dst_end_index = dst_idx
                    .checked_add(cipher_text_block_size)
                    .filter(|end| *end <= dst.len())
                    .ok_or(PKeyError)?;
                let dst = dst.get_mut(dst_idx..dst_end_index).ok_or(PKeyError)?;

                #[cfg(feature = "aws-lc-rs")]
                let block_len = aws_lc_private_decrypt(&decrypting_key, padding, src, dst)?;
                #[cfg(not(feature = "aws-lc-rs"))]
                let block_len = rsa_private_decrypt(key, padding, src, dst)?;
                block_len
            };
            src_idx = src_end_index;
        }
        Ok(dst_idx)
    }

    #[cfg(feature = "aws-lc-rs")]
    fn aws_lc_private_decrypting_key(&self) -> Result<aws_rsa::PrivateDecryptingKey, PKeyError> {
        let der = self.to_der().map_err(|_| PKeyError)?;
        aws_rsa::PrivateDecryptingKey::from_pkcs8(der.as_bytes()).map_err(|_| PKeyError)
    }
}

#[cfg(feature = "aws-lc-rs")]
fn aws_lc_private_decrypt(
    private_key: &aws_rsa::PrivateDecryptingKey,
    padding: RsaPrivateDecryptPadding,
    src: &[u8],
    dst: &mut [u8],
) -> Result<usize, PKeyError> {
    match padding {
        RsaPrivateDecryptPadding::Pkcs1v15 => {
            let key = aws_rsa::Pkcs1PrivateDecryptingKey::new(private_key.clone())
                .map_err(|_| PKeyError)?;
            key.decrypt(src, dst)
                .map(|plaintext| plaintext.len())
                .map_err(|_| PKeyError)
        }
        RsaPrivateDecryptPadding::OaepSha1 => {
            let key = aws_rsa::OaepPrivateDecryptingKey::new(private_key.clone())
                .map_err(|_| PKeyError)?;
            key.decrypt(&aws_rsa::OAEP_SHA1_MGF1SHA1, src, dst, None)
                .map(|plaintext| plaintext.len())
                .map_err(|_| PKeyError)
        }
        RsaPrivateDecryptPadding::OaepSha256 => {
            let key = aws_rsa::OaepPrivateDecryptingKey::new(private_key.clone())
                .map_err(|_| PKeyError)?;
            key.decrypt(&aws_rsa::OAEP_SHA256_MGF1SHA256, src, dst, None)
                .map(|plaintext| plaintext.len())
                .map_err(|_| PKeyError)
        }
    }
}

#[cfg(not(feature = "aws-lc-rs"))]
fn rsa_private_decrypt(
    private_key: &RsaPrivateKey,
    padding: RsaPrivateDecryptPadding,
    src: &[u8],
    dst: &mut [u8],
) -> Result<usize, PKeyError> {
    let plaintext = match padding {
        RsaPrivateDecryptPadding::Pkcs1v15 => private_key.decrypt(rsa::Pkcs1v15Encrypt, src)?,
        RsaPrivateDecryptPadding::OaepSha1 => {
            private_key.decrypt(rsa::Oaep::new::<sha1::Sha1>(), src)?
        }
        RsaPrivateDecryptPadding::OaepSha256 => {
            private_key.decrypt(rsa::Oaep::new::<sha2::Sha256>(), src)?
        }
    };
    dst.get_mut(..plaintext.len())
        .ok_or(PKeyError)?
        .copy_from_slice(&plaintext);
    Ok(plaintext.len())
}

impl KeySize for PublicKey {
    /// Length in bits
    fn size(&self) -> usize {
        use rsa::traits::PublicKeyParts;
        match &self.value {
            PublicKeyKind::Rsa(key) => key.size(),
            #[cfg(feature = "ecc")]
            PublicKeyKind::Ecc(key) => key.curve().scalar_len(),
        }
    }
}

impl PublicKey {
    /// Create a public key wrapper from an RSA key.
    pub(crate) fn from_rsa(value: RsaPublicKeyInner) -> Self {
        Self {
            value: PublicKeyKind::Rsa(value),
        }
    }

    /// Create a public key wrapper from an EC key.
    #[cfg(feature = "ecc")]
    pub(crate) fn from_ecc(value: crate::ecc::EccPublicKey) -> Self {
        Self {
            value: PublicKeyKind::Ecc(value),
        }
    }

    /// Returns the EC curve if this is an EC public key.
    #[cfg(feature = "ecc")]
    #[must_use]
    pub fn ecc_curve(&self) -> Option<crate::ecc::EccCurve> {
        match &self.value {
            PublicKeyKind::Rsa(_) => None,
            PublicKeyKind::Ecc(key) => Some(key.curve()),
        }
    }

    /// Returns the inner EC public key when this key is EC.
    #[cfg(feature = "ecc")]
    #[must_use]
    pub fn ecc_key(&self) -> Option<&crate::ecc::EccPublicKey> {
        match &self.value {
            PublicKeyKind::Rsa(_) => None,
            PublicKeyKind::Ecc(key) => Some(key),
        }
    }

    fn rsa_key(&self) -> Result<&RsaPublicKeyInner, Error> {
        match &self.value {
            PublicKeyKind::Rsa(key) => Ok(key),
            #[cfg(feature = "ecc")]
            PublicKeyKind::Ecc(_) => Err(Error::new(
                StatusCode::BadSecurityChecksFailed,
                "RSA operation requested for an EC public key",
            )),
        }
    }

    fn rsa_key_for_encrypt(&self) -> Result<&RsaPublicKeyInner, PKeyError> {
        match &self.value {
            PublicKeyKind::Rsa(key) => Ok(key),
            #[cfg(feature = "ecc")]
            PublicKeyKind::Ecc(_) => Err(PKeyError),
        }
    }

    /// Verifies the data using RSA-SHA1
    pub fn verify_sha1(&self, data: &[u8], signature: &[u8]) -> Result<bool, Error> {
        let verifying_key = pkcs1v15::VerifyingKey::<sha1::Sha1>::new(self.rsa_key()?.clone());
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
        let verifying_key = pkcs1v15::VerifyingKey::<sha2::Sha256>::new(self.rsa_key()?.clone());
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
        let verifying_key = pss::VerifyingKey::<sha2::Sha256>::new(self.rsa_key()?.clone());
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
    pub(crate) fn public_encrypt<T: AesAsymmetricEncryptionAlgorithm>(
        &self,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, PKeyError> {
        let cipher_text_block_size = self.cipher_text_block_size();
        let plain_text_block_size = T::get_plaintext_block_size(self.size());
        let key = self.rsa_key_for_encrypt()?;

        let mut rng = rand::thread_rng();

        let mut src_idx = 0;
        let mut dst_idx: usize = 0;

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
                let src = src.get(src_idx..src_end_index).ok_or(PKeyError)?;

                let padding = T::get_padding();
                let encrypted = key.encrypt(&mut rng, padding, src)?;
                if encrypted.len() != cipher_text_block_size {
                    return Err(PKeyError);
                }
                let dst_end_index = dst_idx
                    .checked_add(cipher_text_block_size)
                    .filter(|end| *end <= dst.len())
                    .ok_or(PKeyError)?;
                dst.get_mut(dst_idx..dst_end_index)
                    .ok_or(PKeyError)?
                    .copy_from_slice(&encrypted);
                encrypted.len()
            };

            // Src advances by bytes to encrypt
            src_idx = src_end_index;
        }

        Ok(dst_idx)
    }
}
