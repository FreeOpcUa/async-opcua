use aes::cipher::BlockSizeUser;
use elliptic_curve::ecdh::EagerHash;
use opcua_types::{Error, StatusCode};

use crate::{hash, AesKey, PrivateKey, PublicKey, SHA1_SIZE, SHA256_SIZE, SHA384_SIZE};

#[derive(Debug, Clone)]
/// Derived keys used for AES encryption
pub struct AesDerivedKeys {
    pub(crate) signing_key: Vec<u8>,
    pub(crate) encryption_key: AesKey,
    pub(crate) initialization_vector: Vec<u8>,
}

pub(crate) trait AesSymmetricSignatureAlgorithm {
    #[allow(unused)]
    const URI: &'static str;
    const SIZE: usize;

    /// Sign the data in `data` using the signing key `key`, writing the result to `signature`
    fn sign(key: &[u8], data: &[u8], signature: &mut [u8]) -> Result<(), Error>;

    /// Verify that the data in `data` was signed using the signing key `key`.
    fn verify_signature(key: &[u8], data: &[u8], signature: &[u8]) -> bool;
}

/// HMAC-SHA1 signature algorithm
pub(crate) struct DsigHmacSha1;
impl AesSymmetricSignatureAlgorithm for DsigHmacSha1 {
    const URI: &'static str = crate::algorithms::DSIG_HMAC_SHA1;
    const SIZE: usize = SHA1_SIZE;

    fn sign(key: &[u8], data: &[u8], signature: &mut [u8]) -> Result<(), Error> {
        hash::hmac_sha1(key, data, signature)
    }

    fn verify_signature(key: &[u8], data: &[u8], signature: &[u8]) -> bool {
        hash::verify_hmac_sha1(key, data, signature)
    }
}

/// HMAC-SHA256 signature algorithm
pub(crate) struct DsigHmacSha256;
impl AesSymmetricSignatureAlgorithm for DsigHmacSha256 {
    const URI: &'static str = crate::algorithms::DSIG_HMAC_SHA256;
    const SIZE: usize = SHA256_SIZE;

    fn sign(key: &[u8], data: &[u8], signature: &mut [u8]) -> Result<(), Error> {
        hash::hmac_sha256(key, data, signature)
    }

    fn verify_signature(key: &[u8], data: &[u8], signature: &[u8]) -> bool {
        hash::verify_hmac_sha256(key, data, signature)
    }
}

pub(crate) struct DsigHmacSha384;
impl AesSymmetricSignatureAlgorithm for DsigHmacSha384 {
    const URI: &'static str = crate::algorithms::DSIG_HMAC_SHA384;
    const SIZE: usize = SHA384_SIZE;

    fn sign(key: &[u8], data: &[u8], signature: &mut [u8]) -> Result<(), Error> {
        hash::hmac_sha384(key, data, signature)
    }

    fn verify_signature(key: &[u8], data: &[u8], signature: &[u8]) -> bool {
        hash::verify_hmac_sha384(key, data, signature)
    }
}

pub(crate) trait AesSymmetricEncryptionAlgorithm {
    #[allow(unused)]
    const URI: &'static str;
    const KEY_LENGTH: usize;
    const BLOCK_SIZE: usize;
    const IV_LENGTH: usize = Self::BLOCK_SIZE;

    type DigestMethod: BlockSizeUser + Clone + digest::Digest + EagerHash;

    /// Encrypt the data in `src` using `key`, writing the result to `dst`.
    fn encrypt(key: &AesKey, src: &[u8], iv: &[u8], dst: &mut [u8]) -> Result<usize, Error>;

    /// Decrypt the data in `src` using `key`, writing the result to `dst`.
    fn decrypt(key: &AesKey, src: &[u8], iv: &[u8], dst: &mut [u8]) -> Result<usize, Error>;

    fn validate_args(src: &[u8], iv: &[u8], dst: &[u8]) -> Result<(), Error> {
        if dst.len() < src.len() + Self::BLOCK_SIZE {
            Err(Error::new(
                StatusCode::BadUnexpectedError,
                format!(
                    "Destination buffer is too small ({}) expected {} + {}",
                    src.len(),
                    dst.len(),
                    Self::BLOCK_SIZE
                ),
            ))
        } else if iv.len() != Self::IV_LENGTH {
            Err(Error::new(
                StatusCode::BadUnexpectedError,
                format!(
                    "IV is not an expected size ({}), expected {}",
                    iv.len(),
                    Self::IV_LENGTH
                ),
            ))
        } else if !src.len().is_multiple_of(Self::BLOCK_SIZE) {
            Err(Error::new(
                StatusCode::BadUnexpectedError,
                format!(
                    "Source length ({}) is not a multiple of block size ({}), got {}",
                    src.len(),
                    Self::BLOCK_SIZE,
                    src.len()
                ),
            ))
        } else {
            Ok(())
        }
    }
}

/// AES-128-CBC symmetric encryption algorithm
pub(crate) struct Aes128Cbc;
impl AesSymmetricEncryptionAlgorithm for Aes128Cbc {
    const URI: &'static str = crate::algorithms::ENC_AES128_CBC;
    const KEY_LENGTH: usize = 16;
    const BLOCK_SIZE: usize = 16;

    type DigestMethod = sha1::Sha1;

    fn encrypt(key: &AesKey, src: &[u8], iv: &[u8], dst: &mut [u8]) -> Result<usize, Error> {
        key.encrypt_aes128_cbc(src, iv, dst)
    }

    fn decrypt(key: &AesKey, src: &[u8], iv: &[u8], dst: &mut [u8]) -> Result<usize, Error> {
        key.decrypt_aes128_cbc(src, iv, dst)
    }
}

/// AES-256-CBC symmetric encryption algorithm
pub(crate) struct Aes256Cbc;
impl AesSymmetricEncryptionAlgorithm for Aes256Cbc {
    const URI: &'static str = crate::algorithms::ENC_AES256_CBC;
    const KEY_LENGTH: usize = 32;
    const BLOCK_SIZE: usize = 16;

    type DigestMethod = sha2::Sha256;

    fn encrypt(key: &AesKey, src: &[u8], iv: &[u8], dst: &mut [u8]) -> Result<usize, Error> {
        key.encrypt_aes256_cbc(src, iv, dst)
    }

    fn decrypt(key: &AesKey, src: &[u8], iv: &[u8], dst: &mut [u8]) -> Result<usize, Error> {
        key.decrypt_aes256_cbc(src, iv, dst)
    }
}
