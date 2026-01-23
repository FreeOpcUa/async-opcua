use std::marker::PhantomData;

use aes::cipher::BlockSizeUser;
use elliptic_curve::ecdh::EagerHash;
use opcua_types::{Error, StatusCode};
use rsa::{Oaep, Pkcs1v15Encrypt};

use crate::{
    aes::{calculate_cipher_text_size, diffie_hellman::RsaDiffieHellman},
    hash,
    policy::{minimum_padding, PaddingInfo, SecureChannelRole, SecurityPolicyImpl},
    AesKey, KeySize, PrivateKey, PublicKey, SHA1_SIZE, SHA256_SIZE, SHA384_SIZE,
};

pub(crate) struct AesPolicy<T> {
    _phantom: PhantomData<T>,
}

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

pub(crate) trait AesAsymmetricSignatureAlgorithm {
    const URI: &'static str;

    /// Sign `data` using `key`, writing the result to `out`.
    fn sign(key: &PrivateKey, data: &[u8], out: &mut [u8]) -> Result<usize, Error>;

    /// Verify the `signature` made using the private key for the public key
    /// given by `key` by signing `data`.
    fn verify_signature(key: &PublicKey, data: &[u8], signature: &[u8]) -> Result<bool, Error>;

    /// Produce a pseudo-random sequence of bytes using the PRF
    /// algorithm given in OPC-UA 6.7.5
    fn prf(secret: &[u8], seed: &[u8], length: usize) -> Vec<u8>;
}

/// RSA-SHA256 asymmetric signature algorithm
pub(crate) struct DsigRsaSha256;
impl AesAsymmetricSignatureAlgorithm for DsigRsaSha256 {
    const URI: &'static str = crate::algorithms::DSIG_RSA_SHA256;

    fn sign(key: &PrivateKey, data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        key.sign_sha256(data, out)
    }

    fn verify_signature(key: &PublicKey, data: &[u8], signature: &[u8]) -> Result<bool, Error> {
        key.verify_sha256(data, signature)
    }

    fn prf(secret: &[u8], seed: &[u8], length: usize) -> Vec<u8> {
        hash::p_sha256(secret, seed, length)
    }
}

/// RSA-PSS-SHA256 asymmetric signature algorithm
pub(crate) struct DsigRsaPssSha256;
impl AesAsymmetricSignatureAlgorithm for DsigRsaPssSha256 {
    const URI: &'static str = crate::algorithms::DSIG_RSA_PSS_SHA2_256;

    fn sign(key: &PrivateKey, data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        key.sign_sha256_pss(data, out)
    }

    fn verify_signature(key: &PublicKey, data: &[u8], signature: &[u8]) -> Result<bool, Error> {
        key.verify_sha256_pss(data, signature)
    }

    fn prf(secret: &[u8], seed: &[u8], length: usize) -> Vec<u8> {
        hash::p_sha256(secret, seed, length)
    }
}

/// RSA-SHA1 asymmetric signature algorithm
pub(crate) struct DsigRsaSha1;
impl AesAsymmetricSignatureAlgorithm for DsigRsaSha1 {
    const URI: &'static str = crate::algorithms::DSIG_RSA_SHA1;

    fn sign(key: &PrivateKey, data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        key.sign_sha1(data, out)
    }

    fn verify_signature(key: &PublicKey, data: &[u8], signature: &[u8]) -> Result<bool, Error> {
        key.verify_sha1(data, signature)
    }

    fn prf(secret: &[u8], seed: &[u8], length: usize) -> Vec<u8> {
        hash::p_sha1(secret, seed, length)
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

pub(crate) trait AesAsymmetricEncryptionAlgorithm {
    const URI: &'static str;
    type Padding: rsa::traits::PaddingScheme;

    fn get_padding() -> Self::Padding;

    fn get_plaintext_block_size(key_size: usize) -> usize;
}

/// PKCS1v15 asymmetric encryption algorithm
pub(crate) struct Pkcs1v15;
impl AesAsymmetricEncryptionAlgorithm for Pkcs1v15 {
    const URI: &'static str = crate::algorithms::ENC_RSA_15;
    type Padding = Pkcs1v15Encrypt;

    fn get_padding() -> Self::Padding {
        Pkcs1v15Encrypt
    }

    fn get_plaintext_block_size(key_size: usize) -> usize {
        key_size - 11
    }
}

/// OAEP-SHA1 asymmetric encryption algorithm
pub(crate) struct OaepSha1;
impl AesAsymmetricEncryptionAlgorithm for OaepSha1 {
    const URI: &'static str = crate::algorithms::ENC_RSA_OAEP;
    type Padding = Oaep<sha1::Sha1>;

    fn get_padding() -> Self::Padding {
        Oaep::new()
    }

    fn get_plaintext_block_size(key_size: usize) -> usize {
        key_size - 42
    }
}

/// OAEP-SHA256 asymmetric encryption algorithm
pub(crate) struct OaepSha256;
impl AesAsymmetricEncryptionAlgorithm for OaepSha256 {
    const URI: &'static str = crate::algorithms::ENC_RSA_OAEP_SHA256;
    type Padding = Oaep<sha2::Sha256>;

    fn get_padding() -> Self::Padding {
        Oaep::new()
    }

    fn get_plaintext_block_size(key_size: usize) -> usize {
        key_size - 66
    }
}

impl<T: AesSecurityPolicy + 'static> SecurityPolicyImpl for AesPolicy<T> {
    type TPrivateKey = PrivateKey;
    type TPublicKey = PublicKey;
    type TDerivedKey = AesDerivedKeys;

    fn uri() -> &'static str {
        T::SECURITY_POLICY_URI
    }

    fn is_deprecated() -> bool {
        T::DEPRECATED
    }

    fn as_str() -> &'static str {
        T::SECURITY_POLICY
    }

    fn symmetric_signature_size() -> usize {
        T::SymmetricSignature::SIZE
    }

    fn calculate_cipher_text_size(plain_text_size: usize, key: &Self::TPublicKey) -> usize {
        calculate_cipher_text_size::<T::AsymmetricEncryption>(key.size(), plain_text_size)
    }

    fn encrypting_key_length() -> usize {
        T::SymmetricEncryption::KEY_LENGTH
    }

    fn asymmetric_encryption_algorithm() -> Option<&'static str> {
        Some(T::AsymmetricEncryption::URI)
    }

    fn asymmetric_signature_algorithm() -> &'static str {
        T::AsymmetricSignature::URI
    }

    fn nonce_length() -> usize {
        T::NONCE_LENGTH
    }

    fn plain_text_block_size() -> usize {
        T::SymmetricEncryption::BLOCK_SIZE
    }

    fn uses_legacy_sequence_numbers() -> bool {
        true
    }

    fn asymmetric_padding_info(remote_key: &Self::TPublicKey) -> PaddingInfo {
        PaddingInfo {
            block_size: T::AsymmetricEncryption::get_plaintext_block_size(remote_key.size()),
            minimum_padding: minimum_padding(remote_key.size()),
        }
    }

    fn symmetric_padding_info() -> PaddingInfo {
        PaddingInfo {
            block_size: Self::plain_text_block_size(),
            minimum_padding: minimum_padding(T::SymmetricSignature::SIZE),
        }
    }

    fn asymmetric_sign(
        key: &Self::TPrivateKey,
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        T::AsymmetricSignature::sign(key, data, out)
    }

    fn asymmetric_verify_signature(
        key: &Self::TPublicKey,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        if T::AsymmetricSignature::verify_signature(key, data, signature)? {
            Ok(())
        } else {
            Err(Error::new(
                StatusCode::BadSecurityChecksFailed,
                "Signature mismatch",
            ))
        }
    }

    fn asymmetric_encrypt(
        key: &Self::TPublicKey,
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        key.public_encrypt::<T::AsymmetricEncryption>(data, out)
            .map_err(|e| Error::new(StatusCode::BadUnexpectedError, e))
    }

    fn asymmetric_decrypt(
        key: &Self::TPrivateKey,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, Error> {
        key.private_decrypt::<T::AsymmetricEncryption>(src, dst)
            .map_err(|e| Error::new(StatusCode::BadSecurityChecksFailed, e))
    }

    fn begin_diffie_hellman_exchange(
        _role: SecureChannelRole,
    ) -> Box<dyn crate::aes::diffie_hellman::DiffieHellmanExchange> {
        Box::new(RsaDiffieHellman::<T>::new())
    }

    fn symmetric_decrypt(
        keys: &Self::TDerivedKey,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, Error> {
        T::SymmetricEncryption::validate_args(src, &keys.initialization_vector, dst)?;
        T::SymmetricEncryption::decrypt(&keys.encryption_key, src, &keys.initialization_vector, dst)
    }

    fn symmetric_encrypt(
        keys: &Self::TDerivedKey,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, Error> {
        T::SymmetricEncryption::validate_args(src, &keys.initialization_vector, dst)?;
        T::SymmetricEncryption::encrypt(&keys.encryption_key, src, &keys.initialization_vector, dst)
    }

    fn symmetric_sign(
        keys: &Self::TDerivedKey,
        data: &[u8],
        signature: &mut [u8],
    ) -> Result<(), Error> {
        T::SymmetricSignature::sign(&keys.signing_key, data, signature)
    }

    fn symmetric_verify_signature(
        keys: &Self::TDerivedKey,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        if T::SymmetricSignature::verify_signature(&keys.signing_key, data, signature) {
            Ok(())
        } else {
            Err(Error::new(
                StatusCode::BadSecurityChecksFailed,
                format!("Signature invalid: {signature:?}"),
            ))
        }
    }

    fn is_valid_key_length(length: usize) -> bool {
        let (min, max) = T::ASYMMETRIC_KEY_LENGTH;
        length >= min && length <= max
    }
}

/// Trait for a security policy supported by the library.
pub(crate) trait AesSecurityPolicy {
    /// The name of the policy.
    const SECURITY_POLICY: &'static str;
    /// The URI of the policy, as defined in the OPC-UA standard.
    const SECURITY_POLICY_URI: &'static str;
    /// Whether the security policy is considered deprecated.
    const DEPRECATED: bool = false;
    /// Length of the secure channel nonce.
    const NONCE_LENGTH: usize;

    /// The length of the derived signature key in bytes.
    const DERIVED_SIGNATURE_KEY_LENGTH: usize;
    /// The length of the asymmetric key in bits.
    const ASYMMETRIC_KEY_LENGTH: (usize, usize);

    type SymmetricSignature: AesSymmetricSignatureAlgorithm;
    type AsymmetricSignature: AesAsymmetricSignatureAlgorithm;
    type SymmetricEncryption: AesSymmetricEncryptionAlgorithm;
    type AsymmetricEncryption: AesAsymmetricEncryptionAlgorithm;
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
pub(crate) struct Aes128Sha256RsaOaep;
impl AesSecurityPolicy for Aes128Sha256RsaOaep {
    const SECURITY_POLICY: &str = "Aes128-Sha256-RsaOaep";
    const SECURITY_POLICY_URI: &str =
        "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep";
    const NONCE_LENGTH: usize = 32;

    const DERIVED_SIGNATURE_KEY_LENGTH: usize = 32;
    const ASYMMETRIC_KEY_LENGTH: (usize, usize) = (2048, 4096);

    type AsymmetricSignature = DsigRsaSha256;
    type SymmetricSignature = DsigHmacSha256;
    type SymmetricEncryption = Aes128Cbc;
    type AsymmetricEncryption = OaepSha1;
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
pub(crate) struct Aes256Sha256RsaPss;
impl AesSecurityPolicy for Aes256Sha256RsaPss {
    const SECURITY_POLICY: &str = "Aes256-Sha256-RsaPss";
    const SECURITY_POLICY_URI: &str =
        "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss";
    const NONCE_LENGTH: usize = 32;

    const DERIVED_SIGNATURE_KEY_LENGTH: usize = 32;
    const ASYMMETRIC_KEY_LENGTH: (usize, usize) = (2048, 4096);

    type AsymmetricSignature = DsigRsaPssSha256;
    type SymmetricSignature = DsigHmacSha256;
    type SymmetricEncryption = Aes256Cbc;
    type AsymmetricEncryption = OaepSha256;
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
pub(crate) struct Basic256Sha256;
impl AesSecurityPolicy for Basic256Sha256 {
    const SECURITY_POLICY: &str = "Basic256Sha256";
    const SECURITY_POLICY_URI: &str = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256";
    const NONCE_LENGTH: usize = 32;

    const DERIVED_SIGNATURE_KEY_LENGTH: usize = 32;
    const ASYMMETRIC_KEY_LENGTH: (usize, usize) = (2048, 4096);

    type AsymmetricSignature = DsigRsaSha256;
    type SymmetricSignature = DsigHmacSha256;
    type SymmetricEncryption = Aes256Cbc;
    type AsymmetricEncryption = OaepSha1;
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
pub(crate) struct Basic128Rsa15;
impl AesSecurityPolicy for Basic128Rsa15 {
    const SECURITY_POLICY: &str = "Basic128Rsa15";
    const SECURITY_POLICY_URI: &str = "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15";
    const DEPRECATED: bool = true;
    const NONCE_LENGTH: usize = 16;

    const DERIVED_SIGNATURE_KEY_LENGTH: usize = 16;
    const ASYMMETRIC_KEY_LENGTH: (usize, usize) = (1024, 2048);

    type AsymmetricSignature = DsigRsaSha1;
    type SymmetricSignature = DsigHmacSha1;
    type SymmetricEncryption = Aes128Cbc;
    type AsymmetricEncryption = Pkcs1v15;
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
pub(crate) struct Basic256;
impl AesSecurityPolicy for Basic256 {
    const SECURITY_POLICY: &str = "Basic256";
    const SECURITY_POLICY_URI: &str = "http://opcfoundation.org/UA/SecurityPolicy#Basic256";
    const DEPRECATED: bool = true;
    const NONCE_LENGTH: usize = 32;

    const DERIVED_SIGNATURE_KEY_LENGTH: usize = 24;
    const ASYMMETRIC_KEY_LENGTH: (usize, usize) = (1024, 2048);

    type AsymmetricSignature = DsigRsaSha1;
    type SymmetricSignature = DsigHmacSha1;
    type SymmetricEncryption = Aes256Cbc;
    type AsymmetricEncryption = OaepSha1;
}

#[cfg(test)]
mod tests {
    use crate::{policy::SecureChannelRole, random, AesDerivedKeys, AesKey, SecurityPolicy};

    #[test]
    fn aes_test() {
        // Create a random 128-bit key
        let mut raw_key = [0u8; 16];
        random::bytes(&mut raw_key);

        // Create a random iv.
        let mut iv = [0u8; 16];
        random::bytes(&mut iv);

        let aes_key = AesKey::new(raw_key.to_vec());

        let keys = AesDerivedKeys {
            signing_key: [0u8; 16].to_vec(),
            encryption_key: aes_key,
            initialization_vector: iv.to_vec(),
        };

        let policy = SecurityPolicy::Basic128Rsa15;

        let plaintext = b"01234567890123450123456789012345";
        let buf_size = plaintext.len() + policy.plain_block_size();
        let mut ciphertext = vec![0u8; buf_size];

        let ciphertext = {
            println!(
                "Plaintext = {}, ciphertext = {}",
                plaintext.len(),
                ciphertext.len()
            );
            let r = policy.symmetric_encrypt(&keys, plaintext, &mut ciphertext);
            println!("result = {r:?}");
            assert!(r.is_ok());
            &ciphertext[..r.unwrap()]
        };

        let buf_size = ciphertext.len() + policy.plain_block_size();
        let mut plaintext2 = vec![0u8; buf_size];

        let plaintext2 = {
            let r = policy.symmetric_decrypt(&keys, ciphertext, &mut plaintext2);
            println!("result = {r:?}");
            assert!(r.is_ok());
            &plaintext2[..r.unwrap()]
        };

        assert_eq!(&plaintext[..], plaintext2);
    }
}
