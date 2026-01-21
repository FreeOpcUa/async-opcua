use opcua_types::{constants, Error, StatusCode};

pub(crate) mod aes;

pub use aes::AesDerivedKeys;
pub(crate) use aes::AesPolicy;

use crate::{PrivateKey, PublicKey};

/// Information about padding given by the policy.
pub struct PaddingInfo {
    /// Plain text block size.
    pub block_size: usize,
    /// Minimum padding length.
    pub minimum_padding: usize,
}

/// OPC-UA requires extra padding if the key size is > 2048 bits.
fn minimum_padding(size: usize) -> usize {
    if size <= 256 {
        1
    } else {
        2
    }
}

pub(crate) trait SecurityPolicyImpl {
    /// The type of private key used by this security policy.
    type TPrivateKey;
    /// The type of public key used by this security policy.
    type TPublicKey;
    /// The type of derived key used by this security policy.
    type TDerivedKey;

    /// The OPC-UA security policy URI for this policy.
    fn uri() -> &'static str;

    /// Whether this security policy is deprecated.
    fn is_deprecated() -> bool;

    /// Get the OPC-UA string for this policy.
    fn as_str() -> &'static str;

    /// Get the symmetric signature size in bytes.
    fn symmetric_signature_size() -> usize;

    /// Calculate the cipher text size using the given plain text size and key.
    fn calculate_cipher_text_size(plain_text_size: usize, key: &Self::TPublicKey) -> usize;

    /// Get a string representation of the asymmetric signature algorithm used by this policy.
    fn asymmetric_signature_algorithm() -> &'static str;

    /// Get a string representation of the asymmetric encryption algorithm used by this policy.
    fn asymmetric_encryption_algorithm() -> Option<&'static str>;

    /// Whether this policy uses legacy sequence numbers.
    fn uses_legacy_sequence_numbers() -> bool;

    /// Get the plain text block size used by this policy.
    fn plain_text_block_size() -> usize;

    /// Get the secure channel nonce length used by this policy.
    fn nonce_length() -> usize;

    fn symmetric_padding_info() -> PaddingInfo;

    fn asymmetric_padding_info(remote_key: &Self::TPublicKey) -> PaddingInfo;

    /// Sign the data in `src` using `key`, writing the output to `signature`.
    fn asymmetric_sign(
        key: &Self::TPrivateKey,
        src: &[u8],
        signature: &mut [u8],
    ) -> Result<usize, Error>;

    /// Verify that the data in `src` was signed using the private key for `key`.
    fn asymmetric_verify_signature(
        key: &Self::TPublicKey,
        src: &[u8],
        signature: &[u8],
    ) -> Result<(), Error>;

    /// Asymetrically encrypt the data in `src` using `key`, writing the
    /// result to `dst`.
    fn asymmetric_encrypt(
        key: &Self::TPublicKey,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, Error>;

    /// Asymetrically decrypt the data in `src` using `key`, writing the
    /// result to `dst`.
    fn asymmetric_decrypt(
        key: &Self::TPrivateKey,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, Error>;

    // This will definitely need to change for ECC...
    /// Produce the derived keys for this policy.
    fn derive_secure_channel_keys(secret: &[u8], seed: &[u8]) -> Self::TDerivedKey;

    /// Sign the data in `data` using the signing key in `keys`, writing the result to
    /// `signature`.
    fn symmetric_sign(
        keys: &Self::TDerivedKey,
        data: &[u8],
        signature: &mut [u8],
    ) -> Result<(), Error>;

    /// Verify that the data in `data` was signed using `keys`.
    fn symmetric_verify_signature(
        keys: &Self::TDerivedKey,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), Error>;

    /// Encrypt the data in `src` using `keys`, writing the result to `dst`.
    fn symmetric_encrypt(
        keys: &Self::TDerivedKey,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, Error>;

    /// Decrypt the data in `src` using `keys`, writing the result to `dst`.
    fn symmetric_decrypt(
        keys: &Self::TDerivedKey,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, Error>;

    /// Get the length of the symmetric encryption key, in bytes.
    fn encrypting_key_length() -> usize;

    /// Validate that the given key length is valid.
    fn is_valid_key_length(length: usize) -> bool;
}

/// The OPC-UA None policy, with a stub implementation of `SecurityPolicyImpl`.
pub(crate) struct NonePolicy(());

impl SecurityPolicyImpl for NonePolicy {
    // Temp: In the future we'll want to be generic over this in the
    // secure channel state, which means we could use a zero-sized type here.
    type TPrivateKey = PrivateKey;
    type TPublicKey = PublicKey;
    type TDerivedKey = AesDerivedKeys;

    fn uri() -> &'static str {
        constants::SECURITY_POLICY_NONE_URI
    }

    fn is_deprecated() -> bool {
        false
    }

    fn as_str() -> &'static str {
        constants::SECURITY_POLICY_NONE
    }

    fn asymmetric_encryption_algorithm() -> Option<&'static str> {
        None
    }

    fn asymmetric_signature_algorithm() -> &'static str {
        constants::SECURITY_POLICY_NONE
    }

    fn symmetric_signature_size() -> usize {
        0
    }

    fn uses_legacy_sequence_numbers() -> bool {
        true
    }

    fn nonce_length() -> usize {
        32
    }

    fn plain_text_block_size() -> usize {
        // Not really valid, but strictly speaking the block size for None
        // is 1, since there's no blocks at all.
        1
    }

    fn asymmetric_padding_info(_remote_key: &Self::TPublicKey) -> PaddingInfo {
        PaddingInfo {
            block_size: 0,
            minimum_padding: 0,
        }
    }

    fn symmetric_padding_info() -> PaddingInfo {
        PaddingInfo {
            block_size: 0,
            minimum_padding: 0,
        }
    }

    fn is_valid_key_length(_length: usize) -> bool {
        // Should we do something else here? I don't think we care.
        true
    }

    fn calculate_cipher_text_size(_plain_text_size: usize, _key: &Self::TPublicKey) -> usize {
        panic!("Cannot encrypt using security policy None")
    }

    fn asymmetric_sign(
        _key: &Self::TPrivateKey,
        _data: &[u8],
        _out: &mut [u8],
    ) -> Result<usize, Error> {
        Err(Error::new(
            StatusCode::BadInternalError,
            "Cannot sign using security policy None",
        ))
    }

    fn asymmetric_verify_signature(
        _key: &Self::TPublicKey,
        _data: &[u8],
        _signature: &[u8],
    ) -> Result<(), Error> {
        Err(Error::new(
            StatusCode::BadInternalError,
            "Cannot verify signature using security policy None",
        ))
    }

    fn asymmetric_encrypt(
        _key: &Self::TPublicKey,
        _data: &[u8],
        _out: &mut [u8],
    ) -> Result<usize, Error> {
        Err(Error::new(
            StatusCode::BadInternalError,
            "Cannot encrypt using security policy None",
        ))
    }

    fn asymmetric_decrypt(
        _key: &Self::TPrivateKey,
        _src: &[u8],
        _dst: &mut [u8],
    ) -> Result<usize, Error> {
        Err(Error::new(
            StatusCode::BadInternalError,
            "Cannot decrypt using security policy None",
        ))
    }

    fn derive_secure_channel_keys(_secret: &[u8], _seed: &[u8]) -> Self::TDerivedKey {
        panic!("Cannot derive encryption keys for security policy None")
    }

    fn symmetric_decrypt(
        _keys: &Self::TDerivedKey,
        _src: &[u8],
        _dst: &mut [u8],
    ) -> Result<usize, Error> {
        Err(Error::new(
            StatusCode::BadInternalError,
            "Cannot decrypt using security policy None",
        ))
    }

    fn symmetric_encrypt(
        _keys: &Self::TDerivedKey,
        _src: &[u8],
        _dst: &mut [u8],
    ) -> Result<usize, Error> {
        Err(Error::new(
            StatusCode::BadInternalError,
            "Cannot encrypt using security policy None",
        ))
    }

    fn symmetric_sign(
        _keys: &Self::TDerivedKey,
        _data: &[u8],
        _signature: &mut [u8],
    ) -> Result<(), Error> {
        Err(Error::new(
            StatusCode::BadInternalError,
            "Cannot sign using security policy None",
        ))
    }

    fn symmetric_verify_signature(
        _keys: &Self::TDerivedKey,
        _data: &[u8],
        _signature: &[u8],
    ) -> Result<(), Error> {
        Err(Error::new(
            StatusCode::BadInternalError,
            "Cannot verify signature using security policy None",
        ))
    }

    fn encrypting_key_length() -> usize {
        0
    }
}
