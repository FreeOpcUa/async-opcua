//! RSA-OAEP helpers for identity-token encrypted secrets.

use opcua_types::{status_code::StatusCode, Error};

use crate::{
    policy::aes::{AesAsymmetricEncryptionAlgorithm, OaepSha1, OaepSha256},
    KeySize, PrivateKey,
};

/// Decrypts an RSA-OAEP encrypted identity secret.
///
/// # Errors
///
/// Returns an error if the algorithm is unsupported, the ciphertext is missing
/// or malformed, or RSA decryption fails.
pub fn decrypt_rsa_oaep_secret(
    encryption_algorithm: &str,
    encrypted_secret: &[u8],
    server_key: &PrivateKey,
) -> Result<Vec<u8>, Error> {
    match encryption_algorithm {
        crate::algorithms::ENC_RSA_OAEP => {
            decrypt_with_padding::<OaepSha1>(encrypted_secret, server_key)
        }
        crate::algorithms::ENC_RSA_OAEP_SHA256 => {
            decrypt_with_padding::<OaepSha256>(encrypted_secret, server_key)
        }
        algorithm => Err(Error::new(
            StatusCode::BadIdentityTokenInvalid,
            format!("unsupported RSA-OAEP encryption algorithm {algorithm}"),
        )),
    }
}

fn decrypt_with_padding<T: AesAsymmetricEncryptionAlgorithm>(
    encrypted_secret: &[u8],
    server_key: &PrivateKey,
) -> Result<Vec<u8>, Error> {
    let block_size = server_key.cipher_text_block_size();
    if encrypted_secret.is_empty() {
        return Err(Error::new(
            StatusCode::BadIdentityTokenInvalid,
            "missing encrypted secret",
        ));
    }
    if !encrypted_secret.len().is_multiple_of(block_size) {
        return Err(Error::new(
            StatusCode::BadIdentityTokenInvalid,
            "encrypted secret length is not a complete RSA block",
        ));
    }

    let mut plaintext = vec![0u8; encrypted_secret.len()];
    let plaintext_len = server_key
        .private_decrypt::<T>(encrypted_secret, &mut plaintext)
        .map_err(|_| {
            Error::new(
                StatusCode::BadIdentityTokenInvalid,
                "failed to decrypt encrypted secret",
            )
        })?;
    plaintext.truncate(plaintext_len);

    Ok(plaintext)
}
