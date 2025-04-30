// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Functions related to encrypting / decrypting passwords in a UserNameIdentityToken.
//!
//! The code here determines how or if to encrypt the password depending on the security policy
//! and user token policy.

use std::io::{Cursor, Write};
use std::str::FromStr;

use opcua_types::{
    encoding::{read_u32, write_u32},
    status_code::StatusCode,
    ByteString, UAString,
    {SignatureData, UserNameIdentityToken, UserTokenPolicy, X509IdentityToken},
};
use opcua_types::{Error, IssuedIdentityToken, MessageSecurityMode};
use tracing::{error, warn};

use super::{KeySize, PrivateKey, RsaPadding, SecurityPolicy, X509};

/// Trait for a type with a secret encrypted with legacy secret encryption.
pub trait LegacySecret {
    /// The raw encrypted secret.
    fn raw_secret(&self) -> &ByteString;
    /// The encryption algorithm used to encrypt the secret.
    fn encryption_algorithm(&self) -> &UAString;
}

impl LegacySecret for UserNameIdentityToken {
    fn raw_secret(&self) -> &ByteString {
        &self.password
    }

    fn encryption_algorithm(&self) -> &UAString {
        &self.encryption_algorithm
    }
}

impl LegacySecret for IssuedIdentityToken {
    fn raw_secret(&self) -> &ByteString {
        &self.token_data
    }

    fn encryption_algorithm(&self) -> &UAString {
        &self.encryption_algorithm
    }
}

impl LegacySecret for LegacyEncryptedSecret {
    fn raw_secret(&self) -> &ByteString {
        &self.secret
    }

    fn encryption_algorithm(&self) -> &UAString {
        &self.encryption_algorithm
    }
}

/// Decrypt a legacy secret using the server's nonce and private key.
pub fn legacy_decrypt_secret(
    secret: &impl LegacySecret,
    server_nonce: &[u8],
    server_key: &PrivateKey,
) -> Result<ByteString, Error> {
    if secret.encryption_algorithm().is_empty() {
        Ok(secret.raw_secret().clone())
    } else {
        // Determine the padding from the algorithm.
        let encryption_algorithm = secret.encryption_algorithm().as_ref();
        let padding = match encryption_algorithm {
            super::algorithms::ENC_RSA_15 => RsaPadding::Pkcs1,
            super::algorithms::ENC_RSA_OAEP => RsaPadding::OaepSha1,
            super::algorithms::ENC_RSA_OAEP_SHA256 => RsaPadding::OaepSha256,
            r => {
                error!("decrypt_user_identity_token_password has rejected unsupported user identity encryption algorithm \"{}\"", encryption_algorithm);
                return Err(Error::new(
                    StatusCode::BadIdentityTokenInvalid,
                    format!("Identity token rejected, unsupported encryption algorithm {r}"),
                ));
            }
        };
        legacy_secret_decrypt(secret.raw_secret(), server_nonce, server_key, padding)
    }
}

/// A generic legacy encrypted secret.
pub struct LegacyEncryptedSecret {
    /// The user token policy the encrypted secret conforms to.
    pub policy: UAString,
    /// The encrypted secret.
    pub secret: ByteString,
    /// The encryption algorithm used to encrypt the secret.
    pub encryption_algorithm: UAString,
}

enum EncryptionMode {
    None,
    AsymmetricFor(SecurityPolicy),
}

/// Encrypt a client side user's password using the server nonce and cert.
/// This is described in part 4, 7.41 of the OPC-UA standard.
pub fn legacy_encrypt_secret(
    channel_security_policy: SecurityPolicy,
    channel_security_mode: MessageSecurityMode,
    user_token_policy: &UserTokenPolicy,
    nonce: &[u8],
    cert: &Option<X509>,
    secret_to_encrypt: &[u8],
) -> Result<LegacyEncryptedSecret, Error> {
    let token_security_policy = if user_token_policy.security_policy_uri.is_empty() {
        None
    } else {
        Some(SecurityPolicy::from_str(user_token_policy.security_policy_uri.as_ref()).unwrap())
    };

    // This is an implementation of Table 193 in OPC-UA Part 4, 7.41
    let encryption_mode = match (
        channel_security_policy,
        channel_security_mode,
        token_security_policy,
    ) {
        // Check for unknown security policies
        (_, _, Some(SecurityPolicy::Unknown)) | (SecurityPolicy::Unknown, _, _) => {
            // Unknown security policy is not allowed
            return Err(Error::new(
                StatusCode::BadSecurityPolicyRejected,
                "Unknown user token security policy",
            ));
        }

        // Table implementation begins here
        (SecurityPolicy::None, MessageSecurityMode::None, Some(SecurityPolicy::None) | None) => {
            EncryptionMode::None
        }
        (SecurityPolicy::None, MessageSecurityMode::None, Some(p)) => {
            EncryptionMode::AsymmetricFor(p)
        }
        (p, MessageSecurityMode::Sign | MessageSecurityMode::SignAndEncrypt, None) => {
            EncryptionMode::AsymmetricFor(p)
        }
        (_, MessageSecurityMode::SignAndEncrypt, Some(SecurityPolicy::None)) => {
            EncryptionMode::None
        }
        (_, MessageSecurityMode::Sign, Some(SecurityPolicy::None)) => {
            return Err(Error::new(
                StatusCode::BadSecurityPolicyRejected,
                "User token policy security policy is None but message security mode is Sign",
            ))
        }
        (_, MessageSecurityMode::Sign | MessageSecurityMode::SignAndEncrypt, Some(p)) => {
            EncryptionMode::AsymmetricFor(p)
        }
        // Check for invalid message security modes
        (_, MessageSecurityMode::None | MessageSecurityMode::Invalid, _) => {
            return Err(Error::new(
                StatusCode::BadSecurityChecksFailed,
                "Invalid message security mode",
            ));
        }
    };

    match encryption_mode {
        EncryptionMode::None => {
            if matches!(channel_security_policy, SecurityPolicy::None)
                || matches!(
                    channel_security_mode,
                    MessageSecurityMode::None | MessageSecurityMode::Sign
                )
            {
                warn!("A user identity's password is being sent over the network in plain text. This could be a serious security issue");
            }
            Ok(LegacyEncryptedSecret {
                secret: ByteString::from(secret_to_encrypt),
                encryption_algorithm: UAString::null(),
                policy: user_token_policy.policy_id.clone(),
            })
        }
        EncryptionMode::AsymmetricFor(security_policy) => {
            let password = legacy_secret_encrypt(
                secret_to_encrypt,
                nonce,
                cert.as_ref().unwrap(),
                security_policy
                    .asymmetric_encryption_padding()
                    .ok_or_else(|| {
                        Error::new(
                            StatusCode::BadSecurityPolicyRejected,
                            "Security policy does not support asymmetric encryption",
                        )
                    })?,
            )?;

            Ok(LegacyEncryptedSecret {
                secret: password,
                encryption_algorithm: UAString::from(
                    security_policy
                        .asymmetric_encryption_algorithm()
                        .ok_or_else(|| {
                            Error::new(
                                StatusCode::BadSecurityPolicyRejected,
                                "Security policy does not support asymmetric encryption",
                            )
                        })?,
                ),
                policy: user_token_policy.policy_id.clone(),
            })
        }
    }
}

/// Encrypt a client side user's password using the server nonce and cert. This is described in table 176
/// OPC UA part 4. This function is prefixed "legacy" because 1.04 describes another way of encrypting passwords.
pub(crate) fn legacy_secret_encrypt(
    password: &[u8],
    server_nonce: &[u8],
    server_cert: &X509,
    padding: RsaPadding,
) -> Result<ByteString, Error> {
    // Message format is size, password, nonce
    let plaintext_size = 4 + password.len() + server_nonce.len();
    let mut src = Cursor::new(vec![0u8; plaintext_size]);

    // Write the length of the data to be encrypted excluding the length itself)
    write_u32(&mut src, (plaintext_size - 4) as u32)?;
    src.write(password).map_err(Error::decoding)?;
    src.write(server_nonce).map_err(Error::decoding)?;

    // Encrypt the data with the public key from the server's certificate
    let public_key = server_cert.public_key()?;

    let cipher_size = public_key.calculate_cipher_text_size(plaintext_size, padding);
    let mut dst = vec![0u8; cipher_size];
    let actual_size = public_key
        .public_encrypt(&src.into_inner(), &mut dst, padding)
        .map_err(Error::decoding)?;

    assert_eq!(actual_size, cipher_size);

    Ok(ByteString::from(dst))
}

/// Decrypt the client's password using the server's nonce and private key. This function is prefixed
/// "legacy" because 1.04 describes another way of encrypting passwords.
pub(crate) fn legacy_secret_decrypt(
    secret: &ByteString,
    server_nonce: &[u8],
    server_key: &PrivateKey,
    padding: RsaPadding,
) -> Result<ByteString, Error> {
    if secret.is_null() {
        Err(Error::decoding("Missing server secret"))
    } else {
        // Decrypt the message
        let src = secret.value.as_ref().unwrap();
        let mut dst = vec![0u8; src.len()];
        let mut actual_size = server_key
            .private_decrypt(src, &mut dst, padding)
            .map_err(Error::decoding)?;

        let mut dst = Cursor::new(dst);
        let plaintext_size = read_u32(&mut dst)? as usize;

        /* Remove padding
         *
         * 7.36.2.2 Legacy Encrypted Token Secret Format: A Client should not add any
         * padding after the secret. If a Client adds padding then all bytes shall
         * be zero. A Server shall check for padding added by Clients and ensure
         * that all padding bytes are zeros.
         *
         */
        let mut dst = dst.into_inner();
        if actual_size > plaintext_size + 4 {
            let padding_bytes = &dst[plaintext_size + 4..];
            /*
             * If the Encrypted Token Secret contains padding, the padding must be
             * zeroes according to the 1.04.1 specification errata, chapter 3.
             */
            if !padding_bytes.iter().all(|&x| x == 0) {
                return Err(Error::decoding(
                    "Non-zero padding bytes in decrypted password",
                ));
            } else {
                dst.truncate(plaintext_size + 4);
                actual_size = dst.len();
            }
        }

        if plaintext_size + 4 != actual_size {
            Err(Error::decoding("Invalid plaintext size"))
        } else {
            let nonce_len = server_nonce.len();
            let nonce_begin = actual_size - nonce_len;
            let nonce = &dst[nonce_begin..(nonce_begin + nonce_len)];
            if nonce != server_nonce {
                Err(Error::decoding("Invalid nonce"))
            } else {
                let password = &dst[4..nonce_begin];
                Ok(ByteString::from(password))
            }
        }
    }
}

/// Verify that the X509 identity token supplied to a server contains a valid signature.
pub fn verify_x509_identity_token(
    token: &X509IdentityToken,
    user_token_signature: &SignatureData,
    security_policy: SecurityPolicy,
    server_cert: &X509,
    server_nonce: &[u8],
) -> Result<(), Error> {
    // Since it is not obvious at all from the spec what the user token signature is supposed to be, I looked
    // at the internet for clues:
    //
    // https://stackoverflow.com/questions/46683342/securing-opensecurechannel-messages-and-x509identitytoken
    // https://forum.prosysopc.com/forum/opc-ua/clarification-on-opensecurechannel-messages-and-x509identitytoken-specifications/
    //
    // These suggest that the signature is produced by appending the server nonce to the server certificate
    // and signing with the user certificate's private key.
    //
    // This is the same as the standard handshake between client and server but using the identity cert. It would have been nice
    // if the spec actually said this.

    let signing_cert = super::x509::X509::from_byte_string(&token.certificate_data)?;
    super::verify_signature_data(
        user_token_signature,
        security_policy,
        &signing_cert,
        server_cert,
        server_nonce,
    )
}
