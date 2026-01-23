use opcua_types::{Error, StatusCode};

use crate::{random, AesDerivedKeys};

pub struct AesKeypair {
    pub local: AesDerivedKeys,
    pub remote: AesDerivedKeys,
}

/// Trait for performing a Diffie-Hellman key exchange to derive AES keys.
pub trait DiffieHellmanExchange: Send + Sync {
    /// Get the local nonce (public key or random bytes) to send to the other party.
    fn get_local_nonce(&self) -> Vec<u8>;

    /// For testing, set the local nonce to a specific value.
    /// This is not supported for ECC.
    fn set_local_nonce(&mut self, local_nonce: &[u8]);

    /// Derive the AES keypair from the remote nonce (public key or random bytes).
    fn derive_keypair(&self, remote_nonce: &[u8]) -> Result<AesKeypair, Error>;
}

mod ecc {
    use crypto_common::Generate;
    use elliptic_curve::{
        ecdh::{EphemeralSecret, SharedSecret},
        PublicKey,
    };
    use opcua_types::{Error, StatusCode};
    use spki::{DecodePublicKey, EncodePublicKey};

    use crate::{
        aes::diffie_hellman::DiffieHellmanExchange,
        policy::{aes::AesSymmetricEncryptionAlgorithm, ecc::EccSecurityPolicy},
        AesDerivedKeys, AesKey, SecureChannelRole,
    };

    pub(crate) struct EccDiffieHellman<T: EccSecurityPolicy> {
        ephemeral_key: EphemeralSecret<T::TCurve>,
        role: SecureChannelRole,
    }

    impl<T: EccSecurityPolicy> EccDiffieHellman<T> {
        pub(crate) fn new(role: SecureChannelRole) -> Self {
            let ephemeral_key = EphemeralSecret::generate_from_rng(&mut rand::rng());
            Self {
                ephemeral_key,
                role,
            }
        }

        fn derive_channel_keys(
            &self,
            role: SecureChannelRole,
            shared_secret: &SharedSecret<T::TCurve>,
            local_nonce: &[u8],
            remote_nonce: &[u8],
        ) -> Result<AesDerivedKeys, Error> {
            let required_length = T::DERIVED_SIGNATURE_KEY_LENGTH
                + T::SymmetricEncryption::KEY_LENGTH
                + T::SymmetricEncryption::IV_LENGTH;

            let salt_length = std::mem::size_of::<u16>()
                + 11 // Length of opcua-client and opcua-server.
                + local_nonce.len()
                + remote_nonce.len();

            let mut salt = vec![0u8; salt_length];
            let bytes = (required_length as u16).to_le_bytes();
            salt.copy_from_slice(&bytes);
            match role {
                SecureChannelRole::Client => salt.copy_from_slice(b"opcua-client"),
                SecureChannelRole::Server => salt.copy_from_slice(b"opcua-server"),
            }
            salt.copy_from_slice(local_nonce);
            salt.copy_from_slice(remote_nonce);

            let raw = shared_secret
            .extract::<<T::SymmetricEncryption as AesSymmetricEncryptionAlgorithm>::DigestMethod>(
            Some(&salt),
        );

            let mut data = vec![0u8; required_length];
            raw.expand(&salt, &mut data)
                .map_err(|e| Error::new(StatusCode::BadInternalError, e))?;
            Ok(AesDerivedKeys {
                signing_key: data[0..T::DERIVED_SIGNATURE_KEY_LENGTH].to_vec(),
                encryption_key: AesKey::new(
                    data[T::DERIVED_SIGNATURE_KEY_LENGTH
                        ..(T::DERIVED_SIGNATURE_KEY_LENGTH + T::SymmetricEncryption::KEY_LENGTH)]
                        .to_vec(),
                ),
                initialization_vector: data
                    [(T::DERIVED_SIGNATURE_KEY_LENGTH + T::SymmetricEncryption::KEY_LENGTH)..]
                    .to_vec(),
            })
        }
    }

    impl<T: EccSecurityPolicy + 'static> DiffieHellmanExchange for EccDiffieHellman<T>
    where
        PublicKey<T::TCurve>: EncodePublicKey + DecodePublicKey,
    {
        fn get_local_nonce(&self) -> Vec<u8> {
            self.ephemeral_key
                .public_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes()
                .to_vec()
        }

        fn set_local_nonce(&mut self, _local_nonce: &[u8]) {
            // For security, the elliptic-curves crate doesn't actually allow setting this value at all.
            panic!("Setting local nonce is not supported for ECC Diffie-Hellman");
        }

        fn derive_keypair(&self, remote_nonce: &[u8]) -> Result<super::AesKeypair, Error> {
            let shared_secret = self.ephemeral_key.diffie_hellman(
                &PublicKey::<T::TCurve>::from_public_key_der(remote_nonce).map_err(|e| {
                    Error::new(
                        StatusCode::BadSecurityChecksFailed,
                        format!("Invalid public key DER: {}", e),
                    )
                })?,
            );

            let local_nonce = self.get_local_nonce();
            let local_keys =
                self.derive_channel_keys(self.role, &shared_secret, &local_nonce, remote_nonce)?;
            let remote_keys = self.derive_channel_keys(
                self.role.opposite(),
                &shared_secret,
                remote_nonce,
                &local_nonce,
            )?;
            Ok(super::AesKeypair {
                local: local_keys,
                remote: remote_keys,
            })
        }
    }
}

pub(crate) use ecc::EccDiffieHellman;

mod rsa {
    use opcua_types::Error;

    use crate::{
        policy::aes::{
            AesAsymmetricSignatureAlgorithm, AesSecurityPolicy, AesSymmetricEncryptionAlgorithm,
        },
        random, AesDerivedKeys, AesKey,
    };

    pub(crate) struct RsaDiffieHellman<T: AesSecurityPolicy> {
        _marker: std::marker::PhantomData<fn() -> T>,
        local_nonce: Vec<u8>,
    }

    impl<T: AesSecurityPolicy> RsaDiffieHellman<T> {
        pub(crate) fn new() -> Self {
            let mut nonce = vec![0u8; T::NONCE_LENGTH];
            random::bytes(&mut nonce);
            Self {
                _marker: std::marker::PhantomData,
                local_nonce: nonce,
            }
        }

        fn derive_channel_keys(&self, secret: &[u8], seed: &[u8]) -> AesDerivedKeys {
            let required_length = T::DERIVED_SIGNATURE_KEY_LENGTH
                + T::SymmetricEncryption::KEY_LENGTH
                + T::SymmetricEncryption::IV_LENGTH;

            let data = T::AsymmetricSignature::prf(secret, seed, required_length);
            AesDerivedKeys {
                signing_key: data[0..T::DERIVED_SIGNATURE_KEY_LENGTH].to_vec(),
                encryption_key: AesKey::new(
                    data[T::DERIVED_SIGNATURE_KEY_LENGTH
                        ..(T::DERIVED_SIGNATURE_KEY_LENGTH + T::SymmetricEncryption::KEY_LENGTH)]
                        .to_vec(),
                ),
                initialization_vector: data
                    [(T::DERIVED_SIGNATURE_KEY_LENGTH + T::SymmetricEncryption::KEY_LENGTH)..]
                    .to_vec(),
            }
        }
    }

    impl<T: AesSecurityPolicy + 'static> super::DiffieHellmanExchange for RsaDiffieHellman<T> {
        fn get_local_nonce(&self) -> Vec<u8> {
            self.local_nonce.clone()
        }

        fn set_local_nonce(&mut self, local_nonce: &[u8]) {
            self.local_nonce = local_nonce.to_vec();
        }

        fn derive_keypair(&self, remote_nonce: &[u8]) -> Result<super::AesKeypair, Error> {
            let local_keys = self.derive_channel_keys(remote_nonce, &self.local_nonce);
            let remote_keys = self.derive_channel_keys(&self.local_nonce, remote_nonce);
            Ok(super::AesKeypair {
                local: local_keys,
                remote: remote_keys,
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use crate::{
            aes::diffie_hellman::RsaDiffieHellman, policy::aes::Basic128Rsa15, AesDerivedKeys,
            DiffieHellmanExchange, SecureChannelRole, SecurityPolicy,
        };

        #[test]
        fn derive_keys_from_nonce() {
            // Create a pair of "random" nonces.
            let nonce = vec![
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
                0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
                0x3c, 0x3d, 0x3e, 0x3f,
            ];

            fn make_secure_channel_keys(
                policy: SecurityPolicy,
                remote_nonce: &[u8],
            ) -> AesDerivedKeys {
                let exchange = policy.begin_diffie_hellman_exchange(SecureChannelRole::Client);
                exchange.derive_keypair(remote_nonce).unwrap().local
            }

            // Create a security policy Basic128Rsa15 policy
            //
            // a) SigningKeyLength = 16
            // b) EncryptingKeyLength = 16
            // c) EncryptingBlockSize = 16
            let security_policy = SecurityPolicy::Basic128Rsa15;
            let keys = make_secure_channel_keys(security_policy, &nonce);
            assert_eq!(keys.signing_key.len(), 16);
            assert_eq!(keys.encryption_key.value().len(), 16);
            assert_eq!(keys.initialization_vector.len(), 16);

            // Create a security policy Basic256 policy
            //
            // a) SigningKeyLength = 24
            // b) EncryptingKeyLength = 32
            // c) EncryptingBlockSize = 16
            let security_policy = SecurityPolicy::Basic256;
            let keys = make_secure_channel_keys(security_policy, &nonce);
            assert_eq!(keys.signing_key.len(), 24);
            assert_eq!(keys.encryption_key.value().len(), 32);
            assert_eq!(keys.initialization_vector.len(), 16);

            // Create a security policy Basic256Sha256 policy
            //
            // a) SigningKeyLength = 32
            // b) EncryptingKeyLength = 32
            // c) EncryptingBlockSize = 16
            let security_policy = SecurityPolicy::Basic256Sha256;
            let keys = make_secure_channel_keys(security_policy, &nonce);
            assert_eq!(keys.signing_key.len(), 32);
            assert_eq!(keys.encryption_key.value().len(), 32);
            assert_eq!(keys.initialization_vector.len(), 16);

            // Create a security policy Aes128Sha256RsaOaep policy
            //
            // a) SigningKeyLength = 32
            // b) EncryptingKeyLength = 32
            // c) EncryptingBlockSize = 16
            let security_policy = SecurityPolicy::Aes128Sha256RsaOaep;
            let keys = make_secure_channel_keys(security_policy, &nonce);
            assert_eq!(keys.signing_key.len(), 32);
            assert_eq!(keys.encryption_key.value().len(), 16);
            assert_eq!(keys.initialization_vector.len(), 16);
        }

        #[test]
        fn derive_keys_from_nonce_basic128rsa15() {
            // This test takes two nonces generated from a real client / server session
            let local_nonce = vec![
                0x88, 0x65, 0x13, 0xb6, 0xee, 0xad, 0x68, 0xa2, 0xcb, 0xa7, 0x29, 0x0f, 0x79, 0xb3,
                0x84, 0xf3,
            ];
            let remote_nonce = vec![
                0x17, 0x0c, 0xe8, 0x68, 0x3e, 0xe6, 0xb3, 0x80, 0xb3, 0xf4, 0x67, 0x5c, 0x1e, 0xa2,
                0xcc, 0xb1,
            ];

            // Expected local keys
            let local_signing_key: Vec<u8> = vec![
                0x66, 0x58, 0xa5, 0xa7, 0x8c, 0x7d, 0xa8, 0x4e, 0x57, 0xd3, 0x9b, 0x4d, 0x6b, 0xdc,
                0x93, 0xad,
            ];
            let local_encrypting_key: Vec<u8> = vec![
                0x44, 0x8f, 0x0d, 0x7d, 0x2e, 0x08, 0x99, 0xdd, 0x5b, 0x56, 0x8d, 0xaf, 0x70, 0xc2,
                0x26, 0xfc,
            ];
            let local_iv = vec![
                0x6c, 0x83, 0x7c, 0xd1, 0xa8, 0x61, 0xb9, 0xd7, 0xae, 0xdf, 0x2d, 0xe4, 0x85, 0x26,
                0x81, 0x89,
            ];

            // Expected remote keys
            let remote_signing_key: Vec<u8> = vec![
                0x27, 0x23, 0x92, 0xb7, 0x47, 0xad, 0x48, 0xf6, 0xae, 0x20, 0x30, 0x2f, 0x88, 0x4f,
                0x96, 0x40,
            ];
            let remote_encrypting_key: Vec<u8> = vec![
                0x85, 0x84, 0x1c, 0xcc, 0xcb, 0x3c, 0x39, 0xd4, 0x14, 0x11, 0xa4, 0xfe, 0x01, 0x5a,
                0x0a, 0xcf,
            ];
            let remote_iv = vec![
                0xab, 0xc6, 0x26, 0x78, 0xb9, 0xa4, 0xe6, 0x93, 0x21, 0x9e, 0xc1, 0x7e, 0xd5, 0x8b,
                0x0e, 0xf2,
            ];

            let mut exchange = RsaDiffieHellman::<Basic128Rsa15>::new();
            exchange.local_nonce = local_nonce.clone();

            let keypair = exchange.derive_keypair(&remote_nonce).unwrap();

            // Make the keys using the two nonce values
            let local_keys = keypair.local;
            let remote_keys = keypair.remote;

            // Compare the keys we received against the expected
            assert_eq!(local_keys.signing_key, local_signing_key);
            assert_eq!(
                local_keys.encryption_key.value().to_vec(),
                local_encrypting_key
            );
            assert_eq!(local_keys.initialization_vector, local_iv);

            assert_eq!(remote_keys.signing_key, remote_signing_key);
            assert_eq!(
                remote_keys.encryption_key.value().to_vec(),
                remote_encrypting_key
            );
            assert_eq!(remote_keys.initialization_vector, remote_iv);
        }
    }
}

pub(crate) use rsa::RsaDiffieHellman;

pub(crate) struct NoneDiffieHellman {
    local_nonce: Vec<u8>,
}

impl NoneDiffieHellman {
    pub(crate) fn new() -> Self {
        let mut nonce = vec![0u8; 32];
        random::bytes(&mut nonce);
        Self { local_nonce: nonce }
    }
}

impl DiffieHellmanExchange for NoneDiffieHellman {
    fn get_local_nonce(&self) -> Vec<u8> {
        self.local_nonce.clone()
    }

    fn set_local_nonce(&mut self, local_nonce: &[u8]) {
        self.local_nonce = local_nonce.to_vec();
    }

    fn derive_keypair(&self, _remote_nonce: &[u8]) -> Result<AesKeypair, Error> {
        Err(Error::new(
            StatusCode::BadSecurityChecksFailed,
            "Diffie-Hellman exchange not supported for None security policy",
        ))
    }
}
