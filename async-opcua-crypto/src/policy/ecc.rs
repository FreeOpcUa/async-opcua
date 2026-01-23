use std::marker::PhantomData;

use ecdsa::{
    hazmat::DigestAlgorithm,
    signature::{Signer, Verifier},
    EcdsaCurve, PrimeCurve, Signature, SignatureSize, SigningKey, VerifyingKey,
};
use elliptic_curve::{array::ArraySize, CurveArithmetic, PublicKey};
use opcua_types::{Error, StatusCode};
use spki::{DecodePublicKey, EncodePublicKey};

use crate::{
    aes::diffie_hellman::EccDiffieHellman,
    policy::{
        aes::{AesSymmetricEncryptionAlgorithm, AesSymmetricSignatureAlgorithm},
        minimum_padding, SecureChannelRole, SecurityPolicyImpl,
    },
    AesDerivedKeys, PaddingInfo,
};

pub(crate) trait EccSecurityPolicy {
    type TCurve: CurveArithmetic + PrimeCurve + EcdsaCurve + DigestAlgorithm;

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

    const ASYMMETRIC_SIGNATURE_ALGORITHM: &'static str;

    type SymmetricEncryption: AesSymmetricEncryptionAlgorithm;
    type SymmetricSignature: AesSymmetricSignatureAlgorithm;
}

struct EccPolicy<T>(PhantomData<T>);

impl<T: EccSecurityPolicy + 'static> SecurityPolicyImpl for EccPolicy<T>
where
    // <T::TCurve as CurveArithmetic>::Scalar: SignPrimitive<T::TCurve>,
    // <T::TCurve as CurveArithmetic>::AffinePoint: VerifyPrimitive<T::TCurve>,
    SignatureSize<T::TCurve>: ArraySize,
    PublicKey<T::TCurve>: DecodePublicKey + EncodePublicKey,
{
    type TPrivateKey = elliptic_curve::SecretKey<T::TCurve>;
    type TPublicKey = elliptic_curve::PublicKey<T::TCurve>;

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

    fn calculate_cipher_text_size(plain_text_size: usize, _key: &Self::TPublicKey) -> usize {
        // No asymmetric encryption for ECC policies
        plain_text_size
    }

    fn asymmetric_signature_algorithm() -> &'static str {
        T::ASYMMETRIC_SIGNATURE_ALGORITHM
    }

    fn asymmetric_encryption_algorithm() -> Option<&'static str> {
        None
    }

    fn uses_legacy_sequence_numbers() -> bool {
        false
    }

    fn plain_text_block_size() -> usize {
        T::SymmetricEncryption::BLOCK_SIZE
    }

    fn nonce_length() -> usize {
        T::NONCE_LENGTH
    }

    fn symmetric_padding_info() -> super::PaddingInfo {
        PaddingInfo {
            block_size: Self::plain_text_block_size(),
            minimum_padding: minimum_padding(T::SymmetricSignature::SIZE),
        }
    }

    fn asymmetric_padding_info(_remote_key: &Self::TPublicKey) -> super::PaddingInfo {
        // No asymmetric encryption for ECC policies
        PaddingInfo {
            block_size: 1,
            minimum_padding: 0,
        }
    }

    fn asymmetric_sign(
        key: &Self::TPrivateKey,
        src: &[u8],
        signature: &mut [u8],
    ) -> Result<usize, opcua_types::Error> {
        let signing_key: SigningKey<T::TCurve> = SigningKey::from(key);
        let raw_signature = Signer::<Signature<T::TCurve>>::try_sign(&signing_key, src)
            .map_err(|e| Error::new(StatusCode::BadInternalError, e))?;
        let raw_bytes = raw_signature.to_bytes();
        let bytes = raw_bytes.as_ref();
        signature.copy_from_slice(bytes);

        Ok(bytes.len())
    }

    fn asymmetric_verify_signature(
        key: &Self::TPublicKey,
        src: &[u8],
        signature: &[u8],
    ) -> Result<(), opcua_types::Error> {
        let verifying_key: VerifyingKey<T::TCurve> = VerifyingKey::from(key);
        let sig = Signature::<T::TCurve>::from_slice(signature)
            .map_err(|e| Error::new(StatusCode::BadInternalError, e))?;
        Verifier::<Signature<T::TCurve>>::verify(&verifying_key, src, &sig)
            .map_err(|e| Error::new(StatusCode::BadSecurityChecksFailed, e))
    }

    fn asymmetric_encrypt(
        _key: &Self::TPublicKey,
        _src: &[u8],
        _dst: &mut [u8],
    ) -> Result<usize, opcua_types::Error> {
        Err(opcua_types::Error::new(
            StatusCode::BadNotImplemented,
            "Asymmetric encryption not implemented for ECC policies",
        ))
    }

    fn asymmetric_decrypt(
        _key: &Self::TPrivateKey,
        _src: &[u8],
        _dst: &mut [u8],
    ) -> Result<usize, opcua_types::Error> {
        Err(opcua_types::Error::new(
            StatusCode::BadNotImplemented,
            "Asymmetric encryption not implemented for ECC policies",
        ))
    }

    fn begin_diffie_hellman_exchange(
        role: SecureChannelRole,
    ) -> Box<dyn crate::aes::diffie_hellman::DiffieHellmanExchange> {
        Box::new(EccDiffieHellman::<T>::new(role))
    }

    fn symmetric_decrypt(
        keys: &AesDerivedKeys,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, Error> {
        T::SymmetricEncryption::validate_args(src, &keys.initialization_vector, dst)?;
        T::SymmetricEncryption::decrypt(&keys.encryption_key, src, &keys.initialization_vector, dst)
    }

    fn symmetric_encrypt(
        keys: &AesDerivedKeys,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, Error> {
        T::SymmetricEncryption::validate_args(src, &keys.initialization_vector, dst)?;
        T::SymmetricEncryption::encrypt(&keys.encryption_key, src, &keys.initialization_vector, dst)
    }

    fn symmetric_sign(
        keys: &AesDerivedKeys,
        data: &[u8],
        signature: &mut [u8],
    ) -> Result<(), Error> {
        T::SymmetricSignature::sign(&keys.signing_key, data, signature)
    }

    fn symmetric_verify_signature(
        keys: &AesDerivedKeys,
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

    fn encrypting_key_length() -> usize {
        T::SymmetricEncryption::KEY_LENGTH
    }

    fn is_valid_key_length(length: usize) -> bool {
        let (min, max) = T::ASYMMETRIC_KEY_LENGTH;
        length >= min && length <= max
    }
}

pub(crate) struct EccNistP384;
impl EccSecurityPolicy for EccNistP384 {
    type TCurve = p384::NistP384;
    const SECURITY_POLICY: &'static str = "ECC-nistP384";
    const SECURITY_POLICY_URI: &'static str =
        "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP384";
    const NONCE_LENGTH: usize = 96;

    /// The length of the derived signature key in bytes.
    const DERIVED_SIGNATURE_KEY_LENGTH: usize = 48;
    /// The length of the asymmetric key in bits.
    const ASYMMETRIC_KEY_LENGTH: (usize, usize) = (384, 384);

    const ASYMMETRIC_SIGNATURE_ALGORITHM: &'static str = crate::algorithms::DSIG_ECDSA_SHA2_384;

    type SymmetricEncryption = crate::policy::aes::Aes256Cbc;
    type SymmetricSignature = crate::policy::aes::DsigHmacSha384;
}

pub(crate) struct EccBrainpoolP256r1;
impl EccSecurityPolicy for EccBrainpoolP256r1 {
    type TCurve = bp256::BrainpoolP256r1;
    const SECURITY_POLICY: &'static str = "ECC-brainpoolP256r1";
    const SECURITY_POLICY_URI: &'static str =
        "http://opcfoundation.org/UA/SecurityPolicy#ECC_brainpoolP256r1";
    const NONCE_LENGTH: usize = 64;

    const DERIVED_SIGNATURE_KEY_LENGTH: usize = 32;
    const ASYMMETRIC_KEY_LENGTH: (usize, usize) = (256, 256);
    const ASYMMETRIC_SIGNATURE_ALGORITHM: &'static str = crate::algorithms::DSIG_ECDSA_SHA2_256;

    type SymmetricEncryption = crate::policy::aes::Aes128Cbc;
    type SymmetricSignature = crate::policy::aes::DsigHmacSha256;
}

#[cfg(test)]
mod tests {
    use crypto_common::Generate;
    use elliptic_curve::ecdh::EphemeralSecret;

    // Temp, validate that EccPolicy<P> for each policy
    // implements SecurityPolicyImpl. There are some extra
    // bounds needed on the impl that we want to check.
    // Once this is actually in use elsewhere this test can be removed.
    #[allow(dead_code)]
    mod test_trait_impl {
        use crate::policy::{
            ecc::{EccBrainpoolP256r1, EccNistP384, EccPolicy},
            SecurityPolicyImpl,
        };

        type PolicyNistP384 = EccPolicy<EccNistP384>;
        type PolicyBrainpoolP256r1 = EccPolicy<EccBrainpoolP256r1>;

        fn _assert_impls() {
            <PolicyNistP384 as SecurityPolicyImpl>::as_str();
            <PolicyBrainpoolP256r1 as SecurityPolicyImpl>::as_str();
        }
    }

    #[test]
    fn test_how_does_diffie_hellman_work() {
        // Test to explain how diffie-hellman works with elliptic curves,
        // and verify our understanding is correct.

        // Each side generates a random ephemeral secret.
        let server_key = EphemeralSecret::<p384::NistP384>::generate_from_rng(&mut rand::rng());
        let client_key = EphemeralSecret::<p384::NistP384>::generate_from_rng(&mut rand::rng());

        // Each side derives the public key from the secret.
        let server_public = server_key.public_key();
        let client_public = client_key.public_key();

        // The public key is sent to the other side, as the respective `nonce` in the open secure channel request/response.
        // Each side then combines their own secret with the other side's public key to derive the shared secret.
        let server_shared = server_key.diffie_hellman(&client_public);
        let client_shared = client_key.diffie_hellman(&server_public);

        // The derived shared secret is the same on both sides, so we can now use it to derive symmetric keys.
        // The resulting symmetric keys are _not_ the same, as each side uses a different salt,
        // however both parties are able to derive keys for both sides of the channel, which we need
        // for signing and encrypting messages in both directions.
        assert_eq!(
            server_shared.raw_secret_bytes(),
            client_shared.raw_secret_bytes()
        );
    }
}
