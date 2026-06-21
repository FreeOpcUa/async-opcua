// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0

//! Independent tests for the ECC EphemeralKey signing/verification (OPC UA Part 4 §7.15 /
//! Part 6 §6.8.2). Authored separately from the production implementation (verification division),
//! anchored to §7.15: the signature is calculated over the EphemeralKey **publicKey bytes** using the
//! ApplicationInstanceCertificate's key and the policy's asymmetric signature algorithm, and is
//! verified with the signer's certificate.

use crate::ecc::{
    encode_public_key, generate_ephemeral_keypair, sign_ephemeral_public_key,
    verify_ephemeral_public_key, EccCurve,
};
use crate::{PrivateKey, SecurityPolicy, X509Data, X509};

fn ec_cert(curve: EccCurve) -> (X509, PrivateKey) {
    let data = X509Data {
        key_size: 0, // ignored for EC
        common_name: "async-opcua ecc test".to_string(),
        organization: "test".to_string(),
        organizational_unit: "test".to_string(),
        country: "IE".to_string(),
        state: "test".to_string(),
        alt_host_names: vec!["urn:async-opcua-test".to_string(), "localhost".to_string()].into(),
        certificate_duration_days: 60,
    };
    X509::cert_and_pkey_ecc(curve, &data).expect("generate EC self-signed test certificate")
}

/// §7.15: an EphemeralKey publicKey signed with the application-instance EC key verifies against the
/// corresponding certificate; a tampered key or signature is rejected.
#[test]
fn ephemeral_public_key_signature_roundtrips_and_rejects_tamper() {
    for (curve, policy) in [
        (EccCurve::P256, SecurityPolicy::EccNistP256),
        (EccCurve::P384, SecurityPolicy::EccNistP384),
    ] {
        let (cert, key) = ec_cert(curve);
        let keypair = generate_ephemeral_keypair(curve).expect("ephemeral keypair");
        let public_key =
            encode_public_key(keypair.public_key()).expect("encode ephemeral public key");

        let signature = sign_ephemeral_public_key(policy, &key, &public_key)
            .expect("sign ephemeral public key");
        verify_ephemeral_public_key(policy, &cert, &public_key, &signature)
            .expect("a validly-signed EphemeralKey publicKey must verify against the signer cert");

        // Tampered public key -> reject.
        let mut tampered_key = public_key.clone();
        tampered_key[0] ^= 0x01;
        assert!(
            verify_ephemeral_public_key(policy, &cert, &tampered_key, &signature).is_err(),
            "a tampered EphemeralKey publicKey must be rejected"
        );

        // Tampered signature -> reject.
        let mut tampered_sig = signature.clone();
        let last = tampered_sig.len() - 1;
        tampered_sig[last] ^= 0x01;
        assert!(
            verify_ephemeral_public_key(policy, &cert, &public_key, &tampered_sig).is_err(),
            "a tampered EphemeralKey signature must be rejected"
        );
    }
}
