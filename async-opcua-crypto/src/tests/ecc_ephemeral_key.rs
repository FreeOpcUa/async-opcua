// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0

//! Independent tests for the ECC EphemeralKey signing/verification (OPC UA Part 4 §7.15 /
//! Part 6 §6.8.2). Authored separately from the production implementation (verification division),
//! anchored to §7.15: the signature is calculated over the EphemeralKey **publicKey bytes** using the
//! ApplicationInstanceCertificate's key and the policy's asymmetric signature algorithm, and is
//! verified with the signer's certificate.

use crate::ecc::{
    decode_public_key, encode_public_key, generate_ephemeral_keypair, issue_server_ephemeral_key,
    sign_ephemeral_public_key, verify_ephemeral_public_key, EccCurve,
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

/// US1 (FR-001/FR-002): the server issues a signed EphemeralKey for a valid ECC ECDHPolicyUri (the
/// returned EphemeralKeyType verifies against the server cert and its publicKey is the keypair's
/// point); a non-ECC / unknown policy is rejected with Bad_SecurityPolicyRejected.
#[test]
fn issue_server_ephemeral_key_signs_for_ecc_and_rejects_non_ecc() {
    for (curve, policy) in [
        (EccCurve::P256, SecurityPolicy::EccNistP256),
        (EccCurve::P384, SecurityPolicy::EccNistP384),
    ] {
        let (cert, key) = ec_cert(curve);
        let (keypair, ek) =
            issue_server_ephemeral_key(policy.to_uri(), &key).expect("issue EphemeralKey for ECC");

        verify_ephemeral_public_key(policy, &cert, ek.public_key.as_ref(), ek.signature.as_ref())
            .expect("the issued EphemeralKey signature must verify against the server cert");
        let decoded = decode_public_key(curve, ek.public_key.as_ref())
            .expect("the issued publicKey must be a valid curve point");
        assert_eq!(
            decoded.encoded(),
            keypair.public_key().encoded(),
            "the returned EphemeralKeyType.publicKey must match the issued keypair"
        );
    }

    // Non-ECC / unknown ECDHPolicyUri -> Bad_SecurityPolicyRejected (the signing key is unused on
    // this path because the policy is rejected first).
    let (_cert, key) = ec_cert(EccCurve::P256);
    let err = issue_server_ephemeral_key(
        "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
        &key,
    )
    .expect_err("a non-ECC ECDHPolicyUri must be rejected");
    assert_eq!(
        err.status(),
        opcua_types::StatusCode::BadSecurityPolicyRejected
    );
}

/// US2 (FR-003): the client reads the server's ECDHKey from a response header, verifies its signature
/// against the server certificate, and recovers the ephemeral public key; a forged signature is
/// rejected; an absent key yields None.
#[test]
fn client_reads_and_verifies_server_ephemeral_key() {
    use crate::ecc::{
        build_ecdh_key_response, issue_server_ephemeral_key, read_and_verify_server_ephemeral_key,
    };
    use opcua_types::ExtensionObject;

    for (curve, policy) in [
        (EccCurve::P256, SecurityPolicy::EccNistP256),
        (EccCurve::P384, SecurityPolicy::EccNistP384),
    ] {
        let (server_cert, server_key) = ec_cert(curve);
        let (keypair, ek) =
            issue_server_ephemeral_key(policy.to_uri(), &server_key).expect("issue");
        let header = build_ecdh_key_response(ek);

        let recovered = read_and_verify_server_ephemeral_key(&header, policy, &server_cert)
            .expect("a validly-signed ECDHKey must verify")
            .expect("a key is present");
        assert_eq!(
            recovered.encoded(),
            keypair.public_key().encoded(),
            "the recovered server ephemeral public key must match what the server issued"
        );

        // Forged: a different server's cert must fail signature verification.
        let (other_cert, _other_key) = ec_cert(curve);
        assert!(
            read_and_verify_server_ephemeral_key(&header, policy, &other_cert).is_err(),
            "an ECDHKey signed by a different key must be rejected"
        );

        // Absent ECDHKey -> Ok(None).
        assert!(read_and_verify_server_ephemeral_key(
            &ExtensionObject::null(),
            policy,
            &server_cert
        )
        .expect("null header is not an error")
        .is_none());
    }
}
