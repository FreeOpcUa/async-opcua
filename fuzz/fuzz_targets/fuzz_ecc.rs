#![cfg_attr(feature = "nightly", no_main)]

#[cfg(not(feature = "nightly"))]
fn main() {
    panic!("Fuzzing requires the nightly feature to be enabled.");
}

// Fuzz the attacker-controlled ECC OpenSecureChannel decode/verify entry points
// (feature 012, T024). These parse bytes that arrive on the wire — the ephemeral
// public key carried in the nonce and the ECDSA signature — and must NEVER panic,
// only return an error, on malformed input.
#[cfg(feature = "nightly")]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    use opcua::crypto::ecc::{
        decode_public_key, ecdsa_verify, EccCurve, EccPrivateKey, EccPublicKey,
    };

    // First byte selects the curve; the rest is the fuzzed wire payload.
    let curve = if data.first().copied().unwrap_or(0) & 1 == 0 {
        EccCurve::P256
    } else {
        EccCurve::P384
    };
    let body = data.get(1..).unwrap_or(&[]);

    // Ephemeral public key as `X || Y` (the OpenSecureChannel nonce field).
    let _ = decode_public_key(curve, body);

    // Uncompressed SEC1 public key parse.
    let _ = EccPublicKey::from_sec1_bytes(curve, body);

    // ECDSA verification against a fixed, valid key with an attacker-supplied
    // signature/message — exercises the raw r||s signature parser + verifier.
    let scalar_len = if matches!(curve, EccCurve::P256) {
        32
    } else {
        48
    };
    let scalar = vec![1u8; scalar_len];
    if let Ok(private_key) = EccPrivateKey::from_scalar_bytes(curve, &scalar) {
        if let Ok(verifying_key) = private_key.public_key() {
            let _ = ecdsa_verify(&verifying_key, body, body);
        }
    }

    // Feature 015 (T015): the ECC token EphemeralKey exchange (Part 6 §6.8.2) carries
    // `ECDHPolicyUri` / `ECDHKey` in the request/response AdditionalHeader — an attacker-
    // controlled `ExtensionObject`. Decode arbitrary wire bytes into that ExtensionObject and
    // run the reader entry points; a malformed / wrong-inner-type / oversized header must
    // return None/Err, never panic.
    {
        use opcua::crypto::ecc::{read_ecdh_key, read_ecdh_policy_uri};
        use opcua::types::{BinaryDecodable, ContextOwned, ExtensionObject};
        use std::io::Cursor;

        let mut stream = Cursor::new(body);
        let ctx = ContextOwned::default();
        if let Ok(header) = ExtensionObject::decode(&mut stream, &ctx.context()) {
            let _ = read_ecdh_policy_uri(&header);
            let _ = read_ecdh_key(&header);
        }
    }

    // Feature 016 (T023): the server decrypts an attacker-controlled `EccEncryptedSecret`
    // (Part 4 §7.40.2.5) via `ecc_decrypt_secret`. Feed arbitrary bytes as the envelope against a
    // fixed server EphemeralKey + signer cert: any malformed / tampered / wrong input must return
    // the uniform error, never panic.
    {
        use opcua::crypto::ecc::{ecc_decrypt_secret, EccCurve, EphemeralPrivateKey};
        use opcua::crypto::SecurityPolicy;
        use std::sync::OnceLock;

        // Build the fixed P-256 signer cert + server ephemeral key once (cert generation is costly).
        static FIXTURE: OnceLock<Option<(opcua::crypto::X509, EphemeralPrivateKey)>> =
            OnceLock::new();
        let fixture = FIXTURE.get_or_init(|| {
            let data = opcua::crypto::X509Data {
                key_size: 0,
                common_name: "fuzz-ecc".to_string(),
                organization: "f".to_string(),
                organizational_unit: "f".to_string(),
                country: "IE".to_string(),
                state: "f".to_string(),
                alt_host_names: vec!["urn:f".to_string(), "localhost".to_string()].into(),
                certificate_duration_days: 60,
            };
            let cert = opcua::crypto::X509::cert_and_pkey_ecc(EccCurve::P256, &data).ok()?;
            let server = EphemeralPrivateKey::from_scalar_bytes(EccCurve::P256, &[7u8; 32]).ok()?;
            Some((cert.0, server))
        });
        if let Some((signer_cert, server_ephemeral)) = fixture {
            let _ = ecc_decrypt_secret(
                SecurityPolicy::EccNistP256,
                body,
                &[0x5Au8; 32],
                server_ephemeral,
                signer_cert,
            );
        }
    }
});
