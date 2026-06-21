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
});
