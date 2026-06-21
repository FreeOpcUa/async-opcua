// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0

//! Independent tests for the ECC `EccEncryptedSecret` key derivation (OPC UA Part 6 §6.8.3) and, as the
//! feature is implemented, the §7.40.2.5 envelope. Authored separately from the production code
//! (verification division). The HKDF math is anchored to **IETF RFC 5869** test vectors (Appendix A) —
//! NOT to the production code path — because the §6.8.3 KDF *is* RFC 5869 HKDF (Extract+Expand). The
//! §6.8.3-specific construction (the `opcua-secret` salt + Info=Salt + the Table 71 split) is verified by
//! hand-building the salt bytes in the test and recomputing the keying material independently.

use crate::ecc::{derive_secret_keys, EccCurve, EccEncryptedSecret};
use crate::SecurityPolicy;
use opcua_types::{ByteString, DateTime};

/// Decode an ASCII hex string (whitespace ignored) to bytes.
fn hex(s: &str) -> Vec<u8> {
    let cleaned: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    cleaned
        .chunks_exact(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16).expect("valid hex");
            let lo = (pair[1] as char).to_digit(16).expect("valid hex");
            ((hi << 4) | lo) as u8
        })
        .collect()
}

/// Independent RFC 5869 HKDF Extract+Expand with explicit salt/info (the normative algorithm the §6.8.3
/// KDF builds on). Used as the test's own reference; the next test pins this against the RFC vector.
fn rfc5869_hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm).expect("valid HKDF length");
    okm
}

fn rfc5869_hkdf_sha384(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let hk = hkdf::Hkdf::<sha2::Sha384>::new(Some(salt), ikm);
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm).expect("valid HKDF length");
    okm
}

/// RFC 5869 Appendix A.1 (Test Case 1, SHA-256) — the external ground truth for HKDF Extract+Expand.
/// If this matches, the HKDF primitive the §6.8.3 KDF depends on is correct (not a rigged loopback).
#[test]
fn hkdf_sha256_matches_rfc5869_test_case_1() {
    let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex("000102030405060708090a0b0c");
    let info = hex("f0f1f2f3f4f5f6f7f8f9");
    let expected_okm = hex("3cb25f25faacd57a90434f64d0362f2a\
         2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
         34007208d5b887185865");
    let okm = rfc5869_hkdf_sha256(&ikm, &salt, &info, 42);
    assert_eq!(okm, expected_okm, "HKDF-SHA256 must match RFC 5869 A.1 OKM");
}

/// §6.8.3: `derive_secret_keys` MUST build `SecretSalt = L(le16) | "opcua-secret" | SenderPublicKey |
/// ReceiverPublicKey`, run HKDF with IKM=shared secret and **Info = Salt**, and split the keying
/// material into EncryptingKey (per-curve length) then IV (16) — Table 71. Per-curve: P-256 ⇒ AES-128
/// (16-byte key); P-384 ⇒ AES-256 (32-byte key). Verified against an independent HKDF recomputation
/// using a hand-built salt (the §6.8.3-specific logic), with the HKDF primitive itself pinned by the
/// RFC 5869 test above.
#[test]
fn derive_secret_keys_follows_section_6_8_3() {
    for (curve, shared_len, enc_len) in [
        (EccCurve::P256, 32usize, 16usize),
        (EccCurve::P384, 48usize, 32usize),
    ] {
        // Distinct, deterministic inputs (content is irrelevant to the KDF structure under test).
        let shared_secret: Vec<u8> = (0..shared_len).map(|i| (i as u8).wrapping_mul(7)).collect();
        let sender_public_key: Vec<u8> = (0..65).map(|i| 0x40u8 ^ i as u8).collect();
        let receiver_public_key: Vec<u8> = (0..65).map(|i| 0x80u8 ^ i as u8).collect();

        let l = (enc_len + 16) as u16;
        let mut salt = Vec::new();
        salt.extend_from_slice(&l.to_le_bytes());
        salt.extend_from_slice(b"opcua-secret");
        salt.extend_from_slice(&sender_public_key);
        salt.extend_from_slice(&receiver_public_key);

        let okm = match curve {
            EccCurve::P256 => rfc5869_hkdf_sha256(&shared_secret, &salt, &salt, enc_len + 16),
            EccCurve::P384 => rfc5869_hkdf_sha384(&shared_secret, &salt, &salt, enc_len + 16),
        };
        let expected_enc = &okm[..enc_len];
        let expected_iv = &okm[enc_len..enc_len + 16];

        let keys = derive_secret_keys(
            curve,
            &shared_secret,
            &sender_public_key,
            &receiver_public_key,
        )
        .expect("derive_secret_keys must succeed for valid inputs");

        assert_eq!(
            keys.encrypting_key.value(),
            expected_enc,
            "{curve:?}: EncryptingKey must be HKDF(opcua-secret salt)[0..{enc_len}]"
        );
        assert_eq!(
            keys.iv.as_slice(),
            expected_iv,
            "{curve:?}: IV must be HKDF(opcua-secret salt)[{enc_len}..{}]",
            enc_len + 16
        );
        assert_eq!(
            keys.encrypting_key.value().len(),
            enc_len,
            "{curve:?}: EncryptingKey length must be {enc_len} (AES-128 P-256 / AES-256 P-384)"
        );
        assert_eq!(keys.iv.len(), 16, "{curve:?}: IV length must be 16");
    }
}

/// Fail-closed: a shared secret of the wrong length for the curve (not the x-coordinate size) must be
/// rejected rather than silently deriving keys from malformed input.
#[test]
fn derive_secret_keys_rejects_wrong_shared_secret_length() {
    let sender = vec![0x04u8; 65];
    let receiver = vec![0x04u8; 65];
    // P-256 expects a 32-byte shared secret; give it 31.
    assert!(derive_secret_keys(EccCurve::P256, &[1u8; 31], &sender, &receiver).is_err());
    // P-384 expects 48; give it 32.
    assert!(derive_secret_keys(EccCurve::P384, &[1u8; 32], &sender, &receiver).is_err());
}

fn sample_envelope() -> EccEncryptedSecret {
    EccEncryptedSecret {
        security_policy_uri: SecurityPolicy::EccNistP256.to_uri().to_string(),
        certificate: ByteString::null(),
        signing_time: DateTime::now(),
        sender_public_key: ByteString::from((0..64u8).collect::<Vec<u8>>()),
        receiver_public_key: ByteString::from((64..128u8).collect::<Vec<u8>>()),
        // AES-CBC ciphertext blob — multiple of the 16-byte block.
        encrypted_payload: (0..48u8).map(|i| i.wrapping_mul(3)).collect(),
        // ECDSA raw r||s for P-256 is 64 bytes.
        signature: (0..64u8).map(|i| 0xA0u8 ^ i).collect(),
    }
}

/// §7.40.2.5 / Table 186: the envelope serializes and parses back byte-for-byte. The EncodingMask is
/// always 1, and the trailing Signature (raw r||s, curve-derived length) is split from the encrypted
/// payload using the SecurityPolicyUri's curve.
#[test]
fn ecc_encrypted_secret_envelope_round_trips() {
    let env = sample_envelope();
    let bytes = env.encode().expect("encode envelope");

    let decoded = EccEncryptedSecret::decode(&bytes).expect("decode envelope");
    assert_eq!(decoded.security_policy_uri, env.security_policy_uri);
    assert_eq!(decoded.certificate, env.certificate);
    assert_eq!(decoded.signing_time, env.signing_time);
    assert_eq!(decoded.sender_public_key, env.sender_public_key);
    assert_eq!(decoded.receiver_public_key, env.receiver_public_key);
    assert_eq!(decoded.encrypted_payload, env.encrypted_payload);
    assert_eq!(decoded.signature, env.signature);

    // Re-encoding the decoded value reproduces the exact bytes.
    assert_eq!(decoded.encode().expect("re-encode"), bytes);

    // The data-to-sign is a strict prefix of the full encoding (everything before the Signature).
    let to_sign = env.encode_data_to_sign().expect("data to sign");
    assert!(bytes.starts_with(&to_sign));
    assert_eq!(bytes.len(), to_sign.len() + env.signature.len());
}

/// Fail-closed: truncated / empty / garbage bytes must return an error, never panic.
#[test]
fn ecc_encrypted_secret_decode_rejects_malformed_bytes() {
    let bytes = sample_envelope().encode().expect("encode envelope");

    // Empty and every truncation prefix must error without panicking.
    assert!(EccEncryptedSecret::decode(&[]).is_err());
    for cut in 1..bytes.len() {
        let _ = EccEncryptedSecret::decode(&bytes[..cut]); // must not panic (result ignored)
    }
    // A clearly-too-short buffer is an error.
    assert!(EccEncryptedSecret::decode(&bytes[..bytes.len() / 2]).is_err());

    // Random/garbage bytes must not panic.
    let garbage: Vec<u8> = (0..200u8)
        .map(|i| i.wrapping_mul(31).wrapping_add(7))
        .collect();
    let _ = EccEncryptedSecret::decode(&garbage);
}
