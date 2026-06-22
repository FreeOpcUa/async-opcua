//! Feature 026 / US1 (T006, T007): independent verification of the PubSub AES-CTR symmetric
//! policies against OPC UA Part 14 §7.2.4.4.3.2 (Tables 156/157).
//!
//! The oracle here builds the AES-CTR keystream block-by-block using the raw `aes` block cipher and
//! the Part-14 counter block (KeyNonce[4] ‖ MessageNonce[8] ‖ BlockCounter[4], 32-bit big-endian,
//! starting at 1). This is a DIFFERENT code path than the production `ctr::Ctr32BE`, so it catches a
//! wrong counter-block layout / endianness / start value — not just "AES is correct".

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};

use crate::{AesDerivedKeys, AesKey, SecurityPolicy};

/// Part-14 Table 157 counter block: KeyNonce(4) ‖ MessageNonce(8) ‖ BlockCounter(4)=1.
fn counter_block(key_nonce: &[u8; 4], message_nonce: &[u8; 8]) -> [u8; 16] {
    let mut cb = [0u8; 16];
    cb[0..4].copy_from_slice(key_nonce);
    cb[4..12].copy_from_slice(message_nonce);
    cb[12..16].copy_from_slice(&1u32.to_be_bytes()); // BlockCounter starts at 1
    cb
}

/// Independent AES-CTR: XOR plaintext with keystream, incrementing only the low 32 bits of the
/// counter block as a big-endian integer (Part-14 / RFC 3686 convention).
fn ctr_oracle<F: Fn([u8; 16]) -> [u8; 16]>(
    encrypt_block: F,
    mut counter: [u8; 16],
    data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let keystream = encrypt_block(counter);
        for (b, k) in chunk.iter().zip(keystream.iter()) {
            out.push(b ^ k);
        }
        let c = u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]])
            .wrapping_add(1);
        counter[12..16].copy_from_slice(&c.to_be_bytes());
    }
    out
}

fn aes128_block(key: &[u8]) -> impl Fn([u8; 16]) -> [u8; 16] + '_ {
    let cipher = aes::Aes128::new(GenericArray::from_slice(key));
    move |blk| {
        let mut b = GenericArray::clone_from_slice(&blk);
        cipher.encrypt_block(&mut b);
        let mut o = [0u8; 16];
        o.copy_from_slice(&b);
        o
    }
}

fn aes256_block(key: &[u8]) -> impl Fn([u8; 16]) -> [u8; 16] + '_ {
    let cipher = aes::Aes256::new(GenericArray::from_slice(key));
    move |blk| {
        let mut b = GenericArray::clone_from_slice(&blk);
        cipher.encrypt_block(&mut b);
        let mut o = [0u8; 16];
        o.copy_from_slice(&b);
        o
    }
}

fn keys(enc_key: &[u8], counter: [u8; 16]) -> AesDerivedKeys {
    // 32-byte HMAC-SHA256 signing key; contents irrelevant to the encryption KAT.
    AesDerivedKeys::from_parts(
        vec![0x11; 32],
        AesKey::new(enc_key.to_vec()),
        counter.to_vec(),
    )
}

#[test]
fn aes128_ctr_matches_part14_counter_block_vector() {
    let policy = SecurityPolicy::PubSubAes128Ctr;
    let enc_key = [0xA5u8; 16];
    let key_nonce = [0x01, 0x02, 0x03, 0x04];
    let message_nonce = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
    // 35 bytes => spans 3 AES blocks and is NOT block-aligned (proves no padding for CTR).
    let plaintext: Vec<u8> = (0u8..35).collect();

    let cb = counter_block(&key_nonce, &message_nonce);
    let expected = ctr_oracle(aes128_block(&enc_key), cb, &plaintext);

    let mut dst = vec![0u8; plaintext.len()];
    let n = policy
        .symmetric_encrypt(&keys(&enc_key, cb), &plaintext, &mut dst)
        .expect("AES-128-CTR encrypt should succeed");
    assert_eq!(n, plaintext.len(), "CTR is size-preserving (no padding)");
    assert_eq!(
        dst, expected,
        "ciphertext must match the Part-14 Table-157 keystream"
    );
}

#[test]
fn aes256_ctr_matches_part14_counter_block_vector() {
    let policy = SecurityPolicy::PubSubAes256Ctr;
    let enc_key = [0x5Au8; 32];
    let key_nonce = [0x21, 0x22, 0x23, 0x24];
    let message_nonce = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37];
    let plaintext: Vec<u8> = (0u8..48).collect();

    let cb = counter_block(&key_nonce, &message_nonce);
    let expected = ctr_oracle(aes256_block(&enc_key), cb, &plaintext);

    let mut dst = vec![0u8; plaintext.len()];
    let n = policy
        .symmetric_encrypt(&keys(&enc_key, cb), &plaintext, &mut dst)
        .expect("AES-256-CTR encrypt should succeed");
    assert_eq!(n, plaintext.len());
    assert_eq!(dst, expected);
}

#[test]
fn ctr_round_trips_and_is_symmetric() {
    let policy = SecurityPolicy::PubSubAes128Ctr;
    let enc_key = [0x7Cu8; 16];
    let cb = counter_block(&[9, 9, 9, 9], &[1, 2, 3, 4, 5, 6, 7, 8]);
    let plaintext = b"the quick brown fox jumps over!!"; // 32 bytes

    let mut ct = vec![0u8; plaintext.len()];
    policy
        .symmetric_encrypt(&keys(&enc_key, cb), plaintext, &mut ct)
        .unwrap();
    assert_ne!(&ct[..], &plaintext[..]);

    // CTR decrypt == encrypt with the same counter block.
    let mut pt = vec![0u8; ct.len()];
    policy
        .symmetric_decrypt(&keys(&enc_key, cb), &ct, &mut pt)
        .unwrap();
    assert_eq!(&pt[..], &plaintext[..]);
}

#[test]
fn ctr_rejects_wrong_iv_length() {
    let policy = SecurityPolicy::PubSubAes128Ctr;
    // 15-byte IV (not a 16-byte counter block) must fail closed.
    let bad =
        AesDerivedKeys::from_parts(vec![0x11; 32], AesKey::new(vec![0xA5; 16]), vec![0u8; 15]);
    let mut dst = vec![0u8; 16];
    assert!(policy
        .symmetric_encrypt(&bad, &[0u8; 16], &mut dst)
        .is_err());
}

#[test]
fn ctr_policy_key_and_signature_lengths() {
    assert_eq!(SecurityPolicy::PubSubAes128Ctr.encrypting_key_length(), 16);
    assert_eq!(SecurityPolicy::PubSubAes256Ctr.encrypting_key_length(), 32);
    assert_eq!(
        SecurityPolicy::PubSubAes128Ctr.symmetric_signature_size(),
        32
    );
    assert_eq!(
        SecurityPolicy::PubSubAes256Ctr.symmetric_signature_size(),
        32
    );
    assert!(SecurityPolicy::PubSubAes128Ctr.is_supported());
    assert!(SecurityPolicy::PubSubAes256Ctr.is_supported());
}

#[test]
fn ctr_policy_uri_round_trips() {
    for policy in [
        SecurityPolicy::PubSubAes128Ctr,
        SecurityPolicy::PubSubAes256Ctr,
    ] {
        let uri = policy.to_uri();
        assert_eq!(
            SecurityPolicy::from_uri(uri),
            policy,
            "URI {uri} must round-trip"
        );
    }
}

// T007: HMAC-SHA256 signature over the message, with tamper detection.
#[test]
fn ctr_policy_hmac_sha256_signs_and_detects_tampering() {
    let policy = SecurityPolicy::PubSubAes256Ctr;
    let signing_key = vec![0x42u8; 32];
    let signed =
        AesDerivedKeys::from_parts(signing_key, AesKey::new(vec![0u8; 32]), [0u8; 16].to_vec());

    let data = b"part-14 network message bytes";
    let mut sig = vec![0u8; policy.symmetric_signature_size()];
    policy.symmetric_sign(&signed, data, &mut sig).unwrap();
    assert_eq!(sig.len(), 32);

    policy
        .symmetric_verify_signature(&signed, data, &sig)
        .expect("valid HMAC must verify");

    let mut tampered = data.to_vec();
    tampered[0] ^= 0x01;
    assert!(
        policy
            .symmetric_verify_signature(&signed, &tampered, &sig)
            .is_err(),
        "a tampered message must fail HMAC verification"
    );
}
