//! Feature 026 / US2 (T010, T011): Part-14 SecurityHeader framing assertions and the fail-closed
//! decode corpus. Wire layout per OPC UA Part 14 1.05.06 §7.2.2.2.3 / Figure A.3.

use std::time::Duration;

use opcua_crypto::SecurityPolicy;
use opcua_pubsub::{
    security::{SecurityGroup, SecurityKeySet, UadpSecurityCodec},
    PublisherId, UadpDataSetMessage, UadpNetworkMessage,
};
use opcua_types::{ContextOwned, MessageSecurityMode, StatusCode};

const POLICY: SecurityPolicy = SecurityPolicy::PubSubAes256Ctr;

// PublisherId::None keeps the header offsets deterministic so we can assert raw SecurityHeader
// fields. With one DataSetMessage the layout is:
//   [0]   UADPFlags (0xE1: version|GroupHeader|PayloadHeader|ExtendedFlags1)
//   [1]   ExtendedFlags1 (0x10 SecurityHeader enabled)
//   [2]   GroupFlags (0x0F)
//   [3..5]   writer_group_id      [5..9] group_version    [9..11] network_message_number
//   [11..13] sequence_number
//   [13]  PayloadHeader count (1) [14..16] dataset_writer_id
//   [16]  SecurityFlags           [17..21] SecurityTokenId [21] NonceLength  [22..] MessageNonce
const SECURITY_FLAGS_OFFSET: usize = 16;
const NONCE_LENGTH_OFFSET: usize = 21;

fn sample_message() -> UadpNetworkMessage {
    UadpNetworkMessage {
        publisher_id: PublisherId::None,
        writer_group_id: 7,
        network_message_number: 0,
        sequence_number: 9,
        dataset_messages: vec![UadpDataSetMessage {
            dataset_writer_id: 42,
            sequence_number: 101,
            timestamp: None,
            status: None,
            fields: vec![opcua_types::Variant::from(72.5f64)],
        }],
    }
}

fn key_set(token_id: u32) -> SecurityKeySet {
    // PubSubAes256Ctr: 32-byte signing key, 32-byte encryption key, >=4-byte key nonce.
    SecurityKeySet::from_parts(token_id, vec![0x11; 32], vec![0x22; 32], vec![0x33; 8]).unwrap()
}

fn encode(mode: MessageSecurityMode) -> (Vec<u8>, SecurityKeySet) {
    let ctx_owned = ContextOwned::default();
    let ctx = ctx_owned.context();
    let ks = key_set(5);
    let codec = UadpSecurityCodec::new(mode, POLICY, ks.clone());
    let bytes = codec.encode_network_message(&sample_message(), &ctx).unwrap();
    (bytes, ks)
}

#[test]
fn sign_and_encrypt_emits_part14_security_header_not_opcuaps1() {
    let (secured, _) = encode(MessageSecurityMode::SignAndEncrypt);

    assert!(!secured.starts_with(b"OPCUAPS1"), "legacy envelope must be gone");
    assert_ne!(secured[0] & 0x80, 0, "ExtendedFlags1 must be enabled");
    assert_ne!(secured[1] & 0x10, 0, "SecurityHeader flag (ExtendedFlags1 bit4) must be set");
    // SecurityFlags bit0 (Signed) + bit1 (Encrypted) set; footer/reserved clear.
    assert_eq!(secured[SECURITY_FLAGS_OFFSET], 0x03);
    assert_eq!(secured[NONCE_LENGTH_OFFSET], 8, "encrypted NonceLength must be 8");
}

#[test]
fn sign_only_sets_signed_flag_and_zero_nonce() {
    let (secured, _) = encode(MessageSecurityMode::Sign);

    assert_ne!(secured[1] & 0x10, 0);
    assert_eq!(secured[SECURITY_FLAGS_OFFSET], 0x01, "Sign-only: only the Signed bit");
    assert_eq!(secured[NONCE_LENGTH_OFFSET], 0, "Sign-only carries no MessageNonce");
}

fn decode_with(secured: &[u8], candidate: SecurityKeySet, mode: MessageSecurityMode) -> StatusCode {
    let ctx_owned = ContextOwned::default();
    let ctx = ctx_owned.context();
    let codec = UadpSecurityCodec::with_candidates(mode, POLICY, vec![candidate]);
    match codec.decode_network_message(secured, &ctx) {
        Ok(_) => StatusCode::Good,
        Err(e) => e.status(),
    }
}

#[test]
fn decode_rejects_tampered_ciphertext() {
    let (mut secured, ks) = encode(MessageSecurityMode::SignAndEncrypt);
    let mid = secured.len() / 2;
    secured[mid] ^= 0x01; // flip a ciphertext byte -> HMAC over the message must fail
    assert_eq!(
        decode_with(&secured, ks, MessageSecurityMode::SignAndEncrypt),
        StatusCode::BadSecurityChecksFailed
    );
}

#[test]
fn decode_rejects_tampered_signature() {
    let (mut secured, ks) = encode(MessageSecurityMode::SignAndEncrypt);
    let last = secured.len() - 1;
    secured[last] ^= 0x01; // flip a signature byte
    assert_eq!(
        decode_with(&secured, ks, MessageSecurityMode::SignAndEncrypt),
        StatusCode::BadSecurityChecksFailed
    );
}

#[test]
fn decode_rejects_reserved_security_flag_bit() {
    let (mut secured, ks) = encode(MessageSecurityMode::SignAndEncrypt);
    secured[SECURITY_FLAGS_OFFSET] |= 0x10; // set a reserved SecurityFlags bit (bit4)
    // Rejected at SecurityHeader parse (fail closed) before any crypto.
    assert_eq!(
        decode_with(&secured, ks, MessageSecurityMode::SignAndEncrypt),
        StatusCode::BadDecodingError
    );
}

#[test]
fn decode_rejects_bad_encrypted_nonce_length() {
    let (mut secured, ks) = encode(MessageSecurityMode::SignAndEncrypt);
    secured[NONCE_LENGTH_OFFSET] = 7; // encrypted message must have NonceLength == 8
    // Rejected at SecurityHeader parse (fail closed).
    assert_eq!(
        decode_with(&secured, ks, MessageSecurityMode::SignAndEncrypt),
        StatusCode::BadDecodingError
    );
}

#[test]
fn decode_rejects_unknown_security_token() {
    let (secured, _) = encode(MessageSecurityMode::SignAndEncrypt);
    // Candidate holds a DIFFERENT token id than the one on the wire (5) -> no key match.
    assert_eq!(
        decode_with(&secured, key_set(999), MessageSecurityMode::SignAndEncrypt),
        StatusCode::BadSecurityChecksFailed
    );
}

#[test]
fn decode_rejects_truncation_without_panicking() {
    let (secured, ks) = encode(MessageSecurityMode::SignAndEncrypt);
    // Every truncation must fail closed (never panic / over-allocate).
    for len in 0..secured.len() {
        let status = decode_with(&secured[..len], ks.clone(), MessageSecurityMode::SignAndEncrypt);
        assert_ne!(status, StatusCode::Good, "truncation to {len} must not decode");
    }
}

#[test]
fn decode_round_trips_both_modes() {
    let ctx_owned = ContextOwned::default();
    let ctx = ctx_owned.context();
    for mode in [MessageSecurityMode::Sign, MessageSecurityMode::SignAndEncrypt] {
        let ks = key_set(5);
        let secured = UadpSecurityCodec::new(mode, POLICY, ks.clone())
            .encode_network_message(&sample_message(), &ctx)
            .unwrap();
        let decoded = UadpSecurityCodec::with_candidates(mode, POLICY, vec![ks])
            .decode_network_message(&secured, &ctx)
            .unwrap();
        assert_eq!(decoded, sample_message(), "round-trip must recover the message ({mode:?})");
    }
}

// A security group's current and next key sets are both accepted on decode (token selection).
#[test]
fn decode_accepts_next_key_token() {
    let ctx_owned = ContextOwned::default();
    let ctx = ctx_owned.context();
    let group = SecurityGroup::new("g", Duration::from_secs(3600)).unwrap();
    let next = group.next_key_set().clone();
    // Publisher signs under the NEXT key set; subscriber holds current + next as candidates.
    let secured = UadpSecurityCodec::new(MessageSecurityMode::SignAndEncrypt, POLICY, next.clone())
        .encode_network_message(&sample_message(), &ctx)
        .unwrap();
    let candidates = vec![group.current_key_set().clone(), next];
    let decoded = UadpSecurityCodec::with_candidates(MessageSecurityMode::SignAndEncrypt, POLICY, candidates)
        .decode_network_message(&secured, &ctx)
        .unwrap();
    assert_eq!(decoded, sample_message());
}
