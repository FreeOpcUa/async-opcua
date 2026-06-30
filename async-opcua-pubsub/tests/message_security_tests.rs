//! Feature 026 / US2 (T010, T011): Part-14 SecurityHeader framing assertions and the fail-closed
//! decode corpus. Wire layout per OPC UA Part 14 1.05.06 §7.2.2.2.3 / Figure A.3.

use std::sync::Arc;
use std::time::Duration;

use opcua_core::sync::RwLock;
use opcua_crypto::{AesDerivedKeys, AesKey, SecurityPolicy};
use opcua_pubsub::{
    engine::PubSubEngine,
    security::{SecurityGroup, SecurityKeySet, UadpSecurityCodec},
    PublisherId, UadpDataSetMessage, UadpNetworkMessage,
};
use opcua_server::address_space::AddressSpace;
use opcua_types::{ContextOwned, DecodingOptions, MessageSecurityMode, NamespaceMap, StatusCode};

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
const MESSAGE_NONCE_OFFSET: usize = 22; // 8-byte MessageNonce: [22..26]=Random, [26..30]=SeqNumber
const SIGNATURE_LEN: usize = 32;
const ENCRYPTED_HEADER_LEN: usize = MESSAGE_NONCE_OFFSET + 8;

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
    let bytes = codec
        .encode_network_message(&sample_message(), &ctx)
        .unwrap();
    (bytes, ks)
}

#[test]
fn sign_and_encrypt_emits_part14_security_header_not_opcuaps1() {
    let (secured, _) = encode(MessageSecurityMode::SignAndEncrypt);

    assert!(
        !secured.starts_with(b"OPCUAPS1"),
        "legacy envelope must be gone"
    );
    assert_ne!(secured[0] & 0x80, 0, "ExtendedFlags1 must be enabled");
    assert_ne!(
        secured[1] & 0x10,
        0,
        "SecurityHeader flag (ExtendedFlags1 bit4) must be set"
    );
    // SecurityFlags bit0 (Signed) + bit1 (Encrypted) set; footer/reserved clear.
    assert_eq!(secured[SECURITY_FLAGS_OFFSET], 0x03);
    assert_eq!(
        secured[NONCE_LENGTH_OFFSET], 8,
        "encrypted NonceLength must be 8"
    );
}

#[test]
fn sign_only_sets_signed_flag_and_zero_nonce() {
    let (secured, _) = encode(MessageSecurityMode::Sign);

    assert_ne!(secured[1] & 0x10, 0);
    assert_eq!(
        secured[SECURITY_FLAGS_OFFSET], 0x01,
        "Sign-only: only the Signed bit"
    );
    assert_eq!(
        secured[NONCE_LENGTH_OFFSET], 0,
        "Sign-only carries no MessageNonce"
    );
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

fn address_space() -> Arc<RwLock<AddressSpace>> {
    Arc::new(RwLock::new(AddressSpace::new()))
}

fn encryption_keys(key_set: &SecurityKeySet, message_nonce: &[u8]) -> AesDerivedKeys {
    let mut counter_block = Vec::with_capacity(16);
    counter_block.extend_from_slice(&key_set.key_nonce()[..4]);
    counter_block.extend_from_slice(message_nonce);
    counter_block.extend_from_slice(&1u32.to_be_bytes());
    AesDerivedKeys::from_parts(
        key_set.signing_key().to_vec(),
        AesKey::new(key_set.encryption_key().value().to_vec()),
        counter_block,
    )
}

fn append_encrypted_trailing_payload(mut secured: Vec<u8>, key_set: &SecurityKeySet) -> Vec<u8> {
    let message_nonce = &secured[MESSAGE_NONCE_OFFSET..ENCRYPTED_HEADER_LEN];
    let keys = encryption_keys(key_set, message_nonce);
    let signature_start = secured.len() - SIGNATURE_LEN;
    let ciphertext = &secured[ENCRYPTED_HEADER_LEN..signature_start];

    let mut plaintext = vec![0u8; ciphertext.len()];
    let plaintext_len = POLICY
        .symmetric_decrypt(&keys, ciphertext, &mut plaintext)
        .unwrap();
    plaintext.truncate(plaintext_len);
    plaintext.extend_from_slice(&[0xAA, 0xBB, 0xCC]);

    let mut expanded_ciphertext = vec![0u8; plaintext.len()];
    let ciphertext_len = POLICY
        .symmetric_encrypt(&keys, &plaintext, &mut expanded_ciphertext)
        .unwrap();
    expanded_ciphertext.truncate(ciphertext_len);

    secured.truncate(ENCRYPTED_HEADER_LEN);
    secured.extend_from_slice(&expanded_ciphertext);
    let mut signature = vec![0u8; POLICY.symmetric_signature_size()];
    POLICY
        .symmetric_sign(&keys, &secured, &mut signature)
        .unwrap();
    secured.extend_from_slice(&signature);
    secured
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
        let status = decode_with(
            &secured[..len],
            ks.clone(),
            MessageSecurityMode::SignAndEncrypt,
        );
        assert_ne!(
            status,
            StatusCode::Good,
            "truncation to {len} must not decode"
        );
    }
}

#[test]
fn trailing_secured_payload_is_rejected_before_replay_advances() {
    // OPC-10000-14 7.2.4.4.2 defines the UADP NetworkMessage layout as the complete encoded
    // payload shape; 7.2.4.4.3 defines the secured UADP header/signature processing around it.
    // Authenticated extra plaintext after the declared DataSetMessage must therefore fail closed,
    // and a rejection must not consume the NetworkMessage sequence number in replay state.
    let ctx_owned = ContextOwned::default();
    let ctx = ctx_owned.context();
    let mut engine = PubSubEngine::new(address_space());
    let current_key = key_set(5);
    let group = SecurityGroup::with_key_sets(
        "line-a",
        current_key.clone(),
        key_set(6),
        Duration::from_secs(3600),
    )
    .unwrap();
    engine.register_security_group(group);

    let valid = UadpSecurityCodec::new(
        MessageSecurityMode::SignAndEncrypt,
        POLICY,
        current_key.clone(),
    )
    .encode_network_message(&sample_message(), &ctx)
    .unwrap();
    let trailing = append_encrypted_trailing_payload(valid.clone(), &current_key);

    let rejected = engine
        .decode_subscriber_uadp_message(
            "line-a",
            MessageSecurityMode::SignAndEncrypt,
            POLICY,
            &trailing,
            &ctx,
        )
        .unwrap_err();
    assert_eq!(rejected, StatusCode::BadSecurityChecksFailed);

    let accepted = engine
        .decode_subscriber_uadp_message(
            "line-a",
            MessageSecurityMode::SignAndEncrypt,
            POLICY,
            &valid,
            &ctx,
        )
        .expect("rejected trailing payload must not advance replay state");
    assert_eq!(accepted, sample_message());
}

#[test]
fn oversized_secured_payload_is_rejected_before_replay_advances() {
    // MCP citation: OPC-10000-14 7.2.4.4.3.2 defines AES-CTR secured-message processing via the
    // MessageNonce; 7.2.4.4.2 defines NetworkMessage SequenceNumber and nonce fields. A subscriber
    // must reject an over-limit secured payload before accepting the sequence in replay state.
    let ctx_owned = ContextOwned::default();
    let ctx = ctx_owned.context();
    let mut engine = PubSubEngine::new(address_space());
    let current_key = key_set(5);
    let group = SecurityGroup::with_key_sets(
        "line-a",
        current_key.clone(),
        key_set(6),
        Duration::from_secs(3600),
    )
    .unwrap();
    engine.register_security_group(group);

    let secured = UadpSecurityCodec::new(
        MessageSecurityMode::SignAndEncrypt,
        POLICY,
        current_key.clone(),
    )
    .encode_network_message(&sample_message(), &ctx)
    .unwrap();

    let limited_options = DecodingOptions {
        max_secured_payload_len: secured.len() - 1,
        ..DecodingOptions::test()
    };
    let limited_ctx_owned = ContextOwned::new_default(NamespaceMap::new(), limited_options);
    let limited_ctx = limited_ctx_owned.context();

    let rejected = engine
        .decode_subscriber_uadp_message(
            "line-a",
            MessageSecurityMode::SignAndEncrypt,
            POLICY,
            &secured,
            &limited_ctx,
        )
        .unwrap_err();
    assert_eq!(rejected, StatusCode::BadSecurityChecksFailed);

    let accepted = engine
        .decode_subscriber_uadp_message(
            "line-a",
            MessageSecurityMode::SignAndEncrypt,
            POLICY,
            &secured,
            &ctx,
        )
        .expect("rejected oversized payload must not advance replay state");
    assert_eq!(accepted, sample_message());
}

#[test]
fn decode_round_trips_both_modes() {
    let ctx_owned = ContextOwned::default();
    let ctx = ctx_owned.context();
    for mode in [
        MessageSecurityMode::Sign,
        MessageSecurityMode::SignAndEncrypt,
    ] {
        let ks = key_set(5);
        let secured = UadpSecurityCodec::new(mode, POLICY, ks.clone())
            .encode_network_message(&sample_message(), &ctx)
            .unwrap();
        let decoded = UadpSecurityCodec::with_candidates(mode, POLICY, vec![ks])
            .decode_network_message(&secured, &ctx)
            .unwrap();
        assert_eq!(
            decoded,
            sample_message(),
            "round-trip must recover the message ({mode:?})"
        );
    }
}

// US3 (T013): the core static-IV fix. Encoding the SAME message twice under one key set must
// produce a DIFFERENT MessageNonce and DIFFERENT ciphertext. A static-IV implementation (the
// pre-fix OPCUAPS1 codec, which reused key_nonce[..block] as the IV) produced identical ciphertext
// here — so this test fails on the old behaviour and passes on the per-message-nonce fix.
#[test]
fn each_message_gets_a_fresh_nonce_and_distinct_ciphertext() {
    let (a, _) = encode(MessageSecurityMode::SignAndEncrypt);
    let (b, _) = encode(MessageSecurityMode::SignAndEncrypt);

    // MessageNonce = Random[4] ‖ SequenceNumber(UInt32 LE). sample_message() has seq = 9, so the
    // sequence portion is identical across both encodes; only the random portion changes.
    assert_eq!(
        &a[MESSAGE_NONCE_OFFSET + 4..MESSAGE_NONCE_OFFSET + 8],
        &9u32.to_le_bytes(),
        "nonce sequence portion must equal the NetworkMessage SequenceNumber"
    );
    let random_a = &a[MESSAGE_NONCE_OFFSET..MESSAGE_NONCE_OFFSET + 4];
    let random_b = &b[MESSAGE_NONCE_OFFSET..MESSAGE_NONCE_OFFSET + 4];
    assert_ne!(
        random_a, random_b,
        "the random nonce portion must be fresh per message"
    );

    // Identical plaintext under one key set must NOT yield identical ciphertext (no IV reuse).
    let ct_a = &a[MESSAGE_NONCE_OFFSET + 8..a.len() - SIGNATURE_LEN];
    let ct_b = &b[MESSAGE_NONCE_OFFSET + 8..b.len() - SIGNATURE_LEN];
    assert_eq!(ct_a.len(), ct_b.len());
    assert_ne!(ct_a, ct_b, "static-IV reuse would make these equal");
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
    let decoded =
        UadpSecurityCodec::with_candidates(MessageSecurityMode::SignAndEncrypt, POLICY, candidates)
            .decode_network_message(&secured, &ctx)
            .unwrap();
    assert_eq!(decoded, sample_message());
}
