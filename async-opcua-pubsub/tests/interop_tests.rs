//! Feature 026 / US5 (T016, T017): external-interop cross-check (SC-004).
//!
//! No live external Part-14 SignAndEncrypt stack is runnable in this CI (the OPC Foundation .NET
//! interop harness does plaintext UADP only; building open62541's PubSub-CTR path is out of reach
//! here). Per FR-012/SC-004's fallback, this test stands in an INDEPENDENT implementation of the
//! Part-14 security layer — raw HMAC-SHA256 (`hmac`+`sha2`) and AES-CTR built from the raw `aes`
//! block cipher and the Table-157 counter block, a completely different code path than the
//! production `ctr`/`SecurityPolicy` codec — and checks BOTH interop directions byte-for-byte:
//!   1. production encodes  -> the independent verifier checks the HMAC + decrypts the payload.
//!   2. the independent encoder builds a secured message -> the production codec decodes it.
//!
//! DOCUMENTED GAP: this is a spec-anchored independent cross-check, not a live third-party run.
//! Live .NET / open62541 PubSub-CTR interop remains a tracked backlog item (conformance-gap-backlog).

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use opcua_crypto::SecurityPolicy;
use opcua_pubsub::{
    security::{SecurityKeySet, UadpSecurityCodec},
    PublisherId, UadpDataSetMessage, UadpNetworkMessage,
};
use opcua_types::{BinaryDecodable, BinaryEncodable, ContextOwned, MessageSecurityMode};

const POLICY: SecurityPolicy = SecurityPolicy::PubSubAes256Ctr;
const TOKEN: u32 = 5;
const SIGNING_KEY: [u8; 32] = [0x11; 32];
const ENC_KEY: [u8; 32] = [0x22; 32];
const KEY_NONCE: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
const SIG_LEN: usize = 32;

// Same deterministic header layout as the US2 framing tests (PublisherId::None + 1 DataSetMessage):
const NONCE_OFFSET: usize = 22; // 8-byte MessageNonce
const CIPHERTEXT_OFFSET: usize = 30; // after the 8-byte nonce

fn key_set() -> SecurityKeySet {
    SecurityKeySet::from_parts(
        TOKEN,
        SIGNING_KEY.to_vec(),
        ENC_KEY.to_vec(),
        KEY_NONCE.to_vec(),
    )
    .unwrap()
}

fn message() -> UadpNetworkMessage {
    UadpNetworkMessage {
        publisher_id: PublisherId::None,
        writer_group_id: 7,
        network_message_number: 0,
        sequence_number: 3,
        dataset_messages: vec![UadpDataSetMessage {
            dataset_writer_id: 10,
            sequence_number: 3,
            timestamp: None,
            status: None,
            fields: vec![opcua_types::Variant::from(72.5f64)],
        }],
    }
}

// ---- independent security primitives (NOT the production code path) ----

fn independent_hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// AES-256-CTR via the raw block cipher + Part-14 Table-157 counter block
/// (KeyNonce[4] ‖ MessageNonce[8] ‖ BlockCounter[4] big-endian from 1). Symmetric (enc == dec).
fn independent_ctr(
    enc_key: &[u8],
    key_nonce4: &[u8],
    message_nonce8: &[u8],
    data: &[u8],
) -> Vec<u8> {
    let cipher = aes::Aes256::new(GenericArray::from_slice(enc_key));
    let mut counter = [0u8; 16];
    counter[0..4].copy_from_slice(&key_nonce4[..4]);
    counter[4..12].copy_from_slice(message_nonce8);
    counter[12..16].copy_from_slice(&1u32.to_be_bytes());

    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut block = GenericArray::clone_from_slice(&counter);
        cipher.encrypt_block(&mut block);
        for (b, k) in chunk.iter().zip(block.iter()) {
            out.push(b ^ k);
        }
        let c = u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]])
            .wrapping_add(1);
        counter[12..16].copy_from_slice(&c.to_be_bytes());
    }
    out
}

// Direction 1: production encodes; an independent third party verifies + decrypts it.
#[test]
fn external_verifier_validates_production_output() {
    let ctx_owned = ContextOwned::default();
    let ctx = ctx_owned.context();
    let secured = UadpSecurityCodec::new(MessageSecurityMode::SignAndEncrypt, POLICY, key_set())
        .encode_network_message(&message(), &ctx)
        .unwrap();

    let sig_start = secured.len() - SIG_LEN;
    let signed_region = &secured[..sig_start];
    let signature = &secured[sig_start..];

    // 1) Independent HMAC-SHA256 over the whole message matches the appended signature.
    assert_eq!(
        independent_hmac(&SIGNING_KEY, signed_region),
        signature,
        "HMAC mismatch"
    );

    // 2) Independent AES-CTR decrypt of the payload region recovers the plaintext DataSetMessages.
    let message_nonce = &secured[NONCE_OFFSET..NONCE_OFFSET + 8];
    let ciphertext = &secured[CIPHERTEXT_OFFSET..sig_start];
    let plaintext_payload = independent_ctr(&ENC_KEY, &KEY_NONCE[..4], message_nonce, ciphertext);

    // Reassemble header (incl SecurityHeader) + decrypted payload and decode as plain UADP.
    let mut reassembled = secured[..CIPHERTEXT_OFFSET].to_vec();
    reassembled.extend_from_slice(&plaintext_payload);
    let recovered = UadpNetworkMessage::decode(&mut &reassembled[..], &ctx).unwrap();
    assert_eq!(
        recovered,
        message(),
        "external party must recover our DataSet"
    );
}

// Direction 2: an independent encoder builds a foreign secured message; production decodes it.
#[test]
fn production_decodes_externally_built_message() {
    let ctx_owned = ContextOwned::default();
    let ctx = ctx_owned.context();

    // Plain UADP (None mode): UADPFlags(1) ‖ GroupHeader(11) ‖ PayloadHeader(3) ‖ DataSetMessages.
    let plain = message().encode_to_vec(&ctx);
    let header_no_flags = &plain[1..15]; // GroupHeader + PayloadHeader (skip the UADPFlags byte)
    let payload_plain = &plain[15..];

    let message_nonce: [u8; 8] = [0xA1, 0xA2, 0xA3, 0xA4, 3, 0, 0, 0]; // Random(4) ‖ seq=3 LE

    let mut foreign = Vec::new();
    foreign.push(plain[0] | 0x80); // UADPFlags + ExtendedFlags1 enabled
    foreign.push(0x10); // ExtendedFlags1: SecurityHeader enabled
    foreign.extend_from_slice(header_no_flags);
    // SecurityHeader: flags signed+encrypted, token, NonceLength=8, MessageNonce.
    foreign.push(0x03);
    foreign.extend_from_slice(&TOKEN.to_le_bytes());
    foreign.push(8);
    foreign.extend_from_slice(&message_nonce);
    // Encrypt the payload independently and append.
    let ciphertext = independent_ctr(&ENC_KEY, &KEY_NONCE[..4], &message_nonce, payload_plain);
    foreign.extend_from_slice(&ciphertext);
    // Sign the whole message independently and append.
    let signature = independent_hmac(&SIGNING_KEY, &foreign);
    foreign.extend_from_slice(&signature);

    let decoded = UadpSecurityCodec::with_candidates(
        MessageSecurityMode::SignAndEncrypt,
        POLICY,
        vec![key_set()],
    )
    .decode_network_message(&foreign, &ctx)
    .expect("production must decode the externally-built secured message");
    assert_eq!(decoded, message());
}
