//! Secure-channel transmit/receive round-trip benchmark (feature 009 / FR-030 / PERF-P12).
//!
//! Measures the per-chunk crypto path — `Chunker::encode` → `apply_security`
//! (sign/encrypt) → `verify_and_remove_security` (decrypt/verify) → `Chunker::decode`
//! — across None / Sign / SignAndEncrypt using the modern Basic256Sha256 policy.
#![allow(missing_docs)] // bench harness (criterion_main!) generates undocumented items

use std::{path::Path, sync::Arc};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use opcua_core::{
    comms::{
        chunker::Chunker,
        secure_channel::{DecryptedChunkStorage, Role, SecureChannel},
        sequence_number::SequenceNumberHandle,
    },
    sync::RwLock,
    RequestMessage,
};
use opcua_crypto::{CertificateStore, SecurityPolicy};
use opcua_types::{
    ContextOwned, GetEndpointsRequest, MessageSecurityMode, RequestHeader, UAString,
};

fn make_channel(
    security_mode: MessageSecurityMode,
    security_policy: SecurityPolicy,
    local_nonce: &[u8],
    remote_nonce: &[u8],
) -> SecureChannel {
    // Empty store at a non-existent path: read_own_cert() fails, so the channel has
    // no certificate/private key — sufficient for the symmetric (derived-key) path.
    let store = Arc::new(RwLock::new(CertificateStore::new(Path::new(
        "./bench-nonexistent-pki",
    ))));
    let ctx = Arc::new(RwLock::new(ContextOwned::default()));
    let mut channel = SecureChannel::new(store, Role::Client, ctx);
    channel.set_security_mode(security_mode);
    channel.set_security_policy(security_policy);
    channel.set_local_nonce(local_nonce);
    channel.set_remote_nonce(remote_nonce);
    // The None policy has no symmetric keys to derive (and panics if asked).
    if security_policy != SecurityPolicy::None {
        channel.derive_keys();
    }
    channel
}

fn make_channels(
    security_mode: MessageSecurityMode,
    security_policy: SecurityPolicy,
) -> (SecureChannel, SecureChannel) {
    let local = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let remote = [
        16u8, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    ];
    (
        make_channel(security_mode, security_policy, &local, &remote),
        make_channel(security_mode, security_policy, &remote, &local),
    )
}

fn sample_message() -> RequestMessage {
    RequestMessage::from(GetEndpointsRequest {
        request_header: RequestHeader::dummy(),
        endpoint_url: UAString::null(),
        locale_ids: None,
        profile_uris: None,
    })
}

fn roundtrip(sender: &SecureChannel, receiver: &SecureChannel, message: &RequestMessage) {
    let chunks =
        Chunker::encode(SequenceNumberHandle::new(true), 1, 0, 0, sender, message).unwrap();
    let mut secured = Vec::new();
    let mut decrypted_data = DecryptedChunkStorage::new();
    for chunk in &chunks {
        let mut encrypted = vec![0u8; chunk.data.len() + 4096];
        let n = sender.apply_security(chunk, &mut encrypted[..]).unwrap();
        let recovered = receiver
            .verify_and_remove_security(encrypted[..n].to_vec().into(), &mut decrypted_data)
            .unwrap();
        secured.push(recovered);
    }
    let decoded: RequestMessage = Chunker::decode(&secured, receiver, None).unwrap();
    std::hint::black_box(decoded);
}

fn bench_secure_channel(c: &mut Criterion) {
    let message = sample_message();
    let cases = [
        ("none", MessageSecurityMode::None, SecurityPolicy::None),
        (
            "sign_basic256sha256",
            MessageSecurityMode::Sign,
            SecurityPolicy::Basic256Sha256,
        ),
        (
            "sign_and_encrypt_basic256sha256",
            MessageSecurityMode::SignAndEncrypt,
            SecurityPolicy::Basic256Sha256,
        ),
    ];

    let mut group = c.benchmark_group("secure_channel_roundtrip");
    for (name, mode, policy) in cases {
        let (sender, receiver) = make_channels(mode, policy);
        group.bench_function(BenchmarkId::from_parameter(name), |b| {
            b.iter(|| roundtrip(&sender, &receiver, &message))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_secure_channel);
criterion_main!(benches);
