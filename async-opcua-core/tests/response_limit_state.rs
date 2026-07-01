//! Regression tests for per-channel response body limit state.

use std::{
    io::{Read, Write},
    path::Path,
    sync::Arc,
};

use opcua_core::{
    comms::{
        buffer::SendBuffer,
        message_chunk::MessageChunkType,
        secure_channel::{Role, SecureChannel},
    },
    messages::{Message, MessageType},
};
use opcua_crypto::CertificateStore;
use opcua_types::{BinaryEncodable, Context, EncodingResult, Error, NodeId, ObjectId, StatusCode};
use parking_lot::RwLock;

struct DummyResponse {
    byte_len: usize,
}

impl DummyResponse {
    fn new(byte_len: usize) -> Self {
        Self { byte_len }
    }
}

impl BinaryEncodable for DummyResponse {
    fn byte_len(&self, _ctx: &Context<'_>) -> usize {
        self.byte_len
    }

    fn encode<S: Write + ?Sized>(&self, stream: &mut S, _ctx: &Context<'_>) -> EncodingResult<()> {
        stream.write_all(&vec![0; self.byte_len])?;
        Ok(())
    }
}

impl MessageType for DummyResponse {
    fn message_type(&self) -> MessageChunkType {
        MessageChunkType::Message
    }
}

impl Message for DummyResponse {
    fn request_handle(&self) -> u32 {
        77
    }

    fn decode_by_object_id<S: Read>(
        _stream: &mut S,
        _object_id: ObjectId,
        _ctx: &Context<'_>,
    ) -> EncodingResult<Self> {
        Err(Error::decoding(
            "DummyResponse is encode-only for response limit tests",
        ))
    }

    fn type_id(&self) -> NodeId {
        NodeId::from(ObjectId::ReadResponse_Encoding_DefaultBinary)
    }
}

#[test]
fn zero_limit_preserves_part4_5_7_2_2_unbounded_response_size() {
    let mut channel = SecureChannel::new(
        Arc::new(RwLock::new(CertificateStore::new(Path::new("./pki")))),
        Role::Server,
        Default::default(),
    );
    channel.set_secure_channel_id(9001);
    channel.set_client_response_body_limit(0);
    assert_eq!(channel.client_response_body_limit(), None);

    let mut buffer = SendBuffer::new(8192, 0, 0, true);

    assert!(buffer
        .write(9001, DummyResponse::new(64 * 1024), &channel)
        .is_ok());
}

#[test]
fn nonzero_limit_applies_part4_5_7_2_2_response_body_limit() {
    let mut channel = SecureChannel::new(
        Arc::new(RwLock::new(CertificateStore::new(Path::new("./pki")))),
        Role::Server,
        Default::default(),
    );
    channel.set_secure_channel_id(9002);
    channel.set_client_response_body_limit(1024);
    assert_eq!(channel.client_response_body_limit(), Some(1024));

    let mut buffer = SendBuffer::new(8192, 0, 0, true);

    assert!(buffer
        .write(9002, DummyResponse::new(512), &channel)
        .is_ok());
}

#[test]
fn oversized_response_returns_part4_5_3_bad_response_too_large() {
    let limit = 1024u32;
    let extra = 1u32;
    let body_len = (limit + extra) as usize;
    let request_id = 9003;
    let mut channel = SecureChannel::new(
        Arc::new(RwLock::new(CertificateStore::new(Path::new("./pki")))),
        Role::Server,
        Default::default(),
    );
    channel.set_secure_channel_id(9003);
    channel.set_client_response_body_limit(limit);

    let mut buffer = SendBuffer::new(8192, 0, 0, true);

    let err = buffer
        .write(request_id, DummyResponse::new(body_len), &channel)
        .unwrap_err();
    assert_eq!(err.status(), StatusCode::BadResponseTooLarge);
}

#[test]
fn bad_response_too_large_matches_part4_7_38_2_status() {
    let limit = 32u32;
    let body_len = (limit + 1) as usize;
    let request_id = 9004;
    let mut channel = SecureChannel::new(
        Arc::new(RwLock::new(CertificateStore::new(Path::new("./pki")))),
        Role::Server,
        Default::default(),
    );
    channel.set_secure_channel_id(9004);
    channel.set_client_response_body_limit(limit);

    let mut buffer = SendBuffer::new(8192, 0, 0, true);

    let err = buffer
        .write(request_id, DummyResponse::new(body_len), &channel)
        .unwrap_err();
    assert_eq!(err.status(), StatusCode::BadResponseTooLarge);
    assert_eq!(err.status().bits(), 0x80B9_0000);
    assert_eq!(err.full_context(), Some((request_id, 77)));
}

#[test]
fn concurrent_channels_use_independent_response_limits() {
    let mut channel_a = SecureChannel::new(
        Arc::new(RwLock::new(CertificateStore::new(Path::new("./pki")))),
        Role::Server,
        Default::default(),
    );
    channel_a.set_secure_channel_id(9010);
    channel_a.set_client_response_body_limit(512);

    let mut channel_b = SecureChannel::new(
        Arc::new(RwLock::new(CertificateStore::new(Path::new("./pki")))),
        Role::Server,
        Default::default(),
    );
    channel_b.set_secure_channel_id(9011);
    channel_b.set_client_response_body_limit(2048);

    assert_eq!(channel_a.client_response_body_limit(), Some(512));
    assert_eq!(channel_b.client_response_body_limit(), Some(2048));

    let mut buffer_a = SendBuffer::new(8192, 0, 0, true);
    let mut buffer_b = SendBuffer::new(8192, 0, 0, true);

    let err = buffer_a
        .write(9010, DummyResponse::new(1024), &channel_a)
        .unwrap_err();
    assert_eq!(err.status(), StatusCode::BadResponseTooLarge);

    assert!(buffer_b
        .write(9011, DummyResponse::new(1024), &channel_b)
        .is_ok());

    assert_eq!(channel_a.client_response_body_limit(), Some(512));
    assert_eq!(channel_b.client_response_body_limit(), Some(2048));
}

#[test]
fn closed_channel_drops_response_limit_state() {
    let old_limit = 1024usize;
    let mut channel = SecureChannel::new(
        Arc::new(RwLock::new(CertificateStore::new(Path::new("./pki")))),
        Role::Server,
        Default::default(),
    );
    channel.set_secure_channel_id(9020);
    channel.set_client_response_body_limit(old_limit as u32);
    assert_eq!(channel.client_response_body_limit(), Some(old_limit));

    channel.set_client_response_body_limit(0);
    assert_eq!(channel.client_response_body_limit(), None);

    let mut buffer = SendBuffer::new(8192, 0, 0, true);

    assert!(buffer
        .write(9020, DummyResponse::new(old_limit + 1), &channel)
        .is_ok());
}
