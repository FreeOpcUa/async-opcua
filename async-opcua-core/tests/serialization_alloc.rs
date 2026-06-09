//! Outbound serialization metrics and bounds checks.

use std::sync::{atomic::Ordering, Mutex};

use bytes::BytesMut;
use opcua_core::comms::{
    tcp_codec::{Message, TcpCodec, SERIALIZATION_METRICS},
    tcp_types::AcknowledgeMessage,
};
use opcua_types::encoding::{DecodingOptions, SimpleBinaryEncodable};
use tokio_util::codec::Encoder;

static SERIALIZATION_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn encode_acknowledge_updates_bytes_written_metric() {
    let _guard = SERIALIZATION_TEST_LOCK.lock().unwrap();
    let bytes_before = SERIALIZATION_METRICS.bytes_written.load(Ordering::Relaxed);
    let errors_before = SERIALIZATION_METRICS
        .serialization_errors
        .load(Ordering::Relaxed);

    let mut codec = TcpCodec::new(DecodingOptions {
        max_message_size: 1024,
        ..DecodingOptions::default()
    });
    let message = AcknowledgeMessage::new(0, 8192, 8192, 0, 0);
    let expected_len = message.byte_len();
    let mut output = BytesMut::new();

    Encoder::encode(&mut codec, Message::Acknowledge(message), &mut output)
        .expect("acknowledge message should encode");

    assert_eq!(output.len(), expected_len);
    assert_eq!(
        SERIALIZATION_METRICS.bytes_written.load(Ordering::Relaxed) - bytes_before,
        expected_len as u64
    );
    assert_eq!(
        SERIALIZATION_METRICS
            .serialization_errors
            .load(Ordering::Relaxed),
        errors_before
    );
}

#[test]
fn encode_oversized_acknowledge_increments_error_metric() {
    let _guard = SERIALIZATION_TEST_LOCK.lock().unwrap();
    let bytes_before = SERIALIZATION_METRICS.bytes_written.load(Ordering::Relaxed);
    let errors_before = SERIALIZATION_METRICS
        .serialization_errors
        .load(Ordering::Relaxed);

    let message = AcknowledgeMessage::new(0, 8192, 8192, 0, 0);
    let mut codec = TcpCodec::new(DecodingOptions {
        max_message_size: message.byte_len() - 1,
        ..DecodingOptions::default()
    });
    let mut output = BytesMut::new();

    let err = Encoder::encode(&mut codec, Message::Acknowledge(message), &mut output)
        .expect_err("oversized acknowledge message should fail encoding");

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(output.is_empty());
    assert_eq!(
        SERIALIZATION_METRICS.bytes_written.load(Ordering::Relaxed),
        bytes_before
    );
    assert_eq!(
        SERIALIZATION_METRICS
            .serialization_errors
            .load(Ordering::Relaxed),
        errors_before + 1
    );
}
