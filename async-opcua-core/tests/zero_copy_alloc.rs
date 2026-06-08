//! Zero-copy network parsing allocation test.
//!
//! Asserts that MessageChunk::decode_zero_copy slices the source Bytes buffer
//! without copying or allocating new memory.

use bytes::Bytes;
use opcua_core::comms::message_chunk::MessageChunk;
use opcua_types::encoding::DecodingOptions;

#[test]
fn test_message_chunk_decode_zero_copy() {
    // 8 bytes message header + 4 bytes sequence number + 4 bytes request id + payload
    // Header: MessageType (3 bytes) + ChunkType (1 byte) + MessageSize (4 bytes)
    // "MSG" + "F" + [24, 0, 0, 0] (little-endian)
    let mut input_bytes = vec![b'M', b'S', b'G', b'F', 24, 0, 0, 0];
    // Sequence header: sequence number (4 bytes), request id (4 bytes)
    input_bytes.extend_from_slice(&1u32.to_le_bytes());
    input_bytes.extend_from_slice(&42u32.to_le_bytes());
    // Payload (8 bytes)
    input_bytes.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

    let original_bytes = Bytes::from(input_bytes);
    let mut stream_bytes = original_bytes.clone();

    let decoding_options = DecodingOptions::default();
    let chunk = MessageChunk::decode_zero_copy(&mut stream_bytes, &decoding_options)
        .expect("Failed to decode message chunk");

    // The decoded chunk's data must point to the EXACT same memory location as the original bytes,
    // indicating that no copying or allocation occurred.
    assert_eq!(
        chunk.data.as_ptr(),
        original_bytes.as_ptr(),
        "Memory copy detected: zero-copy parsing constraint violated!"
    );
}
