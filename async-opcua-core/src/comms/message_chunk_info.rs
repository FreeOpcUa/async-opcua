// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Implementation of [ChunkInfo], utility wrapping various message headers
//! to provide a common source of info about a message chunk.

use std::io::Cursor;

use opcua_types::{EncodingResult, SimpleBinaryDecodable};

use super::{
    message_chunk::{MessageChunk, MessageChunkHeader},
    secure_channel::SecureChannel,
    security_header::{SecurityHeader, SequenceHeader},
};

/// Chunk info provides some basic information gleaned from reading the chunk such as offsets into
/// the chunk and so on. The chunk MUST be decrypted before calling this otherwise the values are
/// garbage.
#[derive(Debug, Clone, PartialEq)]
pub struct ChunkInfo {
    /// Message header.
    pub message_header: MessageChunkHeader,
    /// Chunks either have an asymmetric or symmetric security header
    pub security_header: SecurityHeader,
    /// Sequence header information
    pub sequence_header: SequenceHeader,
    /// Byte offset to sequence header
    pub security_header_offset: usize,
    /// Byte offset to sequence header
    pub sequence_header_offset: usize,
    /// Byte offset to actual message body
    pub body_offset: usize,
    /// Length of message body
    pub body_length: usize,
}

impl ChunkInfo {
    /// Create a new message chunk info instance, containing detailed information
    /// about the chunk.
    pub fn new(chunk: &MessageChunk, secure_channel: &SecureChannel) -> EncodingResult<ChunkInfo> {
        let mut stream = Cursor::new(&chunk.data);

        let decoding_options = secure_channel.decoding_options();

        let message_header = MessageChunkHeader::decode(&mut stream, &decoding_options)?;

        // Read the security header
        let security_header_offset = stream.position() as usize;
        let security_header = SecurityHeader::decode_from_stream(
            &mut stream,
            message_header.message_type.is_open_secure_channel(),
            &decoding_options,
        )?;

        // Read the sequence header. Note that this is garbage if the chunk is encrypted.
        let sequence_header_offset = stream.position() as usize;
        let sequence_header = SequenceHeader::decode(&mut stream, &decoding_options)?;

        // Read Body
        let body_offset = stream.position() as usize;

        // All of what follows is the message body
        let body_length = chunk.data.len() - body_offset;

        let chunk_info = ChunkInfo {
            message_header,
            security_header,
            sequence_header,
            security_header_offset,
            sequence_header_offset,
            body_offset,
            body_length,
        };

        Ok(chunk_info)
    }
}
