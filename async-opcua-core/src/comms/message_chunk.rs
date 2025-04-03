// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! A message chunk is a message or a portion of a message, optionally encrypted & signed, which
//! has been split for transmission.

use std::io::{Cursor, Read, Write};

use opcua_types::{
    process_decode_io_result, process_encode_io_result, read_u32, read_u8, status_code::StatusCode,
    write_u32, write_u8, DecodingOptions, EncodingResult, Error, SimpleBinaryDecodable,
    SimpleBinaryEncodable,
};
use tracing::{error, trace};

use super::{
    message_chunk_info::ChunkInfo,
    secure_channel::SecureChannel,
    security_header::{SecurityHeader, SequenceHeader},
    tcp_types::{
        CHUNK_FINAL, CHUNK_FINAL_ERROR, CHUNK_INTERMEDIATE, CHUNK_MESSAGE,
        CLOSE_SECURE_CHANNEL_MESSAGE, MIN_CHUNK_SIZE, OPEN_SECURE_CHANNEL_MESSAGE,
    },
};

/// The size of a chunk header, used by several places
pub const MESSAGE_CHUNK_HEADER_SIZE: usize = 3 + 1 + 4 + 4;
/// Offset of the MessageSize in chunk headers. This comes after the chunk type and
/// the is_final flag.
pub const MESSAGE_SIZE_OFFSET: usize = 3 + 1;

#[derive(Debug, Clone, Copy, PartialEq)]
/// Type of message chunk.
pub enum MessageChunkType {
    /// Chunk is part of a normal service message.
    Message,
    /// Chunk is an open secure channel message.
    OpenSecureChannel,
    /// Chunk is a close secure channel message.
    CloseSecureChannel,
}

impl MessageChunkType {
    /// `true` if this is an `OpenSecureChannel` message.
    pub fn is_open_secure_channel(&self) -> bool {
        *self == MessageChunkType::OpenSecureChannel
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
/// Type of message chunk.
pub enum MessageIsFinalType {
    /// Intermediate
    Intermediate,
    /// Final chunk
    Final,
    /// Abort
    FinalError,
}

#[derive(Debug, Clone, PartialEq)]
/// Message chunk header.
pub struct MessageChunkHeader {
    /// The kind of chunk - message, open or close
    pub message_type: MessageChunkType,
    /// The chunk type - C == intermediate, F = the final chunk, A = the final chunk when aborting
    pub is_final: MessageIsFinalType,
    /// The size of the chunk (message) including the header
    pub message_size: u32,
    /// Secure channel id
    pub secure_channel_id: u32,
}

impl SimpleBinaryEncodable for MessageChunkHeader {
    fn byte_len(&self) -> usize {
        MESSAGE_CHUNK_HEADER_SIZE
    }

    fn encode<S: Write + ?Sized>(&self, stream: &mut S) -> EncodingResult<()> {
        let message_type = match self.message_type {
            MessageChunkType::Message => CHUNK_MESSAGE,
            MessageChunkType::OpenSecureChannel => OPEN_SECURE_CHANNEL_MESSAGE,
            MessageChunkType::CloseSecureChannel => CLOSE_SECURE_CHANNEL_MESSAGE,
        };

        let is_final = match self.is_final {
            MessageIsFinalType::Intermediate => CHUNK_INTERMEDIATE,
            MessageIsFinalType::Final => CHUNK_FINAL,
            MessageIsFinalType::FinalError => CHUNK_FINAL_ERROR,
        };

        process_encode_io_result(stream.write_all(message_type))?;
        write_u8(stream, is_final)?;
        write_u32(stream, self.message_size)?;
        write_u32(stream, self.secure_channel_id)
    }
}

impl SimpleBinaryDecodable for MessageChunkHeader {
    fn decode<S: Read + ?Sized>(stream: &mut S, _: &DecodingOptions) -> EncodingResult<Self> {
        let mut message_type_code = [0u8; 3];
        process_decode_io_result(stream.read_exact(&mut message_type_code))?;
        let message_type = match &message_type_code as &[u8] {
            CHUNK_MESSAGE => MessageChunkType::Message,
            OPEN_SECURE_CHANNEL_MESSAGE => MessageChunkType::OpenSecureChannel,
            CLOSE_SECURE_CHANNEL_MESSAGE => MessageChunkType::CloseSecureChannel,
            r => {
                return Err(Error::decoding(format!(
                    "Invalid message chunk type: {r:?}"
                )));
            }
        };

        let chunk_type_code = read_u8(stream)?;
        let is_final = match chunk_type_code {
            CHUNK_FINAL => MessageIsFinalType::Final,
            CHUNK_INTERMEDIATE => MessageIsFinalType::Intermediate,
            CHUNK_FINAL_ERROR => MessageIsFinalType::FinalError,
            r => {
                return Err(Error::decoding(format!("Invalid message final type: {r}")));
            }
        };

        let message_size = read_u32(stream)?;
        let secure_channel_id = read_u32(stream)?;

        Ok(MessageChunkHeader {
            message_type,
            is_final,
            message_size,
            secure_channel_id,
        })
    }
}

impl MessageChunkHeader {}

/// A chunk holds a message or a portion of a message, if the message has been split into multiple chunks.
/// The chunk's data may be signed and encrypted. To extract the message requires all the chunks
/// to be available in sequence so they can be formed back into the message.
#[derive(Debug)]
pub struct MessageChunk {
    /// All of the chunk's data including headers, payload, padding, signature
    pub data: Vec<u8>,
}

impl SimpleBinaryEncodable for MessageChunk {
    fn byte_len(&self) -> usize {
        self.data.len()
    }

    fn encode<S: Write + ?Sized>(&self, stream: &mut S) -> EncodingResult<()> {
        stream.write_all(&self.data).map_err(|e| {
            Error::encoding(format!(
                "Encoding error while writing message chunk to stream: {e}"
            ))
        })
    }
}

impl SimpleBinaryDecodable for MessageChunk {
    fn decode<S: Read + ?Sized>(
        in_stream: &mut S,
        decoding_options: &DecodingOptions,
    ) -> EncodingResult<Self> {
        // Read the header out first
        let chunk_header =
            MessageChunkHeader::decode(in_stream, decoding_options).map_err(|err| {
                Error::new(
                    StatusCode::BadCommunicationError,
                    format!("Cannot decode chunk header {:?}", err),
                )
            })?;

        let message_size = chunk_header.message_size as usize;
        if decoding_options.max_message_size > 0 && message_size > decoding_options.max_message_size
        {
            // Message_size should be sanity checked and rejected if too large.
            Err(Error::new(
                StatusCode::BadTcpMessageTooLarge,
                format!(
                    "Message size {} exceeds maximum message size {}",
                    message_size, decoding_options.max_message_size
                ),
            ))
        } else {
            // Now make a buffer to write the header and message into
            let data = vec![0u8; message_size];
            let mut stream = Cursor::new(data);

            // Write header to a buffer
            let chunk_header_size = chunk_header.byte_len();
            chunk_header.encode(&mut stream)?;

            // Get the data (with header written to it)
            let mut data = stream.into_inner();

            // Read remainder of stream into slice after the header
            in_stream.read_exact(&mut data[chunk_header_size..])?;

            Ok(MessageChunk { data })
        }
    }
}

#[derive(Debug)]
/// Error returned if the chunk is too small, this indicates
/// an error somewhere else.
pub struct MessageChunkTooSmall;

impl MessageChunk {
    /// Create a new message chunk.
    pub fn new(
        sequence_number: u32,
        request_id: u32,
        message_type: MessageChunkType,
        is_final: MessageIsFinalType,
        secure_channel: &SecureChannel,
        data: &[u8],
    ) -> EncodingResult<MessageChunk> {
        // security header depends on message type
        let security_header = secure_channel.make_security_header(message_type);
        let sequence_header = SequenceHeader {
            sequence_number,
            request_id,
        };

        // Calculate the chunk body size
        let mut message_size = MESSAGE_CHUNK_HEADER_SIZE;
        message_size += security_header.byte_len();
        message_size += sequence_header.byte_len();
        message_size += data.len();

        trace!(
            "Creating a chunk with a size of {}, data excluding padding & signature",
            message_size
        );
        let secure_channel_id = secure_channel.secure_channel_id();
        let chunk_header = MessageChunkHeader {
            message_type,
            is_final,
            message_size: message_size as u32,
            secure_channel_id,
        };

        let mut buf = vec![0u8; message_size];
        let buf_ref = &mut buf as &mut [u8];
        let mut stream = Cursor::new(buf_ref);
        // write chunk header
        chunk_header.encode(&mut stream)?;
        // write security header
        security_header.encode(&mut stream)?;
        // write sequence header
        sequence_header.encode(&mut stream)?;
        // write message
        stream.write_all(data)?;

        Ok(MessageChunk { data: buf })
    }

    /// Calculates the body size that fit inside of a message chunk of a particular size.
    /// This requires calculating the size of the header, the signature, padding etc. and deducting it
    /// to reveal the message size
    pub fn body_size_from_message_size(
        message_type: MessageChunkType,
        secure_channel: &SecureChannel,
        max_chunk_size: usize,
    ) -> Result<usize, MessageChunkTooSmall> {
        if max_chunk_size < MIN_CHUNK_SIZE {
            error!(
                "chunk size {} is less than minimum allowed by the spec",
                max_chunk_size
            );
            return Err(MessageChunkTooSmall);
        }
        // First, get the size of the various message chunk headers.
        let security_header = secure_channel.make_security_header(message_type);

        let mut header_size = MESSAGE_CHUNK_HEADER_SIZE;
        header_size += security_header.byte_len();
        header_size += (SequenceHeader {
            sequence_number: 0,
            request_id: 0,
        })
        .byte_len();

        // Next, get the size of the signature, which may be zero if the
        // header isn't signed.
        let signature_size = secure_channel.signature_size(&security_header);

        // Get the encryption block size, and the minimum padding length.
        // The minimum padding depends on the key length.
        let (plain_text_block_size, minimum_padding) =
            secure_channel.get_padding_block_sizes(&security_header, signature_size, message_type);

        // Compute the max chunk size aligned to an encryption block.
        // When encrypting, the size must be a whole multiple of `plain_text_block_size`,
        // we round the max chunk size down to the nearest such chunk.
        let aligned_max_chunk_size = if plain_text_block_size > 0 {
            max_chunk_size - (max_chunk_size % plain_text_block_size)
        } else {
            max_chunk_size
        };
        // So, the total maximum chunk body size is
        // - the aligned chunk size,
        // - minus the size of the message chunk headers.
        // - minus the size of the signature.
        // - minus the minimum padding.

        // This means that if the chunk size is 8191, with 32 bytes header and 32 bytes signature,
        // 1 minimum padding and 16 bytes block size,
        // we get a chunk size of 8111. Add the header, 8143, add the signature
        // 8175, pad with a minimum padding of 1 -> 8176.

        // Note that if we used a chunk size of 8112 instead, we would end up with
        // 8176 bytes after header and signature, and we would need to pad _16_ bytes,
        // which would put us at 8192, which exceeds the configured limit.
        // So 8111 is the largest the chunk can possibly be with this chunk size.

        Ok(aligned_max_chunk_size - header_size - signature_size - minimum_padding)
    }

    /// Decode the message header from the inner data.
    pub fn message_header(
        &self,
        decoding_options: &DecodingOptions,
    ) -> EncodingResult<MessageChunkHeader> {
        // Message header is first so just read it
        let mut stream = Cursor::new(&self.data);
        MessageChunkHeader::decode(&mut stream, decoding_options)
    }

    /// Check if this message is an OpenSecureChannel request.
    pub fn is_open_secure_channel(&self, decoding_options: &DecodingOptions) -> bool {
        if let Ok(message_header) = self.message_header(decoding_options) {
            message_header.message_type.is_open_secure_channel()
        } else {
            false
        }
    }

    /// Decode info about this chunk.
    pub fn chunk_info(&self, secure_channel: &SecureChannel) -> EncodingResult<ChunkInfo> {
        ChunkInfo::new(self, secure_channel)
    }

    pub(crate) fn encrypted_data_offset(
        &self,
        decoding_options: &DecodingOptions,
    ) -> EncodingResult<usize> {
        // Fetch just the encrypted data offset, which may be slightly more efficient than
        // fetching the entire ChunkInfo struct.
        let mut stream = Cursor::new(&self.data);
        let message_header = MessageChunkHeader::decode(&mut stream, decoding_options)?;
        SecurityHeader::decode_from_stream(
            &mut stream,
            message_header.message_type.is_open_secure_channel(),
            decoding_options,
        )?;
        Ok(stream.position() as usize)
    }
}
