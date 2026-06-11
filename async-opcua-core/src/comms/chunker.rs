// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Contains code for turning messages into chunks and chunks into messages.

use std::io::{Read, Write};

use crate::{
    comms::{
        message_chunk::{MessageChunk, MessageIsFinalType},
        secure_channel::SecureChannel,
        sequence_number::SequenceNumberHandle,
    },
    Message,
};

use opcua_crypto::SecurityPolicy;
use opcua_types::{
    encoding::BinaryEncodable, node_id::NodeId, status_code::StatusCode, BinaryDecodable,
    EncodingResult, Error, ObjectId, SimpleBinaryEncodable,
};
use tracing::{debug, error, trace};

use super::{message_chunk::MessageChunkType, security_header::SequenceHeader};

/// Read implementation for a sequence of message chunks.
/// This lets us avoid allocating a buffer for the message.
///
/// All this type does is `Read` to the end of each chunk, then step into the next
/// chunk once the previous chunk is exhausted.
struct ReceiveStream<'a, T> {
    buffer: &'a [u8],
    channel: &'a SecureChannel,
    items: T,
    num_items: usize,
    pos: usize,
    index: usize,
}
impl<'a, T: Iterator<Item = &'a MessageChunk>> ReceiveStream<'a, T> {
    fn new(channel: &'a SecureChannel, mut items: T, num_items: usize) -> Result<Self, Error> {
        let Some(chunk) = items.next() else {
            return Err(Error::new(
                StatusCode::BadUnexpectedError,
                "Stream contained no chunks",
            ));
        };

        let chunk_info = chunk.chunk_info(channel)?;
        let expected_is_final = if num_items == 1 {
            MessageIsFinalType::Final
        } else {
            MessageIsFinalType::Intermediate
        };
        if chunk_info.message_header.is_final != expected_is_final {
            return Err(Error::new(
                StatusCode::BadDecodingError,
                "Last chunk not marked as final",
            ));
        }

        let body_start = chunk_info.body_offset;
        let body_end = body_start + chunk_info.body_length;
        let body_data = &chunk.data[body_start..body_end];
        Ok(Self {
            buffer: body_data,
            channel,
            items,
            pos: 0,
            num_items,
            index: 0,
        })
    }
}

impl<'a, T: Iterator<Item = &'a MessageChunk>> Read for ReceiveStream<'a, T> {
    fn read(&mut self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        if self.buffer.len() == self.pos {
            let Some(chunk) = self.items.next() else {
                return Ok(0);
            };
            self.index += 1;
            let chunk_info = chunk.chunk_info(self.channel)?;
            let expected_is_final = if self.index == self.num_items - 1 {
                MessageIsFinalType::Final
            } else {
                MessageIsFinalType::Intermediate
            };
            if chunk_info.message_header.is_final != expected_is_final {
                return Err(StatusCode::BadDecodingError.into());
            }

            let body_start = chunk_info.body_offset;
            let body_end = body_start + chunk_info.body_length;
            let body_data = &chunk.data[body_start..body_end];
            self.buffer = body_data;
            self.pos = 0;
        }
        let written = buf.write(&self.buffer[self.pos..])?;
        self.pos += written;
        Ok(written)
    }
}

/// Streaming chunk encoder that writes complete chunks (headers + body)
/// contiguously into a caller-provided [`BytesMut`], emitting each chunk as a
/// zero-copy [`Bytes`](bytes::Bytes) slice of that storage. With a reused
/// connection-local storage buffer this makes steady-state transmit encoding
/// allocation free: once the chunks from the previous message are dropped the
/// storage allocation is reclaimed by `reserve`.
struct ChunkingStream<'a, 'b> {
    secure_channel: &'a SecureChannel,
    storage: &'b mut bytes::BytesMut,
    out: &'b mut Vec<MessageChunk>,
    expected_chunk_count: usize,
    chunks_emitted: usize,
    max_body_per_chunk: usize,
    header_size: usize,
    current_body_target: usize,
    body_written: usize,
    chunk_started: bool,
    is_closed: bool,
    sequence_number: SequenceNumberHandle,
    request_id: u32,
    message_size: usize,
    message_type: MessageChunkType,
}

impl<'a, 'b> ChunkingStream<'a, 'b> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        message_type: MessageChunkType,
        secure_channel: &'a SecureChannel,
        max_chunk_size: usize,
        message_size: usize,
        request_id: u32,
        request_handle: u32,
        sequence_number: SequenceNumberHandle,
        storage: &'b mut bytes::BytesMut,
        out: &'b mut Vec<MessageChunk>,
    ) -> Result<Self, Error> {
        let (expected_chunk_count, max_body_per_chunk) = if max_chunk_size > 0 {
            let max_body_per_chunk = MessageChunk::body_size_from_message_size(
                message_type,
                secure_channel,
                max_chunk_size,
            )
            .map_err(|e| {
                e.with_context(
                    Some(request_id),
                    if request_handle > 0 {
                        Some(request_handle)
                    } else {
                        None
                    },
                )
            })?;
            (message_size / max_body_per_chunk + 1, max_body_per_chunk)
        } else {
            (1, 0)
        };

        let security_header = secure_channel.make_security_header(message_type);
        let header_size = super::message_chunk::MESSAGE_CHUNK_HEADER_SIZE
            + SimpleBinaryEncodable::byte_len(&security_header)
            + SimpleBinaryEncodable::byte_len(&SequenceHeader {
                sequence_number: 0,
                request_id: 0,
            });

        // Any leftovers from a previously failed encode are dead; this only
        // touches the unsplit tail, so chunks still in flight are unaffected.
        storage.clear();
        // On a warmed buffer whose previous chunks have been sent and
        // dropped, this reclaims the existing allocation instead of
        // allocating anew.
        storage.reserve(message_size + expected_chunk_count * header_size);

        Ok(Self {
            secure_channel,
            storage,
            out,
            expected_chunk_count,
            chunks_emitted: 0,
            max_body_per_chunk,
            header_size,
            current_body_target: 0,
            body_written: 0,
            chunk_started: false,
            is_closed: false,
            sequence_number,
            request_id,
            message_type,
            message_size,
        })
    }

    /// Write the chunk headers for the next chunk. The body size of every
    /// chunk is known up front, so the headers can be written before the
    /// body streams in.
    fn start_chunk(&mut self) -> EncodingResult<()> {
        let is_last = self.chunks_emitted == self.expected_chunk_count - 1;
        self.current_body_target = if self.max_body_per_chunk == 0 {
            self.message_size
        } else if is_last {
            self.message_size % self.max_body_per_chunk
        } else {
            self.max_body_per_chunk
        };
        let is_final = if is_last {
            MessageIsFinalType::Final
        } else {
            MessageIsFinalType::Intermediate
        };

        let chunk_header = super::message_chunk::MessageChunkHeader {
            message_type: self.message_type,
            is_final,
            message_size: (self.header_size + self.current_body_target) as u32,
            secure_channel_id: self.secure_channel.secure_channel_id(),
        };
        let security_header = self.secure_channel.make_security_header(self.message_type);
        let sequence_header = SequenceHeader {
            sequence_number: self.sequence_number.current(),
            request_id: self.request_id,
        };
        self.sequence_number.increment(1);

        let mut writer = bytes::BufMut::writer(&mut *self.storage);
        SimpleBinaryEncodable::encode(&chunk_header, &mut writer)?;
        SimpleBinaryEncodable::encode(&security_header, &mut writer)?;
        SimpleBinaryEncodable::encode(&sequence_header, &mut writer)?;

        self.body_written = 0;
        self.chunk_started = true;
        Ok(())
    }

    fn emit_chunk(&mut self) {
        let chunk_len = self.header_size + self.current_body_target;
        let data = self.storage.split_to(chunk_len).freeze();
        self.out.push(MessageChunk { data });
        self.chunks_emitted += 1;
        self.chunk_started = false;
        if self.chunks_emitted == self.expected_chunk_count {
            self.is_closed = true;
        }
    }

    fn finish(self) -> EncodingResult<usize> {
        if !self.is_closed {
            return Err(Error::encoding(
                "Message did not encode to the expected size",
            ));
        }
        Ok(self.chunks_emitted)
    }
}

impl Write for ChunkingStream<'_, '_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.is_closed {
            return Ok(0);
        }
        if !self.chunk_started {
            self.start_chunk()?;
        }

        let to_read = buf.len().min(self.current_body_target - self.body_written);
        self.storage.extend_from_slice(&buf[..to_read]);
        self.body_written += to_read;
        if self.body_written == self.current_body_target {
            self.emit_chunk();
        }

        Ok(to_read)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.is_closed {
            return Ok(());
        }
        if !self.chunk_started {
            self.start_chunk()?;
        }
        // Mirror the old zero-initialized buffer: a message that encodes
        // shorter than its declared byte_len pads the chunk with zeros.
        if self.body_written < self.current_body_target {
            bytes::BufMut::put_bytes(
                &mut *self.storage,
                0,
                self.current_body_target - self.body_written,
            );
            self.body_written = self.current_body_target;
        }
        self.emit_chunk();
        Ok(())
    }
}

/// The Chunker is responsible for turning messages to chunks and chunks into messages.
pub struct Chunker;

impl Chunker {
    /// Ensure all of the supplied chunks have a valid secure channel id, and the correct
    /// request ID.
    ///
    /// The function returns
    /// `BadSequenceNumberInvalid` or `BadSecureChannelIdInvalid` for failure.
    pub fn validate_chunks(
        secure_channel: &SecureChannel,
        chunks: &[MessageChunk],
    ) -> Result<(), Error> {
        let first_sequence_number = {
            let chunk_info = chunks[0].chunk_info(secure_channel)?;
            chunk_info.sequence_header.sequence_number
        };
        trace!(
            "Received chunk with sequence number {}",
            first_sequence_number
        );

        let secure_channel_id = secure_channel.secure_channel_id();

        // Validate that all chunks have incrementing sequence numbers and valid chunk types
        let mut expected_request_id: u32 = 0;
        for (i, chunk) in chunks.iter().enumerate() {
            let chunk_info = chunk.chunk_info(secure_channel)?;

            // Check the channel id of each chunk
            if secure_channel_id != 0
                && chunk_info.message_header.secure_channel_id != secure_channel_id
            {
                return Err(Error::new(
                    StatusCode::BadSecureChannelIdInvalid,
                    format!(
                        "Secure channel id {} does not match expected id {}",
                        chunk_info.message_header.secure_channel_id, secure_channel_id
                    ),
                ));
            }
            let sequence_number = chunk_info.sequence_header.sequence_number;

            // Check the request id against the first chunk's request id
            if i == 0 {
                expected_request_id = chunk_info.sequence_header.request_id;
            } else if chunk_info.sequence_header.request_id != expected_request_id {
                return Err(Error::new(StatusCode::BadSequenceNumberInvalid, format!(
                    "Chunk sequence number of {} has a request id {} which is not the expected value of {}, idx {}",
                    sequence_number, chunk_info.sequence_header.request_id, expected_request_id, i
                )));
            }
        }
        Ok(())
    }

    /// Encodes a message using the supplied sequence number and secure channel info and emits the corresponding chunks
    ///
    /// max_chunk_count refers to the maximum byte length that a chunk should not exceed or 0 for no limit
    /// max_message_size refers to the maximum byte length of a message or 0 for no limit
    ///
    pub fn encode(
        sequence_number: SequenceNumberHandle,
        request_id: u32,
        max_message_size: usize,
        max_chunk_size: usize,
        secure_channel: &SecureChannel,
        supported_message: &impl Message,
    ) -> std::result::Result<Vec<MessageChunk>, Error> {
        let mut storage = bytes::BytesMut::new();
        let mut chunks = Vec::new();
        Self::encode_into(
            sequence_number,
            request_id,
            max_message_size,
            max_chunk_size,
            secure_channel,
            supported_message,
            &mut storage,
            &mut chunks,
        )?;
        Ok(chunks)
    }

    /// Encodes a message like [`Chunker::encode`], but writes the chunk data
    /// into the reusable `storage` buffer and appends the resulting chunks to
    /// `out`, returning how many chunks were produced.
    ///
    /// Each produced [`MessageChunk`] holds a zero-copy slice of `storage`;
    /// once those chunks are dropped the storage allocation is reclaimed by
    /// the next call, so a connection that reuses both buffers does not
    /// allocate on the transmit path at steady state.
    #[allow(clippy::too_many_arguments)]
    pub fn encode_into(
        sequence_number: SequenceNumberHandle,
        request_id: u32,
        max_message_size: usize,
        max_chunk_size: usize,
        secure_channel: &SecureChannel,
        supported_message: &impl Message,
        storage: &mut bytes::BytesMut,
        out: &mut Vec<MessageChunk>,
    ) -> std::result::Result<usize, Error> {
        let security_policy = secure_channel.security_policy();
        if security_policy == SecurityPolicy::Unknown {
            panic!("Security policy cannot be unknown");
        }

        let ctx_id = Some(request_id);
        let handle = supported_message.request_handle();
        let ctx_handle = if handle > 0 { Some(handle) } else { None };

        // Client / server stacks should validate the length of a message before sending it and
        // here makes as good a place as any to do that.
        let ctx_r = secure_channel.context();
        let ctx = ctx_r.context();
        let mut message_size = supported_message.byte_len(&ctx);
        if max_message_size > 0 && message_size > max_message_size {
            error!(
                "Max message size is {} and message {} exceeds that",
                max_message_size, message_size
            );
            // Client stack should report a BadRequestTooLarge, server BadResponseTooLarge
            return Err(Error::new(
                if secure_channel.is_client_role() {
                    StatusCode::BadRequestTooLarge
                } else {
                    StatusCode::BadResponseTooLarge
                },
                format!(
                    "Max message size is {max_message_size} and message {message_size} exceeds that"
                ),
            )
            .with_context(ctx_id, ctx_handle));
        }

        let node_id = supported_message.type_id();
        message_size += node_id.byte_len(&ctx);

        let message_type = supported_message.message_type();

        let mut stream = ChunkingStream::new(
            message_type,
            secure_channel,
            max_chunk_size,
            message_size,
            request_id,
            handle,
            sequence_number,
            storage,
            out,
        )?;

        node_id.encode(&mut stream, &ctx)?;
        supported_message
            .encode(&mut stream, &ctx)
            .map_err(|e| e.with_context(ctx_id, ctx_handle))?;

        stream.flush()?;

        stream.finish()
    }

    /// Decodes a series of chunks to create a message. The message must be of a `SupportedMessage`
    /// type otherwise an error will occur.
    pub fn decode<T: Message>(
        chunks: &[MessageChunk],
        secure_channel: &SecureChannel,
        expected_node_id: Option<NodeId>,
    ) -> std::result::Result<T, Error> {
        // Calculate the size of data held in all chunks
        for (i, chunk) in chunks.iter().enumerate() {
            let chunk_info = chunk.chunk_info(secure_channel)?;
            // The last most chunk is expected to be final, the rest intermediate
            let expected_is_final = if i == chunks.len() - 1 {
                MessageIsFinalType::Final
            } else {
                MessageIsFinalType::Intermediate
            };
            if chunk_info.message_header.is_final != expected_is_final {
                return Err(Error::decoding(
                    "Last message in sequence is not marked as final",
                ));
            }
        }

        let mut stream = ReceiveStream::new(secure_channel, chunks.iter(), chunks.len())?;

        // The extension object prefix is just the node id. A point the spec rather unhelpfully doesn't
        // elaborate on. Probably because people enjoy debugging why the stream pos is out by 1 byte
        // for hours.

        let ctx_r = secure_channel.context();
        let ctx = ctx_r.context();

        // Read node id from stream
        let node_id = NodeId::decode(&mut stream, &ctx)?;
        let object_id = Self::object_id_from_node_id(node_id, expected_node_id)?;

        // Now decode the payload using the node id.
        match T::decode_by_object_id(&mut stream, object_id, &ctx) {
            Ok(decoded_message) => {
                // debug!("Returning decoded msg {:?}", decoded_message);
                Ok(decoded_message)
            }
            Err(err) => {
                debug!("Cannot decode message {:?}, err = {:?}", object_id, err);
                Err(err)
            }
        }
    }

    fn object_id_from_node_id(
        node_id: NodeId,
        expected_node_id: Option<NodeId>,
    ) -> Result<ObjectId, Error> {
        if let Some(id) = expected_node_id {
            if node_id != id {
                return Err(Error::decoding(format!(
                    "The message ID {node_id} is not the expected value {id}"
                )));
            }
        }
        node_id
            .as_object_id()
            .map_err(|_| Error::decoding(format!("The message id {node_id} is not an object id")))
    }
}
