// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! The codec is an implementation of a tokio Encoder/Decoder which can be used to read
//! data from the socket in terms of frames which in our case are any of the following:
//!
//! * HEL - Hello message
//! * ACK - Acknowledge message
//! * ERR - Error message
//! * MSG - Message chunk
//! * OPN - Open Secure Channel message
//! * CLO - Close Secure Channel message
use std::{
    io::{self, IoSlice},
    sync::atomic::{AtomicU64, Ordering},
};

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio_util::codec::{Decoder, Encoder};
use tracing::error;

use opcua_types::{
    constants,
    encoding::{DecodingOptions, SimpleBinaryDecodable, SimpleBinaryEncodable},
    status_code::StatusCode,
};

use super::{
    message_chunk::MessageChunk,
    tcp_types::{
        AcknowledgeMessage, ErrorMessage, HelloMessage, MessageHeader, MessageType,
        ReverseHelloMessage, MESSAGE_HEADER_LEN,
    },
};

/// Thread-safe counters for outbound serialization.
#[derive(Debug)]
pub struct SerializationMetrics {
    /// Number of serialization failures observed while encoding outbound messages.
    pub serialization_errors: AtomicU64,
    /// Total number of bytes successfully written to outbound buffers.
    pub bytes_written: AtomicU64,
}

impl SerializationMetrics {
    /// Creates a zero-initialized serialization metrics registry.
    pub const fn new() -> Self {
        Self {
            serialization_errors: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
        }
    }
}

impl Default for SerializationMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Global outbound serialization metrics registry.
pub static SERIALIZATION_METRICS: SerializationMetrics = SerializationMetrics::new();

#[derive(Debug)]
/// Message type sent over OPC-UA streams.
pub enum Message {
    /// Hello message, the first part of a connection negotiation.
    Hello(HelloMessage),
    /// Acknowledge message, acceptance of negotiation.
    Acknowledge(AcknowledgeMessage),
    /// Error message, final fatal message describing reason for
    /// why the channel will be closed.
    Error(ErrorMessage),
    /// Part of a general OPC-UA message.
    Chunk(MessageChunk),
    /// Reverse Hello message, sent by the server to the client.
    ReverseHello(ReverseHelloMessage),
}

/// Implements a tokio codec that as close as possible, allows incoming data to be transformed into
/// OPC UA message chunks with no intermediate buffers. Chunks are subsequently transformed into
/// messages so there is still some buffers within message chunks, but not at the raw socket level.
pub struct TcpCodec {
    decoding_options: DecodingOptions,
    write_buf: BytesMut,
}

impl Decoder for TcpCodec {
    type Item = Message;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.len() >= MESSAGE_HEADER_LEN {
            // Every OPC UA message has at least 8 bytes of header to be read to see what follows

            // Get the message header
            let message_header = {
                let header = buf
                    .get(..MESSAGE_HEADER_LEN)
                    .ok_or_else(|| io::Error::other("Cannot decode TCP message header"))?;
                let mut buf = io::Cursor::new(header);
                MessageHeader::decode(&mut buf, &self.decoding_options)?
            };

            // Once we have the header we can infer the message size required to read the rest of
            // the message. The buffer needs to have at least that amount of bytes in it for the
            // whole message to be extracted.
            let message_size = message_header.message_size as usize;
            Self::validate_declared_message_size(message_size, &self.decoding_options)?;
            if buf.len() >= message_size {
                // Extract the message bytes from the buffer & decode them into a message
                let mut buf = buf.split_to(message_size);
                let message =
                    Self::decode_message(message_header, &mut buf, &self.decoding_options)
                        .map_err(|e| {
                            error!("Codec got an error {} while decoding a message", e);
                            io::Error::from(e)
                        })?;
                Ok(Some(message))
            } else {
                // Not enough bytes
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }
}

impl Encoder<Message> for TcpCodec {
    type Error = io::Error;

    fn encode(&mut self, data: Message, buf: &mut BytesMut) -> Result<(), io::Error> {
        self.reset_write_buffer();
        let max_message_size = self.decoding_options.max_message_size;

        let result = match data {
            Message::Hello(msg) => Self::write(msg, max_message_size, &mut self.write_buf),
            Message::Acknowledge(msg) => Self::write(msg, max_message_size, &mut self.write_buf),
            Message::Error(msg) => Self::write(msg, max_message_size, &mut self.write_buf),
            Message::Chunk(msg) => Self::write(msg, max_message_size, &mut self.write_buf),
            Message::ReverseHello(msg) => Self::write(msg, max_message_size, &mut self.write_buf),
        };

        if let Err(err) = result {
            SERIALIZATION_METRICS
                .serialization_errors
                .fetch_add(1, Ordering::Relaxed);
            self.reset_write_buffer();
            return Err(err);
        }

        let bytes_written = self.write_buf.len() as u64;
        buf.put_slice(&self.write_buf);
        SERIALIZATION_METRICS
            .bytes_written
            .fetch_add(bytes_written, Ordering::Relaxed);
        self.reset_write_buffer();
        Ok(())
    }
}

impl TcpCodec {
    /// Constructs a new TcpCodec. The abort flag is set to terminate the codec even while it is
    /// waiting for a frame to arrive.
    pub fn new(decoding_options: DecodingOptions) -> TcpCodec {
        TcpCodec {
            decoding_options,
            write_buf: BytesMut::with_capacity(65536),
        }
    }

    /// Clears the reusable connection-local write buffer without releasing its allocation.
    pub fn reset_write_buffer(&mut self) {
        self.write_buf.clear();
    }

    /// Writes one OPC UA TCP frame using vectored I/O, splitting the common header from the body.
    pub async fn write_frame_vectored<W>(write: &mut W, frame: &[u8]) -> Result<usize, io::Error>
    where
        W: AsyncWrite + Unpin + ?Sized,
    {
        let slices = Self::frame_slices(frame);
        write.write_vectored(&slices).await
    }

    /// Writes one complete OPC UA TCP frame using repeated vectored writes.
    pub async fn write_all_frame_vectored<W>(
        write: &mut W,
        mut frame: &[u8],
    ) -> Result<(), io::Error>
    where
        W: AsyncWrite + Unpin + ?Sized,
    {
        while !frame.is_empty() {
            let written = Self::write_frame_vectored(write, frame).await?;
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write OPC UA frame",
                ));
            }
            frame = frame
                .get(written..)
                .ok_or_else(|| io::Error::other("invalid TCP frame write range"))?;
        }
        Ok(())
    }

    fn frame_slices(frame: &[u8]) -> [IoSlice<'_>; 2] {
        let split_at = frame.len().min(MESSAGE_HEADER_LEN);
        let (header, body) = frame.split_at(split_at);
        [IoSlice::new(header), IoSlice::new(body)]
    }

    fn validate_declared_message_size(
        message_size: usize,
        decoding_options: &DecodingOptions,
    ) -> Result<(), io::Error> {
        // 0 means "unlimited" for negotiated message assembly, but the TCP frame decoder still
        // needs a finite guard before waiting for or splitting an attacker-declared frame.
        let max_message_size = if decoding_options.max_message_size == 0 {
            constants::MAX_MESSAGE_SIZE
        } else {
            decoding_options.max_message_size
        };

        if message_size < MESSAGE_HEADER_LEN {
            return Err(io::Error::other(opcua_types::Error::new(
                StatusCode::BadTcpMessageTooLarge,
                format!(
                    "Message size {message_size} is smaller than TCP header size {MESSAGE_HEADER_LEN}"
                ),
            )));
        }

        if message_size > max_message_size {
            return Err(io::Error::other(opcua_types::Error::new(
                StatusCode::BadTcpMessageTooLarge,
                format!(
                    "Message size {message_size} exceeds maximum message size {max_message_size}"
                ),
            )));
        }

        Ok(())
    }

    // Writes the encodable thing into the buffer.
    fn write<T>(msg: T, max_message_size: usize, buf: &mut BytesMut) -> Result<(), io::Error>
    where
        T: SimpleBinaryEncodable + std::fmt::Debug,
    {
        let encoded_len = msg.byte_len();
        if max_message_size > 0 && encoded_len > max_message_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Encoded message length {encoded_len} exceeds maximum message size {max_message_size}"
                ),
            ));
        }
        buf.reserve(encoded_len);
        msg.encode(&mut buf.writer()).map(|_| ()).map_err(|err| {
            error!("Error writing message {:?}, err = {}", msg, err);
            io::Error::other(format!("Error = {err}"))
        })
    }

    /// Reads a message out of the buffer, which is assumed by now to be the proper length
    fn decode_message(
        message_header: MessageHeader,
        bytes_mut: &mut BytesMut,
        decoding_options: &DecodingOptions,
    ) -> Result<Message, StatusCode> {
        let mut buf = io::Cursor::new(&bytes_mut[..]);
        match message_header.message_type {
            MessageType::Acknowledge => Ok(Message::Acknowledge(AcknowledgeMessage::decode(
                &mut buf,
                decoding_options,
            )?)),
            MessageType::Hello => Ok(Message::Hello(HelloMessage::decode(
                &mut buf,
                decoding_options,
            )?)),
            MessageType::Error => Ok(Message::Error(ErrorMessage::decode(
                &mut buf,
                decoding_options,
            )?)),
            MessageType::Chunk => {
                let mut bytes = bytes_mut.split_to(bytes_mut.len()).freeze();
                let chunk = MessageChunk::decode_zero_copy(&mut bytes, decoding_options)?;
                Ok(Message::Chunk(chunk))
            }
            MessageType::ReverseHello => Ok(Message::ReverseHello(ReverseHelloMessage::decode(
                &mut buf,
                decoding_options,
            )?)),
            MessageType::Invalid => {
                error!("Message type for chunk is invalid.");
                Err(StatusCode::BadCommunicationError)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::{BufMut, BytesMut};
    use opcua_types::{
        encoding::{DecodingOptions, SimpleBinaryEncodable},
        StatusCode,
    };
    use tokio_util::codec::Decoder;

    use super::{ErrorMessage, Message, TcpCodec, MESSAGE_HEADER_LEN};

    fn error_frame(reason: &str) -> BytesMut {
        let message = ErrorMessage::new(StatusCode::BadUnexpectedError, reason);
        let mut frame = BytesMut::with_capacity(message.byte_len());
        message.encode(&mut (&mut frame).writer()).unwrap();
        frame
    }

    fn connection_header_frame(message_type: &[u8], message_size: u32) -> BytesMut {
        let mut frame = BytesMut::from(message_type);
        frame.extend_from_slice(&message_size.to_le_bytes());
        frame
    }

    fn oversized_header_frame(message_size: u32) -> BytesMut {
        connection_header_frame(&b"ERRF"[..], message_size)
    }

    #[test]
    fn decode_rejects_declared_message_size_above_configured_max() {
        let mut codec = TcpCodec::new(DecodingOptions {
            max_message_size: 16,
            ..DecodingOptions::default()
        });
        let mut frame = oversized_header_frame(17);

        let err = codec.decode(&mut frame).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert!(err.to_string().contains("BadTcpMessageTooLarge"));
    }

    #[test]
    fn decode_rejects_oversized_declared_message_size_before_payload_allocation() {
        let mut codec = TcpCodec::new(DecodingOptions {
            max_message_size: 0,
            ..DecodingOptions::default()
        });
        let mut frame = oversized_header_frame(u32::MAX);
        let initial_capacity = frame.capacity();

        let err = codec.decode(&mut frame).expect_err(
            "OPC-10000-6 7.1.2.2 and 7.1.5 require BadTcpMessageTooLarge \
             for an impossible declared MessageSize before waiting for the payload",
        );

        assert!(
            err.to_string().contains("BadTcpMessageTooLarge"),
            "expected BadTcpMessageTooLarge for oversized declared MessageSize {}, got {err}",
            u32::MAX
        );
        assert_eq!(
            frame.capacity(),
            initial_capacity,
            "decoder must reject from the header without reserving the declared payload"
        );
    }

    #[test]
    fn pre_hello_ack_and_err_declared_message_sizes_are_bounded_before_negotiation() {
        for message_type in [&b"ACKF"[..], &b"ERRF"[..]] {
            let mut codec = TcpCodec::new(DecodingOptions {
                max_message_size: 0,
                ..DecodingOptions::default()
            });
            let mut frame = connection_header_frame(message_type, u32::MAX);
            let initial_capacity = frame.capacity();
            let label = std::str::from_utf8(message_type).unwrap();

            let err = codec.decode(&mut frame).expect_err(
                "OPC-10000-6 7.1.2.2 requires pre-Hello ACK/ERR MessageSize \
                 to be bounded before negotiation; expected BadTcpMessageTooLarge \
                 instead of waiting for the declared payload",
            );

            assert!(
                err.to_string().contains("BadTcpMessageTooLarge"),
                "expected BadTcpMessageTooLarge for pre-Hello {label} declared MessageSize {}, got {err}",
                u32::MAX
            );
            assert_eq!(
                frame.capacity(),
                initial_capacity,
                "pre-Hello {label} decoder path must reject from the header without reserving the declared payload"
            );
        }
    }

    #[test]
    fn pre_hello_ack_and_err_declared_message_sizes_below_header_are_rejected_before_splitting() {
        for message_type in [&b"ACKF"[..], &b"ERRF"[..]] {
            let mut codec = TcpCodec::new(DecodingOptions {
                max_message_size: 0,
                ..DecodingOptions::default()
            });
            let mut frame = connection_header_frame(message_type, (MESSAGE_HEADER_LEN - 1) as u32);
            let initial_len = frame.len();
            let label = std::str::from_utf8(message_type).unwrap();

            let err = codec.decode(&mut frame).expect_err(
                "OPC-10000-6 7.1.2.2 requires MessageSize to include the 8-byte \
                 header; expected BadTcpMessageTooLarge before splitting the buffer",
            );

            assert!(
                err.to_string().contains("BadTcpMessageTooLarge"),
                "expected BadTcpMessageTooLarge for pre-Hello {label} declared MessageSize {}, got {err}",
                MESSAGE_HEADER_LEN - 1
            );
            assert_eq!(
                frame.len(),
                initial_len,
                "pre-Hello {label} decoder path must reject a below-header MessageSize without consuming bytes"
            );
        }
    }

    #[test]
    fn decode_accepts_declared_message_size_equal_to_configured_max() {
        let mut frame = error_frame("fits exactly");
        let mut codec = TcpCodec::new(DecodingOptions {
            max_message_size: frame.len(),
            ..DecodingOptions::default()
        });

        let decoded = codec.decode(&mut frame).unwrap();

        assert!(matches!(decoded, Some(Message::Error(_))));
    }

    #[test]
    fn decode_accepts_large_declared_message_size_when_max_is_unlimited() {
        let mut frame = error_frame(&"large but unlimited ".repeat(32));
        let mut codec = TcpCodec::new(DecodingOptions {
            max_message_size: 0,
            ..DecodingOptions::default()
        });

        let decoded = codec.decode(&mut frame).unwrap();

        assert!(matches!(decoded, Some(Message::Error(_))));
    }
}
