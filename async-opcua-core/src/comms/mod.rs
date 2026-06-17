// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Contains all code related to sending / receiving messages from a transport
//! and turning those messages into and out of chunks.

pub mod buffer;
pub mod chunker;
pub mod message_chunk;
pub mod message_chunk_info;
pub mod secure_channel;
pub mod security_header;
pub mod sequence_number;
pub mod tcp_codec;
pub mod tcp_types;
pub mod url;
#[cfg(feature = "wss")]
pub mod wss;

use bytes::{Bytes, BytesMut};

/// A zero-copy buffer used for reading from and writing to the network layer.
pub type NetworkBuffer = BytesMut;
/// A zero-copy byte slice containing a read/parsed payload from the network layer.
pub type NetworkPayload = Bytes;
