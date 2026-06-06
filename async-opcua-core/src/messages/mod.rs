//! [RequestMessage] and [ResponseMessage], and utilities for working with these.

use std::io::Read;

use opcua_types::{BinaryEncodable, EncodingResult, NodeId, ObjectId};

mod request;
mod response;

pub use request::RequestMessage;
pub use response::ResponseMessage;

use crate::comms::message_chunk::MessageChunkType;

/// Trait implemented by messages and message chunks.
pub trait MessageType {
    /// Get the message chunk type.
    fn message_type(&self) -> MessageChunkType;
}

/// Trait implemented by messages.
pub trait Message: BinaryEncodable + MessageType {
    /// Get the message request handle.
    fn request_handle(&self) -> u32;

    /// Decode the message by object ID.
    fn decode_by_object_id<S: Read>(
        stream: &mut S,
        object_id: ObjectId,
        ctx: &opcua_types::Context<'_>,
    ) -> EncodingResult<Self>
    where
        Self: Sized;

    /// Get the type ID of the message.
    fn type_id(&self) -> NodeId;
}
