use opcua_types::{
    BinaryDecodable, BinaryEncodable, Context, DateTime, EncodingResult, Error, StatusCode,
    UAString, Variant,
};
use std::io::{Read, Write};

/// The PublisherId type in a UADP NetworkMessage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublisherId {
    /// No PublisherId is present.
    None,
    /// PublisherId is a byte.
    Byte(u8),
    /// PublisherId is a 16-bit unsigned integer.
    UInt16(u16),
    /// PublisherId is a 32-bit unsigned integer.
    UInt32(u32),
    /// PublisherId is a 64-bit unsigned integer.
    UInt64(u64),
    /// PublisherId is a string.
    String(String),
}

impl BinaryEncodable for PublisherId {
    fn byte_len(&self, ctx: &Context<'_>) -> usize {
        match self {
            PublisherId::None => 1,
            PublisherId::Byte(v) => 1 + v.byte_len(ctx),
            PublisherId::UInt16(v) => 1 + v.byte_len(ctx),
            PublisherId::UInt32(v) => 1 + v.byte_len(ctx),
            PublisherId::UInt64(v) => 1 + v.byte_len(ctx),
            PublisherId::String(v) => {
                let ua_str = UAString::from(v.clone());
                1 + ua_str.byte_len(ctx)
            }
        }
    }

    fn encode<S: Write + ?Sized>(&self, stream: &mut S, ctx: &Context<'_>) -> EncodingResult<()> {
        match self {
            PublisherId::None => 0u8.encode(stream, ctx),
            PublisherId::Byte(v) => {
                1u8.encode(stream, ctx)?;
                v.encode(stream, ctx)
            }
            PublisherId::UInt16(v) => {
                2u8.encode(stream, ctx)?;
                v.encode(stream, ctx)
            }
            PublisherId::UInt32(v) => {
                3u8.encode(stream, ctx)?;
                v.encode(stream, ctx)
            }
            PublisherId::UInt64(v) => {
                4u8.encode(stream, ctx)?;
                v.encode(stream, ctx)
            }
            PublisherId::String(v) => {
                5u8.encode(stream, ctx)?;
                let ua_str = UAString::from(v.clone());
                ua_str.encode(stream, ctx)
            }
        }
    }
}

impl BinaryDecodable for PublisherId {
    fn decode<S: Read + ?Sized>(stream: &mut S, ctx: &Context<'_>) -> EncodingResult<Self> {
        let ty = u8::decode(stream, ctx)?;
        match ty {
            0 => Ok(PublisherId::None),
            1 => Ok(PublisherId::Byte(u8::decode(stream, ctx)?)),
            2 => Ok(PublisherId::UInt16(u16::decode(stream, ctx)?)),
            3 => Ok(PublisherId::UInt32(u32::decode(stream, ctx)?)),
            4 => Ok(PublisherId::UInt64(u64::decode(stream, ctx)?)),
            5 => {
                let ua_str = UAString::decode(stream, ctx)?;
                Ok(PublisherId::String(ua_str.to_string()))
            }
            _ => Err(Error::decoding("Invalid PublisherId type")),
        }
    }
}

/// A DataSetMessage within a UADP NetworkMessage.
#[derive(Debug, Clone, PartialEq)]
pub struct UadpDataSetMessage {
    /// The dataset writer ID identifying the publisher.
    pub dataset_writer_id: u16,
    /// The cyclic sequence number of the message.
    pub sequence_number: u16,
    /// The timestamp when the message was prepared, if enabled.
    pub timestamp: Option<DateTime>,
    /// The status code of the payload data, if enabled.
    pub status: Option<StatusCode>,
    /// The field values making up the dataset message.
    pub fields: Vec<Variant>,
}

impl BinaryEncodable for UadpDataSetMessage {
    fn byte_len(&self, ctx: &Context<'_>) -> usize {
        let mut len = 2; // dataset_writer_id
        len += 1; // flags1
        len += 2; // sequence_number
        if self.timestamp.is_some() {
            len += 8; // DateTime ticks
        }
        if self.status.is_some() {
            len += 4; // StatusCode bits
        }
        len += 2; // field count
        for field in &self.fields {
            len += field.byte_len(ctx);
        }
        len
    }

    fn encode<S: Write + ?Sized>(&self, stream: &mut S, ctx: &Context<'_>) -> EncodingResult<()> {
        self.dataset_writer_id.encode(stream, ctx)?;

        let mut flags1: u8 = 0x01; // message valid
        flags1 |= 0x08; // SequenceNumber enabled (always on in our implementation)
        if self.timestamp.is_some() {
            flags1 |= 0x40; // Timestamp enabled
        }
        if self.status.is_some() {
            flags1 |= 0x10; // Status enabled
        }
        flags1.encode(stream, ctx)?;

        self.sequence_number.encode(stream, ctx)?;

        if let Some(timestamp) = self.timestamp {
            timestamp.encode(stream, ctx)?;
        }
        if let Some(status) = self.status {
            status.bits().encode(stream, ctx)?;
        }

        let field_count = self.fields.len() as u16;
        field_count.encode(stream, ctx)?;
        for field in &self.fields {
            field.encode(stream, ctx)?;
        }
        Ok(())
    }
}

impl BinaryDecodable for UadpDataSetMessage {
    fn decode<S: Read + ?Sized>(stream: &mut S, ctx: &Context<'_>) -> EncodingResult<Self> {
        let dataset_writer_id = u16::decode(stream, ctx)?;
        let flags1 = u8::decode(stream, ctx)?;

        let sequence_number = if (flags1 & 0x08) != 0 {
            u16::decode(stream, ctx)?
        } else {
            0
        };

        let timestamp = if (flags1 & 0x40) != 0 {
            Some(DateTime::decode(stream, ctx)?)
        } else {
            None
        };

        let status = if (flags1 & 0x10) != 0 {
            Some(StatusCode::from(u32::decode(stream, ctx)?))
        } else {
            None
        };

        let field_count = u16::decode(stream, ctx)?;
        let max_dataset_fields = ctx.options().max_dataset_fields;
        if field_count as usize > max_dataset_fields {
            return Err(Error::decoding(format!(
                "UADP dataset message field_count ({field_count}) exceeds max_dataset_fields ({max_dataset_fields})"
            )));
        }
        let mut fields = Vec::with_capacity(field_count as usize);
        for _ in 0..field_count {
            fields.push(Variant::decode(stream, ctx)?);
        }

        Ok(UadpDataSetMessage {
            dataset_writer_id,
            sequence_number,
            timestamp,
            status,
            fields,
        })
    }
}

/// A complete UADP NetworkMessage.
#[derive(Debug, Clone, PartialEq)]
pub struct UadpNetworkMessage {
    /// The identity of the publisher.
    pub publisher_id: PublisherId,
    /// The writer group ID for cyclic publishing.
    pub writer_group_id: u16,
    /// The collection of dataset messages in the payload.
    pub dataset_messages: Vec<UadpDataSetMessage>,
}

impl BinaryEncodable for UadpNetworkMessage {
    fn byte_len(&self, ctx: &Context<'_>) -> usize {
        let mut len = 1; // version and flags
        if self.publisher_id != PublisherId::None {
            len += self.publisher_id.byte_len(ctx);
        }
        // GroupHeader
        len += 2; // writer_group_id
        len += 4; // group_version
                  // PayloadHeader
        len += 1; // dataset_writer_count
        len += self.dataset_messages.len() * 2; // dataset_writer_ids
                                                // DataSetMessages
        for msg in &self.dataset_messages {
            len += msg.byte_len(ctx);
        }
        len
    }

    fn encode<S: Write + ?Sized>(&self, stream: &mut S, ctx: &Context<'_>) -> EncodingResult<()> {
        let mut flags = 1u8; // UADP version 1
        if self.publisher_id != PublisherId::None {
            flags |= 0x10; // PublisherId present
        }
        flags |= 0x20; // GroupHeader present
        flags |= 0x40; // PayloadHeader present
        flags.encode(stream, ctx)?;

        if self.publisher_id != PublisherId::None {
            self.publisher_id.encode(stream, ctx)?;
        }

        // GroupHeader
        self.writer_group_id.encode(stream, ctx)?;
        0u32.encode(stream, ctx)?; // GroupVersion (0 for simplicity)

        // PayloadHeader
        let count = self.dataset_messages.len() as u8;
        count.encode(stream, ctx)?;
        for msg in &self.dataset_messages {
            msg.dataset_writer_id.encode(stream, ctx)?;
        }

        // DataSetMessages
        for msg in &self.dataset_messages {
            msg.encode(stream, ctx)?;
        }
        Ok(())
    }
}

impl BinaryDecodable for UadpNetworkMessage {
    fn decode<S: Read + ?Sized>(stream: &mut S, ctx: &Context<'_>) -> EncodingResult<Self> {
        let flags = u8::decode(stream, ctx)?;
        let version = flags & 0x0F;
        if version != 1 {
            return Err(Error::decoding("Unsupported UADP version"));
        }

        let publisher_id = if (flags & 0x10) != 0 {
            PublisherId::decode(stream, ctx)?
        } else {
            PublisherId::None
        };

        let writer_group_id = if (flags & 0x20) != 0 {
            let id = u16::decode(stream, ctx)?;
            let _group_version = u32::decode(stream, ctx)?;
            id
        } else {
            return Err(Error::decoding("GroupHeader is missing"));
        };

        let count = if (flags & 0x40) != 0 {
            let count = u8::decode(stream, ctx)?;
            let max_dataset_messages = ctx.options().max_dataset_messages;
            if count as usize > max_dataset_messages {
                return Err(Error::decoding(format!(
                    "UADP network message dataset message count ({count}) exceeds max_dataset_messages ({max_dataset_messages})"
                )));
            }
            for _ in 0..count {
                let _writer_id = u16::decode(stream, ctx)?;
            }
            count
        } else {
            0
        };

        let mut dataset_messages = Vec::with_capacity(count as usize);
        for _ in 0..count {
            dataset_messages.push(UadpDataSetMessage::decode(stream, ctx)?);
        }

        Ok(UadpNetworkMessage {
            publisher_id,
            writer_group_id,
            dataset_messages,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opcua_types::{ContextOwned, StatusCode, Variant};

    #[test]
    fn test_uadp_roundtrip() {
        let ctx_owned = ContextOwned::default();
        let ctx = ctx_owned.context();

        let msg = UadpNetworkMessage {
            publisher_id: PublisherId::String("UdpPublisher1".to_string()),
            writer_group_id: 1,
            dataset_messages: vec![UadpDataSetMessage {
                dataset_writer_id: 101,
                sequence_number: 1,
                timestamp: Some(DateTime::now()),
                status: Some(StatusCode::Good),
                fields: vec![Variant::from(20.0f64)],
            }],
        };

        let encoded = msg.encode_to_vec(&ctx);
        let decoded = UadpNetworkMessage::decode(&mut &encoded[..], &ctx).unwrap();
        assert_eq!(msg.publisher_id, decoded.publisher_id);
        assert_eq!(msg.writer_group_id, decoded.writer_group_id);
        assert_eq!(msg.dataset_messages.len(), decoded.dataset_messages.len());
        assert_eq!(
            msg.dataset_messages[0].dataset_writer_id,
            decoded.dataset_messages[0].dataset_writer_id
        );
        assert_eq!(
            msg.dataset_messages[0].sequence_number,
            decoded.dataset_messages[0].sequence_number
        );
        assert_eq!(
            msg.dataset_messages[0].status,
            decoded.dataset_messages[0].status
        );
        assert_eq!(
            msg.dataset_messages[0].fields,
            decoded.dataset_messages[0].fields
        );
    }
}
