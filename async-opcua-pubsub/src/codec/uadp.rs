use opcua_types::{
    BinaryDecodable, BinaryEncodable, Context, DateTime, EncodingResult, Error, StatusCode,
    UAString, Variant,
};
use std::io::{Read, Write};

const UADP_VERSION: u8 = 1;
const UADP_FLAG_PUBLISHER_ID: u8 = 0x10;
const UADP_FLAG_GROUP_HEADER: u8 = 0x20;
const UADP_FLAG_PAYLOAD_HEADER: u8 = 0x40;
const UADP_FLAG_EXTENDED_FLAGS1: u8 = 0x80;
const UADP_EXTENDED_FLAGS1_SECURITY_HEADER: u8 = 0x10;
const SECURITY_FLAG_ENCRYPTED: u8 = 0x02;
const SECURITY_FLAG_FOOTER: u8 = 0x04;
const SECURITY_FLAGS_RESERVED: u8 = 0xF0;
const ENCRYPTED_MESSAGE_NONCE_LEN: u8 = 8;

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

/// UADP NetworkMessage SecurityHeader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityHeader {
    /// SecurityFlags: bit0 signed, bit1 encrypted, bit2 footer, bit3 force key reset.
    pub security_flags: u8,
    /// PubSub security token id selecting the key set.
    pub security_token_id: u32,
    /// Message nonce bytes.
    pub message_nonce: Vec<u8>,
}

impl BinaryEncodable for SecurityHeader {
    fn byte_len(&self, _ctx: &Context<'_>) -> usize {
        let mut len = 1 + 4 + 1 + self.message_nonce.len();
        if (self.security_flags & SECURITY_FLAG_FOOTER) != 0 {
            len += 2;
        }
        len
    }

    fn encode<S: Write + ?Sized>(&self, stream: &mut S, ctx: &Context<'_>) -> EncodingResult<()> {
        let nonce_len: u8 = self
            .message_nonce
            .len()
            .try_into()
            .map_err(|_| Error::encoding("UADP SecurityHeader nonce is too long"))?;

        self.security_flags.encode(stream, ctx)?;
        self.security_token_id.encode(stream, ctx)?;
        nonce_len.encode(stream, ctx)?;
        stream.write_all(&self.message_nonce)?;
        if (self.security_flags & SECURITY_FLAG_FOOTER) != 0 {
            0u16.encode(stream, ctx)?;
        }
        Ok(())
    }
}

impl BinaryDecodable for SecurityHeader {
    fn decode<S: Read + ?Sized>(stream: &mut S, ctx: &Context<'_>) -> EncodingResult<Self> {
        let security_flags = u8::decode(stream, ctx)?;
        if (security_flags & SECURITY_FLAGS_RESERVED) != 0 {
            return Err(Error::decoding(
                "UADP SecurityHeader reserved security flags are set",
            ));
        }

        let security_token_id = u32::decode(stream, ctx)?;
        let nonce_len = u8::decode(stream, ctx)?;
        if (security_flags & SECURITY_FLAG_ENCRYPTED) != 0
            && nonce_len != ENCRYPTED_MESSAGE_NONCE_LEN
        {
            return Err(Error::decoding(
                "UADP encrypted SecurityHeader nonce length must be 8",
            ));
        }

        let mut message_nonce = vec![0u8; nonce_len as usize];
        stream.read_exact(&mut message_nonce)?;
        if (security_flags & SECURITY_FLAG_FOOTER) != 0 {
            let _security_footer_size = u16::decode(stream, ctx)?;
        }

        Ok(Self {
            security_flags,
            security_token_id,
            message_nonce,
        })
    }
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
    /// GroupHeader NetworkMessageNumber.
    pub network_message_number: u16,
    /// GroupHeader NetworkMessage-level sequence number; owned/incremented by the publisher, consumed by message security and replay protection.
    pub sequence_number: u16,
    /// The collection of dataset messages in the payload.
    pub dataset_messages: Vec<UadpDataSetMessage>,
}

/// Decoded UADP header region metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UadpHeaderRegion {
    pub publisher_id: PublisherId,
    pub writer_group_id: u16,
    pub network_message_number: u16,
    pub sequence_number: u16,
    pub dataset_writer_ids: Vec<u16>,
}

impl UadpNetworkMessage {
    pub(crate) fn header_region_byte_len(
        &self,
        ctx: &Context<'_>,
        security_header: Option<&SecurityHeader>,
    ) -> usize {
        let mut len = 1; // UADPFlags
        if security_header.is_some() {
            len += 1; // ExtendedFlags1
        }
        if self.publisher_id != PublisherId::None {
            len += self.publisher_id.byte_len(ctx);
        }
        len += 1; // group_flags
        len += 2; // writer_group_id
        len += 4; // group_version
        len += 2; // network_message_number
        len += 2; // sequence_number
        len += 1; // dataset_writer_count
        len += self.dataset_messages.len() * 2; // dataset_writer_ids
        if let Some(security_header) = security_header {
            len += security_header.byte_len(ctx);
        }
        len
    }

    pub(crate) fn payload_region_byte_len(&self, ctx: &Context<'_>) -> usize {
        self.dataset_messages
            .iter()
            .map(|msg| msg.byte_len(ctx))
            .sum()
    }

    pub(crate) fn encode_header_region<S: Write + ?Sized>(
        &self,
        stream: &mut S,
        ctx: &Context<'_>,
        security_header: Option<&SecurityHeader>,
    ) -> EncodingResult<()> {
        let mut flags = UADP_VERSION;
        if self.publisher_id != PublisherId::None {
            flags |= UADP_FLAG_PUBLISHER_ID;
        }
        flags |= UADP_FLAG_GROUP_HEADER | UADP_FLAG_PAYLOAD_HEADER;
        if security_header.is_some() {
            flags |= UADP_FLAG_EXTENDED_FLAGS1;
        }
        flags.encode(stream, ctx)?;

        if security_header.is_some() {
            UADP_EXTENDED_FLAGS1_SECURITY_HEADER.encode(stream, ctx)?;
        }

        if self.publisher_id != PublisherId::None {
            self.publisher_id.encode(stream, ctx)?;
        }

        0b0000_1111u8.encode(stream, ctx)?;
        self.writer_group_id.encode(stream, ctx)?;
        0u32.encode(stream, ctx)?;
        self.network_message_number.encode(stream, ctx)?;
        self.sequence_number.encode(stream, ctx)?;

        let count: u8 = self
            .dataset_messages
            .len()
            .try_into()
            .map_err(|_| Error::encoding("UADP dataset message count exceeds u8"))?;
        count.encode(stream, ctx)?;
        for msg in &self.dataset_messages {
            msg.dataset_writer_id.encode(stream, ctx)?;
        }

        if let Some(security_header) = security_header {
            security_header.encode(stream, ctx)?;
        }

        Ok(())
    }

    pub(crate) fn encode_payload_region<S: Write + ?Sized>(
        &self,
        stream: &mut S,
        ctx: &Context<'_>,
    ) -> EncodingResult<()> {
        for msg in &self.dataset_messages {
            msg.encode(stream, ctx)?;
        }
        Ok(())
    }

    pub(crate) fn decode_header_region<S: Read + ?Sized>(
        stream: &mut S,
        ctx: &Context<'_>,
    ) -> EncodingResult<(UadpHeaderRegion, Option<SecurityHeader>)> {
        let flags = u8::decode(stream, ctx)?;
        let version = flags & 0x0F;
        if version != UADP_VERSION {
            return Err(Error::decoding("Unsupported UADP version"));
        }

        let security_header_present = if (flags & UADP_FLAG_EXTENDED_FLAGS1) != 0 {
            let extended_flags1 = u8::decode(stream, ctx)?;
            (extended_flags1 & UADP_EXTENDED_FLAGS1_SECURITY_HEADER) != 0
        } else {
            false
        };

        let publisher_id = if (flags & UADP_FLAG_PUBLISHER_ID) != 0 {
            PublisherId::decode(stream, ctx)?
        } else {
            PublisherId::None
        };

        let (writer_group_id, network_message_number, sequence_number) =
            if (flags & UADP_FLAG_GROUP_HEADER) != 0 {
                let group_flags = u8::decode(stream, ctx)?;
                if (group_flags & 0b1111_0000) != 0 {
                    return Err(Error::decoding("UADP GroupFlags reserved bits are set"));
                }
                let writer_group_id = if (group_flags & 0b0000_0001) != 0 {
                    u16::decode(stream, ctx)?
                } else {
                    0
                };
                if (group_flags & 0b0000_0010) != 0 {
                    let _group_version = u32::decode(stream, ctx)?;
                }
                let network_message_number = if (group_flags & 0b0000_0100) != 0 {
                    u16::decode(stream, ctx)?
                } else {
                    0
                };
                let sequence_number = if (group_flags & 0b0000_1000) != 0 {
                    u16::decode(stream, ctx)?
                } else {
                    0
                };
                (writer_group_id, network_message_number, sequence_number)
            } else {
                return Err(Error::decoding("GroupHeader is missing"));
            };

        let dataset_writer_ids = if (flags & UADP_FLAG_PAYLOAD_HEADER) != 0 {
            let count = u8::decode(stream, ctx)?;
            let max_dataset_messages = ctx.options().max_dataset_messages;
            if count as usize > max_dataset_messages {
                return Err(Error::decoding(format!(
                    "UADP network message dataset message count ({count}) exceeds max_dataset_messages ({max_dataset_messages})"
                )));
            }
            let mut dataset_writer_ids = Vec::with_capacity(count as usize);
            for _ in 0..count {
                dataset_writer_ids.push(u16::decode(stream, ctx)?);
            }
            dataset_writer_ids
        } else {
            Vec::new()
        };

        let security_header = if security_header_present {
            Some(SecurityHeader::decode(stream, ctx)?)
        } else {
            None
        };

        Ok((
            UadpHeaderRegion {
                publisher_id,
                writer_group_id,
                network_message_number,
                sequence_number,
                dataset_writer_ids,
            },
            security_header,
        ))
    }

    pub(crate) fn decode_payload_region<S: Read + ?Sized>(
        header: &UadpHeaderRegion,
        stream: &mut S,
        ctx: &Context<'_>,
    ) -> EncodingResult<Vec<UadpDataSetMessage>> {
        let mut dataset_messages = Vec::with_capacity(header.dataset_writer_ids.len());
        for _ in &header.dataset_writer_ids {
            dataset_messages.push(UadpDataSetMessage::decode(stream, ctx)?);
        }
        Ok(dataset_messages)
    }
}

impl BinaryEncodable for UadpNetworkMessage {
    fn byte_len(&self, ctx: &Context<'_>) -> usize {
        self.header_region_byte_len(ctx, None) + self.payload_region_byte_len(ctx)
    }

    fn encode<S: Write + ?Sized>(&self, stream: &mut S, ctx: &Context<'_>) -> EncodingResult<()> {
        self.encode_header_region(stream, ctx, None)?;
        self.encode_payload_region(stream, ctx)
    }
}

impl BinaryDecodable for UadpNetworkMessage {
    fn decode<S: Read + ?Sized>(stream: &mut S, ctx: &Context<'_>) -> EncodingResult<Self> {
        let (header, _security_header) = Self::decode_header_region(stream, ctx)?;
        let dataset_messages = Self::decode_payload_region(&header, stream, ctx)?;

        Ok(UadpNetworkMessage {
            publisher_id: header.publisher_id,
            writer_group_id: header.writer_group_id,
            network_message_number: header.network_message_number,
            sequence_number: header.sequence_number,
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
            network_message_number: 0,
            sequence_number: 1,
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

    // T003 (feature 026): the Part-14 GroupHeader NetworkMessageNumber + NetworkMessage-level
    // SequenceNumber round-trip, and decode rejects reserved GroupFlags bits.
    fn sample_message(network_message_number: u16, sequence_number: u16) -> UadpNetworkMessage {
        UadpNetworkMessage {
            publisher_id: PublisherId::None,
            writer_group_id: 7,
            network_message_number,
            sequence_number,
            dataset_messages: vec![UadpDataSetMessage {
                dataset_writer_id: 101,
                sequence_number: 3,
                timestamp: None,
                status: None,
                fields: vec![Variant::from(20.0f64)],
            }],
        }
    }

    #[test]
    fn group_header_sequence_fields_round_trip() {
        let ctx_owned = ContextOwned::default();
        let ctx = ctx_owned.context();
        let msg = sample_message(5, 42);

        let encoded = msg.encode_to_vec(&ctx);
        // PublisherId::None => NetworkMessage flags byte (0x60) at [0], GroupFlags at [1].
        assert_eq!(
            encoded[1], 0b0000_1111,
            "GroupFlags should enable all four fields"
        );

        let decoded = UadpNetworkMessage::decode(&mut &encoded[..], &ctx).unwrap();
        assert_eq!(decoded.network_message_number, 5);
        assert_eq!(decoded.sequence_number, 42);
        assert_eq!(decoded.writer_group_id, 7);
        // NetworkMessage-level sequence is distinct from the DataSetMessage-level one.
        assert_eq!(decoded.dataset_messages[0].sequence_number, 3);
    }

    #[test]
    fn group_header_rejects_reserved_flag_bits() {
        let ctx_owned = ContextOwned::default();
        let ctx = ctx_owned.context();
        let mut encoded = sample_message(1, 1).encode_to_vec(&ctx);
        encoded[1] |= 0b0001_0000; // set a reserved GroupFlags bit (bit 4)

        let err = UadpNetworkMessage::decode(&mut &encoded[..], &ctx);
        assert!(err.is_err(), "decode must reject reserved GroupFlags bits");
    }
}
