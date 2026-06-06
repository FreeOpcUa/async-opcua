use std::io::{Read, Write};
use std::str::FromStr;

use tracing::warn;

use super::{Identifier, NodeId};
use crate::{json::*, ByteString, Error, Guid, UAString};

// JSON serialization schema as per spec:
//
// "Type"
//      The IdentifierType encoded as a JSON number.
//      Allowed values are:
//            0 - UInt32 Identifier encoded as a JSON number.
//            1 - A String Identifier encoded as a JSON string.
//            2 - A Guid Identifier encoded as described in 5.4.2.7.
//            3 - A ByteString Identifier encoded as described in 5.4.2.8.
//      This field is omitted for UInt32 identifiers.
// "Id"
//      The Identifier.
//      The value of the id field specifies the encoding of this field.
// "Namespace"
//      The NamespaceIndex for the NodeId.
//      The field is encoded as a JSON number for the reversible encoding.
//      The field is omitted if the NamespaceIndex equals 0.
//      For the non-reversible encoding, the field is the NamespaceUri associated with the NamespaceIndex, encoded as a JSON string.
//      A NamespaceIndex of 1 is always encoded as a JSON number.

enum RawIdentifier {
    String(String),
    Integer(u32),
}

impl JsonEncodable for NodeId {
    fn encode(
        &self,
        stream: &mut JsonStreamWriter<&mut dyn Write>,
        ctx: &crate::json::Context<'_>,
    ) -> crate::EncodingResult<()> {
        stream.begin_object()?;
        match &self.identifier {
            super::Identifier::Numeric(n) => {
                stream.name("Id")?;
                stream.number_value(*n)?;
            }
            super::Identifier::String(uastring) => {
                stream.name("IdType")?;
                stream.number_value(1)?;
                stream.name("Id")?;
                JsonEncodable::encode(uastring, stream, ctx)?;
            }
            super::Identifier::Guid(guid) => {
                stream.name("IdType")?;
                stream.number_value(2)?;
                stream.name("Id")?;
                JsonEncodable::encode(guid, stream, ctx)?;
            }
            super::Identifier::ByteString(byte_string) => {
                stream.name("IdType")?;
                stream.number_value(3)?;
                stream.name("Id")?;
                JsonEncodable::encode(byte_string, stream, ctx)?;
            }
        }
        if self.namespace != 0 {
            stream.name("Namespace")?;
            stream.number_value(self.namespace)?;
        }
        stream.end_object()?;
        Ok(())
    }
}

impl JsonDecodable for NodeId {
    fn decode(
        stream: &mut JsonStreamReader<&mut dyn Read>,
        _ctx: &Context<'_>,
    ) -> crate::EncodingResult<Self> {
        match stream.peek()? {
            ValueType::Null => {
                stream.next_null()?;
                return Ok(Self::null());
            }
            _ => stream.begin_object()?,
        }

        let mut id_type: Option<u16> = None;
        let mut namespace: Option<u16> = None;
        let mut value: Option<RawIdentifier> = None;

        while stream.has_next()? {
            match stream.next_name()? {
                "IdType" => {
                    id_type = Some(stream.next_number()??);
                }
                "Namespace" => {
                    namespace = Some(stream.next_number()??);
                }
                "Id" => match stream.peek()? {
                    ValueType::Null => {
                        stream.next_null()?;
                        value = Some(RawIdentifier::Integer(0));
                    }
                    ValueType::Number => {
                        value = Some(RawIdentifier::Integer(stream.next_number()??));
                    }
                    _ => {
                        value = Some(RawIdentifier::String(stream.next_string()?));
                    }
                },
                _ => stream.skip_value()?,
            }
        }

        let identifier = match id_type {
            Some(1) => {
                let Some(RawIdentifier::String(s)) = value else {
                    return Err(Error::decoding("Invalid NodeId, empty identifier"));
                };
                let s = UAString::from(s);
                if s.is_null() || s.is_empty() {
                    return Err(Error::decoding("Invalid NodeId, empty identifier"));
                }
                Identifier::String(s)
            }
            Some(2) => {
                let Some(RawIdentifier::String(s)) = value else {
                    return Err(Error::decoding("Invalid NodeId, empty identifier"));
                };
                if s.is_empty() {
                    return Err(Error::decoding("Invalid NodeId, empty identifier"));
                }
                let s = Guid::from_str(&s).map_err(|_| {
                    warn!("Unable to decode GUID identifier");
                    Error::decoding("Unable to decode GUID identifier")
                })?;
                Identifier::Guid(s)
            }
            Some(3) => {
                let Some(RawIdentifier::String(s)) = value else {
                    return Err(Error::decoding("Invalid NodeId, empty identifier"));
                };
                if s.is_empty() {
                    return Err(Error::decoding("Invalid NodeId, empty identifier"));
                }
                let s: ByteString = ByteString::from_base64(&s)
                    .ok_or_else(|| Error::decoding("Unable to decode bytestring identifier"))?;
                Identifier::ByteString(s)
            }
            None | Some(0) => {
                let Some(RawIdentifier::Integer(s)) = value else {
                    return Err(Error::decoding("Invalid NodeId, empty identifier"));
                };
                Identifier::Numeric(s)
            }
            Some(r) => {
                return Err(Error::decoding(format!(
                    "Failed to deserialize NodeId, got unexpected IdType {r}"
                )));
            }
        };

        stream.end_object()?;
        Ok(Self {
            namespace: namespace.unwrap_or_default(),
            identifier,
        })
    }
}
