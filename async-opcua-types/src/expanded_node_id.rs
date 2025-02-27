// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Contains the implementation of `ExpandedNodeId`.

use std::{
    self,
    borrow::Cow,
    fmt,
    io::{Read, Write},
    str::FromStr,
    sync::LazyLock,
};

use crate::{
    byte_string::ByteString,
    encoding::{BinaryDecodable, BinaryEncodable, EncodingResult},
    guid::Guid,
    node_id::{Identifier, NodeId},
    read_u16, read_u32, read_u8,
    status_code::StatusCode,
    string::*,
    write_u16, write_u32, write_u8, Context, Error, NamespaceMap,
};

/// A NodeId that allows the namespace URI to be specified instead of an index.
#[derive(PartialEq, Debug, Clone, Eq, Hash, Default)]
pub struct ExpandedNodeId {
    /// The inner NodeId.
    pub node_id: NodeId,
    /// The full namespace URI. If this is set, the node ID namespace index may be zero.
    pub namespace_uri: UAString,
    /// The server index. 0 means current server.
    pub server_index: u32,
}

#[cfg(feature = "json")]
mod json {
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
    // "ServerUri"
    //      The ServerIndex for the ExpandedNodeId.
    //      This field is encoded as a JSON number for the reversible encoding.
    //      This field is omitted if the ServerIndex equals 0.
    //      For the non-reversible encoding, this field is the ServerUri associated with the ServerIndex portion of the ExpandedNodeId, encoded as a JSON string.

    use std::io::{Read, Write};
    use std::str::FromStr;

    use crate::{json::*, ByteString, Error, Guid};

    use super::{ExpandedNodeId, Identifier, NodeId, UAString};
    enum RawIdentifier {
        String(String),
        Integer(u32),
    }

    impl JsonEncodable for ExpandedNodeId {
        fn encode(
            &self,
            stream: &mut JsonStreamWriter<&mut dyn Write>,
            ctx: &crate::json::Context<'_>,
        ) -> super::EncodingResult<()> {
            stream.begin_object()?;
            match &self.node_id.identifier {
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
            if !self.namespace_uri.is_null() {
                stream.name("Namespace")?;
                stream.string_value(self.namespace_uri.as_ref())?;
            } else if self.node_id.namespace != 0 {
                stream.name("Namespace")?;
                stream.number_value(self.node_id.namespace)?;
            }
            if self.server_index != 0 {
                stream.name("ServerUri")?;
                stream.number_value(self.server_index)?;
            }
            stream.end_object()?;
            Ok(())
        }

        fn is_null_json(&self) -> bool {
            self.is_null()
        }
    }

    impl JsonDecodable for ExpandedNodeId {
        fn decode(
            stream: &mut JsonStreamReader<&mut dyn Read>,
            _ctx: &Context<'_>,
        ) -> super::EncodingResult<Self> {
            match stream.peek()? {
                ValueType::Null => {
                    stream.next_null()?;
                    return Ok(Self::null());
                }
                _ => stream.begin_object()?,
            }

            let mut id_type: Option<u16> = None;
            let mut namespace: Option<RawIdentifier> = None;
            let mut value: Option<RawIdentifier> = None;
            let mut server_uri: Option<u32> = None;

            while stream.has_next()? {
                match stream.next_name()? {
                    "IdType" => {
                        id_type = Some(stream.next_number()??);
                    }
                    "Namespace" => match stream.peek()? {
                        ValueType::Null => {
                            stream.next_null()?;
                            namespace = Some(RawIdentifier::Integer(0));
                        }
                        ValueType::Number => {
                            namespace = Some(RawIdentifier::Integer(stream.next_number()??));
                        }
                        _ => {
                            namespace = Some(RawIdentifier::String(stream.next_string()?));
                        }
                    },
                    "ServerUri" => {
                        server_uri = Some(stream.next_number()??);
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
                    let s = Guid::from_str(&s)
                        .map_err(|_| Error::decoding("Unable to decode GUID identifier"))?;
                    Identifier::Guid(s)
                }
                Some(3) => {
                    let Some(RawIdentifier::String(s)) = value else {
                        return Err(Error::decoding("Invalid NodeId, empty identifier"));
                    };
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

            let (namespace_uri, namespace) = match namespace {
                Some(RawIdentifier::String(s)) => (Some(s), 0u16),
                Some(RawIdentifier::Integer(s)) => (None, s.try_into().map_err(Error::decoding)?),
                None => (None, 0),
            };

            stream.end_object()?;
            Ok(ExpandedNodeId {
                node_id: NodeId {
                    namespace,
                    identifier,
                },
                namespace_uri: namespace_uri.into(),
                server_index: server_uri.unwrap_or_default(),
            })
        }
    }
}

#[cfg(feature = "xml")]
mod xml {
    // ExpandedNodeId in XML is for some reason just the exact same
    // as a NodeId.
    use crate::{xml::*, NodeId, UAString};
    use std::io::{Read, Write};

    use super::ExpandedNodeId;

    impl XmlType for ExpandedNodeId {
        const TAG: &'static str = "ExpandedNodeId";
    }

    impl XmlEncodable for ExpandedNodeId {
        fn encode(
            &self,
            writer: &mut XmlStreamWriter<&mut dyn Write>,
            context: &Context<'_>,
        ) -> EncodingResult<()> {
            let Some(node_id) = context.namespaces().resolve_node_id(self) else {
                return Err(Error::encoding(
                    "Unable to resolve ExpandedNodeId, invalid namespace",
                ));
            };
            node_id.encode(writer, context)
        }

        fn is_null_xml(&self) -> bool {
            self.is_null()
        }
    }

    impl XmlDecodable for ExpandedNodeId {
        fn decode(
            reader: &mut XmlStreamReader<&mut dyn Read>,
            context: &Context<'_>,
        ) -> EncodingResult<Self> {
            let node_id = NodeId::decode(reader, context)?;
            Ok(ExpandedNodeId {
                node_id,
                namespace_uri: UAString::null(),
                server_index: 0,
            })
        }
    }
}

impl BinaryEncodable for ExpandedNodeId {
    fn byte_len(&self, ctx: &crate::Context<'_>) -> usize {
        let mut size = self.node_id.byte_len(ctx);
        if !self.namespace_uri.is_null() {
            size += self.namespace_uri.byte_len(ctx);
        }
        if self.server_index != 0 {
            size += self.server_index.byte_len(ctx);
        }
        size
    }

    fn encode<S: Write + ?Sized>(&self, stream: &mut S, ctx: &Context<'_>) -> EncodingResult<()> {
        let mut data_encoding = 0;
        if !self.namespace_uri.is_null() {
            data_encoding |= 0x80;
        }
        if self.server_index != 0 {
            data_encoding |= 0x40;
        }

        // Type determines the byte code
        match &self.node_id.identifier {
            Identifier::Numeric(value) => {
                if self.node_id.namespace == 0 && *value <= 255 {
                    // node id fits into 2 bytes when the namespace is 0 and the value <= 255
                    write_u8(stream, data_encoding)?;
                    write_u8(stream, *value as u8)?;
                } else if self.node_id.namespace <= 255 && *value <= 65535 {
                    // node id fits into 4 bytes when namespace <= 255 and value <= 65535
                    write_u8(stream, data_encoding | 0x1)?;
                    write_u8(stream, self.node_id.namespace as u8)?;
                    write_u16(stream, *value as u16)?;
                } else {
                    // full node id
                    write_u8(stream, data_encoding | 0x2)?;
                    write_u16(stream, self.node_id.namespace)?;
                    write_u32(stream, *value)?;
                }
            }
            Identifier::String(value) => {
                write_u8(stream, data_encoding | 0x3)?;
                write_u16(stream, self.node_id.namespace)?;
                value.encode(stream, ctx)?;
            }
            Identifier::Guid(value) => {
                write_u8(stream, data_encoding | 0x4)?;
                write_u16(stream, self.node_id.namespace)?;
                value.encode(stream, ctx)?;
            }
            Identifier::ByteString(ref value) => {
                write_u8(stream, data_encoding | 0x5)?;
                write_u16(stream, self.node_id.namespace)?;
                value.encode(stream, ctx)?;
            }
        }
        if !self.namespace_uri.is_null() {
            self.namespace_uri.encode(stream, ctx)?;
        }
        if self.server_index != 0 {
            self.server_index.encode(stream, ctx)?;
        }
        Ok(())
    }
}

impl BinaryDecodable for ExpandedNodeId {
    fn decode<S: Read + ?Sized>(stream: &mut S, ctx: &Context<'_>) -> EncodingResult<Self> {
        let data_encoding = read_u8(stream)?;
        let identifier = data_encoding & 0x0f;
        let node_id = match identifier {
            0x0 => {
                let value = read_u8(stream)?;
                NodeId::new(0, u32::from(value))
            }
            0x1 => {
                let namespace = read_u8(stream)?;
                let value = read_u16(stream)?;
                NodeId::new(u16::from(namespace), u32::from(value))
            }
            0x2 => {
                let namespace = read_u16(stream)?;
                let value = read_u32(stream)?;
                NodeId::new(namespace, value)
            }
            0x3 => {
                let namespace = read_u16(stream)?;
                let value = UAString::decode(stream, ctx)?;
                NodeId::new(namespace, value)
            }
            0x4 => {
                let namespace = read_u16(stream)?;
                let value = Guid::decode(stream, ctx)?;
                NodeId::new(namespace, value)
            }
            0x5 => {
                let namespace = read_u16(stream)?;
                let value = ByteString::decode(stream, ctx)?;
                NodeId::new(namespace, value)
            }
            _ => {
                return Err(Error::encoding(format!(
                    "Unrecognized expanded node id type {}",
                    identifier
                )));
            }
        };

        // Optional stuff
        let namespace_uri = if data_encoding & 0x80 != 0 {
            UAString::decode(stream, ctx)?
        } else {
            UAString::null()
        };
        let server_index = if data_encoding & 0x40 != 0 {
            u32::decode(stream, ctx)?
        } else {
            0
        };

        Ok(ExpandedNodeId {
            node_id,
            namespace_uri,
            server_index,
        })
    }
}

impl From<&NodeId> for ExpandedNodeId {
    fn from(value: &NodeId) -> Self {
        value.clone().into()
    }
}

impl From<(NodeId, u32)> for ExpandedNodeId {
    fn from(v: (NodeId, u32)) -> Self {
        ExpandedNodeId {
            node_id: v.0,
            namespace_uri: UAString::null(),
            server_index: v.1,
        }
    }
}

impl From<(NodeId, &str)> for ExpandedNodeId {
    fn from(v: (NodeId, &str)) -> Self {
        ExpandedNodeId {
            node_id: v.0,
            namespace_uri: v.1.into(),
            server_index: 0,
        }
    }
}

impl From<NodeId> for ExpandedNodeId {
    fn from(v: NodeId) -> Self {
        ExpandedNodeId {
            node_id: v,
            namespace_uri: UAString::null(),
            server_index: 0,
        }
    }
}

impl fmt::Display for ExpandedNodeId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Formatted depending on the namespace uri being empty or not.
        if self.namespace_uri.is_empty() {
            // svr=<serverindex>;ns=<namespaceindex>;<type>=<value>
            write!(f, "svr={};{}", self.server_index, self.node_id)
        } else {
            // The % and ; chars have to be escaped out in the uri
            let namespace_uri = String::from(self.namespace_uri.as_ref())
                .replace('%', "%25")
                .replace(';', "%3b");
            // svr=<serverindex>;nsu=<uri>;<type>=<value>
            write!(
                f,
                "svr={};nsu={};{}",
                self.server_index, namespace_uri, self.node_id.identifier
            )
        }
    }
}

impl FromStr for ExpandedNodeId {
    type Err = StatusCode;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        use regex::Regex;

        // Parses a node from a string using the format specified in 5.3.1.11 part 6
        //
        // svr=<serverindex>;ns=<namespaceindex>;<type>=<value>
        // or
        // svr=<serverindex>;nsu=<uri>;<type>=<value>

        static RE: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(
                r"^svr=(?P<svr>[0-9]+);(ns=(?P<ns>[0-9]+)|nsu=(?P<nsu>[^;]+));(?P<t>[isgb]=.+)$",
            )
            .unwrap()
        });

        let captures = RE.captures(s).ok_or(StatusCode::BadNodeIdInvalid)?;

        // Server index
        let server_index = captures
            .name("svr")
            .ok_or(StatusCode::BadNodeIdInvalid)
            .and_then(|server_index| {
                server_index
                    .as_str()
                    .parse::<u32>()
                    .map_err(|_| StatusCode::BadNodeIdInvalid)
            })?;

        // Check for namespace uri
        let namespace_uri = if let Some(nsu) = captures.name("nsu") {
            // The % and ; chars need to be unescaped
            let nsu = String::from(nsu.as_str())
                .replace("%3b", ";")
                .replace("%25", "%");
            UAString::from(nsu)
        } else {
            UAString::null()
        };

        let namespace = if let Some(ns) = captures.name("ns") {
            ns.as_str()
                .parse::<u16>()
                .map_err(|_| StatusCode::BadNodeIdInvalid)?
        } else {
            0
        };

        // Type identifier
        let t = captures.name("t").unwrap();
        Identifier::from_str(t.as_str())
            .map(|t| ExpandedNodeId {
                server_index,
                namespace_uri,
                node_id: NodeId::new(namespace, t),
            })
            .map_err(|_| StatusCode::BadNodeIdInvalid)
    }
}

impl ExpandedNodeId {
    /// Creates an expanded node id from a node id
    pub fn new<T>(value: T) -> ExpandedNodeId
    where
        T: 'static + Into<ExpandedNodeId>,
    {
        value.into()
    }

    /// Return a null ExpandedNodeId.
    pub fn null() -> ExpandedNodeId {
        Self::new(NodeId::null())
    }

    /// Return `true` if this expanded node ID is null.
    pub fn is_null(&self) -> bool {
        self.node_id.is_null()
    }

    /// Try to resolve the expanded node ID into a NodeId.
    /// This will directly return the inner NodeId if namespace URI is null, otherwise it will
    /// try to return a NodeId with the namespace index given by the namespace uri.
    /// If server index is non-zero, this will always return None, otherwise, it will return
    /// None if the namespace is not in the namespace map.
    pub fn try_resolve<'a>(&'a self, namespaces: &NamespaceMap) -> Option<Cow<'a, NodeId>> {
        if self.server_index != 0 {
            return None;
        }
        if let Some(uri) = self.namespace_uri.value() {
            let idx = namespaces.get_index(uri)?;
            Some(Cow::Owned(NodeId {
                namespace: idx,
                identifier: self.node_id.identifier.clone(),
            }))
        } else {
            Some(Cow::Borrowed(&self.node_id))
        }
    }
}
