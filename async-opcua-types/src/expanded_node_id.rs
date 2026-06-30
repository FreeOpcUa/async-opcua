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
};

use crate::{
    byte_string::ByteString,
    encoding::{BinaryDecodable, BinaryEncodable, EncodingResult},
    guid::Guid,
    node_id::{Identifier, NodeId},
    read_u16, read_u32, read_u8,
    status_code::StatusCode,
    string::*,
    write_u16, write_u32, write_u8, Context, Error, NamespaceMap, UaNullable,
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

impl UaNullable for ExpandedNodeId {
    fn is_ua_null(&self) -> bool {
        self.is_null()
    }
}

#[cfg(feature = "json")]
mod json {
    use std::io::{Read, Write};
    use std::str::FromStr;

    use crate::{json::*, Error, StatusCode};

    use super::{ExpandedNodeId, NodeId, UAString};

    const OPC_UA_NAMESPACE_URI: &str = "http://opcfoundation.org/UA/";

    fn namespace_uri_for_index<'a>(ctx: &'a Context<'_>, namespace: u16) -> Option<&'a str> {
        ctx.namespaces()
            .known_namespaces()
            .iter()
            .find_map(|(uri, index)| (*index == namespace).then_some(uri.as_str()))
    }

    fn escape_namespace_uri(namespace_uri: &str) -> String {
        namespace_uri.replace('%', "%25").replace(';', "%3b")
    }

    fn invalid_expanded_node_id(value: &str) -> Error {
        Error::new(
            StatusCode::BadNodeIdInvalid,
            format!("invalid ExpandedNodeId JSON string {value:?}"),
        )
    }

    fn json_node_id_string(node_id: &NodeId, ctx: &Context<'_>) -> String {
        if node_id.namespace == 0 {
            node_id.identifier.to_string()
        } else if let Some(namespace_uri) = namespace_uri_for_index(ctx, node_id.namespace) {
            if namespace_uri == OPC_UA_NAMESPACE_URI {
                node_id.identifier.to_string()
            } else {
                format!(
                    "nsu={};{}",
                    escape_namespace_uri(namespace_uri),
                    node_id.identifier
                )
            }
        } else {
            node_id.to_string()
        }
    }

    fn json_expanded_node_id_string(value: &ExpandedNodeId, ctx: &Context<'_>) -> String {
        let node_id = if value.namespace_uri.is_empty() {
            json_node_id_string(&value.node_id, ctx)
        } else {
            format!(
                "nsu={};{}",
                escape_namespace_uri(value.namespace_uri.as_ref()),
                value.node_id.identifier
            )
        };

        if value.server_index == 0 {
            node_id
        } else {
            format!("svr={};{node_id}", value.server_index)
        }
    }

    fn decode_expanded_node_id_string(
        value: &str,
        ctx: &Context<'_>,
    ) -> super::EncodingResult<ExpandedNodeId> {
        if value.starts_with("svu=") {
            return Ok(ExpandedNodeId {
                node_id: NodeId::new(0, value),
                namespace_uri: UAString::null(),
                server_index: 0,
            });
        }

        let mut expanded_node_id =
            ExpandedNodeId::from_str(value).map_err(|_| invalid_expanded_node_id(value))?;

        if expanded_node_id.server_index == 0 {
            if let Some(namespace_uri) = expanded_node_id.namespace_uri.value().as_deref() {
                if let Some(namespace) = ctx.namespaces().get_index(namespace_uri) {
                    expanded_node_id.node_id.namespace = namespace;
                    expanded_node_id.namespace_uri = UAString::null();
                }
            }
        }

        Ok(expanded_node_id)
    }

    impl JsonEncodable for ExpandedNodeId {
        fn encode(
            &self,
            stream: &mut JsonStreamWriter<&mut dyn Write>,
            ctx: &crate::json::Context<'_>,
        ) -> super::EncodingResult<()> {
            let value = json_expanded_node_id_string(self, ctx);
            stream.string_value(&value)?;
            Ok(())
        }
    }

    impl JsonDecodable for ExpandedNodeId {
        fn decode(
            stream: &mut JsonStreamReader<&mut dyn Read>,
            ctx: &Context<'_>,
        ) -> super::EncodingResult<Self> {
            match stream.peek()? {
                ValueType::Null => {
                    stream.next_null()?;
                    Ok(Self::null())
                }
                ValueType::String => {
                    let value = stream.next_str()?;
                    decode_expanded_node_id_string(value, ctx)
                }
                _ => Err(Error::decoding(
                    "invalid ExpandedNodeId JSON value, expected string",
                )),
            }
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
                    "Unrecognized expanded node id type {identifier}"
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

impl<T> From<(T, &str)> for ExpandedNodeId
where
    T: Into<NodeId>,
{
    fn from(value: (T, &str)) -> Self {
        ExpandedNodeId {
            node_id: value.0.into(),
            namespace_uri: value.1.into(),
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
        // Parses an ExpandedNodeId from its string form (Part 6 §5.1.12, Table 6). The ServerIndex
        // and NamespaceUri prefixes are BOTH optional; a bare NodeId is itself a valid ExpandedNodeId:
        //
        //   <node-id>
        //   svr=<serverindex>;<node-id>
        //   [svr=<serverindex>;]nsu=<uri>;<node-id>
        //
        // where <node-id> is "[ns=<namespaceindex>;]<type>=<value>" (parsed by NodeId::from_str).
        let mut rest = s;
        let mut server_index = 0u32;
        let mut namespace_uri = UAString::null();

        if let Some(after) = rest.strip_prefix("svr=") {
            let (digits, tail) = after.split_once(';').ok_or(StatusCode::BadNodeIdInvalid)?;
            server_index = digits
                .parse::<u32>()
                .map_err(|_| StatusCode::BadNodeIdInvalid)?;
            rest = tail;
        }

        if let Some(after) = rest.strip_prefix("nsu=") {
            let (uri, tail) = after.split_once(';').ok_or(StatusCode::BadNodeIdInvalid)?;
            if uri.is_empty() {
                return Err(StatusCode::BadNodeIdInvalid);
            }
            // The % and ; chars are escaped inside the URI; unescape %3b before %25.
            namespace_uri = UAString::from(uri.replace("%3b", ";").replace("%25", "%"));
            // When a NamespaceUri is given, the NodeId must not also carry a NamespaceIndex.
            if tail.starts_with("ns=") {
                return Err(StatusCode::BadNodeIdInvalid);
            }
            rest = tail;
        }

        Ok(ExpandedNodeId {
            server_index,
            namespace_uri,
            node_id: NodeId::from_str(rest)?,
        })
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

    /// Creates an expanded node id from a namespace URI and an identifier.
    pub fn new_with_namespace(namespace: &str, value: impl Into<Identifier> + 'static) -> Self {
        Self {
            namespace_uri: namespace.into(),
            node_id: NodeId::new(0, value),
            server_index: 0,
        }
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
