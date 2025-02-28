// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Contains the implementation of `NodeId`.

use std::{
    self,
    convert::TryFrom,
    fmt,
    io::{Read, Write},
    str::FromStr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        LazyLock,
    },
};

use crate::{
    byte_string::ByteString,
    encoding::{BinaryDecodable, BinaryEncodable, EncodingResult},
    guid::Guid,
    read_u16, read_u32, read_u8,
    status_code::StatusCode,
    string::*,
    write_u16, write_u32, write_u8, DataTypeId, Error, MethodId, ObjectId, ObjectTypeId,
    ReferenceTypeId, UaNullable, VariableId, VariableTypeId,
};

/// The kind of identifier, numeric, string, guid or byte
#[derive(Eq, PartialEq, Clone, Debug, Hash)]
pub enum Identifier {
    /// Numeric node ID identifier. i=123
    Numeric(u32),
    /// String node ID identifier, s=...
    String(UAString),
    /// GUID node ID identifier, g=...
    Guid(Guid),
    /// Opaque node ID identifier, o=...
    ByteString(ByteString),
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Identifier::Numeric(v) => write!(f, "i={}", *v),
            Identifier::String(v) => write!(f, "s={}", v),
            Identifier::Guid(v) => write!(f, "g={:?}", v),
            Identifier::ByteString(v) => write!(f, "b={}", v.as_base64()),
        }
    }
}

impl FromStr for Identifier {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() < 2 {
            Err(())
        } else {
            let k = &s[..2];
            let v = &s[2..];
            match k {
                "i=" => v.parse::<u32>().map(|v| v.into()).map_err(|_| ()),
                "s=" => Ok(UAString::from(v).into()),
                "g=" => Guid::from_str(v).map(|v| v.into()).map_err(|_| ()),
                "b=" => ByteString::from_base64(v).map(|v| v.into()).ok_or(()),
                _ => Err(()),
            }
        }
    }
}

impl From<i32> for Identifier {
    fn from(v: i32) -> Self {
        Identifier::Numeric(v as u32)
    }
}

impl From<u32> for Identifier {
    fn from(v: u32) -> Self {
        Identifier::Numeric(v)
    }
}

impl<'a> From<&'a str> for Identifier {
    fn from(v: &'a str) -> Self {
        Identifier::from(UAString::from(v))
    }
}

impl From<&String> for Identifier {
    fn from(v: &String) -> Self {
        Identifier::from(UAString::from(v))
    }
}

impl From<String> for Identifier {
    fn from(v: String) -> Self {
        Identifier::from(UAString::from(v))
    }
}

impl From<UAString> for Identifier {
    fn from(v: UAString) -> Self {
        Identifier::String(v)
    }
}

impl From<Guid> for Identifier {
    fn from(v: Guid) -> Self {
        Identifier::Guid(v)
    }
}

impl From<ByteString> for Identifier {
    fn from(v: ByteString) -> Self {
        Identifier::ByteString(v)
    }
}

#[derive(Debug)]
/// Error returned from working with node IDs.
pub struct NodeIdError;

impl fmt::Display for NodeIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeIdError")
    }
}

impl std::error::Error for NodeIdError {}

/// An identifier for a node in the address space of an OPC UA Server.
#[derive(PartialEq, Eq, Clone, Debug, Hash)]
pub struct NodeId {
    /// The index for a namespace
    pub namespace: u16,
    /// The identifier for the node in the address space
    pub identifier: Identifier,
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.namespace != 0 {
            write!(f, "ns={};{}", self.namespace, self.identifier)
        } else {
            write!(f, "{}", self.identifier)
        }
    }
}

impl UaNullable for NodeId {
    fn is_ua_null(&self) -> bool {
        self.is_null()
    }
}

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

#[cfg(feature = "json")]
mod json {
    use std::io::{Read, Write};
    use std::str::FromStr;

    use log::warn;

    use crate::{json::*, ByteString, Error, Guid};

    use super::{Identifier, NodeId, UAString};
    enum RawIdentifier {
        String(String),
        Integer(u32),
    }

    impl JsonEncodable for NodeId {
        fn encode(
            &self,
            stream: &mut JsonStreamWriter<&mut dyn Write>,
            ctx: &crate::json::Context<'_>,
        ) -> super::EncodingResult<()> {
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
        ) -> super::EncodingResult<Self> {
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
}

#[cfg(feature = "xml")]
mod xml {
    use crate::xml::*;
    use std::{
        io::{Read, Write},
        str::FromStr,
    };

    use super::NodeId;

    impl XmlType for NodeId {
        const TAG: &'static str = "NodeId";
    }

    impl XmlEncodable for NodeId {
        fn encode(
            &self,
            writer: &mut XmlStreamWriter<&mut dyn Write>,
            ctx: &crate::xml::Context<'_>,
        ) -> Result<(), Error> {
            let namespace_index = ctx.resolve_namespace_index_inverse(self.namespace)?;

            let self_str = if namespace_index > 0 {
                format!("ns={};{}", namespace_index, self.identifier)
            } else {
                self.identifier.to_string()
            };
            let val = ctx.resolve_alias_inverse(&self_str);
            writer.encode_child("Identifier", val, ctx)
        }
    }

    impl XmlDecodable for NodeId {
        fn decode(
            read: &mut XmlStreamReader<&mut dyn Read>,
            context: &Context<'_>,
        ) -> Result<Self, Error>
        where
            Self: Sized,
        {
            let val: Option<String> = read.decode_single_child("Identifier", context)?;
            let Some(val) = val else {
                return Ok(NodeId::null());
            };

            let val_str = context.resolve_alias(&val);
            let mut id = NodeId::from_str(val_str)
                .map_err(|e| Error::new(e, format!("Invalid node ID: {val_str}")))?;
            id.namespace = context.resolve_namespace_index(id.namespace)?;
            Ok(id)
        }
    }
}

impl BinaryEncodable for NodeId {
    fn byte_len(&self, ctx: &crate::Context<'_>) -> usize {
        // Type determines the byte code
        let size: usize = match self.identifier {
            Identifier::Numeric(value) => {
                if self.namespace == 0 && value <= 255 {
                    2
                } else if self.namespace <= 255 && value <= 65535 {
                    4
                } else {
                    7
                }
            }
            Identifier::String(ref value) => 3 + value.byte_len(ctx),
            Identifier::Guid(ref value) => 3 + value.byte_len(ctx),
            Identifier::ByteString(ref value) => 3 + value.byte_len(ctx),
        };
        size
    }

    fn encode<S: Write + ?Sized>(
        &self,
        stream: &mut S,
        ctx: &crate::Context<'_>,
    ) -> EncodingResult<()> {
        // Type determines the byte code
        match &self.identifier {
            Identifier::Numeric(value) => {
                if self.namespace == 0 && *value <= 255 {
                    // node id fits into 2 bytes when the namespace is 0 and the value <= 255
                    write_u8(stream, 0x0)?;
                    write_u8(stream, *value as u8)
                } else if self.namespace <= 255 && *value <= 65535 {
                    // node id fits into 4 bytes when namespace <= 255 and value <= 65535
                    write_u8(stream, 0x1)?;
                    write_u8(stream, self.namespace as u8)?;
                    write_u16(stream, *value as u16)
                } else {
                    // full node id
                    write_u8(stream, 0x2)?;
                    write_u16(stream, self.namespace)?;
                    write_u32(stream, *value)
                }
            }
            Identifier::String(value) => {
                write_u8(stream, 0x3)?;
                write_u16(stream, self.namespace)?;
                value.encode(stream, ctx)
            }
            Identifier::Guid(value) => {
                write_u8(stream, 0x4)?;
                write_u16(stream, self.namespace)?;
                value.encode(stream, ctx)
            }
            Identifier::ByteString(value) => {
                write_u8(stream, 0x5)?;
                write_u16(stream, self.namespace)?;
                value.encode(stream, ctx)
            }
        }
    }
}

impl BinaryDecodable for NodeId {
    fn decode<S: Read + ?Sized>(stream: &mut S, ctx: &crate::Context<'_>) -> EncodingResult<Self> {
        let identifier = read_u8(stream)?;
        let node_id = match identifier {
            0x0 => {
                let namespace = 0;
                let value = read_u8(stream)?;
                NodeId::new(namespace, u32::from(value))
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
                return Err(Error::decoding(format!(
                    "Unrecognized node id type {}",
                    identifier
                )));
            }
        };
        Ok(node_id)
    }
}

impl FromStr for NodeId {
    type Err = StatusCode;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        use regex::Regex;

        // Parses a node from a string using the format specified in 5.3.1.10 part 6
        //
        // ns=<namespaceindex>;<type>=<value>
        //
        // Where type:
        //   i = NUMERIC
        //   s = STRING
        //   g = GUID
        //   b = OPAQUE (ByteString)
        //
        // If namespace == 0, the ns=0; will be omitted

        static RE: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"^(ns=(?P<ns>[0-9]+);)?(?P<t>[isgb]=.+)$").unwrap());

        let captures = RE.captures(s).ok_or(StatusCode::BadNodeIdInvalid)?;

        // Check namespace (optional)
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
            .map(|t| NodeId::new(namespace, t))
            .map_err(|_| StatusCode::BadNodeIdInvalid)
    }
}

impl From<&NodeId> for NodeId {
    fn from(v: &NodeId) -> Self {
        v.clone()
    }
}

impl From<NodeId> for String {
    fn from(value: NodeId) -> Self {
        value.to_string()
    }
}

impl<'a> From<(u16, &'a str)> for NodeId {
    fn from(v: (u16, &'a str)) -> Self {
        Self::new(v.0, UAString::from(v.1))
    }
}

impl From<(u16, UAString)> for NodeId {
    fn from(v: (u16, UAString)) -> Self {
        Self::new(v.0, v.1)
    }
}

impl From<(u16, u32)> for NodeId {
    fn from(v: (u16, u32)) -> Self {
        Self::new(v.0, v.1)
    }
}

impl From<(u16, Guid)> for NodeId {
    fn from(v: (u16, Guid)) -> Self {
        Self::new(v.0, v.1)
    }
}

impl From<(u16, ByteString)> for NodeId {
    fn from(v: (u16, ByteString)) -> Self {
        Self::new(v.0, v.1)
    }
}

// Cheap comparisons intended for use when comparing node IDs to constants.
impl PartialEq<(u16, &str)> for NodeId {
    fn eq(&self, other: &(u16, &str)) -> bool {
        self.namespace == other.0
            && match &self.identifier {
                Identifier::String(s) => s.as_ref() == other.1,
                _ => false,
            }
    }
}

impl PartialEq<(u16, &[u8; 16])> for NodeId {
    fn eq(&self, other: &(u16, &[u8; 16])) -> bool {
        self.namespace == other.0
            && match &self.identifier {
                Identifier::Guid(s) => s.as_bytes() == other.1,
                _ => false,
            }
    }
}

impl PartialEq<(u16, &[u8])> for NodeId {
    fn eq(&self, other: &(u16, &[u8])) -> bool {
        self.namespace == other.0
            && match &self.identifier {
                Identifier::ByteString(s) => {
                    s.value.as_ref().is_some_and(|v| v.as_slice() == other.1)
                }
                _ => false,
            }
    }
}

impl PartialEq<(u16, u32)> for NodeId {
    fn eq(&self, other: &(u16, u32)) -> bool {
        self.namespace == other.0
            && match &self.identifier {
                Identifier::Numeric(s) => s == &other.1,
                _ => false,
            }
    }
}

impl PartialEq<ObjectId> for NodeId {
    fn eq(&self, other: &ObjectId) -> bool {
        *self == (0u16, *other as u32)
    }
}

impl PartialEq<ObjectTypeId> for NodeId {
    fn eq(&self, other: &ObjectTypeId) -> bool {
        *self == (0u16, *other as u32)
    }
}

impl PartialEq<ReferenceTypeId> for NodeId {
    fn eq(&self, other: &ReferenceTypeId) -> bool {
        *self == (0u16, *other as u32)
    }
}

impl PartialEq<VariableId> for NodeId {
    fn eq(&self, other: &VariableId) -> bool {
        *self == (0u16, *other as u32)
    }
}

impl PartialEq<VariableTypeId> for NodeId {
    fn eq(&self, other: &VariableTypeId) -> bool {
        *self == (0u16, *other as u32)
    }
}

impl PartialEq<DataTypeId> for NodeId {
    fn eq(&self, other: &DataTypeId) -> bool {
        *self == (0u16, *other as u32)
    }
}

static NEXT_NODE_ID_NUMERIC: AtomicUsize = AtomicUsize::new(1);

impl Default for NodeId {
    fn default() -> Self {
        NodeId::null()
    }
}

impl NodeId {
    /// Constructs a new NodeId from anything that can be turned into Identifier
    /// u32, Guid, ByteString or String
    pub fn new<T>(namespace: u16, value: T) -> NodeId
    where
        T: 'static + Into<Identifier>,
    {
        NodeId {
            namespace,
            identifier: value.into(),
        }
    }

    /// Returns the node id for the root folder.
    pub fn root_folder_id() -> NodeId {
        ObjectId::RootFolder.into()
    }

    /// Returns the node id for the objects folder.
    pub fn objects_folder_id() -> NodeId {
        ObjectId::ObjectsFolder.into()
    }

    /// Returns the node id for the types folder.
    pub fn types_folder_id() -> NodeId {
        ObjectId::TypesFolder.into()
    }

    /// Returns the node id for the views folder.
    pub fn views_folder_id() -> NodeId {
        ObjectId::ViewsFolder.into()
    }

    /// Test if the node id is null, i.e. 0 namespace and 0 identifier
    pub fn is_null(&self) -> bool {
        self.namespace == 0 && self.identifier == Identifier::Numeric(0)
    }

    /// Returns a null node id
    pub fn null() -> NodeId {
        NodeId::new(0, 0u32)
    }

    /// Creates a numeric node id with an id incrementing up from 1000
    pub fn next_numeric(namespace: u16) -> NodeId {
        NodeId::new(
            namespace,
            NEXT_NODE_ID_NUMERIC.fetch_add(1, Ordering::SeqCst) as u32,
        )
    }

    /// Extracts an ObjectId from a node id, providing the node id holds an object id
    pub fn as_object_id(&self) -> std::result::Result<ObjectId, NodeIdError> {
        match self.identifier {
            Identifier::Numeric(id) if self.namespace == 0 => {
                ObjectId::try_from(id).map_err(|_| NodeIdError)
            }
            _ => Err(NodeIdError),
        }
    }

    /// Try to convert this to a builtin variable ID.
    pub fn as_variable_id(&self) -> std::result::Result<VariableId, NodeIdError> {
        match self.identifier {
            Identifier::Numeric(id) if self.namespace == 0 => {
                VariableId::try_from(id).map_err(|_| NodeIdError)
            }
            _ => Err(NodeIdError),
        }
    }

    /// Try to convert this to a builtin reference type ID.
    pub fn as_reference_type_id(&self) -> std::result::Result<ReferenceTypeId, NodeIdError> {
        if self.is_null() {
            Err(NodeIdError)
        } else {
            match self.identifier {
                Identifier::Numeric(id) if self.namespace == 0 => {
                    ReferenceTypeId::try_from(id).map_err(|_| NodeIdError)
                }
                _ => Err(NodeIdError),
            }
        }
    }

    /// Try to convert this to a builtin data type ID.
    pub fn as_data_type_id(&self) -> std::result::Result<DataTypeId, NodeIdError> {
        match self.identifier {
            Identifier::Numeric(id) if self.namespace == 0 => {
                DataTypeId::try_from(id).map_err(|_| NodeIdError)
            }
            _ => Err(NodeIdError),
        }
    }

    /// Try to convert this to a builtin method ID.
    pub fn as_method_id(&self) -> std::result::Result<MethodId, NodeIdError> {
        match self.identifier {
            Identifier::Numeric(id) if self.namespace == 0 => {
                MethodId::try_from(id).map_err(|_| NodeIdError)
            }
            _ => Err(NodeIdError),
        }
    }

    /// Test if the node id is numeric
    pub fn is_numeric(&self) -> bool {
        matches!(self.identifier, Identifier::Numeric(_))
    }

    /// Test if the node id is a string
    pub fn is_string(&self) -> bool {
        matches!(self.identifier, Identifier::String(_))
    }

    /// Test if the node id is a guid
    pub fn is_guid(&self) -> bool {
        matches!(self.identifier, Identifier::Guid(_))
    }

    /// Test if the node id us a byte string
    pub fn is_byte_string(&self) -> bool {
        matches!(self.identifier, Identifier::ByteString(_))
    }

    /// Get the numeric value of this node ID if it is numeric.
    pub fn as_u32(&self) -> Option<u32> {
        match &self.identifier {
            Identifier::Numeric(i) => Some(*i),
            _ => None,
        }
    }
}
