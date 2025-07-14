//! Contains implementation of the OPC-UA `NodeId` type,
//! which is used to identify nodes in the address space of an OPC-UA server.

use std::{
    fmt,
    io::{Read, Write},
    str::FromStr,
    sync::{
        atomic::{AtomicU32, Ordering},
        LazyLock,
    },
};

mod id_ref;
mod identifier;
#[cfg(feature = "json")]
mod json;
#[cfg(feature = "xml")]
mod xml;

pub use identifier::Identifier;

use crate::{
    read_u16, read_u32, read_u8, write_u16, write_u32, write_u8, BinaryDecodable, BinaryEncodable,
    ByteString, DataTypeId, EncodingResult, Error, Guid, MethodId, ObjectId, ReferenceTypeId,
    StatusCode, UAString, UaNullable, VariableId,
};

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
                    "Unrecognized node id type {identifier}"
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

impl<'a> From<&'a str> for NodeId {
    fn from(value: &'a str) -> Self {
        (0u16, value).into()
    }
}

impl From<UAString> for NodeId {
    fn from(value: UAString) -> Self {
        (0u16, value).into()
    }
}

impl From<u32> for NodeId {
    fn from(value: u32) -> Self {
        (0, value).into()
    }
}

impl From<Guid> for NodeId {
    fn from(value: Guid) -> Self {
        (0, value).into()
    }
}

impl From<ByteString> for NodeId {
    fn from(value: ByteString) -> Self {
        (0, value).into()
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

static NEXT_NODE_ID_NUMERIC: AtomicU32 = AtomicU32::new(1);

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
            NEXT_NODE_ID_NUMERIC.fetch_add(1, Ordering::SeqCst),
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
