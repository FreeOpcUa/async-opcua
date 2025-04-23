// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Contains the implementation of `ExtensionObject`.

use std::{
    any::{Any, TypeId},
    fmt,
    io::{Read, Write},
};

use crate::{write_i32, write_u8, Error, ExpandedMessageInfo, ExpandedNodeId, UaNullable};

use super::{
    encoding::{BinaryDecodable, BinaryEncodable, EncodingResult},
    node_id::NodeId,
    ObjectId,
};

#[derive(Debug)]
/// Error returned when working with extension objects.
pub struct ExtensionObjectError;

impl fmt::Display for ExtensionObjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExtensionObjectError")
    }
}

/// Trait for an OPC-UA struct that can be dynamically encoded back to binary (or JSON).
/// ExtensionObject wraps a dynamic object for this trait.
/// Note that this trait is automatically implemented for anything that implements
/// [BinaryEncodable], [JsonEncodable] (with the `json` feature), [Send], [Sync], [Clone],
/// [ExpandedMessageInfo], [std::fmt::Debug] and [PartialEq].
///
/// All of these are automatically derived during codegen, if you
/// want to manually implement a type that can be stored as an extension object,
/// you need to implement or derive all of these traits.
pub trait DynEncodable: Any + Send + Sync + std::fmt::Debug {
    /// Encode the struct using OPC-UA binary encoding.
    fn encode_binary(
        &self,
        stream: &mut dyn std::io::Write,
        ctx: &crate::Context<'_>,
    ) -> EncodingResult<()>;

    #[cfg(feature = "json")]
    /// Encode the struct using reversible OPC-UA JSON encoding.
    fn encode_json(
        &self,
        stream: &mut crate::json::JsonStreamWriter<&mut dyn std::io::Write>,
        ctx: &crate::Context<'_>,
    ) -> EncodingResult<()>;

    #[cfg(feature = "xml")]
    /// Encode the struct using OPC-UA XML encoding.
    fn encode_xml(
        &self,
        stream: &mut crate::xml::XmlStreamWriter<&mut dyn std::io::Write>,
        ctx: &crate::Context<'_>,
    ) -> EncodingResult<()>;

    #[cfg(feature = "xml")]
    /// The XML tag name for this struct.
    fn xml_tag_name(&self) -> &str;

    /// Get the binary byte length of this struct.
    fn byte_len_dyn(&self, ctx: &crate::Context<'_>) -> usize;

    /// Get the binary encoding ID of this struct.
    fn binary_type_id(&self) -> ExpandedNodeId;

    #[cfg(feature = "json")]
    /// Get the JSON encoding ID of this struct.
    fn json_type_id(&self) -> ExpandedNodeId;

    #[cfg(feature = "xml")]
    /// Get the XML encoding ID of this struct.
    fn xml_type_id(&self) -> ExpandedNodeId;

    /// Get the data type ID of this struct.
    fn data_type_id(&self) -> ExpandedNodeId;

    /// Method to cast this to a dyn Any box, required for downcasting.
    fn as_dyn_any(self: Box<Self>) -> Box<dyn Any + Send + Sync + 'static>;

    /// Method to cast this to a dyn Any trait object, required for downcasting by reference.
    fn as_dyn_any_ref(&self) -> &(dyn Any + Send + Sync);

    /// Clone this to a dyn box. Required in order to implement Clone for ExtensionObject.
    fn clone_box(&self) -> Box<dyn DynEncodable>;

    /// Compare this with dynamic object. Invokes the PartialEq implementation of self and other,
    /// if other has type `Self`.
    fn dyn_eq(&self, other: &dyn DynEncodable) -> bool;

    /// Get the type name of the type, by calling `std::any::type_name` on `Self`.
    /// Very useful for debugging.
    fn type_name(&self) -> &'static str;
}

macro_rules! blanket_dyn_encodable {
    ($bound:tt $(+ $others:tt)*) => {
        impl<T> DynEncodable for T
        where
            T: $bound  $(+ $others)* + ExpandedMessageInfo + Any + std::fmt::Debug + Send + Sync + Clone + PartialEq,
        {
            fn encode_binary(&self, stream: &mut dyn std::io::Write, ctx: &crate::Context<'_>) -> EncodingResult<()> {
                BinaryEncodable::encode(self, stream, ctx)
            }

            #[cfg(feature = "json")]
            fn encode_json(
                &self,
                stream: &mut crate::json::JsonStreamWriter<&mut dyn std::io::Write>,
                ctx: &crate::Context<'_>
            ) -> EncodingResult<()> {
                JsonEncodable::encode(self, stream, ctx)
            }

            #[cfg(feature = "xml")]
            fn encode_xml(
                &self,
                stream: &mut crate::xml::XmlStreamWriter<&mut dyn std::io::Write>,
                ctx: &crate::Context<'_>,
            ) -> EncodingResult<()> {
                XmlEncodable::encode(self, stream, ctx)
            }

            #[cfg(feature = "xml")]
            fn xml_tag_name(&self,) -> &str {
                self.tag()
            }

            fn byte_len_dyn(&self, ctx: &crate::Context<'_>,) -> usize {
                BinaryEncodable::byte_len(self, ctx)
            }

            fn binary_type_id(&self) -> ExpandedNodeId {
                self.full_type_id()
            }

            #[cfg(feature = "json")]
            fn json_type_id(&self) -> ExpandedNodeId {
                self.full_json_type_id()
            }

            #[cfg(feature = "xml")]
            fn xml_type_id(&self) -> ExpandedNodeId {
                self.full_xml_type_id()
            }

            fn data_type_id(&self) -> ExpandedNodeId {
                self.full_data_type_id()
            }

            fn as_dyn_any(self: Box<Self>) -> Box<dyn Any + Send + Sync + 'static> {
                self
            }

            fn as_dyn_any_ref(&self) -> &(dyn Any + Send + Sync) {
                self
            }

            fn clone_box(&self) -> Box<dyn DynEncodable> {
                Box::new(self.clone())
            }

            fn dyn_eq(&self, other: &dyn DynEncodable) -> bool {
                if let Some(o) = other.as_dyn_any_ref().downcast_ref::<Self>() {
                    o == self
                } else {
                    false
                }
            }

            fn type_name(&self) -> &'static str {
                std::any::type_name::<Self>()
            }
        }
    };
}

#[cfg(feature = "json")]
use crate::json::JsonEncodable;

#[cfg(feature = "xml")]
use crate::xml::XmlEncodable;

#[cfg(feature = "xml")]
macro_rules! blanket_call_2 {
    ($($res:tt)*) => {
        blanket_dyn_encodable!($($res)* + XmlEncodable);
    }
}
#[cfg(not(feature = "xml"))]
macro_rules! blanket_call_2 {
    ($($res:tt)*) => {
        blanket_dyn_encodable!($($res)*);
    }
}

#[cfg(feature = "json")]
macro_rules! blanket_call_1 {
    ($($res:tt)*) => {
        blanket_call_2!($($res)* + JsonEncodable);
    }
}
#[cfg(not(feature = "json"))]
macro_rules! blanket_call_1 {
    ($($res:tt)*) => {
        blanket_call_2!($($res)*);
    }
}

blanket_call_1!(BinaryEncodable);

impl PartialEq for dyn DynEncodable {
    fn eq(&self, other: &dyn DynEncodable) -> bool {
        self.dyn_eq(other)
    }
}

impl std::error::Error for ExtensionObjectError {}

impl UaNullable for ExtensionObject {}

#[cfg(feature = "json")]
mod json {
    use std::io::{Cursor, Read};

    use crate::{json::*, ByteString, Error, NodeId};

    use super::ExtensionObject;

    impl JsonEncodable for ExtensionObject {
        fn encode(
            &self,
            stream: &mut JsonStreamWriter<&mut dyn std::io::Write>,
            ctx: &crate::Context<'_>,
        ) -> super::EncodingResult<()> {
            let Some(body) = &self.body else {
                stream.null_value()?;
                return Ok(());
            };

            let type_id = body.json_type_id();

            let id = type_id.try_resolve(ctx.namespaces()).ok_or_else(|| {
                Error::encoding(format!("Missing namespace for encoding ID: {}", type_id))
            })?;

            stream.begin_object()?;

            stream.name("UaTypeId")?;
            JsonEncodable::encode(id.as_ref(), stream, ctx)?;

            stream.name("UaBody")?;
            body.encode_json(stream, ctx)?;

            stream.end_object()?;

            Ok(())
        }
    }

    impl JsonDecodable for ExtensionObject {
        fn decode(
            stream: &mut JsonStreamReader<&mut dyn std::io::Read>,
            ctx: &Context<'_>,
        ) -> super::EncodingResult<Self> {
            if stream.peek()? == ValueType::Null {
                stream.next_null()?;
                return Ok(Self::null());
            }

            let mut type_id: Option<NodeId> = None;
            let mut encoding: Option<u32> = None;
            let mut raw_body = None;
            let mut raw_string_body: Option<String> = None;
            let mut body = None;

            stream.begin_object()?;

            while stream.has_next()? {
                match stream.next_name()? {
                    "UaTypeId" => type_id = Some(JsonDecodable::decode(stream, ctx)?),
                    "UaEncoding" => encoding = Some(JsonDecodable::decode(stream, ctx)?),
                    "UaBody" => match stream.peek()? {
                        ValueType::Object => {
                            if encoding.is_some_and(|e| e != 0) {
                                return Err(Error::decoding(format!(
                                    "Invalid encoding, expected 0 or null, got {:?}",
                                    encoding
                                )));
                            }
                            if let Some(type_id) = &type_id {
                                body = Some(ctx.load_from_json(type_id, stream)?);
                            } else {
                                raw_body = Some(consume_raw_value(stream)?);
                            }
                        }
                        _ => {
                            raw_string_body = Some(JsonDecodable::decode(stream, ctx)?);
                        }
                    },
                    _ => stream.skip_value()?,
                }
            }

            stream.end_object()?;

            let Some(type_id) = type_id else {
                return Err(Error::decoding("Missing type ID in extension object"));
            };

            let encoding = encoding.unwrap_or_default();

            if let Some(body) = body {
                Ok(body)
            } else if let Some(raw_body) = raw_body {
                if encoding != 0 {
                    return Err(Error::decoding(format!(
                        "Invalid encoding, expected 0 or null, got {}",
                        encoding
                    )));
                }
                let mut cursor = Cursor::new(raw_body);
                let mut inner_stream = JsonStreamReader::new(&mut cursor as &mut dyn Read);
                Ok(ctx.load_from_json(&type_id, &mut inner_stream)?)
            } else if let Some(string_body) = raw_string_body {
                if encoding == 1 {
                    let bytes = ByteString::from_base64_ignore_whitespace(string_body).ok_or_else(
                        || Error::decoding("Invalid base64 string is JSON extension object"),
                    )?;
                    let Some(raw) = bytes.value else {
                        return Err(Error::decoding("Missing extension object body"));
                    };
                    let mut cursor = Cursor::new(raw);
                    Ok(ctx.load_from_binary(&type_id, &mut cursor as &mut dyn Read)?)
                } else if encoding == 2 {
                    #[cfg(feature = "xml")]
                    {
                        let mut cursor = Cursor::new(string_body.as_bytes());
                        let mut inner_stream =
                            crate::xml::XmlStreamReader::new(&mut cursor as &mut dyn Read);
                        if crate::xml::enter_first_tag(&mut inner_stream)? {
                            Ok(ctx.load_from_xml(&type_id, &mut inner_stream)?)
                        } else {
                            Ok(ExtensionObject::null())
                        }
                    }
                    #[cfg(not(feature = "xml"))]
                    {
                        tracing::warn!("XML feature is not enabled, deserializing XML payloads in JSON extension objects is not supported");
                        Ok(ExtensionObject::null())
                    }
                } else {
                    Err(Error::decoding(format!("Unsupported extension object encoding, expected 1 or 2 for string, got {encoding}")))
                }
            } else {
                Err(Error::decoding("Missing extension object body"))
            }
        }
    }
}

#[cfg(feature = "xml")]
mod xml {
    use opcua_xml::events::Event;

    use crate::{xml::*, ByteString, NodeId};
    use std::io::{Read, Write};

    use super::ExtensionObject;

    impl XmlType for ExtensionObject {
        const TAG: &'static str = "ExtensionObject";
    }

    impl XmlEncodable for ExtensionObject {
        fn encode(
            &self,
            writer: &mut XmlStreamWriter<&mut dyn Write>,
            ctx: &crate::Context<'_>,
        ) -> super::EncodingResult<()> {
            let Some(body) = &self.body else {
                // An empty extension object is legal, meaning a null value.
                return Ok(());
            };
            let type_id = body.xml_type_id();
            let id = type_id.try_resolve(ctx.namespaces()).ok_or_else(|| {
                Error::encoding(format!("Missing namespace for encoding ID: {type_id}"))
            })?;

            writer.encode_child("TypeId", id.as_ref(), ctx)?;
            writer.write_start("Body")?;
            writer.write_start(body.xml_tag_name())?;
            body.encode_xml(writer, ctx)?;
            writer.write_end(body.xml_tag_name())?;
            writer.write_end("Body")?;

            Ok(())
        }
    }

    impl XmlDecodable for ExtensionObject {
        fn decode(
            read: &mut XmlStreamReader<&mut dyn Read>,
            ctx: &Context<'_>,
        ) -> Result<Self, Error> {
            let mut type_id = None;
            let mut body = None;
            read.iter_children(
                |key, reader, ctx| {
                    match key.as_str() {
                        "TypeId" => type_id = Some(NodeId::decode(reader, ctx)?),
                        "Body" => {
                            // First, read the top level element.
                            let top_level = loop {
                                match reader.next_event()? {
                                    Event::Start(s) => break s,
                                    Event::End(_) => {
                                        return Ok(()); // End of the body itself
                                    }
                                    _ => (),
                                }
                            };
                            let Some(type_id) = type_id.take() else {
                                return Err(Error::decoding("Missing type ID in extension object"));
                            };

                            if top_level.name().0 == b"ByteString" {
                                // If it's a bytestring, decode it as a binary body.
                                let val = ByteString::decode(reader, ctx)?;
                                if let Some(raw) = val.value {
                                    let mut cursor = std::io::Cursor::new(raw);
                                    body = Some(ctx.load_from_binary(&type_id, &mut cursor)?);
                                }
                            } else {
                                // Decode from XML.
                                body = Some(ctx.load_from_xml(&type_id, reader)?);
                            }
                            // Read to the end of the body.
                            reader.skip_value()?;
                        }
                        _ => reader.skip_value()?,
                    };
                    Ok(())
                },
                ctx,
            )?;
            Ok(body.unwrap_or_else(ExtensionObject::null))
        }
    }
}

/// An extension object holds an OPC-UA structure deserialize to a [DynEncodable].
/// This makes it possible to deserialize an extension object, the serialize it back in a different
/// format, without reflecting over or inspecting the inner type.
///
/// Note that in order for a type to be deserialized into an ExtensionObject, the
/// [crate::Context] given during deserialization needs to contain a [crate::TypeLoader]
/// that can handle the type.
#[derive(PartialEq, Debug)]
pub struct ExtensionObject {
    /// The raw extension object body.
    pub body: Option<Box<dyn DynEncodable>>,
}

impl Clone for ExtensionObject {
    fn clone(&self) -> Self {
        Self {
            body: self.body.as_ref().map(|b| b.clone_box()),
        }
    }
}

impl Default for ExtensionObject {
    fn default() -> Self {
        Self::null()
    }
}

impl BinaryEncodable for ExtensionObject {
    fn byte_len(&self, ctx: &crate::Context<'_>) -> usize {
        let type_id = self.binary_type_id();
        let id = type_id.try_resolve(ctx.namespaces());

        // Just default to null here, we'll fail later.
        let mut size = id.map(|n| n.byte_len(ctx)).unwrap_or(2usize);
        size += match &self.body {
            Some(b) => 5 + b.byte_len_dyn(ctx),
            None => 1,
        };

        size
    }

    fn encode<S: Write + ?Sized>(
        &self,
        mut stream: &mut S,
        ctx: &crate::Context<'_>,
    ) -> EncodingResult<()> {
        let type_id = self.binary_type_id();
        let id = type_id.try_resolve(ctx.namespaces());
        let Some(id) = id else {
            return Err(Error::encoding(format!("Unknown encoding ID: {type_id}")));
        };

        BinaryEncodable::encode(id.as_ref(), stream, ctx)?;

        match &self.body {
            Some(b) => {
                write_u8(stream, 0x1)?;
                write_i32(stream, b.byte_len_dyn(ctx) as i32)?;
                b.encode_binary(&mut stream as &mut dyn Write, ctx)
            }
            None => write_u8(stream, 0x0),
        }
    }
}
impl BinaryDecodable for ExtensionObject {
    fn decode<S: Read + ?Sized>(
        mut stream: &mut S,
        ctx: &crate::Context<'_>,
    ) -> EncodingResult<Self> {
        // Extension object is depth checked to prevent deep recursion
        let _depth_lock = ctx.options().depth_lock()?;
        let node_id = NodeId::decode(stream, ctx)?;
        let encoding_type = u8::decode(stream, ctx)?;
        let body = match encoding_type {
            0x0 => None,
            0x1 => {
                let size = i32::decode(stream, ctx)?;
                if size <= 0 {
                    None
                } else {
                    Some(ctx.load_from_binary(&node_id, &mut stream)?)
                }
            }
            0x2 => {
                #[cfg(feature = "xml")]
                {
                    let body = crate::UAString::decode(stream, ctx)?;
                    let Some(body) = body.value() else {
                        return Ok(ExtensionObject::null());
                    };
                    let mut cursor = std::io::Cursor::new(body.as_bytes());
                    let mut inner_stream =
                        crate::xml::XmlStreamReader::new(&mut cursor as &mut dyn Read);
                    if crate::xml::enter_first_tag(&mut inner_stream)? {
                        Some(ctx.load_from_xml(&node_id, &mut inner_stream)?)
                    } else {
                        None
                    }
                }

                #[cfg(not(feature = "xml"))]
                {
                    tracing::warn!("XML feature is not enabled, deserializing XML payloads in JSON extension objects is not supported");
                    let size = i32::decode(stream, ctx)?;
                    if size > 0 {
                        crate::encoding::skip_bytes(stream, size as u64)?;
                    }
                    None
                }
            }
            _ => {
                return Err(Error::decoding(format!(
                    "Invalid encoding type {} in stream",
                    encoding_type
                )));
            }
        };
        Ok(body.unwrap_or_else(ExtensionObject::null))
    }
}

impl ExtensionObject {
    /// Create an extension object from a structure.
    pub fn new<T>(encodable: T) -> ExtensionObject
    where
        T: DynEncodable,
    {
        Self {
            body: Some(Box::new(encodable)),
        }
    }

    /// Creates a null extension object, i.e. one with no value or payload
    pub fn null() -> ExtensionObject {
        ExtensionObject { body: None }
    }

    /// Tests for an empty extension object.
    pub fn is_null(&self) -> bool {
        self.body.is_none()
    }

    /// Get the binary type ID of the inner type.
    pub fn binary_type_id(&self) -> ExpandedNodeId {
        self.body
            .as_ref()
            .map(|b| b.binary_type_id())
            .unwrap_or_else(ExpandedNodeId::null)
    }

    /// Returns the object id of the thing this extension object contains, assuming the
    /// object id can be recognised from the node id.
    pub fn object_id(&self) -> Result<ObjectId, ExtensionObjectError> {
        self.body
            .as_ref()
            .ok_or(ExtensionObjectError)?
            .binary_type_id()
            .node_id
            .as_object_id()
            .map_err(|_| ExtensionObjectError)
    }

    /// Create an extension object from a structure.
    pub fn from_message<T>(encodable: T) -> ExtensionObject
    where
        T: DynEncodable,
    {
        Self {
            body: Some(Box::new(encodable)),
        }
    }

    /// Consume the extension object and return the inner value downcast to `T`,
    /// if the inner type is present and is an instance of `T`.
    ///
    /// You can use [match_extension_object_owned] for conveniently casting to one or more expected types.
    pub fn into_inner_as<T: Send + Sync + 'static>(self) -> Option<Box<T>> {
        self.body.and_then(|b| b.as_dyn_any().downcast().ok())
    }

    /// Return the inner value by reference downcast to `T`,
    /// if the inner type is present and is an instance of `T`.
    ///
    /// You can use [match_extension_object] for conveniently casting to one or more expected types.
    pub fn inner_as<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.body
            .as_ref()
            .and_then(|b| b.as_dyn_any_ref().downcast_ref())
    }

    /// Get the rust [std::any::TypeId] of the inner type, if the extension object is not null.
    pub fn type_id(&self) -> Option<TypeId> {
        self.body.as_ref().map(|b| (**b).type_id())
    }

    /// Return `true` if the inner value is an instance of `T`
    pub fn inner_is<T: 'static>(&self) -> bool {
        self.type_id() == Some(TypeId::of::<T>())
    }

    /// Get the name of the Rust type stored in the extension object, unless it is empty.
    pub fn type_name(&self) -> Option<&'static str> {
        self.body.as_ref().map(|b| b.type_name())
    }

    /// Get the full data type ID of the inner type.
    /// Note that for custom types this will not be resolved, so you need
    /// to call [`ExpandedNodeId::try_resolve`] to get the actual `NodeId`.
    pub fn data_type(&self) -> Option<ExpandedNodeId> {
        self.body.as_ref().map(|b| b.data_type_id())
    }
}

/// Macro for consuming an extension object and taking different actions depending on the
/// inner type, like a match over types.
///
/// # Example
///
/// ```
/// # mod opcua { pub(super) use opcua_types as types; }
/// use opcua::types::{EUInformation, ExtensionObject, match_extension_object_owned};
/// let obj = opcua::types::ExtensionObject::from_message(EUInformation {
///     namespace_uri: "Degrees C".into(),
///     ..Default::default()
/// });
/// match_extension_object_owned!(obj,
///     _v: opcua::types::Argument => println!("Object is argument"),
///     _v: EUInformation => println!("Object is EUInformation"),
///     _ => println!("Body is something else: {:?}", obj.type_name()),
/// )
/// ```
#[macro_export]
macro_rules! match_extension_object_owned {
    (_final { $($nom:tt)* }) => {
        $($nom)*
    };
    (_inner $obj:ident, { $($nom:tt)* }, _ => $t:expr $(,)?) => {
        match_extension_object_owned!(_final {
            $($nom)*
            else {
                $t
            }
        })
    };
    (_inner $obj:ident, { $($nom:tt)* }, $tok:ident: $typ:ty => $t:expr $(,)?) => {
        match_extension_object_owned!(_final {
            $($nom)*
            else if $obj.inner_is::<$typ>() {
                let $tok: $typ = *$obj.into_inner_as::<$typ>().unwrap();
                $t
            }
        })
    };
    (_inner $obj:ident, { $($nom:tt)* }, $tok:ident: $typ:ty => $t:expr, $($r:tt)*) => {
        match_extension_object_owned!(_inner $obj, {
            $($nom)*
            else if $obj.inner_is::<$typ>() {
                let $tok: $typ = *$obj.into_inner_as::<$typ>().unwrap();
                $t
            }
        }, $($r)*)
    };
    ($obj:ident, $tok:ident: $typ:ty => $t:expr, $($r:tt)*) => {
        match_extension_object_owned!(_inner $obj, {
            if $obj.inner_is::<$typ>() {
                let $tok: $typ = *$obj.into_inner_as::<$typ>().unwrap();
                $t
            }
        }, $($r)*)
    };
}

pub use match_extension_object_owned;

/// Macro for inspecting an extension object by reference and taking different actions depending on the
/// inner type, like a match over types.
///
/// # Example
///
/// ```
/// # mod opcua { pub(super) use opcua_types as types; }
/// use opcua::types::{EUInformation, ExtensionObject, match_extension_object};
/// let obj = opcua::types::ExtensionObject::from_message(EUInformation {
///     namespace_uri: "Degrees C".into(),
///     ..Default::default()
/// });
/// match_extension_object!(obj,
///     _v: opcua::types::Argument => println!("Object is argument"),
///     _v: EUInformation => println!("Object is EUInformation"),
///     _ => println!("Body is something else: {:?}", obj.type_name()),
/// )
/// ```
#[macro_export]
macro_rules! match_extension_object {
    (_final { $($nom:tt)* }) => {
        $($nom)*
    };
    (_inner $obj:ident, { $($nom:tt)* }, _ => $t:expr $(,)?) => {
        match_extension_object!(_final {
            $($nom)*
            else {
                $t
            }
        })
    };
    (_inner $obj:ident, { $($nom:tt)* }, $tok:ident: $typ:ty => $t:expr $(,)?) => {
        match_extension_object!(_final {
            $($nom)*
            else if let Some($tok) = $obj.inner_as::<$typ>() {
                $t
            }
        })
    };
    (_inner $obj:ident, { $($nom:tt)* }, $tok:ident: $typ:ty => $t:expr, $($r:tt)*) => {
        match_extension_object!(_inner $obj, {
            $($nom)*
            else if let Some($tok) = $obj.inner_as::<$typ>() {
                $t
            }
        }, $($r)*)
    };
    ($obj:ident, $tok:ident: $typ:ty => $t:expr, $($r:tt)*) => {
        match_extension_object!(_inner $obj, {
            if let Some($tok) = $obj.inner_as::<$typ>() {
                $t
            }
        }, $($r)*)
    };
}

pub use match_extension_object;
