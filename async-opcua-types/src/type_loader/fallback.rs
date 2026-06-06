//! Implementation of a type loader that simply extracts the raw binary data.

use crate::{
    BinaryEncodable, ByteString, Error, ExpandedMessageInfo, ExpandedNodeId, NodeId, UaNullable,
};

use super::TypeLoader;

/// Type loader that accepts any type, and simply returns one of
/// [ByteStringBody], [JsonBody], or [XmlBody]
pub struct FallbackTypeLoader;

impl TypeLoader for FallbackTypeLoader {
    #[cfg(feature = "xml")]
    fn load_from_xml(
        &self,
        node_id: &crate::NodeId,
        stream: &mut crate::xml::XmlStreamReader<&mut dyn std::io::Read>,
        _ctx: &super::Context<'_>,
        name: &str,
    ) -> Option<crate::EncodingResult<Box<dyn crate::DynEncodable>>> {
        let raw = match stream.consume_raw() {
            Ok(v) => v,
            Err(e) => return Some(Err(e.into())),
        };
        Some(Ok(Box::new(XmlBody {
            raw,
            encoding_id: node_id.clone(),
            tag_name: name.to_owned(),
        })))
    }

    #[cfg(feature = "json")]
    fn load_from_json(
        &self,
        node_id: &crate::NodeId,
        stream: &mut crate::json::JsonStreamReader<&mut dyn std::io::Read>,
        _ctx: &super::Context<'_>,
    ) -> Option<crate::EncodingResult<Box<dyn crate::DynEncodable>>> {
        use crate::json::consume_raw_value;

        let raw = match consume_raw_value(stream) {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        Some(Ok(Box::new(JsonBody {
            raw,
            encoding_id: node_id.clone(),
        })))
    }

    fn load_from_binary(
        &self,
        node_id: &NodeId,
        stream: &mut dyn std::io::Read,
        _ctx: &super::Context<'_>,
        length: Option<usize>,
    ) -> Option<crate::EncodingResult<Box<dyn crate::DynEncodable>>> {
        // If the length is unknown, there really isn't a lot we can do.
        let length = length?;
        let mut buf = vec![0u8; length];
        if let Err(e) = stream.read_exact(&mut buf) {
            return Some(Err(e.into()));
        }
        Some(Ok(Box::new(ByteStringBody {
            raw: ByteString::from(buf),
            encoding_id: node_id.clone(),
        })))
    }

    fn priority(&self) -> super::TypeLoaderPriority {
        super::TypeLoaderPriority::Fallback
    }
}

/// A fallback value for an [ExtensionObject](crate::ExtensionObject) body
/// originally encoded as a [ByteString].
#[derive(Debug, PartialEq, Clone)]
pub struct ByteStringBody {
    raw: ByteString,
    encoding_id: NodeId,
}

impl ByteStringBody {
    /// Create a new ByteStringBody with the given raw data and encoding ID.
    pub fn new(raw: ByteString, encoding_id: NodeId) -> Self {
        Self { raw, encoding_id }
    }

    /// Get the raw XML body as a sequence of bytes.
    pub fn raw_body(&self) -> &ByteString {
        &self.raw
    }

    /// Consume the ByteStringBody and return the raw body as a sequence of bytes.
    pub fn into_raw(self) -> ByteString {
        self.raw
    }

    /// Get the encoding ID of this object.
    pub fn encoding_id(&self) -> &NodeId {
        &self.encoding_id
    }
}

impl BinaryEncodable for ByteStringBody {
    fn byte_len(&self, _ctx: &crate::Context<'_>) -> usize {
        self.raw.len()
    }

    fn encode<S: std::io::Write + ?Sized>(
        &self,
        stream: &mut S,
        _ctx: &super::Context<'_>,
    ) -> crate::EncodingResult<()> {
        Ok(stream.write_all(self.raw.as_ref())?)
    }

    fn override_encoding(&self) -> Option<crate::BuiltInDataEncoding> {
        Some(crate::BuiltInDataEncoding::Binary)
    }
}

// We always just return the raw node ID here. There really isn't much alternative. In practice what we need to
// do is just serialize the value back in its raw form, which may or may not be possible.
impl ExpandedMessageInfo for ByteStringBody {
    fn full_data_type_id(&self) -> crate::ExpandedNodeId {
        ExpandedNodeId::new(self.encoding_id.clone())
    }

    fn full_json_type_id(&self) -> ExpandedNodeId {
        ExpandedNodeId::new(self.encoding_id.clone())
    }

    fn full_type_id(&self) -> ExpandedNodeId {
        ExpandedNodeId::new(self.encoding_id.clone())
    }

    fn full_xml_type_id(&self) -> ExpandedNodeId {
        ExpandedNodeId::new(self.encoding_id.clone())
    }
}

impl UaNullable for ByteStringBody {
    fn is_ua_null(&self) -> bool {
        self.raw.is_null()
    }
}

/// A fallback value for an [ExtensionObject](crate::ExtensionObject) body
/// originally encoded as a JSON object.
#[derive(Debug, PartialEq, Clone)]
pub struct JsonBody {
    raw: Vec<u8>,
    encoding_id: NodeId,
}

impl JsonBody {
    /// Create a new JsonBody with the given raw data and encoding ID.
    pub fn new(raw: Vec<u8>, encoding_id: NodeId) -> Self {
        Self { raw, encoding_id }
    }

    /// Get the raw XML body as a sequence of bytes.
    pub fn raw_body(&self) -> &[u8] {
        &self.raw
    }

    /// Consume the JsonBody and return the raw body as a sequence of bytes.
    pub fn into_raw(self) -> Vec<u8> {
        self.raw
    }

    /// Get the encoding ID of this object.
    pub fn encoding_id(&self) -> &NodeId {
        &self.encoding_id
    }
}

impl BinaryEncodable for JsonBody {
    fn byte_len(&self, _ctx: &crate::Context<'_>) -> usize {
        0
    }

    fn encode<S: std::io::Write + ?Sized>(
        &self,
        _stream: &mut S,
        _ctx: &super::Context<'_>,
    ) -> crate::EncodingResult<()> {
        // This just isn't supported by the standard.
        Err(Error::encoding(
            "Cannot encode a raw json body as a binary ExtensionObject body",
        ))
    }

    fn override_encoding(&self) -> Option<crate::BuiltInDataEncoding> {
        Some(crate::BuiltInDataEncoding::JSON)
    }
}

impl ExpandedMessageInfo for JsonBody {
    fn full_data_type_id(&self) -> crate::ExpandedNodeId {
        ExpandedNodeId::new(self.encoding_id.clone())
    }

    fn full_json_type_id(&self) -> ExpandedNodeId {
        ExpandedNodeId::new(self.encoding_id.clone())
    }

    fn full_type_id(&self) -> ExpandedNodeId {
        ExpandedNodeId::new(self.encoding_id.clone())
    }

    fn full_xml_type_id(&self) -> ExpandedNodeId {
        ExpandedNodeId::new(self.encoding_id.clone())
    }
}

impl UaNullable for JsonBody {
    fn is_ua_null(&self) -> bool {
        self.raw.is_empty()
    }
}

/// A fallback value for an [ExtensionObject](crate::ExtensionObject) body
/// originally encoded as an XML structure.
#[derive(Debug, PartialEq, Clone)]
pub struct XmlBody {
    raw: Vec<u8>,
    encoding_id: NodeId,
    tag_name: String,
}

impl XmlBody {
    /// Create a new XmlBody with the given raw data and encoding ID.
    pub fn new(raw: Vec<u8>, encoding_id: NodeId, tag_name: String) -> Self {
        Self {
            raw,
            encoding_id,
            tag_name,
        }
    }

    /// Get the raw XML body as a sequence of bytes.
    pub fn raw_body(&self) -> &[u8] {
        &self.raw
    }

    /// Consume the XmlBody and return the raw body as a sequence of bytes.
    pub fn into_raw(self) -> Vec<u8> {
        self.raw
    }

    /// Get the encoding ID of this object.
    pub fn encoding_id(&self) -> &NodeId {
        &self.encoding_id
    }
}

impl BinaryEncodable for XmlBody {
    fn byte_len(&self, _ctx: &crate::Context<'_>) -> usize {
        self.raw.len()
    }

    fn encode<S: std::io::Write + ?Sized>(
        &self,
        stream: &mut S,
        _ctx: &super::Context<'_>,
    ) -> crate::EncodingResult<()> {
        stream.write_all(&self.raw)?;
        Ok(())
    }

    fn override_encoding(&self) -> Option<crate::BuiltInDataEncoding> {
        Some(crate::BuiltInDataEncoding::XML)
    }
}

impl ExpandedMessageInfo for XmlBody {
    fn full_data_type_id(&self) -> crate::ExpandedNodeId {
        ExpandedNodeId::new(self.encoding_id.clone())
    }

    fn full_json_type_id(&self) -> ExpandedNodeId {
        ExpandedNodeId::new(self.encoding_id.clone())
    }

    fn full_type_id(&self) -> ExpandedNodeId {
        ExpandedNodeId::new(self.encoding_id.clone())
    }

    fn full_xml_type_id(&self) -> ExpandedNodeId {
        ExpandedNodeId::new(self.encoding_id.clone())
    }
}

impl UaNullable for XmlBody {
    fn is_ua_null(&self) -> bool {
        self.raw.is_empty()
    }
}

#[cfg(feature = "json")]
mod json {
    use crate::json::*;

    use super::{ByteStringBody, JsonBody, XmlBody};

    impl JsonEncodable for ByteStringBody {
        fn encode(
            &self,
            stream: &mut struson::writer::JsonStreamWriter<&mut dyn std::io::Write>,
            _ctx: &crate::Context<'_>,
        ) -> crate::EncodingResult<()> {
            stream.string_value(&self.raw.as_base64())?;
            Ok(())
        }
    }

    impl JsonEncodable for JsonBody {
        fn encode(
            &self,
            stream: &mut JsonStreamWriter<&mut dyn std::io::Write>,
            _ctx: &crate::Context<'_>,
        ) -> crate::EncodingResult<()> {
            write_raw_value(&self.raw, stream)?;
            Ok(())
        }
    }

    impl JsonEncodable for XmlBody {
        fn encode(
            &self,
            stream: &mut JsonStreamWriter<&mut dyn std::io::Write>,
            _ctx: &crate::Context<'_>,
        ) -> crate::EncodingResult<()> {
            stream.string_value(&String::from_utf8_lossy(&self.raw))?;
            Ok(())
        }
    }
}

#[cfg(feature = "xml")]
mod xml {
    use crate::{
        xml::{XmlEncodable, XmlType},
        Error,
    };

    use super::{ByteStringBody, JsonBody, XmlBody};

    impl XmlType for ByteStringBody {
        const TAG: &'static str = "ByteString";
    }

    impl XmlEncodable for ByteStringBody {
        fn encode(
            &self,
            writer: &mut opcua_xml::XmlStreamWriter<&mut dyn std::io::Write>,
            _context: &crate::Context<'_>,
        ) -> crate::EncodingResult<()> {
            writer.write_text(&self.raw.as_base64())?;
            Ok(())
        }
    }

    impl XmlType for JsonBody {
        const TAG: &'static str = "JsonElement"; // Just need something here, as a placeholder.
    }

    impl XmlEncodable for JsonBody {
        fn encode(
            &self,
            _writer: &mut opcua_xml::XmlStreamWriter<&mut dyn std::io::Write>,
            _context: &crate::Context<'_>,
        ) -> crate::EncodingResult<()> {
            // This just isn't supported by the standard.
            Err(Error::encoding(
                "Cannot encode a raw json body as an XML ExtensionObject body",
            ))
        }
    }

    impl XmlType for XmlBody {
        const TAG: &'static str = "XmlElement";
        fn tag(&self) -> &str {
            &self.tag_name
        }
    }

    impl XmlEncodable for XmlBody {
        fn encode(
            &self,
            writer: &mut opcua_xml::XmlStreamWriter<&mut dyn std::io::Write>,
            _context: &crate::Context<'_>,
        ) -> crate::EncodingResult<()> {
            writer.write_raw(&self.raw)?;
            Ok(())
        }
    }
}
