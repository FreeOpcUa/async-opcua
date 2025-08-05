//! Tests for the fallback type loader, in various combinations.

use std::io::{Cursor, Read, Seek, SeekFrom, Write};

use opcua_macros::ua_encodable;
use opcua_xml::{XmlStreamReader, XmlStreamWriter};
use struson::{
    reader::JsonStreamReader,
    writer::{JsonStreamWriter, JsonWriter},
};

mod opcua {
    pub(super) use crate as types;
}
use crate::{
    binary_decode_to_enc,
    json::{JsonDecodable, JsonEncodable},
    json_decode_to_enc,
    xml::{XmlDecodable, XmlEncodable},
    xml_decode_to_enc, BinaryDecodable, BinaryEncodable, ByteStringBody, ContextOwned,
    ExpandedMessageInfo, ExtensionObject, Identifier, JsonBody, KeyValuePair, NodeId, TypeLoader,
    XmlBody,
};

#[ua_encodable]
#[derive(Debug, Clone, PartialEq)]
struct CustomType {
    data: KeyValuePair,
    foo: i32,
    bar: u32,
}

impl ExpandedMessageInfo for CustomType {
    fn full_type_id(&self) -> crate::ExpandedNodeId {
        NodeId::new(1, "customtype-binary").into()
    }

    fn full_json_type_id(&self) -> crate::ExpandedNodeId {
        NodeId::new(1, "customtype-json").into()
    }

    fn full_xml_type_id(&self) -> crate::ExpandedNodeId {
        NodeId::new(1, "customtype-xml").into()
    }

    fn full_data_type_id(&self) -> crate::ExpandedNodeId {
        NodeId::new(1, "customtype").into()
    }
}

impl Default for CustomType {
    fn default() -> Self {
        Self {
            data: KeyValuePair {
                key: "test".into(),
                value: 123.into(),
            },
            foo: 321,
            bar: 1,
        }
    }
}

struct MyTypeLoader;

impl TypeLoader for MyTypeLoader {
    fn load_from_xml(
        &self,
        node_id: &crate::NodeId,
        stream: &mut crate::xml::XmlStreamReader<&mut dyn std::io::Read>,
        ctx: &crate::Context<'_>,
        _name: &str,
    ) -> Option<crate::EncodingResult<Box<dyn crate::DynEncodable>>> {
        let Identifier::String(s) = &node_id.identifier else {
            return None;
        };
        if !s.as_ref().contains("customtype") {
            return None;
        }
        Some(xml_decode_to_enc::<CustomType>(stream, ctx))
    }

    fn load_from_json(
        &self,
        node_id: &crate::NodeId,
        stream: &mut crate::json::JsonStreamReader<&mut dyn std::io::Read>,
        ctx: &crate::Context<'_>,
    ) -> Option<crate::EncodingResult<Box<dyn crate::DynEncodable>>> {
        let Identifier::String(s) = &node_id.identifier else {
            return None;
        };
        if !s.as_ref().contains("customtype") {
            return None;
        }
        Some(json_decode_to_enc::<CustomType>(stream, ctx))
    }

    fn load_from_binary(
        &self,
        node_id: &NodeId,
        stream: &mut dyn std::io::Read,
        ctx: &crate::Context<'_>,
        _length: Option<usize>,
    ) -> Option<crate::EncodingResult<Box<dyn crate::DynEncodable>>> {
        let Identifier::String(s) = &node_id.identifier else {
            return None;
        };
        if !s.as_ref().contains("customtype") {
            return None;
        }
        Some(binary_decode_to_enc::<CustomType>(stream, ctx))
    }
}

#[test]
fn test_fallback_binary() {
    let v = CustomType::default();
    let to_encode = ExtensionObject::new(v.clone());
    let buf = Vec::<u8>::new();
    let mut cursor = Cursor::new(buf);
    let mut ctx = ContextOwned::default();
    BinaryEncodable::encode(&to_encode, &mut cursor, &ctx.context()).unwrap();

    cursor.seek(std::io::SeekFrom::Start(0)).unwrap();
    let decoded =
        <ExtensionObject as BinaryDecodable>::decode(&mut cursor, &ctx.context()).unwrap();
    let elem = decoded.into_inner_as::<ByteStringBody>().unwrap();
    assert_eq!(elem.encoding_id(), &v.full_type_id().node_id);

    // Serialize it back, then decode it with the real type loader.
    let to_encode = ExtensionObject::new(*elem);
    cursor.seek(SeekFrom::Start(0)).unwrap();
    cursor.get_mut().clear();
    BinaryEncodable::encode(&to_encode, &mut cursor, &ctx.context()).unwrap();

    ctx.loaders_mut().add_type_loader(MyTypeLoader);
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let decoded =
        <ExtensionObject as BinaryDecodable>::decode(&mut cursor, &ctx.context()).unwrap();
    let elem = decoded.into_inner_as::<CustomType>().unwrap();
    assert_eq!(*elem, v);
}

#[test]
fn test_fallback_xml() {
    let v = CustomType::default();
    let to_encode = ExtensionObject::new(v.clone());
    let buf = Vec::<u8>::new();
    let mut cursor = Cursor::new(buf);
    let mut ctx = ContextOwned::default();
    let mut writer = XmlStreamWriter::new(&mut cursor as &mut dyn Write);
    XmlEncodable::encode(&to_encode, &mut writer, &ctx.context()).unwrap();

    cursor.seek(std::io::SeekFrom::Start(0)).unwrap();
    let mut reader = XmlStreamReader::new(&mut cursor as &mut dyn Read);
    let decoded = <ExtensionObject as XmlDecodable>::decode(&mut reader, &ctx.context()).unwrap();
    let elem = decoded.into_inner_as::<XmlBody>().unwrap();
    assert_eq!(elem.encoding_id(), &v.full_xml_type_id().node_id);

    // Serialize it back, then decode it with the real type loader.
    let to_encode = ExtensionObject::new(*elem);
    cursor.seek(SeekFrom::Start(0)).unwrap();
    cursor.get_mut().clear();
    let mut writer = XmlStreamWriter::new(&mut cursor as &mut dyn Write);
    XmlEncodable::encode(&to_encode, &mut writer, &ctx.context()).unwrap();

    ctx.loaders_mut().add_type_loader(MyTypeLoader);
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = XmlStreamReader::new(&mut cursor as &mut dyn Read);
    let decoded = <ExtensionObject as XmlDecodable>::decode(&mut reader, &ctx.context()).unwrap();
    let elem = decoded.into_inner_as::<CustomType>().unwrap();
    assert_eq!(*elem, v);
}

#[test]
fn test_fallback_json() {
    let v = CustomType::default();
    let to_encode = ExtensionObject::new(v.clone());
    let buf = Vec::<u8>::new();
    let mut cursor = Cursor::new(buf);
    let mut ctx = ContextOwned::default();
    let mut writer = JsonStreamWriter::new(&mut cursor as &mut dyn Write);
    JsonEncodable::encode(&to_encode, &mut writer, &ctx.context()).unwrap();
    writer.finish_document().unwrap();

    cursor.seek(std::io::SeekFrom::Start(0)).unwrap();
    let mut reader = JsonStreamReader::new(&mut cursor as &mut dyn Read);
    let decoded = <ExtensionObject as JsonDecodable>::decode(&mut reader, &ctx.context()).unwrap();
    let elem = decoded.into_inner_as::<JsonBody>().unwrap();
    assert_eq!(elem.encoding_id(), &v.full_json_type_id().node_id);

    // Serialize it back, then decode it with the real type loader.
    let to_encode = ExtensionObject::new(*elem);
    cursor.seek(SeekFrom::Start(0)).unwrap();
    cursor.get_mut().clear();
    let mut writer = JsonStreamWriter::new(&mut cursor as &mut dyn Write);
    JsonEncodable::encode(&to_encode, &mut writer, &ctx.context()).unwrap();
    writer.finish_document().unwrap();

    ctx.loaders_mut().add_type_loader(MyTypeLoader);
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = JsonStreamReader::new(&mut cursor as &mut dyn Read);
    let decoded = <ExtensionObject as JsonDecodable>::decode(&mut reader, &ctx.context()).unwrap();
    let elem = decoded.into_inner_as::<CustomType>().unwrap();
    assert_eq!(*elem, v);
}
