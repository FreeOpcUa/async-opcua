//! Enabled with the "xml" feature.
//!
//! Core utilities for working with decoding OPC UA types from NodeSet2 XML files.

mod builtins;
mod encoding;

pub use crate::{Context, EncodingResult, Error};
pub use encoding::{XmlDecodable, XmlEncodable, XmlReadExt, XmlType, XmlWriteExt};
pub use opcua_xml::{XmlStreamReader, XmlStreamWriter};

use std::{
    io::{Cursor, Read},
    str::FromStr,
};

use log::warn;
pub use opcua_xml::schema::opc_ua_types::XmlElement;

use crate::{
    Array, ByteString, ExpandedNodeId, ExtensionObject, LocalizedText, NodeId, QualifiedName,
    StatusCode, UninitializedIndex, Variant, VariantScalarTypeId,
};

impl From<UninitializedIndex> for Error {
    fn from(value: UninitializedIndex) -> Self {
        Self::decoding(format!("Uninitialized index {}", value.0))
    }
}

fn mk_node_id(node_id: &opc_ua_types::NodeId, ctx: &Context<'_>) -> Result<NodeId, Error> {
    let Some(idf) = &node_id.identifier else {
        return Ok(NodeId::null());
    };
    let Ok(mut parsed) = NodeId::from_str(idf) else {
        return Err(Error::decoding(format!("Invalid node ID: {idf}")));
    };
    parsed.namespace = ctx.resolve_namespace_index(parsed.namespace)?;
    Ok(parsed)
}

use opcua_xml::{
    events::Event,
    schema::opc_ua_types::{self, Variant as XmlVariant},
};

/// Enter the first tag in the stream, returning `true` if a start tag was found.
pub(crate) fn enter_first_tag(stream: &mut XmlStreamReader<&mut dyn Read>) -> EncodingResult<bool> {
    loop {
        match stream.next_event()? {
            Event::Start(_) => return Ok(true),
            Event::End(_) | Event::Eof | Event::Empty(_) => {
                return Ok(false);
            }
            _ => (),
        }
    }
}

fn mk_extension_object(
    val: &opc_ua_types::ExtensionObject,
    ctx: &Context<'_>,
) -> EncodingResult<ExtensionObject> {
    let Some(body) = &val.body else {
        return Ok(ExtensionObject::null());
    };
    let Some(data) = &body.raw else {
        return Ok(ExtensionObject::null());
    };
    let Some(type_id) = &val.type_id else {
        return Err(Error::decoding("Extension object missing type ID"));
    };
    let node_id = mk_node_id(type_id, ctx)?;
    let mut cursor = Cursor::new(data.as_bytes());
    let mut stream = XmlStreamReader::new(&mut cursor as &mut dyn Read);
    // Read the entry tag, as this is how extension objects are parsed
    enter_first_tag(&mut stream)?;
    ctx.load_from_xml(&node_id, &mut stream)
}

impl Variant {
    /// Create a Variant value from a NodeSet2 variant object.
    /// Note that this is different from the `FromXml` implementation of `Variant`,
    /// which accepts an untyped XML node.
    pub fn from_nodeset(val: &XmlVariant, ctx: &Context<'_>) -> EncodingResult<Variant> {
        Ok(match val {
            XmlVariant::Boolean(v) => (*v).into(),
            XmlVariant::ListOfBoolean(v) => v.into(),
            XmlVariant::SByte(v) => (*v).into(),
            XmlVariant::ListOfSByte(v) => v.into(),
            XmlVariant::Byte(v) => (*v).into(),
            XmlVariant::ListOfByte(v) => v.into(),
            XmlVariant::Int16(v) => (*v).into(),
            XmlVariant::ListOfInt16(v) => v.into(),
            XmlVariant::UInt16(v) => (*v).into(),
            XmlVariant::ListOfUInt16(v) => v.into(),
            XmlVariant::Int32(v) => (*v).into(),
            XmlVariant::ListOfInt32(v) => v.into(),
            XmlVariant::UInt32(v) => (*v).into(),
            XmlVariant::ListOfUInt32(v) => v.into(),
            XmlVariant::Int64(v) => (*v).into(),
            XmlVariant::ListOfInt64(v) => v.into(),
            XmlVariant::UInt64(v) => (*v).into(),
            XmlVariant::ListOfUInt64(v) => v.into(),
            XmlVariant::Float(v) => (*v).into(),
            XmlVariant::ListOfFloat(v) => v.into(),
            XmlVariant::Double(v) => (*v).into(),
            XmlVariant::ListOfDouble(v) => v.into(),
            XmlVariant::String(v) => v.clone().into(),
            XmlVariant::ListOfString(v) => v.into(),
            XmlVariant::DateTime(v) => (*v).into(),
            XmlVariant::ListOfDateTime(v) => v.into(),
            XmlVariant::Guid(v) => (*v).into(),
            XmlVariant::ListOfGuid(v) => v.into(),
            XmlVariant::ByteString(b) => ByteString::from_base64(b.trim())
                .unwrap_or_else(|| {
                    warn!("Invalid byte string: {b}");
                    ByteString::null()
                })
                .into(),
            XmlVariant::ListOfByteString(v) => v
                .iter()
                .map(|b| {
                    ByteString::from_base64(b.trim()).unwrap_or_else(|| {
                        warn!("Invalid byte string: {b}");
                        ByteString::null()
                    })
                })
                .collect::<Vec<_>>()
                .into(),
            XmlVariant::XmlElement(vec) => Variant::XmlElement(
                vec.iter()
                    .map(|v| v.to_string().trim().to_owned())
                    .collect::<String>()
                    .into(),
            ),
            XmlVariant::ListOfXmlElement(vec) => Variant::Array(Box::new(Array {
                value_type: VariantScalarTypeId::XmlElement,
                values: vec
                    .iter()
                    .map(|v| {
                        Variant::XmlElement(
                            v.iter()
                                .map(|vv| vv.to_string().trim().to_string())
                                .collect::<String>()
                                .into(),
                        )
                    })
                    .collect(),
                dimensions: None,
            })),
            XmlVariant::QualifiedName(q) => QualifiedName::new(
                ctx.resolve_namespace_index(q.namespace_index.unwrap_or(0))?,
                q.name.as_deref().unwrap_or("").trim(),
            )
            .into(),
            XmlVariant::ListOfQualifiedName(v) => v
                .iter()
                .map(|q| {
                    Ok(QualifiedName::new(
                        ctx.resolve_namespace_index(q.namespace_index.unwrap_or(0))?,
                        q.name.as_deref().unwrap_or("").trim(),
                    ))
                })
                .collect::<Result<Vec<QualifiedName>, Error>>()?
                .into(),
            XmlVariant::LocalizedText(l) => LocalizedText::new(
                l.locale.as_deref().unwrap_or("").trim(),
                l.text.as_deref().unwrap_or("").trim(),
            )
            .into(),
            XmlVariant::ListOfLocalizedText(v) => v
                .iter()
                .map(|l| {
                    LocalizedText::new(
                        l.locale.as_deref().unwrap_or("").trim(),
                        l.text.as_deref().unwrap_or("").trim(),
                    )
                })
                .collect::<Vec<_>>()
                .into(),
            XmlVariant::NodeId(node_id) => mk_node_id(node_id, ctx)?.into(),
            XmlVariant::ListOfNodeId(v) => v
                .iter()
                .map(|node_id| mk_node_id(node_id, ctx))
                .collect::<Result<Vec<_>, _>>()?
                .into(),
            XmlVariant::ExpandedNodeId(node_id) => {
                ExpandedNodeId::new(mk_node_id(node_id, ctx)?).into()
            }
            XmlVariant::ListOfExpandedNodeId(v) => v
                .iter()
                .map(|node_id| Ok(ExpandedNodeId::new(mk_node_id(node_id, ctx)?)))
                .collect::<Result<Vec<_>, Error>>()?
                .into(),
            XmlVariant::ExtensionObject(val) => mk_extension_object(val, ctx)?.into(),
            XmlVariant::ListOfExtensionObject(v) => v
                .iter()
                .map(|val| mk_extension_object(val, ctx))
                .collect::<Result<Vec<_>, _>>()?
                .into(),
            XmlVariant::Variant(variant) => {
                let inner = Variant::from_nodeset(variant, ctx)?;
                Variant::Variant(Box::new(inner))
            }
            XmlVariant::ListOfVariant(vec) => Variant::Array(Box::new(Array {
                value_type: VariantScalarTypeId::Variant,
                values: vec
                    .iter()
                    .map(|v| Ok(Variant::Variant(Box::new(Variant::from_nodeset(v, ctx)?))))
                    .collect::<Result<Vec<_>, Error>>()?,
                dimensions: None,
            })),
            XmlVariant::StatusCode(status_code) => StatusCode::from(status_code.code).into(),
            XmlVariant::ListOfStatusCode(vec) => vec
                .iter()
                .map(|v| StatusCode::from(v.code))
                .collect::<Vec<_>>()
                .into(),
        })
    }
}
