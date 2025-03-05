use crate::{
    xml::*, Array, ByteString, DataValue, DateTime, DiagnosticInfo, ExpandedNodeId,
    ExtensionObject, Guid, LocalizedText, NodeId, QualifiedName, StatusCode, UAString,
};

use super::{Variant, VariantScalarTypeId};

impl XmlType for Variant {
    const TAG: &'static str = "Variant";
}
impl VariantScalarTypeId {
    /// Get the XML name of a variant type.
    pub fn xml_name(&self) -> &'static str {
        match self {
            VariantScalarTypeId::Boolean => "Boolean",
            VariantScalarTypeId::SByte => "SByte",
            VariantScalarTypeId::Byte => "Byte",
            VariantScalarTypeId::Int16 => "Int16",
            VariantScalarTypeId::UInt16 => "UInt16",
            VariantScalarTypeId::Int32 => "Int32",
            VariantScalarTypeId::UInt32 => "UInt32",
            VariantScalarTypeId::Int64 => "Int64",
            VariantScalarTypeId::UInt64 => "UInt64",
            VariantScalarTypeId::Float => "Float",
            VariantScalarTypeId::Double => "Double",
            VariantScalarTypeId::String => "String",
            VariantScalarTypeId::DateTime => "DateTime",
            VariantScalarTypeId::Guid => "Guid",
            VariantScalarTypeId::ByteString => "ByteString",
            VariantScalarTypeId::XmlElement => "XmlElement",
            VariantScalarTypeId::NodeId => "NodeId",
            VariantScalarTypeId::ExpandedNodeId => "ExpandedNodeId",
            VariantScalarTypeId::StatusCode => "StatusCode",
            VariantScalarTypeId::QualifiedName => "QualifiedName",
            VariantScalarTypeId::LocalizedText => "LocalizedText",
            VariantScalarTypeId::ExtensionObject => "ExtensionObject",
            VariantScalarTypeId::DataValue => "DataValue",
            VariantScalarTypeId::Variant => "Variant",
            VariantScalarTypeId::DiagnosticInfo => "DiagnosticInfo",
        }
    }

    /// Get a variant type ID from the XML name of the variant type.
    pub fn from_xml_name(name: &str) -> Option<Self> {
        Some(match name {
            "Boolean" => VariantScalarTypeId::Boolean,
            "SByte" => VariantScalarTypeId::SByte,
            "Byte" => VariantScalarTypeId::Byte,
            "Int16" => VariantScalarTypeId::Int16,
            "UInt16" => VariantScalarTypeId::UInt16,
            "Int32" => VariantScalarTypeId::Int32,
            "UInt32" => VariantScalarTypeId::UInt32,
            "Int64" => VariantScalarTypeId::Int64,
            "UInt64" => VariantScalarTypeId::UInt64,
            "Float" => VariantScalarTypeId::Float,
            "Double" => VariantScalarTypeId::Double,
            "String" => VariantScalarTypeId::String,
            "DateTime" => VariantScalarTypeId::DateTime,
            "Guid" => VariantScalarTypeId::Guid,
            "ByteString" => VariantScalarTypeId::ByteString,
            "XmlElement" => VariantScalarTypeId::XmlElement,
            "NodeId" => VariantScalarTypeId::NodeId,
            "ExpandedNodeId" => VariantScalarTypeId::ExpandedNodeId,
            "StatusCode" => VariantScalarTypeId::StatusCode,
            "QualifiedName" => VariantScalarTypeId::QualifiedName,
            "LocalizedText" => VariantScalarTypeId::LocalizedText,
            "ExtensionObject" => VariantScalarTypeId::ExtensionObject,
            "DataValue" => VariantScalarTypeId::DataValue,
            "Variant" => VariantScalarTypeId::Variant,
            "DiagnosticInfo" => VariantScalarTypeId::DiagnosticInfo,
            _ => return None,
        })
    }
}

impl Variant {
    /// Get a default variant of the given type.
    pub fn get_variant_default(ty: VariantScalarTypeId) -> Variant {
        match ty {
            VariantScalarTypeId::Boolean => Variant::Boolean(Default::default()),
            VariantScalarTypeId::SByte => Variant::SByte(Default::default()),
            VariantScalarTypeId::Byte => Variant::Byte(Default::default()),
            VariantScalarTypeId::Int16 => Variant::Int16(Default::default()),
            VariantScalarTypeId::UInt16 => Variant::UInt16(Default::default()),
            VariantScalarTypeId::Int32 => Variant::Int32(Default::default()),
            VariantScalarTypeId::UInt32 => Variant::UInt32(Default::default()),
            VariantScalarTypeId::Int64 => Variant::Int64(Default::default()),
            VariantScalarTypeId::UInt64 => Variant::UInt64(Default::default()),
            VariantScalarTypeId::Float => Variant::Float(Default::default()),
            VariantScalarTypeId::Double => Variant::Double(Default::default()),
            VariantScalarTypeId::String => Variant::String(Default::default()),
            VariantScalarTypeId::DateTime => Variant::DateTime(Default::default()),
            VariantScalarTypeId::Guid => Variant::Guid(Default::default()),
            VariantScalarTypeId::ByteString => Variant::ByteString(Default::default()),
            VariantScalarTypeId::XmlElement => Variant::XmlElement(Default::default()),
            VariantScalarTypeId::NodeId => Variant::NodeId(Default::default()),
            VariantScalarTypeId::ExpandedNodeId => Variant::ExpandedNodeId(Default::default()),
            VariantScalarTypeId::StatusCode => Variant::StatusCode(Default::default()),
            VariantScalarTypeId::QualifiedName => Variant::QualifiedName(Default::default()),
            VariantScalarTypeId::LocalizedText => Variant::LocalizedText(Default::default()),
            VariantScalarTypeId::ExtensionObject => Variant::ExtensionObject(Default::default()),
            VariantScalarTypeId::DataValue => Variant::DataValue(Default::default()),
            VariantScalarTypeId::Variant => Variant::Variant(Default::default()),
            VariantScalarTypeId::DiagnosticInfo => Variant::DiagnosticInfo(Default::default()),
        }
    }

    /// Decode an XML variant value from stream, consuming the rest of the current element.
    pub fn xml_decode_variant_value(
        stream: &mut XmlStreamReader<&mut dyn std::io::Read>,
        context: &Context<'_>,
        key: &str,
    ) -> EncodingResult<Self> {
        if let Some(ty) = key.strip_prefix("ListOf") {
            let ty = VariantScalarTypeId::from_xml_name(ty)
                .ok_or_else(|| Error::decoding(format!("Invalid variant contents: {key}")))?;
            let mut vec = Vec::new();
            stream.iter_children_include_empty(
                |key, stream, context| {
                    let Some(stream) = stream else {
                        let ty = VariantScalarTypeId::from_xml_name(&key).ok_or_else(|| {
                            Error::decoding(format!("Invalid variant contents: {key}"))
                        })?;
                        vec.push(Self::get_variant_default(ty));
                        return Ok(());
                    };
                    let r = Variant::xml_decode_variant_value(stream, context, &key)?;
                    vec.push(r);
                    Ok(())
                },
                context,
            )?;
            Ok(Self::Array(Box::new(
                Array::new(ty, vec).map_err(Error::decoding)?,
            )))
        } else if key == "Matrix" {
            let mut dims = Vec::new();
            let mut elems = Vec::new();
            stream.iter_children(
                |key, stream, context| match key.as_str() {
                    "Dimensions" => {
                        dims = Vec::<i32>::decode(stream, context)?;
                        Ok(())
                    }
                    "Elements" => stream.iter_children_include_empty(
                        |key, stream, context| {
                            let Some(stream) = stream else {
                                let ty =
                                    VariantScalarTypeId::from_xml_name(&key).ok_or_else(|| {
                                        Error::decoding(format!("Invalid variant contents: {key}"))
                                    })?;
                                elems.push(Self::get_variant_default(ty));
                                return Ok(());
                            };
                            let r = Variant::xml_decode_variant_value(stream, context, &key)?;
                            elems.push(r);
                            Ok(())
                        },
                        context,
                    ),
                    r => Err(Error::decoding(format!(
                        "Invalid field in Matrix content: {r}"
                    ))),
                },
                context,
            )?;
            // If you have an empty matrix there's no actual way to determine the type.
            let scalar_type = elems
                .first()
                .and_then(|v| v.scalar_type_id())
                .unwrap_or(VariantScalarTypeId::Int32);
            Ok(Self::Array(Box::new(
                Array::new_multi(
                    scalar_type,
                    elems,
                    dims.into_iter()
                        .map(|d| d.try_into())
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| {
                            Error::decoding("Invalid array dimensions, must all be non-negative")
                        })?,
                )
                .map_err(Error::decoding)?,
            )))
        } else {
            Ok(match key {
                "Boolean" => Self::Boolean(XmlDecodable::decode(stream, context)?),
                "SByte" => Self::SByte(XmlDecodable::decode(stream, context)?),
                "Byte" => Self::Byte(XmlDecodable::decode(stream, context)?),
                "Int16" => Self::Int16(XmlDecodable::decode(stream, context)?),
                "UInt16" => Self::UInt16(XmlDecodable::decode(stream, context)?),
                "Int32" => Self::Int32(XmlDecodable::decode(stream, context)?),
                "UInt32" => Self::UInt32(XmlDecodable::decode(stream, context)?),
                "Int64" => Self::Int64(XmlDecodable::decode(stream, context)?),
                "UInt64" => Self::UInt64(XmlDecodable::decode(stream, context)?),
                "Float" => Self::Float(XmlDecodable::decode(stream, context)?),
                "Double" => Self::Double(XmlDecodable::decode(stream, context)?),
                "String" => Self::String(XmlDecodable::decode(stream, context)?),
                "DateTime" => Self::DateTime(XmlDecodable::decode(stream, context)?),
                "Guid" => Self::Guid(XmlDecodable::decode(stream, context)?),
                "ByteString" => Self::ByteString(XmlDecodable::decode(stream, context)?),
                "XmlElement" => Self::XmlElement(XmlDecodable::decode(stream, context)?),
                "NodeId" => Self::NodeId(XmlDecodable::decode(stream, context)?),
                "ExpandedNodeId" => Self::ExpandedNodeId(XmlDecodable::decode(stream, context)?),
                "StatusCode" => Self::StatusCode(XmlDecodable::decode(stream, context)?),
                "QualifiedName" => Self::QualifiedName(XmlDecodable::decode(stream, context)?),
                "LocalizedText" => Self::LocalizedText(XmlDecodable::decode(stream, context)?),
                "ExtensionObject" => Self::ExtensionObject(XmlDecodable::decode(stream, context)?),
                "DataValue" => Self::DataValue(XmlDecodable::decode(stream, context)?),
                "Variant" => Self::Variant(XmlDecodable::decode(stream, context)?),
                "DiagnosticInfo" => Self::DiagnosticInfo(XmlDecodable::decode(stream, context)?),
                r => return Err(Error::decoding(format!("Invalid variant type {r}"))),
            })
        }
    }
}

impl XmlEncodable for Variant {
    fn encode(
        &self,
        stream: &mut XmlStreamWriter<&mut dyn std::io::Write>,
        ctx: &Context<'_>,
    ) -> EncodingResult<()> {
        match self {
            Variant::Empty => return Ok(()),
            Variant::Boolean(v) => stream.encode_child(bool::TAG, v, ctx)?,
            Variant::SByte(v) => stream.encode_child(i8::TAG, v, ctx)?,
            Variant::Byte(v) => stream.encode_child(u8::TAG, v, ctx)?,
            Variant::Int16(v) => stream.encode_child(i16::TAG, v, ctx)?,
            Variant::UInt16(v) => stream.encode_child(u16::TAG, v, ctx)?,
            Variant::Int32(v) => stream.encode_child(i32::TAG, v, ctx)?,
            Variant::UInt32(v) => stream.encode_child(u32::TAG, v, ctx)?,
            Variant::Int64(v) => stream.encode_child(i64::TAG, v, ctx)?,
            Variant::UInt64(v) => stream.encode_child(u64::TAG, v, ctx)?,
            Variant::Float(v) => stream.encode_child(f32::TAG, v, ctx)?,
            Variant::Double(v) => stream.encode_child(f64::TAG, v, ctx)?,
            Variant::String(v) => stream.encode_child(UAString::TAG, v, ctx)?,
            Variant::DateTime(v) => stream.encode_child(DateTime::TAG, v, ctx)?,
            Variant::Guid(v) => stream.encode_child(Guid::TAG, v, ctx)?,
            Variant::StatusCode(v) => stream.encode_child(StatusCode::TAG, v, ctx)?,
            Variant::ByteString(v) => stream.encode_child(ByteString::TAG, v, ctx)?,
            Variant::XmlElement(v) => stream.encode_child(crate::XmlElement::TAG, v, ctx)?,
            Variant::QualifiedName(v) => stream.encode_child(QualifiedName::TAG, v, ctx)?,
            Variant::LocalizedText(v) => stream.encode_child(LocalizedText::TAG, v, ctx)?,
            Variant::NodeId(v) => stream.encode_child(NodeId::TAG, v, ctx)?,
            Variant::ExpandedNodeId(v) => stream.encode_child(ExpandedNodeId::TAG, v, ctx)?,
            Variant::ExtensionObject(v) => stream.encode_child(ExtensionObject::TAG, v, ctx)?,
            Variant::Variant(v) => stream.encode_child(Variant::TAG, v, ctx)?,
            Variant::DataValue(v) => stream.encode_child(DataValue::TAG, v, ctx)?,
            Variant::DiagnosticInfo(v) => stream.encode_child(DiagnosticInfo::TAG, v, ctx)?,
            Variant::Array(v) => {
                let xml_name = v.value_type.xml_name();
                if let Some(dims) = v.dimensions.as_ref() {
                    if dims.len() > 1 {
                        stream.write_start("Matrix")?;
                        // For some incredibly annoying reason, OPC-UA insists that dimensions be
                        // encoded as _signed_ integers. For other encoders it's irrelevant,
                        // but it matters for XML.
                        let dims: Vec<_> = dims.iter().map(|d| *d as i32).collect();
                        stream.encode_child("Dimensions", &dims, ctx)?;

                        stream.write_start("Elements")?;
                        for item in &v.values {
                            item.encode(stream, ctx)?;
                        }
                        stream.write_end("Elements")?;
                        stream.write_end("Matrix")?;
                        return Ok(());
                    }
                }
                let tag_name = format!("ListOf{}", xml_name);
                stream.write_start(&tag_name)?;
                for item in &v.values {
                    item.encode(stream, ctx)?;
                }
                stream.write_end(&tag_name)?;
            }
        }

        Ok(())
    }
}

impl XmlDecodable for Variant {
    fn decode(
        stream: &mut XmlStreamReader<&mut dyn std::io::Read>,
        context: &Context<'_>,
    ) -> Result<Self, Error> {
        stream
            .get_first_child(
                |key, stream, ctx| Self::xml_decode_variant_value(stream, ctx, &key),
                context,
            )
            .map(|v| v.unwrap_or(Variant::Empty))
    }
}
