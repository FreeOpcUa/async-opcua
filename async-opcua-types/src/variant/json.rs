//! Utilities for JSON encoding variants.

use std::io::{Cursor, Read};

use crate::{
    json::*, ByteString, DataValue, DateTime, DiagnosticInfo, EncodingResult, Error,
    ExpandedNodeId, ExtensionObject, Guid, LocalizedText, NodeId, QualifiedName, StatusCode,
    UAString, Variant, VariantScalarTypeId, XmlElement,
};

impl Variant {
    /// JSON serialize the value of a variant using OPC-UA JSON encoding.
    ///
    /// Note that this serializes just the _value_. To include the type ID,
    /// use [`JsonEncodable::encode`].
    pub fn serialize_variant_value(
        &self,
        stream: &mut JsonStreamWriter<&mut dyn std::io::Write>,
        ctx: &crate::Context<'_>,
    ) -> crate::EncodingResult<()> {
        match self {
            Variant::Empty => stream.null_value()?,
            Variant::Boolean(v) => JsonEncodable::encode(v, stream, ctx)?,
            Variant::SByte(v) => JsonEncodable::encode(v, stream, ctx)?,
            Variant::Byte(v) => JsonEncodable::encode(v, stream, ctx)?,
            Variant::Int16(v) => JsonEncodable::encode(v, stream, ctx)?,
            Variant::UInt16(v) => JsonEncodable::encode(v, stream, ctx)?,
            Variant::Int32(v) => JsonEncodable::encode(v, stream, ctx)?,
            Variant::UInt32(v) => JsonEncodable::encode(v, stream, ctx)?,
            Variant::Int64(v) => JsonEncodable::encode(v, stream, ctx)?,
            Variant::UInt64(v) => JsonEncodable::encode(v, stream, ctx)?,
            Variant::Float(v) => JsonEncodable::encode(v, stream, ctx)?,
            Variant::Double(v) => JsonEncodable::encode(v, stream, ctx)?,
            Variant::String(v) => JsonEncodable::encode(v, stream, ctx)?,
            Variant::DateTime(v) => JsonEncodable::encode(v, stream, ctx)?,
            Variant::Guid(v) => JsonEncodable::encode(v, stream, ctx)?,
            Variant::StatusCode(v) => JsonEncodable::encode(v, stream, ctx)?,
            Variant::ByteString(v) => JsonEncodable::encode(v, stream, ctx)?,
            Variant::XmlElement(v) => JsonEncodable::encode(v, stream, ctx)?,
            Variant::QualifiedName(v) => JsonEncodable::encode(v, stream, ctx)?,
            Variant::LocalizedText(v) => JsonEncodable::encode(v, stream, ctx)?,
            Variant::NodeId(v) => JsonEncodable::encode(v, stream, ctx)?,
            Variant::ExpandedNodeId(v) => JsonEncodable::encode(v, stream, ctx)?,
            Variant::ExtensionObject(v) => JsonEncodable::encode(v, stream, ctx)?,
            Variant::Variant(v) => JsonEncodable::encode(v, stream, ctx)?,
            Variant::DataValue(v) => JsonEncodable::encode(v, stream, ctx)?,
            Variant::DiagnosticInfo(v) => JsonEncodable::encode(v, stream, ctx)?,
            Variant::Array(array) => {
                // Shouldn't really happen, but there's a reasonable fallback.
                stream.begin_array()?;
                for v in &array.values {
                    v.serialize_variant_value(stream, ctx)?;
                }
                stream.end_array()?;
            }
        }

        Ok(())
    }
}

impl JsonEncodable for Variant {
    fn encode(
        &self,
        stream: &mut JsonStreamWriter<&mut dyn std::io::Write>,
        ctx: &crate::Context<'_>,
    ) -> crate::EncodingResult<()> {
        let type_id = match self.type_id() {
            crate::VariantTypeId::Empty => {
                stream.null_value()?;
                return Ok(());
            }
            crate::VariantTypeId::Scalar(s) => s,
            crate::VariantTypeId::Array(s, _) => s,
        };

        stream.begin_object()?;

        stream.name("Type")?;
        stream.number_value(type_id as u32)?;

        if let Variant::Array(a) = self {
            if let Some(dims) = a.dimensions.as_ref() {
                if dims.len() > 1 {
                    stream.name("Dimensions")?;
                    JsonEncodable::encode(dims, stream, ctx)?;
                }
            }
            stream.name("Body")?;
            stream.begin_array()?;
            for v in &a.values {
                v.serialize_variant_value(stream, ctx)?;
            }
            stream.end_array()?;
        } else {
            stream.name("Body")?;
            self.serialize_variant_value(stream, ctx)?;
        }
        stream.end_object()?;

        Ok(())
    }
}

enum VariantOrArray {
    Single(Variant),
    Array(Vec<Variant>),
}

impl JsonDecodable for Variant {
    fn decode(
        stream: &mut JsonStreamReader<&mut dyn std::io::Read>,
        ctx: &Context<'_>,
    ) -> EncodingResult<Self> {
        if stream.peek()? == ValueType::Null {
            stream.next_null()?;
            return Ok(Self::Empty);
        }

        stream.begin_object()?;

        fn dec_body<T>(
            stream: &mut JsonStreamReader<&mut dyn std::io::Read>,
            ctx: &Context<'_>,
        ) -> EncodingResult<VariantOrArray>
        where
            T: Into<Variant> + JsonDecodable + Default,
        {
            match stream.peek()? {
                ValueType::Array => {
                    let mut res = Vec::new();
                    stream.begin_array()?;
                    while stream.has_next()? {
                        res.push(T::decode(stream, ctx)?.into());
                    }
                    stream.end_array()?;
                    Ok(VariantOrArray::Array(res))
                }
                ValueType::Null => Ok(VariantOrArray::Single(T::default().into())),
                _ => Ok(VariantOrArray::Single(T::decode(stream, ctx)?.into())),
            }
        }

        fn dec_body_dyn(
            stream: &mut JsonStreamReader<&mut dyn std::io::Read>,
            ctx: &Context<'_>,
            type_id: VariantScalarTypeId,
        ) -> EncodingResult<VariantOrArray> {
            match type_id {
                VariantScalarTypeId::Boolean => dec_body::<bool>(stream, ctx),
                VariantScalarTypeId::SByte => dec_body::<i8>(stream, ctx),
                VariantScalarTypeId::Byte => dec_body::<u8>(stream, ctx),
                VariantScalarTypeId::Int16 => dec_body::<i16>(stream, ctx),
                VariantScalarTypeId::UInt16 => dec_body::<u16>(stream, ctx),
                VariantScalarTypeId::Int32 => dec_body::<i32>(stream, ctx),
                VariantScalarTypeId::UInt32 => dec_body::<u32>(stream, ctx),
                VariantScalarTypeId::Int64 => dec_body::<i64>(stream, ctx),
                VariantScalarTypeId::UInt64 => dec_body::<u64>(stream, ctx),
                VariantScalarTypeId::Float => dec_body::<f32>(stream, ctx),
                VariantScalarTypeId::Double => dec_body::<f64>(stream, ctx),
                VariantScalarTypeId::String => dec_body::<UAString>(stream, ctx),
                VariantScalarTypeId::DateTime => dec_body::<DateTime>(stream, ctx),
                VariantScalarTypeId::Guid => dec_body::<Guid>(stream, ctx),
                VariantScalarTypeId::ByteString => dec_body::<ByteString>(stream, ctx),
                VariantScalarTypeId::XmlElement => dec_body::<XmlElement>(stream, ctx),
                VariantScalarTypeId::NodeId => dec_body::<NodeId>(stream, ctx),
                VariantScalarTypeId::ExpandedNodeId => dec_body::<ExpandedNodeId>(stream, ctx),
                VariantScalarTypeId::StatusCode => dec_body::<StatusCode>(stream, ctx),
                VariantScalarTypeId::QualifiedName => dec_body::<QualifiedName>(stream, ctx),
                VariantScalarTypeId::LocalizedText => dec_body::<LocalizedText>(stream, ctx),
                VariantScalarTypeId::ExtensionObject => dec_body::<ExtensionObject>(stream, ctx),
                VariantScalarTypeId::DataValue => dec_body::<DataValue>(stream, ctx),
                VariantScalarTypeId::Variant => {
                    let v = dec_body::<Variant>(stream, ctx)?;
                    // Only place where Into isn't sufficient. Add a layer of indirection
                    // to Single variants.
                    match v {
                        VariantOrArray::Single(variant) => {
                            Ok(VariantOrArray::Single(Variant::Variant(Box::new(variant))))
                        }
                        VariantOrArray::Array(vec) => Ok(VariantOrArray::Array(vec)),
                    }
                }
                VariantScalarTypeId::DiagnosticInfo => dec_body::<DiagnosticInfo>(stream, ctx),
            }
        }

        let mut type_id = None;
        let mut value = None;
        let mut dimensions: Option<Vec<u32>> = None;
        let mut raw_value = None;
        while stream.has_next()? {
            match stream.next_name()? {
                "Type" => {
                    let ty: u32 = stream.next_number()??;
                    if ty != 0 {
                        type_id = Some(VariantScalarTypeId::try_from(ty).map_err(|_| {
                            Error::decoding(format!("Unexpected variant type: {}", ty))
                        })?);
                    }
                }
                "Body" => {
                    if let Some(type_id) = type_id {
                        value = Some(dec_body_dyn(stream, ctx, type_id)?);
                    } else {
                        raw_value = Some(consume_raw_value(stream)?);
                    }
                }
                "Dimensions" => {
                    dimensions = JsonDecodable::decode(stream, ctx)?;
                }
                _ => {
                    stream.skip_value()?;
                }
            }
        }

        let Some(type_id) = type_id else {
            stream.end_object()?;
            return Ok(Variant::Empty);
        };

        if let Some(raw_value) = raw_value {
            let mut cursor = Cursor::new(raw_value);
            let mut inner_stream = JsonStreamReader::new(&mut cursor as &mut dyn Read);
            value = Some(dec_body_dyn(&mut inner_stream, ctx, type_id)?);
        }

        let value = value.unwrap_or_else(|| {
            VariantOrArray::Single(match type_id {
                VariantScalarTypeId::Boolean => Variant::from(bool::default()),
                VariantScalarTypeId::SByte => Variant::from(i8::default()),
                VariantScalarTypeId::Byte => Variant::from(u8::default()),
                VariantScalarTypeId::Int16 => Variant::from(i16::default()),
                VariantScalarTypeId::UInt16 => Variant::from(u16::default()),
                VariantScalarTypeId::Int32 => Variant::from(i32::default()),
                VariantScalarTypeId::UInt32 => Variant::from(u32::default()),
                VariantScalarTypeId::Int64 => Variant::from(i64::default()),
                VariantScalarTypeId::UInt64 => Variant::from(u64::default()),
                VariantScalarTypeId::Float => Variant::from(f32::default()),
                VariantScalarTypeId::Double => Variant::from(f64::default()),
                VariantScalarTypeId::String => Variant::from(UAString::default()),
                VariantScalarTypeId::DateTime => Variant::from(DateTime::default()),
                VariantScalarTypeId::Guid => Variant::from(Guid::default()),
                VariantScalarTypeId::ByteString => Variant::from(ByteString::default()),
                VariantScalarTypeId::XmlElement => Variant::from(XmlElement::default()),
                VariantScalarTypeId::NodeId => Variant::from(NodeId::default()),
                VariantScalarTypeId::ExpandedNodeId => Variant::from(ExpandedNodeId::default()),
                VariantScalarTypeId::StatusCode => Variant::from(StatusCode::default()),
                VariantScalarTypeId::QualifiedName => Variant::from(QualifiedName::default()),
                VariantScalarTypeId::LocalizedText => Variant::from(LocalizedText::default()),
                VariantScalarTypeId::ExtensionObject => Variant::from(ExtensionObject::default()),
                VariantScalarTypeId::DataValue => Variant::from(DataValue::default()),
                VariantScalarTypeId::Variant => Variant::Variant(Box::default()),
                VariantScalarTypeId::DiagnosticInfo => Variant::from(DiagnosticInfo::default()),
            })
        });

        let variant = match (value, dimensions) {
            (VariantOrArray::Single(variant), None) => variant,
            (VariantOrArray::Single(_), Some(_)) => {
                return Err(Error::decoding(
                    "Unexpected dimensions for scalar variant value during json decoding",
                ));
            }
            (VariantOrArray::Array(vec), d) => Variant::Array(Box::new(crate::Array {
                value_type: type_id,
                values: vec,
                dimensions: d,
            })),
        };

        stream.end_object()?;

        Ok(variant)
    }
}
