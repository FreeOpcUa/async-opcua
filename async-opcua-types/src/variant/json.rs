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

        stream.name("UaType")?;
        stream.number_value(type_id as u32)?;

        if let Variant::Array(a) = self {
            if let Some(dims) = a.dimensions.as_ref() {
                if dims.len() > 1 {
                    stream.name("Dimensions")?;
                    JsonEncodable::encode(dims, stream, ctx)?;
                }
            }
            stream.name("Value")?;
            stream.begin_array()?;
            for v in &a.values {
                v.serialize_variant_value(stream, ctx)?;
            }
            stream.end_array()?;
        } else {
            stream.name("Value")?;
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum VariantJsonFieldMode {
    StandardUaTypeValue,
    LegacyTypeBodyCompatibility,
}

impl VariantJsonFieldMode {
    fn legacy_type_body_error(self) -> Option<Error> {
        (self == Self::StandardUaTypeValue).then(|| {
            Error::decoding(
                "legacy Variant JSON Type/Body fields require \
                 Variant::decode_legacy_type_body_json",
            )
        })
    }
}

impl Variant {
    /// Decode the legacy non-standard JSON Variant object that uses `Type`/`Body` fields.
    ///
    /// The standard [`JsonDecodable`] implementation accepts the Part 6 `UaType`/`Value`
    /// shape. This compatibility path is intentionally separate so legacy payload handling is
    /// explicit at the call site.
    #[cfg(feature = "json")]
    pub fn decode_legacy_type_body_json(
        stream: &mut JsonStreamReader<&mut dyn std::io::Read>,
        ctx: &Context<'_>,
    ) -> EncodingResult<Self> {
        decode_variant_json(
            stream,
            ctx,
            VariantJsonFieldMode::LegacyTypeBodyCompatibility,
        )
    }
}

fn decode_variant_json(
    stream: &mut JsonStreamReader<&mut dyn std::io::Read>,
    ctx: &Context<'_>,
    mode: VariantJsonFieldMode,
) -> EncodingResult<Variant> {
    if stream.peek()? == ValueType::Null {
        stream.next_null()?;
        return Ok(Variant::Empty);
    }

    stream.begin_object()?;

    let mut saw_type = false;
    let mut type_id = None;
    let mut value = None;
    let mut dimensions: Option<Vec<u32>> = None;
    let mut raw_value = None;
    while stream.has_next()? {
        match stream.next_name()? {
            "UaType" if mode == VariantJsonFieldMode::StandardUaTypeValue => {
                decode_variant_type(stream, &mut saw_type, &mut type_id)?;
            }
            "Value" if mode == VariantJsonFieldMode::StandardUaTypeValue => {
                decode_variant_value_field(stream, ctx, type_id, &mut value, &mut raw_value)?;
            }
            "Type" if mode == VariantJsonFieldMode::LegacyTypeBodyCompatibility => {
                decode_variant_type(stream, &mut saw_type, &mut type_id)?;
            }
            "UaType" if mode == VariantJsonFieldMode::LegacyTypeBodyCompatibility => {
                decode_variant_type(stream, &mut saw_type, &mut type_id)?;
            }
            "Body" if mode == VariantJsonFieldMode::LegacyTypeBodyCompatibility => {
                decode_variant_value_field(stream, ctx, type_id, &mut value, &mut raw_value)?;
            }
            "Type" | "Body" => {
                if let Some(error) = mode.legacy_type_body_error() {
                    return Err(error);
                }
                stream.skip_value()?;
            }
            "Value" if mode == VariantJsonFieldMode::LegacyTypeBodyCompatibility => {
                return Err(Error::decoding(
                    "standard Variant JSON Value field is not accepted by the legacy \
                     Type/Body compatibility decoder",
                ));
            }
            "Dimensions" => {
                dimensions = JsonDecodable::decode(stream, ctx)?;
            }
            _ => {
                stream.skip_value()?;
            }
        }
    }

    if !saw_type {
        stream.end_object()?;
        return if value.is_some() || raw_value.is_some() || dimensions.is_some() {
            Err(Error::decoding("Variant JSON is missing UaType"))
        } else {
            Ok(Variant::Empty)
        };
    }

    let Some(type_id) = type_id else {
        stream.end_object()?;
        return Ok(Variant::Empty);
    };

    if let Some(raw_value) = raw_value {
        let mut cursor = Cursor::new(raw_value);
        let mut inner_stream = JsonStreamReader::new(&mut cursor as &mut dyn Read);
        value = Some(decode_variant_value_dyn(&mut inner_stream, ctx, type_id)?);
    }

    let value = value.unwrap_or_else(|| VariantOrArray::Single(default_variant(type_id)));

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

fn decode_variant_type(
    stream: &mut JsonStreamReader<&mut dyn std::io::Read>,
    saw_type: &mut bool,
    type_id: &mut Option<VariantScalarTypeId>,
) -> EncodingResult<()> {
    if *saw_type {
        return Err(Error::decoding("duplicate Variant JSON type field"));
    }

    *saw_type = true;
    let ty: u32 = stream.next_number()??;
    if ty != 0 {
        *type_id = Some(
            VariantScalarTypeId::try_from(ty)
                .map_err(|_| Error::decoding(format!("Unexpected variant type: {ty}")))?,
        );
    }

    Ok(())
}

fn decode_variant_value_field(
    stream: &mut JsonStreamReader<&mut dyn std::io::Read>,
    ctx: &Context<'_>,
    type_id: Option<VariantScalarTypeId>,
    value: &mut Option<VariantOrArray>,
    raw_value: &mut Option<Vec<u8>>,
) -> EncodingResult<()> {
    if value.is_some() || raw_value.is_some() {
        return Err(Error::decoding("duplicate Variant JSON value field"));
    }

    if let Some(type_id) = type_id {
        *value = Some(decode_variant_value_dyn(stream, ctx, type_id)?);
    } else {
        *raw_value = Some(consume_raw_value(stream)?);
    }

    Ok(())
}

fn decode_variant_value<T>(
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
                if res.len() >= ctx.options().max_array_length {
                    return Err(Error::new(
                        StatusCode::BadEncodingLimitsExceeded,
                        format!(
                            "JSON array exceeds configured max array length {}",
                            ctx.options().max_array_length
                        ),
                    ));
                }
                res.push(T::decode(stream, ctx)?.into());
            }
            stream.end_array()?;
            Ok(VariantOrArray::Array(res))
        }
        ValueType::Null => {
            stream.next_null()?;
            Ok(VariantOrArray::Single(T::default().into()))
        }
        _ => Ok(VariantOrArray::Single(T::decode(stream, ctx)?.into())),
    }
}

fn decode_variant_value_dyn(
    stream: &mut JsonStreamReader<&mut dyn std::io::Read>,
    ctx: &Context<'_>,
    type_id: VariantScalarTypeId,
) -> EncodingResult<VariantOrArray> {
    match type_id {
        VariantScalarTypeId::Boolean => decode_variant_value::<bool>(stream, ctx),
        VariantScalarTypeId::SByte => decode_variant_value::<i8>(stream, ctx),
        VariantScalarTypeId::Byte => decode_variant_value::<u8>(stream, ctx),
        VariantScalarTypeId::Int16 => decode_variant_value::<i16>(stream, ctx),
        VariantScalarTypeId::UInt16 => decode_variant_value::<u16>(stream, ctx),
        VariantScalarTypeId::Int32 => decode_variant_value::<i32>(stream, ctx),
        VariantScalarTypeId::UInt32 => decode_variant_value::<u32>(stream, ctx),
        VariantScalarTypeId::Int64 => decode_variant_value::<i64>(stream, ctx),
        VariantScalarTypeId::UInt64 => decode_variant_value::<u64>(stream, ctx),
        VariantScalarTypeId::Float => decode_variant_value::<f32>(stream, ctx),
        VariantScalarTypeId::Double => decode_variant_value::<f64>(stream, ctx),
        VariantScalarTypeId::String => decode_variant_value::<UAString>(stream, ctx),
        VariantScalarTypeId::DateTime => decode_variant_value::<DateTime>(stream, ctx),
        VariantScalarTypeId::Guid => decode_variant_value::<Guid>(stream, ctx),
        VariantScalarTypeId::ByteString => decode_variant_value::<ByteString>(stream, ctx),
        VariantScalarTypeId::XmlElement => decode_variant_value::<XmlElement>(stream, ctx),
        VariantScalarTypeId::NodeId => decode_variant_value::<NodeId>(stream, ctx),
        VariantScalarTypeId::ExpandedNodeId => decode_variant_value::<ExpandedNodeId>(stream, ctx),
        VariantScalarTypeId::StatusCode => decode_variant_value::<StatusCode>(stream, ctx),
        VariantScalarTypeId::QualifiedName => decode_variant_value::<QualifiedName>(stream, ctx),
        VariantScalarTypeId::LocalizedText => decode_variant_value::<LocalizedText>(stream, ctx),
        VariantScalarTypeId::ExtensionObject => {
            decode_variant_value::<ExtensionObject>(stream, ctx)
        }
        VariantScalarTypeId::DataValue => decode_variant_value::<DataValue>(stream, ctx),
        VariantScalarTypeId::Variant => {
            let v = decode_variant_value::<Variant>(stream, ctx)?;
            match v {
                VariantOrArray::Single(variant) => {
                    Ok(VariantOrArray::Single(Variant::Variant(Box::new(variant))))
                }
                VariantOrArray::Array(vec) => Ok(VariantOrArray::Array(vec)),
            }
        }
        VariantScalarTypeId::DiagnosticInfo => decode_variant_value::<DiagnosticInfo>(stream, ctx),
    }
}

fn default_variant(type_id: VariantScalarTypeId) -> Variant {
    match type_id {
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
    }
}

impl JsonDecodable for Variant {
    fn decode(
        stream: &mut JsonStreamReader<&mut dyn std::io::Read>,
        ctx: &Context<'_>,
    ) -> EncodingResult<Self> {
        decode_variant_json(stream, ctx, VariantJsonFieldMode::StandardUaTypeValue)
    }
}
