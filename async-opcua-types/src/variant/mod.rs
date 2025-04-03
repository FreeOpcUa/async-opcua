// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Contains the most of the implementation of `Variant`. Some substantial chunks like JSON serialization
//! are moved off into their own files due to the complexity of this functionality.

mod from;
mod into;
#[cfg(feature = "json")]
mod json;
mod type_id;
#[cfg(feature = "xml")]
mod xml;

mod xml_element;

pub use xml_element::XmlElement;

pub use from::TryFromVariant;
pub use into::IntoVariant;
pub use type_id::*;

use std::{
    convert::TryFrom,
    fmt,
    io::{Read, Write},
    str::FromStr,
};

use tracing::error;
use uuid::Uuid;

use crate::{
    array::*,
    byte_string::ByteString,
    date_time::DateTime,
    encoding::{BinaryDecodable, BinaryEncodable, EncodingResult},
    expanded_node_id::ExpandedNodeId,
    extension_object::ExtensionObject,
    guid::Guid,
    localized_text::LocalizedText,
    node_id::NodeId,
    numeric_range::NumericRange,
    qualified_name::QualifiedName,
    status_code::StatusCode,
    string::UAString,
    write_i32, write_u8, DataTypeId, DataValue, DiagnosticInfo, DynEncodable, Error, UaNullable,
};
/// A `Variant` holds built-in OPC UA data types, including single and multi dimensional arrays,
/// data values and extension objects.
///
/// As variants may be passed around a lot on the stack, Boxes are used for more complex types to
/// keep the size of this type down a bit, especially when used in arrays.
#[derive(PartialEq, Debug, Clone, Default)]
pub enum Variant {
    /// Empty type has no value. It is equivalent to a Null value (part 6 5.1.6)
    #[default]
    Empty,
    /// Boolean
    Boolean(bool),
    /// Signed byte
    SByte(i8),
    /// Unsigned byte
    Byte(u8),
    /// Signed 16-bit int
    Int16(i16),
    /// Unsigned 16-bit int
    UInt16(u16),
    /// Signed 32-bit int
    Int32(i32),
    /// Unsigned 32-bit int
    UInt32(u32),
    /// Signed 64-bit int
    Int64(i64),
    /// Unsigned 64-bit int
    UInt64(u64),
    /// Float
    Float(f32),
    /// Double
    Double(f64),
    /// String
    String(UAString),
    /// DateTime
    DateTime(Box<DateTime>),
    /// Guid
    Guid(Box<Guid>),
    /// StatusCode
    StatusCode(StatusCode),
    /// ByteString
    ByteString(ByteString),
    /// XmlElement
    XmlElement(XmlElement),
    /// QualifiedName
    QualifiedName(Box<QualifiedName>),
    /// LocalizedText
    LocalizedText(Box<LocalizedText>),
    /// NodeId
    NodeId(Box<NodeId>),
    /// ExpandedNodeId
    ExpandedNodeId(Box<ExpandedNodeId>),
    /// ExtensionObject
    ExtensionObject(ExtensionObject),
    /// Variant containing a nested variant.
    Variant(Box<Variant>),
    /// DataValue
    DataValue(Box<DataValue>),
    /// DiagnosticInfo
    DiagnosticInfo(Box<DiagnosticInfo>),
    /// Single dimension array which can contain any scalar type, all the same type. Nested
    /// arrays will be rejected.
    /// To represent matrices or nested arrays, set the `array_dimensions` field
    /// on the `Array`.
    Array(Box<Array>),
}

/// Trait for types that can be represented by a variant.
/// Note that the VariantTypeId returned by `variant_type_id`
/// _must_ be the variant type ID of the variant returned by the corresponding
/// `From` trait implementation!
pub trait VariantType {
    /// The variant kind this type will be represented as.
    fn variant_type_id() -> VariantScalarTypeId;
}

// Any type that implements DynEncodable is encoded as an extension object.
impl<T> VariantType for T
where
    T: DynEncodable,
{
    fn variant_type_id() -> VariantScalarTypeId {
        VariantScalarTypeId::ExtensionObject
    }
}

macro_rules! impl_variant_type_for {
    ($tp: ty, $vt: expr) => {
        impl VariantType for $tp {
            fn variant_type_id() -> VariantScalarTypeId {
                $vt
            }
        }
    };
}
impl_variant_type_for!(bool, VariantScalarTypeId::Boolean);
impl_variant_type_for!(i8, VariantScalarTypeId::SByte);
impl_variant_type_for!(u8, VariantScalarTypeId::Byte);
impl_variant_type_for!(i16, VariantScalarTypeId::Int16);
impl_variant_type_for!(u16, VariantScalarTypeId::UInt16);
impl_variant_type_for!(i32, VariantScalarTypeId::Int32);
impl_variant_type_for!(u32, VariantScalarTypeId::UInt32);
impl_variant_type_for!(i64, VariantScalarTypeId::Int64);
impl_variant_type_for!(u64, VariantScalarTypeId::UInt64);
impl_variant_type_for!(f32, VariantScalarTypeId::Float);
impl_variant_type_for!(f64, VariantScalarTypeId::Double);
impl_variant_type_for!(UAString, VariantScalarTypeId::String);
impl_variant_type_for!(String, VariantScalarTypeId::String);
impl_variant_type_for!(&str, VariantScalarTypeId::String);
impl_variant_type_for!(DateTime, VariantScalarTypeId::DateTime);
impl_variant_type_for!(Guid, VariantScalarTypeId::Guid);
impl_variant_type_for!(StatusCode, VariantScalarTypeId::StatusCode);
impl_variant_type_for!(ByteString, VariantScalarTypeId::ByteString);
impl_variant_type_for!(XmlElement, VariantScalarTypeId::XmlElement);
impl_variant_type_for!(QualifiedName, VariantScalarTypeId::QualifiedName);
impl_variant_type_for!(LocalizedText, VariantScalarTypeId::LocalizedText);
impl_variant_type_for!(NodeId, VariantScalarTypeId::NodeId);
impl_variant_type_for!(ExpandedNodeId, VariantScalarTypeId::ExpandedNodeId);
impl_variant_type_for!(ExtensionObject, VariantScalarTypeId::ExtensionObject);
impl_variant_type_for!(Variant, VariantScalarTypeId::Variant);
impl_variant_type_for!(DataValue, VariantScalarTypeId::DataValue);
impl_variant_type_for!(DiagnosticInfo, VariantScalarTypeId::DiagnosticInfo);
impl_variant_type_for!(chrono::DateTime<chrono::Utc>, VariantScalarTypeId::DateTime);
impl_variant_type_for!(Uuid, VariantScalarTypeId::Guid);

macro_rules! cast_to_bool {
    ($value: expr) => {
        if $value == 1 {
            true.into()
        } else if $value == 0 {
            false.into()
        } else {
            Variant::Empty
        }
    };
}

macro_rules! cast_to_integer {
    ($value: expr, $from: ident, $to: ident) => {
        {
            // 64-bit values are the highest supported by OPC UA, so this code will cast
            // and compare values using signed / unsigned types to determine if they're in range.
            let valid = if $value < 0 as $from {
                // Negative values can only go into a signed type and only when the value is greater
                // or equal to the MIN
                $to::MIN != 0 && $value as i64 >= $to::MIN as i64
            } else {
                // Positive values can only go into the type only when the value is less than or equal
                // to the MAX.
                $value as u64 <= $to::MAX as u64
            };
            if !valid {
                // Value is out of range
                // error!("Value {} is outside of the range of receiving in type {}..{}", $value, $to::MIN, $to::MAX);
                Variant::Empty
            } else {
                ($value as $to).into()
            }
        }
    }
}

impl Variant {
    /// Get the value in bytes of the _contents_ of this variant
    /// if it is serialize to OPC-UA binary.
    ///
    /// To get the full byte length including type ID, use
    /// [`BinaryEncodable::encode`]
    pub fn value_byte_len(&self, ctx: &crate::Context<'_>) -> usize {
        match self {
            Variant::Empty => 0,
            Variant::Boolean(value) => value.byte_len(ctx),
            Variant::SByte(value) => value.byte_len(ctx),
            Variant::Byte(value) => value.byte_len(ctx),
            Variant::Int16(value) => value.byte_len(ctx),
            Variant::UInt16(value) => value.byte_len(ctx),
            Variant::Int32(value) => value.byte_len(ctx),
            Variant::UInt32(value) => value.byte_len(ctx),
            Variant::Int64(value) => value.byte_len(ctx),
            Variant::UInt64(value) => value.byte_len(ctx),
            Variant::Float(value) => value.byte_len(ctx),
            Variant::Double(value) => value.byte_len(ctx),
            Variant::String(value) => value.byte_len(ctx),
            Variant::DateTime(value) => value.byte_len(ctx),
            Variant::Guid(value) => value.byte_len(ctx),
            Variant::ByteString(value) => value.byte_len(ctx),
            Variant::XmlElement(value) => value.byte_len(ctx),
            Variant::NodeId(value) => value.byte_len(ctx),
            Variant::ExpandedNodeId(value) => value.byte_len(ctx),
            Variant::StatusCode(value) => value.byte_len(ctx),
            Variant::QualifiedName(value) => value.byte_len(ctx),
            Variant::LocalizedText(value) => value.byte_len(ctx),
            Variant::ExtensionObject(value) => value.byte_len(ctx),
            Variant::DataValue(value) => value.byte_len(ctx),
            Variant::Variant(value) => value.byte_len(ctx),
            Variant::DiagnosticInfo(value) => value.byte_len(ctx),
            Variant::Array(array) => {
                // Array length
                let mut size = 4;
                // Size of each value
                size += array
                    .values
                    .iter()
                    .map(|v| Variant::byte_len_variant_value(v, ctx))
                    .sum::<usize>();
                if let Some(ref dimensions) = array.dimensions {
                    // Dimensions (size + num elements)
                    size += 4 + dimensions.len() * 4;
                }
                size
            }
        }
    }

    /// Encode the _value_ of this variant as binary to the given `stream`.
    ///
    /// Note that to encode a full variant with type ID and other details,
    /// use [`BinaryEncodable::encode`]
    pub fn encode_value<S: Write + ?Sized>(
        &self,
        stream: &mut S,
        ctx: &crate::Context<'_>,
    ) -> EncodingResult<()> {
        match self {
            Variant::Empty => Ok(()),
            Variant::Boolean(value) => value.encode(stream, ctx),
            Variant::SByte(value) => value.encode(stream, ctx),
            Variant::Byte(value) => value.encode(stream, ctx),
            Variant::Int16(value) => value.encode(stream, ctx),
            Variant::UInt16(value) => value.encode(stream, ctx),
            Variant::Int32(value) => value.encode(stream, ctx),
            Variant::UInt32(value) => value.encode(stream, ctx),
            Variant::Int64(value) => value.encode(stream, ctx),
            Variant::UInt64(value) => value.encode(stream, ctx),
            Variant::Float(value) => value.encode(stream, ctx),
            Variant::Double(value) => value.encode(stream, ctx),
            Variant::String(value) => value.encode(stream, ctx),
            Variant::DateTime(value) => value.encode(stream, ctx),
            Variant::Guid(value) => value.encode(stream, ctx),
            Variant::ByteString(value) => value.encode(stream, ctx),
            Variant::XmlElement(value) => value.encode(stream, ctx),
            Variant::NodeId(value) => value.encode(stream, ctx),
            Variant::ExpandedNodeId(value) => value.encode(stream, ctx),
            Variant::StatusCode(value) => value.encode(stream, ctx),
            Variant::QualifiedName(value) => value.encode(stream, ctx),
            Variant::LocalizedText(value) => value.encode(stream, ctx),
            Variant::ExtensionObject(value) => value.encode(stream, ctx),
            Variant::DataValue(value) => value.encode(stream, ctx),
            Variant::Variant(value) => value.encode(stream, ctx),
            Variant::DiagnosticInfo(value) => value.encode(stream, ctx),
            Variant::Array(array) => {
                write_i32(stream, array.values.len() as i32)?;
                for value in array.values.iter() {
                    Variant::encode_variant_value(stream, value, ctx)?;
                }
                if let Some(ref dimensions) = array.dimensions {
                    // Note array dimensions are encoded as Int32 even though they are presented
                    // as UInt32 through attribute.

                    // Encode dimensions length
                    write_i32(stream, dimensions.len() as i32)?;
                    // Encode dimensions
                    for dimension in dimensions {
                        write_i32(stream, *dimension as i32)?;
                    }
                }
                Ok(())
            }
        }
    }
}

impl UaNullable for Variant {
    fn is_ua_null(&self) -> bool {
        self.is_empty()
    }
}

impl BinaryEncodable for Variant {
    fn byte_len(&self, ctx: &crate::Context<'_>) -> usize {
        let mut size: usize = 0;

        // Encoding mask
        size += 1;

        // Value itself
        size += self.value_byte_len(ctx);

        size
    }

    fn encode<S: Write + ?Sized>(
        &self,
        stream: &mut S,
        ctx: &crate::Context<'_>,
    ) -> EncodingResult<()> {
        // Encoding mask will include the array bits if applicable for the type
        let encoding_mask = self.encoding_mask();
        write_u8(stream, encoding_mask)?;

        self.encode_value(stream, ctx)
    }
}

impl BinaryDecodable for Variant {
    fn decode<S: Read + ?Sized>(stream: &mut S, ctx: &crate::Context<'_>) -> EncodingResult<Self> {
        let encoding_mask = u8::decode(stream, ctx)?;
        let element_encoding_mask = encoding_mask & !EncodingMask::ARRAY_MASK;

        // IMPORTANT NOTE: Arrays are constructed through Array::new_multi or Array::new_single
        // to correctly process failures. Don't use Variant::from((value_type, values)) since
        // this will panic & break the runtime. We don't want this when dealing with potentially
        // malicious data.

        // Read array length
        let array_length = if encoding_mask & EncodingMask::ARRAY_VALUES_BIT != 0 {
            let array_length = i32::decode(stream, ctx)?;
            if array_length < -1 {
                return Err(Error::decoding(format!(
                    "Invalid array_length {}",
                    array_length
                )));
            }

            // null array of type for length 0 and -1 so it doesn't fail for length 0
            if array_length <= 0 {
                let value_type_id = VariantScalarTypeId::from_encoding_mask(element_encoding_mask)
                    .ok_or_else(|| {
                        Error::decoding(format!(
                            "Unrecognized encoding mask: {element_encoding_mask}"
                        ))
                    })?;
                return Array::new_multi(value_type_id, Vec::new(), Vec::new())
                    .map(Variant::from)
                    .map_err(Error::decoding);
            }
            array_length
        } else {
            -1
        };

        // Read the value(s). If array length was specified, we assume a single or multi dimension array
        if array_length > 0 {
            // Array length in total cannot exceed max array length
            let array_length = array_length as usize;
            if array_length > ctx.options().max_array_length {
                return Err(Error::new(StatusCode::BadEncodingLimitsExceeded, format!(
                    "Variant array has length {} which exceeds configured array length limit {}", array_length, ctx.options().max_array_length
                )));
            }

            let mut values: Vec<Variant> = Vec::with_capacity(array_length);
            for _ in 0..array_length {
                values.push(Variant::decode_variant_value(
                    stream,
                    element_encoding_mask,
                    ctx,
                )?);
            }
            let value_type_id = VariantScalarTypeId::from_encoding_mask(element_encoding_mask)
                .ok_or_else(|| {
                    Error::decoding(format!(
                        "Unrecognized encoding mask: {element_encoding_mask}"
                    ))
                })?;
            if encoding_mask & EncodingMask::ARRAY_DIMENSIONS_BIT != 0 {
                if let Some(dimensions) = <Option<Vec<_>>>::decode(stream, ctx)? {
                    if dimensions.iter().any(|d| *d == 0) {
                        Err(Error::decoding(
                            "Invalid variant array dimensions, one or more dimensions are 0",
                        ))
                    } else {
                        // This looks clunky but it's to prevent a panic from malicious data
                        // causing an overflow panic
                        let mut array_dimensions_length = 1u32;
                        for d in &dimensions {
                            if let Some(v) = array_dimensions_length.checked_mul(*d) {
                                array_dimensions_length = v;
                            } else {
                                return Err(Error::decoding("Array dimension overflow"));
                            }
                        }
                        if array_dimensions_length != array_length as u32 {
                            Err(Error::decoding(format!(
                                "Array dimensions does not match array length {}",
                                array_length
                            )))
                        } else {
                            // Note Array::new_multi can fail
                            Ok(Array::new_multi(value_type_id, values, dimensions)
                                .map(Variant::from)
                                .map_err(Error::decoding)?)
                        }
                    }
                } else {
                    Err(Error::decoding(
                        "No array dimensions despite the bit flag being set",
                    ))
                }
            } else {
                // Note Array::new_single can fail
                Ok(Array::new(value_type_id, values)
                    .map(Variant::from)
                    .map_err(Error::decoding)?)
            }
        } else if encoding_mask & EncodingMask::ARRAY_DIMENSIONS_BIT != 0 {
            Err(Error::decoding(
                "Array dimensions bit specified without any values",
            ))
        } else {
            // Read a single variant
            Variant::decode_variant_value(stream, element_encoding_mask, ctx)
        }
    }
}

/// This implementation is mainly for debugging / convenience purposes, to eliminate some of the
/// noise in common types from using the Debug trait.
impl fmt::Display for Variant {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Variant::SByte(v) => write!(f, "{}", v),
            Variant::Byte(v) => write!(f, "{}", v),
            Variant::Int16(v) => write!(f, "{}", v),
            Variant::UInt16(v) => write!(f, "{}", v),
            Variant::Int32(v) => write!(f, "{}", v),
            Variant::UInt32(v) => write!(f, "{}", v),
            Variant::Int64(v) => write!(f, "{}", v),
            Variant::UInt64(v) => write!(f, "{}", v),
            Variant::Float(v) => write!(f, "{}", v),
            Variant::Double(v) => write!(f, "{}", v),
            Variant::Boolean(v) => write!(f, "{}", v),
            Variant::String(ref v) => write!(f, "{}", v),
            Variant::Guid(ref v) => write!(f, "{}", v),
            Variant::DateTime(ref v) => write!(f, "{}", v),
            Variant::NodeId(ref v) => write!(f, "{}", v),
            Variant::ExpandedNodeId(ref v) => write!(f, "{}", v),
            Variant::Variant(ref v) => write!(f, "Variant({})", v),
            value => write!(f, "{:?}", value),
        }
    }
}

impl Variant {
    /// Test the flag (convenience method)
    pub fn test_encoding_flag(encoding_mask: u8, flag: u8) -> bool {
        encoding_mask == flag
    }

    /// Returns the length of just the value, not the encoding flag
    fn byte_len_variant_value(value: &Variant, ctx: &crate::Context<'_>) -> usize {
        match value {
            Variant::Empty => 0,
            Variant::Boolean(value) => value.byte_len(ctx),
            Variant::SByte(value) => value.byte_len(ctx),
            Variant::Byte(value) => value.byte_len(ctx),
            Variant::Int16(value) => value.byte_len(ctx),
            Variant::UInt16(value) => value.byte_len(ctx),
            Variant::Int32(value) => value.byte_len(ctx),
            Variant::UInt32(value) => value.byte_len(ctx),
            Variant::Int64(value) => value.byte_len(ctx),
            Variant::UInt64(value) => value.byte_len(ctx),
            Variant::Float(value) => value.byte_len(ctx),
            Variant::Double(value) => value.byte_len(ctx),
            Variant::String(value) => value.byte_len(ctx),
            Variant::DateTime(value) => value.byte_len(ctx),
            Variant::Guid(value) => value.byte_len(ctx),
            Variant::ByteString(value) => value.byte_len(ctx),
            Variant::XmlElement(value) => value.byte_len(ctx),
            Variant::NodeId(value) => value.byte_len(ctx),
            Variant::ExpandedNodeId(value) => value.byte_len(ctx),
            Variant::StatusCode(value) => value.byte_len(ctx),
            Variant::QualifiedName(value) => value.byte_len(ctx),
            Variant::LocalizedText(value) => value.byte_len(ctx),
            Variant::ExtensionObject(value) => value.byte_len(ctx),
            Variant::Variant(value) => value.byte_len(ctx),
            Variant::DataValue(value) => value.byte_len(ctx),
            Variant::DiagnosticInfo(value) => value.byte_len(ctx),
            _ => {
                error!("Cannot compute length of this type (probably nested array)");
                0
            }
        }
    }

    /// Encodes just the value, not the encoding flag
    fn encode_variant_value<S: Write + ?Sized>(
        stream: &mut S,
        value: &Variant,
        ctx: &crate::Context<'_>,
    ) -> EncodingResult<()> {
        match value {
            Variant::Empty => Ok(()),
            Variant::Boolean(value) => value.encode(stream, ctx),
            Variant::SByte(value) => value.encode(stream, ctx),
            Variant::Byte(value) => value.encode(stream, ctx),
            Variant::Int16(value) => value.encode(stream, ctx),
            Variant::UInt16(value) => value.encode(stream, ctx),
            Variant::Int32(value) => value.encode(stream, ctx),
            Variant::UInt32(value) => value.encode(stream, ctx),
            Variant::Int64(value) => value.encode(stream, ctx),
            Variant::UInt64(value) => value.encode(stream, ctx),
            Variant::Float(value) => value.encode(stream, ctx),
            Variant::Double(value) => value.encode(stream, ctx),
            Variant::String(value) => value.encode(stream, ctx),
            Variant::DateTime(value) => value.encode(stream, ctx),
            Variant::Guid(value) => value.encode(stream, ctx),
            Variant::ByteString(value) => value.encode(stream, ctx),
            Variant::XmlElement(value) => value.encode(stream, ctx),
            Variant::NodeId(value) => value.encode(stream, ctx),
            Variant::ExpandedNodeId(value) => value.encode(stream, ctx),
            Variant::StatusCode(value) => value.encode(stream, ctx),
            Variant::QualifiedName(value) => value.encode(stream, ctx),
            Variant::LocalizedText(value) => value.encode(stream, ctx),
            Variant::ExtensionObject(value) => value.encode(stream, ctx),
            Variant::Variant(value) => value.encode(stream, ctx),
            Variant::DataValue(value) => value.encode(stream, ctx),
            Variant::DiagnosticInfo(value) => value.encode(stream, ctx),
            _ => Err(Error::encoding(
                "Cannot encode this variant value type (probably nested array)",
            )),
        }
    }

    /// Reads just the variant value from the stream
    fn decode_variant_value<S: Read + ?Sized>(
        stream: &mut S,
        encoding_mask: u8,
        ctx: &crate::Context<'_>,
    ) -> EncodingResult<Self> {
        let result = if encoding_mask == 0 {
            Variant::Empty
        } else if Self::test_encoding_flag(encoding_mask, EncodingMask::BOOLEAN) {
            Self::from(bool::decode(stream, ctx)?)
        } else if Self::test_encoding_flag(encoding_mask, EncodingMask::SBYTE) {
            Self::from(i8::decode(stream, ctx)?)
        } else if Self::test_encoding_flag(encoding_mask, EncodingMask::BYTE) {
            Self::from(u8::decode(stream, ctx)?)
        } else if Self::test_encoding_flag(encoding_mask, EncodingMask::INT16) {
            Self::from(i16::decode(stream, ctx)?)
        } else if Self::test_encoding_flag(encoding_mask, EncodingMask::UINT16) {
            Self::from(u16::decode(stream, ctx)?)
        } else if Self::test_encoding_flag(encoding_mask, EncodingMask::INT32) {
            Self::from(i32::decode(stream, ctx)?)
        } else if Self::test_encoding_flag(encoding_mask, EncodingMask::UINT32) {
            Self::from(u32::decode(stream, ctx)?)
        } else if Self::test_encoding_flag(encoding_mask, EncodingMask::INT64) {
            Self::from(i64::decode(stream, ctx)?)
        } else if Self::test_encoding_flag(encoding_mask, EncodingMask::UINT64) {
            Self::from(u64::decode(stream, ctx)?)
        } else if Self::test_encoding_flag(encoding_mask, EncodingMask::FLOAT) {
            Self::from(f32::decode(stream, ctx)?)
        } else if Self::test_encoding_flag(encoding_mask, EncodingMask::DOUBLE) {
            Self::from(f64::decode(stream, ctx)?)
        } else if Self::test_encoding_flag(encoding_mask, EncodingMask::STRING) {
            Self::from(UAString::decode(stream, ctx)?)
        } else if Self::test_encoding_flag(encoding_mask, EncodingMask::DATE_TIME) {
            Self::from(DateTime::decode(stream, ctx)?)
        } else if Self::test_encoding_flag(encoding_mask, EncodingMask::GUID) {
            Self::from(Guid::decode(stream, ctx)?)
        } else if Self::test_encoding_flag(encoding_mask, EncodingMask::BYTE_STRING) {
            Self::from(ByteString::decode(stream, ctx)?)
        } else if Self::test_encoding_flag(encoding_mask, EncodingMask::XML_ELEMENT) {
            // Force the type to be XmlElement since its typedef'd to UAString
            Variant::XmlElement(XmlElement::decode(stream, ctx)?)
        } else if Self::test_encoding_flag(encoding_mask, EncodingMask::NODE_ID) {
            Self::from(NodeId::decode(stream, ctx)?)
        } else if Self::test_encoding_flag(encoding_mask, EncodingMask::EXPANDED_NODE_ID) {
            Self::from(ExpandedNodeId::decode(stream, ctx)?)
        } else if Self::test_encoding_flag(encoding_mask, EncodingMask::STATUS_CODE) {
            Self::from(StatusCode::decode(stream, ctx)?)
        } else if Self::test_encoding_flag(encoding_mask, EncodingMask::QUALIFIED_NAME) {
            Self::from(QualifiedName::decode(stream, ctx)?)
        } else if Self::test_encoding_flag(encoding_mask, EncodingMask::LOCALIZED_TEXT) {
            Self::from(LocalizedText::decode(stream, ctx)?)
        } else if Self::test_encoding_flag(encoding_mask, EncodingMask::EXTENSION_OBJECT) {
            // Extension object internally does depth checking to prevent deep recursion
            Self::from(ExtensionObject::decode(stream, ctx)?)
        } else if Self::test_encoding_flag(encoding_mask, EncodingMask::VARIANT) {
            // Nested variant is depth checked to prevent deep recursion
            let _depth_lock = ctx.options().depth_lock()?;
            Variant::Variant(Box::new(Variant::decode(stream, ctx)?))
        } else if Self::test_encoding_flag(encoding_mask, EncodingMask::DATA_VALUE) {
            Self::from(DataValue::decode(stream, ctx)?)
        } else if Self::test_encoding_flag(encoding_mask, EncodingMask::DIAGNOSTIC_INFO) {
            Self::from(DiagnosticInfo::decode(stream, ctx)?)
        } else {
            Variant::Empty
        };
        Ok(result)
    }

    fn cast_scalar(&self, target_type: VariantScalarTypeId) -> Variant {
        match *self {
            Variant::Boolean(v) => match target_type {
                VariantScalarTypeId::Byte => Variant::Byte(u8::from(v)),
                VariantScalarTypeId::SByte => Variant::SByte(i8::from(v)),
                VariantScalarTypeId::Float => Variant::Float(f32::from(v)),
                VariantScalarTypeId::Int16 => Variant::Int16(i16::from(v)),
                VariantScalarTypeId::Int32 => Variant::Int32(i32::from(v)),
                VariantScalarTypeId::Int64 => Variant::Int64(i64::from(v)),
                VariantScalarTypeId::UInt16 => Variant::UInt16(u16::from(v)),
                VariantScalarTypeId::UInt32 => Variant::UInt32(u32::from(v)),
                VariantScalarTypeId::UInt64 => Variant::UInt64(u64::from(v)),
                VariantScalarTypeId::Double => Variant::Double(f64::from(v)),
                VariantScalarTypeId::String => {
                    UAString::from(if v { "true" } else { "false" }).into()
                }
                _ => Variant::Empty,
            },
            Variant::Byte(v) => match target_type {
                VariantScalarTypeId::Boolean => cast_to_bool!(v),
                VariantScalarTypeId::String => format!("{}", v).into(),
                _ => Variant::Empty,
            },
            Variant::Double(v) => {
                // Truncated value used in integer conversions
                let vt = f64::trunc(v + 0.5);
                match target_type {
                    VariantScalarTypeId::Boolean => cast_to_bool!(v as i64),
                    VariantScalarTypeId::Byte => cast_to_integer!(vt, f64, u8),
                    VariantScalarTypeId::Float => (v as f32).into(),
                    VariantScalarTypeId::Int16 => cast_to_integer!(vt, f64, i16),
                    VariantScalarTypeId::Int32 => cast_to_integer!(vt, f64, i32),
                    VariantScalarTypeId::Int64 => cast_to_integer!(vt, f64, i64),
                    VariantScalarTypeId::SByte => cast_to_integer!(vt, f64, i8),
                    VariantScalarTypeId::String => format!("{}", v).into(),
                    VariantScalarTypeId::UInt16 => cast_to_integer!(vt, f64, u16),
                    VariantScalarTypeId::UInt32 => cast_to_integer!(vt, f64, u32),
                    VariantScalarTypeId::UInt64 => cast_to_integer!(vt, f64, u64),
                    _ => Variant::Empty,
                }
            }
            Variant::ByteString(ref v) => match target_type {
                VariantScalarTypeId::Guid => Guid::try_from(v)
                    .map(|v| v.into())
                    .unwrap_or(Variant::Empty),
                _ => Variant::Empty,
            },
            Variant::DateTime(ref v) => match target_type {
                VariantScalarTypeId::String => format!("{}", *v).into(),
                _ => Variant::Empty,
            },
            Variant::ExpandedNodeId(ref v) => match target_type {
                VariantScalarTypeId::NodeId => v.node_id.clone().into(),
                _ => Variant::Empty,
            },
            Variant::Float(v) => {
                let vt = f32::trunc(v + 0.5);
                match target_type {
                    VariantScalarTypeId::Boolean => cast_to_bool!(v as i64),
                    VariantScalarTypeId::Byte => cast_to_integer!(vt, f32, u8),
                    VariantScalarTypeId::Int16 => cast_to_integer!(vt, f32, i16),
                    VariantScalarTypeId::Int32 => cast_to_integer!(vt, f32, i32),
                    VariantScalarTypeId::Int64 => cast_to_integer!(vt, f32, i64),
                    VariantScalarTypeId::SByte => cast_to_integer!(vt, f32, i8),
                    VariantScalarTypeId::String => format!("{}", v).into(),
                    VariantScalarTypeId::UInt16 => cast_to_integer!(vt, f32, u16),
                    VariantScalarTypeId::UInt32 => cast_to_integer!(vt, f32, u32),
                    VariantScalarTypeId::UInt64 => cast_to_integer!(vt, f32, u64),
                    _ => Variant::Empty,
                }
            }
            Variant::Guid(ref v) => match target_type {
                VariantScalarTypeId::String => format!("{}", *v).into(),
                VariantScalarTypeId::ByteString => ByteString::from(v.as_ref().clone()).into(),
                _ => Variant::Empty,
            },
            Variant::Int16(v) => match target_type {
                VariantScalarTypeId::Boolean => cast_to_bool!(v),
                VariantScalarTypeId::Byte => cast_to_integer!(v, i16, u8),
                VariantScalarTypeId::SByte => cast_to_integer!(v, i16, i8),
                VariantScalarTypeId::String => format!("{}", v).into(),
                VariantScalarTypeId::UInt16 => cast_to_integer!(v, i16, u16),
                _ => Variant::Empty,
            },
            Variant::Int32(v) => match target_type {
                VariantScalarTypeId::Boolean => cast_to_bool!(v),
                VariantScalarTypeId::Byte => cast_to_integer!(v, i32, u8),
                VariantScalarTypeId::Int16 => cast_to_integer!(v, i32, i16),
                VariantScalarTypeId::SByte => cast_to_integer!(v, i32, i8),
                VariantScalarTypeId::StatusCode => (StatusCode::from(v as u32)).into(),
                VariantScalarTypeId::String => format!("{}", v).into(),
                VariantScalarTypeId::UInt16 => cast_to_integer!(v, i32, u16),
                VariantScalarTypeId::UInt32 => cast_to_integer!(v, i32, u32),
                _ => Variant::Empty,
            },
            Variant::Int64(v) => match target_type {
                VariantScalarTypeId::Boolean => cast_to_bool!(v),
                VariantScalarTypeId::Byte => cast_to_integer!(v, i64, u8),
                VariantScalarTypeId::Int16 => cast_to_integer!(v, i64, i16),
                VariantScalarTypeId::Int32 => cast_to_integer!(v, i64, i32),
                VariantScalarTypeId::SByte => cast_to_integer!(v, i64, i8),
                VariantScalarTypeId::StatusCode => StatusCode::from(v as u32).into(),
                VariantScalarTypeId::String => format!("{}", v).into(),
                VariantScalarTypeId::UInt16 => cast_to_integer!(v, i64, u16),
                VariantScalarTypeId::UInt32 => cast_to_integer!(v, i64, u32),
                VariantScalarTypeId::UInt64 => cast_to_integer!(v, i64, u64),
                _ => Variant::Empty,
            },
            Variant::SByte(v) => match target_type {
                VariantScalarTypeId::Boolean => cast_to_bool!(v),
                VariantScalarTypeId::Byte => cast_to_integer!(v, i8, u8),
                VariantScalarTypeId::String => format!("{}", v).into(),
                _ => Variant::Empty,
            },
            Variant::StatusCode(v) => match target_type {
                VariantScalarTypeId::UInt16 => (((v.bits() & 0xffff_0000) >> 16) as u16).into(),
                _ => Variant::Empty,
            },
            Variant::String(ref v) => match target_type {
                VariantScalarTypeId::NodeId => {
                    if v.is_null() {
                        Variant::Empty
                    } else {
                        NodeId::from_str(v.as_ref())
                            .map(|v| v.into())
                            .unwrap_or(Variant::Empty)
                    }
                }
                VariantScalarTypeId::ExpandedNodeId => {
                    if v.is_null() {
                        Variant::Empty
                    } else {
                        ExpandedNodeId::from_str(v.as_ref())
                            .map(|v| v.into())
                            .unwrap_or(Variant::Empty)
                    }
                }
                VariantScalarTypeId::DateTime => {
                    if v.is_null() {
                        Variant::Empty
                    } else {
                        DateTime::from_str(v.as_ref())
                            .map(|v| v.into())
                            .unwrap_or(Variant::Empty)
                    }
                }
                VariantScalarTypeId::LocalizedText => {
                    if v.is_null() {
                        LocalizedText::null().into()
                    } else {
                        LocalizedText::new("", v.as_ref()).into()
                    }
                }
                VariantScalarTypeId::QualifiedName => {
                    if v.is_null() {
                        QualifiedName::null().into()
                    } else {
                        QualifiedName::new(0, v.as_ref()).into()
                    }
                }
                _ => Variant::Empty,
            },
            Variant::UInt16(v) => match target_type {
                VariantScalarTypeId::Boolean => cast_to_bool!(v),
                VariantScalarTypeId::Byte => cast_to_integer!(v, u16, u8),
                VariantScalarTypeId::SByte => cast_to_integer!(v, u16, i8),
                VariantScalarTypeId::String => format!("{}", v).into(),
                _ => Variant::Empty,
            },
            Variant::UInt32(v) => match target_type {
                VariantScalarTypeId::Boolean => cast_to_bool!(v),
                VariantScalarTypeId::Byte => cast_to_integer!(v, u32, u8),
                VariantScalarTypeId::Int16 => cast_to_integer!(v, u32, i16),
                VariantScalarTypeId::SByte => cast_to_integer!(v, u32, i8),
                VariantScalarTypeId::StatusCode => StatusCode::from(v).into(),
                VariantScalarTypeId::String => format!("{}", v).into(),
                VariantScalarTypeId::UInt16 => cast_to_integer!(v, u32, u16),
                _ => Variant::Empty,
            },
            Variant::UInt64(v) => match target_type {
                VariantScalarTypeId::Boolean => cast_to_bool!(v),
                VariantScalarTypeId::Byte => cast_to_integer!(v, u64, u8),
                VariantScalarTypeId::Int16 => cast_to_integer!(v, u64, i16),
                VariantScalarTypeId::SByte => cast_to_integer!(v, u64, i8),
                VariantScalarTypeId::StatusCode => {
                    StatusCode::from((v & 0x0000_0000_ffff_ffff) as u32).into()
                }
                VariantScalarTypeId::String => format!("{}", v).into(),
                VariantScalarTypeId::UInt16 => cast_to_integer!(v, u64, u16),
                VariantScalarTypeId::UInt32 => cast_to_integer!(v, u64, u32),
                _ => Variant::Empty,
            },

            // NodeId, LocalizedText, QualifiedName, XmlElement have no explicit cast
            _ => Variant::Empty,
        }
    }

    fn cast_array(&self, target_type: VariantScalarTypeId, dims: Option<&[u32]>) -> Variant {
        match self {
            Variant::Array(a) => {
                // Check if the total length is compatible.
                if let Some(dim) = dims {
                    let len: usize = dim
                        .iter()
                        .map(|v| *v as usize)
                        .reduce(|l, r| l * r)
                        .unwrap_or(0);
                    if len != a.values.len() {
                        return Variant::Empty;
                    }
                }

                let mut res = Vec::with_capacity(a.values.len());
                for v in a.values.iter() {
                    let conv = v.cast(target_type);
                    if matches!(conv, Variant::Empty) {
                        return Variant::Empty;
                    }
                    res.push(conv);
                }

                Variant::Array(Box::new(Array {
                    value_type: target_type,
                    values: res,
                    dimensions: dims.map(|d| d.to_vec()).or_else(|| a.dimensions.clone()),
                }))
            }
            scalar => {
                if let Some(dims) = dims {
                    if dims.len() != 1 || dims[0] != 1 {
                        return Variant::Empty;
                    }
                }
                let converted = scalar.cast(target_type);
                if matches!(converted, Variant::Empty) {
                    return converted;
                }
                Self::Array(Box::new(Array {
                    value_type: target_type,
                    values: vec![converted],
                    dimensions: dims.map(|d| d.to_vec()),
                }))
            }
        }
    }

    /// Performs an EXPLICIT cast from one type to another. This will first attempt an implicit
    /// conversion and only then attempt to cast. Casting is potentially lossy.
    pub fn cast<'a>(&self, target_type: impl Into<VariantTypeId<'a>>) -> Variant {
        let target_type: VariantTypeId = target_type.into();
        let self_type = self.type_id();
        if self_type == target_type {
            return self.clone();
        }

        let result = self.convert(target_type);
        if !matches!(result, Variant::Empty) {
            return result;
        }

        match target_type {
            VariantTypeId::Empty => Variant::Empty,
            VariantTypeId::Scalar(s) => self.cast_scalar(s),
            VariantTypeId::Array(s, d) => self.cast_array(s, d),
        }
    }

    fn convert_scalar(&self, target_type: VariantScalarTypeId) -> Variant {
        // See OPC UA Part 4 table 118
        match *self {
            Variant::Boolean(v) => {
                // true == 1, false == 0
                match target_type {
                    VariantScalarTypeId::Byte => (v as u8).into(),
                    VariantScalarTypeId::Double => ((v as u8) as f64).into(),
                    VariantScalarTypeId::Float => ((v as u8) as f32).into(),
                    VariantScalarTypeId::Int16 => (v as i16).into(),
                    VariantScalarTypeId::Int32 => (v as i32).into(),
                    VariantScalarTypeId::Int64 => (v as i64).into(),
                    VariantScalarTypeId::SByte => (v as i8).into(),
                    VariantScalarTypeId::UInt16 => (v as u16).into(),
                    VariantScalarTypeId::UInt32 => (v as u32).into(),
                    VariantScalarTypeId::UInt64 => (v as u64).into(),
                    _ => Variant::Empty,
                }
            }
            Variant::Byte(v) => match target_type {
                VariantScalarTypeId::Double => (v as f64).into(),
                VariantScalarTypeId::Float => (v as f32).into(),
                VariantScalarTypeId::Int16 => (v as i16).into(),
                VariantScalarTypeId::Int32 => (v as i32).into(),
                VariantScalarTypeId::Int64 => (v as i64).into(),
                VariantScalarTypeId::SByte => (v as i8).into(),
                VariantScalarTypeId::UInt16 => (v as u16).into(),
                VariantScalarTypeId::UInt32 => (v as u32).into(),
                VariantScalarTypeId::UInt64 => (v as u64).into(),
                _ => Variant::Empty,
            },

            // ByteString - everything is X or E except to itself
            // DateTime - everything is X or E except to itself
            // Double - everything is X or E except to itself
            Variant::ExpandedNodeId(ref v) => {
                // Everything is X or E except to String
                match target_type {
                    VariantScalarTypeId::String => format!("{}", v).into(),
                    _ => Variant::Empty,
                }
            }
            Variant::Float(v) => {
                // Everything is X or E except to Double
                match target_type {
                    VariantScalarTypeId::Double => (v as f64).into(),
                    _ => Variant::Empty,
                }
            }

            // Guid - everything is X or E except to itself
            Variant::Int16(v) => match target_type {
                VariantScalarTypeId::Double => (v as f64).into(),
                VariantScalarTypeId::Float => (v as f32).into(),
                VariantScalarTypeId::Int32 => (v as i32).into(),
                VariantScalarTypeId::Int64 => (v as i64).into(),
                VariantScalarTypeId::UInt32 => {
                    if v < 0 {
                        Variant::Empty
                    } else {
                        (v as u32).into()
                    }
                }
                VariantScalarTypeId::UInt64 => {
                    if v < 0 {
                        Variant::Empty
                    } else {
                        (v as u64).into()
                    }
                }
                _ => Variant::Empty,
            },
            Variant::Int32(v) => match target_type {
                VariantScalarTypeId::Double => (v as f64).into(),
                VariantScalarTypeId::Float => (v as f32).into(),
                VariantScalarTypeId::Int64 => (v as i64).into(),
                VariantScalarTypeId::UInt64 => {
                    if v < 0 {
                        Variant::Empty
                    } else {
                        (v as u64).into()
                    }
                }
                _ => Variant::Empty,
            },
            Variant::Int64(v) => match target_type {
                VariantScalarTypeId::Double => (v as f64).into(),
                VariantScalarTypeId::Float => (v as f32).into(),
                _ => Variant::Empty,
            },
            Variant::NodeId(ref v) => {
                // Guid - everything is X or E except to ExpandedNodeId and String
                match target_type {
                    VariantScalarTypeId::ExpandedNodeId => ExpandedNodeId::from(*v.clone()).into(),
                    VariantScalarTypeId::String => format!("{}", v).into(),
                    _ => Variant::Empty,
                }
            }
            Variant::SByte(v) => match target_type {
                VariantScalarTypeId::Double => (v as f64).into(),
                VariantScalarTypeId::Float => (v as f32).into(),
                VariantScalarTypeId::Int16 => (v as i16).into(),
                VariantScalarTypeId::Int32 => (v as i32).into(),
                VariantScalarTypeId::Int64 => (v as i64).into(),
                VariantScalarTypeId::UInt16 => {
                    if v < 0 {
                        Variant::Empty
                    } else {
                        (v as u16).into()
                    }
                }
                VariantScalarTypeId::UInt32 => {
                    if v < 0 {
                        Variant::Empty
                    } else {
                        (v as u32).into()
                    }
                }
                VariantScalarTypeId::UInt64 => {
                    if v < 0 {
                        Variant::Empty
                    } else {
                        (v as u64).into()
                    }
                }
                _ => Variant::Empty,
            },
            Variant::StatusCode(v) => match target_type {
                VariantScalarTypeId::Int32 => (v.bits() as i32).into(),
                VariantScalarTypeId::Int64 => (v.bits() as i64).into(),
                VariantScalarTypeId::UInt32 => v.bits().into(),
                VariantScalarTypeId::UInt64 => (v.bits() as u64).into(),
                _ => Variant::Empty,
            },
            Variant::String(ref v) => {
                if v.is_empty() {
                    Variant::Empty
                } else {
                    let v = v.as_ref();
                    match target_type {
                        VariantScalarTypeId::Boolean => {
                            // String values containing “true”, “false”, “1” or “0” can be converted
                            // to Boolean values. Other string values cause a conversion error. In
                            // this case Strings are case-insensitive.
                            if v == "true" || v == "1" {
                                true.into()
                            } else if v == "false" || v == "0" {
                                false.into()
                            } else {
                                Variant::Empty
                            }
                        }
                        VariantScalarTypeId::Byte => {
                            u8::from_str(v).map(|v| v.into()).unwrap_or(Variant::Empty)
                        }
                        VariantScalarTypeId::Double => {
                            f64::from_str(v).map(|v| v.into()).unwrap_or(Variant::Empty)
                        }
                        VariantScalarTypeId::Float => {
                            f32::from_str(v).map(|v| v.into()).unwrap_or(Variant::Empty)
                        }
                        VariantScalarTypeId::Guid => Guid::from_str(v)
                            .map(|v| v.into())
                            .unwrap_or(Variant::Empty),
                        VariantScalarTypeId::Int16 => {
                            i16::from_str(v).map(|v| v.into()).unwrap_or(Variant::Empty)
                        }
                        VariantScalarTypeId::Int32 => {
                            i32::from_str(v).map(|v| v.into()).unwrap_or(Variant::Empty)
                        }
                        VariantScalarTypeId::Int64 => {
                            i64::from_str(v).map(|v| v.into()).unwrap_or(Variant::Empty)
                        }
                        VariantScalarTypeId::NodeId => NodeId::from_str(v)
                            .map(|v| v.into())
                            .unwrap_or(Variant::Empty),
                        VariantScalarTypeId::SByte => {
                            i8::from_str(v).map(|v| v.into()).unwrap_or(Variant::Empty)
                        }
                        VariantScalarTypeId::UInt16 => {
                            u16::from_str(v).map(|v| v.into()).unwrap_or(Variant::Empty)
                        }
                        VariantScalarTypeId::UInt32 => {
                            u32::from_str(v).map(|v| v.into()).unwrap_or(Variant::Empty)
                        }
                        VariantScalarTypeId::UInt64 => {
                            u64::from_str(v).map(|v| v.into()).unwrap_or(Variant::Empty)
                        }
                        _ => Variant::Empty,
                    }
                }
            }
            Variant::LocalizedText(ref v) => match target_type {
                VariantScalarTypeId::String => v.text.clone().into(),
                _ => Variant::Empty,
            },
            Variant::QualifiedName(ref v) => {
                match target_type {
                    VariantScalarTypeId::String => {
                        if v.is_null() {
                            UAString::null().into()
                        } else {
                            // drop the namespace index
                            v.name.clone().into()
                        }
                    }
                    VariantScalarTypeId::LocalizedText => {
                        if v.is_null() {
                            LocalizedText::null().into()
                        } else {
                            // empty locale, drop namespace index
                            LocalizedText::new("", v.name.as_ref()).into()
                        }
                    }
                    _ => Variant::Empty,
                }
            }
            Variant::UInt16(v) => {
                match target_type {
                    VariantScalarTypeId::Double => (v as f64).into(),
                    VariantScalarTypeId::Float => (v as f32).into(),
                    VariantScalarTypeId::Int16 => (v as i16).into(),
                    VariantScalarTypeId::Int32 => (v as i32).into(),
                    VariantScalarTypeId::Int64 => (v as i64).into(),
                    VariantScalarTypeId::StatusCode => {
                        // The 16-bit value is treated as the top 16 bits of the status code
                        StatusCode::from((v as u32) << 16).into()
                    }
                    VariantScalarTypeId::UInt32 => (v as u32).into(),
                    VariantScalarTypeId::UInt64 => (v as u64).into(),
                    _ => Variant::Empty,
                }
            }
            Variant::UInt32(v) => match target_type {
                VariantScalarTypeId::Double => (v as f64).into(),
                VariantScalarTypeId::Float => (v as f32).into(),
                VariantScalarTypeId::Int32 => (v as i32).into(),
                VariantScalarTypeId::Int64 => (v as i64).into(),
                VariantScalarTypeId::UInt64 => (v as u64).into(),
                _ => Variant::Empty,
            },
            Variant::UInt64(v) => match target_type {
                VariantScalarTypeId::Double => (v as f64).into(),
                VariantScalarTypeId::Float => (v as f32).into(),
                VariantScalarTypeId::Int64 => (v as i64).into(),
                _ => Variant::Empty,
            },
            Variant::Array(ref s) => {
                if s.values.len() != 1 {
                    return Variant::Empty;
                }
                let val = &s.values[0];
                val.convert(target_type)
            }
            // XmlElement everything is X
            _ => Variant::Empty,
        }
    }

    fn convert_array(&self, target_type: VariantScalarTypeId, dims: Option<&[u32]>) -> Variant {
        match self {
            Variant::Array(a) => {
                // Dims must be equal for an implicit conversion.
                if dims.is_some() && dims != a.dimensions.as_deref() {
                    return Variant::Empty;
                }

                let mut res = Vec::with_capacity(a.values.len());
                for v in a.values.iter() {
                    let conv = v.convert(target_type);
                    if matches!(conv, Variant::Empty) {
                        return Variant::Empty;
                    }
                    res.push(conv);
                }

                Variant::Array(Box::new(Array {
                    value_type: target_type,
                    values: res,
                    dimensions: a.dimensions.clone(),
                }))
            }
            scalar => {
                if let Some(dims) = dims {
                    if dims.len() != 1 || dims[0] != 1 {
                        return Variant::Empty;
                    }
                }
                let converted = scalar.convert(target_type);
                if matches!(converted, Variant::Empty) {
                    return converted;
                }
                Self::Array(Box::new(Array {
                    value_type: target_type,
                    values: vec![converted],
                    dimensions: dims.map(|d| d.to_vec()),
                }))
            }
        }
    }

    /// Performs an IMPLICIT conversion from one type to another
    pub fn convert<'a>(&self, target_type: impl Into<VariantTypeId<'a>>) -> Variant {
        let target_type: VariantTypeId = target_type.into();
        if self.type_id() == target_type {
            return self.clone();
        }

        match target_type {
            VariantTypeId::Empty => Variant::Empty,
            VariantTypeId::Scalar(s) => self.convert_scalar(s),
            VariantTypeId::Array(s, d) => self.convert_array(s, d),
        }
    }

    /// Get the type ID of this variant. This can be useful to
    /// work with the variant abstractly, and check if the variant is
    /// of the expected type and dimensions.
    pub fn type_id(&self) -> VariantTypeId<'_> {
        match self {
            Variant::Empty => VariantTypeId::Empty,
            Variant::Boolean(_) => VariantTypeId::Scalar(VariantScalarTypeId::Boolean),
            Variant::SByte(_) => VariantTypeId::Scalar(VariantScalarTypeId::SByte),
            Variant::Byte(_) => VariantTypeId::Scalar(VariantScalarTypeId::Byte),
            Variant::Int16(_) => VariantTypeId::Scalar(VariantScalarTypeId::Int16),
            Variant::UInt16(_) => VariantTypeId::Scalar(VariantScalarTypeId::UInt16),
            Variant::Int32(_) => VariantTypeId::Scalar(VariantScalarTypeId::Int32),
            Variant::UInt32(_) => VariantTypeId::Scalar(VariantScalarTypeId::UInt32),
            Variant::Int64(_) => VariantTypeId::Scalar(VariantScalarTypeId::Int64),
            Variant::UInt64(_) => VariantTypeId::Scalar(VariantScalarTypeId::UInt64),
            Variant::Float(_) => VariantTypeId::Scalar(VariantScalarTypeId::Float),
            Variant::Double(_) => VariantTypeId::Scalar(VariantScalarTypeId::Double),
            Variant::String(_) => VariantTypeId::Scalar(VariantScalarTypeId::String),
            Variant::DateTime(_) => VariantTypeId::Scalar(VariantScalarTypeId::DateTime),
            Variant::Guid(_) => VariantTypeId::Scalar(VariantScalarTypeId::Guid),
            Variant::ByteString(_) => VariantTypeId::Scalar(VariantScalarTypeId::ByteString),
            Variant::XmlElement(_) => VariantTypeId::Scalar(VariantScalarTypeId::XmlElement),
            Variant::NodeId(_) => VariantTypeId::Scalar(VariantScalarTypeId::NodeId),
            Variant::ExpandedNodeId(_) => {
                VariantTypeId::Scalar(VariantScalarTypeId::ExpandedNodeId)
            }
            Variant::StatusCode(_) => VariantTypeId::Scalar(VariantScalarTypeId::StatusCode),
            Variant::QualifiedName(_) => VariantTypeId::Scalar(VariantScalarTypeId::QualifiedName),
            Variant::LocalizedText(_) => VariantTypeId::Scalar(VariantScalarTypeId::LocalizedText),
            Variant::ExtensionObject(_) => {
                VariantTypeId::Scalar(VariantScalarTypeId::ExtensionObject)
            }
            Variant::Variant(_) => VariantTypeId::Scalar(VariantScalarTypeId::Variant),
            Variant::DataValue(_) => VariantTypeId::Scalar(VariantScalarTypeId::DataValue),
            Variant::DiagnosticInfo(_) => {
                VariantTypeId::Scalar(VariantScalarTypeId::DiagnosticInfo)
            }
            Variant::Array(v) => VariantTypeId::Array(v.value_type, v.dimensions.as_deref()),
        }
    }

    /// Get the scalar type id of this variant, if present.
    ///
    /// This returns None only if the variant is empty.
    pub fn scalar_type_id(&self) -> Option<VariantScalarTypeId> {
        match self.type_id() {
            VariantTypeId::Empty => None,
            VariantTypeId::Scalar(s) => Some(s),
            VariantTypeId::Array(s, _) => Some(s),
        }
    }

    /// Returns `true` if this variant is [`Variant::Empty`].
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }

    /// Tests and returns true if the variant holds a numeric type
    pub fn is_numeric(&self) -> bool {
        matches!(
            self,
            Variant::SByte(_)
                | Variant::Byte(_)
                | Variant::Int16(_)
                | Variant::UInt16(_)
                | Variant::Int32(_)
                | Variant::UInt32(_)
                | Variant::Int64(_)
                | Variant::UInt64(_)
                | Variant::Float(_)
                | Variant::Double(_)
        )
    }

    /// Test if the variant holds an array
    pub fn is_array(&self) -> bool {
        matches!(self, Variant::Array(_))
    }

    /// Try to get the inner array if this is an array variant.
    pub fn as_array(&self) -> Option<&Vec<Variant>> {
        match self {
            Variant::Array(a) => Some(&a.values),
            _ => None,
        }
    }

    /// Check if this is an array of the given variant type.
    pub fn is_array_of_type(&self, variant_type: VariantScalarTypeId) -> bool {
        match self {
            Variant::Array(array) => values_are_of_type(array.values.as_slice(), variant_type),
            _ => false,
        }
    }

    /// Tests that the variant is in a valid state. In particular for arrays ensuring that the
    /// values are all acceptable and for a multi dimensional array that the dimensions equal
    /// the actual values.
    pub fn is_valid(&self) -> bool {
        match self {
            Variant::Array(array) => array.is_valid(),
            _ => true,
        }
    }

    /// Converts the numeric type to a double or returns None
    pub fn as_f64(&self) -> Option<f64> {
        match *self {
            Variant::SByte(value) => Some(value as f64),
            Variant::Byte(value) => Some(value as f64),
            Variant::Int16(value) => Some(value as f64),
            Variant::UInt16(value) => Some(value as f64),
            Variant::Int32(value) => Some(value as f64),
            Variant::UInt32(value) => Some(value as f64),
            Variant::Int64(value) => {
                // NOTE: Int64 could overflow
                Some(value as f64)
            }
            Variant::UInt64(value) => {
                // NOTE: UInt64 could overflow
                Some(value as f64)
            }
            Variant::Float(value) => Some(value as f64),
            Variant::Double(value) => Some(value),
            _ => None,
        }
    }

    /// Returns the scalar data type. Returns None if the variant is Empty.
    pub fn data_type(&self) -> Option<ExpandedNodeId> {
        match self {
            Variant::Boolean(_) => Some(DataTypeId::Boolean.into()),
            Variant::SByte(_) => Some(DataTypeId::SByte.into()),
            Variant::Byte(_) => Some(DataTypeId::Byte.into()),
            Variant::Int16(_) => Some(DataTypeId::Int16.into()),
            Variant::UInt16(_) => Some(DataTypeId::UInt16.into()),
            Variant::Int32(_) => Some(DataTypeId::Int32.into()),
            Variant::UInt32(_) => Some(DataTypeId::UInt32.into()),
            Variant::Int64(_) => Some(DataTypeId::Int64.into()),
            Variant::UInt64(_) => Some(DataTypeId::UInt64.into()),
            Variant::Float(_) => Some(DataTypeId::Float.into()),
            Variant::Double(_) => Some(DataTypeId::Double.into()),
            Variant::String(_) => Some(DataTypeId::String.into()),
            Variant::DateTime(_) => Some(DataTypeId::DateTime.into()),
            Variant::Guid(_) => Some(DataTypeId::Guid.into()),
            Variant::ByteString(_) => Some(DataTypeId::ByteString.into()),
            Variant::XmlElement(_) => Some(DataTypeId::XmlElement.into()),
            Variant::NodeId(_) => Some(DataTypeId::NodeId.into()),
            Variant::ExpandedNodeId(_) => Some(DataTypeId::ExpandedNodeId.into()),
            Variant::StatusCode(_) => Some(DataTypeId::StatusCode.into()),
            Variant::QualifiedName(_) => Some(DataTypeId::QualifiedName.into()),
            Variant::LocalizedText(_) => Some(DataTypeId::LocalizedText.into()),
            Variant::Variant(_) => Some(DataTypeId::BaseDataType.into()),
            Variant::DataValue(_) => Some(DataTypeId::DataValue.into()),
            Variant::DiagnosticInfo(_) => Some(DataTypeId::DiagnosticInfo.into()),
            Variant::ExtensionObject(extension_object) => extension_object.data_type(),
            Variant::Array(array) => {
                if array.values.is_empty() {
                    return None;
                }
                array.values[0].data_type()
            }
            Variant::Empty => None,
        }
    }

    // Gets the encoding mask to write the variant to disk
    pub(crate) fn encoding_mask(&self) -> u8 {
        match self {
            Variant::Empty => 0,
            Variant::Boolean(_) => EncodingMask::BOOLEAN,
            Variant::SByte(_) => EncodingMask::SBYTE,
            Variant::Byte(_) => EncodingMask::BYTE,
            Variant::Int16(_) => EncodingMask::INT16,
            Variant::UInt16(_) => EncodingMask::UINT16,
            Variant::Int32(_) => EncodingMask::INT32,
            Variant::UInt32(_) => EncodingMask::UINT32,
            Variant::Int64(_) => EncodingMask::INT64,
            Variant::UInt64(_) => EncodingMask::UINT64,
            Variant::Float(_) => EncodingMask::FLOAT,
            Variant::Double(_) => EncodingMask::DOUBLE,
            Variant::String(_) => EncodingMask::STRING,
            Variant::DateTime(_) => EncodingMask::DATE_TIME,
            Variant::Guid(_) => EncodingMask::GUID,
            Variant::ByteString(_) => EncodingMask::BYTE_STRING,
            Variant::XmlElement(_) => EncodingMask::XML_ELEMENT,
            Variant::NodeId(_) => EncodingMask::NODE_ID,
            Variant::ExpandedNodeId(_) => EncodingMask::EXPANDED_NODE_ID,
            Variant::StatusCode(_) => EncodingMask::STATUS_CODE,
            Variant::QualifiedName(_) => EncodingMask::QUALIFIED_NAME,
            Variant::LocalizedText(_) => EncodingMask::LOCALIZED_TEXT,
            Variant::ExtensionObject(_) => EncodingMask::EXTENSION_OBJECT,
            Variant::Variant(_) => EncodingMask::VARIANT,
            Variant::DataValue(_) => EncodingMask::DATA_VALUE,
            Variant::DiagnosticInfo(_) => EncodingMask::DIAGNOSTIC_INFO,
            Variant::Array(array) => array.encoding_mask(),
        }
    }

    /// This function is for a special edge case of converting a byte string to a
    /// single array of bytes
    pub fn to_byte_array(&self) -> Result<Self, ArrayError> {
        let array = match self {
            Variant::ByteString(values) => match &values.value {
                None => Array::new(VariantScalarTypeId::Byte, vec![])?,
                Some(values) => {
                    let values: Vec<Variant> = values.iter().map(|v| Variant::Byte(*v)).collect();
                    Array::new(VariantScalarTypeId::Byte, values)?
                }
            },
            _ => panic!(),
        };
        Ok(Variant::from(array))
    }

    /// This function returns a substring of a ByteString or a UAString
    fn substring(&self, min: usize, max: usize) -> Result<Variant, StatusCode> {
        match self {
            Variant::ByteString(v) => v
                .substring(min, max)
                .map(Variant::from)
                .map_err(|_| StatusCode::BadIndexRangeNoData),
            Variant::String(v) => v
                .substring(min, max)
                .map(Variant::from)
                .map_err(|_| StatusCode::BadIndexRangeNoData),
            _ => panic!("Should not be calling substring on other types"),
        }
    }
    /// Set a range of values in this variant using a different variant.
    pub fn set_range_of(
        &mut self,
        range: &NumericRange,
        other: &Variant,
    ) -> Result<(), StatusCode> {
        // TODO: This doesn't seem complete.
        // Types need to be the same
        if self.data_type() != other.data_type() {
            return Err(StatusCode::BadIndexRangeDataMismatch);
        }

        let other_array = if let Variant::Array(other) = other {
            other
        } else {
            return Err(StatusCode::BadIndexRangeNoData);
        };
        let other_values = &other_array.values;

        // Check value is same type as our array
        match self {
            Variant::Array(ref mut array) => {
                let values = &mut array.values;
                match range {
                    NumericRange::None => Err(StatusCode::BadIndexRangeNoData),
                    NumericRange::Index(idx) => {
                        let idx = (*idx) as usize;
                        if idx >= values.len() || other_values.is_empty() {
                            Err(StatusCode::BadIndexRangeNoData)
                        } else {
                            values[idx] = other_values[0].clone();
                            Ok(())
                        }
                    }
                    NumericRange::Range(min, max) => {
                        let (min, max) = ((*min) as usize, (*max) as usize);
                        if min >= values.len() {
                            Err(StatusCode::BadIndexRangeNoData)
                        } else {
                            // Possibly this could splice or something but it's trying to copy elements
                            // until either the source or destination array is finished.
                            let mut idx = min;
                            while idx < values.len() && idx <= max && idx - min < other_values.len()
                            {
                                values[idx] = other_values[idx - min].clone();
                                idx += 1;
                            }
                            Ok(())
                        }
                    }
                    NumericRange::MultipleRanges(_ranges) => {
                        // Not yet supported
                        error!("Multiple ranges not supported");
                        Err(StatusCode::BadIndexRangeNoData)
                    }
                }
            }
            _ => {
                error!("Writing a range is not supported when the recipient is not an array");
                Err(StatusCode::BadWriteNotSupported)
            }
        }
    }

    /// This function gets a range of values from the variant if it is an array,
    /// or returns the variant itself.
    pub fn range_of_owned(self, range: &NumericRange) -> Result<Variant, StatusCode> {
        match range {
            NumericRange::None => Ok(self),
            r => self.range_of(r),
        }
    }

    /// This function gets a range of values from the variant if it is an array, or returns a clone
    /// of the variant itself.
    pub fn range_of(&self, range: &NumericRange) -> Result<Variant, StatusCode> {
        match range {
            NumericRange::None => Ok(self.clone()),
            NumericRange::Index(idx) => {
                let idx = (*idx) as usize;
                match self {
                    Variant::String(_) | Variant::ByteString(_) => self.substring(idx, idx),
                    Variant::Array(array) => {
                        // Get value at the index (or not)
                        let values = &array.values;
                        if let Some(v) = values.get(idx) {
                            let values = vec![v.clone()];
                            Ok(Variant::from((array.value_type, values)))
                        } else {
                            Err(StatusCode::BadIndexRangeNoData)
                        }
                    }
                    _ => Err(StatusCode::BadIndexRangeDataMismatch),
                }
            }
            NumericRange::Range(min, max) => {
                let (min, max) = ((*min) as usize, (*max) as usize);
                match self {
                    Variant::String(_) | Variant::ByteString(_) => self.substring(min, max),
                    Variant::Array(array) => {
                        let values = &array.values;
                        if min >= values.len() {
                            // Min must be in range
                            Err(StatusCode::BadIndexRangeNoData)
                        } else {
                            let max = if max >= values.len() {
                                values.len() - 1
                            } else {
                                max
                            };
                            let values = &values[min..=max];
                            let values: Vec<Variant> = values.to_vec();
                            Ok(Variant::from((array.value_type, values)))
                        }
                    }
                    _ => Err(StatusCode::BadIndexRangeDataMismatch),
                }
            }
            NumericRange::MultipleRanges(ranges) => {
                let mut res = Vec::new();
                for range in ranges {
                    let v = self.range_of(range)?;
                    match v {
                        Variant::Array(a) => {
                            res.extend(a.values.into_iter());
                        }
                        r => res.push(r),
                    }
                }
                let type_id = if !res.is_empty() {
                    let VariantTypeId::Scalar(s) = res[0].type_id() else {
                        return Err(StatusCode::BadIndexRangeNoData);
                    };
                    s
                } else {
                    match self.type_id() {
                        VariantTypeId::Array(s, _) => s,
                        VariantTypeId::Scalar(s) => s,
                        VariantTypeId::Empty => return Ok(Variant::Empty),
                    }
                };

                Ok(Self::Array(Box::new(
                    Array::new(type_id, res).map_err(|_| StatusCode::BadInvalidArgument)?,
                )))
            }
        }
    }

    /// Try to cast this variant to the type `T`.
    pub fn try_cast_to<T: TryFromVariant>(self) -> Result<T, Error> {
        T::try_from_variant(self)
    }
}
