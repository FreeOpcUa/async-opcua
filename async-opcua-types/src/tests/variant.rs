use std::str::FromStr;

use crate::{
    numeric_range::NumericRange,
    status_code::StatusCode,
    variant::{Variant, VariantTypeId},
    ByteString, DataTypeId, DataValue, DateTime, DiagnosticInfo, ExpandedNodeId, Guid,
    LocalizedText, NodeId, QualifiedName, TryFromVariant, UAString, VariantScalarTypeId,
};

#[test]
fn is_numeric() {
    assert!(Variant::from(10i8).is_numeric());
    assert!(Variant::from(10u8).is_numeric());
    assert!(Variant::from(10i16).is_numeric());
    assert!(Variant::from(10u16).is_numeric());
    assert!(Variant::from(10i32).is_numeric());
    assert!(Variant::from(10u32).is_numeric());
    assert!(Variant::from(10i64).is_numeric());
    assert!(Variant::from(10u64).is_numeric());
    assert!(Variant::from(10f32).is_numeric());
    assert!(Variant::from(10f64).is_numeric());

    assert!(!Variant::from("foo").is_numeric());
    assert!(!Variant::from(true).is_numeric());
}

#[test]
fn size() {
    // Test that the variant is boxing enough data to keep the stack size down to some manageable
    // amount.
    use std::mem;
    let vsize = mem::size_of::<Variant>();
    println!("Variant size = {vsize}");
    assert!(vsize <= 32);
}

#[test]
fn variant_type_id() {
    use crate::{
        status_code::StatusCode, ByteString, DateTime, ExpandedNodeId, ExtensionObject, Guid,
        LocalizedText, NodeId, QualifiedName, UAString, XmlElement,
    };

    let types = [
        (Variant::Empty, VariantTypeId::Empty),
        (
            Variant::from(true),
            VariantTypeId::Scalar(VariantScalarTypeId::Boolean),
        ),
        (
            Variant::from(0i8),
            VariantTypeId::Scalar(VariantScalarTypeId::SByte),
        ),
        (
            Variant::from(0u8),
            VariantTypeId::Scalar(VariantScalarTypeId::Byte),
        ),
        (
            Variant::from(0i16),
            VariantTypeId::Scalar(VariantScalarTypeId::Int16),
        ),
        (
            Variant::from(0u16),
            VariantTypeId::Scalar(VariantScalarTypeId::UInt16),
        ),
        (
            Variant::from(0i32),
            VariantTypeId::Scalar(VariantScalarTypeId::Int32),
        ),
        (
            Variant::from(0u32),
            VariantTypeId::Scalar(VariantScalarTypeId::UInt32),
        ),
        (
            Variant::from(0i64),
            VariantTypeId::Scalar(VariantScalarTypeId::Int64),
        ),
        (
            Variant::from(0u64),
            VariantTypeId::Scalar(VariantScalarTypeId::UInt64),
        ),
        (
            Variant::from(0f32),
            VariantTypeId::Scalar(VariantScalarTypeId::Float),
        ),
        (
            Variant::from(0f64),
            VariantTypeId::Scalar(VariantScalarTypeId::Double),
        ),
        (
            Variant::from(UAString::null()),
            VariantTypeId::Scalar(VariantScalarTypeId::String),
        ),
        (
            Variant::from(ByteString::null()),
            VariantTypeId::Scalar(VariantScalarTypeId::ByteString),
        ),
        (
            Variant::XmlElement(XmlElement::null()),
            VariantTypeId::Scalar(VariantScalarTypeId::XmlElement),
        ),
        (
            Variant::from(StatusCode::Good),
            VariantTypeId::Scalar(VariantScalarTypeId::StatusCode),
        ),
        (
            Variant::from(DateTime::now()),
            VariantTypeId::Scalar(VariantScalarTypeId::DateTime),
        ),
        (
            Variant::from(Guid::new()),
            VariantTypeId::Scalar(VariantScalarTypeId::Guid),
        ),
        (
            Variant::from(NodeId::null()),
            VariantTypeId::Scalar(VariantScalarTypeId::NodeId),
        ),
        (
            Variant::from(ExpandedNodeId::null()),
            VariantTypeId::Scalar(VariantScalarTypeId::ExpandedNodeId),
        ),
        (
            Variant::from(QualifiedName::null()),
            VariantTypeId::Scalar(VariantScalarTypeId::QualifiedName),
        ),
        (
            Variant::from(LocalizedText::null()),
            VariantTypeId::Scalar(VariantScalarTypeId::LocalizedText),
        ),
        (
            Variant::from(ExtensionObject::null()),
            VariantTypeId::Scalar(VariantScalarTypeId::ExtensionObject),
        ),
        (
            Variant::from(DataValue::null()),
            VariantTypeId::Scalar(VariantScalarTypeId::DataValue),
        ),
        (
            Variant::Variant(Box::new(Variant::from(32u8))),
            VariantTypeId::Scalar(VariantScalarTypeId::Variant),
        ),
        (
            Variant::from(DiagnosticInfo::null()),
            VariantTypeId::Scalar(VariantScalarTypeId::DiagnosticInfo),
        ),
        (
            Variant::from(vec![1]),
            VariantTypeId::Array(VariantScalarTypeId::Int32, None),
        ),
    ];
    for t in &types {
        assert_eq!(t.0.type_id(), t.1);
    }
}

#[test]
fn variant_u32_array() {
    let vars = [1u32, 2u32, 3u32];
    let v = Variant::from(&vars[..]);
    assert!(v.is_array());
    assert!(v.is_array_of_type(VariantScalarTypeId::UInt32));
    assert!(v.is_valid());

    match v {
        Variant::Array(array) => {
            let values = array.values;
            assert_eq!(values.len(), 3);
            let mut i = 1u32;
            for v in values {
                assert!(v.is_numeric());
                match v {
                    Variant::UInt32(v) => {
                        assert_eq!(v, i);
                    }
                    _ => panic!("Not the expected type"),
                }
                i += 1;
            }
        }
        _ => panic!("Not an array"),
    }
}

#[test]
fn variant_try_into_u32_array() {
    let vars = [1u32, 2u32, 3u32];
    let v = Variant::from(&vars[..]);
    assert!(v.is_array());
    assert!(v.is_array_of_type(VariantScalarTypeId::UInt32));
    assert!(v.is_valid());

    let result = <Vec<u32>>::try_from_variant(v).unwrap();
    assert_eq!(result.len(), 3);
}

#[test]
fn variant_i32_array() {
    let vars = [1, 2, 3];
    let v = Variant::from(&vars[..]);
    assert!(v.is_array());
    assert!(v.is_array_of_type(VariantScalarTypeId::Int32));
    assert!(v.is_valid());

    match v {
        Variant::Array(array) => {
            let values = array.values;
            assert_eq!(values.len(), 3);
            let mut i = 1;
            for v in values {
                assert!(v.is_numeric());
                match v {
                    Variant::Int32(v) => {
                        assert_eq!(v, i);
                    }
                    _ => panic!("Not the expected type"),
                }
                i += 1;
            }
        }
        _ => panic!("Not an array"),
    }
}

#[test]
fn variant_multi_dimensional_array() {
    let v = Variant::from((
        VariantScalarTypeId::Int32,
        vec![Variant::from(10)],
        vec![1u32],
    ));
    assert!(v.is_array());
    assert!(v.is_array_of_type(VariantScalarTypeId::Int32));
    assert!(v.is_valid());

    let v = Variant::from((
        VariantScalarTypeId::Int32,
        vec![Variant::from(10), Variant::from(10)],
        vec![2u32],
    ));
    assert!(v.is_array());
    assert!(v.is_array_of_type(VariantScalarTypeId::Int32));
    assert!(v.is_valid());

    let v = Variant::from((
        VariantScalarTypeId::Int32,
        vec![Variant::from(10), Variant::from(10)],
        vec![1u32, 2u32],
    ));
    assert!(v.is_array());
    assert!(v.is_array_of_type(VariantScalarTypeId::Int32));
    assert!(v.is_valid());

    let v = Variant::from((
        VariantScalarTypeId::Int32,
        vec![
            Variant::from(10),
            Variant::from(10),
            Variant::from(10),
            Variant::from(10),
            Variant::from(10),
            Variant::from(10),
        ],
        vec![1u32, 2u32, 3u32],
    ));
    assert!(v.is_array());
    assert!(v.is_array_of_type(VariantScalarTypeId::Int32));
    assert!(v.is_valid());
}

#[test]
fn index_of_array() {
    let vars: Vec<Variant> = [1, 2, 3].iter().map(|v| Variant::from(*v)).collect();
    let v = Variant::from((VariantScalarTypeId::Int32, vars));
    assert!(v.is_array());

    let r = v.range_of(&NumericRange::None).unwrap();
    assert_eq!(r, v);

    let r = v.range_of(&NumericRange::Index(1)).unwrap();
    match r {
        Variant::Array(array) => {
            assert_eq!(array.values.len(), 1);
            assert_eq!(array.values[0], Variant::Int32(2));
        }
        _ => panic!(),
    }

    let r = v.range_of(&NumericRange::Range(1, 2)).unwrap();
    match r {
        Variant::Array(array) => {
            assert_eq!(array.values.len(), 2);
            assert_eq!(array.values[0], Variant::Int32(2));
            assert_eq!(array.values[1], Variant::Int32(3));
        }
        _ => panic!(),
    }

    let r = v.range_of(&NumericRange::Range(1, 200)).unwrap();
    match r {
        Variant::Array(array) => {
            assert_eq!(array.values.len(), 2);
        }
        _ => panic!(),
    }

    let r = v.range_of(&NumericRange::Range(3, 200)).unwrap_err();
    assert_eq!(r, StatusCode::BadIndexRangeNoData);
}

#[test]
fn index_of_string() {
    let v: Variant = "Hello World".into();

    let r = v.range_of(&NumericRange::None).unwrap();
    assert_eq!(r, v);

    // Letter W
    let r = v.range_of(&NumericRange::Index(6)).unwrap();
    assert_eq!(r, Variant::from("W"));

    let r = v.range_of(&NumericRange::Range(6, 100)).unwrap();
    assert_eq!(r, Variant::from("World"));

    let r = v.range_of(&NumericRange::Range(11, 200)).unwrap_err();
    assert_eq!(r, StatusCode::BadIndexRangeNoData);
}

fn ensure_conversion_fails<'a>(v: &Variant, convert_to: Vec<impl Into<VariantTypeId<'a>>>) {
    convert_to.into_iter().for_each(|vt| {
        let t: VariantTypeId = vt.into();
        assert_eq!(v.convert(t), Variant::Empty);
    });
}

#[test]
fn variant_convert_bool() {
    let v: Variant = true.into();
    assert_eq!(v.convert(v.type_id()), v);
    // All these are implicit conversions expected to succeed
    assert_eq!(v.convert(VariantScalarTypeId::SByte), Variant::SByte(1));
    assert_eq!(v.convert(VariantScalarTypeId::Byte), Variant::Byte(1));
    assert_eq!(v.convert(VariantScalarTypeId::Double), Variant::Double(1.0));
    assert_eq!(v.convert(VariantScalarTypeId::Float), Variant::Float(1.0));
    assert_eq!(v.convert(VariantScalarTypeId::Int16), Variant::Int16(1));
    assert_eq!(v.convert(VariantScalarTypeId::UInt16), Variant::UInt16(1));
    assert_eq!(v.convert(VariantScalarTypeId::Int32), Variant::Int32(1));
    assert_eq!(v.convert(VariantScalarTypeId::UInt32), Variant::UInt32(1));
    assert_eq!(v.convert(VariantScalarTypeId::Int64), Variant::Int64(1));
    assert_eq!(v.convert(VariantScalarTypeId::UInt64), Variant::UInt64(1));
    // Impermissible
    ensure_conversion_fails(
        &v,
        vec![
            VariantScalarTypeId::ByteString,
            VariantScalarTypeId::String,
            VariantScalarTypeId::DateTime,
            VariantScalarTypeId::ExpandedNodeId,
            VariantScalarTypeId::Guid,
            VariantScalarTypeId::NodeId,
            VariantScalarTypeId::StatusCode,
            VariantScalarTypeId::LocalizedText,
            VariantScalarTypeId::QualifiedName,
            VariantScalarTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_bool() {
    // String
    assert_eq!(
        Variant::from(false).cast(VariantScalarTypeId::String),
        Variant::from("false")
    );
    assert_eq!(
        Variant::from(true).cast(VariantScalarTypeId::String),
        Variant::from("true")
    );
}

#[test]
fn variant_convert_byte() {
    let v: Variant = 5u8.into();
    assert_eq!(v.convert(v.type_id()), v);
    // All these are implicit conversions expected to succeed
    assert_eq!(v.convert(VariantScalarTypeId::Double), Variant::Double(5.0));
    assert_eq!(v.convert(VariantScalarTypeId::Float), Variant::Float(5.0));
    assert_eq!(v.convert(VariantScalarTypeId::Int16), Variant::Int16(5));
    assert_eq!(v.convert(VariantScalarTypeId::Int32), Variant::Int32(5));
    assert_eq!(v.convert(VariantScalarTypeId::Int64), Variant::Int64(5));
    assert_eq!(v.convert(VariantScalarTypeId::SByte), Variant::SByte(5));
    assert_eq!(v.convert(VariantScalarTypeId::UInt16), Variant::UInt16(5));
    assert_eq!(v.convert(VariantScalarTypeId::UInt32), Variant::UInt32(5));
    assert_eq!(v.convert(VariantScalarTypeId::UInt64), Variant::UInt64(5));
    // Impermissible
    ensure_conversion_fails(
        &v,
        vec![
            VariantScalarTypeId::Boolean,
            VariantScalarTypeId::String,
            VariantScalarTypeId::ByteString,
            VariantScalarTypeId::DateTime,
            VariantScalarTypeId::ExpandedNodeId,
            VariantScalarTypeId::Guid,
            VariantScalarTypeId::NodeId,
            VariantScalarTypeId::StatusCode,
            VariantScalarTypeId::LocalizedText,
            VariantScalarTypeId::QualifiedName,
            VariantScalarTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_byte() {
    let v: Variant = 5u8.into();
    // Boolean
    assert_eq!(
        Variant::from(11u8).cast(VariantScalarTypeId::Boolean),
        Variant::Empty
    );
    assert_eq!(
        Variant::from(1u8).cast(VariantScalarTypeId::Boolean),
        Variant::from(true)
    );
    // String
    assert_eq!(v.cast(VariantScalarTypeId::String), Variant::from("5"));
}

#[test]
fn variant_convert_double() {
    let v: Variant = 12.5f64.into();
    assert_eq!(v.convert(v.type_id()), v);
    // Impermissible
    ensure_conversion_fails(
        &v,
        vec![
            VariantScalarTypeId::Boolean,
            VariantScalarTypeId::Byte,
            VariantScalarTypeId::ByteString,
            VariantScalarTypeId::DateTime,
            VariantScalarTypeId::ExpandedNodeId,
            VariantScalarTypeId::Float,
            VariantScalarTypeId::Guid,
            VariantScalarTypeId::Int16,
            VariantScalarTypeId::Int32,
            VariantScalarTypeId::Int64,
            VariantScalarTypeId::NodeId,
            VariantScalarTypeId::SByte,
            VariantScalarTypeId::StatusCode,
            VariantScalarTypeId::String,
            VariantScalarTypeId::LocalizedText,
            VariantScalarTypeId::QualifiedName,
            VariantScalarTypeId::UInt16,
            VariantScalarTypeId::UInt32,
            VariantScalarTypeId::UInt64,
            VariantScalarTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_double() {
    let v: Variant = 12.5f64.into();
    // Cast Boolean
    assert_eq!(
        Variant::from(11f64).cast(VariantScalarTypeId::Boolean),
        Variant::Empty
    );
    assert_eq!(
        Variant::from(1f64).cast(VariantScalarTypeId::Boolean),
        Variant::from(true)
    );
    //  Cast Byte, Float, Int16, Int32, Int64, SByte, UInt16, UInt32, UInt64
    assert_eq!(v.cast(VariantScalarTypeId::Byte), Variant::from(13u8));
    assert_eq!(v.cast(VariantScalarTypeId::Float), Variant::from(12.5f32));
    assert_eq!(v.cast(VariantScalarTypeId::Int16), Variant::from(13i16));
    assert_eq!(v.cast(VariantScalarTypeId::Int32), Variant::from(13i32));
    assert_eq!(v.cast(VariantScalarTypeId::Int64), Variant::from(13i64));
    assert_eq!(v.cast(VariantScalarTypeId::SByte), Variant::from(13i8));
    assert_eq!(v.cast(VariantScalarTypeId::UInt16), Variant::from(13u16));
    assert_eq!(v.cast(VariantScalarTypeId::UInt32), Variant::from(13u32));
    assert_eq!(v.cast(VariantScalarTypeId::UInt64), Variant::from(13u64));
    assert_eq!(v.cast(VariantScalarTypeId::String), Variant::from("12.5"));
}

#[test]
fn variant_convert_float() {
    let v: Variant = 12.5f32.into();
    assert_eq!(v.convert(v.type_id()), v);
    // All these are implicit conversions expected to succeed
    assert_eq!(
        v.convert(VariantScalarTypeId::Double),
        Variant::Double(12.5)
    );
    // Impermissible
    ensure_conversion_fails(
        &v,
        vec![
            VariantScalarTypeId::Boolean,
            VariantScalarTypeId::Byte,
            VariantScalarTypeId::ByteString,
            VariantScalarTypeId::DateTime,
            VariantScalarTypeId::ExpandedNodeId,
            VariantScalarTypeId::Guid,
            VariantScalarTypeId::Int16,
            VariantScalarTypeId::Int32,
            VariantScalarTypeId::Int64,
            VariantScalarTypeId::NodeId,
            VariantScalarTypeId::SByte,
            VariantScalarTypeId::StatusCode,
            VariantScalarTypeId::String,
            VariantScalarTypeId::LocalizedText,
            VariantScalarTypeId::QualifiedName,
            VariantScalarTypeId::UInt16,
            VariantScalarTypeId::UInt32,
            VariantScalarTypeId::UInt64,
            VariantScalarTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_float() {
    let v: Variant = 12.5f32.into();
    // Boolean
    assert_eq!(
        Variant::from(11f32).cast(VariantScalarTypeId::Boolean),
        Variant::Empty
    );
    assert_eq!(
        Variant::from(1f32).cast(VariantScalarTypeId::Boolean),
        Variant::from(true)
    );
    // Cast
    assert_eq!(v.cast(VariantScalarTypeId::Byte), Variant::from(13u8));
    assert_eq!(v.cast(VariantScalarTypeId::Int16), Variant::from(13i16));
    assert_eq!(v.cast(VariantScalarTypeId::Int32), Variant::from(13i32));
    assert_eq!(v.cast(VariantScalarTypeId::Int64), Variant::from(13i64));
    assert_eq!(v.cast(VariantScalarTypeId::SByte), Variant::from(13i8));
    assert_eq!(v.cast(VariantScalarTypeId::UInt16), Variant::from(13u16));
    assert_eq!(v.cast(VariantScalarTypeId::UInt32), Variant::from(13u32));
    assert_eq!(v.cast(VariantScalarTypeId::UInt64), Variant::from(13u64));
    assert_eq!(v.cast(VariantScalarTypeId::String), Variant::from("12.5"));
}

#[test]
fn variant_convert_int16() {
    let v: Variant = 8i16.into();
    assert_eq!(v.convert(v.type_id()), v);
    // All these are implicit conversions expected to succeed
    assert_eq!(v.convert(VariantScalarTypeId::Double), Variant::Double(8.0));
    assert_eq!(v.convert(VariantScalarTypeId::Float), Variant::Float(8.0));
    assert_eq!(v.convert(VariantScalarTypeId::Int32), Variant::Int32(8));
    assert_eq!(v.convert(VariantScalarTypeId::Int64), Variant::Int64(8));
    assert_eq!(v.convert(VariantScalarTypeId::UInt32), Variant::UInt32(8));
    assert_eq!(v.convert(VariantScalarTypeId::UInt64), Variant::UInt64(8));
    // Impermissible
    ensure_conversion_fails(
        &v,
        vec![
            VariantScalarTypeId::Boolean,
            VariantScalarTypeId::Byte,
            VariantScalarTypeId::ByteString,
            VariantScalarTypeId::DateTime,
            VariantScalarTypeId::ExpandedNodeId,
            VariantScalarTypeId::Guid,
            VariantScalarTypeId::SByte,
            VariantScalarTypeId::NodeId,
            VariantScalarTypeId::StatusCode,
            VariantScalarTypeId::String,
            VariantScalarTypeId::LocalizedText,
            VariantScalarTypeId::QualifiedName,
            VariantScalarTypeId::UInt16,
            VariantScalarTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_int16() {
    let v: Variant = 8i16.into();
    // Cast Boolean, Byte, SByte, String, UInt16
    assert_eq!(v.cast(VariantScalarTypeId::Boolean), Variant::Empty);
    assert_eq!(
        Variant::from(1i16).cast(VariantScalarTypeId::Boolean),
        Variant::from(true)
    );
    assert_eq!(v.cast(VariantScalarTypeId::Byte), Variant::from(8u8));
    assert_eq!(
        Variant::from(-120i16).cast(VariantScalarTypeId::Byte),
        Variant::Empty
    );
    assert_eq!(v.cast(VariantScalarTypeId::SByte), Variant::from(8i8));
    assert_eq!(
        Variant::from(-137i16).cast(VariantScalarTypeId::SByte),
        Variant::Empty
    );
    assert_eq!(v.cast(VariantScalarTypeId::String), Variant::from("8"));
    assert_eq!(v.cast(VariantScalarTypeId::UInt16), Variant::from(8u16));
}

#[test]
fn variant_convert_int32() {
    let v: Variant = 9i32.into();
    assert_eq!(v.convert(v.type_id()), v);
    // All these are implicit conversions expected to succeed
    assert_eq!(v.convert(VariantScalarTypeId::Double), Variant::Double(9.0));
    assert_eq!(v.convert(VariantScalarTypeId::Float), Variant::Float(9.0));
    assert_eq!(v.convert(VariantScalarTypeId::Int64), Variant::Int64(9));
    assert_eq!(v.convert(VariantScalarTypeId::UInt64), Variant::UInt64(9));
    // Impermissible
    ensure_conversion_fails(
        &v,
        vec![
            VariantScalarTypeId::Boolean,
            VariantScalarTypeId::Byte,
            VariantScalarTypeId::ByteString,
            VariantScalarTypeId::DateTime,
            VariantScalarTypeId::ExpandedNodeId,
            VariantScalarTypeId::Guid,
            VariantScalarTypeId::Int16,
            VariantScalarTypeId::NodeId,
            VariantScalarTypeId::SByte,
            VariantScalarTypeId::StatusCode,
            VariantScalarTypeId::String,
            VariantScalarTypeId::LocalizedText,
            VariantScalarTypeId::QualifiedName,
            VariantScalarTypeId::UInt16,
            VariantScalarTypeId::UInt32,
            VariantScalarTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_int32() {
    let v: Variant = 9i32.into();
    // Boolean
    assert_eq!(v.cast(VariantScalarTypeId::Boolean), Variant::Empty);
    assert_eq!(
        Variant::from(1i32).cast(VariantScalarTypeId::Boolean),
        Variant::from(true)
    );
    // Byte
    assert_eq!(v.cast(VariantScalarTypeId::Byte), Variant::from(9u8));
    assert_eq!(
        Variant::from(-120i32).cast(VariantScalarTypeId::Byte),
        Variant::Empty
    );
    // Int16
    assert_eq!(v.cast(VariantScalarTypeId::Int16), Variant::from(9i16));
    // SByte
    assert_eq!(v.cast(VariantScalarTypeId::SByte), Variant::from(9i8));
    assert_eq!(
        Variant::from(-137i32).cast(VariantScalarTypeId::SByte),
        Variant::Empty
    );
    // StatusCode
    let status_code = StatusCode::BadResourceUnavailable.set_semantics_changed(true);
    assert_eq!(
        Variant::from(status_code.bits() as i32).cast(VariantScalarTypeId::StatusCode),
        Variant::from(status_code)
    );
    // String
    assert_eq!(v.cast(VariantScalarTypeId::String), Variant::from("9"));
    // UInt16
    assert_eq!(v.cast(VariantScalarTypeId::UInt16), Variant::from(9u16));
    assert_eq!(
        Variant::from(-120i32).cast(VariantScalarTypeId::UInt16),
        Variant::Empty
    );
    // UInt32
    assert_eq!(v.cast(VariantScalarTypeId::UInt32), Variant::from(9u32));
    assert_eq!(
        Variant::from(-120i32).cast(VariantScalarTypeId::UInt32),
        Variant::Empty
    );
}

#[test]
fn variant_convert_int64() {
    let v: Variant = 10i64.into();
    assert_eq!(v.convert(v.type_id()), v);
    // All these are implicit conversions expected to succeed
    assert_eq!(
        v.convert(VariantScalarTypeId::Double),
        Variant::Double(10.0)
    );
    assert_eq!(v.convert(VariantScalarTypeId::Float), Variant::Float(10.0));
    // Impermissible
    ensure_conversion_fails(
        &v,
        vec![
            VariantScalarTypeId::Boolean,
            VariantScalarTypeId::Byte,
            VariantScalarTypeId::ByteString,
            VariantScalarTypeId::DateTime,
            VariantScalarTypeId::ExpandedNodeId,
            VariantScalarTypeId::Guid,
            VariantScalarTypeId::Int16,
            VariantScalarTypeId::Int32,
            VariantScalarTypeId::NodeId,
            VariantScalarTypeId::SByte,
            VariantScalarTypeId::StatusCode,
            VariantScalarTypeId::String,
            VariantScalarTypeId::LocalizedText,
            VariantScalarTypeId::QualifiedName,
            VariantScalarTypeId::UInt16,
            VariantScalarTypeId::UInt32,
            VariantScalarTypeId::UInt64,
            VariantScalarTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_int64() {
    let v: Variant = 10i64.into();
    // Boolean
    assert_eq!(v.cast(VariantScalarTypeId::Boolean), Variant::Empty);
    assert_eq!(
        Variant::from(1i64).cast(VariantScalarTypeId::Boolean),
        Variant::from(true)
    );
    // Byte
    assert_eq!(v.cast(VariantScalarTypeId::Byte), Variant::from(10u8));
    assert_eq!(
        Variant::from(-120i64).cast(VariantScalarTypeId::Byte),
        Variant::Empty
    );
    // Int16
    assert_eq!(v.cast(VariantScalarTypeId::Int16), Variant::from(10i16));
    // SByte
    assert_eq!(v.cast(VariantScalarTypeId::SByte), Variant::from(10i8));
    assert_eq!(
        Variant::from(-137i64).cast(VariantScalarTypeId::SByte),
        Variant::Empty
    );
    // StatusCode
    let status_code = StatusCode::BadResourceUnavailable.set_semantics_changed(true);
    assert_eq!(
        Variant::from(status_code.bits() as i64).cast(VariantScalarTypeId::StatusCode),
        Variant::from(status_code)
    );
    // String
    assert_eq!(v.cast(VariantScalarTypeId::String), Variant::from("10"));
    // UInt16
    assert_eq!(v.cast(VariantScalarTypeId::UInt16), Variant::from(10u16));
    assert_eq!(
        Variant::from(-120i64).cast(VariantScalarTypeId::UInt16),
        Variant::Empty
    );
    // UInt32
    assert_eq!(v.cast(VariantScalarTypeId::UInt32), Variant::from(10u32));
    assert_eq!(
        Variant::from(-120i64).cast(VariantScalarTypeId::UInt32),
        Variant::Empty
    );
    // UInt64
    assert_eq!(v.cast(VariantScalarTypeId::UInt64), Variant::from(10u64));
    assert_eq!(
        Variant::from(-120i64).cast(VariantScalarTypeId::UInt32),
        Variant::Empty
    );
}

#[test]
fn variant_convert_sbyte() {
    let v: Variant = 12i8.into();
    assert_eq!(v.convert(v.type_id()), v);
    // All these are implicit conversions expected to succeed
    assert_eq!(
        v.convert(VariantScalarTypeId::Double),
        Variant::Double(12.0)
    );
    assert_eq!(v.convert(VariantScalarTypeId::Float), Variant::Float(12.0));
    assert_eq!(v.convert(VariantScalarTypeId::Int16), Variant::Int16(12));
    assert_eq!(v.convert(VariantScalarTypeId::Int32), Variant::Int32(12));
    assert_eq!(v.convert(VariantScalarTypeId::Int64), Variant::Int64(12));
    assert_eq!(v.convert(VariantScalarTypeId::UInt16), Variant::UInt16(12));
    assert_eq!(v.convert(VariantScalarTypeId::UInt32), Variant::UInt32(12));
    assert_eq!(v.convert(VariantScalarTypeId::UInt64), Variant::UInt64(12));
    // Impermissible
    ensure_conversion_fails(
        &v,
        vec![
            VariantScalarTypeId::Boolean,
            VariantScalarTypeId::Byte,
            VariantScalarTypeId::ByteString,
            VariantScalarTypeId::DateTime,
            VariantScalarTypeId::ExpandedNodeId,
            VariantScalarTypeId::Guid,
            VariantScalarTypeId::NodeId,
            VariantScalarTypeId::StatusCode,
            VariantScalarTypeId::String,
            VariantScalarTypeId::LocalizedText,
            VariantScalarTypeId::QualifiedName,
            VariantScalarTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_sbyte() {
    let v: Variant = 12i8.into();
    // Boolean
    assert_eq!(v.cast(VariantScalarTypeId::Boolean), Variant::Empty);
    assert_eq!(
        Variant::from(1i8).cast(VariantScalarTypeId::Boolean),
        Variant::from(true)
    );
    // Byte
    assert_eq!(v.cast(VariantScalarTypeId::Byte), Variant::from(12u8));
    assert_eq!(
        Variant::from(-120i8).cast(VariantScalarTypeId::Byte),
        Variant::Empty
    );
    // String
    assert_eq!(v.cast(VariantScalarTypeId::String), Variant::from("12"));
}

#[test]
fn variant_convert_string() {
    let v = Variant::from("Reflexive Test");
    assert_eq!(v.convert(v.type_id()), v);
    // Boolean
    assert_eq!(
        Variant::from("1").convert(VariantScalarTypeId::Boolean),
        true.into()
    );
    assert_eq!(
        Variant::from("0").convert(VariantScalarTypeId::Boolean),
        false.into()
    );
    assert_eq!(
        Variant::from("true").convert(VariantScalarTypeId::Boolean),
        true.into()
    );
    assert_eq!(
        Variant::from("false").convert(VariantScalarTypeId::Boolean),
        false.into()
    );
    assert_eq!(
        Variant::from(" false").convert(VariantScalarTypeId::Boolean),
        Variant::Empty
    );
    // Byte
    assert_eq!(
        Variant::from("12").convert(VariantScalarTypeId::Byte),
        12u8.into()
    );
    assert_eq!(
        Variant::from("256").convert(VariantScalarTypeId::Byte),
        Variant::Empty
    );
    // Double
    assert_eq!(
        Variant::from("12.5").convert(VariantScalarTypeId::Double),
        12.5f64.into()
    );
    // Float
    assert_eq!(
        Variant::from("12.5").convert(VariantScalarTypeId::Float),
        12.5f32.into()
    );
    // Guid
    assert_eq!(
        Variant::from("d47a32c9-5ee7-43c1-a733-0fe30bf26b50").convert(VariantScalarTypeId::Guid),
        Guid::from_str("d47a32c9-5ee7-43c1-a733-0fe30bf26b50")
            .unwrap()
            .into()
    );
    // Int16
    assert_eq!(
        Variant::from("12").convert(VariantScalarTypeId::Int16),
        12i16.into()
    );
    assert_eq!(
        Variant::from("65536").convert(VariantScalarTypeId::Int16),
        Variant::Empty
    );
    // Int32
    assert_eq!(
        Variant::from("12").convert(VariantScalarTypeId::Int32),
        12i32.into()
    );
    assert_eq!(
        Variant::from("2147483648").convert(VariantScalarTypeId::Int32),
        Variant::Empty
    );
    // Int64
    assert_eq!(
        Variant::from("12").convert(VariantScalarTypeId::Int64),
        12i64.into()
    );
    assert_eq!(
        Variant::from("9223372036854775808").convert(VariantScalarTypeId::Int64),
        Variant::Empty
    );
    // SByte
    assert_eq!(
        Variant::from("12").convert(VariantScalarTypeId::SByte),
        12i8.into()
    );
    assert_eq!(
        Variant::from("128").convert(VariantScalarTypeId::SByte),
        Variant::Empty
    );
    assert_eq!(
        Variant::from("-129").convert(VariantScalarTypeId::SByte),
        Variant::Empty
    );
    // UInt16
    assert_eq!(
        Variant::from("12").convert(VariantScalarTypeId::UInt16),
        12u16.into()
    );
    assert_eq!(
        Variant::from("65536").convert(VariantScalarTypeId::UInt16),
        Variant::Empty
    );
    // UInt32
    assert_eq!(
        Variant::from("12").convert(VariantScalarTypeId::UInt32),
        12u32.into()
    );
    assert_eq!(
        Variant::from("4294967296").convert(VariantScalarTypeId::UInt32),
        Variant::Empty
    );
    // UInt64
    assert_eq!(
        Variant::from("12").convert(VariantScalarTypeId::UInt64),
        12u64.into()
    );
    assert_eq!(
        Variant::from("18446744073709551615").convert(VariantScalarTypeId::UInt32),
        Variant::Empty
    );
    // Impermissible
    let v = Variant::from("xxx");
    ensure_conversion_fails(
        &v,
        vec![
            VariantScalarTypeId::ByteString,
            VariantScalarTypeId::StatusCode,
            VariantScalarTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_string() {
    // DateTime
    let now = DateTime::now();
    let now_s = format!("{now}");
    let now_v: Variant = now.into();
    assert_eq!(
        Variant::from(now_s).cast(VariantScalarTypeId::DateTime),
        now_v
    );
    // ExpandedNodeId
    assert_eq!(
        Variant::from("svr=5;ns=22;s=Hello World").cast(VariantScalarTypeId::ExpandedNodeId),
        ExpandedNodeId {
            node_id: NodeId::new(22, "Hello World"),
            namespace_uri: UAString::null(),
            server_index: 5,
        }
        .into()
    );
    // NodeId
    assert_eq!(
        Variant::from("ns=22;s=Hello World").cast(VariantScalarTypeId::NodeId),
        NodeId::new(22, "Hello World").into()
    );
    // LocalizedText
    assert_eq!(
        Variant::from("Localized Text").cast(VariantScalarTypeId::LocalizedText),
        LocalizedText::new("", "Localized Text").into()
    );
    // QualifiedName
    assert_eq!(
        Variant::from("Qualified Name").cast(VariantScalarTypeId::QualifiedName),
        QualifiedName::new(0, "Qualified Name").into()
    );
}

#[test]
fn variant_convert_uint16() {
    let v: Variant = 80u16.into();
    assert_eq!(v.convert(v.type_id()), v);
    // All these are implicit conversions expected to succeed
    assert_eq!(
        v.convert(VariantScalarTypeId::Double),
        Variant::Double(80.0)
    );
    assert_eq!(v.convert(VariantScalarTypeId::Float), Variant::Float(80.0));
    assert_eq!(v.convert(VariantScalarTypeId::Int16), Variant::Int16(80));
    assert_eq!(v.convert(VariantScalarTypeId::Int32), Variant::Int32(80));
    assert_eq!(v.convert(VariantScalarTypeId::Int64), Variant::Int64(80));
    assert_eq!(
        v.convert(VariantScalarTypeId::StatusCode),
        Variant::StatusCode(StatusCode::from(80 << 16))
    );
    assert_eq!(v.convert(VariantScalarTypeId::UInt32), Variant::UInt32(80));
    assert_eq!(v.convert(VariantScalarTypeId::UInt64), Variant::UInt64(80));
    // Impermissible
    ensure_conversion_fails(
        &v,
        vec![
            VariantScalarTypeId::Boolean,
            VariantScalarTypeId::Byte,
            VariantScalarTypeId::ByteString,
            VariantScalarTypeId::DateTime,
            VariantScalarTypeId::ExpandedNodeId,
            VariantScalarTypeId::Guid,
            VariantScalarTypeId::SByte,
            VariantScalarTypeId::String,
            VariantScalarTypeId::NodeId,
            VariantScalarTypeId::LocalizedText,
            VariantScalarTypeId::QualifiedName,
            VariantScalarTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_convert_array() {
    let v = Variant::from((VariantScalarTypeId::Int32, vec![1, 2, 3, 4]));
    assert_eq!(
        v.convert(VariantTypeId::Array(VariantScalarTypeId::Int64, None)),
        Variant::from((VariantScalarTypeId::Int64, vec![1i64, 2i64, 3i64, 4i64]))
    );
    assert_eq!(
        v.convert(VariantTypeId::Array(VariantScalarTypeId::UInt64, None)),
        Variant::from((VariantScalarTypeId::UInt64, vec![1u64, 2u64, 3u64, 4u64]))
    );

    ensure_conversion_fails(
        &v,
        vec![
            VariantTypeId::Scalar(VariantScalarTypeId::Int32),
            VariantTypeId::Array(VariantScalarTypeId::ByteString, None),
            VariantTypeId::Empty,
            VariantTypeId::Array(VariantScalarTypeId::Int32, Some(&[2, 2])),
            VariantTypeId::Array(VariantScalarTypeId::Int32, Some(&[3, 3])),
        ],
    );

    let v = Variant::from((
        VariantScalarTypeId::Int32,
        vec![1, 2, 3, 4],
        vec![2u32, 2u32],
    ));
    assert_eq!(
        v.convert(VariantTypeId::Array(VariantScalarTypeId::Int64, None)),
        Variant::from((
            VariantScalarTypeId::Int64,
            vec![1i64, 2i64, 3i64, 4i64],
            vec![2u32, 2u32]
        ))
    );
    assert_eq!(
        v.convert(VariantTypeId::Array(
            VariantScalarTypeId::Int64,
            Some(&[2, 2])
        )),
        Variant::from((
            VariantScalarTypeId::Int64,
            vec![1i64, 2i64, 3i64, 4i64],
            vec![2u32, 2u32]
        ))
    );

    ensure_conversion_fails(
        &v,
        vec![
            VariantTypeId::Scalar(VariantScalarTypeId::Int32),
            VariantTypeId::Array(VariantScalarTypeId::ByteString, None),
            VariantTypeId::Array(VariantScalarTypeId::Int64, Some(&[4])),
        ],
    )
}

#[test]
fn variant_cast_array() {
    let v = Variant::from((VariantScalarTypeId::Int32, vec![1, 2, 3, 4]));
    assert_eq!(
        v.cast(VariantTypeId::Array(VariantScalarTypeId::Int16, None)),
        Variant::from((VariantScalarTypeId::Int16, vec![1i16, 2i16, 3i16, 4i16]))
    );
    assert_eq!(
        v.cast(VariantTypeId::Array(
            VariantScalarTypeId::Int16,
            Some(&[2, 2])
        )),
        Variant::from((
            VariantScalarTypeId::Int16,
            vec![1i16, 2i16, 3i16, 4i16],
            vec![2u32, 2u32]
        ))
    );
    assert_eq!(
        v.cast(VariantTypeId::Array(
            VariantScalarTypeId::Int16,
            Some(&[1, 1, 1, 4])
        )),
        Variant::from((
            VariantScalarTypeId::Int16,
            vec![1i16, 2i16, 3i16, 4i16],
            vec![1u32, 1u32, 1u32, 4u32]
        ))
    );
    assert_eq!(
        v.cast(VariantTypeId::Array(
            VariantScalarTypeId::Int16,
            Some(&[3, 3])
        )),
        Variant::Empty
    );
}

#[test]
fn variant_cast_uint16() {
    let v: Variant = 80u16.into();
    // Boolean
    assert_eq!(v.cast(VariantScalarTypeId::Boolean), Variant::Empty);
    assert_eq!(
        Variant::from(1u16).cast(VariantScalarTypeId::Boolean),
        Variant::from(true)
    );
    // Byte
    assert_eq!(v.cast(VariantScalarTypeId::Byte), Variant::from(80u8));
    assert_eq!(
        Variant::from(256u16).cast(VariantScalarTypeId::Byte),
        Variant::Empty
    );
    // SByte
    assert_eq!(v.cast(VariantScalarTypeId::SByte), Variant::from(80i8));
    assert_eq!(
        Variant::from(128u16).cast(VariantScalarTypeId::SByte),
        Variant::Empty
    );
    // String
    assert_eq!(v.cast(VariantScalarTypeId::String), Variant::from("80"));
}

#[test]
fn variant_convert_uint32() {
    let v: Variant = 23u32.into();
    assert_eq!(v.convert(v.type_id()), v);
    // All these are implicit conversions expected to succeed
    assert_eq!(
        v.convert(VariantScalarTypeId::Double),
        Variant::Double(23.0)
    );
    assert_eq!(v.convert(VariantScalarTypeId::Float), Variant::Float(23.0));
    assert_eq!(v.convert(VariantScalarTypeId::Int32), Variant::Int32(23));
    assert_eq!(v.convert(VariantScalarTypeId::Int64), Variant::Int64(23));
    assert_eq!(v.convert(VariantScalarTypeId::UInt32), Variant::UInt32(23));
    assert_eq!(v.convert(VariantScalarTypeId::UInt64), Variant::UInt64(23));
    // Impermissible
    ensure_conversion_fails(
        &v,
        vec![
            VariantScalarTypeId::Boolean,
            VariantScalarTypeId::Byte,
            VariantScalarTypeId::ByteString,
            VariantScalarTypeId::DateTime,
            VariantScalarTypeId::ExpandedNodeId,
            VariantScalarTypeId::Guid,
            VariantScalarTypeId::Int16,
            VariantScalarTypeId::SByte,
            VariantScalarTypeId::StatusCode,
            VariantScalarTypeId::String,
            VariantScalarTypeId::NodeId,
            VariantScalarTypeId::LocalizedText,
            VariantScalarTypeId::QualifiedName,
            VariantScalarTypeId::UInt16,
            VariantScalarTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_uint32() {
    let v: Variant = 23u32.into();
    // Boolean
    assert_eq!(v.cast(VariantScalarTypeId::Boolean), Variant::Empty);
    assert_eq!(
        Variant::from(1u32).cast(VariantScalarTypeId::Boolean),
        Variant::from(true)
    );
    // Byte
    assert_eq!(v.cast(VariantScalarTypeId::Byte), Variant::from(23u8));
    assert_eq!(
        Variant::from(256u32).cast(VariantScalarTypeId::Byte),
        Variant::Empty
    );
    // Int16
    assert_eq!(v.cast(VariantScalarTypeId::Int16), Variant::from(23i16));
    assert_eq!(
        Variant::from(102256u32).cast(VariantScalarTypeId::Int16),
        Variant::Empty
    );
    // SByte
    assert_eq!(v.cast(VariantScalarTypeId::SByte), Variant::from(23i8));
    assert_eq!(
        Variant::from(128u32).cast(VariantScalarTypeId::SByte),
        Variant::Empty
    );
    // StatusCode
    let status_code = StatusCode::BadResourceUnavailable.set_semantics_changed(true);
    assert_eq!(
        Variant::from(status_code.bits()).cast(VariantScalarTypeId::StatusCode),
        Variant::from(status_code)
    );
    // String
    assert_eq!(v.cast(VariantScalarTypeId::String), Variant::from("23"));
    // UInt16
    assert_eq!(v.cast(VariantScalarTypeId::UInt16), Variant::from(23u16));
    assert_eq!(
        Variant::from(102256u32).cast(VariantScalarTypeId::UInt16),
        Variant::Empty
    );
}

#[test]
fn variant_convert_uint64() {
    let v: Variant = 43u64.into();
    assert_eq!(v.convert(v.type_id()), v);
    // All these are implicit conversions expected to succeed
    assert_eq!(
        v.convert(VariantScalarTypeId::Double),
        Variant::Double(43.0)
    );
    assert_eq!(v.convert(VariantScalarTypeId::Float), Variant::Float(43.0));
    assert_eq!(v.convert(VariantScalarTypeId::Int64), Variant::Int64(43));
    assert_eq!(v.convert(VariantScalarTypeId::UInt64), Variant::UInt64(43));
    // Impermissible
    ensure_conversion_fails(
        &v,
        vec![
            VariantScalarTypeId::Boolean,
            VariantScalarTypeId::Byte,
            VariantScalarTypeId::ByteString,
            VariantScalarTypeId::DateTime,
            VariantScalarTypeId::ExpandedNodeId,
            VariantScalarTypeId::Guid,
            VariantScalarTypeId::Int16,
            VariantScalarTypeId::Int32,
            VariantScalarTypeId::SByte,
            VariantScalarTypeId::StatusCode,
            VariantScalarTypeId::String,
            VariantScalarTypeId::NodeId,
            VariantScalarTypeId::LocalizedText,
            VariantScalarTypeId::QualifiedName,
            VariantScalarTypeId::UInt16,
            VariantScalarTypeId::UInt32,
            VariantScalarTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_uint64() {
    let v: Variant = 43u64.into();
    // Boolean
    assert_eq!(v.cast(VariantScalarTypeId::Boolean), Variant::Empty);
    assert_eq!(
        Variant::from(1u64).cast(VariantScalarTypeId::Boolean),
        Variant::from(true)
    );
    // Byte
    assert_eq!(v.cast(VariantScalarTypeId::Byte), Variant::from(43u8));
    assert_eq!(
        Variant::from(256u64).cast(VariantScalarTypeId::Byte),
        Variant::Empty
    );
    // Int16
    assert_eq!(v.cast(VariantScalarTypeId::Int16), Variant::from(43i16));
    assert_eq!(
        Variant::from(102256u64).cast(VariantScalarTypeId::Int16),
        Variant::Empty
    );
    // SByte
    assert_eq!(v.cast(VariantScalarTypeId::SByte), Variant::from(43i8));
    assert_eq!(
        Variant::from(128u64).cast(VariantScalarTypeId::SByte),
        Variant::Empty
    );
    // StatusCode
    let status_code = StatusCode::BadResourceUnavailable.set_semantics_changed(true);
    assert_eq!(
        Variant::from(status_code.bits() as u64).cast(VariantScalarTypeId::StatusCode),
        Variant::from(status_code)
    );
    // String
    assert_eq!(v.cast(VariantScalarTypeId::String), Variant::from("43"));
    // UInt16
    assert_eq!(v.cast(VariantScalarTypeId::UInt16), Variant::from(43u16));
    assert_eq!(
        Variant::from(102256u64).cast(VariantScalarTypeId::UInt16),
        Variant::Empty
    );
    // UInt32
    assert_eq!(v.cast(VariantScalarTypeId::UInt32), Variant::from(43u32));
    assert_eq!(
        Variant::from(4294967298u64).cast(VariantScalarTypeId::UInt32),
        Variant::Empty
    );
}

#[test]
fn variant_cast_date_time() {
    let now = DateTime::now();
    let now_s = format!("{now}");
    assert_eq!(
        Variant::from(now).cast(VariantScalarTypeId::String),
        now_s.into()
    );
}

#[test]
fn variant_convert_guid() {
    let v = Variant::from(Guid::new());
    // Impermissible
    ensure_conversion_fails(
        &v,
        vec![
            VariantScalarTypeId::Boolean,
            VariantScalarTypeId::Byte,
            VariantScalarTypeId::ByteString,
            VariantScalarTypeId::DateTime,
            VariantScalarTypeId::Double,
            VariantScalarTypeId::ExpandedNodeId,
            VariantScalarTypeId::Float,
            VariantScalarTypeId::Int16,
            VariantScalarTypeId::Int32,
            VariantScalarTypeId::Int64,
            VariantScalarTypeId::NodeId,
            VariantScalarTypeId::SByte,
            VariantScalarTypeId::StatusCode,
            VariantScalarTypeId::String,
            VariantScalarTypeId::LocalizedText,
            VariantScalarTypeId::QualifiedName,
            VariantScalarTypeId::UInt16,
            VariantScalarTypeId::UInt32,
            VariantScalarTypeId::UInt64,
            VariantScalarTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_guid() {
    let g = Guid::new();
    let v = Variant::from(g.clone());
    // ByteString
    let b = ByteString::from(g.clone());
    assert_eq!(v.cast(VariantScalarTypeId::ByteString), b.into());
    // String
    assert_eq!(v.cast(VariantScalarTypeId::String), format!("{g}").into());
}

#[test]
fn variant_convert_status_code() {
    let v = Variant::from(StatusCode::BadInvalidArgument);
    assert_eq!(v.convert(v.type_id()), v);
    // Implicit Int32, Int64, UInt32, UInt64
    assert_eq!(
        v.convert(VariantScalarTypeId::Int32),
        Variant::Int32(-2136276992i32)
    ); // 0x80AB_0000 overflows to negative
    assert_eq!(
        v.convert(VariantScalarTypeId::Int64),
        Variant::Int64(0x80AB_0000)
    );
    assert_eq!(
        v.convert(VariantScalarTypeId::UInt32),
        Variant::UInt32(0x80AB_0000)
    );
    assert_eq!(
        v.convert(VariantScalarTypeId::UInt64),
        Variant::UInt64(0x80AB_0000)
    );
    // Impermissible
    ensure_conversion_fails(
        &v,
        vec![
            VariantScalarTypeId::Boolean,
            VariantScalarTypeId::Byte,
            VariantScalarTypeId::ByteString,
            VariantScalarTypeId::DateTime,
            VariantScalarTypeId::Double,
            VariantScalarTypeId::ExpandedNodeId,
            VariantScalarTypeId::Float,
            VariantScalarTypeId::Guid,
            VariantScalarTypeId::Int16,
            VariantScalarTypeId::NodeId,
            VariantScalarTypeId::SByte,
            VariantScalarTypeId::String,
            VariantScalarTypeId::LocalizedText,
            VariantScalarTypeId::QualifiedName,
            VariantScalarTypeId::UInt16,
            VariantScalarTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_status_code() {
    let status_code = StatusCode::BadResourceUnavailable.set_semantics_changed(true);
    let v = Variant::from(status_code);
    // Cast UInt16 (BadResourceUnavailable == 0x8004_0000)
    assert_eq!(v.cast(VariantScalarTypeId::UInt16), Variant::UInt16(0x8004));
}

#[test]
fn variant_convert_byte_string() {
    let v = Variant::from(ByteString::from(b"test"));
    assert_eq!(v.convert(v.type_id()), v);
    // Impermissible
    ensure_conversion_fails(
        &v,
        vec![
            VariantScalarTypeId::Boolean,
            VariantScalarTypeId::Byte,
            VariantScalarTypeId::DateTime,
            VariantScalarTypeId::Double,
            VariantScalarTypeId::ExpandedNodeId,
            VariantScalarTypeId::Float,
            VariantScalarTypeId::Guid,
            VariantScalarTypeId::Int16,
            VariantScalarTypeId::Int32,
            VariantScalarTypeId::Int64,
            VariantScalarTypeId::NodeId,
            VariantScalarTypeId::SByte,
            VariantScalarTypeId::StatusCode,
            VariantScalarTypeId::String,
            VariantScalarTypeId::LocalizedText,
            VariantScalarTypeId::QualifiedName,
            VariantScalarTypeId::UInt16,
            VariantScalarTypeId::UInt32,
            VariantScalarTypeId::UInt64,
            VariantScalarTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_byte_string() {
    let g = Guid::new();
    let v = Variant::from(ByteString::from(g.clone()));
    // Guid
    assert_eq!(v.cast(VariantScalarTypeId::Guid), g.into());
}

#[test]
fn variant_convert_qualified_name() {
    let v = Variant::from(QualifiedName::new(123, "hello"));
    assert_eq!(v.convert(v.type_id()), v);
    // LocalizedText
    assert_eq!(
        v.convert(VariantScalarTypeId::LocalizedText),
        Variant::from(LocalizedText::new("", "hello"))
    );
    // String
    assert_eq!(
        v.convert(VariantScalarTypeId::String),
        Variant::from("hello")
    );
    // Impermissible
    ensure_conversion_fails(
        &v,
        vec![
            VariantScalarTypeId::Boolean,
            VariantScalarTypeId::Byte,
            VariantScalarTypeId::ByteString,
            VariantScalarTypeId::DateTime,
            VariantScalarTypeId::Double,
            VariantScalarTypeId::ExpandedNodeId,
            VariantScalarTypeId::Float,
            VariantScalarTypeId::Guid,
            VariantScalarTypeId::Int16,
            VariantScalarTypeId::Int32,
            VariantScalarTypeId::Int64,
            VariantScalarTypeId::NodeId,
            VariantScalarTypeId::SByte,
            VariantScalarTypeId::StatusCode,
            VariantScalarTypeId::UInt16,
            VariantScalarTypeId::UInt32,
            VariantScalarTypeId::UInt64,
            VariantScalarTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_convert_localized_text() {
    let v = Variant::from(LocalizedText::new("fr-FR", "bonjour"));
    assert_eq!(v.convert(v.type_id()), v);
    // String
    assert_eq!(
        v.convert(VariantScalarTypeId::String),
        Variant::from("bonjour")
    );
    // Impermissible
    ensure_conversion_fails(
        &v,
        vec![
            VariantScalarTypeId::Boolean,
            VariantScalarTypeId::Byte,
            VariantScalarTypeId::ByteString,
            VariantScalarTypeId::DateTime,
            VariantScalarTypeId::Double,
            VariantScalarTypeId::ExpandedNodeId,
            VariantScalarTypeId::Float,
            VariantScalarTypeId::Guid,
            VariantScalarTypeId::Int16,
            VariantScalarTypeId::Int32,
            VariantScalarTypeId::Int64,
            VariantScalarTypeId::NodeId,
            VariantScalarTypeId::SByte,
            VariantScalarTypeId::StatusCode,
            VariantScalarTypeId::QualifiedName,
            VariantScalarTypeId::UInt16,
            VariantScalarTypeId::UInt32,
            VariantScalarTypeId::UInt64,
            VariantScalarTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_convert_node_id() {
    let v = Variant::from(NodeId::new(99, "my node"));
    assert_eq!(v.convert(v.type_id()), v);
    // ExpandedNodeId
    assert_eq!(
        v.convert(VariantScalarTypeId::ExpandedNodeId),
        Variant::from(ExpandedNodeId {
            node_id: NodeId::new(99, "my node"),
            namespace_uri: UAString::null(),
            server_index: 0,
        })
    );
    // String
    assert_eq!(
        v.convert(VariantScalarTypeId::String),
        Variant::from("ns=99;s=my node")
    );
    // Impermissible
    ensure_conversion_fails(
        &v,
        vec![
            VariantScalarTypeId::Boolean,
            VariantScalarTypeId::Byte,
            VariantScalarTypeId::ByteString,
            VariantScalarTypeId::DateTime,
            VariantScalarTypeId::Double,
            VariantScalarTypeId::Float,
            VariantScalarTypeId::Guid,
            VariantScalarTypeId::Int16,
            VariantScalarTypeId::Int32,
            VariantScalarTypeId::Int64,
            VariantScalarTypeId::SByte,
            VariantScalarTypeId::LocalizedText,
            VariantScalarTypeId::QualifiedName,
            VariantScalarTypeId::UInt16,
            VariantScalarTypeId::UInt32,
            VariantScalarTypeId::UInt64,
            VariantScalarTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_convert_expanded_node_id() {
    let v = Variant::from(ExpandedNodeId {
        node_id: NodeId::new(22, "Hello World"),
        namespace_uri: UAString::null(),
        server_index: 5,
    });
    assert_eq!(v.convert(v.type_id()), v);
    // String
    assert_eq!(
        v.convert(VariantScalarTypeId::String),
        Variant::from("svr=5;ns=22;s=Hello World")
    );
    // Impermissible
    ensure_conversion_fails(
        &v,
        vec![
            VariantScalarTypeId::Boolean,
            VariantScalarTypeId::Byte,
            VariantScalarTypeId::ByteString,
            VariantScalarTypeId::DateTime,
            VariantScalarTypeId::Double,
            VariantScalarTypeId::Float,
            VariantScalarTypeId::Guid,
            VariantScalarTypeId::Int16,
            VariantScalarTypeId::Int32,
            VariantScalarTypeId::Int64,
            VariantScalarTypeId::NodeId,
            VariantScalarTypeId::SByte,
            VariantScalarTypeId::LocalizedText,
            VariantScalarTypeId::QualifiedName,
            VariantScalarTypeId::UInt16,
            VariantScalarTypeId::UInt32,
            VariantScalarTypeId::UInt64,
            VariantScalarTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_expanded_node_id() {
    let v = Variant::from(ExpandedNodeId {
        node_id: NodeId::new(22, "Hello World"),
        namespace_uri: UAString::null(),
        server_index: 5,
    });
    // NodeId
    assert_eq!(
        v.cast(VariantScalarTypeId::NodeId),
        Variant::from(NodeId::new(22, "Hello World"))
    );
}

#[test]
fn variant_bytestring_to_bytearray() {
    let v = ByteString::from(&[0x1, 0x2, 0x3, 0x4]);
    let v = Variant::from(v);

    let v = v.to_byte_array().unwrap();
    assert_eq!(v.data_type().unwrap().node_id, DataTypeId::Byte);

    let array = match v {
        Variant::Array(v) => v,
        _ => panic!(),
    };

    let v = array.values;
    assert_eq!(v.len(), 4);
    assert_eq!(v[0], Variant::Byte(0x1));
    assert_eq!(v[1], Variant::Byte(0x2));
    assert_eq!(v[2], Variant::Byte(0x3));
    assert_eq!(v[3], Variant::Byte(0x4));
}

// TODO arrays
