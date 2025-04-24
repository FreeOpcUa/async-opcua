use std::{
    io::{Cursor, Read, Seek, Write},
    str::FromStr,
};

use base64::Engine;
use opcua_macros::{JsonDecodable, JsonEncodable, UaNullable};
use serde_json::{json, Value};
use struson::{
    reader::JsonStreamReader,
    writer::{JsonStreamWriter, JsonWriter},
};

use crate::{
    byte_string::ByteString,
    data_value::DataValue,
    date_time::DateTime,
    diagnostic_info::DiagnosticInfo,
    expanded_node_id::ExpandedNodeId,
    guid::Guid,
    json::{JsonDecodable, JsonEncodable},
    localized_text::LocalizedText,
    node_id::NodeId,
    qualified_name::QualifiedName,
    status_code::StatusCode,
    string::UAString,
    variant::Variant,
    Argument, Array, BinaryEncodable, DataTypeId, EUInformation, ObjectId, VariantScalarTypeId,
};

use crate::{ContextOwned, EncodingResult, ExtensionObject};

fn ctx() -> ContextOwned {
    ContextOwned::default()
}

fn from_value<T: JsonDecodable>(v: Value) -> EncodingResult<T> {
    let v = serde_json::to_string(&v).unwrap();
    let ctx = ctx();
    let stream = &mut v.as_bytes() as &mut dyn Read;
    let mut reader = JsonStreamReader::new(stream);
    T::decode(&mut reader, &ctx.context())
}

fn from_str<T: JsonDecodable>(v: &str) -> EncodingResult<T> {
    let ctx = ctx();
    let stream = &mut v.as_bytes() as &mut dyn Read;
    let mut reader = JsonStreamReader::new(stream);
    T::decode(&mut reader, &ctx.context())
}

fn to_string<T: JsonEncodable>(v: &T) -> EncodingResult<String> {
    let mut target = Vec::new();
    let mut stream = Cursor::new(&mut target);
    let mut writer = JsonStreamWriter::new(&mut stream as &mut dyn Write);
    let ctx = ctx();
    v.encode(&mut writer, &ctx.context())?;
    writer.finish_document().unwrap();
    Ok(String::from_utf8(target).unwrap())
}

fn to_value<T: JsonEncodable>(v: &T) -> EncodingResult<Value> {
    let v = to_string(v)?;
    Ok(serde_json::from_str(&v).unwrap())
}

#[test]
fn serialize_string() {
    let s: UAString = from_value(json!(null)).unwrap();
    assert!(s.is_null());

    let json = to_string(&UAString::null()).unwrap();
    println!("null str = {}", json);
    assert_eq!(json, "null");

    let s: UAString = from_value(json!("Hello World!")).unwrap();
    assert_eq!(s.as_ref(), "Hello World!");

    let json = to_string(&UAString::from("Hello World!")).unwrap();
    println!("hw str = {}", json);
    assert_eq!(json, r#""Hello World!""#);

    let json = to_string(&UAString::from("")).unwrap();
    println!("empty str = {}", json);
    assert_eq!(json, r#""""#);
}

#[test]
fn serialize_date_time() {
    let dt1 = DateTime::rfc3339_now();
    let vs = to_string(&dt1).unwrap();
    println!("date_time = {}", vs);
    let dt2 = from_str::<DateTime>(&vs).unwrap();
    assert_eq!(dt1, dt2);
}

#[test]
fn serialize_guid() {
    let g1 = Guid::new();
    let vs = to_string(&g1).unwrap();
    println!("guid = {}", vs);
    let g2: Guid = from_str(&vs).unwrap();
    assert_eq!(g1, g2);

    let g1: Guid = from_value(json!("f9e561f3-351c-47a2-b969-b8d6d7226fee")).unwrap();
    let g2 = Guid::from_str("f9e561f3-351c-47a2-b969-b8d6d7226fee").unwrap();
    assert_eq!(g1, g2);

    assert!(from_value::<Guid>(json!("{f9e561f3-351c-47a2-b969-b8d6d7226fee")).is_err());
}

#[test]
fn serialize_data_value() {
    let _source_timestamp = DateTime::now();
    let _server_timestamp = DateTime::now();
    let dv1 = DataValue {
        value: Some(Variant::from(100u16)),
        status: Some(StatusCode::BadAggregateListMismatch),
        source_timestamp: None, // FIXME
        source_picoseconds: Some(123),
        server_timestamp: None, // FIXME
        server_picoseconds: Some(456),
    };
    let s = to_string(&dv1).unwrap();

    let dv2 = from_str(&s).unwrap();
    assert_eq!(dv1, dv2);
}

#[test]
fn serialize_node_id() {
    let n = NodeId::new(0, 1);
    let json = to_value(&n).unwrap();
    assert_eq!(json, json!({"Id": 1}));
    let n2 = from_value::<NodeId>(json).unwrap();
    assert_eq!(n, n2);
    let n3 = from_value::<NodeId>(json!({"Type": 0, "Id": 1})).unwrap();
    assert_eq!(n, n3);

    let n = NodeId::new(10, 5);
    let json = to_value(&n).unwrap();
    assert_eq!(json, json!({"Id": 5, "Namespace": 10}));
    let n2 = from_value::<NodeId>(json).unwrap();
    assert_eq!(n, n2);

    let n = NodeId::new(1, "Hello");
    let json = to_value(&n).unwrap();
    assert_eq!(json, json!({"IdType": 1, "Id": "Hello", "Namespace": 1}));
    let n2 = from_value::<NodeId>(json).unwrap();
    assert_eq!(n, n2);

    let guid = "995a9546-cd91-4393-b1c8-a83851f88d6a";
    let n = NodeId::new(1, Guid::from_str(guid).unwrap());
    let json = to_value(&n).unwrap();
    assert_eq!(json, json!({"IdType": 2, "Id": guid, "Namespace": 1}));
    let n2 = from_value::<NodeId>(json).unwrap();
    assert_eq!(n, n2);

    let bytestring = "aGVsbG8gd29ybGQ=";
    let n = NodeId::new(1, ByteString::from_base64(bytestring).unwrap());
    let json = to_value(&n).unwrap();
    assert_eq!(json, json!({"IdType": 3, "Id": bytestring, "Namespace": 1}));
    let n2 = from_value::<NodeId>(json).unwrap();
    assert_eq!(n, n2);

    // Missing namespace is treated as 0
    let n2 = from_value::<NodeId>(json!({"IdType": 1, "Id": "XYZ"})).unwrap();
    assert_eq!(NodeId::new(0, "XYZ"), n2);

    // Invalid Type
    let n = from_value::<NodeId>(json!({"IdType": 5, "Id": "InvalidType", "Namespace": 1}));
    assert!(n.is_err());

    // Missing id
    let n = from_value::<NodeId>(json!({"IdType": 1, "Namespace": 1}));
    assert!(n.is_err());

    // Invalid string ids
    let n = from_value::<NodeId>(json!({"IdType": 1, "Id": null, "Namespace": 1}));
    assert!(n.is_err());
    let n = from_value::<NodeId>(json!({"IdType": 1, "Id": true, "Namespace": 1}));
    assert!(n.is_err());
    let n = from_value::<NodeId>(json!({"IdType": 1, "Id": "", "Namespace": 1}));
    assert!(n.is_err());

    // Invalid guid
    let n = from_value::<NodeId>(json!({"IdType": 2, "Id": null, "Namespace": 1}));
    assert!(n.is_err());
    let n = from_value::<NodeId>(json!({"IdType": 2, "Id": "1234", "Namespace": 1}));
    assert!(n.is_err());
    let n = from_value::<NodeId>(json!({"IdType": 2, "Id": "", "Namespace": 1}));
    assert!(n.is_err());

    // Invalid bytestring
    let n = from_value::<NodeId>(json!({"IdType": 3, "Id": null, "Namespace": 1}));
    assert!(n.is_err());
    let n = from_value::<NodeId>(json!({"IdType": 3, "Id": "", "Namespace": 1}));
    assert!(n.is_err());
}

#[test]
fn serialize_expanded_node_id() {
    let n = ExpandedNodeId::new(NodeId::new(0, 1));
    let json = to_value(&n).unwrap();
    assert_eq!(json, json!({"Id": 1}));

    let mut n = ExpandedNodeId::new(NodeId::new(1, 1));
    n.server_index = 5;
    n.namespace_uri = "urn:SomeNamespace".into();
    let json = to_value(&n).unwrap();
    assert_eq!(
        json,
        json!({"Id": 1, "Namespace": "urn:SomeNamespace", "ServerUri": 5})
    );
}

#[test]
fn serialize_byte_string() {
    let v = ByteString::from(vec![1, 2, 3, 4]);
    let json = to_value(&v).unwrap();
    assert_eq!(json, json!("AQIDBA=="));
}

#[test]
fn serialize_status_code() {
    let s = from_value::<StatusCode>(json!(0)).unwrap();
    assert_eq!(s, StatusCode::Good);

    let v = StatusCode::Good;
    let json = to_value(&v).unwrap();
    assert_eq!(json, json!(0));

    let v = StatusCode::BadDecodingError;
    let json = to_value(&v).unwrap();
    assert_eq!(json, json!(0x8007_0000i64))
}

#[test]
fn serialize_extension_object() {
    let v = ExtensionObject::null();
    let json = to_value(&v).unwrap();
    assert_eq!(json, json!(null));

    // As json body.
    let argument = Argument {
        name: "Arg".into(),
        data_type: DataTypeId::Double.into(),
        value_rank: 1,
        array_dimensions: Some(vec![3]),
        description: "An argument".into(),
    };

    let v = ExtensionObject::from_message(argument);
    let json = to_value(&v).unwrap();
    assert_eq!(
        json,
        json!({
            "UaTypeId": {
                "Id": ObjectId::Argument_Encoding_DefaultJson as i32
            },
            "UaBody": {
                "Name": "Arg",
                "DataType": {
                    "Id": 11
                },
                "ValueRank": 1,
                "ArrayDimensions": [3],
                "Description": {
                    "Text": "An argument"
                }
            }
        })
    );
}

#[test]
fn serialize_localized_text() {
    let v = LocalizedText::new("en", "Text");
    let json = to_value(&v).unwrap();
    assert_eq!(json, json!({"Locale": "en", "Text": "Text"}));

    let v: LocalizedText = "Text".into();
    let json = to_value(&v).unwrap();
    assert_eq!(json, json!({"Text": "Text"}));
}

#[test]
fn serialize_qualified_name() {
    let v = QualifiedName::new(0, "Test");
    let json = to_value(&v).unwrap();
    assert_eq!(json, json!("Test"));

    let v = QualifiedName::new(2, "Test");
    let json = to_value(&v).unwrap();
    assert_eq!(json, json!("2:Test"));
}

/// Serializes and deserializes a variant. The input json should match
/// what the serialized output is. In some cases, this function may not be useful
/// if the input is not the same as the output.
fn test_ser_de_variant(variant: Variant, expected: Value) {
    // Turn the variant to a json value and compare to expected json value
    let value = to_value(&variant).unwrap();
    println!(
        "Comparing variant as json {} to expected json {}",
        serde_json::to_string(&value).unwrap(),
        serde_json::to_string(&expected).unwrap()
    );
    assert_eq!(value, expected);
    // Parse value back to json and compare to Variant
    let value = from_value::<Variant>(expected).unwrap();
    println!(
        "Comparing parsed variant {:?} to expected variant {:?}",
        value, variant
    );
    assert_eq!(value, variant);
}

/// Deserializes JSON into a Variant and compare to the expected value.
fn test_json_to_variant(json: Value, expected: Variant) {
    let value = from_value::<Variant>(json).unwrap();
    println!(
        "Comparing parsed variant {:?} to expected variant {:?}",
        value, expected
    );
    assert_eq!(value, expected);
}

// These tests ensure serialize / deserialize works with the canonical
// form and with some other input json with missing fields or
// null values that deserialize to the proper values.

#[test]
fn serialize_variant_empty() {
    // Empty (0)
    test_ser_de_variant(Variant::Empty, json!(null));
    test_json_to_variant(json!(null), Variant::Empty);
    test_json_to_variant(json!({"Type": 0}), Variant::Empty);
    test_json_to_variant(json!({"Type": 0, "Body": null}), Variant::Empty);
}

#[test]
fn serialize_variant_boolean() {
    // Boolean
    test_ser_de_variant(Variant::Boolean(true), json!({"Type": 1, "Body": true}));
    test_ser_de_variant(Variant::Boolean(false), json!({"Type": 1, "Body": false}));
}

#[test]
fn serialize_variant_numeric() {
    // 8, 16 and 32-bit numerics. Missing body should be treated as the default
    // numeric value, i.e. 0
    test_ser_de_variant(Variant::SByte(-1), json!({"Type": 2, "Body": -1}));
    test_json_to_variant(json!({"Type": 2}), Variant::SByte(0));
    test_ser_de_variant(Variant::Byte(1), json!({"Type": 3, "Body": 1}));
    test_json_to_variant(json!({"Type": 3}), Variant::Byte(0));
    test_ser_de_variant(Variant::Int16(-2), json!({"Type": 4, "Body": -2}));
    test_json_to_variant(json!({"Type": 4}), Variant::Int16(0));
    test_ser_de_variant(Variant::UInt16(2), json!({"Type": 5, "Body": 2}));
    test_json_to_variant(json!({"Type": 5}), Variant::UInt16(0));
    test_ser_de_variant(Variant::Int32(-3), json!({"Type": 6, "Body": -3}));
    test_json_to_variant(json!({"Type": 6}), Variant::Int32(0));
    test_ser_de_variant(Variant::UInt32(3), json!({"Type": 7, "Body": 3}));
    test_json_to_variant(json!({"Type": 7}), Variant::UInt32(0));

    // Int64 & UInt64 are encoded as strings. Missing body should be treated as the default
    // numeric value, i.e. 0
    test_ser_de_variant(Variant::Int64(-1i64), json!({"Type": 8, "Body": -1}));
    test_json_to_variant(json!({"Type": 8}), Variant::Int64(0));
    test_ser_de_variant(Variant::UInt64(1000u64), json!({"Type": 9, "Body": 1000}));
    test_json_to_variant(json!({"Type": 9}), Variant::UInt64(0));
}

#[test]
fn serialize_variant_float() {
    // Missing body should be treated as the default numeric value, i.e. 0.0

    // This test doesn't call test_json_to_variant because the roundtrip
    // can lead to precision issues. Instead it pulls the values straight out
    // and compares after casting.
    let f32_val = 123.456f32;
    let variant = Variant::Float(f32_val);
    let value = to_value(&variant).unwrap();
    assert_eq!(*value.get("Type").unwrap(), json!(10));
    let body = value.get("Body").unwrap();
    assert_eq!(body.as_f64().unwrap() as f32, f32_val);

    // Test for NaN
    let v = to_value(&Variant::Float(f32::NAN)).unwrap();
    let json = json!({"Type": 10, "Body": "NaN"});
    assert_eq!(v, json);

    // This test is a bit different because assert_eq won't work since comparing NaN to itself always yields
    // false so impossible to use assert_eq!().
    let value = from_value::<Variant>(json!({"Type": 10, "Body": "NaN"})).unwrap();
    if let Variant::Float(v) = value {
        assert!(v.is_nan())
    } else {
        panic!("Expected NaN");
    }

    // Tests for Infinity
    test_ser_de_variant(
        Variant::Float(f32::INFINITY),
        json!({"Type": 10, "Body": "Infinity"}),
    );
    test_ser_de_variant(
        Variant::Float(f32::NEG_INFINITY),
        json!({"Type": 10, "Body": "-Infinity"}),
    );
}

#[test]
fn serialize_variant_double() {
    // Double
    test_ser_de_variant(
        Variant::Double(-451.001),
        json!({"Type": 11, "Body": -451.001}),
    );
    test_json_to_variant(json!({"Type": 11}), Variant::Double(0.0));

    let v = to_value(&Variant::Double(f64::NAN)).unwrap();
    let json = json!({"Type": 11, "Body": "NaN"});
    assert_eq!(v, json);

    // This test is a bit different because assert_eq won't work since comparing NaN to itself always yields
    // false so impossible to use assert_eq!().
    let value = from_value::<Variant>(json!({"Type": 11, "Body": "NaN"})).unwrap();
    if let Variant::Double(v) = value {
        assert!(v.is_nan())
    } else {
        panic!("Expected NaN");
    }

    // Tests for Infinity
    test_ser_de_variant(
        Variant::Double(f64::INFINITY),
        json!({"Type": 11, "Body": "Infinity"}),
    );
    test_ser_de_variant(
        Variant::Double(f64::NEG_INFINITY),
        json!({"Type": 11, "Body": "-Infinity"}),
    );
}

#[test]
fn serialize_variant_string() {
    // String (12)
    test_ser_de_variant(
        Variant::String(UAString::from("Hello")),
        json!({"Type": 12, "Body": "Hello"}),
    );
    test_ser_de_variant(
        Variant::String(UAString::null()),
        json!({"Type": 12, "Body": null}),
    );
    test_json_to_variant(json!({"Type": 12}), Variant::String(UAString::null()));
    test_json_to_variant(
        json!({"Type": 12, "Body": null}),
        Variant::String(UAString::null()),
    );
}

#[test]
fn serialize_variant_datetime() {
    // DateTime (13)
    test_ser_de_variant(
        Variant::DateTime(Box::new(DateTime::ymd(2000, 1, 1))),
        json!({
            "Type": 13, "Body": "2000-01-01T00:00:00.000Z"
        }),
    );
}

#[test]
fn serialize_variant_guid() {
    // Guid (14)
    let guid = Guid::new();
    test_ser_de_variant(
        Variant::Guid(Box::new(guid.clone())),
        json!({"Type": 14, "Body": guid.to_string()}),
    );
    test_ser_de_variant(
        Variant::Guid(Box::new(Guid::null())),
        json!({"Type": 14, "Body": "00000000-0000-0000-0000-000000000000"}),
    );
}

#[test]
fn serialize_variant_bytestring() {
    // ByteString (15)
    let v = ByteString::from(&[0x1, 0x2, 0x3, 0x4]);
    let base64 = v.as_base64();
    test_ser_de_variant(Variant::ByteString(v), json!({"Type": 15, "Body": base64}));
    test_ser_de_variant(
        Variant::ByteString(ByteString::null()),
        json!({"Type": 15, "Body": null}),
    );
}

/*
#[test]
fn serialize_variant_xmlelement() {
    // TODO XmlElement (16)
    todo!()
}
 */

#[test]
fn serialize_variant_node_id() {
    // NodeId (17)
    test_ser_de_variant(
        Variant::NodeId(Box::new(NodeId::new(5, "Hello World"))),
        json!({"Type": 17, "Body": { "IdType": 1, "Id": "Hello World", "Namespace": 5}}),
    );
}

#[test]
fn serialize_variant_expanded_node_id() {
    // ExpandedNodeId (18)
    test_ser_de_variant(
        Variant::ExpandedNodeId(Box::new(ExpandedNodeId::new((
            NodeId::new(5, "Hello World"),
            20,
        )))),
        json!({"Type": 18, "Body": { "IdType": 1, "Id": "Hello World", "Namespace": 5, "ServerUri": 20}}),
    );
}

#[test]
fn serialize_variant_status_code() {
    // StatusCode (19)
    test_ser_de_variant(
        Variant::StatusCode(StatusCode::Good),
        json!({"Type": 19, "Body": 0}),
    );

    test_ser_de_variant(
        Variant::StatusCode(StatusCode::BadServerHalted),
        json!({"Type": 19, "Body": 0x800E0000u32}),
    );
}

#[test]
fn serialize_variant_qualified_name() {
    // QualifiedName (20)
    test_ser_de_variant(
        Variant::QualifiedName(Box::new(QualifiedName::null())),
        json!({"Type": 20, "Body": null}),
    );
}

#[test]
fn serialize_variant_localized_text() {
    // LocalizedText (21)
    test_ser_de_variant(
        Variant::LocalizedText(Box::new(LocalizedText::null())),
        json!({"Type": 21, "Body": {}}),
    );
}

#[test]
fn serialize_variant_extension_object() {
    // ExtensionObject (22)
    test_ser_de_variant(
        Variant::ExtensionObject(ExtensionObject::null()),
        json!({"Type": 22, "Body": null}),
    );
    let argument = Argument {
        name: "Arg".into(),
        data_type: DataTypeId::Double.into(),
        value_rank: 1,
        array_dimensions: Some(vec![3]),
        description: "An argument".into(),
    };
    // Note: There's a fair bit more to do here, but it's all quite complicated.
    // First, for some insane reason structs with optional fields are supposed to
    // have an "encoding mask".
    // Second, all default values are supposed to be skipped.
    // Neither of these are easy to do, and will probably require a custom
    // serialize/deserialize macro.
    test_ser_de_variant(
        Variant::ExtensionObject(ExtensionObject::from_message(argument)),
        json!({
            "Type": 22,
            "Body": {
                "UaTypeId": {
                    "Id": ObjectId::Argument_Encoding_DefaultJson as i32
                },
                "UaBody": {
                    "Name": "Arg",
                    "DataType": {
                        "Id": 11
                    },
                    "ValueRank": 1,
                    "ArrayDimensions": [3],
                    "Description": {
                        "Text": "An argument"
                    }
                }
            }
        }),
    );
}

#[test]
fn serialize_variant_data_value() {
    // DataValue (23)
    let mut v = DataValue::null();

    let now = DateTime::rfc3339_now();

    v.server_timestamp = Some(now);
    v.source_timestamp = Some(now);

    let now_str = now.to_rfc3339();

    test_ser_de_variant(
        Variant::DataValue(Box::new(v)),
        json!({"Type": 23, "Body": { "ServerTimestamp": now_str.clone(), "SourceTimestamp": now_str }}),
    );
}

#[test]
fn serialize_variant_variant() {
    // Variant (24)
    test_ser_de_variant(
        Variant::Variant(Box::new(Variant::Empty)),
        json!({"Type": 24, "Body": null}),
    );

    test_ser_de_variant(
        Variant::Variant(Box::new(Variant::Double(1.2))),
        json!({"Type": 24, "Body": { "Type": 11, "Body": 1.2 }}),
    );
}

#[test]
fn serialize_variant_diagnostic_info() {
    // DiagnosticInfo (25)
    test_ser_de_variant(
        Variant::DiagnosticInfo(Box::new(DiagnosticInfo::null())),
        json!({"Type": 25, "Body": {}}),
    );

    test_ser_de_variant(
        Variant::DiagnosticInfo(Box::new(DiagnosticInfo {
            symbolic_id: Some(2),
            namespace_uri: Some(3),
            additional_info: Some("info".into()),
            locale: Some(4),
            ..Default::default()
        })),
        json!({"Type": 25, "Body": {
            "SymbolicId": 2,
            "NamespaceUri": 3,
            "AdditionalInfo": "info",
            "Locale": 4,
        }}),
    )
}

#[test]
fn serialize_variant_single_dimension_array() {
    test_ser_de_variant(
        Variant::from(vec![1, 2, 3]),
        json!({"Type": 6, "Body": [1, 2, 3]}),
    );

    test_ser_de_variant(
        Variant::from(vec![
            LocalizedText::new("en", "Test"),
            LocalizedText::new("en", "Test2"),
        ]),
        json!({"Type": 21, "Body": [{
            "Locale": "en",
            "Text": "Test"
        }, {
            "Locale": "en",
            "Text": "Test2"
        }]}),
    )
}

#[test]
fn serialize_variant_multi_dimension_array() {
    let v = Array::new_multi(
        VariantScalarTypeId::Int32,
        [1, 2, 3, 4, 5, 6]
            .into_iter()
            .map(Variant::from)
            .collect::<Vec<_>>(),
        vec![2, 3],
    )
    .unwrap();
    test_ser_de_variant(
        v.into(),
        json!({
            "Type": 6,
            "Body": [1, 2, 3, 4, 5, 6],
            "Dimensions": [2, 3]
        }),
    );
}

#[test]
fn extension_object_round_trip() {
    let v = EUInformation {
        namespace_uri: "some.namespace.uri".into(),
        unit_id: 15,
        display_name: "Degrees C".into(),
        description: "Temperature in degrees Celsius".into(),
    };
    let obj = ExtensionObject::from_message(v.clone());
    // This is the reason why we want to store the extension object as a dynamic object,
    // note that the rest of the code does not concretely reference EUInformation. We can
    // work with structures from OPC-UA without actually knowing what they are, concretely.
    // This is especially useful for clients that are server agnostic.

    // Serialize to binary
    let ctx_r = ContextOwned::default();
    let ctx = ctx_r.context();
    let mut buf = Vec::with_capacity(obj.byte_len(&ctx));
    let mut cursor = Cursor::new(&mut buf);
    crate::BinaryEncodable::encode(&obj, &mut cursor, &ctx).unwrap();
    // Deserialize from binary
    cursor.seek(std::io::SeekFrom::Start(0)).unwrap();
    let obj_2: ExtensionObject = crate::BinaryDecodable::decode(&mut cursor, &ctx).unwrap();
    // Write it to JSON
    let mut buf2 = Vec::new();
    let mut cursor2 = Cursor::new(&mut buf2);
    let mut serializer = JsonStreamWriter::new(&mut cursor2 as &mut dyn Write);
    JsonEncodable::encode(&obj_2, &mut serializer, &ctx).unwrap();
    serializer.finish_document().unwrap();
    let value: Value = serde_json::from_slice(&buf2).unwrap();

    assert_eq!(
        value,
        json!({
            "UaBody": {
                "NamespaceUri": "some.namespace.uri",
                "UnitId": 15,
                "DisplayName": {
                    "Text": "Degrees C"
                },
                "Description": {
                    "Text": "Temperature in degrees Celsius"
                }
            },
            "UaTypeId": {
                "Id": ObjectId::EUInformation_Encoding_DefaultJson as u32
            }
        })
    );

    // Deserialize it back from JSON.
    let mut cursor3 = Cursor::new(&buf2);
    let mut reader = JsonStreamReader::new(&mut cursor3 as &mut dyn Read);
    let obj_3: ExtensionObject = JsonDecodable::decode(&mut reader, &ctx).unwrap();
    // Verify that we've completed a round-trip and ended up with something identical to the original object.
    assert_eq!(obj_3, obj);
}

#[test]
fn test_custom_struct_with_optional() {
    mod opcua {
        pub(super) use crate as types;
    }

    #[derive(Debug, PartialEq, Clone, JsonDecodable, JsonEncodable, UaNullable)]
    struct MyStructWithOptionalFields {
        foo: i32,
        #[opcua(optional)]
        my_opt: Option<LocalizedText>,
        #[opcua(optional)]
        my_opt_2: Option<i32>,
    }

    let st = MyStructWithOptionalFields {
        foo: 123,
        my_opt: None,
        my_opt_2: None,
    };

    let v = to_value(&st).unwrap();
    assert_eq!(
        v,
        json!({
            "EncodingMask": 0,
            "Foo": 123,
        })
    );
    let st_cmp = from_value(v).unwrap();
    assert_eq!(st, st_cmp);

    let st = MyStructWithOptionalFields {
        foo: 123,
        my_opt: None,
        my_opt_2: Some(321),
    };
    let v = to_value(&st).unwrap();
    assert_eq!(
        v,
        json!({
            "EncodingMask": 2,
            "Foo": 123,
            "MyOpt2": 321,
        })
    );
    let st_cmp = from_value(v).unwrap();
    assert_eq!(st, st_cmp);

    let st = MyStructWithOptionalFields {
        foo: 123,
        my_opt: Some(LocalizedText::new("Foo", "Bar")),
        my_opt_2: Some(321),
    };
    let v = to_value(&st).unwrap();
    assert_eq!(
        v,
        json!({
            "EncodingMask": 3,
            "Foo": 123,
            "MyOpt2": 321,
            "MyOpt": {
                "Locale": "Foo",
                "Text": "Bar"
            }
        })
    );
    let st_cmp = from_value(v).unwrap();
    assert_eq!(st, st_cmp);
}

#[test]
fn test_custom_union() {
    mod opcua {
        pub(super) use crate as types;
    }

    #[derive(Debug, PartialEq, Clone, JsonDecodable, JsonEncodable, UaNullable)]
    enum MyUnion {
        Var1(i32),
        #[opcua(rename = "EUInfo")]
        Var2(EUInformation),
        Var3(f64),
    }

    let st = MyUnion::Var1(123);
    let v = to_value(&st).unwrap();
    assert_eq!(
        v,
        json!({
            "SwitchField": 1,
            "Var1": 123
        })
    );
    let st_cmp = from_value(v).unwrap();
    assert_eq!(st, st_cmp);

    let st = MyUnion::Var2(EUInformation {
        namespace_uri: "test".into(),
        unit_id: 123,
        display_name: "test".into(),
        description: "desc".into(),
    });
    let v = to_value(&st).unwrap();
    assert_eq!(
        v,
        json!({
            "SwitchField": 2,
            "EUInfo": {
                "NamespaceUri": "test",
                "UnitId": 123,
                "DisplayName": {
                    "Text": "test",
                },
                "Description": {
                    "Text": "desc",
                }
            }
        })
    );
    let st_cmp = from_value(v).unwrap();
    assert_eq!(st, st_cmp);

    let st = MyUnion::Var3(123.123);
    let v = to_value(&st).unwrap();
    assert_eq!(
        v,
        json!({
            "SwitchField": 3,
            "Var3": 123.123
        })
    );
    let st_cmp = from_value(v).unwrap();
    assert_eq!(st, st_cmp);
}

#[test]
fn test_custom_union_nullable() {
    mod opcua {
        pub(super) use crate as types;
    }

    #[derive(Debug, PartialEq, Clone, JsonDecodable, JsonEncodable, UaNullable)]
    enum MyUnion {
        Var1(i32),
        Null,
    }

    let st = MyUnion::Var1(123);
    let v = to_value(&st).unwrap();
    assert_eq!(
        v,
        json!({
            "SwitchField": 1,
            "Var1": 123
        })
    );
    let st_cmp = from_value(v).unwrap();
    assert_eq!(st, st_cmp);

    let st = MyUnion::Null;
    let v = to_value(&st).unwrap();
    assert_eq!(
        v,
        json!({
            "SwitchField": 0
        })
    );
    let st_cmp = from_value(v).unwrap();
    assert_eq!(st, st_cmp);
}

#[test]
fn test_xml_in_json() {
    let json = json!({
        "UaTypeId": {
            "Id": ObjectId::EUInformation_Encoding_DefaultXml as u32
        },
        "UaEncoding": 2,
        "UaBody": "
        <EUInformation>
            <NamespaceUri>https://my.namespace.uri</NamespaceUri>
            <UnitId>1</UnitId>
            <DisplayName><Locale>en</Locale><Text>MyUnit</Text></DisplayName>
            <Description><Locale>en</Locale><Text>MyDesc</Text></Description>
        </EUInformation>"
    });
    let ctx_r = ContextOwned::default();
    let ctx = ctx_r.context();
    let json = json.to_string();
    let mut cursor = Cursor::new(json.as_bytes());
    let mut reader = JsonStreamReader::new(&mut cursor as &mut dyn Read);
    let obj_3: ExtensionObject = JsonDecodable::decode(&mut reader, &ctx).unwrap();

    assert_eq!(
        &EUInformation {
            namespace_uri: "https://my.namespace.uri".into(),
            unit_id: 1,
            display_name: LocalizedText::new("en", "MyUnit"),
            description: LocalizedText::new("en", "MyDesc"),
        },
        obj_3.inner_as().unwrap()
    );
}

#[test]
fn test_binary_in_json() {
    let json = json!({
        "UaTypeId": {
            "Id": ObjectId::EUInformation_Encoding_DefaultBinary as u32
        },
        "UaEncoding": 1,
        "UaBody": "
        GAAAAGh0dHBzOi8vbXkubmFtZXNwYWNlLnVya
        QEAAAADAgAAAGVuBgAAAE15VW5pdAMCAAAAZW
        4GAAAATXlEZXNj"
    });

    let rf = EUInformation {
        namespace_uri: "https://my.namespace.uri".into(),
        unit_id: 1,
        display_name: LocalizedText::new("en", "MyUnit"),
        description: LocalizedText::new("en", "MyDesc"),
    };
    let ctx_r = ContextOwned::default();
    let ctx = ctx_r.context();

    let mut buf = Vec::with_capacity(rf.byte_len(&ctx));
    let mut cursor = Cursor::new(&mut buf);
    crate::BinaryEncodable::encode(&rf, &mut cursor, &ctx).unwrap();
    println!("{}", base64::engine::general_purpose::STANDARD.encode(buf));

    let json = json.to_string();
    let mut cursor = Cursor::new(json.as_bytes());
    let mut reader = JsonStreamReader::new(&mut cursor as &mut dyn Read);
    let obj_3: ExtensionObject = JsonDecodable::decode(&mut reader, &ctx).unwrap();

    assert_eq!(
        &EUInformation {
            namespace_uri: "https://my.namespace.uri".into(),
            unit_id: 1,
            display_name: LocalizedText::new("en", "MyUnit"),
            description: LocalizedText::new("en", "MyDesc"),
        },
        obj_3.inner_as().unwrap()
    );
}
