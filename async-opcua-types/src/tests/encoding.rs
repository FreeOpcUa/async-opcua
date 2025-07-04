use std::{
    io::{Cursor, Write},
    str::FromStr,
};

use opcua_xml::XmlStreamWriter;

use crate::{
    encoding::{BinaryDecodable, DecodingOptions},
    string::UAString,
    tests::*,
    write_u8, Array, ByteString, ContextOwned, DataValue, DateTime, DepthGauge, DiagnosticInfo,
    EUInformation, EncodingMask, ExpandedNodeId, ExtensionObject, Guid, LocalizedText,
    NamespaceMap, NodeId, ObjectId, QualifiedName, Variant, VariantScalarTypeId, XmlElement,
};

#[test]
fn encoding_bool() {
    serialize_test(true);
    serialize_test(false);
}

#[test]
fn encoding_sbyte() {
    serialize_test(0_i8);
    serialize_test(100_i8);
    serialize_test(-90_i8);
}

#[test]
fn encoding_byte() {
    serialize_test(0_u8);
    serialize_test(255_u8);
    serialize_test(90_u8);
}

#[test]
fn encoding_int16() {
    serialize_test(0_i16);
    serialize_test(-17000_i16);
    serialize_test(32000_i16);
}

#[test]
fn encoding_uint16() {
    serialize_test(0_u16);
    serialize_test(57000_u16);
    serialize_test(32000_u16);
}

#[test]
fn encoding_int32() {
    serialize_test(0_i32);
    serialize_test(-17444000_i32);
    serialize_test(32004440_i32);
}

#[test]
fn encoding_uint32() {
    serialize_test(0_u32);
    serialize_test(57055500_u32);
    serialize_test(32555000_u32);
}

#[test]
fn encoding_int64() {
    serialize_test(0_i64);
    serialize_test(-17442224000_i64);
    serialize_test(32022204440_i64);
}

#[test]
fn encoding_uint64() {
    serialize_test(0_u64);
    serialize_test(57054445500_u64);
    serialize_test(34442555000_u64);
}

#[test]
fn encoding_f32() {
    serialize_test(0 as f32);
    serialize_test(12.4342_f32);
    serialize_test(5686.222_f32);
}

#[test]
fn encoding_f64() {
    serialize_test(0 as f64);
    serialize_test(12.43424324234_f64);
    serialize_test(5686.222342342_f64);
}

#[test]
fn encoding_string() {
    // Null
    serialize_test(UAString::null());
    // UTF-8 strings
    serialize_test(UAString::from(""));
    serialize_test(UAString::from("ショッピング"));
    serialize_test(UAString::from("This is a test"));
}

#[test]
fn encode_string_part_6_5224() {
    // Sample from OPCUA Part 6 - 5.2.2.4
    let expected = [0x06, 0x00, 0x00, 0x00, 0xE6, 0xB0, 0xB4, 0x42, 0x6F, 0x79];
    let input = UAString::from("水Boy");
    serialize_and_compare(input, &expected);
}

#[test]
fn decode_string_malformed_utf8() {
    // Test that string returns a decoding error when it receives some malformed UTF-8
    // Bytes below are a mangled 水Boy, missing a byte
    let bytes = [0x06, 0x00, 0x00, 0xE6, 0xB0, 0xB4, 0x42, 0x6F, 0x79];
    let mut stream = Cursor::new(bytes);
    let ctx = ContextOwned::default();
    assert_eq!(
        <UAString as BinaryDecodable>::decode(&mut stream, &ctx.context())
            .unwrap_err()
            .status(),
        StatusCode::BadDecodingError
    );
}

#[test]
fn encoding_datetime() {
    let now = DateTime::now();
    serialize_test(now);

    let epoch = DateTime::epoch();
    serialize_test(epoch);

    let endtimes = DateTime::endtimes();
    serialize_test(endtimes);

    // serialize a date below Jan 1 1601 ensure it decodes as epoch
    let before_epoch = DateTime::ymd_hms(1599, 1, 1, 0, 0, 0);
    serialize_test_expected(before_epoch, DateTime::epoch());

    // serialize a date after Dec 31 9999 ensure it decodes as endtimes
    let after_endtimes = DateTime::ymd_hms(10000, 1, 1, 0, 0, 0);
    serialize_test_expected(after_endtimes, DateTime::endtimes());
}

#[test]
fn encoding_guid() {
    let guid = Guid::from_str("F0001234-FACE-BEEF-0102-030405060708").unwrap();
    assert_eq!("f0001234-face-beef-0102-030405060708", format!("{guid:?}"));
    let new_guid = serialize_test_and_return(guid.clone());
    assert_eq!(
        "f0001234-face-beef-0102-030405060708",
        format!("{new_guid:?}")
    );
    serialize_test(guid);
}

#[test]
fn encode_guid_5226() {
    // Sample from OPCUA Part 6 - 5.2.2.6
    let expected_bytes = [
        0x91, 0x2B, 0x96, 0x72, 0x75, 0xFA, 0xE6, 0x4A, 0x8D, 0x28, 0xB4, 0x04, 0xDC, 0x7D, 0xAF,
        0x63,
    ];
    let guid = Guid::from_str("912b9672-75fa-e64a-8D28-B404DC7DAF63").unwrap();
    serialize_and_compare(guid, &expected_bytes);
}

#[test]
fn node_id_2byte_numeric() {
    // Sample from OPCUA Part 6 - 5.2.2.9
    let node_id = NodeId::new(0, 0x72_u32);
    let expected_bytes = [0x0, 0x72];
    serialize_and_compare(node_id.clone(), &expected_bytes);

    serialize_test(node_id);
}

#[test]
fn node_id_4byte_numeric() {
    // Sample from OPCUA Part 6 - 5.2.2.9
    let node_id = NodeId::new(5, 1025);
    assert!(node_id.is_numeric());
    // NOTE: Example is wrong in 1.0.3, says 0x40, not 0x4
    let expected_bytes = [0x1, 0x5, 0x1, 0x4];
    serialize_and_compare(node_id, &expected_bytes);

    // Serialize / deserialize to itself
    let node_id = NodeId::new(5, 1025);
    serialize_test(node_id);
}

#[test]
fn node_id_large_namespace() {
    let node_id = NodeId::new(0x100, 1);
    assert!(node_id.is_numeric());

    let expected_bytes = [0x2, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0];
    serialize_and_compare(node_id.clone(), &expected_bytes);

    serialize_test(node_id);
}

#[test]
fn node_id_large_id() {
    let node_id = NodeId::new(1, 0xdeadbeef_u32);
    assert!(node_id.is_numeric());

    let expected_bytes = [0x2, 0x1, 0x0, 0xef, 0xbe, 0xad, 0xde];
    serialize_and_compare(node_id.clone(), &expected_bytes);

    serialize_test(node_id);
}

#[test]
fn node_id_string_part_6_5229() {
    // Sample from OPCUA Part 6 - 5.2.2.9
    let node_id = NodeId::new(1, "Hot水");
    assert!(node_id.is_string());
    // NOTE: Example is wrong in 1.0.3, says 'r' instead of 'H'
    let expected_bytes = [
        0x03, 0x1, 0x0, 0x6, 0x0, 0x0, 0x0, 0x48, 0x6F, 0x74, 0xE6, 0xB0, 0xB4,
    ];
    serialize_and_compare(node_id.clone(), &expected_bytes);

    serialize_test(node_id);
}

#[test]
fn node_id_guid() {
    let guid = Guid::from_str("912b9672-75fa-e64a-8D28-B404DC7DAF63").unwrap();
    let node_id = NodeId::new(1, guid);
    assert!(node_id.is_guid());
    serialize_test(node_id);
}

#[test]
fn node_id_byte_string() {
    serialize_test(ByteString::null());
    let node_id = NodeId::new(30, ByteString::from(b"this is a byte string"));
    assert!(node_id.is_byte_string());
    serialize_test(node_id);
}

#[test]
fn localized_text() {
    let t = LocalizedText {
        locale: UAString::null(),
        text: UAString::null(),
    };
    serialize_test(t);

    let t = LocalizedText {
        locale: UAString::from("Hello world"),
        text: UAString::null(),
    };
    serialize_test(t);

    let t = LocalizedText {
        locale: UAString::null(),
        text: UAString::from("Now is the winter of our discontent"),
    };
    serialize_test(t);

    let t = LocalizedText {
        locale: UAString::from("ABCDEFG"),
        text: UAString::from("Now is the winter of our discontent"),
    };
    serialize_test(t);
}

#[test]
fn expanded_node_id() {
    let node_id = ExpandedNodeId::new(NodeId::new(200, 2000));
    serialize_test(node_id);

    let mut node_id = ExpandedNodeId::new(NodeId::new(200, 2000));
    node_id.namespace_uri = UAString::from("test");
    serialize_test(node_id);

    let mut node_id = ExpandedNodeId::new(NodeId::new(200, 2000));
    node_id.server_index = 500;

    serialize_test(node_id);

    let mut node_id = ExpandedNodeId::new(NodeId::new(200, 2000));
    node_id.namespace_uri = UAString::from("test2");
    node_id.server_index = 50330;
    serialize_test(node_id);
}

#[test]
fn qualified_name() {
    let qname = QualifiedName {
        namespace_index: 100,
        name: UAString::from("this is a qualified name"),
    };
    serialize_test(qname);
}

#[test]
fn variant() {
    use std::mem;
    println!(
        "Size of a variant in bytes is {}",
        mem::size_of::<Variant>()
    );

    // Boolean
    let v = Variant::Boolean(true);
    serialize_test(v);
    // SByte
    let v = Variant::SByte(-44);
    serialize_test(v);
    // Byte
    let v = Variant::Byte(255);
    serialize_test(v);
    // Int16
    let v = Variant::Int16(-20000);
    serialize_test(v);
    // UInt16
    let v = Variant::UInt16(55778);
    serialize_test(v);
    // Int32
    let v = Variant::Int32(-9999999);
    serialize_test(v);
    // UInt32
    let v = Variant::UInt32(24424244);
    serialize_test(v);
    // Int64
    let v = Variant::Int64(-384747424424244);
    serialize_test(v);
    // UInt64
    let v = Variant::UInt64(9384747424422314244);
    serialize_test(v);
    // Float
    let v = Variant::Float(77.33f32);
    serialize_test(v);
    // Double
    let v = Variant::Double(99.123f64);
    serialize_test(v);
    // DateTime
    let v = Variant::from(DateTime::now());
    serialize_test(v);
    // UAString
    let v = Variant::from(UAString::from("Hello Everybody"));
    serialize_test(v);
    // ByteString
    let v = Variant::from(ByteString::from(b"Everything or nothing"));
    serialize_test(v);
    // XmlElement
    let v = Variant::from(XmlElement::from("The world wonders"));
    serialize_test(v);
    // NodeId(NodeId),
    let v: NodeId = ObjectId::AddNodesItem_Encoding_DefaultBinary.into();
    let v = Variant::from(v);
    serialize_test(v);
    let v = Variant::from(NodeId::new(99, "hello everyone"));
    serialize_test(v);
    // ExpandedNodeId
    let v: ExpandedNodeId = ObjectId::AddNodesItem_Encoding_DefaultBinary.into();
    let v = Variant::from(v);
    serialize_test(v);
    // StatusCode
    let v = Variant::from(StatusCode::BadTcpMessageTypeInvalid);
    serialize_test(v);
    // QualifiedName
    let v = Variant::from(QualifiedName {
        namespace_index: 100,
        name: UAString::from("this is a qualified name"),
    });
    serialize_test(v);
    // LocalizedText
    let v = Variant::from(LocalizedText {
        locale: UAString::from("Hello everyone"),
        text: UAString::from("This text is localized"),
    });
    serialize_test(v);
    // ExtensionObject
    let v = Variant::from(ExtensionObject::null());
    serialize_test(v);
    // DataValue Variant
    let v = Variant::from(DataValue {
        value: Some(Variant::Double(1000f64)),
        status: Some(StatusCode::GoodClamped),
        source_timestamp: Some(DateTime::now()),
        source_picoseconds: Some(333),
        server_timestamp: Some(DateTime::now()),
        server_picoseconds: Some(666),
    });
    serialize_test(v);
    // Variant in Variant
    let v = Variant::Variant(Box::new(Variant::from(8u8)));
    serialize_test(v);
    // Diagnostic
    let v = Variant::from(DiagnosticInfo {
        symbolic_id: Some(99),
        namespace_uri: Some(437437),
        locale: Some(333),
        localized_text: Some(233),
        additional_info: Some(UAString::from("Nested diagnostic")),
        inner_status_code: Some(StatusCode::Good),
        inner_diagnostic_info: None,
    });
    serialize_test(v);
    // DataValue
    let v = DataValue {
        value: Some(Variant::Double(1000f64)),
        status: Some(StatusCode::GoodClamped),
        source_timestamp: Some(DateTime::now()),
        source_picoseconds: Some(333),
        server_timestamp: Some(DateTime::now()),
        server_picoseconds: Some(666),
    };
    serialize_test(v);
}

#[test]
fn variant_single_dimension_array() {
    let values = vec![
        Variant::Int32(100),
        Variant::Int32(200),
        Variant::Int32(300),
    ];
    let v = Variant::from((VariantScalarTypeId::Int32, values));
    serialize_test(v);
}

#[test]
fn variant_multi_dimension_array() {
    let values = vec![
        Variant::Int32(100),
        Variant::Int32(200),
        Variant::Int32(300),
        Variant::Int32(400),
        Variant::Int32(500),
        Variant::Int32(600),
    ];
    let dimensions = vec![3u32, 2u32];
    let v = Variant::from((VariantScalarTypeId::Int32, values, dimensions));
    serialize_test(v);
}

#[test]
fn diagnostic_info() {
    let mut d = DiagnosticInfo {
        symbolic_id: None,
        namespace_uri: None,
        locale: None,
        localized_text: None,
        additional_info: None,
        inner_status_code: None,
        inner_diagnostic_info: None,
    };
    serialize_test(d.clone());

    d.symbolic_id = Some(25);

    assert_eq!(d.encoding_mask().bits(), 0x1);

    d.namespace_uri = Some(100);
    assert_eq!(d.encoding_mask().bits(), 0x3);

    d.localized_text = Some(120);
    assert_eq!(d.encoding_mask().bits(), 0x7);

    d.locale = Some(110);
    assert_eq!(d.encoding_mask().bits(), 0xf);

    d.additional_info = Some(UAString::from("Hello world"));
    assert_eq!(d.encoding_mask().bits(), 0x1f);

    d.inner_status_code = Some(StatusCode::BadArgumentsMissing);
    assert_eq!(d.encoding_mask().bits(), 0x3f);

    serialize_test(d.clone());

    d.inner_diagnostic_info = Some(Box::new(DiagnosticInfo {
        symbolic_id: Some(99),
        namespace_uri: Some(437437),
        locale: Some(333),
        localized_text: Some(233),
        additional_info: Some(UAString::from("Nested diagnostic")),
        inner_status_code: Some(StatusCode::Good),
        inner_diagnostic_info: None,
    }));

    serialize_test(d.clone());
}

#[test]
fn argument() {
    serialize_test(Argument {
        name: UAString::from("arg"),
        data_type: NodeId::null(),
        value_rank: 1,
        array_dimensions: Some(vec![10]),
        description: LocalizedText::new("foo", "bar"),
    });
}

// test decoding of an null array  null != empty!
#[test]
fn null_array() {
    // @FIXME currently creating an null array via Array or Variant is not possible so do it by hand
    let vec = Vec::new();
    let ctx_f = ContextOwned::default();
    let ctx = ctx_f.context();
    let mut stream = Cursor::new(vec);
    let mask = EncodingMask::BOOLEAN | EncodingMask::ARRAY_MASK;
    mask.encode(&mut stream, &ctx).unwrap();
    let length = 0i32;
    length.encode(&mut stream, &ctx).unwrap();
    let actual = stream.into_inner();
    let mut stream = Cursor::new(actual);
    let arr = Variant::decode(&mut stream, &ctx).unwrap();
    assert_eq!(
        arr,
        Variant::Array(Box::new(Array {
            value_type: VariantScalarTypeId::Boolean,
            values: Vec::new(),
            dimensions: Some(Vec::new())
        }))
    );
}

#[test]
fn deep_encoding() {
    let decoding_options = DecodingOptions {
        decoding_depth_gauge: DepthGauge::new(2),
        ..Default::default()
    };

    let _n = NodeId::new(2, "Hello world");

    let d4 = Variant::from(1);
    let d3 = Variant::Variant(Box::new(d4));
    let d2 = Variant::Variant(Box::new(d3));

    let ctx_f = ContextOwned::new_default(NamespaceMap::new(), decoding_options);
    let ctx = ctx_f.context();

    // This should decode
    let mut stream = serialize_as_stream(d2.clone());
    assert_eq!(Variant::decode(&mut stream, &ctx).unwrap(), d2);

    // This should not decode, too deep
    let d1 = Variant::Variant(Box::new(d2));
    let mut stream = serialize_as_stream(d1);
    let res = Variant::decode(&mut stream, &ctx);
    assert_eq!(res.unwrap_err().status(), StatusCode::BadDecodingError);
}

#[test]
fn test_custom_struct_with_optional() {
    mod opcua {
        pub(super) use crate as types;
    }

    #[derive(Debug, PartialEq, Clone, BinaryDecodable, BinaryEncodable)]
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
    let ctx_f = ContextOwned::default();
    let ctx = ctx_f.context();
    // Byte length reflects that optional fields are left out.
    assert_eq!(st.byte_len(&ctx), 4 + 4);

    serialize_test(st);

    let st = MyStructWithOptionalFields {
        foo: 123,
        my_opt: None,
        my_opt_2: Some(321),
    };
    assert_eq!(st.byte_len(&ctx), 4 + 4 + 4);
    serialize_test(st);

    let st = MyStructWithOptionalFields {
        foo: 123,
        my_opt: Some(LocalizedText::new("Foo", "Bar")),
        my_opt_2: Some(321),
    };
    assert_eq!(
        st.byte_len(&ctx),
        4 + 4 + 4 + st.my_opt.as_ref().unwrap().byte_len(&ctx)
    );
    serialize_test(st);
}

#[test]
fn test_custom_union() {
    mod opcua {
        pub(super) use crate as types;
    }

    #[derive(Debug, PartialEq, Clone, BinaryDecodable, BinaryEncodable)]
    enum MyUnion {
        Var1(i32),
        Var2(EUInformation),
        Var3(f64),
    }

    let ctx_f = ContextOwned::default();
    let ctx = ctx_f.context();
    let st = MyUnion::Var1(123);
    // Byte length depends on variant contents.
    assert_eq!(st.byte_len(&ctx), 4 + 4);

    serialize_test(st);

    let st = MyUnion::Var2(EUInformation {
        namespace_uri: "test".into(),
        unit_id: 123,
        display_name: "test".into(),
        description: "desc".into(),
    });
    serialize_test(st);

    let st = MyUnion::Var3(123.123);
    // Byte length depends on variant contents.
    assert_eq!(st.byte_len(&ctx), 4 + 8);
    serialize_test(st);
}

#[test]
fn test_custom_union_nullable() {
    mod opcua {
        pub(super) use crate as types;
    }

    #[derive(Debug, PartialEq, Clone, BinaryDecodable, BinaryEncodable)]
    enum MyUnion {
        Var1(i32),
        Null,
    }

    let ctx_f = ContextOwned::default();
    let ctx = ctx_f.context();
    let st = MyUnion::Var1(123);
    // Byte length depends on variant contents.
    assert_eq!(st.byte_len(&ctx), 4 + 4);

    serialize_test(st);

    let st = MyUnion::Null;
    assert_eq!(st.byte_len(&ctx), 4);
    serialize_test(st);
}

#[test]
fn test_xml_in_binary() {
    // Bit tricky to test since we don't support encoding extension objects as XML.
    // We may actually allow this to some extent in the future, using the same mechanism
    // we'll use for decoding fallback.
    let mut buf = Vec::new();
    let mut stream = Cursor::new(&mut buf);
    let ctx_f = ContextOwned::default();
    let ctx = ctx_f.context();
    let rf = EUInformation {
        namespace_uri: "https://my.namespace.uri".into(),
        unit_id: 1,
        display_name: LocalizedText::new("en", "MyUnit"),
        description: LocalizedText::new("en", "MyDesc"),
    };
    let id: NodeId = ObjectId::EUInformation_Encoding_DefaultXml.into();
    id.encode(&mut stream, &ctx).unwrap();

    write_u8(&mut stream, 0x2).unwrap();
    let mut xml_buf = Vec::new();
    let mut xml_stream = Cursor::new(&mut xml_buf);
    let _ = xml_stream.write(b"<EUInformation>").unwrap();
    let mut xml_writer = XmlStreamWriter::new(&mut xml_stream as &mut dyn Write);
    crate::xml::XmlEncodable::encode(&rf, &mut xml_writer, &ctx).unwrap();
    let _ = xml_stream.write(b"</EUInformation>").unwrap();
    let str = UAString::from(String::from_utf8(xml_buf).unwrap());
    str.encode(&mut stream, &ctx).unwrap();

    stream.set_position(0);
    let decoded = ExtensionObject::decode(&mut stream, &ctx).unwrap();
    assert_eq!(decoded.inner_as::<EUInformation>().unwrap(), &rf);
}
