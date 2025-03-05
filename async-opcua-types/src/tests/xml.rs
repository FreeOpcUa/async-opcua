use std::io::{Cursor, Read, Write};
use std::str::FromStr;

use opcua_macros::{XmlDecodable, XmlEncodable, XmlType};
use opcua_xml::XmlStreamReader;

use crate::xml::{XmlDecodable, XmlEncodable};
use crate::{
    Argument, Array, ByteString, DataTypeId, DataValue, DateTime, EUInformation, ExpandedNodeId,
    ExtensionObject, Guid, LocalizedText, NodeId, QualifiedName, StatusCode, UAString, UaNullable,
    Variant, XmlElement,
};
use crate::{Context, ContextOwned, DecodingOptions, EncodingResult};

use crate::{NamespaceMap, NodeSetNamespaceMapper};

fn namespaces() -> NamespaceMap {
    NamespaceMap::new()
}

fn mapper(ns: &mut NamespaceMap) -> NodeSetNamespaceMapper<'_> {
    NodeSetNamespaceMapper::new(ns)
}

fn context<'a>(mapper: &'a NodeSetNamespaceMapper<'a>, owned: &'a ContextOwned) -> Context<'a> {
    let mut ctx = owned.context();
    ctx.set_index_map(mapper.index_map());
    ctx
}

fn from_xml_str_ctx<T: XmlDecodable>(data: &str, ctx: &Context<'_>) -> EncodingResult<T> {
    let mut cursor = Cursor::new(data.as_bytes());
    let mut reader = XmlStreamReader::new(&mut cursor as &mut dyn Read);
    T::decode(&mut reader, ctx)
}

fn encode_xml_ctx<T: XmlEncodable>(data: &T, ctx: &Context<'_>) -> EncodingResult<String> {
    let mut buf = Vec::new();
    let mut writer = opcua_xml::XmlStreamWriter::new(&mut buf as &mut dyn Write);
    data.encode(&mut writer, ctx)?;
    Ok(String::from_utf8(buf).unwrap())
}

fn xml_round_trip_ctx<T: XmlDecodable + XmlEncodable + PartialEq + std::fmt::Debug>(
    cmp: &T,
    data: &str,
    ctx: &Context<'_>,
) {
    let decoded = from_xml_str_ctx::<T>(data, ctx).unwrap();
    let encoded = encode_xml_ctx(&decoded, ctx).unwrap();
    println!("{encoded}");
    let decoded2 = from_xml_str_ctx::<T>(&encoded, ctx).unwrap();
    assert_eq!(decoded, decoded2);
    assert_eq!(&decoded, cmp);
}

fn xml_round_trip<T: XmlDecodable + XmlEncodable + PartialEq + std::fmt::Debug>(
    cmp: &T,
    data: &str,
) {
    let ctx = ContextOwned::new_default(namespaces(), DecodingOptions::default());
    let ctx_ref = ctx.context();
    xml_round_trip_ctx(cmp, data, &ctx_ref);
}

#[test]
fn from_xml_u8() {
    xml_round_trip(&5u8, "5");
}

#[test]
fn from_xml_i8() {
    xml_round_trip(&5i8, "5");
}

#[test]
fn from_xml_u16() {
    xml_round_trip(&5u16, "5");
}

#[test]
fn from_xml_i16() {
    xml_round_trip(&5i16, "5");
}

#[test]
fn from_xml_u32() {
    xml_round_trip(&5u32, "5");
}

#[test]
fn from_xml_i32() {
    xml_round_trip(&5i32, "5");
}

#[test]
fn from_xml_u64() {
    xml_round_trip(&5u64, "5");
}

#[test]
fn from_xml_i64() {
    xml_round_trip(&5i64, "5");
}

#[test]
fn from_xml_f32() {
    xml_round_trip(&5.5f32, "5.5");
}

#[test]
fn from_xml_f64() {
    xml_round_trip(&5.5f64, "5.5");
}

#[test]
fn from_xml_bool() {
    xml_round_trip(&true, "true");
    xml_round_trip(&false, "false");
}

#[test]
fn from_xml_uastring() {
    xml_round_trip(&UAString::from("test string"), "test string");
}

#[test]
fn from_xml_localized_text() {
    xml_round_trip(
        &LocalizedText::new("en", "Some text"),
        "<Locale>en</Locale><Text>Some text</Text>",
    );
}

#[test]
fn from_xml_guid() {
    xml_round_trip(
        &Guid::from_str("f6aae0c0-455f-4285-82a7-d492ea4ef434").unwrap(),
        "<String>f6aae0c0-455f-4285-82a7-d492ea4ef434</String>",
    );
}

#[test]
fn from_xml_node_id() {
    xml_round_trip(&NodeId::new(0, "test"), "<Identifier>s=test</Identifier>");
    let mut ns = namespaces();
    let ctx_owned = ContextOwned::new_default(ns.clone(), DecodingOptions::default());
    ns.add_namespace("opc.tcp://my-server.server");
    let mut mp = mapper(&mut ns);
    mp.add_namespace("opc.tcp://my-server.server", 2);
    let ctx = context(&mp, &ctx_owned);

    xml_round_trip_ctx(
        &NodeId::new(1, ByteString::from_base64("aGVsbG8=").unwrap()),
        "<Identifier>ns=2;b=aGVsbG8=</Identifier>",
        &ctx,
    );
    xml_round_trip_ctx(
        &NodeId::new(1, 123),
        "<Identifier>ns=2;i=123</Identifier>",
        &ctx,
    );
    xml_round_trip_ctx(
        &NodeId::new(
            1,
            Guid::from_str("f6aae0c0-455f-4285-82a7-d492ea4ef434").unwrap(),
        ),
        "<Identifier>ns=2;g=f6aae0c0-455f-4285-82a7-d492ea4ef434</Identifier>",
        &ctx,
    );
}

#[test]
fn from_xml_expanded_node_id() {
    xml_round_trip(
        &ExpandedNodeId::new(NodeId::new(0, "test")),
        "<Identifier>s=test</Identifier>",
    );
}

#[test]
fn from_xml_status_code() {
    xml_round_trip(&StatusCode::GoodCallAgain, "<Code>11075584</Code>");
}

#[test]
fn from_xml_extension_object() {
    xml_round_trip(
        &ExtensionObject::from_message(Argument {
            name: "Some name".into(),
            data_type: DataTypeId::Double.into(),
            value_rank: 1,
            array_dimensions: Some(vec![3]),
            description: LocalizedText::new("en", "Some desc"),
        }),
        r#"
    
        <TypeId><Identifier>i=297</Identifier></TypeId>
        <Body>
            <Argument>
                <Name>Some name</Name>
                <DataType><Identifier>i=11</Identifier></DataType>
                <ValueRank>1</ValueRank>
                <ArrayDimensions><UInt32>3</UInt32></ArrayDimensions>
                <Description>
                    <Locale>en</Locale>
                    <Text>Some desc</Text>
                </Description>
            </Argument>
        </Body>
    
    "#,
    )
}

#[test]
fn from_xml_date_time() {
    xml_round_trip(
        &DateTime::from_str("2020-12-24T20:15:01Z").unwrap(),
        "2020-12-24T20:15:01+00:00",
    );
}

#[test]
fn from_xml_byte_string() {
    xml_round_trip(&ByteString::from_base64("aGVsbG8=").unwrap(), "aGVsbG8=");
}

#[test]
fn from_xml_qualified_name() {
    xml_round_trip(
        &QualifiedName::new(0, "Some name"),
        r#"
    
        <Name>Some name</Name>
    
    "#,
    );
    let mut ns = namespaces();
    ns.add_namespace("opc.tcp://my-server.server");
    let ctx_owned = ContextOwned::new_default(ns.clone(), DecodingOptions::default());
    let mut mp = mapper(&mut ns);
    mp.add_namespace("opc.tcp://my-server.server", 2);
    let ctx = context(&mp, &ctx_owned);

    xml_round_trip_ctx(
        &QualifiedName::new(1, "Some name"),
        r#"
    
        <NamespaceIndex>2</NamespaceIndex>
        <Name>Some name</Name>
    
    "#,
        &ctx,
    )
}

#[test]
fn from_xml_data_value() {
    xml_round_trip(
        &DataValue::new_at_status(
            123i32,
            DateTime::from_str("2020-01-01T15:00:00Z").unwrap(),
            StatusCode::Bad,
        ),
        r#"
            <Value><Int32>123</Int32></Value>
            <StatusCode><Code>2147483648</Code></StatusCode>
            <SourceTimestamp>2020-01-01T15:00:00Z</SourceTimestamp>
            <SourcePicoseconds>0</SourcePicoseconds>
            <ServerTimestamp>2020-01-01T15:00:00Z</ServerTimestamp>
            <ServerPicoseconds>0</ServerPicoseconds>
        "#,
    )
}

#[test]
fn from_xml_xml_element() {
    let data = r#"<Thing>Hello there</Thing>
<Thing>Other thing</Thing>
"#;
    // XML elements are simply captured one-to-one.
    xml_round_trip(&XmlElement::from(data), data);
}

#[test]
fn from_xml_variant() {
    xml_round_trip(&Variant::from(1u8), "<Byte>1</Byte>");
    xml_round_trip(
        &Variant::from(vec![1u8, 2u8]),
        "<ListOfByte><Byte>1</Byte><Byte>2</Byte></ListOfByte>",
    );
    xml_round_trip(&Variant::from(1i8), "<SByte>1</SByte>");
    xml_round_trip(
        &Variant::from(vec![1i8, 2i8]),
        "<ListOfSByte><SByte>1</SByte><SByte>2</SByte></ListOfSByte>",
    );
    xml_round_trip(&Variant::from(1u16), "<UInt16>1</UInt16>");
    xml_round_trip(
        &Variant::from(vec![1u16, 2u16]),
        "<ListOfUInt16><UInt16>1</UInt16><UInt16>2</UInt16></ListOfUInt16>",
    );
    xml_round_trip(&Variant::from(1i16), "<Int16>1</Int16>");
    xml_round_trip(
        &Variant::from(vec![1i16, 2i16]),
        "<ListOfInt16><Int16>1</Int16><Int16>2</Int16></ListOfInt16>",
    );
    xml_round_trip(&Variant::from(1u32), "<UInt32>1</UInt32>");
    xml_round_trip(
        &Variant::from(vec![1u32, 2u32]),
        "<ListOfUInt32><UInt32>1</UInt32><UInt32>2</UInt32></ListOfUInt32>",
    );
    xml_round_trip(&Variant::from(1i32), "<Int32>1</Int32>");
    xml_round_trip(
        &Variant::from(vec![1i32, 2i32]),
        "<ListOfInt32><Int32>1</Int32><Int32>2</Int32></ListOfInt32>",
    );
    xml_round_trip(&Variant::from(1u64), "<UInt64>1</UInt64>");
    xml_round_trip(
        &Variant::from(vec![1u64, 2u64]),
        "<ListOfUInt64><UInt64>1</UInt64><UInt64>2</UInt64></ListOfUInt64>",
    );
    xml_round_trip(&Variant::from(1i64), "<Int64>1</Int64>");
    xml_round_trip(
        &Variant::from(vec![1i64, 2i64]),
        "<ListOfInt64><Int64>1</Int64><Int64>2</Int64></ListOfInt64>",
    );
    xml_round_trip(&Variant::from(1.5f32), "<Float>1.5</Float>");
    xml_round_trip(
        &Variant::from(vec![1.5f32, 2.5f32]),
        "<ListOfFloat><Float>1.5</Float><Float>2.5</Float></ListOfFloat>",
    );
    xml_round_trip(&Variant::from(1.5f64), "<Double>1.5</Double>");
    xml_round_trip(
        &Variant::from(vec![1.5f64, 2.5f64]),
        "<ListOfDouble><Double>1.5</Double><Double>2.5</Double></ListOfDouble>",
    );
    xml_round_trip(&Variant::from("foo"), "<String>foo</String>");
    xml_round_trip(
        &Variant::from(vec!["foo", "bar"]),
        "<ListOfString><String>foo</String><String>bar</String></ListOfString>",
    );
    xml_round_trip(
        &Variant::from(DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z").unwrap()),
        "<DateTime>2020-01-01T00:00:00Z</DateTime>",
    );
    xml_round_trip(
        &Variant::from(vec![DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z").unwrap(), DateTime::parse_from_rfc3339("2020-01-02T00:00:00Z").unwrap()]),
        "<ListOfDateTime><DateTime>2020-01-01T00:00:00Z</DateTime><DateTime>2020-01-02T00:00:00Z</DateTime></ListOfDateTime>",
    );
    let guid = Guid::from_str("f6aae0c0-455f-4285-82a7-d492ea4ef434").unwrap();
    xml_round_trip(
        &Variant::from(guid.clone()),
        "<Guid><String>f6aae0c0-455f-4285-82a7-d492ea4ef434</String></Guid>",
    );
    xml_round_trip(
        &Variant::from(vec![guid.clone(), guid.clone()]),
        "<ListOfGuid><Guid><String>f6aae0c0-455f-4285-82a7-d492ea4ef434</String></Guid>
        <Guid><String>f6aae0c0-455f-4285-82a7-d492ea4ef434</String></Guid></ListOfGuid>",
    );
    xml_round_trip(
        &Variant::from(StatusCode::Bad),
        "<StatusCode><Code>2147483648</Code></StatusCode>",
    );
    xml_round_trip(
        &Variant::from(vec![StatusCode::Bad, StatusCode::Good]),
        "<ListOfStatusCode><StatusCode><Code>2147483648</Code></StatusCode><StatusCode><Code>0</Code></StatusCode></ListOfStatusCode>",
    );
    let data = r#"<Thing>Hello there</Thing>
<Thing>Other thing</Thing>
"#;
    xml_round_trip(
        &Variant::from(XmlElement::from(data)),
        &format!("<XmlElement>{data}</XmlElement>"),
    );
    xml_round_trip(
        &Variant::from(vec![XmlElement::from(data), XmlElement::from(data)]),
        &format!("<ListOfXmlElement><XmlElement>{data}</XmlElement><XmlElement>{data}</XmlElement></ListOfXmlElement>"),
    );
    xml_round_trip(
        &Variant::from(EUInformation {
            namespace_uri: "https://my.namespace.uri".into(),
            unit_id: 1,
            display_name: LocalizedText::from("MyUnit"),
            description: LocalizedText::new("en", "MyDesc"),
        }),
        r#"
        <ExtensionObject>
            <TypeId><Identifier>i=888</Identifier></TypeId>
            <Body>
                <EUInformation>
                    <NamespaceUri>https://my.namespace.uri</NamespaceUri>
                    <UnitId>1</UnitId>
                    <DisplayName><Text>MyUnit</Text></DisplayName>
                    <Description><Locale>en</Locale><Text>MyDesc</Text></Description>
                </EUInformation>
            </Body>
        </ExtensionObject>
        "#,
    );
    xml_round_trip(
        &Variant::from(
            Array::new_multi(
                crate::VariantScalarTypeId::Int32,
                vec![1.into(), 2.into(), 3.into(), 4.into()],
                vec![2, 2],
            )
            .unwrap(),
        ),
        r#"
    <Matrix>
        <Dimensions><UInt32>2</UInt32><UInt32>2</UInt32></Dimensions>
        <Elements>
            <Int32>1</Int32><Int32>2</Int32>
            <Int32>3</Int32><Int32>4</Int32>
        </Elements>
    </Matrix>
    "#,
    );
}

#[test]
fn test_custom_union() {
    mod opcua {
        pub use crate as types;
    }

    #[derive(Debug, PartialEq, Clone, XmlDecodable, XmlEncodable, UaNullable, XmlType)]
    pub enum MyUnion {
        Var1(i32),
        #[opcua(rename = "EUInfo")]
        Var2(EUInformation),
        Var3(f64),
    }

    xml_round_trip(
        &MyUnion::Var1(123),
        r#"<SwitchField>1</SwitchField><Var1>123</Var1>"#,
    );

    xml_round_trip(
        &MyUnion::Var2(EUInformation {
            namespace_uri: "https://my.namespace.uri".into(),
            unit_id: 1,
            display_name: LocalizedText::from("MyUnit"),
            description: LocalizedText::new("en", "MyDesc"),
        }),
        r#"
        <SwitchField>2</SwitchField>
        <EUInfo>
            <NamespaceUri>https://my.namespace.uri</NamespaceUri>
            <UnitId>1</UnitId>
            <DisplayName><Text>MyUnit</Text></DisplayName>
            <Description><Locale>en</Locale><Text>MyDesc</Text></Description>
        </EUInfo>
        "#,
    );

    xml_round_trip(
        &MyUnion::Var3(123.123),
        r#"<SwitchField>1</SwitchField><Var3>123.123</Var3>"#,
    );
}

#[test]
fn test_custom_union_nullable() {
    mod opcua {
        pub use crate as types;
    }

    #[derive(Debug, PartialEq, Clone, XmlDecodable, XmlEncodable, UaNullable, XmlType)]
    pub enum MyUnion {
        Var1(i32),
        Null,
    }

    xml_round_trip(
        &MyUnion::Var1(123),
        r#"<SwitchField>1</SwitchField><Var1>123</Var1>"#,
    );
    xml_round_trip(&MyUnion::Null, r#"<SwitchField>0</SwitchField>"#);
}
