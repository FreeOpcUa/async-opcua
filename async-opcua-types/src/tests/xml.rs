use std::str::FromStr;

use opcua_xml::{from_str, XmlElement};

use crate::{
    xml::FromXml, Argument, ByteString, DataTypeId, DataValue, DateTime, ExpandedNodeId,
    ExtensionObject, Guid, LocalizedText, NodeId, QualifiedName, StatusCode, UAString, Variant,
};
use crate::{Context, ContextOwned, DecodingOptions, EncodingResult, Error};

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

fn from_xml_str<T: FromXml>(data: &str) -> EncodingResult<T> {
    let ctx = ContextOwned::new_default(namespaces(), DecodingOptions::default());
    let ctx_ref = ctx.context();
    from_xml_str_ctx(data, &ctx_ref)
}

fn from_xml_str_ctx<T: FromXml>(data: &str, ctx: &Context<'_>) -> EncodingResult<T> {
    let element: Option<XmlElement> = from_str(data).map_err(Error::decoding)?;
    let Some(element) = element else {
        return Err(Error::decoding("Missing root element"));
    };
    T::from_xml(&element, ctx)
}

#[test]
fn from_xml_u8() {
    assert_eq!(5u8, from_xml_str::<u8>("<Data>5</Data>").unwrap());
}

#[test]
fn from_xml_i8() {
    assert_eq!(5i8, from_xml_str::<i8>("<Data>5</Data>").unwrap());
}

#[test]
fn from_xml_u16() {
    assert_eq!(5u16, from_xml_str::<u16>("<Data>5</Data>").unwrap());
}

#[test]
fn from_xml_i16() {
    assert_eq!(5i16, from_xml_str::<i16>("<Data>5</Data>").unwrap());
}

#[test]
fn from_xml_u32() {
    assert_eq!(5u32, from_xml_str::<u32>("<Data>5</Data>").unwrap());
}

#[test]
fn from_xml_i32() {
    assert_eq!(5i32, from_xml_str::<i32>("<Data>5</Data>").unwrap());
}

#[test]
fn from_xml_u64() {
    assert_eq!(5u64, from_xml_str::<u64>("<Data>5</Data>").unwrap());
}

#[test]
fn from_xml_i64() {
    assert_eq!(5i64, from_xml_str::<i64>("<Data>5</Data>").unwrap());
}

#[test]
fn from_xml_f32() {
    assert_eq!(5.5f32, from_xml_str::<f32>("<Data>5.5</Data>").unwrap());
}

#[test]
fn from_xml_f64() {
    assert_eq!(5.5f64, from_xml_str::<f64>("<Data>5.5</Data>").unwrap());
}

#[test]
fn from_xml_bool() {
    assert!(from_xml_str::<bool>("<Data>true</Data>").unwrap());
    assert!(!from_xml_str::<bool>("<Data>false</Data>").unwrap());
}

#[test]
fn from_xml_uastring() {
    assert_eq!(
        UAString::from("test string"),
        from_xml_str::<UAString>("<Data>test string</Data>").unwrap()
    );
}

#[test]
fn from_xml_localized_text() {
    assert_eq!(
        LocalizedText::new("en", "Some text"),
        from_xml_str("<Data><Locale>en</Locale><Text>Some text</Text></Data>").unwrap()
    );
}

#[test]
fn from_xml_guid() {
    assert_eq!(
        Guid::from_str("f6aae0c0-455f-4285-82a7-d492ea4ef434").unwrap(),
        from_xml_str("<Data><String>f6aae0c0-455f-4285-82a7-d492ea4ef434</String></Data>").unwrap()
    );
}

#[test]
fn from_xml_node_id() {
    assert_eq!(
        NodeId::new(0, "test"),
        from_xml_str::<NodeId>("<Data><Identifier>s=test</Identifier></Data>").unwrap()
    );
    let mut ns = namespaces();
    let ctx_owned = ContextOwned::new_default(ns.clone(), DecodingOptions::default());
    ns.add_namespace("opc.tcp://my-server.server");
    let mut mp = mapper(&mut ns);
    mp.add_namespace("opc.tcp://my-server.server", 2);
    let ctx = context(&mp, &ctx_owned);

    assert_eq!(
        NodeId::new(1, ByteString::from_base64("aGVsbG8=").unwrap()),
        from_xml_str_ctx::<NodeId>(
            "<Data><Identifier>ns=2;b=aGVsbG8=</Identifier></Data>",
            &ctx
        )
        .unwrap()
    );
    assert_eq!(
        NodeId::new(1, 123),
        from_xml_str_ctx::<NodeId>("<Data><Identifier>ns=2;i=123</Identifier></Data>", &ctx)
            .unwrap()
    );
    assert_eq!(
        NodeId::new(
            1,
            Guid::from_str("f6aae0c0-455f-4285-82a7-d492ea4ef434").unwrap()
        ),
        from_xml_str_ctx::<NodeId>(
            "<Data><Identifier>ns=2;g=f6aae0c0-455f-4285-82a7-d492ea4ef434</Identifier></Data>",
            &ctx
        )
        .unwrap()
    );
}

#[test]
fn from_xml_expanded_node_id() {
    assert_eq!(
        ExpandedNodeId::new(NodeId::new(0, "test")),
        from_xml_str::<ExpandedNodeId>("<Data><Identifier>s=test</Identifier></Data>").unwrap()
    );
}

#[test]
fn from_xml_status_code() {
    assert_eq!(
        StatusCode::GoodCallAgain,
        from_xml_str::<StatusCode>("<Data><Code>11075584</Code></Data>").unwrap()
    );
}

#[test]
fn from_xml_extension_object() {
    assert_eq!(
        ExtensionObject::from_message(Argument {
            name: "Some name".into(),
            data_type: DataTypeId::Double.into(),
            value_rank: 1,
            array_dimensions: Some(vec![3]),
            description: LocalizedText::new("en", "Some desc")
        }),
        from_xml_str::<ExtensionObject>(
            r#"
    <Data>
        <TypeId><Identifier>i=297</Identifier></TypeId>
        <Body>
            <Argument>
                <Name>Some name</Name>
                <DataType><Identifier>i=11</Identifier></DataType>
                <ValueRank>1</ValueRank>
                <ArrayDimensions>3</ArrayDimensions>
                <Description>
                    <Locale>en</Locale>
                    <Text>Some desc</Text>
                </Description>
            </Argument>
        </Body>
    </Data>
    "#
        )
        .unwrap()
    )
}

#[test]
fn from_xml_date_time() {
    assert_eq!(
        DateTime::from_str("2020-12-24T20:15:01Z").unwrap(),
        from_xml_str("<Data>2020-12-24T20:15:01+0000</Data>").unwrap()
    );
}

#[test]
fn from_xml_byte_string() {
    assert_eq!(
        ByteString::from_base64("aGVsbG8=").unwrap(),
        from_xml_str("<Data>aGVsbG8=</Data>").unwrap()
    );
}

#[test]
fn from_xml_qualified_name() {
    assert_eq!(
        QualifiedName::new(0, "Some name"),
        from_xml_str(
            r#"
    <Data>
        <Name>Some name</Name>
    </Data>
    "#
        )
        .unwrap()
    );
    let mut ns = namespaces();
    ns.add_namespace("opc.tcp://my-server.server");
    let ctx_owned = ContextOwned::new_default(ns.clone(), DecodingOptions::default());
    let mut mp = mapper(&mut ns);
    mp.add_namespace("opc.tcp://my-server.server", 2);
    let ctx = context(&mp, &ctx_owned);

    assert_eq!(
        QualifiedName::new(1, "Some name"),
        from_xml_str_ctx(
            r#"
    <Data>
        <NamespaceIndex>2</NamespaceIndex>
        <Name>Some name</Name>
    </Data>
    "#,
            &ctx
        )
        .unwrap()
    )
}

#[test]
fn from_xml_data_value() {
    assert_eq!(
        DataValue::new_at_status(
            123i32,
            DateTime::from_str("2020-01-01T15:00:00Z").unwrap(),
            StatusCode::Bad
        ),
        from_xml_str::<DataValue>(
            r#"
        <Data>
            <Value><Int32>123</Int32></Value>
            <StatusCode><Code>2147483648</Code></StatusCode>
            <SourceTimestamp>2020-01-01T15:00:00Z</SourceTimestamp>
            <SourcePicoseconds>0</SourcePicoseconds>
            <ServerTimestamp>2020-01-01T15:00:00Z</ServerTimestamp>
            <ServerPicoseconds>0</ServerPicoseconds>
        </Data>"#
        )
        .unwrap()
    )
}

#[test]
fn from_xml_variant() {
    assert_eq!(
        Variant::from(1u8),
        from_xml_str("<Data><Byte>1</Byte></Data>").unwrap()
    );
    assert_eq!(
        Variant::from(vec![1u8, 2u8]),
        from_xml_str("<Data><ListOfByte><Byte>1</Byte><Byte>2</Byte></ListOfByte></Data>").unwrap()
    );
    assert_eq!(
        Variant::from(1i8),
        from_xml_str("<Data><SByte>1</SByte></Data>").unwrap()
    );
    assert_eq!(
        Variant::from(vec![1i8, 2i8]),
        from_xml_str("<Data><ListOfSByte><SByte>1</SByte><SByte>2</SByte></ListOfSByte></Data>")
            .unwrap()
    );
    assert_eq!(
        Variant::from(1u16),
        from_xml_str("<Data><UInt16>1</UInt16></Data>").unwrap()
    );
    assert_eq!(
        Variant::from(vec![1u16, 2u16]),
        from_xml_str(
            "<Data><ListOfUInt16><UInt16>1</UInt16><UInt16>2</UInt16></ListOfUInt16></Data>"
        )
        .unwrap()
    );
    assert_eq!(
        Variant::from(1i16),
        from_xml_str("<Data><Int16>1</Int16></Data>").unwrap()
    );
    assert_eq!(
        Variant::from(vec![1i16, 2i16]),
        from_xml_str("<Data><ListOfInt16><Int16>1</Int16><Int16>2</Int16></ListOfInt16></Data>")
            .unwrap()
    );
    assert_eq!(
        Variant::from(1u32),
        from_xml_str("<Data><UInt32>1</UInt32></Data>").unwrap()
    );
    assert_eq!(
        Variant::from(vec![1u32, 2u32]),
        from_xml_str(
            "<Data><ListOfUInt32><UInt32>1</UInt32><UInt32>2</UInt32></ListOfUInt32></Data>"
        )
        .unwrap()
    );
    assert_eq!(
        Variant::from(1i32),
        from_xml_str("<Data><Int32>1</Int32></Data>").unwrap()
    );
    assert_eq!(
        Variant::from(vec![1i32, 2i32]),
        from_xml_str("<Data><ListOfInt32><Int32>1</Int32><Int32>2</Int32></ListOfInt32></Data>")
            .unwrap()
    );
    assert_eq!(
        Variant::from(1u64),
        from_xml_str("<Data><UInt64>1</UInt64></Data>").unwrap()
    );
    assert_eq!(
        Variant::from(vec![1u64, 2u64]),
        from_xml_str(
            "<Data><ListOfUInt64><UInt64>1</UInt64><UInt64>2</UInt64></ListOfUInt64></Data>"
        )
        .unwrap()
    );
    assert_eq!(
        Variant::from(1i64),
        from_xml_str("<Data><Int64>1</Int64></Data>").unwrap()
    );
    assert_eq!(
        Variant::from(vec![1i64, 2i64]),
        from_xml_str("<Data><ListOfInt64><Int64>1</Int64><Int64>2</Int64></ListOfInt64></Data>")
            .unwrap()
    );
    assert_eq!(
        Variant::from(1.5f32),
        from_xml_str("<Data><Float>1.5</Float></Data>").unwrap()
    );
    assert_eq!(
        Variant::from(vec![1.5f32, 2.5f32]),
        from_xml_str(
            "<Data><ListOfFloat><Float>1.5</Float><Float>2.5</Float></ListOfFloat></Data>"
        )
        .unwrap()
    );
    assert_eq!(
        Variant::from(1.5f64),
        from_xml_str("<Data><Double>1.5</Double></Data>").unwrap()
    );
    assert_eq!(
        Variant::from(vec![1.5f64, 2.5f64]),
        from_xml_str(
            "<Data><ListOfDouble><Double>1.5</Double><Double>2.5</Double></ListOfDouble></Data>"
        )
        .unwrap()
    );
    assert_eq!(
        Variant::from("foo"),
        from_xml_str("<Data><String>foo</String></Data>").unwrap()
    );
    assert_eq!(
        Variant::from(vec!["foo", "bar"]),
        from_xml_str(
            "<Data><ListOfString><String>foo</String><String>bar</String></ListOfString></Data>"
        )
        .unwrap()
    );
}
