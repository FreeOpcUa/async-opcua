use std::io::Cursor;
use std::io::Read;
use std::io::Write;

use opcua::types::BinaryDecodable;
use opcua::types::BinaryEncodable;
use opcua::types::ContextOwned;
use opcua::types::DecodingOptions;
use opcua::types::DynEncodable;
use opcua::types::ExtensionObject;
use opcua::types::NamespaceMap;
use opcua::types::TypeLoaderCollection;
use opcua::types::UaEnum;
use opcua::types::json::JsonDecodable;
use opcua::types::json::JsonEncodable;
use opcua::types::json::JsonStreamReader;
use opcua::types::json::JsonStreamWriter;
use opcua::types::json::JsonWriter;
use opcua::types::xml::XmlDecodable;
use opcua::types::xml::XmlEncodable;
use opcua::xml::XmlStreamReader;
use opcua::xml::XmlStreamWriter;

use crate::generated::base::enums::*;
use crate::generated::base::structs::*;
use crate::generated::ext::structs::*;

fn ctx() -> ContextOwned {
    let mut namespaces = NamespaceMap::new();
    namespaces.add_namespace("http://github.com/freeopcua/async-opcua/codegen-tests");
    namespaces.add_namespace("http://github.com/freeopcua/async-opcua/codegen-tests/ext");
    let mut loaders = TypeLoaderCollection::new();
    loaders.add_type_loader(crate::generated::base::GeneratedTypeLoader);
    loaders.add_type_loader(crate::generated::ext::GeneratedTypeLoader);
    let ctx_owned = ContextOwned::new(namespaces, loaders, DecodingOptions::default());
    ctx_owned
}

fn all_encoding_roundtrip<
    T: BinaryEncodable
        + BinaryDecodable
        + JsonEncodable
        + JsonDecodable
        + XmlEncodable
        + XmlDecodable
        + PartialEq
        + std::fmt::Debug,
>(
    ty: &T,
) {
    let ctx_owned = ctx();
    let ctx = ctx_owned.context();

    // Binary
    let mut data = vec![0u8; ty.byte_len(&ctx)];
    let mut stream = Cursor::new(&mut data as &mut [u8]);
    BinaryEncodable::encode(ty, &mut stream, &ctx).unwrap();
    stream.set_position(0);
    let rf: T = BinaryDecodable::decode(&mut stream, &ctx).unwrap();
    assert_eq!(&rf, ty);

    // JSON
    let mut cursor = Cursor::new(Vec::new());
    let mut stream = JsonStreamWriter::new(&mut cursor as &mut dyn Write);
    JsonEncodable::encode(ty, &mut stream, &ctx).unwrap();
    stream.finish_document().unwrap();
    println!("JSON: {}", String::from_utf8_lossy(&cursor.get_ref()));
    cursor.set_position(0);
    let mut stream = JsonStreamReader::new(&mut cursor as &mut dyn Read);
    let rf: T = JsonDecodable::decode(&mut stream, &ctx).unwrap();
    assert_eq!(&rf, ty);

    // XML
    let mut cursor = Cursor::new(Vec::new());
    let mut stream = XmlStreamWriter::new(&mut cursor as &mut dyn Write);
    XmlEncodable::encode(ty, &mut stream, &ctx).unwrap();
    println!("XML: {}", String::from_utf8_lossy(&cursor.get_ref()));
    cursor.set_position(0);
    let mut stream = XmlStreamReader::new(&mut cursor as &mut dyn Read);
    let rf: T = XmlDecodable::decode(&mut stream, &ctx).unwrap();
    assert_eq!(&rf, ty);
}

/// Encode and decode a value, both as itself and wrapped in an ExtensionObject.
fn encoding_roundtrip_extension_object<
    T: DynEncodable
        + JsonEncodable
        + JsonDecodable
        + BinaryDecodable
        + BinaryEncodable
        + XmlEncodable
        + XmlDecodable
        + PartialEq
        + std::fmt::Debug,
>(
    val: T,
) {
    all_encoding_roundtrip(&val);
    let obj = ExtensionObject::new(val);
    all_encoding_roundtrip(&obj);
}

#[test]
fn test_simple_enum() {
    let v = SimpleEnum::Foo;
    assert_eq!(v as i32, 3);
    let v = SimpleEnum::from_repr(4).unwrap();
    assert_eq!(v, SimpleEnum::Bar);

    let v = SimpleEnum::from_str("FooBar_5").unwrap();
    assert_eq!(v, SimpleEnum::FooBar);
    assert_eq!(v.as_str(), "FooBar_5");
    all_encoding_roundtrip(&v);
}

#[test]
fn test_simple_struct() {
    let s = SimpleStruct {
        foo: "hello".into(),
        bar: 42,
        baz: true,
        simple_enum: SimpleEnum::Bar,
        numbers: Some(vec![1.0, 2.0, 3.0]),
    };
    encoding_roundtrip_extension_object(s);
}

#[test]
fn test_extended_struct() {
    let s = ExtendedStruct {
        foo: "hello".into(),
        bar: 42,
        baz: true,
        simple_enum: SimpleEnum::Bar,
        numbers: Some(vec![1.0, 2.0, 3.0]),
        bar_2: -12345,
        foo_2: "world".into(),
    };
    encoding_roundtrip_extension_object(s);
}

#[test]
fn test_container_struct() {
    let s = ContainerStruct {
        simple: SimpleStruct {
            foo: "hello".into(),
            bar: 42,
            baz: true,
            simple_enum: SimpleEnum::Bar,
            numbers: Some(vec![1.0, 2.0, 3.0]),
        },
        extended: ExtendedStruct {
            foo: "hello".into(),
            bar: 42,
            baz: true,
            simple_enum: SimpleEnum::Bar,
            numbers: Some(vec![1.0, 2.0, 3.0]),
            bar_2: -12345,
            foo_2: "world".into(),
        },
        simples: Some(vec![
            SimpleStruct {
                foo: "one".into(),
                bar: 1,
                baz: false,
                simple_enum: SimpleEnum::Foo,
                numbers: None,
            },
            SimpleStruct {
                foo: "two".into(),
                bar: 2,
                baz: true,
                simple_enum: SimpleEnum::FooBar,
                numbers: Some(vec![2.0, 4.0, 6.0]),
            },
        ]),
        built_in: opcua::types::EUInformation {
            namespace_uri: "http://example.com".into(),
            unit_id: 100,
            display_name: "Example Unit".into(),
            description: "An example engineering unit".into(),
        },
        built_ins: Some(vec![
            opcua::types::EUInformation {
                namespace_uri: "http://example.com/one".into(),
                unit_id: 101,
                display_name: "Unit One".into(),
                description: "First unit".into(),
            },
            opcua::types::EUInformation {
                namespace_uri: "http://example.com/two".into(),
                unit_id: 102,
                display_name: "Unit Two".into(),
                description: "Second unit".into(),
            },
        ]),
    };
    encoding_roundtrip_extension_object(s);
}

#[test]
fn test_external_struct() {
    let s = ExtStruct {
        simple: SimpleStruct {
            foo: "hello".into(),
            bar: 42,
            baz: true,
            simple_enum: SimpleEnum::Bar,
            numbers: Some(vec![1.0, 2.0, 3.0]),
        },
        extended: ExtendedStruct {
            foo: "hello".into(),
            bar: 42,
            baz: true,
            simple_enum: SimpleEnum::Bar,
            numbers: Some(vec![1.0, 2.0, 3.0]),
            bar_2: -12345,
            foo_2: "world".into(),
        },
        baz: true,
        simple_enum: SimpleEnum::Foo,
    };
    encoding_roundtrip_extension_object(s);
}
