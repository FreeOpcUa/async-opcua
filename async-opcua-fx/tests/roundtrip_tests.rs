//! Independent round-trip checks for the generated + hand-written FX/Data types.
//! The key correctness properties: (1) FX types encode under the FX/Data namespace URI (NOT ns0),
//! and (2) they survive an ExtensionObject binary round-trip through the GeneratedTypeLoader,
//! including the hand-written union field.

use std::io::{Cursor, Seek, SeekFrom};

use async_opcua_fx::generated::types::GeneratedTypeLoader;
use async_opcua_fx::{
    ConnectionEndpointConfigurationDataType, ConnectionEndpointDefinitionDataType,
};
use opcua_types::{
    BinaryDecodable, BinaryEncodable, ContextOwned, ExpandedMessageInfo, ExtensionObject, NodeId,
};

const FX_DATA_NS: &str = "http://opcfoundation.org/UA/FX/Data/";

#[test]
fn fx_type_is_tagged_with_fx_namespace_not_ns0() {
    let v = ConnectionEndpointConfigurationDataType::default();
    let id = v.full_type_id();
    assert_eq!(
        id.namespace_uri.as_ref(),
        FX_DATA_NS,
        "FX types must carry the FX/Data namespace URI, not be encoded as ns0"
    );
}

#[test]
fn connection_endpoint_config_roundtrips_through_type_loader() {
    // Exercise the generated struct AND the hand-written union (connection_endpoint = Node variant).
    let value = ConnectionEndpointConfigurationDataType {
        functional_entity_node: NodeId::new(2, "FunctionalEntity"),
        connection_endpoint: ConnectionEndpointDefinitionDataType::Node(NodeId::new(3, "Endpoint")),
        expected_verification_variables: None,
        control_groups: Some(vec![NodeId::new(1, 42u32)]),
        configuration_data: None,
        communication_links: ExtensionObject::null(),
    };

    // The context must know the FX/Data namespace (so the type-id URI resolves to a wire index)
    // and carry the FX type loader (so decode reconstructs the concrete type).
    let mut ctx = ContextOwned::default();
    ctx.namespaces_mut().add_namespace(FX_DATA_NS);
    ctx.loaders_mut().add_type_loader(GeneratedTypeLoader);

    let obj = ExtensionObject::from_message(value.clone());
    let mut cursor = Cursor::new(Vec::<u8>::new());
    BinaryEncodable::encode(&obj, &mut cursor, &ctx.context()).unwrap();

    cursor.seek(SeekFrom::Start(0)).unwrap();
    let decoded =
        <ExtensionObject as BinaryDecodable>::decode(&mut cursor, &ctx.context()).unwrap();
    let back = decoded
        .into_inner_as::<ConnectionEndpointConfigurationDataType>()
        .expect("decoded back into the concrete FX type via the loader");
    assert_eq!(*back, value);
}

#[test]
fn union_null_variant_roundtrips() {
    let value = ConnectionEndpointConfigurationDataType {
        connection_endpoint: ConnectionEndpointDefinitionDataType::Null,
        ..Default::default()
    };

    let mut ctx = ContextOwned::default();
    ctx.namespaces_mut().add_namespace(FX_DATA_NS);
    ctx.loaders_mut().add_type_loader(GeneratedTypeLoader);

    let obj = ExtensionObject::from_message(value.clone());
    let mut cursor = Cursor::new(Vec::<u8>::new());
    BinaryEncodable::encode(&obj, &mut cursor, &ctx.context()).unwrap();
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let decoded =
        <ExtensionObject as BinaryDecodable>::decode(&mut cursor, &ctx.context()).unwrap();
    let back = decoded
        .into_inner_as::<ConnectionEndpointConfigurationDataType>()
        .unwrap();
    assert_eq!(*back, value);
}
