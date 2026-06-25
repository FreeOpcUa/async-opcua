//! Independent round-trip checks for the generated + hand-written FX/CM types (piece 5a).
//! Exercises the generated NodeIdTranslationDataType carrying the hand-written PortableNodeIdentifier
//! union, encoded under the FX/CM namespace URI through the CM type loader.

use std::io::{Cursor, Seek, SeekFrom};

use async_opcua_fx::{CmGeneratedTypeLoader, NodeIdTranslationDataType, PortableNodeIdentifier};
use opcua_types::{
    BinaryDecodable, BinaryEncodable, ContextOwned, ExpandedMessageInfo, ExtensionObject, NodeId,
};

const FX_CM_NS: &str = "http://opcfoundation.org/UA/FX/CM/";

#[test]
fn cm_type_is_tagged_with_fx_cm_namespace() {
    let v = NodeIdTranslationDataType::default();
    assert_eq!(v.full_type_id().namespace_uri.as_ref(), FX_CM_NS);
}

#[test]
fn node_id_translation_roundtrips_through_cm_loader() {
    let value = NodeIdTranslationDataType {
        node_placeholder: NodeId::new(2, "Placeholder"),
        portable_node: PortableNodeIdentifier::Alias("alias-name".into()),
    };

    let mut ctx = ContextOwned::default();
    ctx.namespaces_mut().add_namespace(FX_CM_NS);
    ctx.loaders_mut().add_type_loader(CmGeneratedTypeLoader);

    let obj = ExtensionObject::from_message(value.clone());
    let mut cursor = Cursor::new(Vec::<u8>::new());
    BinaryEncodable::encode(&obj, &mut cursor, &ctx.context()).unwrap();

    cursor.seek(SeekFrom::Start(0)).unwrap();
    let decoded =
        <ExtensionObject as BinaryDecodable>::decode(&mut cursor, &ctx.context()).unwrap();
    let back = decoded
        .into_inner_as::<NodeIdTranslationDataType>()
        .expect("decoded back into the concrete CM type via the loader");
    assert_eq!(*back, value);
}
