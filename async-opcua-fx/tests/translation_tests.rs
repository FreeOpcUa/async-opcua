//! Independent tests for FX piece 5b: NodeIdTranslation (placeholder -> portable -> local NodeId).

use async_opcua_fx::{
    resolve_portable_node, translate, translate_to_node_id, NodeIdTranslationDataType,
    PortableNodeIdentifier,
};
use opcua_types::{NamespaceMap, NodeId, PortableNodeId, StatusCode};

fn table_entry(placeholder: NodeId, portable: PortableNodeIdentifier) -> NodeIdTranslationDataType {
    NodeIdTranslationDataType {
        node_placeholder: placeholder,
        portable_node: portable,
    }
}

#[test]
fn translate_to_node_id_resolves_via_namespace_uri() {
    let mut namespaces = NamespaceMap::new();
    let idx = namespaces.add_namespace("urn:remote");

    let placeholder = NodeId::new(2, "PH");
    let table = vec![table_entry(
        placeholder.clone(),
        PortableNodeIdentifier::Node(PortableNodeId {
            namespace_uri: "urn:remote".into(),
            identifier: NodeId::new(0, "Real"),
        }),
    )];

    let resolved = translate_to_node_id(&table, &placeholder, &namespaces).expect("resolves");
    // namespace mapped to the local index, identifier value preserved.
    assert_eq!(resolved, NodeId::new(idx, "Real"));
}

#[test]
fn resolve_node_with_empty_uri_is_identity() {
    let namespaces = NamespaceMap::new();
    let portable = PortableNodeIdentifier::Node(PortableNodeId {
        namespace_uri: "".into(),
        identifier: NodeId::new(3, "AsIs"),
    });
    assert_eq!(
        resolve_portable_node(&portable, &namespaces).unwrap(),
        NodeId::new(3, "AsIs")
    );
}

#[test]
fn resolve_unknown_namespace_is_node_id_unknown() {
    let namespaces = NamespaceMap::new(); // "urn:missing" never added
    let portable = PortableNodeIdentifier::Node(PortableNodeId {
        namespace_uri: "urn:missing".into(),
        identifier: NodeId::new(0, "X"),
    });
    assert_eq!(
        resolve_portable_node(&portable, &namespaces).unwrap_err(),
        StatusCode::BadNodeIdUnknown
    );
}

#[test]
fn alias_resolution_is_not_supported_from_namespace_map_alone() {
    let namespaces = NamespaceMap::new();
    let portable = PortableNodeIdentifier::Alias("some-alias".into());
    assert_eq!(
        resolve_portable_node(&portable, &namespaces).unwrap_err(),
        StatusCode::BadNotSupported
    );
}

#[test]
fn translate_miss_returns_none() {
    let table: Vec<NodeIdTranslationDataType> = vec![];
    assert!(translate(&table, &NodeId::new(2, "absent")).is_none());
    let namespaces = NamespaceMap::new();
    assert!(translate_to_node_id(&table, &NodeId::new(2, "absent"), &namespaces).is_none());
}
