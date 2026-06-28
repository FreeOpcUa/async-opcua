use std::{sync::Arc, time::Duration};

use super::utils::{setup, Tester};
use opcua::{
    client::Session,
    nodes::ReferenceTypeBuilder,
    server::{
        address_space::{EventNotifier, NodeBase, NodeType, ObjectBuilder, ObjectTypeBuilder},
        diagnostics::NamespaceMetadata,
        node_manager::memory::{simple_node_manager, SimpleNodeManager},
    },
    types::{
        AddNodeAttributes, AddNodesItem, AddReferencesItem, AttributeId, AttributesMask,
        BrowseDescription, BrowseDirection, DataTypeAttributes, DataTypeId, DeleteNodesItem,
        DeleteReferencesItem, ExpandedNodeId, MethodAttributes, NodeClass, NodeId,
        ObjectAttributes, ObjectId, ObjectTypeAttributes, ObjectTypeId, PermissionType,
        QualifiedName, ReadValueId, ReferenceTypeAttributes, ReferenceTypeId, RolePermissionType,
        StatusCode, TimestampsToReturn, UAString, VariableAttributes, VariableTypeAttributes,
        VariableTypeId, Variant, ViewAttributes,
    },
};

// --- Feature 022: writable address space via the in-memory DEFAULT (SimpleNodeManager) ---
//
// The TestNodeManager (used by `setup()`) OVERRIDES the NodeManagement methods, so the tests above
// exercise its own impl, gate-independent. The new gated default (memory_mgr_impl.rs) is reached only by
// in-memory managers that do NOT override — e.g. SimpleNodeManager. These tests stand up a
// SimpleNodeManager server and drive AddNodes/DeleteNodes through the real service to verify the default
// + the `clients_can_modify_address_space` gate, anchored to OPC UA Part 4 §5.8.

const WRITABLE_NS: &str = "urn:writable-address-space-test";

/// Build a SimpleNodeManager server (gate on/off), seed a parent object, connect.
async fn setup_simple(
    gate_on: bool,
) -> (Tester, Arc<SimpleNodeManager>, u16, NodeId, Arc<Session>) {
    setup_simple_rbac(gate_on, false).await
}

async fn setup_simple_rbac(
    gate_on: bool,
    enforce_rbac: bool,
) -> (Tester, Arc<SimpleNodeManager>, u16, NodeId, Arc<Session>) {
    let mut server = crate::utils::default_server()
        .enforce_role_based_access(enforce_rbac)
        .with_node_manager(simple_node_manager(
            NamespaceMetadata {
                namespace_uri: WRITABLE_NS.to_owned(),
                ..Default::default()
            },
            "writable",
        ));
    server.limits_mut().clients_can_modify_address_space = gate_on;
    let mut tester = Tester::new(server, false).await;
    let nm = tester
        .handle
        .node_managers()
        .get_of_type::<SimpleNodeManager>()
        .unwrap();
    let ns = tester.handle.get_namespace_index(WRITABLE_NS).unwrap();

    // Seed a parent object owned by the SimpleNodeManager so AddNodes under it routes to that manager.
    let parent = NodeId::new(ns, "WritableParent");
    {
        let mut sp = nm.address_space().write();
        ObjectBuilder::new(&parent, "WritableParent", "WritableParent")
            .organized_by(ObjectId::ObjectsFolder)
            .insert(&mut *sp);
    }

    let (session, lp) = tester.connect_default().await.unwrap();
    lp.spawn();
    tokio::time::timeout(Duration::from_secs(2), session.wait_for_connection())
        .await
        .unwrap();
    (tester, nm, ns, parent, session)
}

fn object_item(parent: NodeId, ns: u16, name: &str, requested: ExpandedNodeId) -> AddNodesItem {
    AddNodesItem {
        parent_node_id: parent.into(),
        reference_type_id: ReferenceTypeId::HasComponent.into(),
        requested_new_node_id: requested,
        browse_name: QualifiedName::new(ns, name),
        node_class: NodeClass::Object,
        node_attributes: AddNodeAttributes::Object(ObjectAttributes {
            specified_attributes: 1 << 6, // DisplayName
            display_name: name.into(),
            description: Default::default(),
            write_mask: Default::default(),
            user_write_mask: Default::default(),
            event_notifier: 0,
        })
        .as_extension_object(),
        type_definition: ExpandedNodeId::new(ObjectTypeId::BaseObjectType),
    }
}

#[tokio::test]
async fn simple_writable_add_browse_read_delete() {
    let (_tester, _nm, ns, parent, session) = setup_simple(true).await;

    // AddNodes -> Good + assigned id (Part 4 §5.8). The new node id is client-specified in a namespace
    // the manager owns (server-assigned/null ids require the manager to implement `handle_new_node`).
    let r = session
        .add_nodes(&[object_item(
            parent.clone(),
            ns,
            "Child",
            NodeId::new(ns, "Child").into(),
        )])
        .await
        .unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].status_code, StatusCode::Good);
    let id = r[0].added_node_id.clone();
    assert!(!id.is_null());

    // Read it back THROUGH the service (proves it is in the address space + readable).
    let vals = session
        .read(
            &[ReadValueId {
                node_id: id.clone(),
                attribute_id: AttributeId::BrowseName as u32,
                ..Default::default()
            }],
            TimestampsToReturn::Neither,
            0.0,
        )
        .await
        .unwrap();
    assert_eq!(vals[0].status(), StatusCode::Good);

    // Browse the parent -> the new child reference is present.
    let br = session
        .browse(
            &[BrowseDescription {
                node_id: parent.clone(),
                browse_direction: BrowseDirection::Forward,
                reference_type_id: ReferenceTypeId::HasComponent.into(),
                include_subtypes: true,
                node_class_mask: 0,
                result_mask: 0x3f,
            }],
            1000,
            None,
        )
        .await
        .unwrap();
    let refs = br[0].references.clone().unwrap_or_default();
    assert!(
        refs.iter().any(|rf| rf.node_id.node_id == id),
        "browse of parent must show the added child"
    );

    // DeleteNodes -> Good, then the node is gone (Read -> not Good).
    let dr = session
        .delete_nodes(&[DeleteNodesItem {
            node_id: id.clone(),
            delete_target_references: true,
        }])
        .await
        .unwrap();
    assert_eq!(dr, vec![StatusCode::Good]);

    let vals = session
        .read(
            &[ReadValueId {
                node_id: id.clone(),
                attribute_id: AttributeId::BrowseName as u32,
                ..Default::default()
            }],
            TimestampsToReturn::Neither,
            0.0,
        )
        .await
        .unwrap();
    assert_ne!(
        vals[0].status(),
        StatusCode::Good,
        "deleted node must no longer be readable"
    );
}

#[tokio::test]
async fn simple_writable_error_statuses() {
    let (_tester, _nm, ns, parent, session) = setup_simple(true).await;

    // Duplicate node id (request the parent's own id) -> BadNodeIdExists.
    let r = session
        .add_nodes(&[object_item(
            parent.clone(),
            ns,
            "Dup",
            parent.clone().into(),
        )])
        .await
        .unwrap();
    assert_eq!(r[0].status_code, StatusCode::BadNodeIdExists);

    // Missing parent (new id in the manager's namespace so it routes here) -> BadParentNodeIdInvalid.
    let missing = NodeId::new(ns, "DoesNotExist");
    let r = session
        .add_nodes(&[object_item(
            missing,
            ns,
            "Orphan",
            NodeId::new(ns, "Orphan").into(),
        )])
        .await
        .unwrap();
    assert_eq!(r[0].status_code, StatusCode::BadParentNodeIdInvalid);

    // Delete an unknown node -> BadNodeIdUnknown.
    let r = session
        .delete_nodes(&[DeleteNodesItem {
            node_id: NodeId::new(ns, "Nope"),
            delete_target_references: true,
        }])
        .await
        .unwrap();
    assert_eq!(r, vec![StatusCode::BadNodeIdUnknown]);
}

#[tokio::test]
async fn add_nodes_duplicate_browse_name_returns_bad_browse_name_duplicated() {
    let (_tester, _nm, ns, parent, session) = setup_simple(true).await;

    let first = session
        .add_nodes(&[object_item(
            parent.clone(),
            ns,
            "DuplicateBrowseName",
            NodeId::new(ns, "DuplicateBrowseNameA").into(),
        )])
        .await
        .unwrap();
    assert_eq!(first[0].status_code, StatusCode::Good);

    // OPC UA Part 4 5.8.2.4: duplicate BrowseName under the same parent is rejected.
    let duplicate = session
        .add_nodes(&[object_item(
            parent,
            ns,
            "DuplicateBrowseName",
            NodeId::new(ns, "DuplicateBrowseNameB").into(),
        )])
        .await
        .unwrap();

    assert_eq!(
        duplicate[0].status_code,
        StatusCode::BadBrowseNameDuplicated
    );
}

#[tokio::test]
async fn add_nodes_mismatched_node_class_returns_bad_node_class_invalid() {
    let (_tester, _nm, ns, parent, session) = setup_simple(true).await;
    let mut item = object_item(
        parent,
        ns,
        "InvalidNodeClass",
        NodeId::new(ns, "InvalidNodeClass").into(),
    );
    item.node_class = NodeClass::Unspecified;
    item.type_definition = ExpandedNodeId::null();

    // OPC UA Part 4 5.8.2.4: an invalid node class is rejected with BadNodeClassInvalid.
    let result = session.add_nodes(&[item]).await.unwrap();

    assert_eq!(result[0].status_code, StatusCode::BadNodeClassInvalid);
}

#[tokio::test]
async fn add_nodes_foreign_namespace_returns_bad_node_id_rejected() {
    let (_tester, _nm, ns, parent, session) = setup_simple(true).await;

    // OPC UA Part 4 5.8.2.4: a requested NodeId in an unsupported namespace is rejected.
    let result = session
        .add_nodes(&[object_item(
            parent,
            ns,
            "ForeignNamespace",
            NodeId::new(ns + 100, "ForeignNamespace").into(),
        )])
        .await
        .unwrap();

    assert_eq!(result[0].status_code, StatusCode::BadNodeIdRejected);
}

#[tokio::test]
async fn simple_gate_off_refuses_modification() {
    let (_tester, _nm, ns, parent, session) = setup_simple(false).await;

    // With the gate OFF (default), every NodeManagement op is refused and nothing changes.
    let r = session
        .add_nodes(&[object_item(
            parent.clone(),
            ns,
            "Nope",
            NodeId::new(ns, "Nope").into(),
        )])
        .await
        .unwrap();
    assert_eq!(r[0].status_code, StatusCode::BadServiceUnsupported);
    assert!(r[0].added_node_id.is_null());

    let dr = session
        .delete_nodes(&[DeleteNodesItem {
            node_id: parent.clone(),
            delete_target_references: true,
        }])
        .await
        .unwrap();
    assert_eq!(dr, vec![StatusCode::BadServiceUnsupported]);

    // References are gated too.
    let rr = session
        .add_references(&[AddReferencesItem {
            source_node_id: parent.clone(),
            reference_type_id: ReferenceTypeId::Organizes.into(),
            is_forward: true,
            target_server_uri: Default::default(),
            target_node_id: NodeId::new(ns, "RefTarget").into(),
            target_node_class: NodeClass::Object,
        }])
        .await
        .unwrap();
    assert_eq!(rr, vec![StatusCode::BadServiceUnsupported]);
}

/// Seed an Object owned by the SimpleNodeManager, organized under `parent`.
fn seed_object(nm: &SimpleNodeManager, parent: &NodeId, id: &NodeId, name: &str) {
    let mut sp = nm.address_space().write();
    ObjectBuilder::new(id, name, name)
        .organized_by(parent.clone())
        .insert(&mut *sp);
}

#[tokio::test]
async fn simple_writable_add_delete_reference() {
    let (_tester, nm, ns, parent, session) = setup_simple(true).await;
    let a = NodeId::new(ns, "RefA");
    let b = NodeId::new(ns, "RefB");
    seed_object(&nm, &parent, &a, "RefA");
    seed_object(&nm, &parent, &b, "RefB");

    // AddReferences a -Organizes-> b (forward).
    let r = session
        .add_references(&[AddReferencesItem {
            source_node_id: a.clone(),
            reference_type_id: ReferenceTypeId::Organizes.into(),
            is_forward: true,
            target_server_uri: Default::default(),
            target_node_id: b.clone().into(),
            target_node_class: NodeClass::Object,
        }])
        .await
        .unwrap();
    assert_eq!(r, vec![StatusCode::Good]);

    // Browse a forward Organizes -> b present.
    let browse_a = |session: &Arc<Session>, a: NodeId| {
        let session = session.clone();
        async move {
            session
                .browse(
                    &[BrowseDescription {
                        node_id: a,
                        browse_direction: BrowseDirection::Forward,
                        reference_type_id: ReferenceTypeId::Organizes.into(),
                        include_subtypes: true,
                        node_class_mask: 0,
                        result_mask: 0x3f,
                    }],
                    1000,
                    None,
                )
                .await
                .unwrap()
        }
    };
    let br = browse_a(&session, a.clone()).await;
    assert!(
        br[0]
            .references
            .clone()
            .unwrap_or_default()
            .iter()
            .any(|rf| rf.node_id.node_id == b),
        "browse must show the added reference"
    );

    // DeleteReferences -> Good, then it's gone from Browse.
    let dr = session
        .delete_references(&[DeleteReferencesItem {
            source_node_id: a.clone(),
            reference_type_id: ReferenceTypeId::Organizes.into(),
            is_forward: true,
            target_node_id: b.clone().into(),
            delete_bidirectional: true,
        }])
        .await
        .unwrap();
    assert_eq!(dr, vec![StatusCode::Good]);

    let br = browse_a(&session, a.clone()).await;
    assert!(
        !br[0]
            .references
            .clone()
            .unwrap_or_default()
            .iter()
            .any(|rf| rf.node_id.node_id == b),
        "deleted reference must be gone from Browse"
    );
}

#[tokio::test]
async fn simple_writable_reference_errors() {
    let (_tester, nm, ns, parent, session) = setup_simple(true).await;
    let a = NodeId::new(ns, "RefSrc");
    seed_object(&nm, &parent, &a, "RefSrc");

    let add = |session: &Arc<Session>, src: NodeId, tgt: NodeId, rt: NodeId| {
        let session = session.clone();
        async move {
            session
                .add_references(&[AddReferencesItem {
                    source_node_id: src,
                    reference_type_id: rt,
                    is_forward: true,
                    target_server_uri: Default::default(),
                    target_node_id: tgt.into(),
                    target_node_class: NodeClass::Object,
                }])
                .await
                .unwrap()
        }
    };

    // Both endpoints missing (both in the manager's namespace, both fail) -> BadSourceNodeIdInvalid.
    // NB: per Part 4, a reference add succeeds if EITHER end is handled, so a single-bad-end case can
    // still collapse to Good; both-bad makes the operation-level status unambiguous.
    let r = add(
        &session,
        NodeId::new(ns, "NoSuchSource"),
        NodeId::new(ns, "NoSuchTarget"),
        ReferenceTypeId::Organizes.into(),
    )
    .await;
    assert_eq!(r, vec![StatusCode::BadSourceNodeIdInvalid]);

    // Null reference type (rejected at item validation) -> BadReferenceTypeIdInvalid.
    let r = add(&session, a.clone(), a.clone(), NodeId::null()).await;
    assert_eq!(r, vec![StatusCode::BadReferenceTypeIdInvalid]);
}

#[tokio::test]
async fn add_references_external_local_only_reference_returns_bad_reference_local_only() {
    let (_tester, nm, ns, parent, session) = setup_simple(true).await;
    let source = NodeId::new(ns, "LocalOnlySource");
    let target = NodeId::new(ns, "LocalOnlyTarget");
    seed_object(&nm, &parent, &source, "LocalOnlySource");
    seed_object(&nm, &parent, &target, "LocalOnlyTarget");

    // OPC UA Part 4 5.8.4: local-only reference types are invalid for remote server targets.
    let result = session
        .add_references(&[AddReferencesItem {
            source_node_id: source,
            reference_type_id: ReferenceTypeId::Organizes.into(),
            is_forward: true,
            target_server_uri: UAString::from("urn:remote-server"),
            target_node_id: target.into(),
            target_node_class: NodeClass::Object,
        }])
        .await
        .unwrap();

    assert_eq!(result, vec![StatusCode::BadReferenceLocalOnly]);
}

#[tokio::test]
async fn add_nodes_array_dimensions_value_rank_mismatch_returns_bad_node_attributes_invalid() {
    let (_tester, _nm, ns, parent, session) = setup_simple(true).await;
    let mask = AttributesMask::DISPLAY_NAME
        | AttributesMask::DATA_TYPE
        | AttributesMask::VALUE_RANK
        | AttributesMask::ARRAY_DIMENSIONS;

    // OPC UA Part 3 5.6: ArrayDimensions length must match a concrete ValueRank.
    let result = session
        .add_nodes(&[AddNodesItem {
            parent_node_id: parent.into(),
            reference_type_id: ReferenceTypeId::HasComponent.into(),
            requested_new_node_id: NodeId::new(ns, "RankMismatchVariable").into(),
            browse_name: QualifiedName::new(ns, "RankMismatchVariable"),
            node_class: NodeClass::Variable,
            node_attributes: AddNodeAttributes::Variable(VariableAttributes {
                specified_attributes: mask.bits(),
                display_name: "RankMismatchVariable".into(),
                data_type: DataTypeId::Double.into(),
                value_rank: 1,
                array_dimensions: Some(vec![2, 3]),
                value: Variant::Empty,
                ..Default::default()
            })
            .as_extension_object(),
            type_definition: ExpandedNodeId::new(VariableTypeId::BaseDataVariableType),
        }])
        .await
        .unwrap();

    assert_eq!(result[0].status_code, StatusCode::BadNodeAttributesInvalid);
}

#[tokio::test]
async fn add_nodes_abstract_type_definition_returns_bad_type_definition_invalid() {
    let (_tester, nm, ns, parent, session) = setup_simple(true).await;
    let abstract_type = NodeId::new(ns, "AbstractObjectType");
    {
        let mut sp = nm.address_space().write();
        ObjectTypeBuilder::new(&abstract_type, "AbstractObjectType", "AbstractObjectType")
            .is_abstract(true)
            .subtype_of(ObjectTypeId::BaseObjectType)
            .insert(&mut *sp);
    }

    // OPC UA Part 3 5.6/6: abstract type definitions cannot be instantiated.
    let mut item = object_item(
        parent,
        ns,
        "AbstractTypeInstance",
        NodeId::new(ns, "AbstractTypeInstance").into(),
    );
    item.type_definition = abstract_type.into();
    let result = session.add_nodes(&[item]).await.unwrap();

    assert_eq!(result[0].status_code, StatusCode::BadTypeDefinitionInvalid);
}

#[tokio::test]
async fn add_references_abstract_reference_type_returns_bad_reference_type_id_invalid() {
    let (tester, nm, ns, parent, session) = setup_simple(true).await;
    let source = NodeId::new(ns, "AbstractReferenceSource");
    let target = NodeId::new(ns, "AbstractReferenceTarget");
    seed_object(&nm, &parent, &source, "AbstractReferenceSource");
    seed_object(&nm, &parent, &target, "AbstractReferenceTarget");

    let abstract_reference_type = NodeId::new(ns, "AbstractReferenceType");
    {
        let mut sp = nm.address_space().write();
        ReferenceTypeBuilder::new(
            &abstract_reference_type,
            "AbstractReferenceType",
            "AbstractReferenceType",
        )
        .is_abstract(true)
        .subtype_of(ReferenceTypeId::References)
        .insert(&mut *sp);
    }
    let references_type = NodeId::from(ReferenceTypeId::References);
    tester.handle.type_tree().write().add_type_node(
        &abstract_reference_type,
        &references_type,
        NodeClass::ReferenceType,
    );

    // OPC UA Part 3 5.3.1: abstract ReferenceTypes are not valid instance references.
    let result = session
        .add_references(&[AddReferencesItem {
            source_node_id: source,
            reference_type_id: abstract_reference_type,
            is_forward: true,
            target_server_uri: Default::default(),
            target_node_id: target.into(),
            target_node_class: NodeClass::Object,
        }])
        .await
        .unwrap();

    assert_eq!(result, vec![StatusCode::BadReferenceTypeIdInvalid]);
}

#[tokio::test]
async fn symmetric_reference_type_with_inverse_name_returns_bad_node_attributes_invalid() {
    let (_tester, _nm, ns, parent, session) = setup_simple(true).await;
    let mask = AttributesMask::DISPLAY_NAME
        | AttributesMask::IS_ABSTRACT
        | AttributesMask::SYMMETRIC
        | AttributesMask::INVERSE_NAME;

    // OPC UA Part 3 5.3.2: symmetric ReferenceTypes do not define an InverseName.
    let result = session
        .add_nodes(&[AddNodesItem {
            parent_node_id: parent.into(),
            reference_type_id: ReferenceTypeId::HasComponent.into(),
            requested_new_node_id: NodeId::new(ns, "SymmetricWithInverseName").into(),
            browse_name: QualifiedName::new(ns, "SymmetricWithInverseName"),
            node_class: NodeClass::ReferenceType,
            node_attributes: AddNodeAttributes::ReferenceType(ReferenceTypeAttributes {
                specified_attributes: mask.bits(),
                display_name: "SymmetricWithInverseName".into(),
                description: Default::default(),
                write_mask: Default::default(),
                user_write_mask: Default::default(),
                is_abstract: false,
                symmetric: true,
                inverse_name: "InverseName".into(),
            })
            .as_extension_object(),
            type_definition: ExpandedNodeId::null(),
        }])
        .await
        .unwrap();

    assert_eq!(result[0].status_code, StatusCode::BadNodeAttributesInvalid);
}

/// Edge: deleting a node that has references stays consistent (parent reference removed, no dangling
/// reference, no panic).
#[tokio::test]
async fn simple_writable_delete_node_with_references() {
    let (_tester, _nm, ns, parent, session) = setup_simple(true).await;

    // Add a child (parent -HasComponent-> child) and an extra reference child -Organizes-> parent.
    let child = NodeId::new(ns, "ChildWithRefs");
    let r = session
        .add_nodes(&[object_item(
            parent.clone(),
            ns,
            "ChildWithRefs",
            child.clone().into(),
        )])
        .await
        .unwrap();
    assert_eq!(r[0].status_code, StatusCode::Good);
    let r = session
        .add_references(&[AddReferencesItem {
            source_node_id: child.clone(),
            reference_type_id: ReferenceTypeId::Organizes.into(),
            is_forward: true,
            target_server_uri: Default::default(),
            target_node_id: parent.clone().into(),
            target_node_class: NodeClass::Object,
        }])
        .await
        .unwrap();
    assert_eq!(r, vec![StatusCode::Good]);

    // Delete the child (with its target references) -> Good, no panic.
    let dr = session
        .delete_nodes(&[DeleteNodesItem {
            node_id: child.clone(),
            delete_target_references: true,
        }])
        .await
        .unwrap();
    assert_eq!(dr, vec![StatusCode::Good]);

    // The child is gone and the parent no longer references it (no dangling reference).
    let vals = session
        .read(
            &[ReadValueId {
                node_id: child.clone(),
                attribute_id: AttributeId::BrowseName as u32,
                ..Default::default()
            }],
            TimestampsToReturn::Neither,
            0.0,
        )
        .await
        .unwrap();
    assert_ne!(vals[0].status(), StatusCode::Good);

    let br = session
        .browse(
            &[BrowseDescription {
                node_id: parent.clone(),
                browse_direction: BrowseDirection::Forward,
                reference_type_id: ReferenceTypeId::HasComponent.into(),
                include_subtypes: true,
                node_class_mask: 0,
                result_mask: 0x3f,
            }],
            1000,
            None,
        )
        .await
        .unwrap();
    assert!(
        !br[0]
            .references
            .clone()
            .unwrap_or_default()
            .iter()
            .any(|rf| rf.node_id.node_id == child),
        "deleted child must not remain referenced by the parent"
    );
}

#[tokio::test]
async fn add_delete_node() {
    let (_tester, nm, session) = setup().await;

    let r = session
        .add_nodes(&[AddNodesItem {
            parent_node_id: ObjectId::ObjectsFolder.into(),
            reference_type_id: ReferenceTypeId::HasComponent.into(),
            requested_new_node_id: ExpandedNodeId::null(),
            browse_name: "MyNode".into(),
            node_class: NodeClass::Object,
            node_attributes: AddNodeAttributes::Object(ObjectAttributes {
                specified_attributes: (1 << 5) | (1 << 6),
                display_name: "DisplayName".into(),
                description: "Description".into(),
                write_mask: Default::default(),
                user_write_mask: Default::default(),
                event_notifier: EventNotifier::all().bits(), // Should not be set
            })
            .as_extension_object(),
            type_definition: ExpandedNodeId::new(ObjectTypeId::FolderType),
        }])
        .await
        .unwrap();

    assert_eq!(1, r.len());
    let it = &r[0];
    assert_eq!(it.status_code, StatusCode::Good);
    assert!(!it.added_node_id.is_null());

    let id = it.added_node_id.clone();

    {
        let sp = nm.address_space().read();
        let node_opt = sp.find(&id);
        let Some(node_guard) = node_opt else {
            panic!("Missing");
        };
        let NodeType::Object(o) = &*node_guard else {
            panic!("Missing");
        };
        assert_eq!(o.browse_name(), &"MyNode".into());
        assert_eq!(o.display_name(), &"DisplayName".into());
        assert_eq!(o.description(), Some(&"Description".into()));
        assert_eq!(0, o.event_notifier().bits());
    }

    println!("{id}");

    let r = session
        .delete_nodes(&[DeleteNodesItem {
            node_id: id.clone(),
            delete_target_references: true,
        }])
        .await
        .unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0], StatusCode::Good);
}

#[tokio::test]
async fn add_delete_reference() {
    let (tester, nm, session) = setup().await;

    let id1 = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        ObjectBuilder::new(&id1, "TestObj1", "TestObj1")
            .build()
            .into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        Some(&ObjectTypeId::FolderType.into()),
        Vec::new(),
    );
    let id2 = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        ObjectBuilder::new(&id2, "TestObj2", "TestObj2")
            .build()
            .into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        Some(&ObjectTypeId::FolderType.into()),
        Vec::new(),
    );

    let r = session
        .add_references(&[AddReferencesItem {
            source_node_id: id1.clone(),
            reference_type_id: ReferenceTypeId::HasCondition.into(),
            is_forward: true,
            target_server_uri: Default::default(),
            target_node_id: id2.clone().into(),
            target_node_class: NodeClass::Object,
        }])
        .await
        .unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0], StatusCode::Good);

    {
        let sp = nm.address_space().read();
        let type_tree = tester.handle.type_tree().read();
        sp.find_references(
            &id1,
            None::<(NodeId, bool)>,
            &*type_tree,
            opcua::types::BrowseDirection::Forward,
        )
        .find(|r| r.target_node == &id2 && r.reference_type == &ReferenceTypeId::HasCondition)
        .unwrap();
    }

    let r = session
        .delete_references(&[DeleteReferencesItem {
            source_node_id: id1.clone(),
            reference_type_id: ReferenceTypeId::HasCondition.into(),
            is_forward: true,
            target_node_id: id2.clone().into(),
            delete_bidirectional: true,
        }])
        .await
        .unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0], StatusCode::Good);
}

#[tokio::test]
async fn add_delete_node_limits() {
    let (tester, _nm, session) = setup().await;
    let limit = tester
        .handle
        .info()
        .config
        .limits
        .operational
        .max_nodes_per_node_management;

    // Add zero
    let e = session.add_nodes(&[]).await.unwrap_err();
    assert_eq!(e.status(), StatusCode::BadNothingToDo);

    // Add too many
    let e = session
        .add_nodes(
            &(0..(limit + 1))
                .map(|i| {
                    AddNodesItem {
                        parent_node_id: ObjectId::ObjectsFolder.into(),
                        reference_type_id: ReferenceTypeId::HasComponent.into(),
                        requested_new_node_id: ExpandedNodeId::null(),
                        browse_name: format!("MyNode{i}").into(),
                        node_class: NodeClass::Object,
                        node_attributes: AddNodeAttributes::Object(ObjectAttributes {
                            specified_attributes: (1 << 5) | (1 << 6),
                            display_name: "DisplayName".into(),
                            description: "Description".into(),
                            write_mask: Default::default(),
                            user_write_mask: Default::default(),
                            event_notifier: EventNotifier::all().bits(), // Should not be set
                        })
                        .as_extension_object(),
                        type_definition: ExpandedNodeId::new(ObjectTypeId::FolderType),
                    }
                })
                .collect::<Vec<_>>(),
        )
        .await
        .unwrap_err();
    assert_eq!(e.status(), StatusCode::BadTooManyOperations);
}

#[tokio::test]
async fn add_delete_reference_limits() {
    let (tester, _nm, session) = setup().await;
    let limit = tester
        .handle
        .info()
        .config
        .limits
        .operational
        .max_references_per_references_management;

    // Add zero
    let e = session.add_references(&[]).await.unwrap_err();
    assert_eq!(e.status(), StatusCode::BadNothingToDo);

    // Add too many
    let e = session
        .add_references(
            &(0..(limit + 1))
                .map(|i| AddReferencesItem {
                    source_node_id: NodeId::new(2, i as u32),
                    reference_type_id: ReferenceTypeId::HasCause.into(),
                    is_forward: true,
                    target_server_uri: Default::default(),
                    target_node_id: NodeId::new(2, (i + 1) as u32).into(),
                    target_node_class: NodeClass::Object,
                })
                .collect::<Vec<_>>(),
        )
        .await
        .unwrap_err();
    assert_eq!(e.status(), StatusCode::BadTooManyOperations);
}

/// C7 (multi-AI cross-check, `specs/multi-ai-test-suites/UNIFIED-PROTOCOL.md`): AddNodes processes a
/// batch per-operation (Part 4 §5.8.2) — there is no all-or-nothing rollback. A mixed batch of
/// [good, bad-type, dependent-on-the-good] must: succeed the good one, reject the bad one with a
/// per-node status (leaving no trace), and succeed the dependent one whose parent was added *earlier
/// in the same batch*. The good/dependent nodes persist despite the bad sibling.
#[tokio::test]
async fn add_nodes_mixed_batch_is_per_operation_with_in_batch_dependency() {
    let (_tester, _nm, ns, parent, session) = setup_simple(true).await;

    let good = NodeId::new(ns, "BatchGood");
    let bad = NodeId::new(ns, "BatchBad");
    let dependent = NodeId::new(ns, "BatchDependent");

    // A "bad-type" item: node_class says Variable but the attributes are Object — a class/attributes
    // mismatch the server must reject with BadNodeAttributesInvalid.
    let mut mistyped = object_item(parent.clone(), ns, "BatchBad", bad.clone().into());
    mistyped.node_class = NodeClass::Variable;

    let r = session
        .add_nodes(&[
            // good: child of the existing parent
            object_item(parent.clone(), ns, "BatchGood", good.clone().into()),
            // bad: class/attributes mismatch
            mistyped,
            // dependent: child of `good`, which is added earlier in THIS same batch
            object_item(good.clone(), ns, "BatchDependent", dependent.clone().into()),
        ])
        .await
        .unwrap();
    assert_eq!(r.len(), 3);
    assert_eq!(r[0].status_code, StatusCode::Good, "good node");
    assert_eq!(
        r[1].status_code,
        StatusCode::BadNodeAttributesInvalid,
        "bad-type node must be rejected per-operation"
    );
    assert_eq!(
        r[2].status_code,
        StatusCode::Good,
        "dependent node must resolve its in-batch parent"
    );

    // The good and dependent nodes persist (no rollback); the bad one left no trace.
    let reads = session
        .read(
            &[
                ReadValueId {
                    node_id: good.clone(),
                    attribute_id: AttributeId::BrowseName as u32,
                    ..Default::default()
                },
                ReadValueId {
                    node_id: dependent.clone(),
                    attribute_id: AttributeId::BrowseName as u32,
                    ..Default::default()
                },
                ReadValueId {
                    node_id: bad.clone(),
                    attribute_id: AttributeId::BrowseName as u32,
                    ..Default::default()
                },
            ],
            TimestampsToReturn::Neither,
            0.0,
        )
        .await
        .unwrap();
    assert_eq!(reads[0].status(), StatusCode::Good, "good node persists");
    assert_eq!(
        reads[1].status(),
        StatusCode::Good,
        "dependent node persists"
    );
    assert_ne!(
        reads[2].status(),
        StatusCode::Good,
        "rejected node must not exist"
    );

    // Reference consistency: browsing the good node shows the dependent child.
    let br = session
        .browse(
            &[BrowseDescription {
                node_id: good.clone(),
                browse_direction: BrowseDirection::Forward,
                reference_type_id: ReferenceTypeId::HasComponent.into(),
                include_subtypes: true,
                node_class_mask: 0,
                result_mask: 0x3f,
            }],
            1000,
            None,
        )
        .await
        .unwrap();
    let refs = br[0].references.clone().unwrap_or_default();
    assert!(
        refs.iter().any(|rf| rf.node_id.node_id == dependent),
        "the dependent child must be referenced from its in-batch parent"
    );
}

/// Part 4 §5.7: AddNodes supports all node classes. Feature 022 added Object+Variable; this verifies
/// the remaining six (Method, ObjectType, VariableType, ReferenceType, DataType, View) are created.
#[tokio::test]
async fn simple_writable_adds_all_node_classes() {
    let (_tester, _nm, ns, parent, session) = setup_simple(true).await;
    const DN: u32 = 1 << 6; // DisplayName specified

    fn item(
        parent: &NodeId,
        ns: u16,
        name: &str,
        node_class: NodeClass,
        attrs: AddNodeAttributes,
    ) -> AddNodesItem {
        AddNodesItem {
            parent_node_id: parent.clone().into(),
            reference_type_id: ReferenceTypeId::HasComponent.into(),
            requested_new_node_id: NodeId::new(ns, name).into(),
            browse_name: QualifiedName::new(ns, name),
            node_class,
            node_attributes: attrs.as_extension_object(),
            type_definition: ExpandedNodeId::null(),
        }
    }

    let items = vec![
        item(
            &parent,
            ns,
            "Meth",
            NodeClass::Method,
            AddNodeAttributes::Method(MethodAttributes {
                specified_attributes: DN,
                display_name: "Meth".into(),
                ..Default::default()
            }),
        ),
        item(
            &parent,
            ns,
            "ObjT",
            NodeClass::ObjectType,
            AddNodeAttributes::ObjectType(ObjectTypeAttributes {
                specified_attributes: DN,
                display_name: "ObjT".into(),
                ..Default::default()
            }),
        ),
        item(
            &parent,
            ns,
            "VarT",
            NodeClass::VariableType,
            AddNodeAttributes::VariableType(VariableTypeAttributes {
                specified_attributes: DN,
                display_name: "VarT".into(),
                ..Default::default()
            }),
        ),
        item(
            &parent,
            ns,
            "RefT",
            NodeClass::ReferenceType,
            AddNodeAttributes::ReferenceType(ReferenceTypeAttributes {
                specified_attributes: DN,
                display_name: "RefT".into(),
                ..Default::default()
            }),
        ),
        item(
            &parent,
            ns,
            "DatT",
            NodeClass::DataType,
            AddNodeAttributes::DataType(DataTypeAttributes {
                specified_attributes: DN,
                display_name: "DatT".into(),
                ..Default::default()
            }),
        ),
        item(
            &parent,
            ns,
            "Viw",
            NodeClass::View,
            AddNodeAttributes::View(ViewAttributes {
                specified_attributes: DN,
                display_name: "Viw".into(),
                ..Default::default()
            }),
        ),
    ];
    let expected = [
        NodeClass::Method,
        NodeClass::ObjectType,
        NodeClass::VariableType,
        NodeClass::ReferenceType,
        NodeClass::DataType,
        NodeClass::View,
    ];

    let r = session.add_nodes(&items).await.unwrap();
    assert_eq!(r.len(), 6);
    for (i, res) in r.iter().enumerate() {
        assert_eq!(
            res.status_code,
            StatusCode::Good,
            "class {:?} should add",
            expected[i]
        );
        assert!(!res.added_node_id.is_null());
    }

    // Read NodeClass back through the service for each.
    let reads: Vec<ReadValueId> = r
        .iter()
        .map(|res| ReadValueId {
            node_id: res.added_node_id.clone(),
            attribute_id: AttributeId::NodeClass as u32,
            ..Default::default()
        })
        .collect();
    let vals = session
        .read(&reads, TimestampsToReturn::Neither, 0.0)
        .await
        .unwrap();
    for (i, v) in vals.iter().enumerate() {
        assert_eq!(v.status(), StatusCode::Good);
        let nc = v.value.clone().unwrap();
        assert_eq!(
            nc,
            opcua::types::Variant::Int32(expected[i] as i32),
            "NodeClass of item {i}"
        );
    }
}

/// Part 3 §9.32: GeneralModelChangeEvent reports model changes. This verifies the event's field
/// mapping (the high-risk part): EventType, SourceNode = Server, and the Changes array.
#[tokio::test]
async fn general_model_change_event_fields() {
    use opcua::nodes::{Event, EventField};
    use opcua::server::node_manager::GeneralModelChangeEvent;
    use opcua::types::{
        ModelChangeStructureDataType, NumericRange, ObjectTypeId, QualifiedName, Variant,
    };

    let change = ModelChangeStructureDataType {
        affected: NodeId::new(2, "Added"),
        affected_type: NodeId::null(),
        verb: 1, // NodeAdded
    };
    let event = GeneralModelChangeEvent::new(vec![change.clone()]);

    assert_eq!(
        event.event_type_id(),
        &NodeId::from(ObjectTypeId::GeneralModelChangeEventType)
    );

    let field = |name: &str| {
        event.get_value(
            AttributeId::Value,
            &NumericRange::None,
            &[QualifiedName::new(0, name)],
        )
    };

    assert_eq!(
        field("SourceNode"),
        Variant::from(NodeId::from(ObjectId::Server))
    );
    assert_eq!(
        field("EventType"),
        Variant::from(NodeId::from(ObjectTypeId::GeneralModelChangeEventType))
    );

    // Changes is an array of one ModelChangeStructureDataType (verb NodeAdded).
    let Variant::Array(arr) = field("Changes") else {
        panic!("Changes must be an array");
    };
    assert_eq!(arr.values.len(), 1);
    let Variant::ExtensionObject(obj) = &arr.values[0] else {
        panic!("Changes element must be an ExtensionObject");
    };
    let decoded = obj
        .inner_as::<ModelChangeStructureDataType>()
        .expect("ModelChangeStructureDataType");
    assert_eq!(decoded.affected, NodeId::new(2, "Added"));
    assert_eq!(decoded.verb, 1);
}

/// Part 3 §9.32 end-to-end: AddNodes by a client fires a GeneralModelChangeEvent from the Server node
/// to a subscriber monitoring Server events.
#[tokio::test]
async fn add_nodes_emits_general_model_change_event() {
    use crate::utils::ChannelNotifications;
    use opcua::types::{
        EventFilter, ExtensionObject, MonitoredItemCreateRequest, MonitoringMode,
        MonitoringParameters, NumericRange, ObjectTypeId, SimpleAttributeOperand, Variant,
    };

    let (_tester, _nm, ns, parent, session) = setup_simple(true).await;

    // Subscribe to events on the Server node.
    let (notifs, _, mut events) = ChannelNotifications::new();
    let sub_id = session
        .create_subscription(Duration::from_millis(100), 100, 20, 1000, 0, true, notifs)
        .await
        .unwrap();
    let select = vec![
        SimpleAttributeOperand {
            type_definition_id: NodeId::new(0, 2041),
            browse_path: Some(vec![QualifiedName::new(0, "EventType")]),
            attribute_id: AttributeId::Value as u32,
            index_range: NumericRange::None,
        },
        SimpleAttributeOperand {
            type_definition_id: NodeId::from(ObjectTypeId::GeneralModelChangeEventType),
            browse_path: Some(vec![QualifiedName::new(0, "Changes")]),
            attribute_id: AttributeId::Value as u32,
            index_range: NumericRange::None,
        },
    ];
    let res = session
        .create_monitored_items(
            sub_id,
            TimestampsToReturn::Both,
            vec![MonitoredItemCreateRequest {
                item_to_monitor: ReadValueId {
                    node_id: ObjectId::Server.into(),
                    attribute_id: AttributeId::EventNotifier as u32,
                    ..Default::default()
                },
                monitoring_mode: MonitoringMode::Reporting,
                requested_parameters: MonitoringParameters {
                    sampling_interval: 0.0,
                    queue_size: 10,
                    discard_oldest: true,
                    filter: ExtensionObject::new(EventFilter {
                        select_clauses: Some(select),
                        where_clause: Default::default(),
                    }),
                    ..Default::default()
                },
            }],
        )
        .await
        .unwrap();
    assert_eq!(
        res[0].result.status_code,
        StatusCode::Good,
        "Server must accept event monitoring"
    );

    // AddNodes -> should fire a GeneralModelChangeEvent from the Server node.
    let r = session
        .add_nodes(&[object_item(
            parent.clone(),
            ns,
            "ModelChangeChild",
            NodeId::new(ns, "ModelChangeChild").into(),
        )])
        .await
        .unwrap();
    assert_eq!(r[0].status_code, StatusCode::Good);

    // AddNodes fires both a GeneralModelChangeEvent and node-management audit events; find the
    // model-change one (field[0] = EventType, field[1] = Changes) among the delivered events.
    let model_change_type = Variant::from(NodeId::from(ObjectTypeId::GeneralModelChangeEventType));
    let mut found = false;
    for _ in 0..5 {
        let Ok(Some((_h, v))) = tokio::time::timeout(Duration::from_secs(3), events.recv()).await
        else {
            break;
        };
        let fields = v.unwrap();
        if fields[0] == model_change_type {
            let Variant::Array(changes) = &fields[1] else {
                panic!("Changes must be an array, got {:?}", fields[1]);
            };
            assert!(!changes.values.is_empty(), "at least one change reported");
            found = true;
            break;
        }
    }
    assert!(
        found,
        "a GeneralModelChangeEvent must be delivered after AddNodes"
    );
}

/// Part 3/4 auditing: AddNodes by a client emits an AuditAddNodesEventType (i=2091) from the Server
/// node, recording the action for auditors.
#[tokio::test]
async fn add_nodes_emits_audit_event() {
    use crate::utils::ChannelNotifications;
    use opcua::types::{
        EventFilter, ExtensionObject, MonitoredItemCreateRequest, MonitoringMode,
        MonitoringParameters, NumericRange, SimpleAttributeOperand, Variant,
    };

    let (_tester, _nm, ns, parent, session) = setup_simple(true).await;

    let (notifs, _, mut events) = ChannelNotifications::new();
    let sub_id = session
        .create_subscription(Duration::from_millis(100), 100, 20, 1000, 0, true, notifs)
        .await
        .unwrap();
    let select = vec![SimpleAttributeOperand {
        type_definition_id: NodeId::new(0, 2041), // BaseEventType
        browse_path: Some(vec![QualifiedName::new(0, "EventType")]),
        attribute_id: AttributeId::Value as u32,
        index_range: NumericRange::None,
    }];
    let res = session
        .create_monitored_items(
            sub_id,
            TimestampsToReturn::Both,
            vec![MonitoredItemCreateRequest {
                item_to_monitor: ReadValueId {
                    node_id: ObjectId::Server.into(),
                    attribute_id: AttributeId::EventNotifier as u32,
                    ..Default::default()
                },
                monitoring_mode: MonitoringMode::Reporting,
                requested_parameters: MonitoringParameters {
                    sampling_interval: 0.0,
                    queue_size: 10,
                    discard_oldest: true,
                    filter: ExtensionObject::new(EventFilter {
                        select_clauses: Some(select),
                        where_clause: Default::default(),
                    }),
                    ..Default::default()
                },
            }],
        )
        .await
        .unwrap();
    assert_eq!(res[0].result.status_code, StatusCode::Good);

    let r = session
        .add_nodes(&[object_item(
            parent.clone(),
            ns,
            "AuditChild",
            NodeId::new(ns, "AuditChild").into(),
        )])
        .await
        .unwrap();
    assert_eq!(r[0].status_code, StatusCode::Good);

    // AuditAddNodesEventType = i=2091. Find it among the delivered events.
    let audit_type = Variant::from(NodeId::new(0, 2091));
    let mut found = false;
    for _ in 0..5 {
        let Ok(Some((_h, v))) = tokio::time::timeout(Duration::from_secs(3), events.recv()).await
        else {
            break;
        };
        if v.unwrap()[0] == audit_type {
            found = true;
            break;
        }
    }
    assert!(
        found,
        "an AuditAddNodesEventType must be delivered after AddNodes"
    );
}

/// Feature 031 US5 (Part 3 §8.55 AddReference): AddReferences requires the AddReference permission on
/// the source node. The anonymous session holds the Anonymous role (i=15644), not Operator (i=15680),
/// so a source granting AddReference only to Operator denies it; an unpermissioned source allows it.
#[tokio::test]
async fn simple_add_reference_enforced_by_role_permission() {
    // RBAC enforcement is opt-in; enable it so node-level RolePermissions are honored.
    let (_tester, nm, ns, parent, session) = setup_simple_rbac(true, true).await;
    let src = NodeId::new(ns, "RbacRefSrc");
    let tgt = NodeId::new(ns, "RbacRefTgt");
    {
        let mut sp = nm.address_space().write();
        ObjectBuilder::new(&src, "RbacRefSrc", "RbacRefSrc")
            .organized_by(parent.clone())
            .role_permissions(vec![RolePermissionType {
                role_id: NodeId::new(0, 15680), // Operator only — anonymous session lacks it
                permissions: PermissionType::AddReference,
            }])
            .insert(&mut *sp);
        ObjectBuilder::new(&tgt, "RbacRefTgt", "RbacRefTgt")
            .organized_by(parent.clone())
            .insert(&mut *sp);
    }

    let denied = session
        .add_references(&[AddReferencesItem {
            source_node_id: src,
            reference_type_id: ReferenceTypeId::Organizes.into(),
            is_forward: true,
            target_server_uri: Default::default(),
            target_node_id: tgt.clone().into(),
            target_node_class: NodeClass::Object,
        }])
        .await
        .unwrap();
    assert_eq!(denied, vec![StatusCode::BadUserAccessDenied]);

    // Control: a source granting AddReference to the Anonymous role the session holds is allowed.
    // (Under opt-in enforcement an UNconfigured node would fail closed, so the grant is explicit.)
    let open = NodeId::new(ns, "OpenRefSrc");
    {
        let mut sp = nm.address_space().write();
        ObjectBuilder::new(&open, "OpenRefSrc", "OpenRefSrc")
            .organized_by(parent.clone())
            .role_permissions(vec![RolePermissionType {
                role_id: NodeId::new(0, 15644), // Anonymous — held by the anonymous session
                permissions: PermissionType::AddReference,
            }])
            .insert(&mut *sp);
    }
    let allowed = session
        .add_references(&[AddReferencesItem {
            source_node_id: open,
            reference_type_id: ReferenceTypeId::Organizes.into(),
            is_forward: true,
            target_server_uri: Default::default(),
            target_node_id: tgt.into(),
            target_node_class: NodeClass::Object,
        }])
        .await
        .unwrap();
    assert_eq!(allowed, vec![StatusCode::Good]);
}
