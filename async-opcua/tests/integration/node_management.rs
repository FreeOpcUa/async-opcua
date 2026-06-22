use std::{sync::Arc, time::Duration};

use super::utils::{setup, Tester};
use opcua::{
    client::Session,
    server::{
        address_space::{EventNotifier, NodeBase, NodeType, ObjectBuilder},
        diagnostics::NamespaceMetadata,
        node_manager::memory::{simple_node_manager, SimpleNodeManager},
    },
    types::{
        AddNodeAttributes, AddNodesItem, AddReferencesItem, AttributeId, BrowseDescription,
        BrowseDirection, DeleteNodesItem, DeleteReferencesItem, ExpandedNodeId, NodeClass, NodeId,
        ObjectAttributes, ObjectId, ObjectTypeId, QualifiedName, ReadValueId, ReferenceTypeId,
        StatusCode, TimestampsToReturn,
    },
};

// --- Feature 022: writable address space via the in-memory DEFAULT (SimpleNodeManager) ---
//
// The TestNodeManager (used by `setup()`) OVERRIDES the NodeManagement methods, so the tests above
// exercise its own impl, gate-independent. The new gated default (memory_mgr_impl.rs) is reached only by
// in-memory managers that do NOT override — e.g. SimpleNodeManager. These tests stand up a
// SimpleNodeManager server and drive AddNodes/DeleteNodes through the real service to verify the default
// + the `clients_can_modify_address_space` gate, anchored to OPC UA Part 4 §5.7.

const WRITABLE_NS: &str = "urn:writable-address-space-test";

/// Build a SimpleNodeManager server (gate on/off), seed a parent object, connect.
async fn setup_simple(
    gate_on: bool,
) -> (Tester, Arc<SimpleNodeManager>, u16, NodeId, Arc<Session>) {
    let mut server = crate::utils::default_server().with_node_manager(simple_node_manager(
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

    // AddNodes -> Good + assigned id (Part 4 §5.7). The new node id is client-specified in a namespace
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
