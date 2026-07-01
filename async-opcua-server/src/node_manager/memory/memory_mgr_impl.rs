use async_trait::async_trait;
use std::sync::Arc;

use crate::{
    address_space::{AccessLevel, AddressSpace, EventNotifier, NodeType, ReferenceDirection},
    diagnostics::NamespaceMetadata,
    node_manager::{
        audit_events, AddNodeItem, AddReferenceItem, DeleteNodeItem, DeleteReferenceItem,
        GeneralModelChangeEvent, HistoryNode, HistoryUpdateNode, MethodCall, MonitoredItemRef,
        MonitoredItemUpdateRef, ParsedReadValueId, RegisterNodeItem, RequestContext, ServerContext,
        WriteNode,
    },
    rbac,
    session::continuation_points::ContinuationPoint,
    subscriptions::CreateMonitoredItem,
};
use opcua_core::sync::RwLock;
use opcua_nodes::{
    DataType, Event, Method, NodeBase, Object, ObjectType, ReferenceType, TypeTree, Variable,
    VariableType, View,
};
use opcua_types::{
    AddNodeAttributes, AttributesMask, BrowseDirection, DataTypeId, DataValue, ExpandedNodeId,
    LocalizedText, ModelChangeStructureDataType, MonitoringMode, NodeClass, NodeId, ObjectId,
    PermissionType, ReadAnnotationDataDetails, ReadAtTimeDetails, ReadEventDetails,
    ReadProcessedDetails, ReadRawModifiedDetails, ReferenceTypeId, StatusCode, TimestampsToReturn,
    Variant, WriteMask,
};

const MODEL_CHANGE_NODE_ADDED: u8 = 1;
const MODEL_CHANGE_NODE_DELETED: u8 = 2;
const MODEL_CHANGE_REFERENCE_ADDED: u8 = 4;
const MODEL_CHANGE_REFERENCE_DELETED: u8 = 8;

/// Callback used by the default in-memory method `Call` implementation.
pub type InMemoryMethodCallback = Arc<
    dyn Fn(&RequestContext, &[Variant]) -> Result<Vec<Variant>, StatusCode> + Send + Sync + 'static,
>;

/// Trait for constructing an [InMemoryNodeManagerImpl].
///
/// Note that this is called with the lock on the [AddressSpace] held,
/// if you try to lock it again, it will deadlock.
pub trait InMemoryNodeManagerImplBuilder {
    /// Type implementing [InMemoryNodeManagerImpl] constructed by this builder.
    type Impl: InMemoryNodeManagerImpl;

    /// Build the node manager impl.
    fn build(self, context: ServerContext, address_space: &mut AddressSpace) -> Self::Impl;
}

impl<T, R: InMemoryNodeManagerImpl> InMemoryNodeManagerImplBuilder for T
where
    T: FnOnce(ServerContext, &mut AddressSpace) -> R,
{
    type Impl = R;

    fn build(self, context: ServerContext, address_space: &mut AddressSpace) -> Self::Impl {
        self(context, address_space)
    }
}

fn clients_can_modify_address_space(context: &RequestContext) -> bool {
    context.info.config.limits.clients_can_modify_address_space
}

fn authorize_node_management_permission(
    context: &RequestContext,
    address_space: &AddressSpace,
    node_id: &NodeId,
    required: PermissionType,
) -> bool {
    let Some(node) = address_space.find(node_id) else {
        return true;
    };

    rbac::decision::authorize_ctx(context, &node, required)
}

fn model_change(affected: NodeId, verb: u8) -> ModelChangeStructureDataType {
    ModelChangeStructureDataType {
        affected,
        affected_type: NodeId::null(),
        verb,
    }
}

fn notify_model_changes(context: &RequestContext, changes: Vec<ModelChangeStructureDataType>) {
    if changes.is_empty() {
        return;
    }

    let event = GeneralModelChangeEvent::new(changes);
    let server_node_id = NodeId::from(ObjectId::Server);
    let items = std::iter::once((&event as &dyn Event, &server_node_id));
    context.subscriptions.notify_events(items);
}

fn add_nodes_impl(
    context: &RequestContext,
    address_space: &RwLock<AddressSpace>,
    nodes_to_add: &mut [&mut AddNodeItem],
) {
    if !clients_can_modify_address_space(context) {
        for item in nodes_to_add {
            item.set_result(NodeId::null(), StatusCode::BadServiceUnsupported);
        }
        return;
    }

    let mut changes = Vec::new();
    let mut audit_items = Vec::new();

    {
        let mut address_space = address_space.write();

        for item in nodes_to_add.iter_mut() {
            if item.status().is_bad() && item.status() != StatusCode::BadNotSupported {
                continue;
            }

            let parent_id = item.parent_node_id().node_id.clone();
            if parent_id.is_null() || !address_space.node_exists(&parent_id) {
                item.set_result(NodeId::null(), StatusCode::BadParentNodeIdInvalid);
                continue;
            }

            if !authorize_node_management_permission(
                context,
                &address_space,
                &parent_id,
                PermissionType::AddNode,
            ) {
                item.set_result(NodeId::null(), StatusCode::BadUserAccessDenied);
                continue;
            }

            if item.reference_type_id().is_null() {
                item.set_result(NodeId::null(), StatusCode::BadReferenceTypeIdInvalid);
                continue;
            }

            let type_tree = context.type_tree.read();
            if address_space
                .find_node_by_browse_name(
                    &parent_id,
                    Some((item.reference_type_id().clone(), false)),
                    &*type_tree,
                    BrowseDirection::Forward,
                    item.browse_name().clone(),
                )
                .is_some()
            {
                item.set_result(NodeId::null(), StatusCode::BadBrowseNameDuplicated);
                continue;
            }
            drop(type_tree);

            let type_tree = context.type_tree.read();
            if let Err(status) = validate_type_definition(&address_space, &*type_tree, item) {
                item.set_result(NodeId::null(), status);
                continue;
            }
            drop(type_tree);

            let assigned_id = if item.requested_new_node_id().is_null() {
                next_unused_node_id(&address_space, parent_id.namespace)
            } else if !address_space
                .namespaces()
                .contains_key(&item.requested_new_node_id().namespace)
            {
                item.set_result(NodeId::null(), StatusCode::BadNodeIdRejected);
                continue;
            } else if address_space.node_exists(item.requested_new_node_id()) {
                item.set_result(NodeId::null(), StatusCode::BadNodeIdExists);
                continue;
            } else {
                item.requested_new_node_id().clone()
            };

            let node = match build_node(item, &assigned_id) {
                Ok(node) => node,
                Err(status) => {
                    item.set_result(NodeId::null(), status);
                    continue;
                }
            };

            {
                let type_tree = context.type_tree.read();
                if let Err(status) =
                    validate_type_refinement(&address_space, &*type_tree, item, &node)
                {
                    item.set_result(NodeId::null(), status);
                    continue;
                }
            }

            let type_definition_id = item.type_definition_id().node_id.clone();
            let has_type_definition_id = NodeId::from(ReferenceTypeId::HasTypeDefinition);
            let mut references = vec![(
                &parent_id,
                item.reference_type_id(),
                ReferenceDirection::Inverse,
            )];
            if !type_definition_id.is_null() {
                references.push((
                    &type_definition_id,
                    &has_type_definition_id,
                    ReferenceDirection::Forward,
                ));
            }

            if address_space.insert(node, Some(references.as_slice())) {
                item.set_result(assigned_id.clone(), StatusCode::Good);
                audit_items.push(audit_events::add_nodes_item(item));
                changes.push(model_change(assigned_id, MODEL_CHANGE_NODE_ADDED));
            } else {
                item.set_result(NodeId::null(), StatusCode::BadNodeIdExists);
            }
        }
    }

    audit_events::notify_add_nodes(context, audit_items);
    notify_model_changes(context, changes);
}

fn delete_nodes_impl(
    context: &RequestContext,
    address_space: &RwLock<AddressSpace>,
    nodes_to_delete: &mut [&mut DeleteNodeItem],
) {
    if !clients_can_modify_address_space(context) {
        for item in nodes_to_delete {
            item.set_result(StatusCode::BadServiceUnsupported);
        }
        return;
    }

    let mut changes = Vec::new();
    let mut audit_items = Vec::new();

    {
        let mut address_space = address_space.write();

        for item in nodes_to_delete.iter_mut() {
            if item.node_id().is_null() {
                item.set_result(StatusCode::BadNodeIdInvalid);
                continue;
            }

            if !authorize_node_management_permission(
                context,
                &address_space,
                item.node_id(),
                PermissionType::DeleteNode,
            ) {
                item.set_result(StatusCode::BadUserAccessDenied);
                continue;
            }

            let deleted_node_id = item.node_id().clone();
            if address_space
                .delete(item.node_id(), item.delete_target_references())
                .is_some()
            {
                item.set_result(StatusCode::Good);
                audit_items.push(audit_events::delete_nodes_item(item));
                changes.push(model_change(deleted_node_id, MODEL_CHANGE_NODE_DELETED));
            } else {
                item.set_result(StatusCode::BadNodeIdUnknown);
            }
        }
    }

    audit_events::notify_delete_nodes(context, audit_items);
    notify_model_changes(context, changes);
}

fn add_references_impl(
    context: &RequestContext,
    address_space: &RwLock<AddressSpace>,
    references_to_add: &mut [&mut AddReferenceItem],
) {
    if !clients_can_modify_address_space(context) {
        for item in references_to_add {
            item.set_source_result(StatusCode::BadServiceUnsupported);
            item.set_target_result(StatusCode::BadServiceUnsupported);
        }
        return;
    }

    let mut changes = Vec::new();
    let mut audit_items = Vec::new();

    {
        let mut address_space = address_space.write();
        let type_tree = context.type_tree.read();

        for item in references_to_add.iter_mut() {
            let source_owned = address_space
                .namespaces()
                .contains_key(&item.source_node_id().namespace);
            let target_owned = address_space
                .namespaces()
                .contains_key(&item.target_node_id().node_id.namespace);

            let handle_source = source_owned && item.source_status() == StatusCode::BadNotSupported;
            let handle_target = target_owned && item.target_status() == StatusCode::BadNotSupported;
            if !handle_source && !handle_target {
                continue;
            }

            let source_exists = address_space.node_exists(item.source_node_id());
            let target_exists = address_space.node_exists(&item.target_node_id().node_id);

            if source_exists
                && !authorize_node_management_permission(
                    context,
                    &address_space,
                    item.source_node_id(),
                    PermissionType::AddReference,
                )
            {
                item.set_source_result(StatusCode::BadUserAccessDenied);
                item.set_target_result(StatusCode::BadUserAccessDenied);
                continue;
            }

            if !type_tree
                .get(item.reference_type_id())
                .is_some_and(|node_class| node_class == NodeClass::ReferenceType)
            {
                if handle_source {
                    item.set_source_result(StatusCode::BadReferenceTypeIdInvalid);
                }
                if handle_target {
                    item.set_target_result(StatusCode::BadReferenceTypeIdInvalid);
                }
                continue;
            }
            if reference_type_is_abstract(&address_space, item.reference_type_id()) {
                if handle_source {
                    item.set_source_result(StatusCode::BadReferenceTypeIdInvalid);
                }
                if handle_target {
                    item.set_target_result(StatusCode::BadReferenceTypeIdInvalid);
                }
                continue;
            }

            if handle_source && !source_exists {
                item.set_source_result(StatusCode::BadSourceNodeIdInvalid);
            }
            if handle_target && !target_exists {
                item.set_target_result(StatusCode::BadTargetNodeIdInvalid);
            }

            let source_ready = handle_source && source_exists;
            let target_ready = handle_target && target_exists;
            if !source_ready && !target_ready {
                continue;
            }

            if item.source_node_id() == &item.target_node_id().node_id {
                if source_ready {
                    item.set_source_result(StatusCode::BadSourceNodeIdInvalid);
                }
                if target_ready {
                    item.set_target_result(StatusCode::BadTargetNodeIdInvalid);
                }
                continue;
            }

            // OPC 10000-4 §5.8.3: the requested targetNodeClass must match the
            // actual target node's NodeClass. `Unspecified` means the client
            // makes no assertion. Only checkable when the target is local.
            if target_exists && item.target_node_class() != NodeClass::Unspecified {
                let actual_class = address_space
                    .find(&item.target_node_id().node_id)
                    .map(|n| n.node_class());
                if actual_class.is_some_and(|c| c != item.target_node_class()) {
                    if source_ready {
                        item.set_source_result(StatusCode::BadNodeClassInvalid);
                    }
                    if target_ready {
                        item.set_target_result(StatusCode::BadNodeClassInvalid);
                    }
                    continue;
                }
            }

            let (source_node, target_node) = if item.is_forward() {
                (item.source_node_id(), &item.target_node_id().node_id)
            } else {
                (&item.target_node_id().node_id, item.source_node_id())
            };

            if !reference_is_structurally_allowed(
                &address_space,
                &*type_tree,
                item.reference_type_id(),
                source_node,
                target_node,
            ) {
                if source_ready {
                    item.set_source_result(StatusCode::BadReferenceNotAllowed);
                }
                if target_ready {
                    item.set_target_result(StatusCode::BadReferenceNotAllowed);
                }
                continue;
            }

            // OPC 10000-3 §5.5.1 / §5.6.2: an Object/Variable is the SourceNode of
            // exactly one HasTypeDefinition Reference. Reject a second one (the
            // duplicate-to-same-target case is handled below).
            if item.reference_type_id() == &NodeId::from(ReferenceTypeId::HasTypeDefinition)
                && address_space
                    .find_references(
                        source_node,
                        Some((ReferenceTypeId::HasTypeDefinition, false)),
                        &*type_tree,
                        BrowseDirection::Forward,
                    )
                    .next()
                    .is_some()
            {
                if source_ready {
                    item.set_source_result(StatusCode::BadReferenceNotAllowed);
                }
                if target_ready {
                    item.set_target_result(StatusCode::BadReferenceNotAllowed);
                }
                continue;
            }

            if address_space.has_reference(source_node, target_node, item.reference_type_id()) {
                if source_ready {
                    item.set_source_result(StatusCode::BadDuplicateReferenceNotAllowed);
                }
                if target_ready {
                    item.set_target_result(StatusCode::BadDuplicateReferenceNotAllowed);
                }
                continue;
            }

            address_space.insert_reference(source_node, target_node, item.reference_type_id());

            if source_ready {
                item.set_source_result(StatusCode::Good);
            }
            if target_ready {
                item.set_target_result(StatusCode::Good);
            }
            audit_items.push(audit_events::add_references_item(item));
            changes.push(model_change(
                item.source_node_id().clone(),
                MODEL_CHANGE_REFERENCE_ADDED,
            ));
        }
    }

    audit_events::notify_add_references(context, audit_items);
    notify_model_changes(context, changes);
}

fn delete_references_impl(
    context: &RequestContext,
    address_space: &RwLock<AddressSpace>,
    references_to_delete: &mut [&mut DeleteReferenceItem],
) {
    if !clients_can_modify_address_space(context) {
        for item in references_to_delete {
            item.set_source_result(StatusCode::BadServiceUnsupported);
            item.set_target_result(StatusCode::BadServiceUnsupported);
        }
        return;
    }

    let mut changes = Vec::new();
    let mut audit_items = Vec::new();

    {
        let mut address_space = address_space.write();
        let type_tree = context.type_tree.read();

        for item in references_to_delete.iter_mut() {
            let source_owned = address_space
                .namespaces()
                .contains_key(&item.source_node_id().namespace);
            let target_owned = address_space
                .namespaces()
                .contains_key(&item.target_node_id().node_id.namespace);

            let handle_source = source_owned && item.source_status() == StatusCode::BadNotSupported;
            let handle_target = target_owned && item.target_status() == StatusCode::BadNotSupported;
            if !handle_source && !handle_target {
                continue;
            }

            let source_exists = address_space.node_exists(item.source_node_id());
            let target_exists = address_space.node_exists(&item.target_node_id().node_id);

            if source_exists
                && !authorize_node_management_permission(
                    context,
                    &address_space,
                    item.source_node_id(),
                    PermissionType::RemoveReference,
                )
            {
                item.set_source_result(StatusCode::BadUserAccessDenied);
                item.set_target_result(StatusCode::BadUserAccessDenied);
                continue;
            }

            if !type_tree
                .get(item.reference_type_id())
                .is_some_and(|node_class| node_class == NodeClass::ReferenceType)
            {
                if handle_source {
                    item.set_source_result(StatusCode::BadReferenceTypeIdInvalid);
                }
                if handle_target {
                    item.set_target_result(StatusCode::BadReferenceTypeIdInvalid);
                }
                continue;
            }

            if handle_source && !source_exists {
                item.set_source_result(StatusCode::BadSourceNodeIdInvalid);
            }
            if handle_target && !target_exists {
                item.set_target_result(StatusCode::BadTargetNodeIdInvalid);
            }

            let source_ready = handle_source && source_exists;
            let target_ready = handle_target && target_exists;
            if !source_ready && !target_ready {
                continue;
            }

            let (source_node, target_node) = if item.is_forward() {
                (item.source_node_id(), &item.target_node_id().node_id)
            } else {
                (&item.target_node_id().node_id, item.source_node_id())
            };

            address_space.delete_reference(source_node, target_node, item.reference_type_id());
            if item.delete_bidirectional() {
                address_space.delete_reference(target_node, source_node, item.reference_type_id());
            }

            if source_ready {
                item.set_source_result(StatusCode::Good);
            }
            if target_ready {
                item.set_target_result(StatusCode::Good);
            }
            audit_items.push(audit_events::delete_references_item(item));
            changes.push(model_change(
                item.source_node_id().clone(),
                MODEL_CHANGE_REFERENCE_DELETED,
            ));
        }
    }

    audit_events::notify_delete_references(context, audit_items);
    notify_model_changes(context, changes);
}

/// Resolve a node's NodeClass, preferring a full node in the address space and
/// falling back to type metadata for type-only nodes; `None` if unknown.
fn resolve_node_class(
    address_space: &AddressSpace,
    type_tree: &dyn TypeTree,
    node_id: &NodeId,
) -> Option<NodeClass> {
    if let Some(node) = address_space.find(node_id) {
        return Some(node.node_class());
    }
    type_tree.get(node_id)
}

/// Enforce the NodeClass structural constraints of hierarchical reference types
/// (OPC 10000-4 §5.8.3, OPC 10000-3 §5.3). Conservative: only rejects clearly
/// forbidden combinations; unknown endpoints are permitted so legitimate models
/// (including every combination in the standard nodeset) are never rejected.
fn reference_is_structurally_allowed(
    address_space: &AddressSpace,
    type_tree: &dyn TypeTree,
    reference_type_id: &NodeId,
    source_node_id: &NodeId,
    target_node_id: &NodeId,
) -> bool {
    // HasProperty: the target of a Property reference must be a Variable.
    if type_tree.is_subtype_of(
        reference_type_id,
        &NodeId::from(ReferenceTypeId::HasProperty),
    ) {
        return match address_space.find(target_node_id) {
            Some(target_node) => matches!(&*target_node, NodeType::Variable(_)),
            None => true,
        };
    }

    // HasSubtype: connects a type node to a subtype of the SAME type NodeClass.
    if type_tree.is_subtype_of(
        reference_type_id,
        &NodeId::from(ReferenceTypeId::HasSubtype),
    ) {
        let source_class = resolve_node_class(address_space, type_tree, source_node_id);
        let target_class = resolve_node_class(address_space, type_tree, target_node_id);
        if let (Some(source_class), Some(target_class)) = (source_class, target_class) {
            let is_type_class = |class: NodeClass| {
                matches!(
                    class,
                    NodeClass::ObjectType
                        | NodeClass::VariableType
                        | NodeClass::ReferenceType
                        | NodeClass::DataType
                )
            };
            // A valid HasSubtype is type→type of the same class; anything else is forbidden.
            if !is_type_class(source_class) || source_class != target_class {
                return false;
            }
        }
    }

    true
}

/// A VariableType subtype may only further-restrict (never widen) its
/// supertype's DataType and ValueRank (OPC 10000-3 §5.6.5 / §6.3 subtyping).
/// Only applied when the node is a VariableType added as a HasSubtype of a
/// resolvable VariableType supertype; unknown DataTypes are not judged.
fn validate_type_refinement(
    address_space: &AddressSpace,
    type_tree: &dyn TypeTree,
    item: &AddNodeItem,
    node: &NodeType,
) -> Result<(), StatusCode> {
    let NodeType::VariableType(child) = node else {
        return Ok(());
    };
    if !type_tree.is_subtype_of(
        item.reference_type_id(),
        &NodeId::from(ReferenceTypeId::HasSubtype),
    ) {
        return Ok(());
    }
    let Some(parent) = address_space.find(&item.parent_node_id().node_id) else {
        return Ok(());
    };
    let NodeType::VariableType(parent) = &*parent else {
        return Ok(());
    };

    // DataType: the subtype's DataType must be a subtype of the supertype's.
    // Only judge a DataType the type tree knows; an unknown one can't be proven
    // to widen, so it is allowed (conservative; equal DataTypes always pass).
    if type_tree.get(child.data_type()).is_some()
        && !type_tree.is_subtype_of(child.data_type(), parent.data_type())
    {
        return Err(StatusCode::BadNodeAttributesInvalid);
    }
    // ValueRank: the subtype must further-restrict (not widen) the supertype.
    if !value_rank_is_restriction_of(parent.value_rank(), child.value_rank()) {
        return Err(StatusCode::BadNodeAttributesInvalid);
    }
    Ok(())
}

/// Whether `child` ValueRank is a valid restriction of `parent` ValueRank
/// (OPC 10000-3): Any (-2) accepts anything; ScalarOrOneDimension (-3) accepts
/// scalar or a single dimension; OneOrMoreDimensions (0) accepts any array;
/// Scalar (-1) and fixed ranks (>=1) require an exact match.
fn value_rank_is_restriction_of(parent: i32, child: i32) -> bool {
    const ANY: i32 = -2;
    const SCALAR_OR_ONE_DIMENSION: i32 = -3;
    const ONE_OR_MORE_DIMENSIONS: i32 = 0;
    const SCALAR: i32 = -1;
    match parent {
        ANY => true,
        SCALAR_OR_ONE_DIMENSION => matches!(child, SCALAR_OR_ONE_DIMENSION | SCALAR | 1),
        ONE_OR_MORE_DIMENSIONS => child == ONE_OR_MORE_DIMENSIONS || child >= 1,
        SCALAR => child == SCALAR,
        n => child == n,
    }
}

fn reference_type_is_abstract(address_space: &AddressSpace, reference_type_id: &NodeId) -> bool {
    if let Some(reference_type) = address_space.find(reference_type_id) {
        return match &*reference_type {
            NodeType::ReferenceType(reference_type) => reference_type.is_abstract(),
            _ => false,
        };
    }

    standard_reference_type_is_abstract(reference_type_id)
}

fn standard_reference_type_is_abstract(reference_type_id: &NodeId) -> bool {
    reference_type_id
        .as_reference_type_id()
        .is_ok_and(|reference_type_id| {
            matches!(
                reference_type_id,
                ReferenceTypeId::References
                    | ReferenceTypeId::NonHierarchicalReferences
                    | ReferenceTypeId::HierarchicalReferences
                    | ReferenceTypeId::HasChild
                    | ReferenceTypeId::Aggregates
            )
        })
}

fn validate_type_definition(
    address_space: &AddressSpace,
    type_tree: &dyn TypeTree,
    item: &AddNodeItem,
) -> Result<(), StatusCode> {
    let type_definition_id = &item.type_definition_id().node_id;
    if type_definition_id.is_null() {
        return Ok(());
    }

    let expected_type_class = match item.node_class() {
        NodeClass::Object => NodeClass::ObjectType,
        NodeClass::Variable => NodeClass::VariableType,
        _ => return Ok(()),
    };

    if let Some(type_definition) = address_space.find(type_definition_id) {
        return match (expected_type_class, &*type_definition) {
            (NodeClass::ObjectType, NodeType::ObjectType(object_type))
                if object_type.is_abstract() =>
            {
                Err(StatusCode::BadTypeDefinitionInvalid)
            }
            (NodeClass::VariableType, NodeType::VariableType(variable_type))
                if variable_type.is_abstract() =>
            {
                Err(StatusCode::BadTypeDefinitionInvalid)
            }
            (NodeClass::ObjectType, NodeType::ObjectType(_))
            | (NodeClass::VariableType, NodeType::VariableType(_)) => Ok(()),
            _ => Err(StatusCode::BadTypeDefinitionInvalid),
        };
    }

    // Type definition present only in the type metadata (no full node). Require
    // the correct type NodeClass AND reject abstract types — OPC 10000-3 §5.5.2
    // (ObjectType) / §5.6.5 (VariableType): abstract types cannot be instantiated.
    match type_tree.get(type_definition_id) {
        Some(node_class) if node_class == expected_type_class => {
            if type_tree.is_abstract(type_definition_id) == Some(true) {
                Err(StatusCode::BadTypeDefinitionInvalid)
            } else {
                Ok(())
            }
        }
        _ => Err(StatusCode::BadTypeDefinitionInvalid),
    }
}

fn next_unused_node_id(address_space: &AddressSpace, namespace: u16) -> NodeId {
    loop {
        let node_id = NodeId::next_numeric(namespace);
        if !address_space.node_exists(&node_id) {
            return node_id;
        }
    }
}

fn build_node(item: &AddNodeItem, node_id: &NodeId) -> Result<NodeType, StatusCode> {
    match (item.node_class(), item.node_attributes()) {
        (NodeClass::Object, AddNodeAttributes::Object(attributes)) => {
            build_object(node_id, item.browse_name().clone(), attributes).map(NodeType::from)
        }
        (NodeClass::Variable, AddNodeAttributes::Variable(attributes)) => {
            build_variable(node_id, item.browse_name().clone(), attributes).map(NodeType::from)
        }
        (NodeClass::Method, AddNodeAttributes::Method(attributes)) => {
            build_method(node_id, item.browse_name().clone(), attributes).map(NodeType::from)
        }
        (NodeClass::ObjectType, AddNodeAttributes::ObjectType(attributes)) => {
            build_object_type(node_id, item.browse_name().clone(), attributes).map(NodeType::from)
        }
        (NodeClass::VariableType, AddNodeAttributes::VariableType(attributes)) => {
            build_variable_type(node_id, item.browse_name().clone(), attributes).map(NodeType::from)
        }
        (NodeClass::ReferenceType, AddNodeAttributes::ReferenceType(attributes)) => {
            build_reference_type(node_id, item.browse_name().clone(), attributes)
                .map(NodeType::from)
        }
        (NodeClass::DataType, AddNodeAttributes::DataType(attributes)) => {
            build_data_type(node_id, item.browse_name().clone(), attributes).map(NodeType::from)
        }
        (NodeClass::View, AddNodeAttributes::View(attributes)) => {
            build_view(node_id, item.browse_name().clone(), attributes).map(NodeType::from)
        }
        (
            NodeClass::Object
            | NodeClass::Variable
            | NodeClass::Method
            | NodeClass::ObjectType
            | NodeClass::VariableType
            | NodeClass::ReferenceType
            | NodeClass::DataType
            | NodeClass::View,
            _,
        ) => Err(StatusCode::BadNodeAttributesInvalid),
        _ => Err(StatusCode::BadNodeClassInvalid),
    }
}

fn build_object(
    node_id: &NodeId,
    browse_name: impl Into<opcua_types::QualifiedName>,
    attributes: &opcua_types::ObjectAttributes,
) -> Result<Object, StatusCode> {
    let browse_name = browse_name.into();
    let mask = attributes_mask(attributes.specified_attributes, object_attributes_mask())?;
    let display_name =
        display_name_or_browse_name(&mask, attributes.display_name.clone(), &browse_name);
    let event_notifier = if mask.contains(AttributesMask::EVENT_NOTIFIER) {
        EventNotifier::from_bits_truncate(attributes.event_notifier)
    } else {
        EventNotifier::empty()
    };

    let mut node = Object::new(node_id, browse_name, display_name, event_notifier);
    apply_base_attributes(
        &mut node,
        mask,
        attributes.description.clone(),
        attributes.write_mask,
        attributes.user_write_mask,
    );
    Ok(node)
}

fn build_variable(
    node_id: &NodeId,
    browse_name: impl Into<opcua_types::QualifiedName>,
    attributes: &opcua_types::VariableAttributes,
) -> Result<Variable, StatusCode> {
    let browse_name = browse_name.into();
    let mask = attributes_mask(attributes.specified_attributes, variable_attributes_mask())?;
    let display_name =
        display_name_or_browse_name(&mask, attributes.display_name.clone(), &browse_name);
    let data_type = if mask.contains(AttributesMask::DATA_TYPE) {
        attributes.data_type.clone()
    } else {
        NodeId::from(DataTypeId::BaseDataType)
    };
    let value = if mask.contains(AttributesMask::VALUE) {
        attributes.value.clone()
    } else {
        Variant::Empty
    };

    let mut node = Variable::new_data_value(
        node_id,
        browse_name,
        display_name,
        data_type,
        None,
        None,
        value,
    );

    if mask.contains(AttributesMask::VALUE_RANK) {
        node.set_value_rank(attributes.value_rank);
    }
    if mask.contains(AttributesMask::HISTORIZING) {
        node.set_historizing(attributes.historizing);
    }
    if mask.contains(AttributesMask::ACCESS_LEVEL) {
        node.set_access_level(AccessLevel::from_bits_truncate(attributes.access_level));
    }
    if mask.contains(AttributesMask::USER_ACCESS_LEVEL) {
        node.set_user_access_level(AccessLevel::from_bits_truncate(
            attributes.user_access_level,
        ));
    }
    if mask.contains(AttributesMask::ARRAY_DIMENSIONS) {
        if let Some(array_dimensions) = attributes.array_dimensions.as_ref() {
            validate_array_dimensions(attributes.value_rank, array_dimensions)?;
            node.set_array_dimensions(array_dimensions);
        } else {
            return Err(StatusCode::BadNodeAttributesInvalid);
        }
    }
    if mask.contains(AttributesMask::MINIMUM_SAMPLING_INTERVAL) {
        node.set_minimum_sampling_interval(attributes.minimum_sampling_interval);
    }
    apply_base_attributes(
        &mut node,
        mask,
        attributes.description.clone(),
        attributes.write_mask,
        attributes.user_write_mask,
    );

    Ok(node)
}

fn build_method(
    node_id: &NodeId,
    browse_name: impl Into<opcua_types::QualifiedName>,
    attributes: &opcua_types::MethodAttributes,
) -> Result<Method, StatusCode> {
    let browse_name = browse_name.into();
    let mask = attributes_mask(attributes.specified_attributes, method_attributes_mask())?;
    let display_name =
        display_name_or_browse_name(&mask, attributes.display_name.clone(), &browse_name);

    let mut node = Method::new(node_id, browse_name, display_name, false, false);
    if mask.contains(AttributesMask::EXECUTABLE) {
        node.set_executable(attributes.executable);
    }
    if mask.contains(AttributesMask::USER_EXECUTABLE) {
        node.set_user_executable(attributes.user_executable);
    }
    apply_base_attributes(
        &mut node,
        mask,
        attributes.description.clone(),
        attributes.write_mask,
        attributes.user_write_mask,
    );

    Ok(node)
}

fn build_object_type(
    node_id: &NodeId,
    browse_name: impl Into<opcua_types::QualifiedName>,
    attributes: &opcua_types::ObjectTypeAttributes,
) -> Result<ObjectType, StatusCode> {
    let browse_name = browse_name.into();
    let mask = attributes_mask(
        attributes.specified_attributes,
        object_type_attributes_mask(),
    )?;
    let display_name =
        display_name_or_browse_name(&mask, attributes.display_name.clone(), &browse_name);

    let mut node = ObjectType::new(node_id, browse_name, display_name, false);
    if mask.contains(AttributesMask::IS_ABSTRACT) {
        node.set_is_abstract(attributes.is_abstract);
    }
    apply_base_attributes(
        &mut node,
        mask,
        attributes.description.clone(),
        attributes.write_mask,
        attributes.user_write_mask,
    );

    Ok(node)
}

fn build_variable_type(
    node_id: &NodeId,
    browse_name: impl Into<opcua_types::QualifiedName>,
    attributes: &opcua_types::VariableTypeAttributes,
) -> Result<VariableType, StatusCode> {
    let browse_name = browse_name.into();
    let mask = attributes_mask(
        attributes.specified_attributes,
        variable_type_attributes_mask(),
    )?;
    let display_name =
        display_name_or_browse_name(&mask, attributes.display_name.clone(), &browse_name);
    let data_type = if mask.contains(AttributesMask::DATA_TYPE) {
        attributes.data_type.clone()
    } else {
        NodeId::from(DataTypeId::BaseDataType)
    };
    let value = if mask.contains(AttributesMask::VALUE) {
        attributes.value.clone()
    } else {
        Variant::Empty
    };

    let mut node = VariableType::new(node_id, browse_name, display_name, data_type, false, -1);

    if mask.contains(AttributesMask::VALUE) {
        node.set_value(value);
    }
    if mask.contains(AttributesMask::VALUE_RANK) {
        node.set_value_rank(attributes.value_rank);
    }
    if mask.contains(AttributesMask::ARRAY_DIMENSIONS) {
        if let Some(array_dimensions) = attributes.array_dimensions.as_ref() {
            validate_array_dimensions(attributes.value_rank, array_dimensions)?;
            node.set_array_dimensions(array_dimensions);
        } else {
            return Err(StatusCode::BadNodeAttributesInvalid);
        }
    }
    if mask.contains(AttributesMask::IS_ABSTRACT) {
        node.set_is_abstract(attributes.is_abstract);
    }
    apply_base_attributes(
        &mut node,
        mask,
        attributes.description.clone(),
        attributes.write_mask,
        attributes.user_write_mask,
    );

    Ok(node)
}

fn validate_array_dimensions(value_rank: i32, array_dimensions: &[u32]) -> Result<(), StatusCode> {
    if value_rank >= 1 && array_dimensions.len() != value_rank as usize {
        Err(StatusCode::BadNodeAttributesInvalid)
    } else {
        Ok(())
    }
}

fn build_reference_type(
    node_id: &NodeId,
    browse_name: impl Into<opcua_types::QualifiedName>,
    attributes: &opcua_types::ReferenceTypeAttributes,
) -> Result<ReferenceType, StatusCode> {
    let browse_name = browse_name.into();
    let mask = attributes_mask(
        attributes.specified_attributes,
        reference_type_attributes_mask(),
    )?;
    let display_name =
        display_name_or_browse_name(&mask, attributes.display_name.clone(), &browse_name);

    let mut node = ReferenceType::new(node_id, browse_name, display_name, None, false, false);
    if mask.contains(AttributesMask::IS_ABSTRACT) {
        node.set_is_abstract(attributes.is_abstract);
    }
    if mask.contains(AttributesMask::SYMMETRIC) {
        node.set_symmetric(attributes.symmetric);
    }
    if mask.contains(AttributesMask::INVERSE_NAME) {
        node.set_inverse_name(attributes.inverse_name.clone());
    }
    // OPC 10000-3 §5.3.2: a symmetric ReferenceType must not define an
    // InverseName. Enforced via the node-level well-formedness invariant so the
    // rule has a single source of truth.
    if !node.symmetric_inverse_name_is_valid() {
        return Err(StatusCode::BadNodeAttributesInvalid);
    }
    apply_base_attributes(
        &mut node,
        mask,
        attributes.description.clone(),
        attributes.write_mask,
        attributes.user_write_mask,
    );

    Ok(node)
}

fn build_data_type(
    node_id: &NodeId,
    browse_name: impl Into<opcua_types::QualifiedName>,
    attributes: &opcua_types::DataTypeAttributes,
) -> Result<DataType, StatusCode> {
    let browse_name = browse_name.into();
    let mask = attributes_mask(attributes.specified_attributes, data_type_attributes_mask())?;
    let display_name =
        display_name_or_browse_name(&mask, attributes.display_name.clone(), &browse_name);

    let mut node = DataType::new(node_id, browse_name, display_name, false);
    if mask.contains(AttributesMask::IS_ABSTRACT) {
        node.set_is_abstract(attributes.is_abstract);
    }
    apply_base_attributes(
        &mut node,
        mask,
        attributes.description.clone(),
        attributes.write_mask,
        attributes.user_write_mask,
    );

    Ok(node)
}

fn build_view(
    node_id: &NodeId,
    browse_name: impl Into<opcua_types::QualifiedName>,
    attributes: &opcua_types::ViewAttributes,
) -> Result<View, StatusCode> {
    let browse_name = browse_name.into();
    let mask = attributes_mask(attributes.specified_attributes, view_attributes_mask())?;
    let display_name =
        display_name_or_browse_name(&mask, attributes.display_name.clone(), &browse_name);
    let event_notifier = if mask.contains(AttributesMask::EVENT_NOTIFIER) {
        EventNotifier::from_bits_truncate(attributes.event_notifier)
    } else {
        EventNotifier::empty()
    };

    let mut node = View::new(node_id, browse_name, display_name, event_notifier, false);
    if mask.contains(AttributesMask::CONTAINS_NO_LOOPS) {
        node.set_contains_no_loops(attributes.contains_no_loops);
    }
    apply_base_attributes(
        &mut node,
        mask,
        attributes.description.clone(),
        attributes.write_mask,
        attributes.user_write_mask,
    );

    Ok(node)
}

fn attributes_mask(
    specified_attributes: u32,
    allowed_attributes: AttributesMask,
) -> Result<AttributesMask, StatusCode> {
    let mask = AttributesMask::from_bits(specified_attributes)
        .ok_or(StatusCode::BadNodeAttributesInvalid)?;
    if mask.bits() & !allowed_attributes.bits() != 0 {
        return Err(StatusCode::BadNodeAttributesInvalid);
    }
    Ok(mask)
}

fn base_attributes_mask() -> AttributesMask {
    AttributesMask::DESCRIPTION
        | AttributesMask::DISPLAY_NAME
        | AttributesMask::WRITE_MASK
        | AttributesMask::USER_WRITE_MASK
}

fn object_attributes_mask() -> AttributesMask {
    base_attributes_mask() | AttributesMask::EVENT_NOTIFIER
}

fn variable_attributes_mask() -> AttributesMask {
    base_attributes_mask()
        | AttributesMask::ACCESS_LEVEL
        | AttributesMask::ARRAY_DIMENSIONS
        | AttributesMask::DATA_TYPE
        | AttributesMask::HISTORIZING
        | AttributesMask::MINIMUM_SAMPLING_INTERVAL
        | AttributesMask::USER_ACCESS_LEVEL
        | AttributesMask::VALUE
        | AttributesMask::VALUE_RANK
}

fn method_attributes_mask() -> AttributesMask {
    base_attributes_mask() | AttributesMask::EXECUTABLE | AttributesMask::USER_EXECUTABLE
}

fn object_type_attributes_mask() -> AttributesMask {
    base_attributes_mask() | AttributesMask::IS_ABSTRACT
}

fn variable_type_attributes_mask() -> AttributesMask {
    base_attributes_mask()
        | AttributesMask::ARRAY_DIMENSIONS
        | AttributesMask::DATA_TYPE
        | AttributesMask::IS_ABSTRACT
        | AttributesMask::VALUE
        | AttributesMask::VALUE_RANK
}

fn reference_type_attributes_mask() -> AttributesMask {
    base_attributes_mask()
        | AttributesMask::INVERSE_NAME
        | AttributesMask::IS_ABSTRACT
        | AttributesMask::SYMMETRIC
}

fn data_type_attributes_mask() -> AttributesMask {
    base_attributes_mask() | AttributesMask::IS_ABSTRACT
}

fn view_attributes_mask() -> AttributesMask {
    base_attributes_mask() | AttributesMask::CONTAINS_NO_LOOPS | AttributesMask::EVENT_NOTIFIER
}

fn display_name_or_browse_name(
    mask: &AttributesMask,
    display_name: LocalizedText,
    browse_name: &opcua_types::QualifiedName,
) -> LocalizedText {
    if mask.contains(AttributesMask::DISPLAY_NAME) {
        display_name
    } else {
        browse_name.name.to_string().into()
    }
}

fn apply_base_attributes<T: NodeBase>(
    node: &mut T,
    mask: AttributesMask,
    description: LocalizedText,
    write_mask: u32,
    user_write_mask: u32,
) {
    if mask.contains(AttributesMask::DESCRIPTION) {
        node.set_description(description);
    }
    if mask.contains(AttributesMask::WRITE_MASK) {
        node.set_write_mask(WriteMask::from_bits_truncate(write_mask));
    }
    if mask.contains(AttributesMask::USER_WRITE_MASK) {
        node.set_user_write_mask(WriteMask::from_bits_truncate(user_write_mask));
    }
}

#[async_trait]
#[allow(unused)]
/// Trait for user-provided implementation of the [InMemoryNodeManager](crate::node_manager::memory::InMemoryNodeManager)
pub trait InMemoryNodeManagerImpl: Send + Sync + 'static {
    /// Populate the address space.
    async fn init(&self, address_space: &mut AddressSpace, context: ServerContext);

    /// Name of this node manager, for debug purposes.
    fn name(&self) -> &str;

    /// Return the static list of namespaces this node manager uses.
    fn namespaces(&self) -> Vec<NamespaceMetadata>;

    /// Return whether this node should handle requests to create a node
    /// for the given parent ID. This is only called if no new node ID is
    /// requested, otherwise owns_node is called on the requested node ID.
    fn owns_server_events(&self) -> bool {
        false
    }

    /// Return `true` when this implementation can handle `method_id` even if the call object does
    /// not expose that exact method node as a component (e.g. a cross-node-manager shared method that
    /// validates its own object). Default false.
    fn accepts_method_without_object_component(&self, _method_id: &NodeId) -> bool {
        false
    }

    /// Return `true` if a node with no requested node ID and parent `parent_id`
    /// should be created using this node manager.
    ///
    /// This does not commit to actually allowing the node to be created, it just means
    /// that no other node managers will be called to create the node.
    fn handle_new_node(&self, parent_id: &ExpandedNodeId) -> bool {
        false
    }

    /// Perform the register nodes service. The default behavior for this service is to
    /// do nothing and pretend the nodes were registered.
    async fn register_nodes(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        nodes: &mut [&mut RegisterNodeItem],
    ) -> Result<(), StatusCode> {
        for node in nodes {
            node.set_registered(true);
        }

        Ok(())
    }

    /// Read for variable values. Other attributes are handled by the parent
    /// node ID. This should return a list of data values with the same length
    /// and order as `nodes`.
    async fn read_values(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        nodes: &[&ParsedReadValueId],
        max_age: f64,
        timestamps_to_return: TimestampsToReturn,
    ) -> Vec<DataValue> {
        let address_space = address_space.read();
        nodes
            .iter()
            .map(|n| address_space.read(context, n, max_age, timestamps_to_return))
            .collect()
    }

    /// Create monitored items for the Value attribute, as needed.
    /// This should, at the very least, read the current value of the nodes,
    /// and set appropriate status on the monitored item request, see
    /// default implementation.
    ///
    /// It may also begin sampling as given by the monitored item request.
    async fn create_value_monitored_items(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        items: &mut [&mut &mut CreateMonitoredItem],
    ) {
        let to_read: Vec<_> = items.iter().map(|r| r.item_to_monitor()).collect();
        let values = self
            .read_values(
                context,
                address_space,
                &to_read,
                0.0,
                TimestampsToReturn::Both,
            )
            .await;

        for (value, node) in values.into_iter().zip(items.iter_mut()) {
            if value.status() != StatusCode::BadAttributeIdInvalid {
                node.set_initial_value(value);
            }
            node.set_status(StatusCode::Good);
        }
    }

    /// Create monitored items for events.
    ///
    /// This does not need to do anything.
    async fn create_event_monitored_items(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        items: &mut [&mut &mut CreateMonitoredItem],
    ) {
        // This is just a no-op by default.
    }

    /// Handle the SetMonitoringMode request, to pause or resume sampling.
    ///
    /// This will only get monitored items for events or value.
    async fn set_monitoring_mode(
        &self,
        context: &RequestContext,
        mode: MonitoringMode,
        items: &[&MonitoredItemRef],
    ) {
    }

    /// Handle modification of monitored items, this may adjust
    /// sampling intervals or filters, and require action to update background
    /// processes.
    async fn modify_monitored_items(
        &self,
        context: &RequestContext,
        items: &[&MonitoredItemUpdateRef],
    ) {
    }

    /// Handle deletion of monitored items.
    async fn delete_monitored_items(&self, context: &RequestContext, items: &[&MonitoredItemRef]) {}

    /// Perform the unregister nodes service. The default behavior for this service is to
    /// do nothing.
    async fn unregister_nodes(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        nodes: &[&NodeId],
    ) -> Result<(), StatusCode> {
        // Again, just do nothing
        Ok(())
    }

    /// Perform the history read raw modified service. This should write results
    /// to the `nodes` list of type either `HistoryData` or `HistoryModifiedData`
    ///
    /// Nodes are verified to be readable before this is called.
    async fn history_read_raw_modified(
        &self,
        context: &RequestContext,
        details: &ReadRawModifiedDetails,
        nodes: &mut [&mut &mut HistoryNode],
        timestamps_to_return: TimestampsToReturn,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the history read processed service. This should write results
    /// to the `nodes` list of type `HistoryData`.
    ///
    /// Nodes are verified to be readable before this is called.
    async fn history_read_processed(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        details: &ReadProcessedDetails,
        nodes: &mut [&mut &mut HistoryNode],
        timestamps_to_return: TimestampsToReturn,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the history read processed service. This should write results
    /// to the `nodes` list of type `HistoryData`.
    ///
    /// Nodes are verified to be readable before this is called.
    async fn history_read_at_time(
        &self,
        context: &RequestContext,
        details: &ReadAtTimeDetails,
        nodes: &mut [&mut &mut HistoryNode],
        timestamps_to_return: TimestampsToReturn,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the history read events service. This should write results
    /// to the `nodes` list of type `HistoryEvent`.
    ///
    /// Nodes are verified to be readable before this is called.
    async fn history_read_events(
        &self,
        context: &RequestContext,
        details: &ReadEventDetails,
        nodes: &mut [&mut &mut HistoryNode],
        timestamps_to_return: TimestampsToReturn,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the history read annotations data service. This should write
    /// results to the `nodes` list of type `Annotation`.
    ///
    /// Nodes are verified to be readable before this is called.
    async fn history_read_annotations(
        &self,
        context: &RequestContext,
        details: &ReadAnnotationDataDetails,
        nodes: &mut [&mut &mut HistoryNode],
        timestamps_to_return: TimestampsToReturn,
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Release a history continuation point after the service removes it from the session cache.
    async fn history_release_continuation_point(
        &self,
        context: &RequestContext,
        node_id: &NodeId,
        continuation_point: &ContinuationPoint,
    ) -> Result<(), StatusCode> {
        Ok(())
    }

    /// Perform the HistoryUpdate service. This should write result
    /// status codes to the `nodes` list as appropriate.
    ///
    /// Nodes are verified to be writable before this is called.
    async fn history_update(
        &self,
        context: &RequestContext,
        nodes: &mut [&mut &mut HistoryUpdateNode],
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Perform the write service. This should write results
    /// to the `nodes_to_write` list. The default result is `BadNodeIdUnknown`
    ///
    /// Writing is left almost entirely up to the node manager impl. If you do write
    /// values you should call `context.subscriptions.notify_data_change` to trigger
    /// any monitored items subscribed to the updated values.
    async fn write(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        nodes_to_write: &mut [&mut WriteNode],
    ) -> Result<(), StatusCode> {
        Err(StatusCode::BadServiceUnsupported)
    }

    /// Call a list of methods.
    ///
    /// The methods have already had their arguments verified to have valid length
    /// and the method is verified to exist on the given object. This should try
    /// to execute the methods, and set the result.
    async fn call(
        &self,
        context: &RequestContext,
        _address_space: &RwLock<AddressSpace>,
        methods_to_call: &mut [&mut &mut MethodCall],
    ) -> Result<(), StatusCode> {
        for method in methods_to_call {
            let Some(callback) = self.method_callback(method.method_id()) else {
                method.set_status(StatusCode::BadNotImplemented);
                continue;
            };

            match callback(context, method.arguments()) {
                Ok(outputs) => {
                    method.set_outputs(outputs);
                    method.set_status(StatusCode::Good);
                }
                Err(status) => method.set_status(status),
            }
        }

        Ok(())
    }

    /// Return a callback for executing a method, if this implementation has one registered.
    fn method_callback(&self, method_id: &NodeId) -> Option<InMemoryMethodCallback> {
        None
    }

    /// Add a list of nodes.
    ///
    /// This should create the nodes, or set a failed status as appropriate.
    /// If a node was created, the status should be set to Good.
    async fn add_nodes(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        nodes_to_add: &mut [&mut AddNodeItem],
    ) -> Result<(), StatusCode> {
        add_nodes_impl(context, address_space, nodes_to_add);
        Ok(())
    }

    /// Add a list of references.
    ///
    /// This will be given all references where the source _or_
    /// target belongs to this node manager. A reference is
    /// considered successfully added if either source_status
    /// or target_status are Good.
    ///
    /// If you want to explicitly set the reference to failed,
    /// set both source and target status. Note that it may
    /// already have been added in a different node manager, you are
    /// responsible for any cleanup if you do this.
    async fn add_references(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        references_to_add: &mut [&mut AddReferenceItem],
    ) -> Result<(), StatusCode> {
        add_references_impl(context, address_space, references_to_add);
        Ok(())
    }

    /// Delete a list of nodes.
    ///
    /// This will be given all nodes that belong to this node manager.
    ///
    /// Typically, you also want to implement `delete_node_references` if
    /// there are other node managers that support deletes.
    async fn delete_nodes(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        nodes_to_delete: &mut [&mut DeleteNodeItem],
    ) -> Result<(), StatusCode> {
        delete_nodes_impl(context, address_space, nodes_to_delete);
        Ok(())
    }

    /// Delete references for the given list of nodes.
    /// The node manager should respect `delete_target_references`.
    ///
    /// This is not allowed to fail, you should make it impossible to delete
    /// nodes with immutable references.
    async fn delete_node_references(
        &self,
        _context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        to_delete: &[&DeleteNodeItem],
    ) {
        let mut address_space = address_space.write();
        for item in to_delete {
            if item.status().is_good() {
                address_space
                    .delete_node_references(item.node_id(), item.delete_target_references());
            }
        }
    }

    /// Delete a list of references.
    ///
    /// This will be given all references where the source _or_
    /// target belongs to this node manager. A reference is
    /// considered successfully added if either source_status
    /// or target_status are Good.
    ///
    /// If you want to explicitly set the reference to failed,
    /// set both source and target status. Note that it may
    /// already have been deleted in a different node manager, you are
    /// responsible for any cleanup if you do this.
    async fn delete_references(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        references_to_delete: &mut [&mut DeleteReferenceItem],
    ) -> Result<(), StatusCode> {
        delete_references_impl(context, address_space, references_to_delete);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authenticator::UserToken,
        builder::ServerBuilder,
        identity_token::IdentityToken,
        node_manager::{NodeMutator, RequestContextInner},
        session::instance::Session,
    };
    use async_trait::async_trait;
    use opcua_types::{
        AddNodesItem, AddReferencesItem, AnonymousIdentityToken, ApplicationDescription,
        ByteString, DeleteNodesItem, DiagnosticBits, MessageSecurityMode, ObjectAttributes,
        ObjectTypeId, QualifiedName, UAString,
    };

    struct TestImpl;

    #[async_trait]
    impl InMemoryNodeManagerImpl for TestImpl {
        async fn init(&self, _address_space: &mut AddressSpace, _context: ServerContext) {}

        fn name(&self) -> &str {
            "test"
        }

        fn namespaces(&self) -> Vec<NamespaceMetadata> {
            vec![NamespaceMetadata {
                namespace_uri: "urn:test".to_string(),
                namespace_index: 1,
                ..Default::default()
            }]
        }
    }

    fn request_context() -> RequestContext {
        let mut builder = ServerBuilder::new_anonymous("add nodes duplicate browse name test");
        builder.config_mut().limits.clients_can_modify_address_space = true;
        let (_server, handle) = builder.build().expect("test server should build");
        let info = handle.info().clone();
        let session = Session::create(
            &info,
            NodeId::new(0, 1),
            1,
            60_000,
            0,
            0,
            UAString::from("opc.tcp://localhost"),
            opcua_crypto::SecurityPolicy::None.to_str().to_string(),
            IdentityToken::Anonymous(AnonymousIdentityToken {
                policy_id: UAString::from("anonymous"),
            }),
            None,
            ByteString::null(),
            UAString::from("test"),
            ApplicationDescription::default(),
            MessageSecurityMode::None,
        );

        RequestContext {
            current_node_manager_index: 0,
            inner: Arc::new(RequestContextInner {
                session: Arc::new(RwLock::new(session)),
                session_id: 1,
                authenticator: info.authenticator.clone(),
                token: UserToken("anonymous".to_string()),
                user_roles: Arc::new(Vec::new()),
                type_tree: info.type_tree.clone(),
                type_tree_getter: info.type_tree_getter.clone(),
                subscriptions: handle.subscriptions().clone(),
                info,
            }),
        }
    }

    fn object_attributes() -> ObjectAttributes {
        ObjectAttributes {
            specified_attributes: 0,
            display_name: LocalizedText::null(),
            description: LocalizedText::null(),
            write_mask: 0,
            user_write_mask: 0,
            event_notifier: 0,
        }
    }

    fn object_node(node_id: &NodeId, browse_name: &'static str) -> Object {
        Object::new(node_id, browse_name, browse_name, EventNotifier::empty())
    }

    fn add_object_node_item(
        parent_id: &NodeId,
        new_node_id: &NodeId,
        browse_name: QualifiedName,
    ) -> AddNodeItem {
        add_object_node_item_with_type_definition(
            parent_id,
            new_node_id,
            browse_name,
            ExpandedNodeId::from(NodeId::from(ObjectTypeId::BaseObjectType)),
        )
    }

    fn add_object_node_item_with_type_definition(
        parent_id: &NodeId,
        new_node_id: &NodeId,
        browse_name: QualifiedName,
        type_definition: ExpandedNodeId,
    ) -> AddNodeItem {
        AddNodeItem::new(
            AddNodesItem {
                parent_node_id: ExpandedNodeId::from(parent_id),
                reference_type_id: NodeId::from(ReferenceTypeId::HasComponent),
                requested_new_node_id: ExpandedNodeId::from(new_node_id),
                browse_name,
                node_class: NodeClass::Object,
                node_attributes: AddNodeAttributes::Object(object_attributes())
                    .as_extension_object(),
                type_definition,
            },
            DiagnosticBits::empty(),
        )
    }

    fn add_object_node_item_with_attributes(
        parent_id: &NodeId,
        new_node_id: &NodeId,
        browse_name: QualifiedName,
        attributes: ObjectAttributes,
    ) -> AddNodeItem {
        AddNodeItem::new(
            AddNodesItem {
                parent_node_id: ExpandedNodeId::from(parent_id),
                reference_type_id: NodeId::from(ReferenceTypeId::HasComponent),
                requested_new_node_id: ExpandedNodeId::from(new_node_id),
                browse_name,
                node_class: NodeClass::Object,
                node_attributes: AddNodeAttributes::Object(attributes).as_extension_object(),
                type_definition: ExpandedNodeId::from(NodeId::from(ObjectTypeId::BaseObjectType)),
            },
            DiagnosticBits::empty(),
        )
    }

    fn add_reference_item_with_type(
        source_id: &NodeId,
        target_id: &NodeId,
        reference_type_id: &NodeId,
    ) -> AddReferenceItem {
        add_reference_item_full(source_id, target_id, reference_type_id, NodeClass::Object)
    }

    fn add_variable_type_subtype_item(
        parent_id: &NodeId,
        new_node_id: &NodeId,
        browse_name: QualifiedName,
        data_type: NodeId,
        value_rank: i32,
    ) -> AddNodeItem {
        let attributes = opcua_types::VariableTypeAttributes {
            specified_attributes: (AttributesMask::DATA_TYPE | AttributesMask::VALUE_RANK).bits(),
            data_type,
            value_rank,
            ..Default::default()
        };
        AddNodeItem::new(
            AddNodesItem {
                parent_node_id: ExpandedNodeId::from(parent_id),
                reference_type_id: NodeId::from(ReferenceTypeId::HasSubtype),
                requested_new_node_id: ExpandedNodeId::from(new_node_id),
                browse_name,
                node_class: NodeClass::VariableType,
                node_attributes: AddNodeAttributes::VariableType(attributes).as_extension_object(),
                type_definition: ExpandedNodeId::null(),
            },
            DiagnosticBits::empty(),
        )
    }

    fn add_reference_item_full(
        source_id: &NodeId,
        target_id: &NodeId,
        reference_type_id: &NodeId,
        target_node_class: NodeClass,
    ) -> AddReferenceItem {
        AddReferenceItem::new(
            AddReferencesItem {
                source_node_id: source_id.clone(),
                reference_type_id: reference_type_id.clone(),
                is_forward: true,
                target_server_uri: UAString::null(),
                target_node_id: ExpandedNodeId::from(target_id),
                target_node_class,
            },
            DiagnosticBits::empty(),
        )
    }

    fn deleted_node_item(node_id: &NodeId, delete_target_references: bool) -> DeleteNodeItem {
        let mut item = DeleteNodeItem::new(
            DeleteNodesItem {
                node_id: node_id.clone(),
                delete_target_references,
            },
            DiagnosticBits::empty(),
        );
        item.set_result(StatusCode::Good);
        item
    }

    #[tokio::test]
    async fn duplicate_browse_name_returns_operation_level_bad_browse_name_duplicated() {
        let context = request_context();
        let parent_id = NodeId::new(1, "parent");
        let existing_child_id = NodeId::new(1, "existing-child");
        let duplicate_child_id = NodeId::new(1, "duplicate-child");
        let duplicate_browse_name = QualifiedName::new(1, "DuplicateName");
        let mut address_space = AddressSpace::new();
        address_space.add_namespace("urn:test", 1);
        address_space.insert::<_, NodeId>(object_node(&parent_id, "parent"), None);
        address_space.insert(
            Object::new(
                &existing_child_id,
                duplicate_browse_name.clone(),
                "DuplicateName",
                EventNotifier::empty(),
            ),
            Some(&[(
                &parent_id,
                &NodeId::from(ReferenceTypeId::HasComponent),
                ReferenceDirection::Inverse,
            )]),
        );
        let manager = super::super::InMemoryNodeManager::new(TestImpl, address_space);
        let mut item = add_object_node_item(&parent_id, &duplicate_child_id, duplicate_browse_name);

        {
            let mut nodes = vec![&mut item];
            manager
                .add_nodes(&context, nodes.as_mut_slice())
                .await
                .unwrap();
        }

        assert_eq!(item.status(), StatusCode::BadBrowseNameDuplicated);
        assert!(item.added_node_id().is_null());
        assert!(!manager
            .address_space()
            .read()
            .node_exists(&duplicate_child_id));
    }

    #[tokio::test]
    async fn invalid_type_definition_returns_operation_level_bad_type_definition_invalid() {
        let context = request_context();
        let parent_id = NodeId::new(1, "parent");
        let new_node_id = NodeId::new(1, "child-with-invalid-type");
        let invalid_type_definition = NodeId::new(2, "missing-object-type");
        let mut address_space = AddressSpace::new();
        address_space.add_namespace("urn:test", 1);
        address_space.insert::<_, NodeId>(object_node(&parent_id, "parent"), None);
        let manager = super::super::InMemoryNodeManager::new(TestImpl, address_space);
        let mut item = add_object_node_item_with_type_definition(
            &parent_id,
            &new_node_id,
            QualifiedName::new(1, "ChildWithInvalidType"),
            ExpandedNodeId::from(invalid_type_definition),
        );

        {
            let mut nodes = vec![&mut item];
            manager
                .add_nodes(&context, nodes.as_mut_slice())
                .await
                .unwrap();
        }

        assert_eq!(item.status(), StatusCode::BadTypeDefinitionInvalid);
        assert!(item.added_node_id().is_null());
        assert!(!manager.address_space().read().node_exists(&new_node_id));
    }

    #[tokio::test]
    async fn node_attributes_invalid_returns_operation_level_bad_node_attributes_invalid() {
        let context = request_context();
        let parent_id = NodeId::new(1, "parent");
        let new_node_id = NodeId::new(1, "object-with-variable-value-attribute");
        let mut address_space = AddressSpace::new();
        address_space.add_namespace("http://opcfoundation.org/UA/", 0);
        address_space.add_namespace("urn:test", 1);
        address_space.insert::<_, NodeId>(
            ObjectType::new(
                &NodeId::from(ObjectTypeId::BaseObjectType),
                "BaseObjectType",
                "BaseObjectType",
                false,
            ),
            None,
        );
        address_space.insert::<_, NodeId>(object_node(&parent_id, "parent"), None);
        let manager = super::super::InMemoryNodeManager::new(TestImpl, address_space);
        let mut attributes = object_attributes();
        attributes.specified_attributes = AttributesMask::VALUE.bits();
        let mut item = add_object_node_item_with_attributes(
            &parent_id,
            &new_node_id,
            QualifiedName::new(1, "ObjectWithVariableValueAttribute"),
            attributes,
        );

        {
            let mut nodes = vec![&mut item];
            manager
                .add_nodes(&context, nodes.as_mut_slice())
                .await
                .unwrap();
        }

        assert_eq!(item.status(), StatusCode::BadNodeAttributesInvalid);
        assert!(item.added_node_id().is_null());
        assert!(!manager.address_space().read().node_exists(&new_node_id));
    }

    #[tokio::test]
    async fn abstract_reference_type_returns_operation_level_bad_reference_type_id_invalid() {
        let context = request_context();
        let source_id = NodeId::new(1, "source");
        let target_id = NodeId::new(1, "target");
        let abstract_reference_type = NodeId::from(ReferenceTypeId::References);
        let mut address_space = AddressSpace::new();
        address_space.add_namespace("http://opcfoundation.org/UA/", 0);
        address_space.add_namespace("urn:test", 1);
        address_space.insert::<_, NodeId>(object_node(&source_id, "source"), None);
        address_space.insert::<_, NodeId>(object_node(&target_id, "target"), None);
        address_space.insert::<_, NodeId>(
            ReferenceType::new(
                &abstract_reference_type,
                "References",
                "References",
                None,
                true,
                true,
            ),
            None,
        );
        assert_eq!(
            context.type_tree.read().get(&abstract_reference_type),
            Some(NodeClass::ReferenceType)
        );
        assert!(reference_type_is_abstract(
            &address_space,
            &abstract_reference_type
        ));
        let manager = super::super::InMemoryNodeManager::new(TestImpl, address_space);
        let mut item =
            add_reference_item_with_type(&source_id, &target_id, &abstract_reference_type);

        {
            let mut references = vec![&mut item];
            manager
                .add_references(&context, references.as_mut_slice())
                .await
                .unwrap();
        }

        assert_eq!(item.result_status(), StatusCode::BadReferenceTypeIdInvalid);
        assert_eq!(item.source_status(), StatusCode::BadReferenceTypeIdInvalid);
        assert_eq!(item.target_status(), StatusCode::BadReferenceTypeIdInvalid);
        assert!(!manager.address_space().read().has_reference(
            &source_id,
            &target_id,
            &abstract_reference_type
        ));
    }

    #[tokio::test]
    async fn standard_abstract_reference_type_returns_operation_level_bad_reference_type_id_invalid(
    ) {
        let context = request_context();
        let source_id = NodeId::new(1, "source");
        let target_id = NodeId::new(1, "target");
        let abstract_reference_type = NodeId::from(ReferenceTypeId::References);
        let mut address_space = AddressSpace::new();
        address_space.add_namespace("urn:test", 1);
        address_space.insert::<_, NodeId>(object_node(&source_id, "source"), None);
        address_space.insert::<_, NodeId>(object_node(&target_id, "target"), None);
        assert_eq!(
            context.type_tree.read().get(&abstract_reference_type),
            Some(NodeClass::ReferenceType)
        );
        let manager = super::super::InMemoryNodeManager::new(TestImpl, address_space);
        let mut item =
            add_reference_item_with_type(&source_id, &target_id, &abstract_reference_type);

        {
            let mut references = vec![&mut item];
            manager
                .add_references(&context, references.as_mut_slice())
                .await
                .unwrap();
        }

        assert_eq!(item.result_status(), StatusCode::BadReferenceTypeIdInvalid);
        assert_eq!(item.source_status(), StatusCode::BadReferenceTypeIdInvalid);
        assert_eq!(item.target_status(), StatusCode::BadReferenceTypeIdInvalid);
        assert!(!manager.address_space().read().has_reference(
            &source_id,
            &target_id,
            &abstract_reference_type
        ));
    }

    #[tokio::test]
    async fn add_nodes_abstract_type_definition_in_metadata_is_rejected() {
        // OPC 10000-3 §5.5.2: an abstract ObjectType cannot be instantiated,
        // even when it exists only in the type metadata (no full node in the
        // address space) — the gap P3-03 closes.
        let context = request_context();
        let parent_id = NodeId::new(1, "parent");
        let abstract_type = NodeId::new(2, "abstract-object-type");
        let concrete_type = NodeId::new(2, "concrete-object-type");
        context.type_tree.write().add_type_node(
            &abstract_type,
            &NodeId::from(ObjectTypeId::BaseObjectType),
            NodeClass::ObjectType,
            true,
        );
        context.type_tree.write().add_type_node(
            &concrete_type,
            &NodeId::from(ObjectTypeId::BaseObjectType),
            NodeClass::ObjectType,
            false,
        );
        let build_manager = || {
            let mut address_space = AddressSpace::new();
            address_space.add_namespace("http://opcfoundation.org/UA/", 0);
            address_space.add_namespace("urn:test", 1);
            address_space.insert::<_, NodeId>(object_node(&parent_id, "parent"), None);
            super::super::InMemoryNodeManager::new(TestImpl, address_space)
        };

        // Abstract type definition (metadata-only) -> rejected, no node created.
        let manager = build_manager();
        let child_abstract = NodeId::new(1, "child-abstract");
        let mut item = add_object_node_item_with_type_definition(
            &parent_id,
            &child_abstract,
            QualifiedName::new(1, "ChildAbstract"),
            ExpandedNodeId::from(abstract_type.clone()),
        );
        {
            let mut nodes = vec![&mut item];
            manager
                .add_nodes(&context, nodes.as_mut_slice())
                .await
                .unwrap();
        }
        assert_eq!(item.status(), StatusCode::BadTypeDefinitionInvalid);
        assert!(!manager.address_space().read().node_exists(&child_abstract));

        // Concrete metadata-only type definition -> accepted.
        let manager = build_manager();
        let child_concrete = NodeId::new(1, "child-concrete");
        let mut item = add_object_node_item_with_type_definition(
            &parent_id,
            &child_concrete,
            QualifiedName::new(1, "ChildConcrete"),
            ExpandedNodeId::from(concrete_type.clone()),
        );
        {
            let mut nodes = vec![&mut item];
            manager
                .add_nodes(&context, nodes.as_mut_slice())
                .await
                .unwrap();
        }
        assert_ne!(item.status(), StatusCode::BadTypeDefinitionInvalid);
    }

    #[tokio::test]
    async fn add_references_target_node_class_mismatch_is_bad_node_class_invalid() {
        // OPC 10000-4 §5.8.3: the declared targetNodeClass must match the actual
        // target node's NodeClass. Unspecified means the client asserts nothing.
        let context = request_context();
        let source_id = NodeId::new(1, "source");
        let target_id = NodeId::new(1, "target"); // an Object
        let reference_type = NodeId::from(ReferenceTypeId::HasComponent);
        context.type_tree.write().add_type_node(
            &reference_type,
            &NodeId::from(ReferenceTypeId::References),
            NodeClass::ReferenceType,
            false,
        );
        let build_manager = || {
            let mut address_space = AddressSpace::new();
            address_space.add_namespace("http://opcfoundation.org/UA/", 0);
            address_space.add_namespace("urn:test", 1);
            address_space.insert::<_, NodeId>(
                ReferenceType::new(
                    &reference_type,
                    "HasComponent",
                    "HasComponent",
                    None,
                    false,
                    false,
                ),
                None,
            );
            address_space.insert::<_, NodeId>(object_node(&source_id, "source"), None);
            address_space.insert::<_, NodeId>(object_node(&target_id, "target"), None);
            super::super::InMemoryNodeManager::new(TestImpl, address_space)
        };

        // Mismatch: target is an Object but Variable is declared -> rejected, no reference.
        let manager = build_manager();
        let mut item =
            add_reference_item_full(&source_id, &target_id, &reference_type, NodeClass::Variable);
        {
            let mut refs = vec![&mut item];
            manager
                .add_references(&context, refs.as_mut_slice())
                .await
                .unwrap();
        }
        assert_eq!(item.source_status(), StatusCode::BadNodeClassInvalid);
        assert!(!manager.address_space().read().has_reference(
            &source_id,
            &target_id,
            &reference_type
        ));

        // Matching class -> accepted.
        let manager = build_manager();
        let mut item =
            add_reference_item_full(&source_id, &target_id, &reference_type, NodeClass::Object);
        {
            let mut refs = vec![&mut item];
            manager
                .add_references(&context, refs.as_mut_slice())
                .await
                .unwrap();
        }
        assert_eq!(item.source_status(), StatusCode::Good);
        assert!(manager.address_space().read().has_reference(
            &source_id,
            &target_id,
            &reference_type
        ));

        // Unspecified -> no assertion, accepted.
        let manager = build_manager();
        let mut item =
            add_reference_item_full(&source_id, &target_id, &reference_type, NodeClass::Unspecified);
        {
            let mut refs = vec![&mut item];
            manager
                .add_references(&context, refs.as_mut_slice())
                .await
                .unwrap();
        }
        assert_eq!(item.source_status(), StatusCode::Good);
        assert!(manager.address_space().read().has_reference(
            &source_id,
            &target_id,
            &reference_type
        ));
    }

    #[tokio::test]
    async fn add_nodes_variable_type_subtype_refinement_is_enforced() {
        // OPC 10000-3 §6.3: a VariableType subtype's DataType/ValueRank may only
        // further-restrict the supertype's.
        let context = request_context();
        let super_type = NodeId::new(1, "super-var-type");
        let int32 = NodeId::from(DataTypeId::Int32);
        let string_dt = NodeId::from(DataTypeId::String);
        {
            let mut tt = context.type_tree.write();
            // Register DataTypes so is_subtype_of can judge (String is NOT under Int32).
            tt.add_type_node(
                &int32,
                &NodeId::from(DataTypeId::BaseDataType),
                NodeClass::DataType,
                false,
            );
            tt.add_type_node(
                &string_dt,
                &NodeId::from(DataTypeId::BaseDataType),
                NodeClass::DataType,
                false,
            );
            tt.add_type_node(
                &NodeId::from(ReferenceTypeId::HasSubtype),
                &NodeId::from(ReferenceTypeId::References),
                NodeClass::ReferenceType,
                false,
            );
        }
        // Supertype: DataType Int32, ValueRank Scalar (-1).
        let build_manager = || {
            let mut address_space = AddressSpace::new();
            address_space.add_namespace("http://opcfoundation.org/UA/", 0);
            address_space.add_namespace("urn:test", 1);
            address_space.insert::<_, NodeId>(
                VariableType::new(
                    &super_type,
                    "SuperVarType",
                    "SuperVarType",
                    int32.clone(),
                    false,
                    -1,
                ),
                None,
            );
            super::super::InMemoryNodeManager::new(TestImpl, address_space)
        };

        // Widened DataType (String is not a subtype of Int32) -> rejected.
        let manager = build_manager();
        let mut item = add_variable_type_subtype_item(
            &super_type,
            &NodeId::new(1, "bad-dt"),
            QualifiedName::new(1, "BadDt"),
            string_dt.clone(),
            -1,
        );
        {
            let mut nodes = vec![&mut item];
            manager
                .add_nodes(&context, nodes.as_mut_slice())
                .await
                .unwrap();
        }
        assert_eq!(item.status(), StatusCode::BadNodeAttributesInvalid);

        // Widened ValueRank (scalar supertype -> array subtype) -> rejected.
        let manager = build_manager();
        let mut item = add_variable_type_subtype_item(
            &super_type,
            &NodeId::new(1, "bad-vr"),
            QualifiedName::new(1, "BadVr"),
            int32.clone(),
            1,
        );
        {
            let mut nodes = vec![&mut item];
            manager
                .add_nodes(&context, nodes.as_mut_slice())
                .await
                .unwrap();
        }
        assert_eq!(item.status(), StatusCode::BadNodeAttributesInvalid);

        // Valid restriction (same DataType, same ValueRank) -> accepted.
        let manager = build_manager();
        let mut item = add_variable_type_subtype_item(
            &super_type,
            &NodeId::new(1, "good"),
            QualifiedName::new(1, "Good"),
            int32.clone(),
            -1,
        );
        {
            let mut nodes = vec![&mut item];
            manager
                .add_nodes(&context, nodes.as_mut_slice())
                .await
                .unwrap();
        }
        assert_ne!(item.status(), StatusCode::BadNodeAttributesInvalid);
    }

    #[tokio::test]
    async fn add_references_has_subtype_between_mismatched_classes_is_rejected() {
        // OPC 10000-3 §5.3: HasSubtype connects a type node to a subtype of the
        // SAME type NodeClass. ObjectType -> VariableType is forbidden;
        // ObjectType -> ObjectType is allowed.
        let context = request_context();
        let src_type = NodeId::new(1, "src-object-type");
        let var_type = NodeId::new(1, "a-variable-type");
        let obj_type_2 = NodeId::new(1, "another-object-type");
        let has_subtype = NodeId::from(ReferenceTypeId::HasSubtype);
        context.type_tree.write().add_type_node(
            &has_subtype,
            &NodeId::from(ReferenceTypeId::References),
            NodeClass::ReferenceType,
            false,
        );
        let build_manager = || {
            let mut address_space = AddressSpace::new();
            address_space.add_namespace("http://opcfoundation.org/UA/", 0);
            address_space.add_namespace("urn:test", 1);
            address_space.insert::<_, NodeId>(
                ReferenceType::new(&has_subtype, "HasSubtype", "HasSubtype", None, false, false),
                None,
            );
            address_space
                .insert::<_, NodeId>(ObjectType::new(&src_type, "SrcType", "SrcType", false), None);
            address_space.insert::<_, NodeId>(
                ObjectType::new(&obj_type_2, "ObjType2", "ObjType2", false),
                None,
            );
            address_space.insert::<_, NodeId>(
                VariableType::new(
                    &var_type,
                    "VarType",
                    "VarType",
                    DataTypeId::BaseDataType.into(),
                    false,
                    -1,
                ),
                None,
            );
            super::super::InMemoryNodeManager::new(TestImpl, address_space)
        };

        // ObjectType -> VariableType: forbidden.
        let manager = build_manager();
        let mut item =
            add_reference_item_full(&src_type, &var_type, &has_subtype, NodeClass::Unspecified);
        {
            let mut refs = vec![&mut item];
            manager
                .add_references(&context, refs.as_mut_slice())
                .await
                .unwrap();
        }
        assert_eq!(item.source_status(), StatusCode::BadReferenceNotAllowed);

        // ObjectType -> ObjectType: allowed.
        let manager = build_manager();
        let mut item =
            add_reference_item_full(&src_type, &obj_type_2, &has_subtype, NodeClass::Unspecified);
        {
            let mut refs = vec![&mut item];
            manager
                .add_references(&context, refs.as_mut_slice())
                .await
                .unwrap();
        }
        assert_eq!(item.source_status(), StatusCode::Good);
    }

    #[tokio::test]
    async fn add_references_second_has_type_definition_is_rejected() {
        // OPC 10000-3 §5.5.1: an Object is the SourceNode of exactly one
        // HasTypeDefinition Reference. A second one (to a different target) is
        // rejected even though the duplicate-same-target check wouldn't catch it.
        let context = request_context();
        let source_id = NodeId::new(1, "instance");
        let type_a = NodeId::new(1, "type-a");
        let type_b = NodeId::new(1, "type-b");
        let has_type_def = NodeId::from(ReferenceTypeId::HasTypeDefinition);
        context.type_tree.write().add_type_node(
            &has_type_def,
            &NodeId::from(ReferenceTypeId::References),
            NodeClass::ReferenceType,
            false,
        );
        let build_manager = |with_existing: bool| {
            let mut address_space = AddressSpace::new();
            address_space.add_namespace("http://opcfoundation.org/UA/", 0);
            address_space.add_namespace("urn:test", 1);
            address_space.insert::<_, NodeId>(
                ReferenceType::new(
                    &has_type_def,
                    "HasTypeDefinition",
                    "HasTypeDefinition",
                    None,
                    false,
                    false,
                ),
                None,
            );
            address_space.insert::<_, NodeId>(object_node(&source_id, "instance"), None);
            address_space.insert::<_, NodeId>(object_node(&type_a, "type-a"), None);
            address_space.insert::<_, NodeId>(object_node(&type_b, "type-b"), None);
            if with_existing {
                address_space.insert_reference(&source_id, &type_a, &has_type_def);
            }
            super::super::InMemoryNodeManager::new(TestImpl, address_space)
        };

        // A second HasTypeDefinition to a different target -> rejected.
        let manager = build_manager(true);
        let mut item =
            add_reference_item_full(&source_id, &type_b, &has_type_def, NodeClass::Unspecified);
        {
            let mut refs = vec![&mut item];
            manager
                .add_references(&context, refs.as_mut_slice())
                .await
                .unwrap();
        }
        assert_eq!(item.source_status(), StatusCode::BadReferenceNotAllowed);
        assert!(!manager.address_space().read().has_reference(
            &source_id,
            &type_b,
            &has_type_def
        ));

        // The first HasTypeDefinition on a node without one -> accepted.
        let manager = build_manager(false);
        let mut item =
            add_reference_item_full(&source_id, &type_a, &has_type_def, NodeClass::Unspecified);
        {
            let mut refs = vec![&mut item];
            manager
                .add_references(&context, refs.as_mut_slice())
                .await
                .unwrap();
        }
        assert_eq!(item.source_status(), StatusCode::Good);
        assert!(manager.address_space().read().has_reference(
            &source_id,
            &type_a,
            &has_type_def
        ));
    }

    #[tokio::test]
    async fn duplicate_reference_returns_operation_level_bad_duplicate_reference_not_allowed() {
        let context = request_context();
        let source_id = NodeId::new(1, "source");
        let target_id = NodeId::new(1, "target");
        let reference_type = NodeId::from(ReferenceTypeId::HasComponent);
        let mut address_space = AddressSpace::new();
        address_space.add_namespace("http://opcfoundation.org/UA/", 0);
        address_space.add_namespace("urn:test", 1);
        address_space.insert::<_, NodeId>(
            ReferenceType::new(
                &reference_type,
                "HasComponent",
                "HasComponent",
                None,
                false,
                false,
            ),
            None,
        );
        address_space.insert::<_, NodeId>(object_node(&source_id, "source"), None);
        address_space.insert::<_, NodeId>(
            object_node(&target_id, "target"),
            Some(&[(&source_id, &reference_type, ReferenceDirection::Inverse)]),
        );
        context.type_tree.write().add_type_node(
            &reference_type,
            &NodeId::from(ReferenceTypeId::References),
            NodeClass::ReferenceType,
            false,
        );
        assert!(address_space.has_reference(&source_id, &target_id, &reference_type));
        let manager = super::super::InMemoryNodeManager::new(TestImpl, address_space);
        let mut item = add_reference_item_with_type(&source_id, &target_id, &reference_type);

        {
            let mut references = vec![&mut item];
            manager
                .add_references(&context, references.as_mut_slice())
                .await
                .unwrap();
        }

        assert_eq!(
            item.result_status(),
            StatusCode::BadDuplicateReferenceNotAllowed
        );
        assert_eq!(
            item.source_status(),
            StatusCode::BadDuplicateReferenceNotAllowed
        );
        assert_eq!(
            item.target_status(),
            StatusCode::BadDuplicateReferenceNotAllowed
        );
        assert!(manager.address_space().read().has_reference(
            &source_id,
            &target_id,
            &reference_type
        ));
    }

    #[tokio::test]
    async fn structural_reference_returns_operation_level_bad_reference_not_allowed() {
        let context = request_context();
        let source_id = NodeId::new(1, "source");
        let target_id = NodeId::new(1, "object-target");
        let reference_type = NodeId::from(ReferenceTypeId::HasProperty);
        let mut address_space = AddressSpace::new();
        address_space.add_namespace("http://opcfoundation.org/UA/", 0);
        address_space.add_namespace("urn:test", 1);
        address_space.insert::<_, NodeId>(
            ReferenceType::new(
                &reference_type,
                "HasProperty",
                "HasProperty",
                None,
                false,
                false,
            ),
            None,
        );
        address_space.insert::<_, NodeId>(object_node(&source_id, "source"), None);
        address_space.insert::<_, NodeId>(object_node(&target_id, "object-target"), None);
        context.type_tree.write().add_type_node(
            &reference_type,
            &NodeId::from(ReferenceTypeId::References),
            NodeClass::ReferenceType,
            false,
        );
        let manager = super::super::InMemoryNodeManager::new(TestImpl, address_space);
        let mut item = add_reference_item_with_type(&source_id, &target_id, &reference_type);

        {
            let mut references = vec![&mut item];
            manager
                .add_references(&context, references.as_mut_slice())
                .await
                .unwrap();
        }

        // OPC-10000-3 7.8 requires HasProperty targets to be Variables; an Object
        // target therefore violates the data model and OPC-10000-4 5.8.3.4 maps
        // that operation-level failure to Bad_ReferenceNotAllowed.
        assert_eq!(item.result_status(), StatusCode::BadReferenceNotAllowed);
        assert_eq!(item.source_status(), StatusCode::BadReferenceNotAllowed);
        assert_eq!(item.target_status(), StatusCode::BadReferenceNotAllowed);
        assert!(!manager.address_space().read().has_reference(
            &source_id,
            &target_id,
            &reference_type
        ));
    }

    #[tokio::test]
    async fn delete_node_references_cleans_cross_manager_references_without_unrelated_deletes() {
        let context = request_context();
        let local_source_id = NodeId::new(1, "local-source");
        let local_target_id = NodeId::new(1, "local-target");
        let deleted_source_id = NodeId::new(2, "deleted-source");
        let kept_target_id = NodeId::new(2, "kept-target");
        let deleted_target_id = NodeId::new(2, "deleted-target");
        let unrelated_target_id = NodeId::new(2, "unrelated-target");
        let reference_type = NodeId::from(ReferenceTypeId::HasComponent);
        let mut address_space = AddressSpace::new();
        address_space.add_namespace("urn:test", 1);
        address_space.insert::<_, NodeId>(object_node(&local_source_id, "local-source"), None);
        address_space.insert::<_, NodeId>(object_node(&local_target_id, "local-target"), None);
        address_space.insert_reference(&deleted_source_id, &local_target_id, &reference_type);
        address_space.insert_reference(&local_source_id, &kept_target_id, &reference_type);
        address_space.insert_reference(&local_source_id, &deleted_target_id, &reference_type);
        address_space.insert_reference(&local_source_id, &unrelated_target_id, &reference_type);
        let manager = super::super::InMemoryNodeManager::new(TestImpl, address_space);
        let remove_source_refs = deleted_node_item(&deleted_source_id, false);
        let keep_target_refs = deleted_node_item(&kept_target_id, false);
        let remove_target_refs = deleted_node_item(&deleted_target_id, true);

        manager
            .delete_node_references(
                &context,
                &[&remove_source_refs, &keep_target_refs, &remove_target_refs],
            )
            .await;

        let address_space = manager.address_space().read();
        assert!(!address_space.has_reference(
            &deleted_source_id,
            &local_target_id,
            &reference_type
        ));
        assert!(address_space.has_reference(&local_source_id, &kept_target_id, &reference_type));
        assert!(!address_space.has_reference(
            &local_source_id,
            &deleted_target_id,
            &reference_type
        ));
        assert!(address_space.has_reference(
            &local_source_id,
            &unrelated_target_id,
            &reference_type
        ));
    }
}
