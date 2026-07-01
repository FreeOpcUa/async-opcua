//! The implementation of [InMemoryNodeManager], a generic node manager that keeps
//! all its nodes in memory, and delegates implementing
//! details to a type implementing [InMemoryNodeManagerImpl].

mod memory_mgr_impl;
mod simple;

#[cfg(feature = "generated-address-space")]
mod core;

#[cfg(feature = "generated-address-space")]
pub use core::{CoreNodeManager, CoreNodeManagerBuilder, CoreNodeManagerImpl};

pub use memory_mgr_impl::*;
use opcua_core::{trace_read_lock, trace_write_lock};
pub use simple::*;
use tracing::warn;

use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};

use async_trait::async_trait;
use hashbrown::HashMap;

use crate::{
    address_space::{
        read_node_value, user_access_level, AccessLevel, EventNotifier, NodeType,
        ReferenceDirection,
    },
    diagnostics::NamespaceMetadata,
    rbac,
    session::continuation_points::ContinuationPoint,
    subscriptions::CreateMonitoredItem,
    SubscriptionCache,
};
use opcua_core::sync::RwLock;
use opcua_types::{
    argument::Argument, AccessRestrictionType, AttributeId, BrowseDescriptionResultMask,
    BrowseDirection, DataEncoding, DataValue, DateTime, ExpandedNodeId, MonitoringMode, NodeClass,
    NodeId, NumericRange, PermissionType, ReadAnnotationDataDetails, ReadAtTimeDetails,
    ReadEventDetails, ReadProcessedDetails, ReadRawModifiedDetails, ReferenceDescription,
    ReferenceTypeId, RolePermissionType, StatusCode, TimestampsToReturn, Variant,
};

use super::{
    build::NodeManagerBuilder,
    view::{AddReferenceResult, ExternalReference, ExternalReferenceRequest, NodeMetadata},
    AddNodeItem, AddReferenceItem, AttributeProvider, BrowseNode, BrowsePathItem, DefaultTypeTree,
    DeleteNodeItem, DeleteReferenceItem, DynNodeManager, HistoryNode, HistoryProvider,
    HistoryUpdateDetails, HistoryUpdateNode, MethodCall, MethodProvider, MonitoredItemProvider,
    MonitoredItemRef, MonitoredItemUpdateRef, NodeManagerCore, NodeMutator, QueryRequest, ReadNode,
    RegisterNodeItem, RequestContext, ServerContext, ViewProvider, WriteNode,
};

use crate::address_space::AddressSpace;

#[derive(Default)]
struct BrowseContinuationPoint {
    nodes: VecDeque<ReferenceDescription>,
}

/// A node manager that stores its nodes in an in-memory [AddressSpace]. This
/// only supports a static list of namespaces, and a attributes stored in memory.
///
/// Implementations of custom behavior are provided with a type implementing
/// [InMemoryNodeManagerImpl].
pub struct InMemoryNodeManager<TImpl> {
    address_space: Arc<RwLock<AddressSpace>>,
    namespaces: HashMap<u16, String>,
    inner: TImpl,
}

/// Builder for the in-memory node manager.
pub struct InMemoryNodeManagerBuilder<T> {
    impl_builder: T,
}

impl<T: InMemoryNodeManagerImplBuilder> InMemoryNodeManagerBuilder<T> {
    /// Create a new in memory node manager builder with the given
    /// builder for the [InMemoryNodeManagerImpl].
    pub fn new(impl_builder: T) -> Self {
        Self { impl_builder }
    }
}

impl<T: InMemoryNodeManagerImplBuilder> NodeManagerBuilder for InMemoryNodeManagerBuilder<T> {
    fn build(self: Box<Self>, context: ServerContext) -> Arc<DynNodeManager> {
        let mut address_space = AddressSpace::new();
        let snapshot_info = Arc::clone(&context.info);
        let snapshot_type_tree = Arc::clone(&context.type_tree);
        let inner = self.impl_builder.build(context, &mut address_space);
        {
            let type_tree = trace_read_lock!(snapshot_type_tree);
            snapshot_info.publish_type_tree_snapshot(&type_tree);
        }
        Arc::new(InMemoryNodeManager::new(inner, address_space))
    }
}

impl<TImpl: InMemoryNodeManagerImpl> InMemoryNodeManager<TImpl> {
    pub(crate) fn new(inner: TImpl, address_space: AddressSpace) -> Self {
        Self {
            namespaces: address_space.namespaces().clone(),
            address_space: Arc::new(RwLock::new(address_space)),
            inner,
        }
    }

    /// Return the inner [InMemoryNodeManagerImpl].
    pub fn inner(&self) -> &TImpl {
        &self.inner
    }

    /// Get the address space.
    pub fn address_space(&self) -> &Arc<RwLock<AddressSpace>> {
        &self.address_space
    }

    /// Get a reference to the namespaces managed by this node manager,
    /// by namespace index.
    pub fn namespaces(&self) -> &HashMap<u16, String> {
        &self.namespaces
    }

    fn resolve_method_node_id(
        &self,
        address_space: &AddressSpace,
        type_tree: &DefaultTypeTree,
        method: &MethodCall,
    ) -> Option<NodeId> {
        address_space
            .find_references(
                method.object_id(),
                Some((ReferenceTypeId::HasComponent, false)),
                type_tree,
                BrowseDirection::Forward,
            )
            .find(|r| r.target_node == method.method_id())
            .map(|r| r.target_node.clone())
            .or_else(|| {
                self.inner
                    .accepts_method_without_object_component(method.method_id())
                    .then(|| method.method_id().clone())
            })
    }

    /// Set the attributes given in `values` and notify any subscriptions
    /// about the changes.
    ///
    /// To set values, use [InMemoryNodeManager::set_values].
    pub fn set_attributes<'a>(
        &self,
        subscriptions: &SubscriptionCache,
        values: impl Iterator<Item = (&'a NodeId, AttributeId, Variant)>,
    ) -> Result<(), StatusCode> {
        let address_space = trace_read_lock!(self.address_space);
        let mut output = Vec::new();

        for (id, attribute_id, value) in values {
            let Some(mut node) = address_space.find_mut(id) else {
                return Err(StatusCode::BadNodeIdUnknown);
            };

            let node_mut = node.as_mut_node();
            node_mut.set_attribute(attribute_id, value)?;
            // Don't notify on changes to event notifier, subscribing to that
            // specific attribute means subscribing to events.
            if attribute_id != AttributeId::EventNotifier {
                output.push((id, attribute_id));
            }
        }

        subscriptions.maybe_notify(
            output.into_iter(),
            |node_id, attribute_id, index_range, data_encoding| {
                let node = address_space.find(node_id)?;
                let node_ref = node.as_node();

                node_ref.get_attribute(
                    TimestampsToReturn::Both,
                    attribute_id,
                    index_range,
                    data_encoding,
                )
            },
        );

        Ok(())
    }

    /// Set the attribute given by `attribute_id` on the node with ID `id` to
    /// `value`.
    pub fn set_attribute(
        &self,
        subscriptions: &SubscriptionCache,
        id: &NodeId,
        attribute_id: AttributeId,
        value: Variant,
    ) -> Result<(), StatusCode> {
        self.set_attributes(subscriptions, [(id, attribute_id, value)].into_iter())
    }

    /// Set variable values with updates given by `values`, notifying any
    /// subscriptions of the changes.
    pub fn set_values<'a>(
        &self,
        subscriptions: &SubscriptionCache,
        values: impl Iterator<Item = (&'a NodeId, Option<&'a NumericRange>, DataValue)>,
    ) -> Result<(), StatusCode> {
        let address_space = trace_read_lock!(self.address_space);
        let now = DateTime::now();
        let mut output = Vec::new();

        for (id, index_range, value) in values {
            let Some(mut node) = address_space.find_mut(id) else {
                return Err(StatusCode::BadNodeIdUnknown);
            };

            match &mut *node {
                NodeType::Variable(v) => {
                    if let Some(range) = index_range {
                        let status = value.status();
                        let source_timestamp = value.source_timestamp.unwrap_or(now);
                        let server_timestamp = value.server_timestamp.unwrap_or(now);
                        v.set_value_range(
                            value.value.unwrap_or_default(),
                            range,
                            status,
                            &server_timestamp,
                            &source_timestamp,
                        )?
                    } else {
                        v.set_data_value(value)
                    }
                }
                NodeType::VariableType(v) => v.set_value(value.value.unwrap_or_default()),
                _ => return Err(StatusCode::BadAttributeIdInvalid),
            }

            output.push((id, AttributeId::Value));
        }

        subscriptions.maybe_notify(
            output.into_iter(),
            |node_id, attribute_id, index_range, data_encoding| {
                let node = address_space.find(node_id)?;
                let node_ref = node.as_node();

                node_ref.get_attribute(
                    TimestampsToReturn::Both,
                    attribute_id,
                    index_range,
                    data_encoding,
                )
            },
        );

        Ok(())
    }

    /// Set the variable value to `value`, using `index_range`, on the
    /// node with ID `id`.
    pub fn set_value(
        &self,
        subscriptions: &SubscriptionCache,
        id: &NodeId,
        index_range: Option<&NumericRange>,
        value: DataValue,
    ) -> Result<(), StatusCode> {
        self.set_values(subscriptions, [(id, index_range, value)].into_iter())
    }

    fn get_reference(
        address_space: &AddressSpace,
        type_tree: &DefaultTypeTree,
        target_node: &NodeType,
        result_mask: BrowseDescriptionResultMask,
    ) -> NodeMetadata {
        let node_ref = target_node.as_node();

        let target_node_id = node_ref.node_id().clone();

        let type_definition =
            if result_mask.contains(BrowseDescriptionResultMask::RESULT_MASK_TYPE_DEFINITION) {
                // Type definition NodeId of the TargetNode. Type definitions are only available
                // for the NodeClasses Object and Variable. For all other NodeClasses a null NodeId
                // shall be returned.
                match node_ref.node_class() {
                    NodeClass::Object | NodeClass::Variable => {
                        let mut type_defs = address_space.find_references(
                            &target_node_id,
                            Some((ReferenceTypeId::HasTypeDefinition, false)),
                            type_tree,
                            BrowseDirection::Forward,
                        );
                        if let Some(type_def) = type_defs.next() {
                            ExpandedNodeId::new(type_def.target_node.clone())
                        } else {
                            ExpandedNodeId::null()
                        }
                    }
                    _ => ExpandedNodeId::null(),
                }
            } else {
                ExpandedNodeId::null()
            };

        NodeMetadata {
            node_id: ExpandedNodeId::new(target_node_id),
            browse_name: node_ref.browse_name().clone(),
            display_name: node_ref.display_name().clone(),
            node_class: node_ref.node_class(),
            type_definition,
        }
    }

    fn can_browse_target(context: &RequestContext, target_node: &NodeType) -> bool {
        if !rbac::decision::authorize_ctx(context, target_node, PermissionType::Browse) {
            return false;
        }

        let apply_restrictions_to_browse =
            target_node
                .as_node()
                .access_restrictions()
                .is_some_and(|restrictions| {
                    restrictions.contains(AccessRestrictionType::ApplyRestrictionsToBrowse)
                });
        if apply_restrictions_to_browse {
            rbac::decision::access_restrictions_ok_ctx(context, target_node).is_ok()
        } else {
            true
        }
    }

    /// Browses a single node, returns any external references found.
    fn browse_node(
        address_space: &AddressSpace,
        type_tree: &DefaultTypeTree,
        context: &RequestContext,
        node: &mut BrowseNode,
        namespaces: &hashbrown::HashMap<u16, String>,
    ) {
        let reference_type_id = if node.reference_type_id().is_null() {
            None
        } else if let Ok(reference_type_id) = node.reference_type_id().as_reference_type_id() {
            Some((reference_type_id, node.include_subtypes()))
        } else {
            None
        };

        let mut cont_point = BrowseContinuationPoint::default();

        let source_node_id = node.node_id().clone();

        for reference in address_space.find_references(
            &source_node_id,
            reference_type_id,
            type_tree,
            node.browse_direction(),
        ) {
            if reference.target_node.is_null() {
                warn!(
                    "Target node in reference from {} of type {} is null",
                    node.node_id(),
                    reference.reference_type
                );
                continue;
            }
            let target_node = address_space.find_node(reference.target_node);
            let Some(target_node) = target_node else {
                if namespaces.contains_key(&reference.target_node.namespace) {
                    warn!(
                        "Target node {} in reference from {} of type {} does not exist",
                        reference.target_node,
                        node.node_id(),
                        reference.reference_type
                    );
                } else {
                    node.push_external_reference(ExternalReference::new(
                        reference.target_node.into(),
                        reference.reference_type.clone(),
                        reference.direction,
                    ))
                }

                continue;
            };

            if !Self::can_browse_target(context, &target_node) {
                continue;
            }

            let r_node =
                Self::get_reference(address_space, type_tree, &target_node, node.result_mask());

            let ref_desc = ReferenceDescription {
                reference_type_id: reference.reference_type.clone(),
                is_forward: matches!(reference.direction, ReferenceDirection::Forward),
                node_id: r_node.node_id,
                browse_name: r_node.browse_name,
                display_name: r_node.display_name,
                node_class: r_node.node_class,
                type_definition: r_node.type_definition,
            };

            if let AddReferenceResult::Full(c) = node.add(type_tree, ref_desc) {
                cont_point.nodes.push_back(c);
            }
        }

        if !cont_point.nodes.is_empty() {
            node.set_next_continuation_point(Box::new(cont_point));
        }
    }

    fn translate_browse_paths(
        address_space: &AddressSpace,
        type_tree: &DefaultTypeTree,
        context: &RequestContext,
        namespaces: &hashbrown::HashMap<u16, String>,
        item: &mut BrowsePathItem,
    ) {
        if let Some(name) = item.unmatched_browse_name() {
            let is_full_match = address_space
                .find_node(item.node_id())
                .is_some_and(|n| name.is_null() || n.as_node().browse_name() == name);
            if !is_full_match {
                return;
            } else {
                item.set_browse_name_matched(context.current_node_manager_index);
            }
        }

        let mut matching_nodes = HashSet::new();
        matching_nodes.insert(item.node_id());
        let mut next_matching_nodes = HashSet::new();
        let mut results = Vec::new();

        let mut depth = 0;
        for element in item.path() {
            depth += 1;
            for node_id in matching_nodes.drain() {
                let reference_filter = {
                    if element.reference_type_id.is_null() {
                        None
                    } else {
                        Some((element.reference_type_id.clone(), element.include_subtypes))
                    }
                };

                for rf in address_space.find_references(
                    node_id,
                    reference_filter,
                    type_tree,
                    if element.is_inverse {
                        BrowseDirection::Inverse
                    } else {
                        BrowseDirection::Forward
                    },
                ) {
                    if !next_matching_nodes.contains(rf.target_node) {
                        let Some(node) = address_space.find_node(rf.target_node) else {
                            if !namespaces.contains_key(&rf.target_node.namespace) {
                                results.push((
                                    rf.target_node,
                                    depth,
                                    Some(element.target_name.clone()),
                                ));
                            }
                            continue;
                        };

                        if element.target_name.is_null()
                            || node.as_node().browse_name() == &element.target_name
                        {
                            next_matching_nodes.insert(rf.target_node);
                            results.push((rf.target_node, depth, None));
                        }
                    }
                }
            }
            std::mem::swap(&mut matching_nodes, &mut next_matching_nodes);
        }

        for res in results {
            item.add_element(res.0.clone(), res.1, res.2);
        }
    }

    fn validate_history_read_nodes<'a, 'b>(
        &self,
        context: &RequestContext,
        nodes: &'b mut [&'a mut HistoryNode],
        is_for_events: bool,
    ) -> Vec<&'b mut &'a mut HistoryNode> {
        let address_space = trace_read_lock!(self.address_space);
        let mut valid = Vec::with_capacity(nodes.len());

        for history_node in nodes {
            let Some(node) = address_space.find(history_node.node_id()) else {
                history_node.set_status(StatusCode::BadNodeIdUnknown);
                continue;
            };

            if is_for_events {
                let NodeType::Object(object) = &*node else {
                    history_node.set_status(StatusCode::BadHistoryOperationUnsupported);
                    continue;
                };

                if !object
                    .event_notifier()
                    .contains(EventNotifier::HISTORY_READ)
                {
                    history_node.set_status(StatusCode::BadHistoryOperationUnsupported);
                    continue;
                }
            } else {
                let NodeType::Variable(_) = &*node else {
                    history_node.set_status(StatusCode::BadHistoryOperationUnsupported);
                    continue;
                };

                let user_access_level = user_access_level(context, &node);

                if !user_access_level.contains(AccessLevel::HISTORY_READ) {
                    history_node.set_status(StatusCode::BadUserAccessDenied);
                    continue;
                }
            }

            if !rbac::decision::authorize_ctx(context, &node, PermissionType::ReadHistory) {
                history_node.set_status(StatusCode::BadUserAccessDenied);
                continue;
            }

            valid.push(history_node);
        }

        valid
    }

    fn validate_history_write_nodes<'a, 'b>(
        &self,
        context: &RequestContext,
        nodes: &'b mut [&'a mut HistoryUpdateNode],
    ) -> Vec<&'b mut &'a mut HistoryUpdateNode> {
        let address_space = trace_read_lock!(self.address_space);
        let mut valid = Vec::with_capacity(nodes.len());

        for history_node in nodes {
            let Some(node) = address_space.find(history_node.details().node_id()) else {
                history_node.set_status(StatusCode::BadNodeIdUnknown);
                continue;
            };

            let is_for_events = matches!(
                history_node.details(),
                HistoryUpdateDetails::DeleteEvent(_) | HistoryUpdateDetails::UpdateEvent(_)
            );

            if is_for_events {
                let NodeType::Object(object) = &*node else {
                    history_node.set_status(StatusCode::BadHistoryOperationUnsupported);
                    continue;
                };

                if !object
                    .event_notifier()
                    .contains(EventNotifier::HISTORY_WRITE)
                {
                    history_node.set_status(StatusCode::BadHistoryOperationUnsupported);
                    continue;
                }
            } else {
                let NodeType::Variable(_) = &*node else {
                    history_node.set_status(StatusCode::BadHistoryOperationUnsupported);
                    continue;
                };

                let user_access_level = user_access_level(context, &node);

                if !user_access_level.contains(AccessLevel::HISTORY_WRITE) {
                    history_node.set_status(StatusCode::BadUserAccessDenied);
                    continue;
                }
            }

            if !rbac::decision::authorize_ctx(
                context,
                &node,
                history_node.details().required_permission(),
            ) {
                history_node.set_status(StatusCode::BadUserAccessDenied);
                continue;
            }

            valid.push(history_node);
        }

        valid
    }

    fn validate_method_calls<'a, 'b>(
        &self,
        context: &RequestContext,
        methods: &'b mut [&'a mut MethodCall],
    ) -> Vec<&'b mut &'a mut MethodCall> {
        let address_space = trace_read_lock!(self.address_space);
        let type_tree = trace_read_lock!(context.type_tree);
        let mut valid = Vec::with_capacity(methods.len());

        for method in methods {
            let Some(method_node_id) =
                self.resolve_method_node_id(&address_space, &type_tree, method)
            else {
                method.set_status(StatusCode::BadMethodInvalid);
                continue;
            };

            let Some(method_ref_guard) = address_space.find(&method_node_id) else {
                method.set_status(StatusCode::BadMethodInvalid);
                continue;
            };

            let NodeType::Method(method_node) = &*method_ref_guard else {
                method.set_status(StatusCode::BadMethodInvalid);
                continue;
            };

            // Part 4 §5.12 Table 61: the Executable attribute not allowing execution is
            // Bad_NotExecutable, distinct from the UserExecutable/permission case below.
            if !method_node.executable() {
                method.set_status(StatusCode::BadNotExecutable);
                continue;
            }

            if let Err(status) =
                rbac::decision::access_restrictions_ok_ctx(context, &method_ref_guard)
            {
                method.set_status(status);
                continue;
            }

            if !method_node.user_executable()
                || !context
                    .authenticator
                    .is_user_executable(&context.token, method.method_id())
                || !rbac::decision::authorize_ctx(context, &method_ref_guard, PermissionType::Call)
            {
                method.set_status(StatusCode::BadUserAccessDenied);
                continue;
            }

            let input_arguments = address_space.find_node_by_browse_name(
                method.method_id(),
                Some((ReferenceTypeId::HasProperty, false)),
                &*type_tree,
                BrowseDirection::Forward,
                "InputArguments",
            );

            // If there are no input arguments, it means the method takes no inputs.
            let Some(input_arguments) = input_arguments else {
                if method.arguments().is_empty() {
                    valid.push(method);
                } else {
                    method.set_status(StatusCode::BadTooManyArguments);
                }
                continue;
            };

            // If the input arguments object is invalid, we pass it along anyway and leave it up to
            // the implementation to validate.
            let NodeType::Variable(arg_var) = &*input_arguments else {
                warn!(
                    "InputArguments for method with ID {} has incorrect node class",
                    method.method_id()
                );
                valid.push(method);
                continue;
            };

            let Some(Variant::Array(input_arguments_value)) = arg_var
                .value(
                    TimestampsToReturn::Neither,
                    &NumericRange::None,
                    &DataEncoding::Binary,
                    0.0,
                )
                .value
            else {
                warn!(
                    "InputArguments for method with ID {} has incorrect type",
                    method.method_id()
                );
                valid.push(method);
                continue;
            };

            let num_args = input_arguments_value.values.len();
            let arguments: Vec<_> = input_arguments_value
                .values
                .into_iter()
                .filter_map(|v| match v {
                    Variant::ExtensionObject(o) => o.into_inner_as::<Argument>(),
                    _ => None,
                })
                .collect();
            if arguments.len() != num_args {
                warn!(
                    "InputArguments for method with ID {} has invalid arguments",
                    method.method_id()
                );
                valid.push(method);
                continue;
            };

            if arguments.len() < method.arguments().len() {
                method.set_status(StatusCode::BadTooManyArguments);
                continue;
            }
            // Part 4 §5.12.2: fewer supplied arguments than the method declares is Bad_ArgumentsMissing.
            if arguments.len() > method.arguments().len() {
                method.set_status(StatusCode::BadArgumentsMissing);
                continue;
            }

            valid.push(method);
        }

        valid
    }
}

#[async_trait]
impl<TImpl: InMemoryNodeManagerImpl> NodeManagerCore for InMemoryNodeManager<TImpl> {
    fn owns_node(&self, id: &NodeId) -> bool {
        self.namespaces.contains_key(&id.namespace)
    }

    fn role_permissions(&self, node_id: &NodeId) -> Option<Vec<RolePermissionType>> {
        let address_space = trace_read_lock!(self.address_space);
        let node = address_space.find(node_id)?;
        node.as_node().role_permissions().map(<[_]>::to_vec)
    }

    fn name(&self) -> &str {
        self.inner.name()
    }

    #[allow(clippy::await_holding_lock)]
    async fn init(&self, type_tree: &mut DefaultTypeTree, context: ServerContext) {
        let info = Arc::clone(&context.info);

        // During init we effectively own the address space, so this should be safe.
        let mut address_space = trace_write_lock!(self.address_space);

        self.inner.init(&mut address_space, context).await;

        address_space.load_into_type_tree(type_tree);
        info.publish_type_tree_snapshot(type_tree);
    }

    fn namespaces_for_user(&self, _context: &RequestContext) -> Vec<NamespaceMetadata> {
        self.inner.namespaces()
    }

    fn handle_new_node(&self, parent_id: &ExpandedNodeId) -> bool {
        self.inner.handle_new_node(parent_id)
    }
}

#[async_trait]
impl<TImpl: InMemoryNodeManagerImpl> AttributeProvider for InMemoryNodeManager<TImpl> {
    async fn read(
        &self,
        context: &RequestContext,
        max_age: f64,
        timestamps_to_return: TimestampsToReturn,
        nodes_to_read: &mut [&mut ReadNode],
    ) -> Result<(), StatusCode> {
        let mut read_values = Vec::new();
        {
            let address_space = trace_read_lock!(self.address_space);
            for node in nodes_to_read {
                if node.node().attribute_id == AttributeId::Value {
                    read_values.push(node);
                    continue;
                }

                node.set_result(address_space.read(
                    context,
                    node.node(),
                    max_age,
                    timestamps_to_return,
                ));
            }
        }

        if !read_values.is_empty() {
            let ids: Vec<_> = read_values.iter().map(|r| r.node()).collect();
            let values = self
                .inner
                .read_values(
                    context,
                    &self.address_space,
                    &ids,
                    max_age,
                    timestamps_to_return,
                )
                .await;
            for (read, value) in read_values.iter_mut().zip(values) {
                read.set_result(value);
            }
        }

        Ok(())
    }

    async fn write(
        &self,
        context: &RequestContext,
        nodes_to_write: &mut [&mut WriteNode],
    ) -> Result<(), StatusCode> {
        self.inner
            .write(context, &self.address_space, nodes_to_write)
            .await
    }
}

#[async_trait]
impl<TImpl: InMemoryNodeManagerImpl> ViewProvider for InMemoryNodeManager<TImpl> {
    async fn resolve_external_references(
        &self,
        context: &RequestContext,
        items: &mut [&mut ExternalReferenceRequest],
    ) {
        let address_space = trace_read_lock!(self.address_space);
        let type_tree = trace_read_lock!(context.type_tree);

        for item in items {
            let target_node = address_space.find_node(item.node_id());

            let Some(target_node) = target_node else {
                continue;
            };

            if !Self::can_browse_target(context, &target_node) {
                continue;
            }

            item.set(Self::get_reference(
                &address_space,
                &type_tree,
                &target_node,
                item.result_mask(),
            ));
        }
    }

    async fn browse(
        &self,
        context: &RequestContext,
        nodes_to_browse: &mut [BrowseNode],
    ) -> Result<(), StatusCode> {
        let address_space = trace_read_lock!(self.address_space);
        let type_tree = trace_read_lock!(context.type_tree);

        for node in nodes_to_browse.iter_mut() {
            if node.node_id().is_null() {
                continue;
            }

            node.set_status(StatusCode::Good);

            if let Some(mut point) = node.take_continuation_point::<BrowseContinuationPoint>() {
                loop {
                    if node.remaining() == 0 {
                        break;
                    }
                    let Some(ref_desc) = point.nodes.pop_back() else {
                        break;
                    };
                    // Node is already filtered.
                    node.add_unchecked(ref_desc);
                }
                if !point.nodes.is_empty() {
                    node.set_next_continuation_point(point);
                }
            } else {
                Self::browse_node(&address_space, &type_tree, context, node, &self.namespaces);
            }
        }

        Ok(())
    }

    async fn translate_browse_paths_to_node_ids(
        &self,
        context: &RequestContext,
        nodes: &mut [&mut BrowsePathItem],
    ) -> Result<(), StatusCode> {
        let address_space = trace_read_lock!(self.address_space);
        let type_tree = trace_read_lock!(context.type_tree);

        for node in nodes {
            Self::translate_browse_paths(
                &address_space,
                &type_tree,
                context,
                &self.namespaces,
                node,
            );
        }

        Ok(())
    }

    async fn register_nodes(
        &self,
        context: &RequestContext,
        nodes: &mut [&mut RegisterNodeItem],
    ) -> Result<(), StatusCode> {
        self.inner
            .register_nodes(context, &self.address_space, nodes)
            .await
    }

    async fn unregister_nodes(
        &self,
        context: &RequestContext,
        nodes: &[&NodeId],
    ) -> Result<(), StatusCode> {
        self.inner
            .unregister_nodes(context, &self.address_space, nodes)
            .await
    }

    async fn query(
        &self,
        context: &RequestContext,
        request: &mut QueryRequest,
    ) -> Result<(), StatusCode> {
        let address_space = trace_read_lock!(self.address_space);
        let type_tree = context.get_type_tree_for_user();

        if request.continuation_point().is_some() {
            crate::services::query::handlers::QueryNextHandler::new(
                &address_space,
                type_tree.get(),
                context,
            )
            .execute(request)
        } else {
            crate::services::query::handlers::QueryFirstHandler::new(
                &address_space,
                type_tree.get(),
                context,
            )
            .execute(request)
        }
    }
}

#[async_trait]
impl<TImpl: InMemoryNodeManagerImpl> MonitoredItemProvider for InMemoryNodeManager<TImpl> {
    async fn create_monitored_items(
        &self,
        context: &RequestContext,
        items: &mut [&mut CreateMonitoredItem],
    ) -> Result<(), StatusCode> {
        let mut value_items = Vec::new();
        let mut event_items = Vec::new();

        {
            let address_space = trace_read_lock!(self.address_space);
            for node in items {
                if node.item_to_monitor().attribute_id == AttributeId::Value {
                    // Part 4 §5.13.2: a monitored item on an unknown node (or one the user is not
                    // allowed to read) must be rejected, not silently created. The value-item
                    // implementations below read the value but report Good regardless of the read
                    // status, so validate existence/access here before delegating.
                    match address_space.validate_node_read(context, node.item_to_monitor()) {
                        Ok(_) => value_items.push(node),
                        Err(e) => node.set_status(e),
                    }
                    continue;
                }

                let n = match address_space.validate_node_read(context, node.item_to_monitor()) {
                    Ok(n) => n,
                    Err(e) => {
                        node.set_status(e);
                        continue;
                    }
                };

                let read_result = read_node_value(
                    &n,
                    context,
                    node.item_to_monitor(),
                    0.0,
                    node.timestamps_to_return(),
                );

                // Event monitored items are global, so all we need to do is to validate that the
                // node allows subscribing to events.
                if node.item_to_monitor().attribute_id == AttributeId::EventNotifier {
                    let Some(Variant::Byte(notifier)) = &read_result.value else {
                        node.set_status(StatusCode::BadAttributeIdInvalid);
                        continue;
                    };
                    let notifier = EventNotifier::from_bits_truncate(*notifier);
                    if !notifier.contains(EventNotifier::SUBSCRIBE_TO_EVENTS) {
                        node.set_status(StatusCode::BadAttributeIdInvalid);
                        continue;
                    }

                    // No further action beyond just validation.
                    node.set_status(StatusCode::Good);
                    event_items.push(node);
                    continue;
                }

                // This specific status code here means that the value does not exist, so it is
                // more appropriate to not set an initial value.
                if read_result.status() != StatusCode::BadAttributeIdInvalid {
                    node.set_initial_value(read_result);
                }

                node.set_status(StatusCode::Good);
            }
        }

        if !value_items.is_empty() {
            self.inner
                .create_value_monitored_items(context, &self.address_space, &mut value_items)
                .await;
        }

        if !event_items.is_empty() {
            self.inner
                .create_event_monitored_items(context, &self.address_space, &mut event_items)
                .await;
        }

        Ok(())
    }

    async fn modify_monitored_items(
        &self,
        context: &RequestContext,
        items: &[&MonitoredItemUpdateRef],
    ) {
        let items: Vec<_> = items
            .iter()
            .filter(|it| {
                matches!(
                    it.attribute(),
                    AttributeId::Value | AttributeId::EventNotifier
                )
            })
            .copied()
            .collect();
        self.inner.modify_monitored_items(context, &items).await;
    }

    async fn set_monitoring_mode(
        &self,
        context: &RequestContext,
        mode: MonitoringMode,
        items: &[&MonitoredItemRef],
    ) {
        let items: Vec<_> = items
            .iter()
            .filter(|it| {
                matches!(
                    it.attribute(),
                    AttributeId::Value | AttributeId::EventNotifier
                )
            })
            .copied()
            .collect();
        self.inner.set_monitoring_mode(context, mode, &items).await;
    }

    async fn delete_monitored_items(&self, context: &RequestContext, items: &[&MonitoredItemRef]) {
        let items: Vec<_> = items
            .iter()
            .filter(|it| {
                matches!(
                    it.attribute(),
                    AttributeId::Value | AttributeId::EventNotifier
                )
            })
            .copied()
            .collect();
        self.inner.delete_monitored_items(context, &items).await;
    }
}

#[async_trait]
impl<TImpl: InMemoryNodeManagerImpl> HistoryProvider for InMemoryNodeManager<TImpl> {
    async fn history_read_raw_modified(
        &self,
        context: &RequestContext,
        details: &ReadRawModifiedDetails,
        nodes: &mut [&mut HistoryNode],
        timestamps_to_return: TimestampsToReturn,
    ) -> Result<(), StatusCode> {
        let mut nodes = self.validate_history_read_nodes(context, nodes, false);
        self.inner
            .history_read_raw_modified(context, details, &mut nodes, timestamps_to_return)
            .await
    }

    async fn history_read_processed(
        &self,
        context: &RequestContext,
        details: &ReadProcessedDetails,
        nodes: &mut [&mut HistoryNode],
        timestamps_to_return: TimestampsToReturn,
    ) -> Result<(), StatusCode> {
        let mut nodes = self.validate_history_read_nodes(context, nodes, false);
        self.inner
            .history_read_processed(
                context,
                &self.address_space,
                details,
                &mut nodes,
                timestamps_to_return,
            )
            .await
    }

    async fn history_read_at_time(
        &self,
        context: &RequestContext,
        details: &ReadAtTimeDetails,
        nodes: &mut [&mut HistoryNode],
        timestamps_to_return: TimestampsToReturn,
    ) -> Result<(), StatusCode> {
        let mut nodes = self.validate_history_read_nodes(context, nodes, false);
        self.inner
            .history_read_at_time(context, details, &mut nodes, timestamps_to_return)
            .await
    }

    async fn history_read_events(
        &self,
        context: &RequestContext,
        details: &ReadEventDetails,
        nodes: &mut [&mut HistoryNode],
        timestamps_to_return: TimestampsToReturn,
    ) -> Result<(), StatusCode> {
        let mut nodes = self.validate_history_read_nodes(context, nodes, true);
        self.inner
            .history_read_events(context, details, &mut nodes, timestamps_to_return)
            .await
    }

    async fn history_read_annotations(
        &self,
        context: &RequestContext,
        details: &ReadAnnotationDataDetails,
        nodes: &mut [&mut HistoryNode],
        timestamps_to_return: TimestampsToReturn,
    ) -> Result<(), StatusCode> {
        let mut nodes = self.validate_history_read_nodes(context, nodes, false);
        self.inner
            .history_read_annotations(context, details, &mut nodes, timestamps_to_return)
            .await
    }

    async fn history_release_continuation_point(
        &self,
        context: &RequestContext,
        node_id: &NodeId,
        continuation_point: &ContinuationPoint,
    ) -> Result<(), StatusCode> {
        self.inner
            .history_release_continuation_point(context, node_id, continuation_point)
            .await
    }

    async fn history_update(
        &self,
        context: &RequestContext,
        nodes: &mut [&mut HistoryUpdateNode],
    ) -> Result<(), StatusCode> {
        let mut nodes = self.validate_history_write_nodes(context, nodes);
        self.inner.history_update(context, &mut nodes).await
    }
}

#[async_trait]
impl<TImpl: InMemoryNodeManagerImpl> MethodProvider for InMemoryNodeManager<TImpl> {
    fn authorize_method_calls(
        &self,
        context: &RequestContext,
        methods_to_call: &mut [&mut MethodCall],
    ) -> Result<(), StatusCode> {
        let address_space = trace_read_lock!(self.address_space);
        let type_tree = trace_read_lock!(context.type_tree);

        for method in methods_to_call {
            if method.status() != StatusCode::BadMethodInvalid {
                continue;
            }

            let Some(method_node_id) =
                self.resolve_method_node_id(&address_space, &type_tree, method)
            else {
                continue;
            };

            let Some(method_ref_guard) = address_space.find(&method_node_id) else {
                continue;
            };

            let NodeType::Method(method_node) = &*method_ref_guard else {
                continue;
            };

            if method_node.executable() {
                if let Err(status) =
                    rbac::decision::access_restrictions_ok_ctx(context, &method_ref_guard)
                {
                    method.set_status(status);
                    continue;
                }

                if !rbac::decision::authorize_ctx(context, &method_ref_guard, PermissionType::Call)
                {
                    method.set_status(StatusCode::BadUserAccessDenied);
                }
            }
        }

        Ok(())
    }

    async fn call(
        &self,
        context: &RequestContext,
        methods_to_call: &mut [&mut MethodCall],
    ) -> Result<(), StatusCode> {
        let mut to_call = self.validate_method_calls(context, methods_to_call);
        self.inner
            .call(context, &self.address_space, &mut to_call)
            .await
    }
}

#[async_trait]
impl<TImpl: InMemoryNodeManagerImpl> NodeMutator for InMemoryNodeManager<TImpl> {
    /// Add a list of nodes.
    ///
    /// This should create the nodes, or set a failed status as appropriate.
    /// If a node was created, the status should be set to Good.
    async fn add_nodes(
        &self,
        context: &RequestContext,
        nodes_to_add: &mut [&mut AddNodeItem],
    ) -> Result<(), StatusCode> {
        self.inner
            .add_nodes(context, &self.address_space, nodes_to_add)
            .await
    }

    async fn add_references(
        &self,
        context: &RequestContext,
        references_to_add: &mut [&mut AddReferenceItem],
    ) -> Result<(), StatusCode> {
        self.inner
            .add_references(context, &self.address_space, references_to_add)
            .await
    }

    async fn delete_nodes(
        &self,
        context: &RequestContext,
        nodes_to_delete: &mut [&mut DeleteNodeItem],
    ) -> Result<(), StatusCode> {
        self.inner
            .delete_nodes(context, &self.address_space, nodes_to_delete)
            .await
    }

    async fn delete_node_references(
        &self,
        context: &RequestContext,
        to_delete: &[&DeleteNodeItem],
    ) {
        self.inner
            .delete_node_references(context, &self.address_space, to_delete)
            .await
    }

    async fn delete_references(
        &self,
        context: &RequestContext,
        references_to_delete: &mut [&mut DeleteReferenceItem],
    ) -> Result<(), StatusCode> {
        self.inner
            .delete_references(context, &self.address_space, references_to_delete)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use opcua_core::sync::RwLock;
    use opcua_nodes::{Method, NodeBase, Object, Variable};
    use opcua_types::{
        AccessRestrictionType, AddNodeAttributes, AddNodesItem, AddReferencesItem,
        AnonymousIdentityToken, ApplicationDescription, BrowseDescription, BrowseResult,
        ByteString, CallMethodRequest, DateTime, DeleteAtTimeDetails, DeleteEventDetails,
        DeleteNodesItem, DeleteReferencesItem, DiagnosticBits, EventFilter, ExpandedNodeId,
        HistoryReadValueId, LocalizedText, MessageSecurityMode, NodeClass, NodeClassMask,
        ObjectAttributes, ObjectTypeId, PerformUpdateType, PermissionType, QualifiedName,
        RolePermissionType, UAString, UpdateDataDetails, UpdateEventDetails,
        UpdateStructureDataDetails,
    };

    use crate::{
        authenticator::UserToken, identity_token::IdentityToken, node_manager::RequestContextInner,
        session::instance::Session, ServerBuilder,
    };

    use super::*;

    struct TestMethodImpl {
        method_ids: Vec<NodeId>,
    }

    #[async_trait]
    impl InMemoryNodeManagerImpl for TestMethodImpl {
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

        fn method_callback(&self, method_id: &NodeId) -> Option<InMemoryMethodCallback> {
            if self.method_ids.iter().any(|id| id == method_id) {
                Some(Arc::new(|_, _| Ok(Vec::new())))
            } else {
                None
            }
        }
    }

    fn request_context_enforced() -> RequestContext {
        request_context_with_roles_enforced(Vec::new())
    }

    fn request_context_with_roles_enforced(user_roles: Vec<NodeId>) -> RequestContext {
        request_context_with_roles_and_security_mode_enforced(user_roles, MessageSecurityMode::None)
    }

    fn request_context_with_roles_and_security_mode_enforced(
        user_roles: Vec<NodeId>,
        security_mode: MessageSecurityMode,
    ) -> RequestContext {
        request_context_with_options(user_roles, security_mode, false, true)
    }

    fn request_context_with_roles_and_address_space_modification_enforced(
        user_roles: Vec<NodeId>,
    ) -> RequestContext {
        request_context_with_options(user_roles, MessageSecurityMode::None, true, true)
    }

    fn request_context_with_options(
        user_roles: Vec<NodeId>,
        security_mode: MessageSecurityMode,
        clients_can_modify_address_space: bool,
        enforce_role_based_access: bool,
    ) -> RequestContext {
        let mut builder = ServerBuilder::new_anonymous("test")
            .enforce_role_based_access(enforce_role_based_access);
        builder.config_mut().limits.clients_can_modify_address_space =
            clients_can_modify_address_space;
        let (_server, handle) = builder.build().expect("test server should build");
        let info = handle.info().clone();
        {
            let mut type_tree = info.type_tree.write();
            type_tree.add_type_node(
                &NodeId::from(ReferenceTypeId::HasComponent),
                &NodeId::from(ReferenceTypeId::References),
                NodeClass::ReferenceType,
            );
        }
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
            security_mode,
        );

        let session = Arc::new(RwLock::new(session));
        let user_roles = Arc::new(user_roles);

        RequestContext {
            current_node_manager_index: 0,
            inner: Arc::new(RequestContextInner {
                session,
                session_id: 1,
                authenticator: info.authenticator.clone(),
                token: UserToken("anonymous".to_string()),
                user_roles,
                type_tree: info.type_tree.clone(),
                type_tree_getter: info.type_tree_getter.clone(),
                subscriptions: handle.subscriptions().clone(),
                info,
            }),
        }
    }

    fn role_permission(role_id: &NodeId, permissions: PermissionType) -> RolePermissionType {
        RolePermissionType {
            role_id: role_id.clone(),
            permissions,
        }
    }

    fn object_node(
        node_id: &NodeId,
        browse_name: &'static str,
        role_permissions: Option<Vec<RolePermissionType>>,
    ) -> Object {
        let mut object = Object::new(node_id, browse_name, browse_name, EventNotifier::empty());
        if let Some(role_permissions) = role_permissions {
            object.set_role_permissions(role_permissions);
        }
        object
    }

    fn node_management_manager(nodes: Vec<NodeType>) -> InMemoryNodeManager<TestMethodImpl> {
        let mut address_space = AddressSpace::new();
        address_space.add_namespace("urn:test", 1);
        for node in nodes {
            address_space.insert::<_, NodeId>(node, None);
        }

        InMemoryNodeManager::new(
            TestMethodImpl {
                method_ids: Vec::new(),
            },
            address_space,
        )
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

    fn add_object_node_item(parent_id: &NodeId, new_node_id: &NodeId) -> AddNodeItem {
        AddNodeItem::new(
            AddNodesItem {
                parent_node_id: ExpandedNodeId::from(parent_id),
                reference_type_id: NodeId::from(ReferenceTypeId::HasComponent),
                requested_new_node_id: ExpandedNodeId::from(new_node_id),
                browse_name: QualifiedName::new(1, "new_object"),
                node_class: NodeClass::Object,
                node_attributes: AddNodeAttributes::Object(object_attributes())
                    .as_extension_object(),
                type_definition: ExpandedNodeId::from(NodeId::from(ObjectTypeId::BaseObjectType)),
            },
            DiagnosticBits::empty(),
        )
    }

    fn delete_node_item(node_id: &NodeId) -> DeleteNodeItem {
        DeleteNodeItem::new(
            DeleteNodesItem {
                node_id: node_id.clone(),
                delete_target_references: false,
            },
            DiagnosticBits::empty(),
        )
    }

    fn add_reference_item(source_id: &NodeId, target_id: &NodeId) -> AddReferenceItem {
        AddReferenceItem::new(
            AddReferencesItem {
                source_node_id: source_id.clone(),
                reference_type_id: NodeId::from(ReferenceTypeId::HasComponent),
                is_forward: true,
                target_server_uri: UAString::null(),
                target_node_id: ExpandedNodeId::from(target_id),
                target_node_class: NodeClass::Object,
            },
            DiagnosticBits::empty(),
        )
    }

    fn delete_reference_item(source_id: &NodeId, target_id: &NodeId) -> DeleteReferenceItem {
        DeleteReferenceItem::new(
            DeleteReferencesItem {
                source_node_id: source_id.clone(),
                reference_type_id: NodeId::from(ReferenceTypeId::HasComponent),
                is_forward: true,
                target_node_id: ExpandedNodeId::from(target_id),
                delete_bidirectional: false,
            },
            DiagnosticBits::empty(),
        )
    }

    fn history_variable(
        node_id: &NodeId,
        role_permissions: Option<Vec<RolePermissionType>>,
    ) -> Variable {
        let mut variable = Variable::new(node_id, "history", "history", 0i32);
        let history_access = AccessLevel::CURRENT_READ
            | AccessLevel::CURRENT_WRITE
            | AccessLevel::HISTORY_READ
            | AccessLevel::HISTORY_WRITE;
        variable.set_historizing(true);
        variable.set_access_level(history_access);
        variable.set_user_access_level(history_access);
        if let Some(role_permissions) = role_permissions {
            variable.set_role_permissions(role_permissions);
        }
        variable
    }

    fn history_event_object(
        node_id: &NodeId,
        role_permissions: Option<Vec<RolePermissionType>>,
    ) -> Object {
        let mut object = Object::new(
            node_id,
            "events",
            "events",
            EventNotifier::HISTORY_READ | EventNotifier::HISTORY_WRITE,
        );
        if let Some(role_permissions) = role_permissions {
            object.set_role_permissions(role_permissions);
        }
        object
    }

    fn history_manager(nodes: Vec<NodeType>) -> InMemoryNodeManager<TestMethodImpl> {
        let mut address_space = AddressSpace::new();
        address_space.add_namespace("urn:test", 1);
        for node in nodes {
            address_space.insert::<_, NodeId>(node, None);
        }

        InMemoryNodeManager::new(
            TestMethodImpl {
                method_ids: Vec::new(),
            },
            address_space,
        )
    }

    fn history_read_node(node_id: &NodeId, is_events: bool) -> HistoryNode {
        HistoryNode::new(
            HistoryReadValueId {
                node_id: node_id.clone(),
                index_range: NumericRange::None,
                data_encoding: QualifiedName::null(),
                continuation_point: ByteString::null(),
            },
            is_events,
            None,
        )
    }

    fn update_data_node(node_id: &NodeId, mode: PerformUpdateType) -> HistoryUpdateNode {
        HistoryUpdateNode::new(HistoryUpdateDetails::UpdateData(UpdateDataDetails {
            node_id: node_id.clone(),
            perform_insert_replace: mode,
            update_values: None,
        }))
    }

    fn update_event_node(node_id: &NodeId, mode: PerformUpdateType) -> HistoryUpdateNode {
        HistoryUpdateNode::new(HistoryUpdateDetails::UpdateEvent(UpdateEventDetails {
            node_id: node_id.clone(),
            perform_insert_replace: mode,
            filter: EventFilter::default(),
            event_data: None,
        }))
    }

    fn update_structure_node(node_id: &NodeId, mode: PerformUpdateType) -> HistoryUpdateNode {
        HistoryUpdateNode::new(HistoryUpdateDetails::UpdateStructureData(
            UpdateStructureDataDetails {
                node_id: node_id.clone(),
                perform_insert_replace: mode,
                update_values: None,
            },
        ))
    }

    fn delete_at_time_node(node_id: &NodeId) -> HistoryUpdateNode {
        HistoryUpdateNode::new(HistoryUpdateDetails::DeleteAtTime(DeleteAtTimeDetails {
            node_id: node_id.clone(),
            req_times: Some(vec![DateTime::null()]),
        }))
    }

    fn delete_event_node(node_id: &NodeId) -> HistoryUpdateNode {
        HistoryUpdateNode::new(HistoryUpdateDetails::DeleteEvent(DeleteEventDetails {
            node_id: node_id.clone(),
            event_ids: None,
        }))
    }

    fn validated_history_read_len(
        manager: &InMemoryNodeManager<TestMethodImpl>,
        context: &RequestContext,
        nodes: &mut [&mut HistoryNode],
        is_for_events: bool,
    ) -> usize {
        manager
            .validate_history_read_nodes(context, nodes, is_for_events)
            .len()
    }

    fn validated_history_update_len(
        manager: &InMemoryNodeManager<TestMethodImpl>,
        context: &RequestContext,
        nodes: &mut [&mut HistoryUpdateNode],
    ) -> usize {
        manager.validate_history_write_nodes(context, nodes).len()
    }

    fn method_call(object_id: &NodeId, method_id: &NodeId) -> MethodCall {
        MethodCall::new(
            CallMethodRequest {
                object_id: object_id.clone(),
                method_id: method_id.clone(),
                input_arguments: None,
            },
            DiagnosticBits::empty(),
        )
    }

    fn method_manager(
        object_id: &NodeId,
        methods: Vec<(NodeId, Option<Vec<RolePermissionType>>)>,
    ) -> InMemoryNodeManager<TestMethodImpl> {
        method_manager_with_access_restrictions(
            object_id,
            methods
                .into_iter()
                .map(|(method_id, role_permissions)| (method_id, role_permissions, None))
                .collect(),
        )
    }

    fn method_manager_with_access_restrictions(
        object_id: &NodeId,
        methods: Vec<(
            NodeId,
            Option<Vec<RolePermissionType>>,
            Option<AccessRestrictionType>,
        )>,
    ) -> InMemoryNodeManager<TestMethodImpl> {
        let mut address_space = AddressSpace::new();
        address_space.add_namespace("urn:test", 1);
        address_space.insert::<_, NodeId>(
            Object::new(object_id, "object", "object", EventNotifier::empty()),
            None,
        );

        let method_ids = methods
            .iter()
            .map(|(method_id, _, _)| method_id.clone())
            .collect::<Vec<_>>();

        for (method_id, role_permissions, access_restrictions) in methods {
            let mut method = Method::new(&method_id, "method", "method", true, true);
            if let Some(role_permissions) = role_permissions {
                method.set_role_permissions(role_permissions);
            }
            if let Some(access_restrictions) = access_restrictions {
                method.set_access_restrictions(access_restrictions);
            }
            address_space.insert::<_, NodeId>(method, None);
            address_space.insert_reference(object_id, &method_id, ReferenceTypeId::HasComponent);
        }

        InMemoryNodeManager::new(TestMethodImpl { method_ids }, address_space)
    }

    #[allow(clippy::type_complexity)]
    fn browse_manager(
        parent_id: &NodeId,
        children: Vec<(
            NodeId,
            &'static str,
            Option<Vec<RolePermissionType>>,
            Option<AccessRestrictionType>,
        )>,
    ) -> InMemoryNodeManager<TestMethodImpl> {
        let mut address_space = AddressSpace::new();
        address_space.add_namespace("urn:test", 1);
        address_space.insert::<_, NodeId>(
            Object::new(parent_id, "parent", "parent", EventNotifier::empty()),
            None,
        );

        for (child_id, browse_name, role_permissions, access_restrictions) in children {
            let mut child =
                Object::new(&child_id, browse_name, browse_name, EventNotifier::empty());
            if let Some(role_permissions) = role_permissions {
                child.set_role_permissions(role_permissions);
            }
            if let Some(access_restrictions) = access_restrictions {
                child.set_access_restrictions(access_restrictions);
            }
            address_space.insert::<_, NodeId>(child, None);
            address_space.insert_reference(parent_id, &child_id, ReferenceTypeId::HasComponent);
        }

        InMemoryNodeManager::new(
            TestMethodImpl {
                method_ids: Vec::new(),
            },
            address_space,
        )
    }

    async fn browse_node(
        manager: &InMemoryNodeManager<TestMethodImpl>,
        context: &RequestContext,
        node_id: &NodeId,
        browse_direction: BrowseDirection,
    ) -> BrowseResult {
        let mut node = BrowseNode::new(
            BrowseDescription {
                node_id: node_id.clone(),
                browse_direction,
                reference_type_id: NodeId::from(ReferenceTypeId::HasComponent),
                include_subtypes: false,
                node_class_mask: NodeClassMask::OBJECT.bits(),
                result_mask: BrowseDescriptionResultMask::RESULT_MASK_BROWSE_NAME.bits(),
            },
            100,
            0,
        );

        manager
            .browse(context, std::slice::from_mut(&mut node))
            .await
            .expect("browse should not fail the service");

        let mut session = context.session.write();
        node.into_result(0, 1, &mut session).0
    }

    fn browsed_node_ids(result: &BrowseResult) -> Vec<NodeId> {
        result
            .references
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|reference| reference.node_id.node_id.clone())
            .collect()
    }

    #[tokio::test]
    async fn add_nodes_denies_configured_parent_without_add_node_permission_per_operation() {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles_and_address_space_modification_enforced(vec![
            operator.clone(),
        ]);
        let denied_parent_id = NodeId::new(1, "denied_parent");
        let open_parent_id = NodeId::new(1, "open_parent");
        let denied_new_id = NodeId::new(1, "denied_new");
        let open_new_id = NodeId::new(1, "open_new");
        let manager = node_management_manager(vec![
            NodeType::Object(Box::new(object_node(
                &denied_parent_id,
                "denied_parent",
                Some(vec![role_permission(&operator, PermissionType::DeleteNode)]),
            ))),
            NodeType::Object(Box::new(object_node(
                &open_parent_id,
                "open_parent",
                Some(vec![role_permission(&operator, PermissionType::AddNode)]),
            ))),
        ]);
        let mut denied = add_object_node_item(&denied_parent_id, &denied_new_id);
        let mut open = add_object_node_item(&open_parent_id, &open_new_id);

        {
            let mut nodes = vec![&mut denied, &mut open];
            manager
                .add_nodes(&context, nodes.as_mut_slice())
                .await
                .unwrap();
        }

        assert_eq!(denied.status(), StatusCode::BadUserAccessDenied);
        assert_eq!(open.status(), StatusCode::Good);
        let address_space = manager.address_space.read();
        assert!(!address_space.node_exists(&denied_new_id));
        assert!(address_space.node_exists(&open_new_id));
    }

    #[tokio::test]
    async fn delete_nodes_denies_configured_node_without_delete_node_permission_per_operation() {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles_and_address_space_modification_enforced(vec![
            operator.clone(),
        ]);
        let denied_id = NodeId::new(1, "delete_denied");
        let open_id = NodeId::new(1, "delete_open");
        let manager = node_management_manager(vec![
            NodeType::Object(Box::new(object_node(
                &denied_id,
                "delete_denied",
                Some(vec![role_permission(&operator, PermissionType::AddNode)]),
            ))),
            NodeType::Object(Box::new(object_node(
                &open_id,
                "delete_open",
                Some(vec![role_permission(&operator, PermissionType::DeleteNode)]),
            ))),
        ]);
        let mut denied = delete_node_item(&denied_id);
        let mut open = delete_node_item(&open_id);

        {
            let mut nodes = vec![&mut denied, &mut open];
            manager
                .delete_nodes(&context, nodes.as_mut_slice())
                .await
                .unwrap();
        }

        assert_eq!(denied.status(), StatusCode::BadUserAccessDenied);
        assert_eq!(open.status(), StatusCode::Good);
        let address_space = manager.address_space.read();
        assert!(address_space.node_exists(&denied_id));
        assert!(!address_space.node_exists(&open_id));
    }

    #[tokio::test]
    async fn add_references_denies_configured_source_without_add_reference_permission_per_operation(
    ) {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles_and_address_space_modification_enforced(vec![
            operator.clone(),
        ]);
        let denied_source_id = NodeId::new(1, "add_reference_denied_source");
        let denied_target_id = NodeId::new(1, "add_reference_denied_target");
        let open_source_id = NodeId::new(1, "add_reference_open_source");
        let open_target_id = NodeId::new(1, "add_reference_open_target");
        let manager = node_management_manager(vec![
            NodeType::Object(Box::new(object_node(
                &denied_source_id,
                "add_reference_denied_source",
                Some(vec![role_permission(
                    &operator,
                    PermissionType::RemoveReference,
                )]),
            ))),
            NodeType::Object(Box::new(object_node(
                &denied_target_id,
                "add_reference_denied_target",
                None,
            ))),
            NodeType::Object(Box::new(object_node(
                &open_source_id,
                "add_reference_open_source",
                Some(vec![role_permission(
                    &operator,
                    PermissionType::AddReference,
                )]),
            ))),
            NodeType::Object(Box::new(object_node(
                &open_target_id,
                "add_reference_open_target",
                None,
            ))),
        ]);
        let mut denied = add_reference_item(&denied_source_id, &denied_target_id);
        let mut open = add_reference_item(&open_source_id, &open_target_id);

        {
            let mut references = vec![&mut denied, &mut open];
            manager
                .add_references(&context, references.as_mut_slice())
                .await
                .unwrap();
        }

        assert_eq!(denied.result_status(), StatusCode::BadUserAccessDenied);
        assert_eq!(open.result_status(), StatusCode::Good);
        let address_space = manager.address_space.read();
        assert!(!address_space.has_reference(
            &denied_source_id,
            &denied_target_id,
            &NodeId::from(ReferenceTypeId::HasComponent),
        ));
        assert!(address_space.has_reference(
            &open_source_id,
            &open_target_id,
            &NodeId::from(ReferenceTypeId::HasComponent),
        ));
    }

    #[tokio::test]
    async fn delete_references_denies_configured_source_without_remove_reference_permission_per_operation(
    ) {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles_and_address_space_modification_enforced(vec![
            operator.clone(),
        ]);
        let denied_source_id = NodeId::new(1, "delete_reference_denied_source");
        let denied_target_id = NodeId::new(1, "delete_reference_denied_target");
        let open_source_id = NodeId::new(1, "delete_reference_open_source");
        let open_target_id = NodeId::new(1, "delete_reference_open_target");
        let manager = node_management_manager(vec![
            NodeType::Object(Box::new(object_node(
                &denied_source_id,
                "delete_reference_denied_source",
                Some(vec![role_permission(
                    &operator,
                    PermissionType::AddReference,
                )]),
            ))),
            NodeType::Object(Box::new(object_node(
                &denied_target_id,
                "delete_reference_denied_target",
                None,
            ))),
            NodeType::Object(Box::new(object_node(
                &open_source_id,
                "delete_reference_open_source",
                Some(vec![role_permission(
                    &operator,
                    PermissionType::RemoveReference,
                )]),
            ))),
            NodeType::Object(Box::new(object_node(
                &open_target_id,
                "delete_reference_open_target",
                None,
            ))),
        ]);
        {
            let mut address_space = manager.address_space.write();
            address_space.insert_reference(
                &denied_source_id,
                &denied_target_id,
                ReferenceTypeId::HasComponent,
            );
            address_space.insert_reference(
                &open_source_id,
                &open_target_id,
                ReferenceTypeId::HasComponent,
            );
        }
        let mut denied = delete_reference_item(&denied_source_id, &denied_target_id);
        let mut open = delete_reference_item(&open_source_id, &open_target_id);

        {
            let mut references = vec![&mut denied, &mut open];
            manager
                .delete_references(&context, references.as_mut_slice())
                .await
                .unwrap();
        }

        assert_eq!(denied.result_status(), StatusCode::BadUserAccessDenied);
        assert_eq!(open.result_status(), StatusCode::Good);
        let address_space = manager.address_space.read();
        assert!(address_space.has_reference(
            &denied_source_id,
            &denied_target_id,
            &NodeId::from(ReferenceTypeId::HasComponent),
        ));
        assert!(!address_space.has_reference(
            &open_source_id,
            &open_target_id,
            &NodeId::from(ReferenceTypeId::HasComponent),
        ));
    }

    #[tokio::test]
    async fn browse_omits_forward_target_without_browse_permission() {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles_enforced(vec![operator.clone()]);
        let parent_id = NodeId::new(1, "parent");
        let visible_id = NodeId::new(1, "visible");
        let denied_id = NodeId::new(1, "denied");
        let manager = browse_manager(
            &parent_id,
            vec![
                (
                    visible_id.clone(),
                    "visible",
                    Some(vec![role_permission(&operator, PermissionType::Browse)]),
                    None,
                ),
                (
                    denied_id.clone(),
                    "denied",
                    Some(vec![role_permission(&operator, PermissionType::Read)]),
                    None,
                ),
            ],
        );

        let node = browse_node(&manager, &context, &parent_id, BrowseDirection::Forward).await;
        let refs = browsed_node_ids(&node);

        assert_eq!(node.status_code, StatusCode::Good);
        assert_eq!(refs, vec![visible_id]);
    }

    #[tokio::test]
    async fn browse_omits_inverse_target_without_browse_permission() {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles_enforced(vec![operator.clone()]);
        let parent_id = NodeId::new(1, "parent");
        let child_id = NodeId::new(1, "child");
        let manager = browse_manager(&parent_id, vec![(child_id.clone(), "child", None, None)]);
        {
            let address_space = manager.address_space.write();
            let mut parent = address_space
                .find_mut(&parent_id)
                .expect("parent should exist");
            parent
                .as_mut_node()
                .set_role_permissions(vec![role_permission(&operator, PermissionType::Read)]);
        }

        let node = browse_node(&manager, &context, &child_id, BrowseDirection::Inverse).await;

        assert_eq!(node.status_code, StatusCode::Good);
        assert!(browsed_node_ids(&node).is_empty());
    }

    #[tokio::test]
    async fn browse_keeps_access_restricted_target_when_apply_to_browse_is_unset() {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles_enforced(vec![operator.clone()]);
        let parent_id = NodeId::new(1, "parent");
        let child_id = NodeId::new(1, "encrypted");
        let manager = browse_manager(
            &parent_id,
            vec![(
                child_id.clone(),
                "encrypted",
                Some(vec![role_permission(&operator, PermissionType::Browse)]),
                Some(AccessRestrictionType::EncryptionRequired),
            )],
        );

        let node = browse_node(&manager, &context, &parent_id, BrowseDirection::Forward).await;
        let refs = browsed_node_ids(&node);

        assert_eq!(node.status_code, StatusCode::Good);
        assert_eq!(refs, vec![child_id]);
    }

    #[tokio::test]
    async fn browse_omits_target_when_apply_to_browse_security_is_not_met() {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles_enforced(vec![operator.clone()]);
        let parent_id = NodeId::new(1, "parent");
        let child_id = NodeId::new(1, "encrypted");
        let manager = browse_manager(
            &parent_id,
            vec![(
                child_id,
                "encrypted",
                Some(vec![role_permission(&operator, PermissionType::Browse)]),
                Some(
                    AccessRestrictionType::EncryptionRequired
                        | AccessRestrictionType::ApplyRestrictionsToBrowse,
                ),
            )],
        );

        let node = browse_node(&manager, &context, &parent_id, BrowseDirection::Forward).await;

        assert_eq!(node.status_code, StatusCode::Good);
        assert!(browsed_node_ids(&node).is_empty());
    }

    #[tokio::test]
    async fn browse_keeps_apply_to_browse_target_when_security_is_met() {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles_and_security_mode_enforced(
            vec![operator.clone()],
            MessageSecurityMode::SignAndEncrypt,
        );
        let parent_id = NodeId::new(1, "parent");
        let child_id = NodeId::new(1, "encrypted");
        let manager = browse_manager(
            &parent_id,
            vec![(
                child_id.clone(),
                "encrypted",
                Some(vec![role_permission(&operator, PermissionType::Browse)]),
                Some(
                    AccessRestrictionType::EncryptionRequired
                        | AccessRestrictionType::ApplyRestrictionsToBrowse,
                ),
            )],
        );

        let node = browse_node(&manager, &context, &parent_id, BrowseDirection::Forward).await;
        let refs = browsed_node_ids(&node);

        assert_eq!(node.status_code, StatusCode::Good);
        assert_eq!(refs, vec![child_id]);
    }

    #[tokio::test]
    async fn history_read_denies_configured_variable_without_read_history_permission() {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles_enforced(vec![operator.clone()]);
        let denied_id = NodeId::new(1, "denied_history");
        let open_id = NodeId::new(1, "open_history");
        let manager = history_manager(vec![
            NodeType::Variable(Box::new(history_variable(
                &denied_id,
                Some(vec![role_permission(&operator, PermissionType::Read)]),
            ))),
            NodeType::Variable(Box::new(history_variable(
                &open_id,
                Some(vec![role_permission(
                    &operator,
                    PermissionType::ReadHistory,
                )]),
            ))),
        ]);
        let mut denied = history_read_node(&denied_id, false);
        let mut open = history_read_node(&open_id, false);

        let valid_len = {
            let mut nodes = vec![&mut denied, &mut open];
            validated_history_read_len(&manager, &context, nodes.as_mut_slice(), false)
        };

        assert_eq!(valid_len, 1);
        assert_eq!(denied.status(), StatusCode::BadUserAccessDenied);
        assert_eq!(open.status(), StatusCode::BadNodeIdUnknown);
    }

    #[tokio::test]
    async fn history_read_allows_variable_with_read_history_permission() {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles_enforced(vec![operator.clone()]);
        let node_id = NodeId::new(1, "readable_history");
        let manager = history_manager(vec![NodeType::Variable(Box::new(history_variable(
            &node_id,
            Some(vec![role_permission(
                &operator,
                PermissionType::ReadHistory,
            )]),
        )))]);
        let mut history_node = history_read_node(&node_id, false);

        let valid_len = {
            let mut nodes = vec![&mut history_node];
            validated_history_read_len(&manager, &context, nodes.as_mut_slice(), false)
        };

        assert_eq!(valid_len, 1);
        assert_eq!(history_node.status(), StatusCode::BadNodeIdUnknown);
    }

    #[tokio::test]
    async fn history_read_denies_configured_event_source_without_read_history_permission() {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles_enforced(vec![operator.clone()]);
        let node_id = NodeId::new(1, "event_history");
        let manager = history_manager(vec![NodeType::Object(Box::new(history_event_object(
            &node_id,
            Some(vec![role_permission(
                &operator,
                PermissionType::ReceiveEvents,
            )]),
        )))]);
        let mut history_node = history_read_node(&node_id, true);

        let valid_len = {
            let mut nodes = vec![&mut history_node];
            validated_history_read_len(&manager, &context, nodes.as_mut_slice(), true)
        };

        assert_eq!(valid_len, 0);
        assert_eq!(history_node.status(), StatusCode::BadUserAccessDenied);
    }

    #[tokio::test]
    async fn history_update_insert_data_requires_insert_history_permission() {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles_enforced(vec![operator.clone()]);
        let node_id = NodeId::new(1, "insert_history");
        let manager = history_manager(vec![NodeType::Variable(Box::new(history_variable(
            &node_id,
            Some(vec![role_permission(
                &operator,
                PermissionType::ModifyHistory,
            )]),
        )))]);
        let mut update = update_data_node(&node_id, PerformUpdateType::Insert);

        let denied_len = {
            let mut nodes = vec![&mut update];
            validated_history_update_len(&manager, &context, nodes.as_mut_slice())
        };

        assert_eq!(denied_len, 0);
        assert_eq!(update.status(), StatusCode::BadUserAccessDenied);

        {
            let address_space = manager.address_space.write();
            let mut node = address_space
                .find_mut(&node_id)
                .expect("history node should exist");
            node.as_mut_node()
                .set_role_permissions(vec![role_permission(
                    &operator,
                    PermissionType::InsertHistory,
                )]);
        }

        let mut update = update_data_node(&node_id, PerformUpdateType::Insert);
        let allowed_len = {
            let mut nodes = vec![&mut update];
            validated_history_update_len(&manager, &context, nodes.as_mut_slice())
        };

        assert_eq!(allowed_len, 1);
        assert_eq!(update.status(), StatusCode::BadNodeIdUnknown);
    }

    #[tokio::test]
    async fn history_update_replace_data_requires_modify_history_permission() {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles_enforced(vec![operator.clone()]);
        let node_id = NodeId::new(1, "replace_history");
        let manager = history_manager(vec![NodeType::Variable(Box::new(history_variable(
            &node_id,
            Some(vec![role_permission(
                &operator,
                PermissionType::InsertHistory,
            )]),
        )))]);
        let mut update = update_data_node(&node_id, PerformUpdateType::Replace);

        let denied_len = {
            let mut nodes = vec![&mut update];
            validated_history_update_len(&manager, &context, nodes.as_mut_slice())
        };

        assert_eq!(denied_len, 0);
        assert_eq!(update.status(), StatusCode::BadUserAccessDenied);

        {
            let address_space = manager.address_space.write();
            let mut node = address_space
                .find_mut(&node_id)
                .expect("history node should exist");
            node.as_mut_node()
                .set_role_permissions(vec![role_permission(
                    &operator,
                    PermissionType::ModifyHistory,
                )]);
        }

        let mut update = update_data_node(&node_id, PerformUpdateType::Replace);
        let allowed_len = {
            let mut nodes = vec![&mut update];
            validated_history_update_len(&manager, &context, nodes.as_mut_slice())
        };

        assert_eq!(allowed_len, 1);
        assert_eq!(update.status(), StatusCode::BadNodeIdUnknown);
    }

    #[tokio::test]
    async fn history_update_structure_data_requires_modify_history_permission() {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles_enforced(vec![operator.clone()]);
        let node_id = NodeId::new(1, "structure_history");
        let manager = history_manager(vec![NodeType::Variable(Box::new(history_variable(
            &node_id,
            Some(vec![role_permission(
                &operator,
                PermissionType::InsertHistory,
            )]),
        )))]);
        let mut update = update_structure_node(&node_id, PerformUpdateType::Insert);

        let denied_len = {
            let mut nodes = vec![&mut update];
            validated_history_update_len(&manager, &context, nodes.as_mut_slice())
        };

        assert_eq!(denied_len, 0);
        assert_eq!(update.status(), StatusCode::BadUserAccessDenied);

        {
            let address_space = manager.address_space.write();
            let mut node = address_space
                .find_mut(&node_id)
                .expect("history node should exist");
            node.as_mut_node()
                .set_role_permissions(vec![role_permission(
                    &operator,
                    PermissionType::ModifyHistory,
                )]);
        }

        let mut update = update_structure_node(&node_id, PerformUpdateType::Insert);
        let allowed_len = {
            let mut nodes = vec![&mut update];
            validated_history_update_len(&manager, &context, nodes.as_mut_slice())
        };

        assert_eq!(allowed_len, 1);
        assert_eq!(update.status(), StatusCode::BadNodeIdUnknown);
    }

    #[tokio::test]
    async fn history_update_delete_details_require_delete_history_permission() {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles_enforced(vec![operator.clone()]);
        let node_id = NodeId::new(1, "delete_history");
        let manager = history_manager(vec![NodeType::Variable(Box::new(history_variable(
            &node_id,
            Some(vec![role_permission(
                &operator,
                PermissionType::ModifyHistory,
            )]),
        )))]);
        let mut update = delete_at_time_node(&node_id);

        let denied_len = {
            let mut nodes = vec![&mut update];
            validated_history_update_len(&manager, &context, nodes.as_mut_slice())
        };

        assert_eq!(denied_len, 0);
        assert_eq!(update.status(), StatusCode::BadUserAccessDenied);

        {
            let address_space = manager.address_space.write();
            let mut node = address_space
                .find_mut(&node_id)
                .expect("history node should exist");
            node.as_mut_node()
                .set_role_permissions(vec![role_permission(
                    &operator,
                    PermissionType::DeleteHistory,
                )]);
        }

        let mut update = delete_at_time_node(&node_id);
        let allowed_len = {
            let mut nodes = vec![&mut update];
            validated_history_update_len(&manager, &context, nodes.as_mut_slice())
        };

        assert_eq!(allowed_len, 1);
        assert_eq!(update.status(), StatusCode::BadNodeIdUnknown);
    }

    #[tokio::test]
    async fn history_update_delete_event_requires_delete_history_permission() {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles_enforced(vec![operator.clone()]);
        let node_id = NodeId::new(1, "delete_event_history");
        let manager = history_manager(vec![NodeType::Object(Box::new(history_event_object(
            &node_id,
            Some(vec![role_permission(
                &operator,
                PermissionType::ModifyHistory,
            )]),
        )))]);
        let mut update = delete_event_node(&node_id);

        let denied_len = {
            let mut nodes = vec![&mut update];
            validated_history_update_len(&manager, &context, nodes.as_mut_slice())
        };

        assert_eq!(denied_len, 0);
        assert_eq!(update.status(), StatusCode::BadUserAccessDenied);
    }

    #[tokio::test]
    async fn history_update_insert_event_requires_insert_history_permission() {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles_enforced(vec![operator.clone()]);
        let node_id = NodeId::new(1, "insert_event_history");
        let manager = history_manager(vec![NodeType::Object(Box::new(history_event_object(
            &node_id,
            Some(vec![role_permission(
                &operator,
                PermissionType::ModifyHistory,
            )]),
        )))]);
        let mut update = update_event_node(&node_id, PerformUpdateType::Insert);

        let denied_len = {
            let mut nodes = vec![&mut update];
            validated_history_update_len(&manager, &context, nodes.as_mut_slice())
        };

        assert_eq!(denied_len, 0);
        assert_eq!(update.status(), StatusCode::BadUserAccessDenied);
    }

    #[tokio::test]
    async fn method_dispatch_authorization_denies_only_call_without_call_permission() {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles_enforced(vec![operator.clone()]);
        let object_id = NodeId::new(1, "object");
        let denied_method_id = NodeId::new(1, "denied_method");
        let open_method_id = NodeId::new(1, "open_method");
        let manager = method_manager(
            &object_id,
            vec![
                (
                    denied_method_id.clone(),
                    Some(vec![role_permission(&operator, PermissionType::Read)]),
                ),
                (
                    open_method_id.clone(),
                    Some(vec![role_permission(&operator, PermissionType::Call)]),
                ),
            ],
        );
        let mut denied = method_call(&object_id, &denied_method_id);
        let mut open = method_call(&object_id, &open_method_id);

        {
            let mut calls = vec![&mut denied, &mut open];
            manager
                .authorize_method_calls(&context, calls.as_mut_slice())
                .expect("authorization precheck should not fail the service");
            let mut dispatch = calls
                .iter_mut()
                .filter_map(|call| {
                    if call.status() == StatusCode::BadMethodInvalid {
                        Some(&mut **call)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            manager
                .call(&context, dispatch.as_mut_slice())
                .await
                .unwrap();
        }

        assert_eq!(denied.status(), StatusCode::BadUserAccessDenied);
        assert_eq!(open.status(), StatusCode::Good);
    }

    #[tokio::test]
    async fn method_dispatch_authorization_allows_call_permission() {
        let operator = NodeId::new(0, "Operator");
        let context = request_context_with_roles_enforced(vec![operator.clone()]);
        let object_id = NodeId::new(1, "object");
        let method_id = NodeId::new(1, "method");
        let manager = method_manager(
            &object_id,
            vec![(
                method_id.clone(),
                Some(vec![role_permission(&operator, PermissionType::Call)]),
            )],
        );
        let mut call = method_call(&object_id, &method_id);

        {
            let mut calls = vec![&mut call];
            manager
                .authorize_method_calls(&context, calls.as_mut_slice())
                .expect("authorization precheck should not fail the service");
            manager.call(&context, calls.as_mut_slice()).await.unwrap();
        }

        assert_eq!(call.status(), StatusCode::Good);
    }

    #[tokio::test]
    async fn method_dispatch_authorization_rejects_encryption_required_unencrypted_channel() {
        let context = request_context_enforced();
        let object_id = NodeId::new(1, "object");
        let method_id = NodeId::new(1, "method");
        let manager = method_manager_with_access_restrictions(
            &object_id,
            vec![(
                method_id.clone(),
                None,
                Some(AccessRestrictionType::EncryptionRequired),
            )],
        );
        let mut call = method_call(&object_id, &method_id);

        {
            let mut calls = vec![&mut call];
            manager
                .authorize_method_calls(&context, calls.as_mut_slice())
                .expect("authorization precheck should not fail the service");
        }

        assert_eq!(call.status(), StatusCode::BadSecurityModeInsufficient);
    }
}
