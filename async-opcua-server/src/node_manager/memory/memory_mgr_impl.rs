use async_trait::async_trait;
use std::sync::Arc;

use crate::{
    address_space::{AccessLevel, AddressSpace, EventNotifier, NodeType, ReferenceDirection},
    diagnostics::NamespaceMetadata,
    node_manager::{
        AddNodeItem, AddReferenceItem, DeleteNodeItem, DeleteReferenceItem, HistoryNode,
        HistoryUpdateNode, MethodCall, MonitoredItemRef, MonitoredItemUpdateRef, ParsedReadValueId,
        RegisterNodeItem, RequestContext, ServerContext, WriteNode,
    },
    session::continuation_points::ContinuationPoint,
    subscriptions::CreateMonitoredItem,
};
use opcua_core::sync::RwLock;
use opcua_nodes::{NodeBase, Object, TypeTree, Variable};
use opcua_types::{
    AddNodeAttributes, AttributesMask, DataTypeId, DataValue, ExpandedNodeId, LocalizedText,
    MonitoringMode, NodeClass, NodeId, ReadAnnotationDataDetails, ReadAtTimeDetails,
    ReadEventDetails, ReadProcessedDetails, ReadRawModifiedDetails, ReferenceTypeId, StatusCode,
    TimestampsToReturn, Variant, WriteMask,
};

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

    let mut address_space = address_space.write();

    for item in nodes_to_add {
        if item.status().is_bad() && item.status() != StatusCode::BadNotSupported {
            continue;
        }

        let parent_id = item.parent_node_id().node_id.clone();
        if parent_id.is_null() || !address_space.node_exists(&parent_id) {
            item.set_result(NodeId::null(), StatusCode::BadParentNodeIdInvalid);
            continue;
        }

        if item.reference_type_id().is_null() {
            item.set_result(NodeId::null(), StatusCode::BadReferenceTypeIdInvalid);
            continue;
        }

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
            item.set_result(assigned_id, StatusCode::Good);
        } else {
            item.set_result(NodeId::null(), StatusCode::BadNodeIdExists);
        }
    }
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

    let mut address_space = address_space.write();

    for item in nodes_to_delete {
        if item.node_id().is_null() {
            item.set_result(StatusCode::BadNodeIdInvalid);
            continue;
        }

        if address_space
            .delete(item.node_id(), item.delete_target_references())
            .is_some()
        {
            item.set_result(StatusCode::Good);
        } else {
            item.set_result(StatusCode::BadNodeIdUnknown);
        }
    }
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

    let mut address_space = address_space.write();
    let type_tree = context.type_tree.read();

    for item in references_to_add {
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

        let source_exists = address_space.node_exists(item.source_node_id());
        let target_exists = address_space.node_exists(&item.target_node_id().node_id);

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

        if item.is_forward() {
            address_space.insert_reference(
                item.source_node_id(),
                &item.target_node_id().node_id,
                item.reference_type_id(),
            );
        } else {
            address_space.insert_reference(
                &item.target_node_id().node_id,
                item.source_node_id(),
                item.reference_type_id(),
            );
        }

        if source_ready {
            item.set_source_result(StatusCode::Good);
        }
        if target_ready {
            item.set_target_result(StatusCode::Good);
        }
    }
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

    let mut address_space = address_space.write();
    let type_tree = context.type_tree.read();

    for item in references_to_delete {
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

        let source_exists = address_space.node_exists(item.source_node_id());
        let target_exists = address_space.node_exists(&item.target_node_id().node_id);

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
        (NodeClass::Object, _) | (NodeClass::Variable, _) => {
            Err(StatusCode::BadNodeAttributesInvalid)
        }
        _ => Err(StatusCode::BadNodeClassInvalid),
    }
}

fn build_object(
    node_id: &NodeId,
    browse_name: impl Into<opcua_types::QualifiedName>,
    attributes: &opcua_types::ObjectAttributes,
) -> Result<Object, StatusCode> {
    let browse_name = browse_name.into();
    let mask = attributes_mask(attributes.specified_attributes)?;
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
    let mask = attributes_mask(attributes.specified_attributes)?;
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

fn attributes_mask(specified_attributes: u32) -> Result<AttributesMask, StatusCode> {
    AttributesMask::from_bits(specified_attributes).ok_or(StatusCode::BadNodeAttributesInvalid)
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
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        to_delete: &[&DeleteNodeItem],
    ) {
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
