use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use opcua_core::{trace_read_lock, trace_write_lock};
use opcua_nodes::{HasNodeId, NodeSetImport};

use crate::{
    address_space::{read_node_value, write_node_value, AddressSpace},
    node_manager::{
        DefaultTypeTree, MethodCall, MonitoredItemRef, MonitoredItemUpdateRef, NodeManagerBuilder,
        NodeManagersRef, ParsedReadValueId, RequestContext, ServerContext, SyncSampler, WriteNode,
    },
    CreateMonitoredItem,
};
use opcua_core::sync::RwLock;
use opcua_types::{
    AttributeId, DataValue, MonitoringMode, NodeClass, NodeId, NumericRange, StatusCode,
    TimestampsToReturn, Variant,
};

use super::{
    InMemoryNodeManager, InMemoryNodeManagerBuilder, InMemoryNodeManagerImpl,
    InMemoryNodeManagerImplBuilder, NamespaceMetadata,
};

/// A simple in-memory node manager with utility methods for updating the address space,
/// and a mechanism for setting callbacks on `Read` and `Write` of values.
pub type SimpleNodeManager = InMemoryNodeManager<SimpleNodeManagerImpl>;

type WriteCB = Arc<dyn Fn(DataValue, &NumericRange) -> StatusCode + Send + Sync + 'static>;
type ReadCB = Arc<
    dyn Fn(&NumericRange, TimestampsToReturn, f64) -> Result<DataValue, StatusCode>
        + Send
        + Sync
        + 'static,
>;
type MethodCB = Arc<dyn Fn(&[Variant]) -> Result<Vec<Variant>, StatusCode> + Send + Sync + 'static>;

/// Builder for the [SimpleNodeManager].
pub struct SimpleNodeManagerBuilder {
    namespaces: Vec<NamespaceMetadata>,
    imports: Vec<Box<dyn NodeSetImport>>,
    name: String,
}

impl SimpleNodeManagerBuilder {
    /// Create a new simple node manager builder with the given namespace
    /// and name.
    pub fn new(namespace: NamespaceMetadata, name: &str) -> Self {
        Self {
            namespaces: vec![namespace],
            imports: Vec::new(),
            name: name.to_owned(),
        }
    }

    /// Create a new simple node manager that imports from the given list
    /// of [NodeSetImport]s.
    pub fn new_imports(imports: Vec<Box<dyn NodeSetImport>>, name: &str) -> Self {
        Self {
            namespaces: Vec::new(),
            imports,
            name: name.to_owned(),
        }
    }
}

impl InMemoryNodeManagerImplBuilder for SimpleNodeManagerBuilder {
    type Impl = SimpleNodeManagerImpl;

    fn build(mut self, context: ServerContext, address_space: &mut AddressSpace) -> Self::Impl {
        {
            let mut type_tree = context.type_tree.write();
            for import in self.imports {
                address_space.import_node_set(&*import, type_tree.namespaces_mut());
                let nss = import.get_own_namespaces();
                for ns in nss {
                    if !self.namespaces.iter().any(|n| n.namespace_uri == ns) {
                        self.namespaces.push(NamespaceMetadata {
                            namespace_uri: ns,
                            ..Default::default()
                        });
                    }
                }
            }
            for ns in &mut self.namespaces {
                ns.namespace_index = type_tree.namespaces_mut().add_namespace(&ns.namespace_uri);
            }
        }
        for ns in &self.namespaces {
            address_space.add_namespace(&ns.namespace_uri, ns.namespace_index);
        }
        SimpleNodeManagerImpl::new(self.namespaces, &self.name, context.node_managers.clone())
    }
}

/// Create a node manager builder for the simple node manager with the given
/// namespace and name.
pub fn simple_node_manager(namespace: NamespaceMetadata, name: &str) -> impl NodeManagerBuilder {
    InMemoryNodeManagerBuilder::new(SimpleNodeManagerBuilder::new(namespace, name))
}

/// Create a new simple node manager that imports from the given list
/// of [NodeSetImport]s.
pub fn simple_node_manager_imports(
    imports: Vec<Box<dyn NodeSetImport>>,
    name: &str,
) -> impl NodeManagerBuilder {
    InMemoryNodeManagerBuilder::new(SimpleNodeManagerBuilder::new_imports(imports, name))
}

/// Node manager designed to deal with simple, entirely in-memory, synchronous OPC-UA servers.
///
/// Use this if
///
///  - Your node hierarchy is known and small enough to fit in memory.
///  - No read, write, or method call operations are async or particularly time consuming.
///  - and you don't need to be able to write attributes other than `Value`.
pub struct SimpleNodeManagerImpl {
    write_cbs: RwLock<HashMap<NodeId, WriteCB>>,
    read_cbs: RwLock<HashMap<NodeId, ReadCB>>,
    method_cbs: RwLock<HashMap<NodeId, MethodCB>>,
    namespaces: Vec<NamespaceMetadata>,
    #[allow(unused)]
    node_managers: NodeManagersRef,
    name: String,
    samplers: SyncSampler,
}

#[async_trait]
impl InMemoryNodeManagerImpl for SimpleNodeManagerImpl {
    async fn init(&self, _address_space: &mut AddressSpace, context: ServerContext) {
        self.samplers.run(
            Duration::from_millis(
                context
                    .info
                    .config
                    .limits
                    .subscriptions
                    .min_sampling_interval_ms as u64,
            ),
            context.subscriptions.clone(),
        );
    }

    fn namespaces(&self) -> Vec<NamespaceMetadata> {
        self.namespaces.clone()
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn read_values(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        nodes: &[&ParsedReadValueId],
        max_age: f64,
        timestamps_to_return: TimestampsToReturn,
    ) -> Vec<DataValue> {
        let address_space = address_space.read();
        let cbs = trace_read_lock!(self.read_cbs);

        nodes
            .iter()
            .map(|n| {
                self.read_node_value(
                    &cbs,
                    context,
                    &address_space,
                    n,
                    max_age,
                    timestamps_to_return,
                )
            })
            .collect()
    }

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

        let cbs = trace_read_lock!(self.read_cbs);

        for (value, node) in values.into_iter().zip(items.iter_mut()) {
            if value.status() != StatusCode::BadAttributeIdInvalid {
                node.set_initial_value(value);
            }
            node.set_status(StatusCode::Good);
            let rf = &node.item_to_monitor().node_id;

            if let Some(cb) = cbs.get(rf).cloned() {
                let tss = node.timestamps_to_return();
                let index_range = node.item_to_monitor().index_range.clone();

                self.samplers.add_sampler(
                    node.item_to_monitor().node_id.clone(),
                    AttributeId::Value,
                    move || {
                        Some(match cb(&index_range, tss, 0.0) {
                            Err(e) => DataValue {
                                status: Some(e),
                                ..Default::default()
                            },
                            Ok(v) => v,
                        })
                    },
                    node.monitoring_mode(),
                    node.handle(),
                    Duration::from_millis(node.sampling_interval() as u64),
                )
            }
        }
    }

    async fn modify_monitored_items(
        &self,
        _context: &RequestContext,
        items: &[&MonitoredItemUpdateRef],
    ) {
        for it in items {
            self.samplers.update_sampler(
                it.node_id(),
                it.attribute(),
                it.handle(),
                Duration::from_millis(it.update().revised_sampling_interval as u64),
            );
        }
    }

    async fn set_monitoring_mode(
        &self,
        _context: &RequestContext,
        mode: MonitoringMode,
        items: &[&MonitoredItemRef],
    ) {
        for it in items {
            self.samplers
                .set_sampler_mode(it.node_id(), it.attribute(), it.handle(), mode);
        }
    }

    async fn delete_monitored_items(&self, _context: &RequestContext, items: &[&MonitoredItemRef]) {
        for it in items {
            self.samplers
                .remove_sampler(it.node_id(), it.attribute(), it.handle());
        }
    }

    async fn write(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        nodes_to_write: &mut [&mut WriteNode],
    ) -> Result<(), StatusCode> {
        let mut address_space = trace_write_lock!(address_space);
        let type_tree = trace_read_lock!(context.type_tree);
        let cbs = trace_read_lock!(self.write_cbs);

        for write in nodes_to_write {
            self.write_node_value(&cbs, context, &mut address_space, &type_tree, write);
        }

        Ok(())
    }

    async fn call(
        &self,
        _context: &RequestContext,
        _address_space: &RwLock<AddressSpace>,
        methods_to_call: &mut [&mut &mut MethodCall],
    ) -> Result<(), StatusCode> {
        let cbs = trace_read_lock!(self.method_cbs);
        for method in methods_to_call {
            if let Some(cb) = cbs.get(method.method_id()) {
                match cb(method.arguments()) {
                    Ok(r) => {
                        method.set_outputs(r);
                        method.set_status(StatusCode::Good);
                    }
                    Err(e) => method.set_status(e),
                }
            }
        }

        Ok(())
    }
}

impl SimpleNodeManagerImpl {
    fn new(namespaces: Vec<NamespaceMetadata>, name: &str, node_managers: NodeManagersRef) -> Self {
        Self {
            write_cbs: Default::default(),
            read_cbs: Default::default(),
            method_cbs: Default::default(),
            namespaces,
            name: name.to_owned(),
            node_managers,
            samplers: SyncSampler::new(),
        }
    }

    fn read_node_value(
        &self,
        cbs: &HashMap<NodeId, ReadCB>,
        context: &RequestContext,
        address_space: &AddressSpace,
        node_to_read: &ParsedReadValueId,
        max_age: f64,
        timestamps_to_return: TimestampsToReturn,
    ) -> DataValue {
        let mut result_value = DataValue::null();
        // Check that the read is permitted.
        let node = match address_space.validate_node_read(context, node_to_read) {
            Ok(n) => n,
            Err(e) => {
                result_value.status = Some(e);
                return result_value;
            }
        };

        // If there is a callback registered, call that, otherwise read it from the node hierarchy.
        if let Some(cb) = cbs.get(&node_to_read.node_id) {
            match cb(&node_to_read.index_range, timestamps_to_return, max_age) {
                Err(e) => DataValue {
                    status: Some(e),
                    ..Default::default()
                },
                Ok(v) => v,
            }
        } else {
            // If it can't be found, read it from the node hierarchy.
            read_node_value(node, context, node_to_read, max_age, timestamps_to_return)
        }
    }

    fn write_node_value(
        &self,
        cbs: &HashMap<NodeId, WriteCB>,
        context: &RequestContext,
        address_space: &mut AddressSpace,
        type_tree: &DefaultTypeTree,
        write: &mut WriteNode,
    ) {
        let node = match address_space.validate_node_write(context, write.value(), type_tree) {
            Ok(v) => v,
            Err(e) => {
                write.set_status(e);
                return;
            }
        };

        if node.node_class() != NodeClass::Variable
            || write.value().attribute_id != AttributeId::Value
        {
            write.set_status(StatusCode::BadNotWritable);
            return;
        }

        if let Some(cb) = cbs.get(node.as_node().node_id()) {
            // If there is a callback registered, call that.
            write.set_status(cb(write.value().value.clone(), &write.value().index_range));
        } else if write.value().value.value.is_some() {
            // If not, write the value to the node hierarchy.
            match write_node_value(node, write.value()) {
                Ok(_) => write.set_status(StatusCode::Good),
                Err(e) => write.set_status(e),
            }
        } else {
            // If no value is passed return an error.
            write.set_status(StatusCode::BadNothingToDo);
        }
        if write.status().is_good() {
            if let Some(val) = node.as_mut_node().get_attribute(
                TimestampsToReturn::Both,
                write.value().attribute_id,
                &NumericRange::None,
                &opcua_types::DataEncoding::Binary,
            ) {
                context.subscriptions.notify_data_change(
                    [(val, node.node_id(), write.value().attribute_id)].into_iter(),
                );
            }
        }
    }

    /// Add a callback called on `Write` for the node given by `id`.
    pub fn add_write_callback(
        &self,
        id: NodeId,
        cb: impl Fn(DataValue, &NumericRange) -> StatusCode + Send + Sync + 'static,
    ) {
        let mut cbs = trace_write_lock!(self.write_cbs);
        cbs.insert(id, Arc::new(cb));
    }

    /// Add a callback for `Read` on the node given by `id`.
    pub fn add_read_callback(
        &self,
        id: NodeId,
        cb: impl Fn(&NumericRange, TimestampsToReturn, f64) -> Result<DataValue, StatusCode>
            + Send
            + Sync
            + 'static,
    ) {
        let mut cbs = trace_write_lock!(self.read_cbs);
        cbs.insert(id, Arc::new(cb));
    }

    /// Add a callback for `Call` on the method given by `id`.
    pub fn add_method_callback(
        &self,
        id: NodeId,
        cb: impl Fn(&[Variant]) -> Result<Vec<Variant>, StatusCode> + Send + Sync + 'static,
    ) {
        let mut cbs = trace_write_lock!(self.method_cbs);
        cbs.insert(id, Arc::new(cb));
    }
}
