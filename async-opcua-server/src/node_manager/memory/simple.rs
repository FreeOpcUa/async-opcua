use std::{
    collections::HashMap,
    sync::{Arc, Weak},
    time::Duration,
};

use async_trait::async_trait;
use opcua_core::{trace_read_lock, trace_write_lock};
use opcua_nodes::{HasNodeId, NodeSetImport};

use crate::{
    address_space::{read_node_value, write_node_value, AddressSpace, NodeType},
    alarms::{AlarmSourceRegistry, LimitAlarm, ServerAlarmEvent},
    history::read::modification_infos_or_none,
    node_manager::{
        DefaultTypeTree, MethodCall, MonitoredItemRef, MonitoredItemUpdateRef, NodeManagerBuilder,
        NodeManagersRef, ParsedReadValueId, RequestContext, ServerContext, SyncSampler, WriteNode,
    },
    CreateMonitoredItem, SubscriptionCache,
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
type MethodWithContextCB = Arc<
    dyn Fn(&RequestContext, &[Variant]) -> Result<Vec<Variant>, StatusCode> + Send + Sync + 'static,
>;

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
    method_with_context_cbs: RwLock<HashMap<NodeId, MethodWithContextCB>>,
    namespaces: Vec<NamespaceMetadata>,
    #[allow(unused)]
    node_managers: NodeManagersRef,
    name: String,
    samplers: SyncSampler,
    history_backend: RwLock<Option<Arc<dyn crate::history::HistoryStorageBackend>>>,
    subscriptions: RwLock<Option<Arc<SubscriptionCache>>>,
    alarm_sources: Arc<AlarmSourceRegistry>,
    source_alarm_sampler_started: RwLock<bool>,
}

#[async_trait]
impl InMemoryNodeManagerImpl for SimpleNodeManagerImpl {
    async fn init(&self, _address_space: &mut AddressSpace, context: ServerContext) {
        *self.subscriptions.write() = Some(context.subscriptions.clone());
        let manager = self
            .node_managers
            .get_by_name::<SimpleNodeManager>(&self.name)
            .expect("simple node manager must be registered before sampling alarm sources");
        self.spawn_alarm_source_sampler(
            Arc::clone(manager.address_space()),
            Arc::downgrade(&context.subscriptions),
        );
        self.samplers.run(
            Duration::from_micros(
                // If this is set too low the server will just spin at 100% CPU. Cap it at
                // 100 ms. In custom node manager implementations using the sync sampler
                // users are free to set whatever minimum they want.
                // In practice, if you need sampling rates much lower than 100ms you
                // will likely want a different mechanism than the sync sampler.
                (context
                    .info
                    .config
                    .limits
                    .subscriptions
                    .min_sampling_interval_ms
                    .max(100.0)
                    * 1000.0) as u64,
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
        let mut source_writes: Vec<(NodeId, DataValue)> = Vec::new();

        {
            let address_space = trace_read_lock!(address_space);
            let type_tree = trace_read_lock!(context.type_tree);
            let cbs = trace_read_lock!(self.write_cbs);

            for write in nodes_to_write {
                self.write_node_value(&cbs, context, &address_space, &type_tree, write);

                let source = &write.value().node_id;
                if write.status().is_good()
                    && write.value().attribute_id == AttributeId::Value
                    && !self.alarm_source_registry().alarms_for(source).is_empty()
                {
                    source_writes.push((source.clone(), write.value().value.clone()));
                }
            }
        }

        if !source_writes.is_empty() {
            let mut address_space = trace_write_lock!(address_space);

            for (source, value) in source_writes {
                Self::reevaluate_and_dispatch(
                    self.alarm_source_registry(),
                    &mut address_space,
                    Some(context.subscriptions.as_ref()),
                    &source,
                    &value,
                );
            }
        }

        Ok(())
    }

    async fn call(
        &self,
        context: &RequestContext,
        _address_space: &RwLock<AddressSpace>,
        methods_to_call: &mut [&mut &mut MethodCall],
    ) -> Result<(), StatusCode> {
        let cbs = trace_read_lock!(self.method_cbs);
        let ctx_cbs = trace_read_lock!(self.method_with_context_cbs);
        for method in methods_to_call {
            if let Some(cb) = ctx_cbs.get(method.method_id()) {
                match cb(context, method.arguments()) {
                    Ok(r) => {
                        method.set_outputs(r);
                        method.set_status(StatusCode::Good);
                    }
                    Err(e) => method.set_status(e),
                }
            } else if let Some(cb) = cbs.get(method.method_id()) {
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

    async fn history_read_raw_modified(
        &self,
        _context: &RequestContext,
        details: &opcua_types::ReadRawModifiedDetails,
        nodes: &mut [&mut &mut crate::node_manager::history::HistoryNode],
        _timestamps_to_return: TimestampsToReturn,
    ) -> Result<(), StatusCode> {
        let backend = {
            let guard = self.history_backend.read();
            guard.clone()
        };
        if let Some(backend) = backend {
            for hn in nodes {
                let node_id = hn.node_id();
                let input_cp = hn.continuation_point();
                let backend_token = input_cp
                    .and_then(|cp| cp.get::<crate::history::HistoryContinuationPoint>())
                    .and_then(|hcp| hcp.backend_token.clone());

                let res = backend
                    .read_raw_modified(
                        node_id,
                        details.start_time,
                        details.end_time,
                        details.num_values_per_node,
                        details.return_bounds,
                        details.is_read_modified,
                        backend_token,
                    )
                    .await;

                match res {
                    Ok((values, modification_infos, next_token)) => {
                        let next_cp = next_token.map(|tok| {
                            crate::session::continuation_points::ContinuationPoint::new(Box::new(
                                crate::history::HistoryContinuationPoint::new(
                                    node_id.clone(),
                                    details.start_time,
                                    details.end_time,
                                    details.num_values_per_node,
                                    details.return_bounds,
                                    Some(tok),
                                ),
                            ))
                        });

                        hn.set_next_continuation_point(next_cp);
                        if details.is_read_modified {
                            hn.set_result(opcua_types::HistoryModifiedData {
                                data_values: Some(values),
                                modification_infos: modification_infos_or_none(modification_infos),
                            });
                        } else {
                            hn.set_result(opcua_types::HistoryData {
                                data_values: Some(values),
                            });
                        }
                        hn.set_status(StatusCode::Good);
                    }
                    Err(status) => {
                        hn.set_status(status);
                    }
                }
            }
            Ok(())
        } else {
            Err(StatusCode::BadHistoryOperationUnsupported)
        }
    }

    async fn history_read_processed(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        details: &opcua_types::ReadProcessedDetails,
        nodes: &mut [&mut &mut crate::node_manager::history::HistoryNode],
        timestamps_to_return: TimestampsToReturn,
    ) -> Result<(), StatusCode> {
        let backend = {
            let guard = self.history_backend.read();
            guard.clone()
        };
        if let Some(backend) = backend {
            let stepped: Vec<bool> = {
                let space = trace_read_lock!(address_space);
                nodes
                    .iter()
                    .map(|n| crate::aggregates::resolve_stepped(&space, n.node_id()))
                    .collect()
            };

            crate::aggregates::read_processed_aggregates(
                &backend,
                context,
                details,
                nodes,
                timestamps_to_return,
                &stepped,
            )
            .await
        } else {
            Err(StatusCode::BadHistoryOperationUnsupported)
        }
    }

    async fn history_read_events(
        &self,
        _context: &RequestContext,
        details: &opcua_types::ReadEventDetails,
        nodes: &mut [&mut &mut crate::node_manager::history::HistoryNode],
        _timestamps_to_return: TimestampsToReturn,
    ) -> Result<(), StatusCode> {
        let backend = {
            let guard = self.history_backend.read();
            guard.clone()
        };
        if let Some(backend) = backend {
            for hn in nodes {
                let node_id = hn.node_id();
                let backend_token = hn
                    .continuation_point()
                    .and_then(|cp| cp.get::<crate::history::HistoryContinuationPoint>())
                    .and_then(|hcp| hcp.backend_token.clone());

                match backend
                    .read_events(
                        node_id,
                        details.start_time,
                        details.end_time,
                        details.num_values_per_node,
                        &details.filter,
                        backend_token,
                    )
                    .await
                {
                    Ok((events, next_token)) => {
                        let next_cp = next_token.map(|tok| {
                            crate::session::continuation_points::ContinuationPoint::new(Box::new(
                                crate::history::HistoryContinuationPoint::new(
                                    node_id.clone(),
                                    details.start_time,
                                    details.end_time,
                                    details.num_values_per_node,
                                    false,
                                    Some(tok),
                                ),
                            ))
                        });

                        hn.set_next_continuation_point(next_cp);
                        hn.set_result(opcua_types::HistoryEvent {
                            events: Some(events),
                        });
                        hn.set_status(StatusCode::Good);
                    }
                    Err(status) => hn.set_status(status),
                }
            }
            Ok(())
        } else {
            Err(StatusCode::BadHistoryOperationUnsupported)
        }
    }

    async fn history_read_annotations(
        &self,
        _context: &RequestContext,
        details: &opcua_types::ReadAnnotationDataDetails,
        nodes: &mut [&mut &mut crate::node_manager::history::HistoryNode],
        _timestamps_to_return: TimestampsToReturn,
    ) -> Result<(), StatusCode> {
        let backend = {
            let guard = self.history_backend.read();
            guard.clone()
        };
        if let Some(backend) = backend {
            for hn in nodes {
                let node_id = hn.node_id();
                let backend_token = hn
                    .continuation_point()
                    .and_then(|cp| cp.get::<crate::history::HistoryContinuationPoint>())
                    .and_then(|hcp| hcp.backend_token.clone());
                let req_times = details.req_times.as_deref().unwrap_or(&[]);

                match backend
                    .read_annotations(node_id, req_times, backend_token)
                    .await
                {
                    Ok((data_values, next_token)) => {
                        let start_time = req_times
                            .first()
                            .copied()
                            .unwrap_or_else(opcua_types::DateTime::null);
                        let end_time = req_times
                            .last()
                            .copied()
                            .unwrap_or_else(opcua_types::DateTime::null);
                        let next_cp = next_token.map(|tok| {
                            crate::session::continuation_points::ContinuationPoint::new(Box::new(
                                crate::history::HistoryContinuationPoint::new(
                                    node_id.clone(),
                                    start_time,
                                    end_time,
                                    req_times.len() as u32,
                                    false,
                                    Some(tok),
                                ),
                            ))
                        });

                        hn.set_next_continuation_point(next_cp);
                        hn.set_result(opcua_types::HistoryData {
                            data_values: Some(data_values),
                        });
                        hn.set_status(StatusCode::Good);
                    }
                    Err(status) => hn.set_status(status),
                }
            }
            Ok(())
        } else {
            Err(StatusCode::BadHistoryOperationUnsupported)
        }
    }

    async fn history_release_continuation_point(
        &self,
        _context: &RequestContext,
        _node_id: &NodeId,
        continuation_point: &crate::session::continuation_points::ContinuationPoint,
    ) -> Result<(), StatusCode> {
        let backend_token = continuation_point
            .get::<crate::history::HistoryContinuationPoint>()
            .and_then(|point| point.backend_token.clone());

        let Some(backend_token) = backend_token else {
            return Ok(());
        };

        let backend = {
            let guard = self.history_backend.read();
            guard.clone()
        };

        if let Some(backend) = backend {
            backend.release_continuation_point(backend_token).await
        } else {
            Err(StatusCode::BadHistoryOperationUnsupported)
        }
    }

    async fn history_update(
        &self,
        _context: &RequestContext,
        nodes: &mut [&mut &mut crate::node_manager::history::HistoryUpdateNode],
    ) -> Result<(), StatusCode> {
        let backend = {
            let guard = self.history_backend.read();
            guard.clone()
        };
        let Some(backend) = backend else {
            for hn in nodes {
                hn.set_status(StatusCode::BadHistoryOperationUnsupported);
            }
            return Ok(());
        };

        for hn in nodes {
            match hn.details() {
                crate::node_manager::history::HistoryUpdateDetails::UpdateData(details) => {
                    let result = backend
                        .update_data(
                            &details.node_id,
                            details.perform_insert_replace,
                            details.update_values.clone().unwrap_or_default(),
                        )
                        .await;
                    match result {
                        Ok(results) => {
                            hn.set_operation_results(Some(results));
                            hn.set_status(StatusCode::Good);
                        }
                        Err(status) => hn.set_status(status),
                    }
                }
                crate::node_manager::history::HistoryUpdateDetails::UpdateStructureData(
                    details,
                ) => {
                    let result = backend
                        .update_structure_data(
                            &details.node_id,
                            details.perform_insert_replace,
                            details.update_values.clone().unwrap_or_default(),
                        )
                        .await;
                    match result {
                        Ok(results) => {
                            hn.set_operation_results(Some(results));
                            hn.set_status(StatusCode::Good);
                        }
                        Err(status) => hn.set_status(status),
                    }
                }
                crate::node_manager::history::HistoryUpdateDetails::UpdateEvent(details) => {
                    let result = backend
                        .update_event(
                            &details.node_id,
                            &details.filter,
                            details.event_data.clone().unwrap_or_default(),
                            details.perform_insert_replace,
                        )
                        .await;
                    match result {
                        Ok(results) => {
                            hn.set_operation_results(Some(results));
                            hn.set_status(StatusCode::Good);
                        }
                        Err(status) => hn.set_status(status),
                    }
                }
                crate::node_manager::history::HistoryUpdateDetails::DeleteRawModified(details) => {
                    match backend
                        .delete_raw_modified(
                            &details.node_id,
                            details.is_delete_modified,
                            details.start_time,
                            details.end_time,
                        )
                        .await
                    {
                        Ok(status) => hn.set_status(status),
                        Err(status) => hn.set_status(status),
                    }
                }
                crate::node_manager::history::HistoryUpdateDetails::DeleteAtTime(details) => {
                    let result = backend
                        .delete_at_time(
                            &details.node_id,
                            details.req_times.clone().unwrap_or_default(),
                        )
                        .await;
                    match result {
                        Ok(results) => {
                            hn.set_operation_results(Some(results));
                            hn.set_status(StatusCode::Good);
                        }
                        Err(status) => hn.set_status(status),
                    }
                }
                crate::node_manager::history::HistoryUpdateDetails::DeleteEvent(details) => {
                    let result = backend
                        .delete_event(
                            &details.node_id,
                            details.event_ids.clone().unwrap_or_default(),
                        )
                        .await;
                    match result {
                        Ok(results) => {
                            hn.set_operation_results(Some(results));
                            hn.set_status(StatusCode::Good);
                        }
                        Err(status) => hn.set_status(status),
                    }
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
            method_with_context_cbs: Default::default(),
            namespaces,
            name: name.to_owned(),
            node_managers,
            samplers: SyncSampler::new(),
            history_backend: RwLock::new(None),
            subscriptions: RwLock::new(None),
            alarm_sources: Arc::new(AlarmSourceRegistry::new()),
            source_alarm_sampler_started: RwLock::new(false),
        }
    }

    /// Sets the historical storage backend for this node manager.
    pub fn set_history_backend(&self, backend: Arc<dyn crate::history::HistoryStorageBackend>) {
        *self.history_backend.write() = Some(backend);
    }

    /// Returns the registry of alarms bound to source Variables.
    pub fn alarm_source_registry(&self) -> &AlarmSourceRegistry {
        self.alarm_sources.as_ref()
    }

    /// Binds a limit alarm to a source Variable and registers it for source writes.
    pub fn monitor_alarm_source(&self, source: &NodeId, alarm: LimitAlarm) -> Arc<LimitAlarm> {
        self.node_managers
            .get_by_name::<SimpleNodeManager>(&self.name)
            .expect("simple node manager must be registered before monitoring alarm sources")
            .monitor_alarm_source(source, alarm)
    }

    /// Binds a limit alarm to a source Variable with opt-in periodic source sampling.
    pub fn monitor_alarm_source_sampled(
        &self,
        source: &NodeId,
        alarm: LimitAlarm,
        interval: Duration,
    ) -> Arc<LimitAlarm> {
        self.node_managers
            .get_by_name::<SimpleNodeManager>(&self.name)
            .expect("simple node manager must be registered before monitoring alarm sources")
            .monitor_alarm_source_sampled(source, alarm, interval)
    }

    fn monitor_alarm_source_on_address_space(
        &self,
        address_space: &RwLock<AddressSpace>,
        source: &NodeId,
        alarm: LimitAlarm,
    ) -> Arc<LimitAlarm> {
        let alarm = Self::bind_alarm_source_on_address_space(address_space, source, alarm);
        self.alarm_source_registry()
            .register(source.clone(), alarm.clone());
        alarm
    }

    fn monitor_alarm_source_sampled_on_address_space(
        &self,
        address_space: &RwLock<AddressSpace>,
        source: &NodeId,
        alarm: LimitAlarm,
        interval: Duration,
    ) -> Arc<LimitAlarm> {
        let alarm = Self::bind_alarm_source_on_address_space(address_space, source, alarm);
        self.alarm_source_registry()
            .register_sampled(source.clone(), alarm.clone(), interval);
        alarm
    }

    fn bind_alarm_source_on_address_space(
        address_space: &RwLock<AddressSpace>,
        source: &NodeId,
        alarm: LimitAlarm,
    ) -> Arc<LimitAlarm> {
        let mut alarm = alarm;
        alarm.set_source_node(source.clone());

        {
            let mut space = trace_write_lock!(address_space);
            alarm.write_input_node_property(&mut space, source);
            alarm.write_has_condition_reference(&mut space, source);
        }

        Arc::new(alarm)
    }

    fn spawn_alarm_source_sampler(
        &self,
        address_space: Arc<RwLock<AddressSpace>>,
        subscriptions: Weak<SubscriptionCache>,
    ) {
        {
            let mut started = self.source_alarm_sampler_started.write();
            if *started {
                return;
            }
            *started = true;
        }

        let alarm_sources = Arc::clone(&self.alarm_sources);
        tokio::spawn(async move {
            Self::run_alarm_source_sampler(address_space, alarm_sources, subscriptions).await;
        });
    }

    async fn run_alarm_source_sampler(
        address_space: Arc<RwLock<AddressSpace>>,
        alarm_sources: Arc<AlarmSourceRegistry>,
        subscriptions: Weak<SubscriptionCache>,
    ) {
        const SOURCE_ALARM_SAMPLER_TICK: Duration = Duration::from_millis(100);

        let mut ticker = tokio::time::interval(SOURCE_ALARM_SAMPLER_TICK);
        ticker.tick().await;

        let mut last_fire: HashMap<(NodeId, NodeId), tokio::time::Instant> = HashMap::new();
        loop {
            let now = ticker.tick().await;
            let Some(subscriptions) = subscriptions.upgrade() else {
                break;
            };

            for (source, alarm, sampling_interval) in alarm_sources.sampled_bindings() {
                let key = (source.clone(), alarm.condition_id().clone());
                let due = match last_fire.get(&key) {
                    Some(last) => now.duration_since(*last) >= sampling_interval,
                    None => true,
                };
                if !due {
                    continue;
                }
                last_fire.insert(key, now);

                let Some(value) = Self::read_current_source_value(&address_space, &source) else {
                    continue;
                };

                let mut space = trace_write_lock!(address_space);
                Self::reevaluate_and_dispatch(
                    alarm_sources.as_ref(),
                    &mut space,
                    Some(subscriptions.as_ref()),
                    &source,
                    &value,
                );
            }
        }
    }

    fn read_current_source_value(
        address_space: &RwLock<AddressSpace>,
        source: &NodeId,
    ) -> Option<DataValue> {
        let space = trace_read_lock!(address_space);
        let node = space.find(source)?;
        if !matches!(&*node, NodeType::Variable(_)) {
            return None;
        }

        node.as_node().get_attribute(
            TimestampsToReturn::Both,
            AttributeId::Value,
            &NumericRange::None,
            &opcua_types::DataEncoding::Binary,
        )
    }

    fn reevaluate_and_dispatch(
        alarm_sources: &AlarmSourceRegistry,
        space: &mut AddressSpace,
        subscriptions: Option<&SubscriptionCache>,
        source: &NodeId,
        value: &DataValue,
    ) {
        for alarm in alarm_sources.alarms_for(source) {
            if let Some(ev) = alarm.re_evaluate(space, value) {
                if let Some(subscriptions) = subscriptions {
                    let wrapper = ServerAlarmEvent { event: &ev };
                    subscriptions.notify_events(std::iter::once((
                        &wrapper as &dyn opcua_nodes::Event,
                        &ev.source_node,
                    )));
                }
            }
        }
    }

    /// Programmatically sets a source Variable value and re-evaluates bound alarms.
    pub fn set_source_value(&self, source: &NodeId, value: DataValue) {
        if let Some(manager) = self
            .node_managers
            .get_by_name::<SimpleNodeManager>(&self.name)
        {
            manager.set_source_value(source, value);
        }
    }

    fn set_source_value_on_address_space(
        &self,
        address_space: &RwLock<AddressSpace>,
        source: &NodeId,
        value: DataValue,
    ) {
        let subscriptions = self.subscriptions.read().clone();
        let mut space = trace_write_lock!(address_space);

        let Some(mut node) = space.find_mut(source) else {
            return;
        };

        let NodeType::Variable(variable) = &mut *node else {
            return;
        };

        variable.set_data_value(value.clone());
        drop(node);

        Self::reevaluate_and_dispatch(
            self.alarm_source_registry(),
            &mut space,
            subscriptions.as_deref(),
            source,
            &value,
        );
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
            read_node_value(&node, context, node_to_read, max_age, timestamps_to_return)
        }
    }

    fn write_node_value(
        &self,
        cbs: &HashMap<NodeId, WriteCB>,
        context: &RequestContext,
        address_space: &AddressSpace,
        type_tree: &DefaultTypeTree,
        write: &mut WriteNode,
    ) {
        let mut node = match address_space.validate_node_write(context, write.value(), type_tree) {
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
            match write_node_value(&mut node, write.value()) {
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

    /// Add a callback for `Call` on the method given by `id` that has access to the RequestContext.
    pub fn add_method_callback_with_context(
        &self,
        id: NodeId,
        cb: impl Fn(&RequestContext, &[Variant]) -> Result<Vec<Variant>, StatusCode>
            + Send
            + Sync
            + 'static,
    ) {
        let mut cbs = trace_write_lock!(self.method_with_context_cbs);
        cbs.insert(id, Arc::new(cb));
    }
}

impl InMemoryNodeManager<SimpleNodeManagerImpl> {
    /// Binds a limit alarm to a source Variable and registers it for source writes.
    pub fn monitor_alarm_source(&self, source: &NodeId, alarm: LimitAlarm) -> Arc<LimitAlarm> {
        self.inner().monitor_alarm_source_on_address_space(
            self.address_space().as_ref(),
            source,
            alarm,
        )
    }

    /// Binds a limit alarm to a source Variable with opt-in periodic source sampling.
    pub fn monitor_alarm_source_sampled(
        &self,
        source: &NodeId,
        alarm: LimitAlarm,
        interval: Duration,
    ) -> Arc<LimitAlarm> {
        self.inner().monitor_alarm_source_sampled_on_address_space(
            self.address_space().as_ref(),
            source,
            alarm,
            interval,
        )
    }

    /// Programmatically sets a source Variable value and re-evaluates bound alarms.
    pub fn set_source_value(&self, source: &NodeId, value: DataValue) {
        self.inner().set_source_value_on_address_space(
            self.address_space().as_ref(),
            source,
            value,
        );
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use opcua_types::{
        ApplicationDescription, ByteString, DateTime, DeleteAtTimeDetails, DeleteEventDetails,
        DeleteRawModifiedDetails, EventFilter, HistoryEventFieldList, PerformUpdateType, UAString,
        UpdateDataDetails, UpdateEventDetails, UpdateStructureDataDetails,
    };

    use crate::{
        alarms::{LimitConfig, LimitDef, LimitMode},
        authenticator::UserToken,
        history::{HistoryRawModifiedResult, HistoryStorageBackend},
        identity_token::IdentityToken,
        node_manager::{
            history::{HistoryUpdateDetails, HistoryUpdateNode},
            RequestContextInner,
        },
        session::instance::Session,
        ServerBuilder,
    };

    use super::*;

    #[derive(Debug, Clone, PartialEq)]
    enum HistoryBackendCall {
        UpdateData {
            node_id: NodeId,
            perform_insert_replace: PerformUpdateType,
            entry_count: usize,
        },
        UpdateStructureData {
            node_id: NodeId,
            perform_insert_replace: PerformUpdateType,
            entry_count: usize,
        },
        UpdateEvent {
            node_id: NodeId,
            perform_insert_replace: PerformUpdateType,
            entry_count: usize,
        },
        DeleteRawModified {
            node_id: NodeId,
            is_delete_modified: bool,
            start_time: DateTime,
            end_time: DateTime,
        },
        DeleteAtTime {
            node_id: NodeId,
            entry_count: usize,
        },
        DeleteEvent {
            node_id: NodeId,
            entry_count: usize,
        },
    }

    #[derive(Default)]
    struct RecordingHistoryBackend {
        calls: RwLock<Vec<HistoryBackendCall>>,
    }

    impl RecordingHistoryBackend {
        fn calls(&self) -> Vec<HistoryBackendCall> {
            self.calls.read().clone()
        }
    }

    struct TestSourceAlarm {
        source: NodeId,
        condition: NodeId,
    }

    impl crate::alarms::SourceMonitoredAlarm for TestSourceAlarm {
        fn source_node(&self) -> &NodeId {
            &self.source
        }

        fn condition_id(&self) -> &NodeId {
            &self.condition
        }

        fn re_evaluate(
            &self,
            _address_space: &mut AddressSpace,
            _value: &DataValue,
        ) -> Option<opcua_core::events::AlarmEvent> {
            None
        }
    }

    #[async_trait]
    impl HistoryStorageBackend for RecordingHistoryBackend {
        async fn read_raw_modified(
            &self,
            _node_id: &NodeId,
            _start_time: DateTime,
            _end_time: DateTime,
            _num_values_per_node: u32,
            _return_bounds: bool,
            _is_read_modified: bool,
            _continuation_point: Option<Vec<u8>>,
        ) -> Result<HistoryRawModifiedResult, StatusCode> {
            Err(StatusCode::BadHistoryOperationUnsupported)
        }

        async fn update_data(
            &self,
            node_id: &NodeId,
            perform_insert_replace: PerformUpdateType,
            values: Vec<DataValue>,
        ) -> Result<Vec<StatusCode>, StatusCode> {
            self.calls.write().push(HistoryBackendCall::UpdateData {
                node_id: node_id.clone(),
                perform_insert_replace,
                entry_count: values.len(),
            });
            Ok(vec![StatusCode::Good, StatusCode::BadNoData])
        }

        async fn update_structure_data(
            &self,
            node_id: &NodeId,
            perform_insert_replace: PerformUpdateType,
            values: Vec<DataValue>,
        ) -> Result<Vec<StatusCode>, StatusCode> {
            self.calls
                .write()
                .push(HistoryBackendCall::UpdateStructureData {
                    node_id: node_id.clone(),
                    perform_insert_replace,
                    entry_count: values.len(),
                });
            Ok(vec![StatusCode::BadOutOfRange])
        }

        async fn update_event(
            &self,
            node_id: &NodeId,
            _filter: &EventFilter,
            events: Vec<HistoryEventFieldList>,
            perform_insert_replace: PerformUpdateType,
        ) -> Result<Vec<StatusCode>, StatusCode> {
            self.calls.write().push(HistoryBackendCall::UpdateEvent {
                node_id: node_id.clone(),
                perform_insert_replace,
                entry_count: events.len(),
            });
            Ok(vec![StatusCode::Good, StatusCode::BadEventIdUnknown])
        }

        async fn delete_raw_modified(
            &self,
            node_id: &NodeId,
            is_delete_modified: bool,
            start_time: DateTime,
            end_time: DateTime,
        ) -> Result<StatusCode, StatusCode> {
            self.calls
                .write()
                .push(HistoryBackendCall::DeleteRawModified {
                    node_id: node_id.clone(),
                    is_delete_modified,
                    start_time,
                    end_time,
                });
            Ok(StatusCode::BadDataLost)
        }

        async fn delete_at_time(
            &self,
            node_id: &NodeId,
            req_times: Vec<DateTime>,
        ) -> Result<Vec<StatusCode>, StatusCode> {
            self.calls.write().push(HistoryBackendCall::DeleteAtTime {
                node_id: node_id.clone(),
                entry_count: req_times.len(),
            });
            Ok(vec![StatusCode::Good, StatusCode::BadNoData])
        }

        async fn delete_event(
            &self,
            node_id: &NodeId,
            event_ids: Vec<ByteString>,
        ) -> Result<Vec<StatusCode>, StatusCode> {
            self.calls.write().push(HistoryBackendCall::DeleteEvent {
                node_id: node_id.clone(),
                entry_count: event_ids.len(),
            });
            Ok(vec![StatusCode::BadEventIdUnknown])
        }
    }

    fn request_context() -> RequestContext {
        let (_server, handle) = ServerBuilder::new_anonymous("simple history update routing")
            .build()
            .expect("test server should build");
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
            IdentityToken::Anonymous(opcua_types::AnonymousIdentityToken {
                policy_id: UAString::from("anonymous"),
            }),
            None,
            ByteString::null(),
            UAString::from("test"),
            ApplicationDescription::default(),
            opcua_types::MessageSecurityMode::None,
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

    fn manager() -> SimpleNodeManagerImpl {
        SimpleNodeManagerImpl::new(
            Vec::new(),
            "history-update-test",
            NodeManagersRef::new_empty(),
        )
    }

    #[test]
    fn alarm_source_registry_starts_empty_and_is_reachable() {
        let manager = manager();
        let source = NodeId::new(1, "source");

        assert!(manager
            .alarm_source_registry()
            .alarms_for(&source)
            .is_empty());

        let condition = NodeId::new(1, "condition");
        let alarm = Arc::new(TestSourceAlarm {
            source: source.clone(),
            condition: condition.clone(),
        });

        manager
            .alarm_source_registry()
            .register(source.clone(), alarm);

        let alarms = manager.alarm_source_registry().alarms_for(&source);
        assert_eq!(alarms.len(), 1);
        assert_eq!(alarms[0].condition_id(), &condition);
    }

    #[test]
    fn monitor_alarm_source_sampled_registers_sampled_binding() {
        let manager = manager();
        let address_space = RwLock::new(AddressSpace::new());
        let source = NodeId::new(2, "sampled-source");
        let interval = Duration::from_millis(250);
        let alarm = {
            let mut space = address_space.write();
            space.add_namespace("urn:test:sampled", 2);
            space.add_variables(
                vec![crate::address_space::Variable::new(
                    &source,
                    "SampledSource",
                    "SampledSource",
                    0.0,
                )],
                &NodeId::from(opcua_types::ObjectId::ObjectsFolder),
            );

            let cfg = LimitConfig::new(LimitMode::Exclusive)
                .with_high(LimitDef {
                    value: 10.0,
                    deadband: 0.0,
                    severity: 500,
                })
                .build()
                .expect("limit config should be valid");

            LimitAlarm::create_exclusive_in_address_space(
                &mut space,
                2,
                "Device",
                "High",
                source.clone(),
                cfg,
            )
        };

        let alarm = manager.monitor_alarm_source_sampled_on_address_space(
            &address_space,
            &source,
            alarm,
            interval,
        );

        let sampled = manager.alarm_source_registry().sampled_bindings();
        assert_eq!(sampled.len(), 1);
        assert_eq!(sampled[0].0, source);
        assert_eq!(sampled[0].1.condition_id(), &alarm.condition.condition_id);
        assert_eq!(sampled[0].2, interval);
    }

    fn update_data_node(node_id: &NodeId, entry_count: usize) -> HistoryUpdateNode {
        HistoryUpdateNode::new(HistoryUpdateDetails::UpdateData(UpdateDataDetails {
            node_id: node_id.clone(),
            perform_insert_replace: PerformUpdateType::Insert,
            update_values: Some(vec![DataValue::default(); entry_count]),
        }))
    }

    fn update_structure_node(node_id: &NodeId, entry_count: usize) -> HistoryUpdateNode {
        HistoryUpdateNode::new(HistoryUpdateDetails::UpdateStructureData(
            UpdateStructureDataDetails {
                node_id: node_id.clone(),
                perform_insert_replace: PerformUpdateType::Replace,
                update_values: Some(vec![DataValue::default(); entry_count]),
            },
        ))
    }

    fn update_event_node(node_id: &NodeId, entry_count: usize) -> HistoryUpdateNode {
        HistoryUpdateNode::new(HistoryUpdateDetails::UpdateEvent(UpdateEventDetails {
            node_id: node_id.clone(),
            perform_insert_replace: PerformUpdateType::Update,
            filter: EventFilter::default(),
            event_data: Some(vec![HistoryEventFieldList::default(); entry_count]),
        }))
    }

    fn delete_raw_modified_node(
        node_id: &NodeId,
        start_time: DateTime,
        end_time: DateTime,
    ) -> HistoryUpdateNode {
        HistoryUpdateNode::new(HistoryUpdateDetails::DeleteRawModified(
            DeleteRawModifiedDetails {
                node_id: node_id.clone(),
                is_delete_modified: true,
                start_time,
                end_time,
            },
        ))
    }

    fn delete_at_time_node(node_id: &NodeId, req_times: Vec<DateTime>) -> HistoryUpdateNode {
        HistoryUpdateNode::new(HistoryUpdateDetails::DeleteAtTime(DeleteAtTimeDetails {
            node_id: node_id.clone(),
            req_times: Some(req_times),
        }))
    }

    fn delete_event_node(node_id: &NodeId, entry_count: usize) -> HistoryUpdateNode {
        HistoryUpdateNode::new(HistoryUpdateDetails::DeleteEvent(DeleteEventDetails {
            node_id: node_id.clone(),
            event_ids: Some(
                (0..entry_count)
                    .map(|i| ByteString::from(vec![i as u8]))
                    .collect(),
            ),
        }))
    }

    #[tokio::test]
    async fn history_update_without_backend_sets_node_statuses() {
        let manager = manager();
        let context = request_context();
        let node_id = NodeId::new(1, "without_backend");
        let mut update_data = update_data_node(&node_id, 1);
        let mut delete_raw =
            delete_raw_modified_node(&node_id, DateTime::from(10), DateTime::from(20));

        {
            let mut update_data_ref = &mut update_data;
            let mut delete_raw_ref = &mut delete_raw;
            let mut nodes = vec![&mut update_data_ref, &mut delete_raw_ref];

            assert_eq!(manager.history_update(&context, &mut nodes).await, Ok(()));
        }

        assert_eq!(
            update_data.status(),
            StatusCode::BadHistoryOperationUnsupported
        );
        assert_eq!(
            delete_raw.status(),
            StatusCode::BadHistoryOperationUnsupported
        );
        assert_eq!(update_data.into_result().operation_results, None);
        assert_eq!(delete_raw.into_result().operation_results, None);
    }

    #[tokio::test]
    async fn history_update_routes_all_details_to_backend() {
        let manager = manager();
        let context = request_context();
        let backend = Arc::new(RecordingHistoryBackend::default());
        manager.set_history_backend(backend.clone());

        let node_id = NodeId::new(1, "with_backend");
        let start_time = DateTime::from(10);
        let end_time = DateTime::from(20);
        let req_times = vec![DateTime::from(30), DateTime::from(40)];
        let mut update_data = update_data_node(&node_id, 2);
        let mut update_structure = update_structure_node(&node_id, 1);
        let mut update_event = update_event_node(&node_id, 2);
        let mut delete_raw = delete_raw_modified_node(&node_id, start_time, end_time);
        let mut delete_at_time = delete_at_time_node(&node_id, req_times);
        let mut delete_event = delete_event_node(&node_id, 1);

        {
            let mut update_data_ref = &mut update_data;
            let mut update_structure_ref = &mut update_structure;
            let mut update_event_ref = &mut update_event;
            let mut delete_raw_ref = &mut delete_raw;
            let mut delete_at_time_ref = &mut delete_at_time;
            let mut delete_event_ref = &mut delete_event;
            let mut nodes = vec![
                &mut update_data_ref,
                &mut update_structure_ref,
                &mut update_event_ref,
                &mut delete_raw_ref,
                &mut delete_at_time_ref,
                &mut delete_event_ref,
            ];

            assert_eq!(manager.history_update(&context, &mut nodes).await, Ok(()));
        }

        assert_eq!(
            backend.calls(),
            vec![
                HistoryBackendCall::UpdateData {
                    node_id: node_id.clone(),
                    perform_insert_replace: PerformUpdateType::Insert,
                    entry_count: 2,
                },
                HistoryBackendCall::UpdateStructureData {
                    node_id: node_id.clone(),
                    perform_insert_replace: PerformUpdateType::Replace,
                    entry_count: 1,
                },
                HistoryBackendCall::UpdateEvent {
                    node_id: node_id.clone(),
                    perform_insert_replace: PerformUpdateType::Update,
                    entry_count: 2,
                },
                HistoryBackendCall::DeleteRawModified {
                    node_id: node_id.clone(),
                    is_delete_modified: true,
                    start_time,
                    end_time,
                },
                HistoryBackendCall::DeleteAtTime {
                    node_id: node_id.clone(),
                    entry_count: 2,
                },
                HistoryBackendCall::DeleteEvent {
                    node_id,
                    entry_count: 1,
                },
            ]
        );

        let update_data = update_data.into_result();
        assert_eq!(update_data.status_code, StatusCode::Good);
        assert_eq!(
            update_data.operation_results,
            Some(vec![StatusCode::Good, StatusCode::BadNoData])
        );

        let update_structure = update_structure.into_result();
        assert_eq!(update_structure.status_code, StatusCode::Good);
        assert_eq!(
            update_structure.operation_results,
            Some(vec![StatusCode::BadOutOfRange])
        );

        let update_event = update_event.into_result();
        assert_eq!(update_event.status_code, StatusCode::Good);
        assert_eq!(
            update_event.operation_results,
            Some(vec![StatusCode::Good, StatusCode::BadEventIdUnknown])
        );

        let delete_raw = delete_raw.into_result();
        assert_eq!(delete_raw.status_code, StatusCode::BadDataLost);
        assert_eq!(delete_raw.operation_results, None);

        let delete_at_time = delete_at_time.into_result();
        assert_eq!(delete_at_time.status_code, StatusCode::Good);
        assert_eq!(
            delete_at_time.operation_results,
            Some(vec![StatusCode::Good, StatusCode::BadNoData])
        );

        let delete_event = delete_event.into_result();
        assert_eq!(delete_event.status_code, StatusCode::Good);
        assert_eq!(
            delete_event.operation_results,
            Some(vec![StatusCode::BadEventIdUnknown])
        );
    }
}
