//! InMemoryNodeManager that contains some basic metadata about the
//! simulation. This interface has static nodes, but some dynamic values.

use std::sync::Arc;

use async_trait::async_trait;
use opcua::{
    nodes::{ObjectBuilder, VariableBuilder},
    server::{
        address_space::AddressSpace,
        diagnostics::NamespaceMetadata,
        node_manager::{
            memory::{InMemoryNodeManagerImpl, InMemoryNodeManagerImplBuilder},
            ParsedReadValueId, RequestContext, ServerContext,
        },
    },
    sync::RwLock,
    types::{
        DataTypeId, DataValue, IdType, NodeId, ObjectId, StatusCode, TimestampsToReturn, Variant,
    },
};

use crate::sim::Simulation;

pub struct MetadataNodeManager {
    namespace: NamespaceMetadata,
    sim: Arc<RwLock<Simulation>>,
}

/*
Each node manager must define a builder. This is mostly to make sure we
have type-safe bootstrapping in the server, which really makes node managers
a lot cleaner.

If we didn't have builders like this, you would get situations where
node managers need some part of the core server, like the subscription cache,
but those aren't available until `init`, so you need to store them in `OnceLock`
or `Option`, which isn't great.
*/

pub struct MetadataNodeManagerBuilder {
    namespace: String,
    sim: Arc<RwLock<Simulation>>,
}

impl MetadataNodeManagerBuilder {
    pub fn new(namespace: &str, sim: Arc<RwLock<Simulation>>) -> Self {
        Self {
            namespace: namespace.to_owned(),
            sim,
        }
    }
}

impl InMemoryNodeManagerImplBuilder for MetadataNodeManagerBuilder {
    type Impl = MetadataNodeManager;
    fn build(self, context: ServerContext, address_space: &mut AddressSpace) -> Self::Impl {
        // This kind of pattern is very common in node managers. We need to register the namespace
        // we will use. If we had any custom reference types, we would need to add these here as well,
        // so that other node managers can use them.

        let mut type_tree = context.type_tree.write();
        // Add the namespace to the type tree and address space.
        let ns_index = type_tree.namespaces_mut().add_namespace(&self.namespace);
        address_space.add_namespace(&self.namespace, ns_index);

        MetadataNodeManager {
            namespace: NamespaceMetadata {
                is_namespace_subset: Some(false),
                namespace_uri: self.namespace,
                static_node_id_types: Some(vec![IdType::Numeric]),
                namespace_index: ns_index,
                ..Default::default()
            },
            sim: self.sim,
        }
    }
}

const ROOT_NODE: u32 = 1;
pub const CURRENT_TICK: u32 = 2;
pub const TAGS_ROOT_NODE: u32 = 3;

impl MetadataNodeManager {
    fn node_id(&self, id: u32) -> NodeId {
        NodeId::new(self.namespace.namespace_index, id)
    }
}

#[async_trait]
impl InMemoryNodeManagerImpl for MetadataNodeManager {
    /// Populate the address space.
    async fn init(&self, address_space: &mut AddressSpace, _context: ServerContext) {
        // Populate the static address space
        ObjectBuilder::new(&self.node_id(ROOT_NODE), "Simulation", "Simulation")
            .organized_by(ObjectId::ObjectsFolder)
            .description("Metadata about the simulation")
            .insert(address_space);
        VariableBuilder::new(&self.node_id(CURRENT_TICK), "CurrentTick", "Current tick")
            .component_of(self.node_id(ROOT_NODE))
            .description("The current internal simulation time")
            .data_type(DataTypeId::UInt64)
            .value(0u64)
            .insert(address_space);
        ObjectBuilder::new(&self.node_id(TAGS_ROOT_NODE), "Tags", "Tags")
            .organized_by(ObjectId::ObjectsFolder)
            .description("All simulated tags")
            .insert(address_space);
    }

    /// Name of this node manager, for debug purposes.
    fn name(&self) -> &str {
        "metadata"
    }

    /// Return the static list of namespaces this node manager uses.
    fn namespaces(&self) -> Vec<NamespaceMetadata> {
        vec![self.namespace.clone()]
    }

    async fn read_values(
        &self,
        _context: &RequestContext,
        _address_space: &RwLock<AddressSpace>,
        nodes: &[&ParsedReadValueId],
        _max_age: f64,
        _timestamps_to_return: TimestampsToReturn,
    ) -> Vec<DataValue> {
        // The only callback we really need to register in an InMemoryNodeManager.
        // This method must read values from the underlying system.
        // In this case, we only have the current_tick node, so we read for that.

        let mut res = Vec::new();
        for node in nodes {
            // Should generally be impossible, nodes should always be known here.
            let Some(value) = node.node_id.as_u32() else {
                res.push(DataValue::new_now_status(
                    Variant::Empty,
                    StatusCode::BadNodeIdUnknown,
                ));
                continue;
            };

            let (value, time) = match value {
                2 => self.sim.read().get_current_tick(),
                _ => {
                    res.push(DataValue::new_now_status(
                        Variant::Empty,
                        StatusCode::BadNodeIdUnknown,
                    ));
                    continue;
                }
            };

            res.push(DataValue::new_at(value, time));
        }

        res
    }
}
