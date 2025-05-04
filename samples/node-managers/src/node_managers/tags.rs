use std::{collections::VecDeque, sync::Arc};

use async_trait::async_trait;
use opcua::{
    nodes::{AccessLevel, DefaultTypeTree, ReferenceDirection},
    server::{
        diagnostics::NamespaceMetadata,
        node_manager::{
            as_opaque_node_id, from_opaque_node_id, impl_translate_browse_paths_using_browse,
            AddReferenceResult, BrowseNode, BrowsePathItem, ExternalReference,
            ExternalReferenceRequest, NodeManager, NodeManagerBuilder, NodeMetadata,
            ParsedReadValueId, ReadNode, RequestContext, ServerContext,
        },
        CreateMonitoredItem,
    },
    sync::RwLock,
    types::{
        AccessLevelExType, DataTypeId, DataValue, IdType, Identifier, LocalizedText, NodeClass,
        NodeId, QualifiedName, ReferenceDescription, ReferenceTypeId, StatusCode,
        TimestampsToReturn, VariableTypeId, Variant, WriteMask,
    },
};
use serde::{Deserialize, Serialize};

use crate::sim::{Simulation, TagMeta};

use super::metadata::TAGS_ROOT_NODE;

pub struct TagNodeManagerBuilder {
    namespace: String,
    meta_namespace: String,
    sim: Arc<RwLock<Simulation>>,
}

impl TagNodeManagerBuilder {
    pub fn new(namespace: &str, meta_namespace: &str, sim: Arc<RwLock<Simulation>>) -> Self {
        Self {
            namespace: namespace.to_owned(),
            meta_namespace: meta_namespace.to_owned(),
            sim,
        }
    }
}

impl NodeManagerBuilder for TagNodeManagerBuilder {
    fn build(
        self: Box<Self>,
        context: ServerContext,
    ) -> Arc<opcua::server::node_manager::DynNodeManager> {
        // See `metadata.rs` for some more explanation of builders.
        // Here we just register the namespace in the type tree, so that it
        // is globally available.
        // We aren't strictly speaking required to do this, but it's nice to have.
        let mut type_tree = context.type_tree.write();
        let ns_index = type_tree.namespaces_mut().add_namespace(&self.namespace);

        Arc::new(TagNodeManager {
            namespace: NamespaceMetadata {
                is_namespace_subset: Some(false),
                namespace_index: ns_index,
                namespace_uri: self.namespace,
                static_node_id_types: Some(vec![IdType::String, IdType::Opaque]),
                ..Default::default()
            },
            // Note that `add_namespace` is idempotent. If you call it multiple times
            // it will return the same index each time, so we can safely call it
            // here, even if the metadata node manager has already added the namespace.
            meta_namespace_index: type_tree
                .namespaces_mut()
                .add_namespace(&self.meta_namespace),
            sim: self.sim,
        })
    }
}

pub struct TagNodeManager {
    namespace: NamespaceMetadata,
    meta_namespace_index: u16,
    sim: Arc<RwLock<Simulation>>,
}

#[async_trait]
impl NodeManager for TagNodeManager {
    fn owns_node(&self, id: &NodeId) -> bool {
        // This method must return whether a node is "owned" by this node manager.
        // This is _not_ a check for whether this node exists, just that if it
        // _did_ exist, it would be owned by this node manager.
        // Typically this is a check by namespace, but it isn't required to be.
        // A node manager can own multiple namespaces, part of a namespace, or
        // anything else. You should avoid having overlapping ownership though,
        // as that may cause unexpected behavior. In some cases _both_ node managers
        // would get the node, in other cases only the first.
        id.namespace == self.namespace.namespace_index
    }

    fn name(&self) -> &str {
        "tags"
    }

    fn namespaces_for_user(&self, _context: &RequestContext) -> Vec<NamespaceMetadata> {
        vec![self.namespace.clone()]
    }

    async fn init(&self, _type_tree: &mut DefaultTypeTree, _context: ServerContext) {}

    async fn resolve_external_references(
        &self,
        _context: &RequestContext,
        items: &mut [&mut ExternalReferenceRequest],
    ) {
        // This method resolves external references returned from other node managers.
        // Technically we don't need to implement this here, since no other node manager
        // should return a reference here, but it's good practice to do so, and not
        // very hard if you're already using `NodeMetadata` like we are.
        let sim = self.sim.read();

        for item in items {
            let Some(id) = self.parse_node_id(item.node_id()) else {
                continue;
            };
            let Some(meta) = self.get_node_metadata(&sim, &id) else {
                continue;
            };
            item.set(meta);
        }
    }

    async fn browse(
        &self,
        context: &RequestContext,
        nodes_to_browse: &mut [BrowseNode],
    ) -> Result<(), StatusCode> {
        // Browse should return any references to and from nodes owned by this node manager.
        // This service gets _all_ nodes being browsed, even if they are not owned by
        // this node manager.
        let sim = self.sim.read();
        let type_tree = context.type_tree.read();

        for node in nodes_to_browse {
            if let Err(e) = self.browse_node(&sim, node, &type_tree) {
                node.set_status(e);
            } else if self.owns_node(node.node_id()) {
                node.set_status(StatusCode::Good);
            }
        }
        Ok(())
    }

    async fn read(
        &self,
        _context: &RequestContext,
        _max_age: f64,
        _timestamps_to_return: TimestampsToReturn,
        nodes_to_read: &mut [&mut ReadNode],
    ) -> Result<(), StatusCode> {
        // Read gets attribute values for nodes owned by this node manager.
        let sim = self.sim.read();

        for node in nodes_to_read {
            match self.read_node(&sim, node.node()) {
                Ok(v) => {
                    node.set_result(v);
                }
                Err(e) => {
                    node.set_error(e);
                }
            }
        }

        Ok(())
    }

    async fn translate_browse_paths_to_node_ids(
        &self,
        context: &RequestContext,
        nodes: &mut [&mut BrowsePathItem],
    ) -> Result<(), StatusCode> {
        // Translate browse paths is a bit of a niche service. Most clients
        // will only use them when dealing with methods. Because of this,
        // and the complexity of implementing it, we offer a generic implementation
        // that uses `browse` to implement it, calling browse multiple times.

        // If you have high overhead on individual browse calls, and you expect
        // this service to be used a lot, you should consider manually implementing it.
        impl_translate_browse_paths_using_browse(self, context, nodes).await
    }

    async fn create_monitored_items(
        &self,
        _context: &RequestContext,
        items: &mut [&mut CreateMonitoredItem],
    ) -> Result<(), StatusCode> {
        // We rely on directly notifying the subscription cache of changes,
        // so we don't need to take additional action here. Instead we just
        // read the current value of each and set the initial values.
        let sim = self.sim.read();
        for item in items {
            match self.read_node(&sim, item.item_to_monitor()) {
                Ok(v) => {
                    item.set_initial_value(v);
                    item.set_status(StatusCode::Good);
                }
                Err(e) => {
                    item.set_status(e);
                }
            }
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct TagMetaId {
    tag: String,
    meta: String,
}

enum ParsedNodeId {
    Tag(String),
    Meta(TagMetaId),
}

// In custom node managers we need to handle browse continuation. In this
// case we're going to be lazy and simply keep a queue of yet-to-be-submitted nodes.
// If the potential number of nodes is very high this may not be a good idea, in which
// case you need some smarter cursoring scheme.
#[derive(Default)]
struct BrowseContinuationPoint {
    nodes: VecDeque<ReferenceDescription>,
}

impl TagNodeManager {
    fn parse_node_id(&self, id: &NodeId) -> Option<ParsedNodeId> {
        if id.namespace != self.namespace.namespace_index {
            return None;
        }

        if let Some(parsed) = from_opaque_node_id(id) {
            return Some(ParsedNodeId::Meta(parsed));
        }

        if let Identifier::String(s) = &id.identifier {
            return Some(ParsedNodeId::Tag(s.to_string()));
        }

        None
    }

    fn get_node_metadata_tag(&self, tag: &TagMeta<'_>) -> NodeMetadata {
        NodeMetadata {
            node_id: NodeId::new(self.namespace.namespace_index, tag.tag.to_owned()).into(),
            type_definition: VariableTypeId::BaseDataVariableType.into(),
            browse_name: QualifiedName::new(self.namespace.namespace_index, tag.tag),
            display_name: LocalizedText::new("en", tag.name),
            node_class: NodeClass::Variable,
        }
    }

    fn get_node_metadata(&self, sim: &Simulation, id: &ParsedNodeId) -> Option<NodeMetadata> {
        match id {
            ParsedNodeId::Tag(t) => {
                let tag = sim.get_tag_meta(t)?;
                Some(self.get_node_metadata_tag(&tag))
            }
            ParsedNodeId::Meta(tag_meta_id) => {
                let tag = sim.get_tag_meta(&tag_meta_id.tag)?;
                tag.metadata.get(&tag_meta_id.meta)?;
                let id = as_opaque_node_id(tag_meta_id, self.namespace.namespace_index)?;
                Some(NodeMetadata {
                    node_id: id.into(),
                    type_definition: VariableTypeId::PropertyType.into(),
                    browse_name: QualifiedName::new(
                        self.namespace.namespace_index,
                        &tag_meta_id.meta,
                    ),
                    display_name: LocalizedText::new("en", &tag_meta_id.meta),
                    node_class: NodeClass::Variable,
                })
            }
        }
    }

    fn browse_root_node(
        &self,
        sim: &Simulation,
        node_to_browse: &mut BrowseNode,
        type_tree: &DefaultTypeTree,
    ) {
        // Browse is unique in that it gets nodes that the active node manager does _not_ own.
        // We can use this to return all our tags, by handling browse for the root node.

        let mut cp = BrowseContinuationPoint::default();

        // In this case, we only need to care about references that _we_ own, so we don't need to
        // return inverse references, or type definition references for the root node.
        if node_to_browse.allows_forward()
            && node_to_browse.allows_reference_type(&ReferenceTypeId::Organizes.into(), type_tree)
            && node_to_browse.allows_node_class(NodeClass::Variable)
        {
            for tag in sim.iter_tag_meta() {
                let meta = self.get_node_metadata_tag(&tag);

                if let AddReferenceResult::Full(c) = node_to_browse.add(
                    type_tree,
                    meta.into_ref_desc(true, ReferenceTypeId::Organizes),
                ) {
                    cp.nodes.push_back(c);
                }
            }
        }

        if !cp.nodes.is_empty() {
            node_to_browse.set_next_continuation_point(Box::new(cp));
        }
    }

    fn browse_node(
        &self,
        sim: &Simulation,
        node_to_browse: &mut BrowseNode,
        type_tree: &DefaultTypeTree,
    ) -> Result<(), StatusCode> {
        if node_to_browse.node_id().namespace == self.meta_namespace_index
            && node_to_browse.node_id().as_u32() == Some(TAGS_ROOT_NODE)
        {
            self.browse_root_node(sim, node_to_browse, type_tree);
            return Ok(());
        }

        let Some(id) = self.parse_node_id(node_to_browse.node_id()) else {
            // Only return an error here if we actually know that the node doesn't exist.
            // If it may be owned by a different node manager, just ignore it.
            if self.owns_node(node_to_browse.node_id()) {
                return Err(StatusCode::BadNodeIdUnknown);
            } else {
                return Ok(());
            }
        };

        let mut cp = BrowseContinuationPoint::default();

        match id {
            ParsedNodeId::Tag(t) => {
                let Some(tag) = sim.get_tag_meta(&t) else {
                    return Err(StatusCode::BadNodeIdUnknown);
                };

                // Add references to metadata nodes.
                // We do a quick check for known properties of the reference type,
                // but we don't _have_ to make these checks. `node_to_browse.add` does them
                // as well.
                if node_to_browse
                    .allows_reference_type(&ReferenceTypeId::HasProperty.into(), type_tree)
                    && node_to_browse.allows_node_class(NodeClass::Variable)
                    && node_to_browse.allows_forward()
                {
                    for k in tag.metadata.keys() {
                        let Some(meta) = self.get_node_metadata(
                            sim,
                            &ParsedNodeId::Meta(TagMetaId {
                                tag: t.clone(),
                                meta: k.clone(),
                            }),
                        ) else {
                            continue;
                        };

                        if let AddReferenceResult::Full(c) = node_to_browse.add(
                            type_tree,
                            meta.into_ref_desc(true, ReferenceTypeId::HasProperty),
                        ) {
                            cp.nodes.push_back(c);
                        }
                    }
                }

                // Add references to the root node.
                // This is an "external" reference, meaning it points to a different node manager.
                // You could have created the correct reference description here, this is an
                // easy way to forward the request to a different node manager, in part.
                if node_to_browse
                    .allows_reference_type(&ReferenceTypeId::Organizes.into(), type_tree)
                    && node_to_browse.allows_node_class(NodeClass::Object)
                    && node_to_browse.allows_inverse()
                {
                    node_to_browse.push_external_reference(ExternalReference::new(
                        NodeId::new(self.meta_namespace_index, super::metadata::TAGS_ROOT_NODE)
                            .into(),
                        ReferenceTypeId::Organizes.into(),
                        ReferenceDirection::Inverse,
                    ));
                }

                // Add a reference to the type definition of the node.
                if node_to_browse
                    .allows_reference_type(&ReferenceTypeId::HasTypeDefinition.into(), type_tree)
                    && node_to_browse.allows_node_class(NodeClass::VariableType)
                    && node_to_browse.allows_forward()
                {
                    node_to_browse.push_external_reference(ExternalReference::new(
                        VariableTypeId::BaseDataVariableType.into(),
                        ReferenceTypeId::HasTypeDefinition.into(),
                        ReferenceDirection::Forward,
                    ));
                }
            }
            ParsedNodeId::Meta(tag_meta_id) => {
                let Some(tag) = sim.get_tag_meta(&tag_meta_id.tag) else {
                    return Err(StatusCode::BadNodeIdUnknown);
                };
                if !tag.metadata.contains_key(&tag_meta_id.tag) {
                    return Err(StatusCode::BadNodeIdUnknown);
                }

                if node_to_browse.allows_inverse()
                    && node_to_browse
                        .allows_reference_type(&ReferenceTypeId::HasProperty.into(), type_tree)
                    && node_to_browse.allows_node_class(NodeClass::Variable)
                {
                    let Some(meta) =
                        self.get_node_metadata(sim, &ParsedNodeId::Tag(tag_meta_id.tag.clone()))
                    else {
                        // Should be impossible
                        return Err(StatusCode::BadNodeIdUnknown);
                    };

                    if let AddReferenceResult::Full(c) = node_to_browse.add(
                        type_tree,
                        meta.into_ref_desc(true, ReferenceTypeId::HasProperty),
                    ) {
                        cp.nodes.push_back(c);
                    }
                }

                // Add a reference to the type definition of the node.
                if node_to_browse
                    .allows_reference_type(&ReferenceTypeId::HasTypeDefinition.into(), type_tree)
                    && node_to_browse.allows_node_class(NodeClass::VariableType)
                    && node_to_browse.allows_forward()
                {
                    node_to_browse.push_external_reference(ExternalReference::new(
                        VariableTypeId::PropertyType.into(),
                        ReferenceTypeId::HasTypeDefinition.into(),
                        ReferenceDirection::Forward,
                    ));
                }
            }
        }

        if !cp.nodes.is_empty() {
            node_to_browse.set_next_continuation_point(Box::new(cp));
        }

        Ok(())
    }

    fn read_node(
        &self,
        sim: &Simulation,
        node: &ParsedReadValueId,
    ) -> Result<DataValue, StatusCode> {
        let Some(id) = self.parse_node_id(&node.node_id) else {
            return Err(StatusCode::BadNodeIdUnknown);
        };

        // Here we need to enumerate over each attribute we support, and
        // translate them to the corresponding value in the underlying system.

        match id {
            ParsedNodeId::Tag(t) => {
                let Some(tag) = sim.get_tag_meta(&t) else {
                    return Err(StatusCode::BadNodeIdUnknown);
                };
                let val: Variant = match node.attribute_id {
                    opcua::types::AttributeId::NodeId => {
                        NodeId::new(self.namespace.namespace_index, t.clone()).into()
                    }
                    opcua::types::AttributeId::NodeClass => NodeClass::Variable.into(),
                    opcua::types::AttributeId::BrowseName => {
                        QualifiedName::new(self.namespace.namespace_index, tag.tag).into()
                    }
                    opcua::types::AttributeId::DisplayName => {
                        LocalizedText::new("en", tag.name).into()
                    }
                    opcua::types::AttributeId::Description => {
                        LocalizedText::new("en", tag.description).into()
                    }
                    opcua::types::AttributeId::WriteMask => WriteMask::empty().bits().into(),
                    opcua::types::AttributeId::UserWriteMask => WriteMask::empty().bits().into(),
                    opcua::types::AttributeId::Value => tag.value.get_value(),
                    opcua::types::AttributeId::DataType => {
                        NodeId::from(tag.value.data_type()).into()
                    }
                    opcua::types::AttributeId::ValueRank => (-1i32).into(),
                    opcua::types::AttributeId::AccessLevel => {
                        AccessLevel::CURRENT_READ.bits().into()
                    }
                    opcua::types::AttributeId::UserAccessLevel => {
                        AccessLevel::CURRENT_READ.bits().into()
                    }
                    opcua::types::AttributeId::MinimumSamplingInterval => 0f64.into(),
                    opcua::types::AttributeId::Historizing => false.into(),
                    opcua::types::AttributeId::AccessLevelEx => {
                        // TODO: The type here is wrong, bug in the codegen?
                        // Looks like we generate bitfields as i32, even if they inherit from UInt32.
                        // I think it's because BSD files don't distinguish between the two.
                        // Fixable now that we use NodeSet2 files.
                        (AccessLevelExType::CurrentRead.bits() as u32).into()
                    }
                    _ => return Err(StatusCode::BadAttributeIdInvalid),
                };

                Ok(DataValue::new_at(val, tag.modified_time))
            }
            ParsedNodeId::Meta(tag_meta_id) => {
                let Some(tag) = sim.get_tag_meta(&tag_meta_id.tag) else {
                    return Err(StatusCode::BadNodeIdUnknown);
                };
                let Some(meta) = tag.metadata.get(&tag_meta_id.meta) else {
                    return Err(StatusCode::BadNodeIdUnknown);
                };

                let val: Variant = match node.attribute_id {
                    opcua::types::AttributeId::NodeId => node.node_id.clone().into(),
                    opcua::types::AttributeId::NodeClass => NodeClass::Variable.into(),
                    opcua::types::AttributeId::BrowseName => {
                        QualifiedName::new(self.namespace.namespace_index, tag_meta_id.meta).into()
                    }
                    opcua::types::AttributeId::DisplayName => {
                        LocalizedText::new("en", &tag_meta_id.meta).into()
                    }
                    opcua::types::AttributeId::WriteMask => WriteMask::empty().bits().into(),
                    opcua::types::AttributeId::UserWriteMask => WriteMask::empty().bits().into(),
                    opcua::types::AttributeId::Value => meta.clone().into(),
                    opcua::types::AttributeId::DataType => NodeId::from(DataTypeId::String).into(),
                    // TODO: Write a proper type for ValueRank. I messed up twice remembering what the
                    // value for "scalar" was. Maybe a nice enum?
                    opcua::types::AttributeId::ValueRank => (-1i32).into(),
                    opcua::types::AttributeId::AccessLevel => {
                        AccessLevel::CURRENT_READ.bits().into()
                    }
                    opcua::types::AttributeId::UserAccessLevel => {
                        AccessLevel::CURRENT_READ.bits().into()
                    }
                    opcua::types::AttributeId::MinimumSamplingInterval => 0f64.into(),
                    opcua::types::AttributeId::Historizing => false.into(),
                    opcua::types::AttributeId::AccessLevelEx => {
                        (AccessLevelExType::CurrentRead.bits() as u32).into()
                    }
                    _ => return Err(StatusCode::BadAttributeIdInvalid),
                };

                Ok(DataValue::new_at(val, tag.modified_time))
            }
        }
    }
}
