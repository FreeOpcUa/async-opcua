//! Implementation of [AddressSpace], and in-memory OPC-UA address space.

mod utils;

pub use opcua_nodes::*;
pub use utils::*;

#[cfg(feature = "generated-address-space")]
pub use opcua_core_namespace::CoreNamespace;

use std::collections::VecDeque;

use hashbrown::{HashMap, HashSet};
use tracing::{debug, error, info, warn};

use crate::node_manager::{ParsedReadValueId, ParsedWriteValue, RequestContext};
use opcua_types::{
    BrowseDirection, DataValue, LocalizedText, NodeClass, NodeId, QualifiedName, ReferenceTypeId,
    StatusCode, TimestampsToReturn,
};

/// Represents an in-memory address space.
#[derive(Default)]
pub struct AddressSpace {
    node_map: HashMap<NodeId, NodeType>,
    namespaces: HashMap<u16, String>,
    references: References,
}

impl AddressSpace {
    /// Create a new empty address space.
    pub fn new() -> Self {
        Self {
            node_map: HashMap::new(),
            namespaces: HashMap::new(),
            references: References::new(),
        }
    }

    /// Import a node set into this address space.
    /// This will register namespaces from the node set import.
    pub fn import_node_set<T: NodeSetImport + ?Sized>(
        &mut self,
        import: &T,
        namespaces: &mut NamespaceMap,
    ) {
        let mut map = NodeSetNamespaceMapper::new(namespaces);
        import.register_namespaces(&mut map);
        let owned_namespaces = import.get_own_namespaces();
        for ns in owned_namespaces {
            let idx = map
                .namespaces()
                .known_namespaces()
                .get(&ns)
                .expect("Node import returned owned namespace not added to the namespace map");
            self.add_namespace(&ns, *idx);
        }
        let mut count = 0;
        for item in import.load(&map) {
            count += 1;
            self.import_node(item);
        }
        info!("Imported {count} nodes");
    }

    /// Load types from this address space into the given type tree.
    pub fn load_into_type_tree(&self, type_tree: &mut DefaultTypeTree) {
        let mut found_ids = VecDeque::new();
        // Populate types first so that we have reference types to browse in the next stage.
        for node in self.node_map.values() {
            let nc = node.node_class();
            if !matches!(
                nc,
                NodeClass::DataType
                    | NodeClass::ObjectType
                    | NodeClass::VariableType
                    | NodeClass::ReferenceType
            ) {
                continue;
            }

            let node_id = node.node_id();

            let parent = self
                .references
                .find_references(
                    node_id,
                    Some((ReferenceTypeId::HasSubtype, false)),
                    type_tree,
                    BrowseDirection::Inverse,
                )
                .next();

            // If a node somehow lacks a super-type, insert it as a child of the relevant base type.
            let parent_id = if let Some(parent) = parent {
                parent.target_node.clone()
            } else {
                continue;
            };

            type_tree.add_type_node(node_id, &parent_id, nc);
            found_ids.push_back((node_id, node_id, Vec::new(), nc));
        }

        let mut seen_nodes = HashSet::new();

        // Recursively browse each discovered type for non-type children
        while let Some((node, root_type, path, node_class)) = found_ids.pop_front() {
            for child in self.find_references(
                node,
                Some((ReferenceTypeId::HierarchicalReferences, true)),
                type_tree,
                BrowseDirection::Forward,
            ) {
                if child
                    .reference_type
                    .as_reference_type_id()
                    .is_ok_and(|r| r == ReferenceTypeId::HasSubtype)
                {
                    continue;
                }
                let Some(node_type) = self.node_map.get(child.target_node) else {
                    continue;
                };

                let nc = node_type.node_class();

                if matches!(
                    nc,
                    NodeClass::DataType
                        | NodeClass::ObjectType
                        | NodeClass::VariableType
                        | NodeClass::ReferenceType
                ) {
                    continue;
                }
                let mut path = path.clone();
                path.push(node_type.as_node().browse_name());

                if !seen_nodes.insert(child.target_node) {
                    warn!(
                        "Found node {} more than once when browsing hierarchically",
                        child.target_node
                    );
                    continue;
                }

                found_ids.push_back((child.target_node, root_type, path, nc));
            }

            if !path.is_empty() {
                type_tree.add_type_property(node, root_type, &path, node_class);
            }
        }
    }

    /// Add a namespace to this address space.
    pub fn add_namespace(&mut self, namespace: &str, index: u16) {
        self.namespaces.insert(index, namespace.to_string());
    }

    /// Insert a node and a list of references from/to that node.
    pub fn insert<'a, T, S>(
        &mut self,
        node: T,
        references: Option<&'a [(&'a NodeId, &S, ReferenceDirection)]>,
    ) -> bool
    where
        T: Into<NodeType>,
        S: Into<NodeId> + Clone,
    {
        let node_type = node.into();
        let node_id = node_type.node_id().clone();

        self.assert_namespace(&node_id);

        if self.node_exists(&node_id) {
            error!("This node {} already exists", node_id);
            false
        } else {
            // If references are supplied, add them now
            if let Some(references) = references {
                self.references.insert::<S>(&node_id, references);
            }
            self.node_map.insert(node_id, node_type);

            true
        }
    }

    /// Import a node from an [ImportedItem].
    pub fn import_node(&mut self, node: ImportedItem) -> bool {
        let node_id = node.node.node_id().clone();

        self.assert_namespace(&node_id);
        if self.node_exists(&node_id) {
            error!("This node {} already exists", node_id);
            false
        } else {
            self.node_map.insert(node_id.clone(), node.node);
            for r in node.references {
                self.references.import_reference(node_id.clone(), r);
            }

            true
        }
    }

    /// Get the namespace index of the given namespace URI.
    pub fn namespace_index(&self, namespace: &str) -> Option<u16> {
        self.namespaces
            .iter()
            .find(|(_, ns)| namespace == ns.as_str())
            .map(|(i, _)| *i)
    }

    fn assert_namespace(&self, node_id: &NodeId) {
        if !self.namespaces.contains_key(&node_id.namespace) {
            panic!("Namespace index {} not in address space", node_id.namespace);
        }
    }

    /// Return `true` if the node with the given node ID exists in this address space.
    pub fn node_exists(&self, node_id: &NodeId) -> bool {
        self.node_map.contains_key(node_id)
    }

    /// Insert a references from `source_node` to `target_node` with
    /// the given reference type.
    pub fn insert_reference(
        &mut self,
        source_node: &NodeId,
        target_node: &NodeId,
        reference_type: impl Into<NodeId>,
    ) {
        self.references
            .insert_reference(source_node, target_node, reference_type)
    }

    /// Insert a list of references.
    pub fn insert_references<'a>(
        &mut self,
        references: impl Iterator<Item = (&'a NodeId, &'a NodeId, impl Into<NodeId>)>,
    ) {
        self.references.insert_references(references)
    }

    /// Delete a reference.
    pub fn delete_reference(
        &mut self,
        source_node: &NodeId,
        target_node: &NodeId,
        reference_type: impl Into<NodeId>,
    ) -> bool {
        self.references
            .delete_reference(source_node, target_node, reference_type)
    }

    /// Delete references starting at or pointing to the given node.
    pub fn delete_node_references(
        &mut self,
        source_node: &NodeId,
        delete_target_references: bool,
    ) -> bool {
        self.references
            .delete_node_references(source_node, delete_target_references)
    }

    /// Check if the reference given by `source_node`, `target_node` and
    /// `reference_type` exists in the address space.
    pub fn has_reference(
        &self,
        source_node: &NodeId,
        target_node: &NodeId,
        reference_type: impl Into<NodeId>,
    ) -> bool {
        self.references
            .has_reference(source_node, target_node, reference_type)
    }

    /// Return a lazy iterator over references starting at `source_node`
    /// that match `filter`.
    pub fn find_references<'a: 'b, 'b>(
        &'a self,
        source_node: &'b NodeId,
        filter: Option<(impl Into<NodeId>, bool)>,
        type_tree: &'b dyn TypeTree,
        direction: BrowseDirection,
    ) -> impl Iterator<Item = ReferenceRef<'a>> + 'b {
        self.references
            .find_references(source_node, filter, type_tree, direction)
    }

    /// Find a child of `source_node` matching the given `filter` with
    /// browse name equal to `browse_name`.
    pub fn find_node_by_browse_name<'a: 'b, 'b>(
        &'a self,
        source_node: &'b NodeId,
        filter: Option<(impl Into<NodeId>, bool)>,
        type_tree: &'b dyn TypeTree,
        direction: BrowseDirection,
        browse_name: impl Into<QualifiedName>,
    ) -> Option<&'a NodeType> {
        let name = browse_name.into();
        for rf in self.find_references(source_node, filter, type_tree, direction) {
            let node = self.find_node(rf.target_node);
            if let Some(node) = node {
                if node.as_node().browse_name() == &name {
                    return Some(node);
                }
            }
        }
        None
    }

    /// Find a node by traversing a browse path starting from `source_node`.
    /// All traversed references must match `filter`.
    pub fn find_node_by_browse_path<'a: 'b, 'b>(
        &'a self,
        source_node: &'b NodeId,
        filter: Option<(impl Into<NodeId>, bool)>,
        type_tree: &'b dyn TypeTree,
        direction: BrowseDirection,
        browse_path: &[QualifiedName],
    ) -> Option<&'a NodeType> {
        let mut node = self.find_node(source_node)?;
        let filter: Option<(NodeId, bool)> = filter.map(|(id, c)| (id.into(), c));
        for path_elem in browse_path {
            let mut found = false;
            for rf in self.find_references(node.node_id(), filter.clone(), type_tree, direction) {
                let child = self.find_node(rf.target_node);
                if let Some(child) = child {
                    if child.as_node().browse_name() == path_elem {
                        node = child;
                        found = true;
                        break;
                    }
                }
            }
            if !found {
                return None;
            }
        }
        Some(node)
    }

    /// Get the inner namespace map.
    pub fn namespaces(&self) -> &HashMap<u16, String> {
        &self.namespaces
    }

    /// Find node by something that can be turned into a node id and return a reference to it.
    pub fn find<N>(&self, node_id: N) -> Option<&NodeType>
    where
        N: Into<NodeId>,
    {
        self.find_node(&node_id.into())
    }

    /// Find node by something that can be turned into a node id and return a mutable reference to it.
    pub fn find_mut<N>(&mut self, node_id: N) -> Option<&mut NodeType>
    where
        N: Into<NodeId>,
    {
        self.find_node_mut(&node_id.into())
    }

    /// Finds a node by its node id and returns a reference to it.
    pub fn find_node(&self, node_id: &NodeId) -> Option<&NodeType> {
        self.node_map.get(node_id)
    }

    /// Finds a node by its node id and returns a mutable reference to it.
    pub fn find_node_mut(&mut self, node_id: &NodeId) -> Option<&mut NodeType> {
        self.node_map.get_mut(node_id)
    }

    /// Check if the read is allowed.
    pub fn validate_node_read<'a>(
        &'a self,
        context: &RequestContext,
        node_to_read: &ParsedReadValueId,
    ) -> Result<&'a NodeType, StatusCode> {
        let Some(node) = self.find(&node_to_read.node_id) else {
            debug!(
                "read_node_value result for read node id {}, attribute {:?} cannot find node",
                node_to_read.node_id, node_to_read.attribute_id
            );
            return Err(StatusCode::BadNodeIdUnknown);
        };

        validate_node_read(node, context, node_to_read)?;

        Ok(node)
    }

    /// Invoke the `Read` service on the given node, returning the
    /// data value. The returned data value can be an error.
    pub fn read(
        &self,
        context: &RequestContext,
        node_to_read: &ParsedReadValueId,
        max_age: f64,
        timestamps_to_return: TimestampsToReturn,
    ) -> DataValue {
        let node = match self.validate_node_read(context, node_to_read) {
            Ok(n) => n,
            Err(e) => {
                return DataValue {
                    status: Some(e),
                    ..Default::default()
                };
            }
        };

        read_node_value(node, context, node_to_read, max_age, timestamps_to_return)
    }

    /// Check if the given write is allowed.
    pub fn validate_node_write<'a>(
        &'a mut self,
        context: &RequestContext,
        node_to_write: &ParsedWriteValue,
        type_tree: &dyn TypeTree,
    ) -> Result<&'a mut NodeType, StatusCode> {
        let Some(node) = self.find_mut(&node_to_write.node_id) else {
            debug!(
                "write_node_value result for read node id {}, attribute {:?} cannot find node",
                node_to_write.node_id, node_to_write.attribute_id
            );
            return Err(StatusCode::BadNodeIdUnknown);
        };

        validate_node_write(node, context, node_to_write, type_tree)?;

        Ok(node)
    }

    /// Remove a node from the address space.
    pub fn delete(&mut self, node_id: &NodeId, delete_target_references: bool) -> Option<NodeType> {
        let n = self.node_map.remove(node_id);
        self.references
            .delete_node_references(node_id, delete_target_references);

        n
    }

    /// Add a `FolderType` node.
    pub fn add_folder(
        &mut self,
        node_id: &NodeId,
        browse_name: impl Into<QualifiedName>,
        display_name: impl Into<LocalizedText>,
        parent_node_id: &NodeId,
    ) -> bool {
        self.assert_namespace(node_id);
        ObjectBuilder::new(node_id, browse_name, display_name)
            .is_folder()
            .organized_by(parent_node_id.clone())
            .insert(self)
    }

    /// Add a list of variables to the address space.
    pub fn add_variables(
        &mut self,
        variables: Vec<Variable>,
        parent_node_id: &NodeId,
    ) -> Vec<bool> {
        variables
            .into_iter()
            .map(|v| {
                self.insert(
                    v,
                    Some(&[(
                        parent_node_id,
                        &ReferenceTypeId::Organizes,
                        ReferenceDirection::Inverse,
                    )]),
                )
            })
            .collect()
    }
}

impl NodeInsertTarget for AddressSpace {
    fn insert<'a>(
        &mut self,
        node: impl Into<NodeType>,
        references: Option<&'a [(&'a NodeId, &NodeId, opcua_nodes::ReferenceDirection)]>,
    ) -> bool {
        let node_type = node.into();
        let node_id = node_type.node_id().clone();

        self.assert_namespace(&node_id);

        if self.node_exists(&node_id) {
            error!("This node {} already exists", node_id);
            false
        } else {
            // If references are supplied, add them now
            if let Some(references) = references {
                self.references.insert(&node_id, references);
            }
            self.node_map.insert(node_id, node_type);

            true
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::address_space::{
        CoreNamespace, EventNotifier, MethodBuilder, NodeBase, NodeType, Object, ObjectBuilder,
        ObjectTypeBuilder, Variable, VariableBuilder,
    };
    use opcua_nodes::{DefaultTypeTree, NamespaceMap, TypeTree};
    use opcua_types::{
        argument::Argument, Array, BrowseDirection, DataTypeId, LocalizedText, NodeClass, NodeId,
        NumericRange, ObjectId, ObjectTypeId, QualifiedName, ReferenceTypeId, TimestampsToReturn,
        UAString, Variant, VariantScalarTypeId,
    };

    use super::AddressSpace;

    fn make_sample_address_space() -> AddressSpace {
        let mut address_space = AddressSpace::new();
        address_space.add_namespace("http://opcfoundation.org/UA/", 0);
        let mut namespaces = NamespaceMap::default();
        address_space.import_node_set(&CoreNamespace, &mut namespaces);
        add_sample_vars_to_address_space(&mut address_space);
        address_space
    }

    fn add_sample_vars_to_address_space(address_space: &mut AddressSpace) {
        address_space.add_namespace("urn:test", 1);
        let ns = 1;

        // Create a sample folder under objects folder
        let sample_folder_id = NodeId::next_numeric(ns);
        ObjectBuilder::new(&sample_folder_id, "Sample", "Sample")
            .organized_by(ObjectId::ObjectsFolder)
            .insert(address_space);

        // Add some variables to our sample folder
        let vars = vec![
            Variable::new(&NodeId::new(ns, "v1"), "v1", "v1", 30i32),
            Variable::new(&NodeId::new(ns, 300), "v2", "v2", true),
            Variable::new(&NodeId::new(ns, "v3"), "v3", "v3", "Hello world"),
            Variable::new(&NodeId::new(ns, "v4"), "v4", "v4", 100.123f64),
        ];
        for var in vars {
            let node_id = var.node_id().clone();
            address_space.insert::<_, NodeId>(var, None);
            address_space.insert_reference(
                &sample_folder_id,
                &node_id,
                ReferenceTypeId::HasComponent,
            );
        }
    }

    #[test]
    fn find_root_folder() {
        let address_space = make_sample_address_space();
        let node_type = address_space.find_node(&NodeId::new(0, 84));
        assert!(node_type.is_some());

        let node = node_type.unwrap().as_node();
        assert_eq!(node.node_id(), &NodeId::new(0, 84));
        assert_eq!(node.node_id(), &ObjectId::RootFolder);
    }

    #[test]
    fn find_objects_folder() {
        let address_space = make_sample_address_space();
        let node_type = address_space.find(ObjectId::ObjectsFolder);
        assert!(node_type.is_some());
    }

    #[test]
    fn find_types_folder() {
        let address_space = make_sample_address_space();
        let node_type = address_space.find(ObjectId::TypesFolder);
        assert!(node_type.is_some());
    }

    #[test]
    fn find_views_folder() {
        let address_space = make_sample_address_space();
        let node_type = address_space.find(ObjectId::ViewsFolder);
        assert!(node_type.is_some());
    }

    #[test]
    fn find_common_nodes() {
        let address_space = make_sample_address_space();
        let nodes: Vec<NodeId> = vec![
            ObjectId::RootFolder.into(),
            ObjectId::ObjectsFolder.into(),
            ObjectId::TypesFolder.into(),
            ObjectId::ViewsFolder.into(),
            ObjectId::DataTypesFolder.into(),
            DataTypeId::BaseDataType.into(),
            // Types
            DataTypeId::Boolean.into(),
            DataTypeId::ByteString.into(),
            DataTypeId::DataValue.into(),
            DataTypeId::DateTime.into(),
            DataTypeId::DiagnosticInfo.into(),
            DataTypeId::Enumeration.into(),
            DataTypeId::ExpandedNodeId.into(),
            DataTypeId::Guid.into(),
            DataTypeId::LocalizedText.into(),
            DataTypeId::NodeId.into(),
            DataTypeId::Number.into(),
            DataTypeId::QualifiedName.into(),
            DataTypeId::StatusCode.into(),
            DataTypeId::String.into(),
            DataTypeId::Structure.into(),
            DataTypeId::XmlElement.into(),
            DataTypeId::Double.into(),
            DataTypeId::Float.into(),
            DataTypeId::Integer.into(),
            DataTypeId::SByte.into(),
            DataTypeId::Int16.into(),
            DataTypeId::Int32.into(),
            DataTypeId::Int64.into(),
            DataTypeId::Byte.into(),
            DataTypeId::UInt16.into(),
            DataTypeId::UInt32.into(),
            DataTypeId::UInt64.into(),
            ObjectId::OPCBinarySchema_TypeSystem.into(),
            ObjectTypeId::DataTypeSystemType.into(),
            // Refs
            ObjectId::ReferenceTypesFolder.into(),
            ReferenceTypeId::References.into(),
            ReferenceTypeId::HierarchicalReferences.into(),
            ReferenceTypeId::HasChild.into(),
            ReferenceTypeId::HasSubtype.into(),
            ReferenceTypeId::Organizes.into(),
            ReferenceTypeId::NonHierarchicalReferences.into(),
            ReferenceTypeId::HasTypeDefinition.into(),
        ];
        for n in nodes {
            assert!(address_space.find_node(&n).is_some());
        }
    }

    #[test]
    fn object_attributes() {
        let on = NodeId::new(1, "o1");
        let o = Object::new(&on, "Browse01", "Display01", EventNotifier::empty());
        assert_eq!(o.node_class(), NodeClass::Object);
        assert_eq!(o.node_id(), &on);
        assert_eq!(o.browse_name(), &QualifiedName::new(0, "Browse01"));
        assert_eq!(o.display_name(), &"Display01".into());
    }

    #[test]
    fn find_node_by_id() {
        let address_space = make_sample_address_space();
        let ns = 1;

        assert!(!address_space.node_exists(&NodeId::null()));
        assert!(!address_space.node_exists(&NodeId::new(11, "v3")));

        assert!(address_space.node_exists(&NodeId::new(ns, "v1")));
        assert!(address_space.node_exists(&NodeId::new(ns, 300)));
        assert!(address_space.node_exists(&NodeId::new(ns, "v3")));
    }

    #[test]
    fn find_references() {
        let address_space = make_sample_address_space();

        let references: Vec<_> = address_space
            .find_references(
                &NodeId::root_folder_id(),
                Some((ReferenceTypeId::Organizes, false)),
                &DefaultTypeTree::new(),
                BrowseDirection::Forward,
            )
            .collect();
        assert_eq!(references.len(), 3);

        let references: Vec<_> = address_space
            .find_references(
                &NodeId::root_folder_id(),
                None::<(NodeId, bool)>,
                &DefaultTypeTree::new(),
                BrowseDirection::Forward,
            )
            .collect();
        assert_eq!(references.len(), 4);

        let references: Vec<_> = address_space
            .find_references(
                &NodeId::objects_folder_id(),
                Some((ReferenceTypeId::Organizes, false)),
                &DefaultTypeTree::new(),
                BrowseDirection::Forward,
            )
            .collect();
        assert_eq!(references.len(), 4);

        let r1 = &references[0];
        assert_eq!(r1.reference_type, &ReferenceTypeId::Organizes);
        let child_node_id = r1.target_node.clone();

        let child = address_space.find_node(&child_node_id);
        assert!(child.is_some());
    }

    #[test]
    fn find_inverse_references() {
        let address_space = make_sample_address_space();

        //println!("{:#?}", address_space);
        let references: Vec<_> = address_space
            .find_references(
                &NodeId::root_folder_id(),
                Some((ReferenceTypeId::Organizes, false)),
                &DefaultTypeTree::new(),
                BrowseDirection::Inverse,
            )
            .collect();
        assert!(references.is_empty());

        let references: Vec<_> = address_space
            .find_references(
                &NodeId::objects_folder_id(),
                Some((ReferenceTypeId::Organizes, false)),
                &DefaultTypeTree::new(),
                BrowseDirection::Inverse,
            )
            .collect();
        assert_eq!(references.len(), 1);
    }

    #[test]
    fn find_reference_subtypes() {
        let address_space = make_sample_address_space();
        let mut type_tree = DefaultTypeTree::new();
        address_space.load_into_type_tree(&mut type_tree);

        let reference_types = [
            (
                ReferenceTypeId::References,
                ReferenceTypeId::HierarchicalReferences,
            ),
            (ReferenceTypeId::References, ReferenceTypeId::HasChild),
            (ReferenceTypeId::References, ReferenceTypeId::HasSubtype),
            (ReferenceTypeId::References, ReferenceTypeId::Organizes),
            (ReferenceTypeId::References, ReferenceTypeId::Aggregates),
            (ReferenceTypeId::References, ReferenceTypeId::HasProperty),
            (ReferenceTypeId::References, ReferenceTypeId::HasComponent),
            (
                ReferenceTypeId::References,
                ReferenceTypeId::HasOrderedComponent,
            ),
            (ReferenceTypeId::References, ReferenceTypeId::HasEventSource),
            (ReferenceTypeId::References, ReferenceTypeId::HasNotifier),
            (ReferenceTypeId::References, ReferenceTypeId::GeneratesEvent),
            (
                ReferenceTypeId::References,
                ReferenceTypeId::AlwaysGeneratesEvent,
            ),
            (ReferenceTypeId::References, ReferenceTypeId::HasEncoding),
            (
                ReferenceTypeId::References,
                ReferenceTypeId::HasModellingRule,
            ),
            (ReferenceTypeId::References, ReferenceTypeId::HasDescription),
            (
                ReferenceTypeId::References,
                ReferenceTypeId::HasTypeDefinition,
            ),
            (
                ReferenceTypeId::HierarchicalReferences,
                ReferenceTypeId::HasChild,
            ),
            (
                ReferenceTypeId::HierarchicalReferences,
                ReferenceTypeId::HasSubtype,
            ),
            (
                ReferenceTypeId::HierarchicalReferences,
                ReferenceTypeId::Organizes,
            ),
            (
                ReferenceTypeId::HierarchicalReferences,
                ReferenceTypeId::Aggregates,
            ),
            (
                ReferenceTypeId::HierarchicalReferences,
                ReferenceTypeId::HasProperty,
            ),
            (
                ReferenceTypeId::HierarchicalReferences,
                ReferenceTypeId::HasComponent,
            ),
            (
                ReferenceTypeId::HierarchicalReferences,
                ReferenceTypeId::HasOrderedComponent,
            ),
            (
                ReferenceTypeId::HierarchicalReferences,
                ReferenceTypeId::HasEventSource,
            ),
            (
                ReferenceTypeId::HierarchicalReferences,
                ReferenceTypeId::HasNotifier,
            ),
            (ReferenceTypeId::HasChild, ReferenceTypeId::Aggregates),
            (ReferenceTypeId::HasChild, ReferenceTypeId::HasComponent),
            (
                ReferenceTypeId::HasChild,
                ReferenceTypeId::HasHistoricalConfiguration,
            ),
            (ReferenceTypeId::HasChild, ReferenceTypeId::HasProperty),
            (
                ReferenceTypeId::HasChild,
                ReferenceTypeId::HasOrderedComponent,
            ),
            (ReferenceTypeId::HasChild, ReferenceTypeId::HasSubtype),
            (ReferenceTypeId::Aggregates, ReferenceTypeId::HasComponent),
            (
                ReferenceTypeId::Aggregates,
                ReferenceTypeId::HasHistoricalConfiguration,
            ),
            (ReferenceTypeId::Aggregates, ReferenceTypeId::HasProperty),
            (
                ReferenceTypeId::Aggregates,
                ReferenceTypeId::HasOrderedComponent,
            ),
            (
                ReferenceTypeId::HasComponent,
                ReferenceTypeId::HasOrderedComponent,
            ),
            (
                ReferenceTypeId::HasEventSource,
                ReferenceTypeId::HasNotifier,
            ),
            (
                ReferenceTypeId::HierarchicalReferences,
                ReferenceTypeId::HasNotifier,
            ),
            (
                ReferenceTypeId::References,
                ReferenceTypeId::NonHierarchicalReferences,
            ),
            (
                ReferenceTypeId::NonHierarchicalReferences,
                ReferenceTypeId::GeneratesEvent,
            ),
            (
                ReferenceTypeId::NonHierarchicalReferences,
                ReferenceTypeId::AlwaysGeneratesEvent,
            ),
            (
                ReferenceTypeId::NonHierarchicalReferences,
                ReferenceTypeId::HasEncoding,
            ),
            (
                ReferenceTypeId::NonHierarchicalReferences,
                ReferenceTypeId::HasModellingRule,
            ),
            (
                ReferenceTypeId::NonHierarchicalReferences,
                ReferenceTypeId::HasDescription,
            ),
            (
                ReferenceTypeId::NonHierarchicalReferences,
                ReferenceTypeId::HasTypeDefinition,
            ),
            (
                ReferenceTypeId::GeneratesEvent,
                ReferenceTypeId::AlwaysGeneratesEvent,
            ),
        ];

        // Make sure that subtypes match when subtypes are to be compared and doesn't when they should
        // not be compared.
        reference_types.iter().for_each(|r| {
            let r1 = r.0.into();
            let r2 = r.1.into();
            assert!(type_tree.is_subtype_of(&r2, &r1));
        });
    }

    /// This test is to ensure that adding a Variable with a value of Array to address space sets the
    /// ValueRank and ArrayDimensions attributes correctly.
    #[test]
    fn array_as_variable() {
        // 1 dimensional array with 100 element
        let values = (0..100).map(Variant::Int32).collect::<Vec<Variant>>();

        // Get the variable node back from the address space, ensure that the ValueRank and ArrayDimensions are correct
        let node_id = NodeId::new(2, 1);
        let v = Variable::new(&node_id, "x", "x", (VariantScalarTypeId::Int32, values));

        let value_rank = v.value_rank();
        assert_eq!(value_rank, 1);
        let array_dimensions = v.array_dimensions().unwrap();
        assert_eq!(array_dimensions, vec![100u32]);
    }

    /// This test is to ensure that adding a Variable with a value of Array to address space sets the
    /// ValueRank and ArrayDimensions attributes correctly.
    #[test]
    fn multi_dimension_array_as_variable() {
        // 2 dimensional array with 10x10 elements

        let values = (0..100).map(Variant::Int32).collect::<Vec<Variant>>();
        let mda = Array::new_multi(VariantScalarTypeId::Int32, values, vec![10u32, 10u32]).unwrap();
        assert!(mda.is_valid());

        // Get the variable node back from the address space, ensure that the ValueRank and ArrayDimensions are correct
        let node_id = NodeId::new(2, 1);
        let v = Variable::new(&node_id, "x", "x", mda);

        let value_rank = v.value_rank();
        assert_eq!(value_rank, 2);
        let array_dimensions = v.array_dimensions().unwrap();
        assert_eq!(array_dimensions, vec![10u32, 10u32]);
    }

    #[test]
    fn browse_nodes() {
        let address_space = make_sample_address_space();

        // Test that a node can be found
        let object_id = ObjectId::RootFolder.into();
        let result = address_space.find_node_by_browse_path(
            &object_id,
            None::<(NodeId, bool)>,
            &DefaultTypeTree::new(),
            BrowseDirection::Forward,
            &["Objects".into(), "Sample".into(), "v1".into()],
        );
        let node = result.unwrap();
        assert_eq!(node.as_node().browse_name(), &QualifiedName::from("v1"));

        // Test that a non existent node cannot be found
        let result = address_space.find_node_by_browse_path(
            &object_id,
            None::<(NodeId, bool)>,
            &DefaultTypeTree::new(),
            BrowseDirection::Forward,
            &["Objects".into(), "Sample".into(), "vxxx".into()],
        );
        assert!(result.is_none());
    }

    #[test]
    fn object_builder() {
        let mut address_space = make_sample_address_space();

        let node_type_id = NodeId::new(1, "HelloType");
        let _ot = ObjectTypeBuilder::new(&node_type_id, "HelloType", "HelloType")
            .subtype_of(ObjectTypeId::BaseObjectType)
            .insert(&mut address_space);

        let node_id = NodeId::new(1, "Hello");
        let _o = ObjectBuilder::new(&node_id, "Foo", "Foo")
            .event_notifier(EventNotifier::SUBSCRIBE_TO_EVENTS)
            .organized_by(ObjectId::ObjectsFolder)
            .has_type_definition(node_type_id.clone())
            .insert(&mut address_space);

        // Verify the variable is there
        let _o = match address_space.find_node(&node_id).unwrap() {
            NodeType::Object(o) => o,
            _ => panic!(),
        };

        // Verify the reference to the objects folder is there
        assert!(address_space.has_reference(
            &ObjectId::ObjectsFolder.into(),
            &node_id,
            ReferenceTypeId::Organizes
        ));
        assert!(address_space.has_reference(
            &node_id,
            &node_type_id,
            ReferenceTypeId::HasTypeDefinition
        ));
    }

    #[test]
    fn object_type_builder() {
        let mut address_space = make_sample_address_space();

        let node_type_id = NodeId::new(1, "HelloType");
        let _ot = ObjectTypeBuilder::new(&node_type_id, "HelloType", "HelloType")
            .subtype_of(ObjectTypeId::BaseObjectType)
            .insert(&mut address_space);

        let _ot = match address_space.find_node(&node_type_id).unwrap() {
            NodeType::ObjectType(ot) => ot,
            _ => panic!(),
        };

        assert!(address_space.has_reference(
            &ObjectTypeId::BaseObjectType.into(),
            &node_type_id,
            ReferenceTypeId::HasSubtype
        ));
    }

    #[test]
    fn variable_builder() {
        let result = std::panic::catch_unwind(|| {
            // This should panic
            let _v = VariableBuilder::new(&NodeId::null(), "", "").build();
        });
        assert!(result.is_err());

        // This should build
        let _v = VariableBuilder::new(&NodeId::new(1, 1), "", "")
            .data_type(DataTypeId::Boolean)
            .build();

        // Check a variable with a bunch of fields set
        let v = VariableBuilder::new(&NodeId::new(1, "Hello"), "BrowseName", "DisplayName")
            .description("Desc")
            .data_type(DataTypeId::UInt32)
            .value_rank(10)
            .array_dimensions(&[1, 2, 3])
            .historizing(true)
            .value(Variant::from(999))
            .minimum_sampling_interval(123.0)
            .build();

        assert_eq!(v.node_id(), &NodeId::new(1, "Hello"));
        assert_eq!(v.browse_name(), &QualifiedName::new(0, "BrowseName"));
        assert_eq!(v.display_name(), &"DisplayName".into());
        assert_eq!(v.data_type(), DataTypeId::UInt32);
        assert_eq!(v.description().unwrap(), &"Desc".into());
        assert_eq!(v.value_rank(), 10);
        assert_eq!(v.array_dimensions().unwrap(), vec![1, 2, 3]);
        assert!(v.historizing());
        assert_eq!(
            v.value(
                TimestampsToReturn::Neither,
                &NumericRange::None,
                &opcua_types::DataEncoding::Binary,
                0.0
            )
            .value
            .unwrap(),
            Variant::from(999)
        );
        assert_eq!(v.minimum_sampling_interval().unwrap(), 123.0);

        // Add a variable to the address space

        let mut address_space = make_sample_address_space();
        let node_id = NodeId::new(1, "Hello");
        let _v = VariableBuilder::new(&node_id, "BrowseName", "DisplayName")
            .description("Desc")
            .value_rank(10)
            .data_type(DataTypeId::UInt32)
            .array_dimensions(&[1, 2, 3])
            .historizing(true)
            .value(Variant::from(999))
            .minimum_sampling_interval(123.0)
            .organized_by(ObjectId::ObjectsFolder)
            .insert(&mut address_space);

        // Verify the variable is there
        assert!(address_space.find_node(&node_id).is_some());
        // Verify the reference to the objects folder is there
        assert!(address_space.has_reference(
            &ObjectId::ObjectsFolder.into(),
            &node_id,
            ReferenceTypeId::Organizes
        ));
    }

    #[test]
    fn method_builder() {
        let mut address_space = make_sample_address_space();

        address_space.add_namespace("urn:test", 1);
        let ns = 1;

        let object_id: NodeId = ObjectId::ObjectsFolder.into();

        let fn_node_id = NodeId::new(ns, "HelloWorld");
        let out_args = NodeId::new(ns, "HelloWorldOut");

        let inserted = MethodBuilder::new(&fn_node_id, "HelloWorld", "HelloWorld")
            .component_of(object_id.clone())
            .output_args(
                &mut address_space,
                &out_args,
                &[("Result", DataTypeId::String).into()],
            )
            .insert(&mut address_space);
        assert!(inserted);

        assert!(matches!(
            address_space.find_node(&fn_node_id),
            Some(NodeType::Method(_))
        ));

        let refs: Vec<_> = address_space
            .find_references(
                &fn_node_id,
                Some((ReferenceTypeId::HasProperty, false)),
                &DefaultTypeTree::new(),
                BrowseDirection::Forward,
            )
            .collect();
        assert_eq!(refs.len(), 1);

        let child = address_space
            .find_node(refs.first().unwrap().target_node)
            .unwrap();
        if let NodeType::Variable(v) = child {
            // verify OutputArguments
            // verify OutputArguments / Argument value
            assert_eq!(v.data_type(), DataTypeId::Argument);
            assert_eq!(v.display_name(), &LocalizedText::from("OutputArguments"));
            let v = v
                .value(
                    TimestampsToReturn::Neither,
                    &NumericRange::None,
                    &opcua_types::DataEncoding::Binary,
                    0.0,
                )
                .value
                .unwrap();
            if let Variant::Array(array) = v {
                let v = array.values;
                assert_eq!(v.len(), 1);
                let v = v.first().unwrap().clone();
                if let Variant::ExtensionObject(v) = v {
                    // deserialize the Argument here
                    let argument = v.inner_as::<Argument>().unwrap();
                    assert_eq!(argument.name, UAString::from("Result"));
                    assert_eq!(argument.data_type, DataTypeId::String);
                    assert_eq!(argument.value_rank, -1);
                    assert_eq!(argument.array_dimensions, None);
                    assert_eq!(argument.description, LocalizedText::null());
                } else {
                    panic!("Variant was expected to be extension object, was {:?}", v);
                }
            } else {
                panic!("Variant was expected to be array, was {:?}", v);
            }
        } else {
            panic!();
        }
    }

    #[test]
    fn simple_delete_node() {
        // This is a super basic, debuggable delete test. There is a single Root node, and a
        // child object. After deleting the child, only the Root should exist with no references at
        // all to the child.

        // A blank address space, with nothing at all in it
        let mut address_space = make_sample_address_space();

        // Add a root node
        let root_node = NodeId::root_folder_id();

        let node = Object::new(&root_node, "Root", "", EventNotifier::empty());
        let _ = address_space.insert::<Object, ReferenceTypeId>(node, None);

        let node_id = NodeId::new(1, "Hello");
        let _o = ObjectBuilder::new(&node_id, "Foo", "Foo")
            .organized_by(root_node.clone())
            .insert(&mut address_space);

        // Verify the object and refs are there
        assert!(address_space.find_node(&node_id).is_some());
        assert!(address_space.has_reference(&root_node, &node_id, ReferenceTypeId::Organizes));

        // Try one time deleting references, the other time not deleting them.
        address_space.delete(&node_id, true);
        // Delete the node and the refs
        assert!(address_space.find_node(&node_id).is_none());
        assert!(address_space.find_node(&root_node).is_some());
        assert!(!address_space.has_reference(&root_node, &node_id, ReferenceTypeId::Organizes));
    }

    #[test]
    fn delete_node() {
        // Try creating and deleting a node, verifying that it's totally gone afterwards
        (0..2).for_each(|i| {
            let mut address_space = make_sample_address_space();

            let node_type_id = NodeId::new(1, "HelloType");
            let _ot = ObjectTypeBuilder::new(&node_type_id, "HelloType", "HelloType")
                .subtype_of(ObjectTypeId::BaseObjectType)
                .insert(&mut address_space);

            let node_id = NodeId::new(1, "Hello");
            let _o = ObjectBuilder::new(&node_id, "Foo", "Foo")
                .event_notifier(EventNotifier::SUBSCRIBE_TO_EVENTS)
                .organized_by(ObjectId::ObjectsFolder)
                .has_type_definition(node_type_id.clone())
                .insert(&mut address_space);

            // Verify the object and refs are there
            assert!(address_space.find_node(&node_id).is_some());
            assert!(address_space.has_reference(
                &ObjectId::ObjectsFolder.into(),
                &node_id,
                ReferenceTypeId::Organizes
            ));
            assert!(!address_space.has_reference(
                &node_id,
                &ObjectId::ObjectsFolder.into(),
                ReferenceTypeId::Organizes
            ));
            assert!(address_space.has_reference(
                &node_id,
                &node_type_id,
                ReferenceTypeId::HasTypeDefinition
            ));

            // Try one time deleting references, the other time not deleting them.
            let delete_target_references = i == 1;
            address_space.delete(&node_id, delete_target_references);
            if !delete_target_references {
                // Deleted the node and outgoing refs, but not incoming refs
                assert!(address_space.find_node(&node_id).is_none());
                assert!(address_space.has_reference(
                    &ObjectId::ObjectsFolder.into(),
                    &node_id,
                    ReferenceTypeId::Organizes
                ));
                assert!(!address_space.has_reference(
                    &node_id,
                    &node_type_id,
                    ReferenceTypeId::HasTypeDefinition
                ));
            } else {
                // Delete the node and the refs
                assert!(address_space.find_node(&node_id).is_none());
                assert!(!address_space.has_reference(
                    &ObjectId::ObjectsFolder.into(),
                    &node_id,
                    ReferenceTypeId::Organizes
                ));
                assert!(!address_space.has_reference(
                    &node_id,
                    &node_type_id,
                    ReferenceTypeId::HasTypeDefinition
                ));
            }
        });
    }
}
