//! Utilities for working with namespaces.

use hashbrown::HashMap;

use crate::{errors::OpcUaError, ExpandedNodeId, NodeId, Variant};

/// Utility for handling assignment of namespaces on server startup.
#[derive(Debug, Default, Clone)]
pub struct NamespaceMap {
    known_namespaces: HashMap<String, u16>,
}

impl NamespaceMap {
    /// Create a new namespace map containing only the base namespace.
    pub fn new() -> Self {
        let mut known_namespaces = HashMap::new();
        known_namespaces.insert("http://opcfoundation.org/UA/".to_owned(), 0u16);

        Self { known_namespaces }
    }

    /// Create a new namespace map from the given list of namespaces.
    pub fn new_full(map: HashMap<String, u16>) -> Self {
        Self {
            known_namespaces: map,
        }
    }

    /// Create a new namespace map from a vec of variant as we get when reading
    /// the namespace array from the server
    pub fn new_from_variant_array(array: &[Variant]) -> Result<Self, OpcUaError> {
        let known_namespaces: HashMap<String, u16> = array
            .iter()
            .enumerate()
            .map(|(idx, v)| {
                if let Variant::String(s) = v {
                    Ok((s.value().clone().unwrap_or(String::new()), idx as u16))
                } else {
                    Err(OpcUaError::UnexpectedVariantType {
                        variant_id: v.scalar_type_id(),
                        message: "Namespace array on server contains invalid data".to_string(),
                    })
                }
            })
            .collect::<Result<HashMap<_, _>, _>>()?;
        Ok(Self { known_namespaces })
    }

    /// Add a new namespace, returning its index in the namespace map.
    /// If the namespace is already added, its old index is returned.
    pub fn add_namespace(&mut self, namespace: &str) -> u16 {
        if let Some(ns) = self.known_namespaces.get(namespace) {
            return *ns;
        }
        let max = self
            .known_namespaces
            .iter()
            .map(|kv| *kv.1)
            .max()
            .unwrap_or_default();
        self.known_namespaces.insert(namespace.to_owned(), max + 1);

        max + 1
    }

    /// Return the inner namespace map.
    pub fn known_namespaces(&self) -> &HashMap<String, u16> {
        &self.known_namespaces
    }

    /// Get the index of the given namespace.
    pub fn get_index(&self, ns: &str) -> Option<u16> {
        self.known_namespaces.get(ns).copied()
    }

    /// Try to resolve an expanded node ID to a NodeId.
    pub fn resolve_node_id<'b>(
        &self,
        id: &'b ExpandedNodeId,
    ) -> Option<std::borrow::Cow<'b, NodeId>> {
        id.try_resolve(self)
    }
}

/// Utility handling namespaces when loading node sets.
pub struct NodeSetNamespaceMapper<'a> {
    namespaces: &'a mut NamespaceMap,
    index_map: HashMap<u16, u16>,
}

#[derive(Debug)]
/// Error returned when trying to get an index that is not initialized.
pub struct UninitializedIndex(pub u16);

impl<'a> NodeSetNamespaceMapper<'a> {
    /// Create a new namespace mapper from the given namespace map.
    pub fn new(namespaces: &'a mut NamespaceMap) -> Self {
        Self {
            namespaces,
            index_map: HashMap::new(),
        }
    }

    /// Add a namespace. `index_in_node_set` is the index in the NodeSet2 file being loaded.
    pub fn add_namespace(&mut self, namespace: &str, index_in_node_set: u16) {
        let index = self.namespaces.add_namespace(namespace);
        self.index_map.insert(index_in_node_set, index);
    }

    /// Get the index of a namespace given its index in a NodeSet2 file.
    pub fn get_index(&self, index_in_node_set: u16) -> Result<u16, UninitializedIndex> {
        if index_in_node_set == 0 {
            return Ok(0);
        }
        let Some(idx) = self.index_map.get(&index_in_node_set) else {
            return Err(UninitializedIndex(index_in_node_set));
        };
        Ok(*idx)
    }

    /// Return the inner namespace map.
    pub fn namespaces(&'a self) -> &'a NamespaceMap {
        &*self.namespaces
    }

    /// Return the inner index map.
    pub fn index_map(&self) -> &HashMap<u16, u16> {
        &self.index_map
    }
}
