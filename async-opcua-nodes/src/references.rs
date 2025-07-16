use std::hash::Hasher;

use hashbrown::{Equivalent, HashMap, HashSet};
use opcua_types::{
    node_id::{IdentifierRef, IntoNodeIdRef, NodeIdRef},
    BrowseDirection, Identifier, NodeId,
};

use crate::{ImportedReference, ReferenceDirection, TypeTree};

#[derive(PartialEq, Eq, Clone, Debug, Hash)]
/// Owned OPC-UA reference.
pub struct Reference {
    /// Reference type ID.
    pub reference_type: NodeId,
    /// Target node ID.
    pub target_node: NodeId,
}

// Note, must have same hash and eq implementation as Reference.
#[derive(PartialEq, Eq, Clone, Debug)]
struct ReferenceKey<R: IdentifierRef, R2: IdentifierRef> {
    pub reference_type: NodeIdRef<R2>,
    pub target_node: NodeIdRef<R>,
}

impl<R, R2> std::hash::Hash for ReferenceKey<R, R2>
where
    R: IdentifierRef,
    R2: IdentifierRef,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.reference_type.hash(state);
        self.target_node.hash(state);
    }
}

impl<R, R2> Equivalent<Reference> for ReferenceKey<R, R2>
where
    R: IdentifierRef,
    R2: IdentifierRef,
{
    fn equivalent(&self, key: &Reference) -> bool {
        self.reference_type.equivalent(&key.reference_type)
            && self.target_node.equivalent(&key.target_node)
    }
}

impl<'a> From<&'a Reference> for ReferenceKey<&'a Identifier, &'a Identifier> {
    fn from(value: &'a Reference) -> Self {
        Self {
            reference_type: (&value.reference_type).into_node_id_ref(),
            target_node: (&value.target_node).into_node_id_ref(),
        }
    }
}

#[derive(PartialEq, Eq, Clone, Debug, Hash)]
/// A borrowed version of an OPC-UA reference.
pub struct ReferenceRef<'a> {
    /// Reference type ID.
    pub reference_type: &'a NodeId,
    /// Target node ID.
    pub target_node: &'a NodeId,
    /// Reference direction.
    pub direction: ReferenceDirection,
}

// Note that there is a potentially significant benefit to using hashbrown directly here,
// (which is what the std HashMap is built on!), since it lets us remove references from
// the hash sets without cloning given node IDs.
#[derive(Debug, Default)]
/// Structure for storing and accessing OPC-UA references.
pub struct References {
    /// References by source node ID.
    by_source: HashMap<NodeId, HashSet<Reference>>,
    /// References by target node ID.
    by_target: HashMap<NodeId, HashSet<Reference>>,
}

impl References {
    /// Create a new empty reference store.
    pub fn new() -> Self {
        Self {
            by_source: HashMap::new(),
            by_target: HashMap::new(),
        }
    }

    /// Insert a list of references.
    pub fn insert<'a, S>(
        &mut self,
        source: &NodeId,
        references: &'a [(&'a NodeId, &S, ReferenceDirection)],
    ) where
        S: Into<NodeId> + Clone,
    {
        for (target, typ, direction) in references {
            let typ: NodeId = (*typ).clone().into();
            match direction {
                ReferenceDirection::Forward => self.insert_reference(source, target, typ),
                ReferenceDirection::Inverse => self.insert_reference(target, source, typ),
            }
        }
    }

    /// Insert a new reference.
    pub fn insert_reference(
        &mut self,
        source_node: &NodeId,
        target_node: &NodeId,
        reference_type: impl Into<NodeId>,
    ) {
        if source_node == target_node {
            panic!("Node id from == node id to {source_node}, self reference is not allowed");
        }

        let forward_refs = match self.by_source.get_mut(source_node) {
            Some(r) => r,
            None => self.by_source.entry(source_node.clone()).or_default(),
        };

        let reference_type = reference_type.into();

        if !forward_refs.insert(Reference {
            reference_type: reference_type.clone(),
            target_node: target_node.clone(),
        }) {
            // If the reference is already added, no reason to try adding it to the inverse.
            return;
        }

        let inverse_refs = match self.by_target.get_mut(target_node) {
            Some(r) => r,
            None => self.by_target.entry(target_node.clone()).or_default(),
        };

        inverse_refs.insert(Reference {
            reference_type,
            target_node: source_node.clone(),
        });
    }

    /// Insert a list of references (source, target, reference type)
    pub fn insert_references<'a>(
        &mut self,
        references: impl Iterator<Item = (&'a NodeId, &'a NodeId, impl Into<NodeId>)>,
    ) {
        for (source, target, typ) in references {
            self.insert_reference(source, target, typ);
        }
    }

    /// Import a reference from a nodeset.
    pub fn import_reference(&mut self, source_node: NodeId, rf: ImportedReference) {
        if source_node == rf.target_id {
            panic!("Node id from == node id to {source_node}, self reference is not allowed");
        }

        let mut source = source_node;
        let mut target = rf.target_id;
        if !rf.is_forward {
            (source, target) = (target, source);
        }

        let forward_refs = match self.by_source.get_mut(&source) {
            Some(r) => r,
            None => self.by_source.entry(source.clone()).or_default(),
        };

        if !forward_refs.insert(Reference {
            reference_type: rf.type_id.clone(),
            target_node: target.clone(),
        }) {
            // If the reference is already added, no reason to try adding it to the inverse.
            return;
        }

        let inverse_refs = match self.by_target.get_mut(&target) {
            Some(r) => r,
            None => self.by_target.entry(target).or_default(),
        };

        inverse_refs.insert(Reference {
            reference_type: rf.type_id,
            target_node: source,
        });
    }

    /// Delete a reference.
    pub fn delete_reference<'a>(
        &mut self,
        source_node: impl IntoNodeIdRef<'a>,
        target_node: impl IntoNodeIdRef<'a>,
        reference_type: impl IntoNodeIdRef<'a>,
    ) -> bool {
        let mut found = false;
        let reference_type = reference_type.into_node_id_ref();
        let source_node = source_node.into_node_id_ref();
        let target_node = target_node.into_node_id_ref();
        let rf = ReferenceKey {
            reference_type,
            target_node,
        };
        found |= self
            .by_source
            .get_mut(&source_node)
            .map(|f| f.remove(&rf))
            .unwrap_or_default();

        let rf = ReferenceKey {
            reference_type,
            target_node: source_node,
        };

        found |= self
            .by_target
            .get_mut(&target_node)
            .map(|f| f.remove(&rf))
            .unwrap_or_default();

        found
    }

    /// Delete references from  the given node.
    /// Optionally deleting references _to_ the given node.
    ///
    /// Returns whether any references were found.
    pub fn delete_node_references<'a>(
        &mut self,
        source_node: impl IntoNodeIdRef<'a>,
        delete_target_references: bool,
    ) -> bool {
        let mut found = false;
        let source_node = source_node.into_node_id_ref();
        let source = self.by_source.remove(&source_node);
        found |= source.is_some();
        if delete_target_references {
            for rf in source.into_iter().flatten() {
                if let Some(rec) = self.by_target.get_mut(&rf.target_node) {
                    rec.remove(&ReferenceKey {
                        reference_type: (&rf.reference_type).into_node_id_ref(),
                        target_node: source_node,
                    });
                }
            }
        }

        let target = self.by_target.remove(&source_node);
        found |= target.is_some();

        if delete_target_references {
            for rf in target.into_iter().flatten() {
                if let Some(rec) = self.by_source.get_mut(&rf.target_node) {
                    rec.remove(&ReferenceKey {
                        reference_type: (&rf.reference_type).into_node_id_ref(),
                        target_node: source_node,
                    });
                }
            }
        }

        found
    }

    /// Return `true` if the given reference exists.
    pub fn has_reference<'a>(
        &self,
        source_node: impl IntoNodeIdRef<'a>,
        target_node: impl IntoNodeIdRef<'a>,
        reference_type: impl IntoNodeIdRef<'a>,
    ) -> bool {
        let reference_type = reference_type.into_node_id_ref();
        let target_node = target_node.into_node_id_ref();
        self.by_source
            .get(&source_node.into_node_id_ref())
            .map(|n| {
                n.contains(&ReferenceKey {
                    reference_type,
                    target_node,
                })
            })
            .unwrap_or_default()
    }

    /// Return an iterator over references matching the given filters.
    pub fn find_references<'a: 'b, 'b>(
        &'a self,
        source_node: impl IntoNodeIdRef<'b>,
        filter: Option<(impl Into<NodeId>, bool)>,
        type_tree: &'b dyn TypeTree,
        direction: BrowseDirection,
    ) -> impl Iterator<Item = ReferenceRef<'a>> + 'b {
        ReferenceIterator::new(
            source_node.into_node_id_ref(),
            direction,
            self,
            filter.map(|f| (f.0.into(), f.1)),
            type_tree,
        )
    }
}

// Handy feature to let us easily return a concrete type from `find_references`.
struct ReferenceIterator<'a, 'b> {
    filter: Option<(NodeId, bool)>,
    type_tree: &'b dyn TypeTree,
    iter_s: Option<hashbrown::hash_set::Iter<'a, Reference>>,
    iter_t: Option<hashbrown::hash_set::Iter<'a, Reference>>,
}

impl<'a> Iterator for ReferenceIterator<'a, '_> {
    type Item = ReferenceRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let inner = self.next_inner()?;

            if let Some(filter) = &self.filter {
                if !filter.1 && inner.reference_type != &filter.0
                    || filter.1
                        && !self
                            .type_tree
                            .is_subtype_of(inner.reference_type, &filter.0)
                {
                    continue;
                }
            }

            break Some(inner);
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let mut lower = 0;
        let mut upper = None;
        if let Some(iter_s) = &self.iter_s {
            let (lower_i, upper_i) = iter_s.size_hint();
            lower = lower_i;
            upper = upper_i;
        }

        if let Some(iter_t) = &self.iter_t {
            let (lower_i, upper_i) = iter_t.size_hint();
            lower += lower_i;
            upper = match (upper, upper_i) {
                (Some(l), Some(r)) => Some(l + r),
                _ => None,
            }
        }

        (lower, upper)
    }
}

impl<'a, 'b> ReferenceIterator<'a, 'b> {
    fn new<R: IdentifierRef + 'b>(
        source_node: NodeIdRef<R>,
        direction: BrowseDirection,
        references: &'a References,
        filter: Option<(NodeId, bool)>,
        type_tree: &'b dyn TypeTree,
    ) -> Self {
        Self {
            filter,
            type_tree,
            iter_s: matches!(direction, BrowseDirection::Both | BrowseDirection::Forward)
                .then(|| references.by_source.get(&source_node))
                .flatten()
                .map(|r| r.iter()),
            iter_t: matches!(direction, BrowseDirection::Both | BrowseDirection::Inverse)
                .then(|| references.by_target.get(&source_node))
                .flatten()
                .map(|r| r.iter()),
        }
    }

    fn next_inner(&mut self) -> Option<ReferenceRef<'a>> {
        if let Some(iter_s) = &mut self.iter_s {
            match iter_s.next() {
                Some(r) => {
                    return Some(ReferenceRef {
                        reference_type: &r.reference_type,
                        target_node: &r.target_node,
                        direction: ReferenceDirection::Forward,
                    })
                }
                None => self.iter_s = None,
            }
        }

        if let Some(iter_t) = &mut self.iter_t {
            match iter_t.next() {
                Some(r) => {
                    return Some(ReferenceRef {
                        reference_type: &r.reference_type,
                        target_node: &r.target_node,
                        direction: ReferenceDirection::Inverse,
                    })
                }
                None => self.iter_t = None,
            }
        }

        None
    }
}
