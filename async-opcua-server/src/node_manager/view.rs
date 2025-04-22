use std::collections::{HashMap, VecDeque};

use crate::{
    address_space::ReferenceDirection,
    session::{
        continuation_points::{ContinuationPoint, EmptyContinuationPoint},
        instance::Session,
    },
};
use opcua_crypto::random;
use opcua_nodes::TypeTree;
use opcua_types::{
    BrowseDescription, BrowseDescriptionResultMask, BrowseDirection, BrowsePath, BrowseResult,
    BrowseResultMask, ByteString, ExpandedNodeId, LocalizedText, NodeClass, NodeClassMask, NodeId,
    QualifiedName, ReferenceDescription, RelativePathElement, StatusCode,
};
use tracing::warn;

use super::{NodeManager, RequestContext};

#[derive(Debug, Clone)]
/// Object describing a node with sufficient context to construct
/// a `ReferenceDescription`.
pub struct NodeMetadata {
    /// Node ID of the node.
    pub node_id: ExpandedNodeId,
    /// Type definition of the node.
    pub type_definition: ExpandedNodeId,
    /// Browse name of the node.
    pub browse_name: QualifiedName,
    /// Display name of the node.
    pub display_name: LocalizedText,
    /// Node class of the node.
    pub node_class: NodeClass,
}

impl NodeMetadata {
    /// Convert this metadata into a ReferenceDescription with given
    /// direction and reference type ID.
    pub fn into_ref_desc(
        self,
        is_forward: bool,
        reference_type_id: impl Into<NodeId>,
    ) -> ReferenceDescription {
        ReferenceDescription {
            reference_type_id: reference_type_id.into(),
            is_forward,
            node_id: self.node_id,
            browse_name: self.browse_name,
            display_name: self.display_name,
            node_class: self.node_class,
            type_definition: self.type_definition,
        }
    }
}

#[derive(Debug)]
/// Container for a request for the metadata of a single node.
pub struct ExternalReferenceRequest {
    node_id: NodeId,
    result_mask: BrowseDescriptionResultMask,
    item: Option<NodeMetadata>,
}

impl ExternalReferenceRequest {
    /// Create a new external reference request from the node ID of the node being requested
    /// and a result mask.
    pub fn new(reference: &NodeId, result_mask: BrowseDescriptionResultMask) -> Self {
        Self {
            node_id: reference.clone(),
            result_mask,
            item: None,
        }
    }

    /// Node ID of the node being requested.
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Set the result to a `NodeMetadata` object.
    pub fn set(&mut self, reference: NodeMetadata) {
        self.item = Some(reference);
    }

    /// Get the mask for fields that should be included in the returned `NodeMetadata`.
    pub fn result_mask(&self) -> BrowseDescriptionResultMask {
        self.result_mask
    }

    /// Consume this request and return the result.
    pub fn into_inner(self) -> Option<NodeMetadata> {
        self.item
    }
}

#[derive(Debug)]
/// A reference pointing to some node in a different node manager.
pub struct ExternalReference {
    target_id: ExpandedNodeId,
    reference_type_id: NodeId,
    direction: ReferenceDirection,
}

impl ExternalReference {
    /// Create a new external reference.
    pub fn new(
        target_id: ExpandedNodeId,
        reference_type_id: NodeId,
        direction: ReferenceDirection,
    ) -> Self {
        Self {
            target_id,
            reference_type_id,
            direction,
        }
    }

    /// Create a reference description from this and a `NodeMetadata` object.
    pub fn into_reference(self, meta: NodeMetadata) -> ReferenceDescription {
        ReferenceDescription {
            reference_type_id: self.reference_type_id,
            is_forward: matches!(self.direction, ReferenceDirection::Forward),
            node_id: self.target_id,
            browse_name: meta.browse_name,
            display_name: meta.display_name,
            node_class: meta.node_class,
            type_definition: meta.type_definition,
        }
    }
}

#[derive(Debug)]
/// Result of adding a reference to a browse node.
#[allow(clippy::large_enum_variant)]
pub enum AddReferenceResult {
    /// The reference was added
    Added,
    /// The reference does not match the filters and was rejected
    Rejected,
    /// The reference does match the filters, but the node is full.
    Full(ReferenceDescription),
}

/// Container for a node being browsed and the result of the browse operation.
pub struct BrowseNode {
    node_id: NodeId,
    browse_direction: BrowseDirection,
    reference_type_id: NodeId,
    include_subtypes: bool,
    node_class_mask: NodeClassMask,
    result_mask: BrowseDescriptionResultMask,
    references: Vec<ReferenceDescription>,
    status_code: StatusCode,
    // It is feasible to only keep one continuation point, by using the
    // fact that node managers are sequential. If the first node manager is done reading,
    // we move on to the next.
    // All we need to do is keep track of which node manager made the last continuation point.
    input_continuation_point: Option<ContinuationPoint>,
    next_continuation_point: Option<ContinuationPoint>,
    max_references_per_node: usize,
    input_index: usize,
    pub(crate) start_node_manager: usize,

    /// List of references to nodes not owned by the node manager that generated the
    /// reference. These are resolved after the initial browse, and any excess is stored
    /// in a continuation point.
    external_references: Vec<ExternalReference>,
}

pub(crate) struct BrowseContinuationPoint {
    pub node_manager_index: usize,
    pub continuation_point: ContinuationPoint,
    pub id: ByteString,

    node_id: NodeId,
    browse_direction: BrowseDirection,
    reference_type_id: NodeId,
    include_subtypes: bool,
    node_class_mask: NodeClassMask,
    result_mask: BrowseDescriptionResultMask,
    pub(crate) max_references_per_node: usize,

    external_references: Vec<ExternalReference>,
}

impl BrowseNode {
    /// Create a new empty browse node
    pub(crate) fn new(
        description: BrowseDescription,
        max_references_per_node: usize,
        input_index: usize,
    ) -> Self {
        Self {
            node_id: description.node_id,
            browse_direction: description.browse_direction,
            reference_type_id: description.reference_type_id,
            include_subtypes: description.include_subtypes,
            node_class_mask: NodeClassMask::from_bits_truncate(description.node_class_mask),
            result_mask: BrowseDescriptionResultMask::from_bits_truncate(description.result_mask),
            input_continuation_point: None,
            next_continuation_point: None,
            max_references_per_node,
            references: Vec::new(),
            status_code: StatusCode::BadNodeIdUnknown,
            input_index,
            start_node_manager: 0,
            external_references: Vec::new(),
        }
    }

    pub(crate) fn from_continuation_point(
        point: BrowseContinuationPoint,
        input_index: usize,
    ) -> Self {
        Self {
            node_id: point.node_id,
            browse_direction: point.browse_direction,
            reference_type_id: point.reference_type_id,
            include_subtypes: point.include_subtypes,
            node_class_mask: point.node_class_mask,
            result_mask: point.result_mask,
            references: Vec::new(),
            status_code: StatusCode::BadNodeIdUnknown,
            input_continuation_point: Some(point.continuation_point),
            next_continuation_point: None,
            max_references_per_node: point.max_references_per_node,
            input_index,
            start_node_manager: point.node_manager_index,
            external_references: point.external_references,
        }
    }

    /// Set the response status, you should make sure to set this
    /// if you own the node being browsed. It defaults to BadNodeIdUnknown.
    pub fn set_status(&mut self, status: StatusCode) {
        self.status_code = status;
    }

    /// Get the continuation point created during the last request.
    pub fn continuation_point<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.input_continuation_point.as_ref().and_then(|c| c.get())
    }

    /// Get the continuation point created during the last request.
    pub fn continuation_point_mut<T: Send + Sync + 'static>(&mut self) -> Option<&mut T> {
        self.input_continuation_point
            .as_mut()
            .and_then(|c| c.get_mut())
    }

    /// Consume the continuation point created during the last request.
    pub fn take_continuation_point<T: Send + Sync + 'static>(&mut self) -> Option<Box<T>> {
        self.input_continuation_point.take().and_then(|c| c.take())
    }

    /// Set the continuation point that will be returned to the client.
    pub fn set_next_continuation_point<T: Send + Sync + 'static>(
        &mut self,
        continuation_point: Box<T>,
    ) {
        self.next_continuation_point = Some(ContinuationPoint::new(continuation_point));
    }

    /// Get the current number of added references.
    pub fn result_len(&self) -> usize {
        self.references.len()
    }

    /// Get the number of references that can be added to this result before
    /// stopping and returning a continuation point.
    pub fn remaining(&self) -> usize {
        if self.result_len() >= self.max_references_per_node {
            0
        } else {
            self.max_references_per_node - self.result_len()
        }
    }

    /// Add a reference to the results list, without verifying that it is valid.
    /// If you do this, you are responsible for validating filters,
    /// and requested fields on each reference.
    pub fn add_unchecked(&mut self, reference: ReferenceDescription) {
        self.references.push(reference);
    }

    /// Return `true` if nodes with the given reference type ID should be returned.
    pub fn allows_reference_type(&self, ty: &NodeId, type_tree: &dyn TypeTree) -> bool {
        if self.reference_type_id.is_null() {
            return true;
        }

        if !matches!(
            type_tree.get(&self.reference_type_id),
            Some(NodeClass::ReferenceType)
        ) {
            return false;
        }
        if self.include_subtypes {
            if !type_tree.is_subtype_of(ty, &self.reference_type_id) {
                return false;
            }
        } else if ty != &self.reference_type_id {
            return false;
        }
        true
    }

    /// Return `true` if nodes with the given node class should be returned.
    pub fn allows_node_class(&self, node_class: NodeClass) -> bool {
        self.node_class_mask.is_empty()
            || self
                .node_class_mask
                .contains(NodeClassMask::from_bits_truncate(node_class as u32))
    }

    /// Return `true` if the given reference should be returned.
    pub fn matches_filter(
        &self,
        type_tree: &dyn TypeTree,
        reference: &ReferenceDescription,
    ) -> bool {
        if reference.node_id.is_null() {
            warn!("Skipping reference with null NodeId");
            return false;
        }
        if matches!(reference.node_class, NodeClass::Unspecified) {
            warn!(
                "Skipping reference {} with unspecified node class and NodeId",
                reference.node_id
            );
            return false;
        }
        // Validate the reference and reference type
        if !reference.reference_type_id.is_null()
            && !matches!(
                type_tree.get(&reference.reference_type_id),
                Some(NodeClass::ReferenceType)
            )
        {
            warn!(
                "Skipping reference {} with reference type that does not exist or is not a ReferenceType",
                reference.node_id
            );
            return false;
        }

        if !self.allows_node_class(reference.node_class) {
            return false;
        }

        // Check the reference type filter.
        self.allows_reference_type(&reference.reference_type_id, type_tree)
    }

    /// Add a reference, validating that it matches the filters, and returning `Added` if it was added.
    /// If the browse node is full, this will return `Full` containing the given reference if
    /// `max_references_per_node` would be exceeded. In this case you are responsible for
    /// setting a `ContinuationPoint` to ensure all references are included.
    /// This will clear any fields not required by ResultMask.
    pub fn add(
        &mut self,
        type_tree: &dyn TypeTree,
        mut reference: ReferenceDescription,
    ) -> AddReferenceResult {
        // First, validate that the reference is valid at all.
        if !self.matches_filter(type_tree, &reference) {
            return AddReferenceResult::Rejected;
        }

        if !self
            .result_mask
            .contains(BrowseDescriptionResultMask::RESULT_MASK_BROWSE_NAME)
        {
            reference.browse_name = QualifiedName::null();
        }

        if !self
            .result_mask
            .contains(BrowseDescriptionResultMask::RESULT_MASK_DISPLAY_NAME)
        {
            reference.display_name = LocalizedText::null();
        }

        if !self
            .result_mask
            .contains(BrowseDescriptionResultMask::RESULT_MASK_NODE_CLASS)
        {
            reference.node_class = NodeClass::Unspecified;
        }

        if !self
            .result_mask
            .contains(BrowseDescriptionResultMask::RESULT_MASK_REFERENCE_TYPE)
        {
            reference.reference_type_id = NodeId::null();
        }

        if !self
            .result_mask
            .contains(BrowseDescriptionResultMask::RESULT_MASK_TYPE_DEFINITION)
        {
            reference.type_definition = ExpandedNodeId::null();
        }

        if self.remaining() > 0 {
            self.references.push(reference);
            AddReferenceResult::Added
        } else {
            AddReferenceResult::Full(reference)
        }
    }

    /// Whether to include subtypes of the `reference_type_id`.
    pub fn include_subtypes(&self) -> bool {
        self.include_subtypes
    }

    /// Node ID to browse.
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Direction to browse.
    pub fn browse_direction(&self) -> BrowseDirection {
        self.browse_direction
    }

    /// Mask for node classes to return. If this is empty, all node classes should be returned.
    pub fn node_class_mask(&self) -> &NodeClassMask {
        &self.node_class_mask
    }

    /// Mask for attributes to return.
    pub fn result_mask(&self) -> BrowseDescriptionResultMask {
        self.result_mask
    }

    /// Reference type ID of references to return. Subject to `include_subtypes`.
    pub fn reference_type_id(&self) -> &NodeId {
        &self.reference_type_id
    }

    pub(crate) fn into_result(
        self,
        node_manager_index: usize,
        node_manager_count: usize,
        session: &mut Session,
    ) -> (BrowseResult, usize) {
        // There may be a continuation point defined for the current node manager,
        // in that case return that. There is also a corner case here where
        // remaining == 0 and there is no continuation point.
        // In this case we need to pass an empty continuation point
        // to the next node manager.
        let inner = self
            .next_continuation_point
            .map(|c| (c, node_manager_index))
            .or_else(|| {
                if node_manager_index < node_manager_count - 1 {
                    Some((
                        ContinuationPoint::new(Box::new(EmptyContinuationPoint)),
                        node_manager_index + 1,
                    ))
                } else {
                    None
                }
            });

        let continuation_point = inner.map(|(p, node_manager_index)| BrowseContinuationPoint {
            node_manager_index,
            continuation_point: p,
            id: random::byte_string(6),
            node_id: self.node_id,
            browse_direction: self.browse_direction,
            reference_type_id: self.reference_type_id,
            include_subtypes: self.include_subtypes,
            node_class_mask: self.node_class_mask,
            result_mask: self.result_mask,
            max_references_per_node: self.max_references_per_node,
            external_references: self.external_references,
        });

        let mut result = BrowseResult {
            status_code: self.status_code,
            continuation_point: continuation_point
                .as_ref()
                .map(|c| c.id.clone())
                .unwrap_or_default(),
            references: Some(self.references),
        };

        // If we're out of continuation points, the correct response is to not store it, and
        // set the status code to BadNoContinuationPoints.
        if let Some(c) = continuation_point {
            if session.add_browse_continuation_point(c).is_err() {
                result.status_code = StatusCode::BadNoContinuationPoints;
                result.continuation_point = ByteString::null();
            }
        }

        (result, self.input_index)
    }

    /// Returns whether this node is completed in this invocation of the Browse or
    /// BrowseNext service. If this returns true, no new nodes should be added.
    pub fn is_completed(&self) -> bool {
        self.remaining() == 0 || self.next_continuation_point.is_some()
    }

    /// Add an external reference to the result. This will be resolved by
    /// calling into a different node manager.
    pub fn push_external_reference(&mut self, reference: ExternalReference) {
        self.external_references.push(reference);
    }

    /// Get an iterator over the external references.
    pub fn get_external_refs(&self) -> impl Iterator<Item = &NodeId> {
        self.external_references
            .iter()
            .map(|n| &n.target_id.node_id)
    }

    /// Return `true` if there are any external references to evaluate.
    pub fn any_external_refs(&self) -> bool {
        !self.external_references.is_empty()
    }

    pub(crate) fn resolve_external_references(
        &mut self,
        type_tree: &dyn TypeTree,
        resolved_nodes: &HashMap<&NodeId, &NodeMetadata>,
    ) {
        let mut cont_point = ExternalReferencesContPoint {
            items: VecDeque::new(),
        };

        let refs = std::mem::take(&mut self.external_references);
        for rf in refs {
            if let Some(meta) = resolved_nodes.get(&rf.target_id.node_id) {
                let rf = rf.into_reference((*meta).clone());
                if !self.matches_filter(type_tree, &rf) {
                    continue;
                }
                if self.remaining() > 0 {
                    self.add_unchecked(rf);
                } else {
                    cont_point.items.push_back(rf);
                }
            }
        }

        if !cont_point.items.is_empty() {
            self.set_next_continuation_point(Box::new(cont_point));
        }
    }
}

pub(crate) struct ExternalReferencesContPoint {
    pub items: VecDeque<ReferenceDescription>,
}

// The node manager model works somewhat poorly with translate browse paths.
// In theory a node manager should only need to know about references relating to its own nodes,
// but if a browse path crosses a boundary between node managers it isn't obvious
// how to handle that.
// If it becomes necessary there may be ways to handle this, but it may be we just leave it up
// to the user.

#[derive(Debug, Clone)]
pub(crate) struct BrowsePathResultElement {
    pub(crate) node: NodeId,
    pub(crate) depth: usize,
    pub(crate) unmatched_browse_name: Option<QualifiedName>,
}

/// Container for a node being discovered in a browse path operation.
#[derive(Debug, Clone)]
pub struct BrowsePathItem<'a> {
    pub(crate) node: NodeId,
    input_index: usize,
    depth: usize,
    node_manager_index: usize,
    iteration_number: usize,
    path: &'a [RelativePathElement],
    results: Vec<BrowsePathResultElement>,
    status: StatusCode,
    unmatched_browse_name: Option<QualifiedName>,
}

impl<'a> BrowsePathItem<'a> {
    pub(crate) fn new(
        elem: BrowsePathResultElement,
        input_index: usize,
        root: &BrowsePathItem<'a>,
        node_manager_index: usize,
        iteration_number: usize,
    ) -> Self {
        Self {
            node: elem.node,
            input_index,
            depth: elem.depth,
            node_manager_index,
            path: if elem.depth <= root.path.len() {
                &root.path[elem.depth..]
            } else {
                &[]
            },
            results: Vec::new(),
            status: StatusCode::Good,
            iteration_number,
            unmatched_browse_name: elem.unmatched_browse_name,
        }
    }

    pub(crate) fn new_root(path: &'a BrowsePath, input_index: usize) -> Self {
        let mut status = StatusCode::Good;
        let elements = path.relative_path.elements.as_ref();
        if elements.is_none() || elements.is_some_and(|e| e.is_empty()) {
            status = StatusCode::BadNothingToDo;
        } else if elements.unwrap().iter().any(|el| el.target_name.is_null()) {
            status = StatusCode::BadBrowseNameInvalid;
        }

        Self {
            node: path.starting_node.clone(),
            input_index,
            depth: 0,
            node_manager_index: usize::MAX,
            path: path.relative_path.elements.as_deref().unwrap_or(&[]),
            results: Vec::new(),
            status,
            iteration_number: 0,
            unmatched_browse_name: None,
        }
    }

    /// Full browse path for this item.
    pub fn path(&self) -> &'a [RelativePathElement] {
        self.path
    }

    /// Root node ID to evaluate the path from.
    pub fn node_id(&self) -> &NodeId {
        &self.node
    }

    /// Add a path result element.
    pub fn add_element(
        &mut self,
        node: NodeId,
        relative_depth: usize,
        unmatched_browse_name: Option<QualifiedName>,
    ) {
        self.results.push(BrowsePathResultElement {
            node,
            depth: self.depth + relative_depth,
            unmatched_browse_name,
        })
    }

    /// Set the status code for this operation.
    pub fn set_status(&mut self, status: StatusCode) {
        self.status = status;
    }

    pub(crate) fn results_mut(&mut self) -> &mut Vec<BrowsePathResultElement> {
        &mut self.results
    }

    pub(crate) fn input_index(&self) -> usize {
        self.input_index
    }

    pub(crate) fn node_manager_index(&self) -> usize {
        self.node_manager_index
    }

    /// Get the current result status code.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Get the current interation number.
    pub fn iteration_number(&self) -> usize {
        self.iteration_number
    }

    /// Get the last unmatched browse name, if present.
    pub fn unmatched_browse_name(&self) -> Option<&QualifiedName> {
        self.unmatched_browse_name.as_ref()
    }

    /// Set the browse name as matched by the node manager given by `node_manager_index`.
    pub fn set_browse_name_matched(&mut self, node_manager_index: usize) {
        self.unmatched_browse_name = None;
        self.node_manager_index = node_manager_index;
    }
}

#[derive(Debug)]
/// Container for a single node in a `RegisterNodes` call.
pub struct RegisterNodeItem {
    node_id: NodeId,
    registered: bool,
}

impl RegisterNodeItem {
    pub(crate) fn new(node_id: NodeId) -> Self {
        Self {
            node_id,
            registered: false,
        }
    }

    /// Node ID to register.
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Set the node registered status. This is returned to the client.
    pub fn set_registered(&mut self, registered: bool) {
        self.registered = registered;
    }

    pub(crate) fn into_result(self) -> Option<NodeId> {
        if self.registered {
            Some(self.node_id)
        } else {
            None
        }
    }
}

/// Implementation of translate_browse_path implemented by repeatedly calling browse.
/// Note that this is always less efficient than a dedicated implementation, but
/// for simple node managers it may be a simple solution to get translate browse paths support
/// without a complex implementation.
///
/// Arguments are simply the inputs to translate_browse_paths on `NodeManager`.
pub async fn impl_translate_browse_paths_using_browse(
    mgr: &(impl NodeManager + Send + Sync + 'static),
    context: &RequestContext,
    nodes: &mut [&mut BrowsePathItem<'_>],
) -> Result<(), StatusCode> {
    // For unmatched browse names we first need to check if the node exists.
    let mut to_get_metadata: Vec<_> = nodes
        .iter_mut()
        .filter(|n| n.unmatched_browse_name().is_some())
        .map(|r| {
            let id = r.node_id().clone();
            (
                r,
                ExternalReferenceRequest::new(
                    &id,
                    BrowseDescriptionResultMask::RESULT_MASK_BROWSE_NAME,
                ),
            )
        })
        .collect();
    let mut items_ref: Vec<_> = to_get_metadata.iter_mut().map(|r| &mut r.1).collect();
    mgr.resolve_external_references(context, &mut items_ref)
        .await;
    for (node, ext) in to_get_metadata {
        let Some(i) = ext.item else {
            continue;
        };
        if &i.browse_name == node.unmatched_browse_name().unwrap() {
            node.set_browse_name_matched(context.current_node_manager_index);
        }
    }

    // Start with a map from the node ID to browse, to the index in the original nodes array.
    let mut current_targets = HashMap::new();
    for (idx, item) in nodes.iter_mut().enumerate() {
        // If the node is still unmatched, don't use it.
        if item.unmatched_browse_name.is_some() {
            continue;
        }
        current_targets.insert(item.node_id().clone(), idx);
    }
    let mut next_targets = HashMap::new();
    let mut depth = 0;
    loop {
        // If we are out of targets, we've reached the end.
        if current_targets.is_empty() {
            break;
        }

        // For each target, make a browse node.
        let mut targets = Vec::with_capacity(current_targets.len());
        let mut target_idx_map = HashMap::new();
        for (id, target) in current_targets.iter() {
            let node = &mut nodes[*target];
            let elem = &node.path()[depth];
            target_idx_map.insert(targets.len(), *target);
            targets.push(BrowseNode::new(
                BrowseDescription {
                    node_id: id.clone(),
                    browse_direction: if elem.is_inverse {
                        BrowseDirection::Inverse
                    } else {
                        BrowseDirection::Forward
                    },
                    reference_type_id: elem.reference_type_id.clone(),
                    include_subtypes: elem.include_subtypes,
                    node_class_mask: NodeClassMask::all().bits(),
                    result_mask: BrowseResultMask::BrowseName as u32,
                },
                context
                    .info
                    .config
                    .limits
                    .operational
                    .max_references_per_browse_node,
                *target,
            ));
        }
        mgr.browse(context, &mut targets).await?;

        // Call browse until the results are exhausted.
        let mut next = targets;
        loop {
            let mut next_t = Vec::with_capacity(next.len());
            for (idx, mut target) in next.into_iter().enumerate() {
                // For each node we just browsed, drain the references and external references
                // and produce path target elements from them.
                let orig_idx = target_idx_map[&idx];
                let path_target = &mut nodes[orig_idx];
                let path_elem = &path_target.path[depth];
                for it in target.references.drain(..) {
                    // If we found a reference, add it as a target.
                    if it.browse_name == path_elem.target_name {
                        // If the path is empty, we shouldn't browse any further.
                        if path_target.path.len() > depth + 1 {
                            next_targets.insert(it.node_id.node_id.clone(), orig_idx);
                        }
                        path_target.add_element(it.node_id.node_id, depth + 1, None);
                    }
                }
                // External references are added as unmatched nodes.
                for ext in target.external_references.drain(..) {
                    path_target.add_element(
                        ext.target_id.node_id,
                        depth + 1,
                        Some(path_elem.target_name.clone()),
                    );
                }

                if target.next_continuation_point.is_some() {
                    target.input_continuation_point = target.next_continuation_point;
                    target.next_continuation_point = None;
                    next_t.push(target);
                }
            }
            if next_t.is_empty() {
                break;
            }
            mgr.browse(context, &mut next_t).await?;
            next = next_t;
        }
        std::mem::swap(&mut current_targets, &mut next_targets);
        next_targets.clear();

        depth += 1;
    }

    Ok(())
}
