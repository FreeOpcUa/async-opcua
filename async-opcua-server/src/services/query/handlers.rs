//! Query service handlers.

use std::collections::HashSet;

use crate::{
    address_space::{read_node_value, validate_node_read, AddressSpace, HasNodeId, NodeType},
    node_manager::{
        ParsedNodeTypeDescription, ParsedQueryDataDescription, ParsedReadValueId, QueryRequest,
        RequestContext,
    },
    services::query::{filter::QueryNodeFilter, traversal::QueryGraphTraversal},
    session::continuation_points::{ContinuationPoint, EmptyContinuationPoint},
};
use opcua_nodes::TypeTree;
use opcua_types::{
    AttributeId, BrowseDirection, DataEncoding, ExpandedNodeId, NodeId, QueryDataSet,
    ReferenceTypeId, RelativePath, StatusCode, TimestampsToReturn, Variant,
};

/// Continuation state for paged `QueryFirst`/`QueryNext` traversal.
#[derive(Debug, Clone, Copy)]
pub(crate) struct QueryFirstContinuationPoint {
    emitted_matches: usize,
}

/// Executes QueryFirst-style graph queries over an in-memory address space.
pub(crate) struct QueryFirstHandler<'a, 'ctx> {
    address_space: &'a AddressSpace,
    type_tree: &'a dyn TypeTree,
    context: Option<&'ctx RequestContext>,
    node_filter: QueryNodeFilter<'a>,
}

/// Executes QueryNext-style graph queries from a stored continuation point.
pub(crate) struct QueryNextHandler<'a, 'ctx> {
    inner: QueryFirstHandler<'a, 'ctx>,
}

impl<'a, 'ctx> QueryFirstHandler<'a, 'ctx> {
    #[must_use]
    pub(crate) fn new(
        address_space: &'a AddressSpace,
        type_tree: &'a dyn TypeTree,
        context: &'ctx RequestContext,
    ) -> Self {
        Self::with_context(address_space, type_tree, Some(context))
    }

    #[cfg(test)]
    #[must_use]
    fn new_unrestricted(address_space: &'a AddressSpace, type_tree: &'a dyn TypeTree) -> Self {
        Self::with_context(address_space, type_tree, None)
    }

    fn with_context(
        address_space: &'a AddressSpace,
        type_tree: &'a dyn TypeTree,
        context: Option<&'ctx RequestContext>,
    ) -> Self {
        Self {
            address_space,
            type_tree,
            context,
            node_filter: QueryNodeFilter::new(address_space, type_tree),
        }
    }

    pub(crate) fn execute(&self, request: &mut QueryRequest) -> Result<(), StatusCode> {
        let start_offset = self.start_offset(request)?;
        if request.remaining_data_sets() == 0 {
            return Ok(());
        }

        let page_size = request.remaining_data_sets();
        let (data_sets, has_more) = {
            let node_types = request.node_types();
            let mut traversal = self
                .traversal_for(node_types, request.filter())
                .filter(|node_id| self.query_result_is_authorized(node_id))
                .skip(start_offset);
            let mut data_sets = Vec::with_capacity(page_size);

            while data_sets.len() < page_size {
                let Some(node_id) = traversal.next() else {
                    break;
                };

                data_sets.push(self.data_set_for(&node_id, node_types));
            }

            let has_more = traversal.next().is_some();
            (data_sets, has_more)
        };
        let emitted = data_sets.len();

        for data_set in data_sets {
            request.add_data_set(data_set);
        }

        if has_more {
            request.set_next_continuation_point(Some(ContinuationPoint::new(Box::new(
                QueryFirstContinuationPoint {
                    emitted_matches: start_offset + emitted,
                },
            ))));
        }

        Ok(())
    }

    fn start_offset(&self, request: &QueryRequest) -> Result<usize, StatusCode> {
        let Some(point) = request.continuation_point() else {
            return Ok(0);
        };

        if let Some(point) = point.get::<QueryFirstContinuationPoint>() {
            return Ok(point.emitted_matches);
        }
        if point.get::<EmptyContinuationPoint>().is_some() {
            return Ok(0);
        }

        Err(StatusCode::BadContinuationPointInvalid)
    }

    fn traversal_for(
        &self,
        node_types: &'a [ParsedNodeTypeDescription],
        content_filter: &'a opcua_nodes::ParsedContentFilter,
    ) -> QueryGraphTraversal<'a> {
        if let Some(traversal) = self.single_exact_type_traversal(node_types, content_filter) {
            return traversal;
        }

        if let Some(candidates) = self.exact_type_candidates(node_types) {
            QueryGraphTraversal::with_candidates(
                self.address_space,
                self.type_tree,
                &[],
                content_filter,
                candidates.into_iter(),
            )
        } else {
            QueryGraphTraversal::new(
                self.address_space,
                self.type_tree,
                node_types,
                content_filter,
            )
        }
    }

    fn single_exact_type_traversal(
        &self,
        node_types: &'a [ParsedNodeTypeDescription],
        content_filter: &'a opcua_nodes::ParsedContentFilter,
    ) -> Option<QueryGraphTraversal<'a>> {
        let [node_type] = node_types else {
            return None;
        };
        if node_type.include_sub_types {
            return None;
        }

        let type_id = node_type
            .type_definition_node
            .try_resolve(self.type_tree.namespaces())?;
        let std::borrow::Cow::Borrowed(type_id) = type_id else {
            return None;
        };
        let candidates = self
            .address_space
            .find_references(
                type_id,
                Some((ReferenceTypeId::HasTypeDefinition, false)),
                self.type_tree,
                BrowseDirection::Inverse,
            )
            .filter_map(|reference| self.address_space.find(reference.target_node));

        Some(QueryGraphTraversal::with_typed_candidates(
            self.address_space,
            self.type_tree,
            type_id,
            content_filter,
            candidates,
        ))
    }

    fn exact_type_candidates(
        &self,
        node_types: &'a [ParsedNodeTypeDescription],
    ) -> Option<Vec<&'a NodeType>> {
        if node_types.is_empty()
            || node_types
                .iter()
                .any(|node_type| node_type.include_sub_types)
        {
            return None;
        }

        if let [node_type] = node_types {
            return self.exact_type_candidate_nodes(node_type);
        }

        let mut seen = HashSet::new();
        let mut candidates = Vec::new();
        for node_type in node_types {
            for node in self.exact_type_candidate_nodes(node_type)? {
                let node_id = node.node_id().clone();
                if seen.insert(node_id) {
                    candidates.push(node);
                }
            }
        }

        Some(candidates)
    }

    fn exact_type_candidate_nodes(
        &self,
        node_type: &'a ParsedNodeTypeDescription,
    ) -> Option<Vec<&'a NodeType>> {
        let type_id = node_type
            .type_definition_node
            .try_resolve(self.type_tree.namespaces())?;
        let mut candidates = Vec::new();
        for reference in self.address_space.find_references(
            type_id.as_ref(),
            Some((ReferenceTypeId::HasTypeDefinition, false)),
            self.type_tree,
            BrowseDirection::Inverse,
        ) {
            if let Some(node) = self.address_space.find(reference.target_node) {
                candidates.push(node);
            }
        }

        Some(candidates)
    }

    fn data_set_for(
        &self,
        node_id: &NodeId,
        node_types: &[ParsedNodeTypeDescription],
    ) -> QueryDataSet {
        let type_definition = self
            .node_filter
            .node_type_definition(node_id)
            .unwrap_or_else(NodeId::null);
        let values = self
            .data_to_return(node_id, &type_definition, node_types)
            .filter(|descriptions| !descriptions.is_empty())
            .map(|descriptions| {
                descriptions
                    .iter()
                    .map(|description| self.selected_value(node_id, description))
                    .collect()
            });

        QueryDataSet {
            node_id: ExpandedNodeId::new(node_id.clone()),
            type_definition_node: ExpandedNodeId::new(type_definition),
            values,
        }
    }

    fn data_to_return<'b>(
        &self,
        node_id: &NodeId,
        type_definition: &NodeId,
        node_types: &'b [ParsedNodeTypeDescription],
    ) -> Option<&'b [ParsedQueryDataDescription]> {
        request_node_type_for(
            node_id,
            type_definition,
            self.type_tree,
            self.node_filter,
            node_types,
        )
        .map(|node_type| node_type.data_to_return.as_slice())
    }

    fn selected_value(
        &self,
        node_id: &NodeId,
        description: &ParsedQueryDataDescription,
    ) -> Variant {
        let Some(node) = self.relative_path_target(node_id, &description.relative_path) else {
            return Variant::StatusCode(StatusCode::BadNoMatch);
        };

        if let Some(context) = self.context {
            return self.selected_value_with_context(node, description, context);
        }

        self.selected_value_unrestricted(node, description)
    }

    fn selected_value_with_context(
        &self,
        node: &NodeType,
        description: &ParsedQueryDataDescription,
        context: &RequestContext,
    ) -> Variant {
        let node_to_read = ParsedReadValueId {
            node_id: node.node_id().clone(),
            attribute_id: description.attribute_id,
            index_range: description.index_range.clone(),
            data_encoding: DataEncoding::Binary,
        };

        if let Err(status) = validate_node_read(node, context, &node_to_read) {
            return Variant::StatusCode(status);
        }

        let value = read_node_value(
            node,
            context,
            &node_to_read,
            0.0,
            TimestampsToReturn::Neither,
        );

        if let Some(status) = value.status {
            if status.is_bad() {
                return Variant::StatusCode(status);
            }
        }

        value
            .value
            .unwrap_or(Variant::StatusCode(StatusCode::BadNoValue))
    }

    fn selected_value_unrestricted(
        &self,
        node: &NodeType,
        description: &ParsedQueryDataDescription,
    ) -> Variant {
        let Some(value) = node.as_node().get_attribute(
            TimestampsToReturn::Neither,
            description.attribute_id,
            &description.index_range,
            &DataEncoding::Binary,
        ) else {
            return Variant::StatusCode(StatusCode::BadAttributeIdInvalid);
        };

        if let Some(status) = value.status {
            if status.is_bad() {
                return Variant::StatusCode(status);
            }
        }

        value
            .value
            .unwrap_or(Variant::StatusCode(StatusCode::BadNoValue))
    }

    fn query_result_is_authorized(&self, node_id: &NodeId) -> bool {
        let Some(context) = self.context else {
            return true;
        };
        let Some(node) = self.address_space.find(node_id) else {
            return false;
        };
        let node_to_read = ParsedReadValueId {
            node_id: node_id.clone(),
            attribute_id: AttributeId::NodeId,
            index_range: Default::default(),
            data_encoding: DataEncoding::Binary,
        };

        validate_node_read(node, context, &node_to_read).is_ok()
    }

    fn relative_path_target(&self, node_id: &NodeId, path: &RelativePath) -> Option<&'a NodeType> {
        let mut node = self.address_space.find(node_id)?;

        for element in path.elements.as_deref().unwrap_or_default() {
            let direction = if element.is_inverse {
                BrowseDirection::Inverse
            } else {
                BrowseDirection::Forward
            };
            let next = self
                .address_space
                .find_references(
                    node.node_id(),
                    Some((&element.reference_type_id, element.include_subtypes)),
                    self.type_tree,
                    direction,
                )
                .filter_map(|reference| self.address_space.find(reference.target_node))
                .find(|candidate| candidate.as_node().browse_name() == &element.target_name)?;

            node = next;
        }

        Some(node)
    }
}

impl<'a, 'ctx> QueryNextHandler<'a, 'ctx> {
    #[must_use]
    pub(crate) fn new(
        address_space: &'a AddressSpace,
        type_tree: &'a dyn TypeTree,
        context: &'ctx RequestContext,
    ) -> Self {
        Self {
            inner: QueryFirstHandler::new(address_space, type_tree, context),
        }
    }

    #[cfg(test)]
    #[must_use]
    fn new_unrestricted(address_space: &'a AddressSpace, type_tree: &'a dyn TypeTree) -> Self {
        Self {
            inner: QueryFirstHandler::new_unrestricted(address_space, type_tree),
        }
    }

    pub(crate) fn execute(&self, request: &mut QueryRequest) -> Result<(), StatusCode> {
        if request.continuation_point().is_none() {
            return Err(StatusCode::BadContinuationPointInvalid);
        }

        self.inner.execute(request)
    }
}

fn request_node_type_for<'a>(
    node_id: &NodeId,
    type_definition: &NodeId,
    type_tree: &dyn TypeTree,
    node_filter: QueryNodeFilter<'_>,
    node_types: &'a [ParsedNodeTypeDescription],
) -> Option<&'a ParsedNodeTypeDescription> {
    node_types.iter().find(|node_type| {
        let Some(requested_type) = node_type
            .type_definition_node
            .try_resolve(type_tree.namespaces())
        else {
            return false;
        };

        type_definition == requested_type.as_ref()
            || node_type.include_sub_types
                && node_filter
                    .node_type_definition(node_id)
                    .is_some_and(|actual_type| {
                        type_tree.is_subtype_of(&actual_type, requested_type.as_ref())
                    })
    })
}

#[cfg(test)]
mod tests {
    use super::{QueryFirstContinuationPoint, QueryFirstHandler, QueryNextHandler};
    use crate::{
        address_space::{AddressSpace, ObjectBuilder, ObjectTypeBuilder},
        node_manager::{ParsedNodeTypeDescription, QueryRequest},
    };
    use opcua_nodes::{DefaultTypeTree, ParsedContentFilter};
    use opcua_types::{ExpandedNodeId, NodeId, ObjectTypeId, QualifiedName, StatusCode};

    const TEST_NAMESPACE_URI: &str = "urn:async-opcua:query-handler-tests";

    #[test]
    fn query_first_paginates_after_max_data_sets() {
        let fixture = Fixture::new(3);
        let mut request = QueryRequest::new(
            vec![node_type_description(&fixture.object_type)],
            ParsedContentFilter::empty(),
            2,
            10,
        );

        QueryFirstHandler::new_unrestricted(&fixture.address_space, &fixture.type_tree)
            .execute(&mut request)
            .expect("query should execute");

        assert_eq!(request.data_sets().len(), 2);
        assert!(request
            .next_continuation_point()
            .and_then(|point| point.get::<QueryFirstContinuationPoint>())
            .is_some());
    }

    #[test]
    fn query_first_returns_no_continuation_point_when_page_contains_all_matches() {
        let fixture = Fixture::new(2);
        let mut request = QueryRequest::new(
            vec![node_type_description(&fixture.object_type)],
            ParsedContentFilter::empty(),
            2,
            10,
        );

        QueryFirstHandler::new_unrestricted(&fixture.address_space, &fixture.type_tree)
            .execute(&mut request)
            .expect("query should execute");

        assert_eq!(request.data_sets().len(), 2);
        assert!(request.next_continuation_point().is_none());
    }

    #[test]
    fn query_next_rejects_missing_continuation_point() {
        let fixture = Fixture::new(2);
        let mut request = QueryRequest::new(
            vec![node_type_description(&fixture.object_type)],
            ParsedContentFilter::empty(),
            2,
            10,
        );

        let status = QueryNextHandler::new_unrestricted(&fixture.address_space, &fixture.type_tree)
            .execute(&mut request);

        assert_eq!(status, Err(StatusCode::BadContinuationPointInvalid));
    }

    struct Fixture {
        address_space: AddressSpace,
        type_tree: DefaultTypeTree,
        object_type: NodeId,
    }

    impl Fixture {
        fn new(object_count: usize) -> Self {
            let namespace_index = 1;
            let object_type = NodeId::new(namespace_index, "PagedObjectType");
            let mut address_space = AddressSpace::new();
            address_space.add_namespace(TEST_NAMESPACE_URI, namespace_index);

            ObjectTypeBuilder::new(
                &object_type,
                QualifiedName::new(namespace_index, "PagedObjectType"),
                "PagedObjectType",
            )
            .subtype_of(ObjectTypeId::BaseObjectType)
            .insert(&mut address_space);

            for index in 0..object_count {
                let node_id = NodeId::new(namespace_index, format!("PagedObject-{index}"));
                ObjectBuilder::new(
                    &node_id,
                    QualifiedName::new(namespace_index, format!("PagedObject-{index}")),
                    format!("Paged Object {index}"),
                )
                .has_type_definition(object_type.clone())
                .insert(&mut address_space);
            }

            let mut type_tree = DefaultTypeTree::new();
            type_tree.namespaces_mut().add_namespace(TEST_NAMESPACE_URI);
            address_space.load_into_type_tree(&mut type_tree);

            Self {
                address_space,
                type_tree,
                object_type,
            }
        }
    }

    fn node_type_description(type_definition_node: &NodeId) -> ParsedNodeTypeDescription {
        ParsedNodeTypeDescription {
            type_definition_node: ExpandedNodeId::new(type_definition_node.clone()),
            include_sub_types: true,
            data_to_return: Vec::new(),
        }
    }
}
