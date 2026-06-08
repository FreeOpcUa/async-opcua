//! Query graph traversal helpers.

use std::collections::{HashSet, VecDeque};

use crate::{
    address_space::{AddressSpace, HasNodeId, NodeType},
    node_manager::ParsedNodeTypeDescription,
    services::query::filter::QueryNodeFilter,
};
use opcua_nodes::{ParsedContentFilter, ParsedOperand, TypeTree};
use opcua_types::{BrowseDirection, FilterOperator, NodeId, Variant};

/// Iterates over address-space nodes that satisfy type filters and complex `RelatedTo` joins.
pub struct QueryGraphTraversal<'a> {
    address_space: &'a AddressSpace,
    type_tree: &'a dyn TypeTree,
    node_filter: QueryNodeFilter<'a>,
    node_types: &'a [ParsedNodeTypeDescription],
    candidate_type: Option<&'a NodeId>,
    content_filter: &'a ParsedContentFilter,
    has_related_to: bool,
    related_to_filter: Option<RelatedToFilter<'a>>,
    nodes: Box<dyn Iterator<Item = NodeId> + 'a>,
}

impl<'a> QueryGraphTraversal<'a> {
    /// Creates a traversal over every node in `address_space`.
    #[must_use]
    pub fn new(
        address_space: &'a AddressSpace,
        type_tree: &'a dyn TypeTree,
        node_types: &'a [ParsedNodeTypeDescription],
        content_filter: &'a ParsedContentFilter,
    ) -> Self {
        Self {
            address_space,
            type_tree,
            node_filter: QueryNodeFilter::new(address_space, type_tree),
            node_types,
            candidate_type: None,
            content_filter,
            has_related_to: content_filter_has_related_to(content_filter),
            related_to_filter: single_related_to_filter(content_filter),
            nodes: Box::new(address_space.iter_node_ids()),
        }
    }

    /// Creates a traversal over a caller-provided set of candidate nodes.
    #[must_use]
    pub fn with_candidates(
        address_space: &'a AddressSpace,
        type_tree: &'a dyn TypeTree,
        node_types: &'a [ParsedNodeTypeDescription],
        content_filter: &'a ParsedContentFilter,
        candidates: impl Iterator<Item = NodeId> + 'a,
    ) -> Self {
        Self {
            address_space,
            type_tree,
            node_filter: QueryNodeFilter::new(address_space, type_tree),
            node_types,
            candidate_type: None,
            content_filter,
            has_related_to: content_filter_has_related_to(content_filter),
            related_to_filter: single_related_to_filter(content_filter),
            nodes: Box::new(candidates),
        }
    }

    /// Creates a traversal over candidates that already share a known type definition.
    #[must_use]
    pub fn with_typed_candidates(
        address_space: &'a AddressSpace,
        type_tree: &'a dyn TypeTree,
        candidate_type: &'a NodeId,
        content_filter: &'a ParsedContentFilter,
        candidates: impl Iterator<Item = NodeId> + 'a,
    ) -> Self {
        Self {
            address_space,
            type_tree,
            node_filter: QueryNodeFilter::new(address_space, type_tree),
            node_types: &[],
            candidate_type: Some(candidate_type),
            content_filter,
            has_related_to: content_filter_has_related_to(content_filter),
            related_to_filter: single_related_to_filter(content_filter),
            nodes: Box::new(candidates),
        }
    }

    fn matches(&self, node_id: &NodeId) -> bool {
        self.node_filter
            .matches_node_types(node_id, self.node_types)
            && self.matches_content_filter(node_id)
    }

    fn matches_content_filter(&self, node_id: &NodeId) -> bool {
        if self.content_filter.elements().is_empty() {
            return true;
        }

        if let Some(related_to_filter) = self.related_to_filter {
            return self.matches_related_to_filter(node_id, related_to_filter);
        }

        if self.has_related_to {
            return self.matches_complex_element(node_id, 0);
        }

        self.node_filter
            .matches_content_filter(node_id, self.content_filter)
    }

    fn matches_complex_element(&self, node_id: &NodeId, index: usize) -> bool {
        let Some(element) = self.content_filter.elements().get(index) else {
            return false;
        };

        match element.operator() {
            FilterOperator::RelatedTo => {
                self.matches_related_to_element(node_id, element.operands())
            }
            FilterOperator::And => {
                self.matches_operand_bool(node_id, element.operands().first())
                    && self.matches_operand_bool(node_id, element.operands().get(1))
            }
            FilterOperator::Or => {
                self.matches_operand_bool(node_id, element.operands().first())
                    || self.matches_operand_bool(node_id, element.operands().get(1))
            }
            FilterOperator::Not => !self.matches_operand_bool(node_id, element.operands().first()),
            _ => self
                .node_filter
                .matches_content_filter(node_id, self.content_filter),
        }
    }

    fn matches_related_to_filter(&self, node_id: &NodeId, filter: RelatedToFilter<'_>) -> bool {
        if !self.node_matches_source_related_operand(
            node_id,
            filter.source,
            filter.include_type_subtypes,
        ) {
            return false;
        }

        if filter.hops == 0 {
            self.related_nodes(
                node_id,
                filter.reference_type,
                filter.include_reference_subtypes,
                None,
            )
            .any(|related| {
                self.node_matches_related_operand(
                    &related,
                    filter.target,
                    filter.include_type_subtypes,
                )
            })
        } else if filter.hops == 1 {
            self.address_space
                .find_references(
                    node_id,
                    Some((filter.reference_type, filter.include_reference_subtypes)),
                    self.type_tree,
                    BrowseDirection::Forward,
                )
                .any(|reference| {
                    self.node_matches_related_operand(
                        reference.target_node,
                        filter.target,
                        filter.include_type_subtypes,
                    )
                })
        } else {
            self.related_nodes(
                node_id,
                filter.reference_type,
                filter.include_reference_subtypes,
                Some(filter.hops),
            )
            .any(|related| {
                self.node_matches_related_operand(
                    &related,
                    filter.target,
                    filter.include_type_subtypes,
                )
            })
        }
    }

    fn matches_operand_bool(&self, node_id: &NodeId, operand: Option<&ParsedOperand>) -> bool {
        match operand {
            Some(ParsedOperand::ElementOperand(element)) => {
                self.matches_complex_element(node_id, element.index as usize)
            }
            Some(ParsedOperand::LiteralOperand(literal)) => {
                matches!(literal.value, Variant::Boolean(true))
            }
            _ => false,
        }
    }

    fn matches_related_to_element(&self, node_id: &NodeId, operands: &[ParsedOperand]) -> bool {
        let Some(source) = related_operand(operands.first()) else {
            return false;
        };
        let Some(target) = related_operand(operands.get(1)) else {
            return false;
        };
        let Some(reference_type) = operand_node_id(operands.get(2)) else {
            return false;
        };
        let Some(hops) = operand_u32(operands.get(3)) else {
            return false;
        };
        let include_type_subtypes = operand_bool(operands.get(4)).unwrap_or(false);
        let include_reference_subtypes = operand_bool(operands.get(5)).unwrap_or(false);

        if !self.node_matches_source_related_operand(node_id, source, include_type_subtypes) {
            return false;
        }

        if hops == 0 {
            self.related_nodes(node_id, reference_type, include_reference_subtypes, None)
                .any(|related| {
                    self.node_matches_related_operand(&related, target, include_type_subtypes)
                })
        } else if hops == 1 {
            self.address_space
                .find_references(
                    node_id,
                    Some((reference_type, include_reference_subtypes)),
                    self.type_tree,
                    BrowseDirection::Forward,
                )
                .any(|reference| {
                    self.node_matches_related_operand(
                        reference.target_node,
                        target,
                        include_type_subtypes,
                    )
                })
        } else {
            self.related_nodes(
                node_id,
                reference_type,
                include_reference_subtypes,
                Some(hops),
            )
            .any(|related| {
                self.node_matches_related_operand(&related, target, include_type_subtypes)
            })
        }
    }

    fn node_matches_related_operand(
        &self,
        node_id: &NodeId,
        operand: RelatedOperand<'_>,
        include_type_subtypes: bool,
    ) -> bool {
        match operand {
            RelatedOperand::Type(type_id) => {
                self.node_has_type(node_id, type_id, include_type_subtypes)
            }
            RelatedOperand::RelatedToElement(index) => self
                .content_filter
                .elements()
                .get(index)
                .is_some_and(|element| {
                    element.operator() == FilterOperator::RelatedTo
                        && self.matches_related_to_element(node_id, element.operands())
                }),
        }
    }

    fn node_matches_source_related_operand(
        &self,
        node_id: &NodeId,
        operand: RelatedOperand<'_>,
        include_type_subtypes: bool,
    ) -> bool {
        if let (Some(candidate_type), RelatedOperand::Type(type_id)) =
            (self.candidate_type, operand)
        {
            return *candidate_type == *type_id
                || include_type_subtypes && self.type_tree.is_subtype_of(candidate_type, type_id);
        }

        self.node_matches_related_operand(node_id, operand, include_type_subtypes)
    }

    fn related_nodes(
        &self,
        node_id: &NodeId,
        reference_type: &NodeId,
        include_reference_subtypes: bool,
        max_hops: Option<u32>,
    ) -> RelatedNodes<'a> {
        RelatedNodes::new(
            self.address_space,
            self.type_tree,
            node_id.clone(),
            reference_type.clone(),
            include_reference_subtypes,
            max_hops,
        )
    }

    fn node_has_type(
        &self,
        node_id: &NodeId,
        expected_type: &NodeId,
        include_subtypes: bool,
    ) -> bool {
        self.node_filter
            .node_type_definition(node_id)
            .is_some_and(|actual_type| {
                actual_type == *expected_type
                    || include_subtypes && self.type_tree.is_subtype_of(&actual_type, expected_type)
            })
    }
}

impl Iterator for QueryGraphTraversal<'_> {
    type Item = NodeId;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(node_id) = self.nodes.next() {
            if self.matches(&node_id) {
                return Some(node_id);
            }
        }

        None
    }
}

struct RelatedNodes<'a> {
    address_space: &'a AddressSpace,
    type_tree: &'a dyn TypeTree,
    reference_type: NodeId,
    include_reference_subtypes: bool,
    max_hops: Option<u32>,
    queue: VecDeque<(NodeId, u32)>,
    matches: VecDeque<NodeId>,
    visited: HashSet<NodeId>,
}

impl<'a> RelatedNodes<'a> {
    fn new(
        address_space: &'a AddressSpace,
        type_tree: &'a dyn TypeTree,
        start: NodeId,
        reference_type: NodeId,
        include_reference_subtypes: bool,
        max_hops: Option<u32>,
    ) -> Self {
        let mut visited = HashSet::new();
        visited.insert(start.clone());

        let mut queue = VecDeque::new();
        queue.push_back((start, 0));

        Self {
            address_space,
            type_tree,
            reference_type,
            include_reference_subtypes,
            max_hops,
            queue,
            matches: VecDeque::new(),
            visited,
        }
    }
}

impl Iterator for RelatedNodes<'_> {
    type Item = NodeId;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(node_id) = self.matches.pop_front() {
            return Some(node_id);
        }

        while let Some((node_id, depth)) = self.queue.pop_front() {
            if self.max_hops.is_some_and(|max_hops| depth >= max_hops) {
                continue;
            }

            for reference in self.address_space.find_references(
                &node_id,
                Some((&self.reference_type, self.include_reference_subtypes)),
                self.type_tree,
                BrowseDirection::Forward,
            ) {
                let target = reference.target_node.clone();
                if self.visited.insert(target.clone()) {
                    let next_depth = depth + 1;
                    self.queue.push_back((target.clone(), next_depth));
                    if self.max_hops.is_none_or(|max_hops| next_depth == max_hops) {
                        self.matches.push_back(target);
                    }
                }
            }

            if let Some(node_id) = self.matches.pop_front() {
                return Some(node_id);
            }
        }

        None
    }
}

fn operand_node_id(operand: Option<&ParsedOperand>) -> Option<&NodeId> {
    match operand {
        Some(ParsedOperand::LiteralOperand(literal)) => match &literal.value {
            Variant::NodeId(node_id) => Some(node_id),
            Variant::ExpandedNodeId(node_id) if node_id.server_index == 0 => Some(&node_id.node_id),
            _ => None,
        },
        _ => None,
    }
}

fn content_filter_has_related_to(content_filter: &ParsedContentFilter) -> bool {
    content_filter
        .elements()
        .iter()
        .any(|element| element.operator() == FilterOperator::RelatedTo)
}

#[derive(Clone, Copy)]
struct RelatedToFilter<'a> {
    source: RelatedOperand<'a>,
    target: RelatedOperand<'a>,
    reference_type: &'a NodeId,
    hops: u32,
    include_type_subtypes: bool,
    include_reference_subtypes: bool,
}

fn single_related_to_filter(content_filter: &ParsedContentFilter) -> Option<RelatedToFilter<'_>> {
    let [element] = content_filter.elements() else {
        return None;
    };
    if element.operator() != FilterOperator::RelatedTo {
        return None;
    }

    let operands = element.operands();
    Some(RelatedToFilter {
        source: related_operand(operands.first())?,
        target: related_operand(operands.get(1))?,
        reference_type: operand_node_id(operands.get(2))?,
        hops: operand_u32(operands.get(3))?,
        include_type_subtypes: operand_bool(operands.get(4)).unwrap_or(false),
        include_reference_subtypes: operand_bool(operands.get(5)).unwrap_or(false),
    })
}

#[derive(Clone, Copy)]
enum RelatedOperand<'a> {
    Type(&'a NodeId),
    RelatedToElement(usize),
}

fn related_operand(operand: Option<&ParsedOperand>) -> Option<RelatedOperand<'_>> {
    match operand {
        Some(ParsedOperand::LiteralOperand(literal)) => match &literal.value {
            Variant::NodeId(node_id) => Some(RelatedOperand::Type(node_id)),
            Variant::ExpandedNodeId(node_id) if node_id.server_index == 0 => {
                Some(RelatedOperand::Type(&node_id.node_id))
            }
            _ => None,
        },
        Some(ParsedOperand::ElementOperand(element)) => {
            Some(RelatedOperand::RelatedToElement(element.index as usize))
        }
        _ => None,
    }
}

fn operand_u32(operand: Option<&ParsedOperand>) -> Option<u32> {
    match operand {
        Some(ParsedOperand::LiteralOperand(literal)) => match &literal.value {
            Variant::UInt32(value) => Some(*value),
            Variant::UInt16(value) => Some(u32::from(*value)),
            Variant::Byte(value) => Some(u32::from(*value)),
            _ => None,
        },
        _ => None,
    }
}

fn operand_bool(operand: Option<&ParsedOperand>) -> Option<bool> {
    match operand {
        Some(ParsedOperand::LiteralOperand(literal)) => match &literal.value {
            Variant::Boolean(value) => Some(*value),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::QueryGraphTraversal;
    use crate::{
        address_space::{AddressSpace, ObjectBuilder, ObjectTypeBuilder},
        node_manager::ParsedNodeTypeDescription,
    };
    use opcua_nodes::{DefaultTypeTree, ParsedContentFilter};
    use opcua_types::{
        ContentFilter, ContentFilterElement, ExpandedNodeId, FilterOperator, NodeId, ObjectTypeId,
        Operand, QualifiedName, ReferenceTypeId, StatusCode,
    };

    const TEST_NAMESPACE_URI: &str = "urn:async-opcua:query-traversal-tests";

    struct Fixture {
        address_space: AddressSpace,
        type_tree: DefaultTypeTree,
        fermenter_type: NodeId,
        controller_type: NodeId,
        matching_fermenter: NodeId,
        nonmatching_fermenter: NodeId,
        controller: NodeId,
    }

    impl Fixture {
        fn new() -> Self {
            let namespace_index = 1;
            let fermenter_type = NodeId::new(namespace_index, "FermenterType");
            let cip_fermenter_type = NodeId::new(namespace_index, "CipFermenterType");
            let controller_type = NodeId::new(namespace_index, "ControllerType");
            let matching_fermenter = NodeId::new(namespace_index, "Fermenter-101");
            let nonmatching_fermenter = NodeId::new(namespace_index, "Fermenter-102");
            let controller = NodeId::new(namespace_index, "Controller-101");

            let mut address_space = AddressSpace::new();
            address_space.add_namespace(TEST_NAMESPACE_URI, namespace_index);

            ObjectTypeBuilder::new(
                &fermenter_type,
                QualifiedName::new(namespace_index, "FermenterType"),
                "FermenterType",
            )
            .subtype_of(ObjectTypeId::BaseObjectType)
            .insert(&mut address_space);

            ObjectTypeBuilder::new(
                &cip_fermenter_type,
                QualifiedName::new(namespace_index, "CipFermenterType"),
                "CipFermenterType",
            )
            .subtype_of(fermenter_type.clone())
            .insert(&mut address_space);

            ObjectTypeBuilder::new(
                &controller_type,
                QualifiedName::new(namespace_index, "ControllerType"),
                "ControllerType",
            )
            .subtype_of(ObjectTypeId::BaseObjectType)
            .insert(&mut address_space);

            ObjectBuilder::new(
                &matching_fermenter,
                QualifiedName::new(namespace_index, "Fermenter-101"),
                "Fermenter 101",
            )
            .has_type_definition(cip_fermenter_type.clone())
            .insert(&mut address_space);

            ObjectBuilder::new(
                &nonmatching_fermenter,
                QualifiedName::new(namespace_index, "Fermenter-102"),
                "Fermenter 102",
            )
            .has_type_definition(cip_fermenter_type.clone())
            .insert(&mut address_space);

            ObjectBuilder::new(
                &controller,
                QualifiedName::new(namespace_index, "Controller-101"),
                "Controller 101",
            )
            .has_type_definition(controller_type.clone())
            .component_of(matching_fermenter.clone())
            .insert(&mut address_space);

            let mut type_tree = DefaultTypeTree::new();
            type_tree.namespaces_mut().add_namespace(TEST_NAMESPACE_URI);
            address_space.load_into_type_tree(&mut type_tree);

            Self {
                address_space,
                type_tree,
                fermenter_type,
                controller_type,
                matching_fermenter,
                nonmatching_fermenter,
                controller,
            }
        }

        fn traverse<'a>(
            &'a self,
            node_types: &'a [ParsedNodeTypeDescription],
            content_filter: &'a ParsedContentFilter,
        ) -> Vec<NodeId> {
            QueryGraphTraversal::new(
                &self.address_space,
                &self.type_tree,
                node_types,
                content_filter,
            )
            .collect()
        }
    }

    #[test]
    fn related_to_yields_nodes_with_matching_related_target_at_requested_hop() {
        let fixture = Fixture::new();
        let node_types = vec![node_type_description(&fixture.fermenter_type, true)];
        let content_filter = parse_content_filter(related_to_filter(
            &fixture.fermenter_type,
            &fixture.controller_type,
            1,
            true,
        ));

        let matches = fixture.traverse(&node_types, &content_filter);

        assert_eq!(matches, vec![fixture.matching_fermenter.clone()]);
        assert!(!matches.contains(&fixture.nonmatching_fermenter));
    }

    #[test]
    fn related_to_honors_type_subtype_operand() {
        let fixture = Fixture::new();
        let node_types = vec![node_type_description(&fixture.fermenter_type, true)];
        let content_filter = parse_content_filter(related_to_filter(
            &fixture.fermenter_type,
            &fixture.controller_type,
            1,
            false,
        ));

        let matches = fixture.traverse(&node_types, &content_filter);

        assert!(matches.is_empty());
    }

    #[test]
    fn related_to_zero_hops_searches_to_logical_end() {
        let mut fixture = Fixture::new();
        let nested_controller = NodeId::new(1, "NestedController");

        ObjectBuilder::new(
            &nested_controller,
            QualifiedName::new(1, "NestedController"),
            "Nested Controller",
        )
        .has_type_definition(fixture.controller_type.clone())
        .component_of(fixture.controller.clone())
        .insert(&mut fixture.address_space);

        let node_types = vec![node_type_description(&fixture.fermenter_type, true)];
        let content_filter = parse_content_filter(related_to_filter(
            &fixture.fermenter_type,
            &fixture.controller_type,
            0,
            true,
        ));

        let matches = fixture.traverse(&node_types, &content_filter);

        assert_eq!(matches, vec![fixture.matching_fermenter]);
    }

    #[test]
    fn related_to_supports_chained_element_operands() {
        let mut fixture = Fixture::new();
        let module_type = NodeId::new(1, "ModuleType");
        let module = NodeId::new(1, "Module-101");

        ObjectTypeBuilder::new(
            &module_type,
            QualifiedName::new(1, "ModuleType"),
            "ModuleType",
        )
        .subtype_of(ObjectTypeId::BaseObjectType)
        .insert(&mut fixture.address_space);

        ObjectBuilder::new(&module, QualifiedName::new(1, "Module-101"), "Module 101")
            .has_type_definition(module_type.clone())
            .component_of(fixture.controller.clone())
            .insert(&mut fixture.address_space);

        fixture
            .address_space
            .load_into_type_tree(&mut fixture.type_tree);

        let node_types = vec![node_type_description(&fixture.fermenter_type, true)];
        let content_filter = parse_content_filter(ContentFilter {
            elements: Some(vec![
                related_to_element(
                    Operand::literal(fixture.fermenter_type.clone()),
                    Operand::element(1),
                    1,
                    true,
                ),
                related_to_element(
                    Operand::literal(fixture.controller_type.clone()),
                    Operand::literal(module_type),
                    1,
                    true,
                ),
            ]),
        });

        let matches = fixture.traverse(&node_types, &content_filter);

        assert_eq!(matches, vec![fixture.matching_fermenter]);
    }

    fn node_type_description(
        type_definition_node: &NodeId,
        include_sub_types: bool,
    ) -> ParsedNodeTypeDescription {
        ParsedNodeTypeDescription {
            type_definition_node: ExpandedNodeId::new(type_definition_node.clone()),
            include_sub_types,
            data_to_return: Vec::new(),
        }
    }

    fn related_to_filter(
        source_type: &NodeId,
        target_type: &NodeId,
        hops: u32,
        include_type_subtypes: bool,
    ) -> ContentFilter {
        ContentFilter {
            elements: Some(vec![related_to_element(
                Operand::literal(source_type.clone()),
                Operand::literal(target_type.clone()),
                hops,
                include_type_subtypes,
            )]),
        }
    }

    fn related_to_element(
        source: Operand,
        target: Operand,
        hops: u32,
        include_type_subtypes: bool,
    ) -> ContentFilterElement {
        ContentFilterElement::from((
            FilterOperator::RelatedTo,
            vec![
                source,
                target,
                Operand::literal(NodeId::from(ReferenceTypeId::HasComponent)),
                Operand::literal(hops),
                Operand::literal(include_type_subtypes),
                Operand::literal(true),
            ],
        ))
    }

    fn parse_content_filter(filter: ContentFilter) -> ParsedContentFilter {
        let type_tree = DefaultTypeTree::new();
        let (result, parsed) = ParsedContentFilter::parse(filter, &type_tree, false, &[]);
        assert_eq!(
            result.element_results.expect("element results")[0].status_code,
            StatusCode::Good
        );
        parsed.expect("content filter should parse")
    }
}
