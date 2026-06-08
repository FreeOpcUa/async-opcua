//! Query node and property filter helpers.

use crate::{
    address_space::{AddressSpace, NodeType},
    node_manager::ParsedNodeTypeDescription,
};
use opcua_nodes::{AttributeQueryable, ParsedContentFilter, TypeTree};
use opcua_types::{
    AttributeId, BrowseDirection, DataEncoding, NodeId, NumericRange, QualifiedName,
    ReferenceTypeId, TimestampsToReturn, Variant,
};

/// Evaluates basic query filters against nodes in an [`AddressSpace`].
#[derive(Clone, Copy)]
pub struct QueryNodeFilter<'a> {
    address_space: &'a AddressSpace,
    type_tree: &'a dyn TypeTree,
}

impl<'a> QueryNodeFilter<'a> {
    /// Creates a filter evaluator for an address space and its type tree.
    #[must_use]
    pub fn new(address_space: &'a AddressSpace, type_tree: &'a dyn TypeTree) -> Self {
        Self {
            address_space,
            type_tree,
        }
    }

    /// Returns `true` when `node_id` matches the requested node types and content filter.
    #[must_use]
    pub fn matches(
        &self,
        node_id: &NodeId,
        node_types: &[ParsedNodeTypeDescription],
        content_filter: &ParsedContentFilter,
    ) -> bool {
        self.matches_node_types(node_id, node_types)
            && self.matches_content_filter(node_id, content_filter)
    }

    /// Returns `true` when `node_id` satisfies one of the requested node type descriptions.
    #[must_use]
    pub fn matches_node_types(
        &self,
        node_id: &NodeId,
        node_types: &[ParsedNodeTypeDescription],
    ) -> bool {
        if node_types.is_empty() {
            return true;
        }

        let Some(actual_type) = self.node_type_definition(node_id) else {
            return false;
        };

        node_types.iter().any(|node_type| {
            let Some(requested_type) = node_type
                .type_definition_node
                .try_resolve(self.type_tree.namespaces())
            else {
                return false;
            };

            if node_type.include_sub_types {
                self.type_tree.is_subtype_of(&actual_type, &requested_type)
            } else {
                actual_type == *requested_type
            }
        })
    }

    /// Returns `true` when `node_id` satisfies the parsed content filter.
    #[must_use]
    pub fn matches_content_filter(
        &self,
        node_id: &NodeId,
        content_filter: &ParsedContentFilter,
    ) -> bool {
        content_filter.evaluate(
            QueryFilterTarget {
                filter: *self,
                node_id,
            },
            self.type_tree,
        )
    }

    /// Returns the `HasTypeDefinition` target for `node_id`, if present.
    #[must_use]
    pub fn node_type_definition(&self, node_id: &NodeId) -> Option<NodeId> {
        self.address_space
            .find_references(
                node_id,
                Some((ReferenceTypeId::HasTypeDefinition, false)),
                self.type_tree,
                BrowseDirection::Forward,
            )
            .next()
            .map(|reference| reference.target_node.clone())
    }

    fn node_attribute(
        &self,
        node_id: &NodeId,
        type_definition_id: &NodeId,
        browse_path: &[QualifiedName],
        attribute_id: AttributeId,
        index_range: &NumericRange,
    ) -> Variant {
        if !self.node_matches_operand_type(node_id, type_definition_id) {
            return Variant::Empty;
        }

        let target = if browse_path.is_empty() {
            self.address_space.find(node_id)
        } else {
            self.address_space.find_node_by_browse_path(
                node_id,
                Some((ReferenceTypeId::HasProperty, false)),
                self.type_tree,
                BrowseDirection::Forward,
                browse_path,
            )
        };

        target
            .map(|node| read_attribute(&*node, attribute_id, index_range))
            .unwrap_or(Variant::Empty)
    }

    fn node_matches_operand_type(&self, node_id: &NodeId, type_definition_id: &NodeId) -> bool {
        if type_definition_id.is_null() {
            return true;
        }

        self.node_type_definition(node_id)
            .is_some_and(|actual_type| {
                actual_type == *type_definition_id
                    || self
                        .type_tree
                        .is_subtype_of(&actual_type, type_definition_id)
            })
    }
}

#[derive(Clone, Copy)]
struct QueryFilterTarget<'a, 'b> {
    filter: QueryNodeFilter<'a>,
    node_id: &'b NodeId,
}

impl AttributeQueryable for QueryFilterTarget<'_, '_> {
    fn get_attribute(
        &self,
        type_definition_id: &NodeId,
        browse_path: &[QualifiedName],
        attribute_id: AttributeId,
        index_range: &NumericRange,
    ) -> Variant {
        self.filter.node_attribute(
            self.node_id,
            type_definition_id,
            browse_path,
            attribute_id,
            index_range,
        )
    }

    fn get_type(&self) -> NodeId {
        self.filter
            .node_type_definition(self.node_id)
            .unwrap_or_else(NodeId::null)
    }
}

fn read_attribute(
    node: &NodeType,
    attribute_id: AttributeId,
    index_range: &NumericRange,
) -> Variant {
    let Some(value) = node.as_node().get_attribute(
        TimestampsToReturn::Neither,
        attribute_id,
        index_range,
        &DataEncoding::Binary,
    ) else {
        return Variant::Empty;
    };

    if value.status.is_some_and(|status| status.is_bad()) {
        return Variant::Empty;
    }

    value.value.unwrap_or(Variant::Empty)
}

#[cfg(test)]
mod tests {
    use super::QueryNodeFilter;
    use crate::{
        address_space::{AddressSpace, ObjectBuilder, ObjectTypeBuilder, VariableBuilder},
        node_manager::ParsedNodeTypeDescription,
    };
    use opcua_nodes::{DefaultTypeTree, ParsedContentFilter};
    use opcua_types::{
        AttributeId, ContentFilterBuilder, DataTypeId, ExpandedNodeId, NodeClass, NodeId,
        NumericRange, ObjectTypeId, Operand, QualifiedName, SimpleAttributeOperand, StatusCode,
        VariableTypeId,
    };

    const TEST_NAMESPACE_URI: &str = "urn:async-opcua:query-filter-tests";

    struct Fixture {
        address_space: AddressSpace,
        type_tree: DefaultTypeTree,
        base_type: NodeId,
        subtype: NodeId,
        other_type: NodeId,
        matching_node: NodeId,
        nonmatching_node: NodeId,
    }

    impl Fixture {
        fn new() -> Self {
            let namespace_index = 1;
            let base_type = NodeId::new(namespace_index, "FermenterType");
            let subtype = NodeId::new(namespace_index, "CipFermenterType");
            let other_type = NodeId::new(namespace_index, "PumpType");
            let batch_id_type_property = NodeId::new(namespace_index, "FermenterType.BatchId");
            let matching_node = NodeId::new(namespace_index, "Fermenter-101");
            let nonmatching_node = NodeId::new(namespace_index, "Pump-101");
            let matching_batch_id = NodeId::new(namespace_index, "Fermenter-101.BatchId");
            let nonmatching_batch_id = NodeId::new(namespace_index, "Pump-101.BatchId");

            let mut address_space = AddressSpace::new();
            address_space.add_namespace(TEST_NAMESPACE_URI, namespace_index);

            ObjectTypeBuilder::new(
                &base_type,
                QualifiedName::new(namespace_index, "FermenterType"),
                "FermenterType",
            )
            .subtype_of(ObjectTypeId::BaseObjectType)
            .insert(&mut address_space);

            ObjectTypeBuilder::new(
                &subtype,
                QualifiedName::new(namespace_index, "CipFermenterType"),
                "CipFermenterType",
            )
            .subtype_of(base_type.clone())
            .insert(&mut address_space);

            ObjectTypeBuilder::new(
                &other_type,
                QualifiedName::new(namespace_index, "PumpType"),
                "PumpType",
            )
            .subtype_of(ObjectTypeId::BaseObjectType)
            .insert(&mut address_space);

            VariableBuilder::new(
                &batch_id_type_property,
                QualifiedName::new(namespace_index, "BatchId"),
                "BatchId",
            )
            .data_type(DataTypeId::String)
            .value("")
            .has_type_definition(VariableTypeId::PropertyType)
            .property_of(base_type.clone())
            .insert(&mut address_space);

            add_instance(
                &mut address_space,
                namespace_index,
                &matching_node,
                &subtype,
                &matching_batch_id,
                "FV-101",
            );
            add_instance(
                &mut address_space,
                namespace_index,
                &nonmatching_node,
                &other_type,
                &nonmatching_batch_id,
                "P-101",
            );

            let mut type_tree = DefaultTypeTree::new();
            type_tree.namespaces_mut().add_namespace(TEST_NAMESPACE_URI);
            address_space.load_into_type_tree(&mut type_tree);
            type_tree.add_type_property(
                &batch_id_type_property,
                &base_type,
                &[&QualifiedName::new(namespace_index, "BatchId")],
                NodeClass::Variable,
            );

            Self {
                address_space,
                type_tree,
                base_type,
                subtype,
                other_type,
                matching_node,
                nonmatching_node,
            }
        }

        fn evaluator(&self) -> QueryNodeFilter<'_> {
            QueryNodeFilter::new(&self.address_space, &self.type_tree)
        }
    }

    #[test]
    fn matches_exact_node_type_definition() {
        let fixture = Fixture::new();
        let filter = fixture.evaluator();
        let subtype = node_type_description(&fixture.subtype, false);
        let other_type = node_type_description(&fixture.other_type, false);

        assert!(filter.matches_node_types(&fixture.matching_node, &[subtype]));
        assert!(!filter.matches_node_types(&fixture.matching_node, &[other_type]));
    }

    #[test]
    fn includes_subtypes_when_requested() {
        let fixture = Fixture::new();
        let filter = fixture.evaluator();
        let without_subtypes = node_type_description(&fixture.base_type, false);
        let with_subtypes = node_type_description(&fixture.base_type, true);

        assert!(!filter.matches_node_types(&fixture.matching_node, &[without_subtypes]));
        assert!(filter.matches_node_types(&fixture.matching_node, &[with_subtypes]));
    }

    #[test]
    fn evaluates_property_content_filter() {
        let fixture = Fixture::new();
        let filter = fixture.evaluator();
        let node_type = node_type_description(&fixture.base_type, true);
        let content_filter = parse_content_filter(
            ContentFilterBuilder::new()
                .like(
                    Operand::SimpleAttributeOperand(SimpleAttributeOperand {
                        type_definition_id: fixture.base_type.clone(),
                        browse_path: Some(vec![QualifiedName::new(1, "BatchId")]),
                        attribute_id: AttributeId::Value as u32,
                        index_range: NumericRange::None,
                    }),
                    Operand::literal("FV-%"),
                )
                .build(),
            &fixture.type_tree,
        );

        assert!(filter.matches(&fixture.matching_node, &[node_type], &content_filter));
        assert!(!filter.matches(
            &fixture.nonmatching_node,
            &[node_type_description(&fixture.base_type, true)],
            &content_filter
        ));
    }

    #[test]
    fn returns_empty_for_missing_properties() {
        let fixture = Fixture::new();
        let filter = fixture.evaluator();

        assert_eq!(
            filter.node_attribute(
                &fixture.matching_node,
                &fixture.base_type,
                &[QualifiedName::new(1, "Missing")],
                AttributeId::Value,
                &NumericRange::None,
            ),
            opcua_types::Variant::Empty
        );
    }

    fn add_instance(
        address_space: &mut AddressSpace,
        namespace_index: u16,
        node_id: &NodeId,
        type_id: &NodeId,
        batch_id: &NodeId,
        batch: &str,
    ) {
        ObjectBuilder::new(
            node_id,
            QualifiedName::new(namespace_index, node_id.identifier.to_string()),
            node_id.identifier.to_string(),
        )
        .has_type_definition(type_id.clone())
        .insert(address_space);

        VariableBuilder::new(
            batch_id,
            QualifiedName::new(namespace_index, "BatchId"),
            "BatchId",
        )
        .data_type(DataTypeId::String)
        .value(batch)
        .has_type_definition(VariableTypeId::PropertyType)
        .property_of(node_id.clone())
        .insert(address_space);
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

    fn parse_content_filter(
        filter: opcua_types::ContentFilter,
        type_tree: &DefaultTypeTree,
    ) -> ParsedContentFilter {
        let (result, parsed) = ParsedContentFilter::parse(filter, type_tree, false, &[]);
        assert_eq!(
            result.element_results.expect("element results")[0].status_code,
            StatusCode::Good
        );
        parsed.expect("content filter should parse")
    }
}
