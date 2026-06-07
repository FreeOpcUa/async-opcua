//! Event filter parsing helpers.

use opcua_nodes::{Event, TypeTree};
use opcua_types::{
    AttributeId, ContentFilter, ContentFilterResult, EventFieldList, EventFilter,
    EventFilterResult, NodeClass, NodeId, Operand, QualifiedName, SimpleAttributeOperand,
    StatusCode, Variant,
};

use super::{select::SelectClauses, where_clause::WhereClauses};

/// Parsed in-memory representation of an OPC UA [`EventFilter`].
#[derive(Debug, Clone)]
pub struct ParsedEventFilter {
    select_clauses: SelectClauses,
    where_clauses: WhereClauses,
    field_access: EventFieldAccess,
}

impl ParsedEventFilter {
    /// Parses a raw OPC UA [`EventFilter`] into the server's in-memory representation.
    pub fn parse(
        raw: EventFilter,
        type_tree: &dyn TypeTree,
    ) -> (EventFilterResult, Result<Self, StatusCode>) {
        let EventFilter {
            select_clauses,
            where_clause,
        } = raw;
        let field_access = EventFieldAccess::from_filter(select_clauses.as_deref(), &where_clause);
        let (select_clause_results, select_clauses) =
            SelectClauses::parse(select_clauses, type_tree);
        let (where_clause_result, where_clauses) = WhereClauses::parse(where_clause, type_tree);
        let result = EventFilterResult {
            select_clause_results,
            select_clause_diagnostic_infos: None,
            where_clause_result,
        };
        let parsed = where_clauses
            .and_then(|where_clauses| {
                select_clauses.map(|select_clauses| Self {
                    select_clauses,
                    where_clauses,
                    field_access,
                })
            })
            .map_err(|status| map_filter_error(&result.where_clause_result, status));
        (result, parsed)
    }

    /// Evaluates the parsed filter against an event and returns the selected event fields.
    pub fn evaluate(
        &self,
        event: &dyn Event,
        client_handle: u32,
        type_tree: &dyn TypeTree,
    ) -> Option<EventFieldList> {
        if !self.field_access.where_fields_are_authorized(type_tree) {
            return None;
        }

        if !self.where_clauses.matches(event, type_tree) {
            return None;
        }

        let mut fields = self
            .select_clauses
            .extract_event_fields(event, client_handle);
        self.field_access
            .mask_unauthorized_selected_fields(&mut fields, type_tree);

        Some(fields)
    }
}

#[derive(Debug, Clone)]
struct EventFieldAccess {
    select_fields: Vec<EventFieldReference>,
    where_fields: Vec<EventFieldReference>,
}

impl EventFieldAccess {
    fn from_filter(
        select_clauses: Option<&[SimpleAttributeOperand]>,
        where_clause: &ContentFilter,
    ) -> Self {
        Self {
            select_fields: select_clauses
                .into_iter()
                .flatten()
                .filter_map(EventFieldReference::from_simple_attribute_operand)
                .collect(),
            where_fields: event_fields_in_where_clause(where_clause),
        }
    }

    fn where_fields_are_authorized(&self, type_tree: &dyn TypeTree) -> bool {
        self.where_fields
            .iter()
            .all(|field| field.is_authorized(type_tree))
    }

    fn mask_unauthorized_selected_fields(
        &self,
        fields: &mut EventFieldList,
        type_tree: &dyn TypeTree,
    ) {
        let Some(values) = fields.event_fields.as_mut() else {
            return;
        };

        for (value, field) in values.iter_mut().zip(&self.select_fields) {
            if !field.is_authorized(type_tree) {
                *value = Variant::StatusCode(StatusCode::BadUserAccessDenied);
            }
        }
    }
}

#[derive(Debug, Clone)]
struct EventFieldReference {
    type_definition_id: NodeId,
    browse_path: Vec<QualifiedName>,
    attribute_id: AttributeId,
}

impl EventFieldReference {
    fn from_simple_attribute_operand(clause: &SimpleAttributeOperand) -> Option<Self> {
        Some(Self {
            type_definition_id: clause.type_definition_id.clone(),
            browse_path: clause.browse_path.clone()?,
            attribute_id: AttributeId::from_u32(clause.attribute_id).ok()?,
        })
    }

    fn is_authorized(&self, type_tree: &dyn TypeTree) -> bool {
        if type_tree.get(&self.type_definition_id).is_none() {
            return true;
        }

        let Some(prop) =
            type_tree.find_type_prop_by_browse_path(&self.type_definition_id, &self.browse_path)
        else {
            return false;
        };

        match prop.node_class {
            NodeClass::Object => self.attribute_id == AttributeId::NodeId,
            NodeClass::Variable => self.attribute_id == AttributeId::Value,
            _ => false,
        }
    }
}

fn event_fields_in_where_clause(where_clause: &ContentFilter) -> Vec<EventFieldReference> {
    where_clause
        .elements
        .as_deref()
        .into_iter()
        .flatten()
        .filter_map(|element| element.filter_operands.as_deref())
        .flatten()
        .filter_map(|operand| match Operand::try_from(operand.clone()) {
            Ok(Operand::SimpleAttributeOperand(clause)) => {
                EventFieldReference::from_simple_attribute_operand(&clause)
            }
            _ => None,
        })
        .collect()
}

fn map_filter_error(where_result: &ContentFilterResult, status: StatusCode) -> StatusCode {
    if has_status(where_result, StatusCode::BadFilterOperatorUnsupported) {
        StatusCode::BadMonitoredItemFilterUnsupported
    } else {
        status
    }
}

fn has_status(result: &ContentFilterResult, status: StatusCode) -> bool {
    result.element_results.as_ref().is_some_and(|elements| {
        elements.iter().any(|element| {
            element.status_code == status
                || element
                    .operand_status_codes
                    .as_ref()
                    .is_some_and(|codes| codes.contains(&status))
        })
    })
}

#[cfg(test)]
mod tests {
    use opcua_nodes::{BaseEventType, DefaultTypeTree};
    use opcua_types::{
        AttributeId, ByteString, ContentFilter, EventFilter, FilterOperator, NodeClass, NodeId,
        NumericRange, ObjectId, ObjectTypeId, Operand, QualifiedName, SimpleAttributeOperand,
        StatusCode, Variant,
    };

    use super::ParsedEventFilter;

    #[test]
    fn parse_event_filter_stores_select_clauses_for_evaluation() {
        let type_tree = DefaultTypeTree::new();
        let base_event_type = NodeId::from(ObjectTypeId::BaseEventType);
        let filter = EventFilter {
            select_clauses: Some(vec![
                SimpleAttributeOperand::new_value(base_event_type.clone(), "Message"),
                SimpleAttributeOperand::new_value(base_event_type, "Severity"),
            ]),
            where_clause: ContentFilter { elements: None },
        };

        let (result, parsed) = ParsedEventFilter::parse(filter, &type_tree);

        assert_eq!(
            result.select_clause_results,
            Some(vec![StatusCode::Good, StatusCode::Good])
        );
        let parsed = parsed.expect("event filter should parse");
        let event = BaseEventType::new(
            ObjectTypeId::BaseEventType,
            ByteString::from(b"event-id".as_slice()),
            "high-severity",
            opcua_types::DateTime::now(),
        )
        .set_severity(700);
        let fields = parsed
            .evaluate(&event, 42, &type_tree)
            .expect("event should match empty where clause")
            .event_fields
            .expect("selected fields should be present");

        assert_eq!(fields.len(), 2);
        assert!(
            matches!(&fields[0], Variant::LocalizedText(text) if text.text.as_ref() == "high-severity")
        );
        assert_eq!(fields[1], Variant::UInt16(700));
    }

    #[test]
    fn parse_event_filter_maps_unsupported_where_operator() {
        let type_tree = DefaultTypeTree::new();
        let filter = EventFilter {
            select_clauses: Some(vec![SimpleAttributeOperand::new_value(
                ObjectTypeId::BaseEventType,
                "Severity",
            )]),
            where_clause: ContentFilter {
                elements: Some(vec![(
                    FilterOperator::RelatedTo,
                    vec![
                        Operand::literal(NodeId::from(ObjectId::Server)),
                        Operand::literal(NodeId::null()),
                        Operand::literal(NodeId::null()),
                        Operand::literal(NodeId::null()),
                        Operand::literal(0u32),
                        Operand::literal(false),
                    ],
                )
                    .into()]),
            },
        };

        let (result, parsed) = ParsedEventFilter::parse(filter, &type_tree);

        assert_eq!(
            result
                .where_clause_result
                .element_results
                .expect("where clause element result should be present")[0]
                .status_code,
            StatusCode::BadFilterOperatorUnsupported
        );
        assert_eq!(
            parsed.expect_err("unsupported operator should fail parsing"),
            StatusCode::BadMonitoredItemFilterUnsupported
        );
    }

    #[test]
    fn parse_event_filter_preserves_invalid_operand_status() {
        let type_tree = DefaultTypeTree::new();
        let filter = EventFilter {
            select_clauses: Some(vec![SimpleAttributeOperand::new_value(
                ObjectTypeId::BaseEventType,
                "Severity",
            )]),
            where_clause: ContentFilter {
                elements: Some(vec![(
                    FilterOperator::GreaterThanOrEqual,
                    vec![Operand::simple_attribute(
                        ObjectTypeId::BaseEventType,
                        "Severity",
                        AttributeId::Value,
                        NumericRange::None,
                    )],
                )
                    .into()]),
            },
        };

        let (_, parsed) = ParsedEventFilter::parse(filter, &type_tree);

        assert_eq!(
            parsed.expect_err("operand count mismatch should fail parsing"),
            StatusCode::BadEventFilterInvalid
        );
    }

    #[test]
    fn evaluate_marks_denied_selected_fields_without_leaking_values() {
        let type_tree = base_event_type_tree_with_fields(&["Message"]);
        let base_event_type = NodeId::from(ObjectTypeId::BaseEventType);
        let filter = EventFilter {
            select_clauses: Some(vec![
                SimpleAttributeOperand::new_value(base_event_type.clone(), "Message"),
                SimpleAttributeOperand::new_value(base_event_type, "Severity"),
            ]),
            where_clause: ContentFilter { elements: None },
        };
        let (_, parsed) = ParsedEventFilter::parse(filter, &type_tree);
        let parsed = parsed.expect("event filter should parse");
        let event = event("high-severity", 700);

        let fields = parsed
            .evaluate(&event, 42, &type_tree)
            .expect("empty where clause should match")
            .event_fields
            .expect("selected fields should be present");

        assert_eq!(fields.len(), 2);
        assert!(
            matches!(&fields[0], Variant::LocalizedText(text) if text.text.as_ref() == "high-severity")
        );
        assert_eq!(
            fields[1],
            Variant::StatusCode(StatusCode::BadUserAccessDenied)
        );
    }

    #[test]
    fn evaluate_suppresses_events_when_where_clause_uses_denied_field() {
        let type_tree = base_event_type_tree_with_fields(&["Message"]);
        let base_event_type = NodeId::from(ObjectTypeId::BaseEventType);
        let filter = EventFilter {
            select_clauses: Some(vec![SimpleAttributeOperand::new_value(
                base_event_type.clone(),
                "Message",
            )]),
            where_clause: ContentFilter {
                elements: Some(vec![(
                    FilterOperator::GreaterThanOrEqual,
                    vec![
                        Operand::simple_attribute(
                            base_event_type,
                            "Severity",
                            AttributeId::Value,
                            NumericRange::None,
                        ),
                        Operand::literal(500u16),
                    ],
                )
                    .into()]),
            },
        };
        let (_, parsed) = ParsedEventFilter::parse(filter, &type_tree);
        let parsed = parsed.expect("event filter should parse");
        let event = event("high-severity", 700);

        assert!(parsed.evaluate(&event, 42, &type_tree).is_none());
    }

    fn base_event_type_tree_with_fields(fields: &[&str]) -> DefaultTypeTree {
        let mut type_tree = DefaultTypeTree::new();
        let base_event_type = NodeId::from(ObjectTypeId::BaseEventType);
        type_tree.add_type_node(
            &base_event_type,
            &NodeId::from(ObjectTypeId::BaseObjectType),
            NodeClass::ObjectType,
        );
        for field in fields {
            let browse_name = QualifiedName::new(0, *field);
            type_tree.add_type_property(
                &NodeId::new(1, format!("BaseEventType_{field}")),
                &base_event_type,
                &[&browse_name],
                NodeClass::Variable,
            );
        }
        type_tree
    }

    fn event(message: &str, severity: u16) -> BaseEventType {
        BaseEventType::new(
            ObjectTypeId::BaseEventType,
            ByteString::from(message.as_bytes()),
            message,
            opcua_types::DateTime::now(),
        )
        .set_severity(severity)
    }
}
