//! Event where clause helpers.

use opcua_nodes::{Event, ParsedContentFilter, TypeTree};
use opcua_types::{ContentFilter, ContentFilterResult, FilterOperator, StatusCode};

/// Parsed and validated EventFilter WhereClauses.
#[derive(Debug, Clone)]
pub struct WhereClauses {
    filter: ParsedContentFilter,
}

impl WhereClauses {
    /// Parses EventFilter WhereClauses and returns per-element validation results.
    pub fn parse(
        raw: ContentFilter,
        type_tree: &dyn TypeTree,
    ) -> (ContentFilterResult, Result<Self, StatusCode>) {
        let (result, filter) =
            ParsedContentFilter::parse(raw, type_tree, false, &[FilterOperator::RelatedTo]);

        (result, filter.map(|filter| Self { filter }))
    }

    /// Evaluates the WhereClauses against an event.
    pub fn matches(&self, event: &dyn Event, type_tree: &dyn TypeTree) -> bool {
        self.filter.evaluate(event, type_tree)
    }
}

#[cfg(test)]
mod tests {
    use opcua_nodes::{BaseEventType, DefaultTypeTree};
    use opcua_types::{
        AttributeId, ByteString, ContentFilterBuilder, FilterOperator, NodeId, NumericRange,
        ObjectTypeId, Operand, StatusCode,
    };

    use super::WhereClauses;

    #[test]
    fn evaluates_comparison_against_event_fields() {
        let type_tree = DefaultTypeTree::new();
        let base_event_type = NodeId::from(ObjectTypeId::BaseEventType);
        let filter = ContentFilterBuilder::new()
            .gte(
                Operand::simple_attribute(
                    base_event_type,
                    "Severity",
                    AttributeId::Value,
                    NumericRange::None,
                ),
                Operand::literal(500u16),
            )
            .build();
        let (_, where_clauses) = WhereClauses::parse(filter, &type_tree);
        let where_clauses = where_clauses.expect("where clause should parse");
        let low = event("low-severity", 100);
        let high = event("high-severity", 700);

        assert!(!where_clauses.matches(&low, &type_tree));
        assert!(where_clauses.matches(&high, &type_tree));
    }

    #[test]
    fn accepts_default_view_in_view_operator() {
        let type_tree = DefaultTypeTree::new();
        let filter = (
            FilterOperator::InView,
            vec![Operand::literal(NodeId::null())],
        )
            .into();
        let (result, where_clauses) = WhereClauses::parse(
            opcua_types::ContentFilter {
                elements: Some(vec![filter]),
            },
            &type_tree,
        );

        assert_eq!(
            result.element_results.expect("element result")[0].status_code,
            StatusCode::Good
        );
        let where_clauses = where_clauses.expect("default view should parse");
        assert!(where_clauses.matches(&event("default-view", 100), &type_tree));
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
