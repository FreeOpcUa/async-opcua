//! Event select clause helpers.

use opcua_nodes::{Event, ParsedSimpleAttributeOperand, TypeTree};
use opcua_types::{
    AttributeId, EventFieldList, NodeClass, ObjectTypeId, SimpleAttributeOperand, StatusCode,
};

/// Parsed and validated EventFilter SelectClauses.
#[derive(Debug, Clone)]
pub struct SelectClauses {
    clauses: Vec<ParsedSimpleAttributeOperand>,
}

impl SelectClauses {
    /// Parses EventFilter SelectClauses and returns per-clause validation results.
    pub fn parse(
        raw: Option<Vec<SimpleAttributeOperand>>,
        type_tree: &dyn TypeTree,
    ) -> (Option<Vec<StatusCode>>, Result<Self, StatusCode>) {
        let Some(raw_clauses) = raw else {
            return (
                None,
                Ok(Self {
                    clauses: Vec::new(),
                }),
            );
        };

        let mut statuses = Vec::with_capacity(raw_clauses.len());
        let mut clauses = Vec::with_capacity(raw_clauses.len());
        let mut has_error = false;

        for clause in raw_clauses {
            match validate_select_clause(clause, type_tree) {
                Ok(clause) => {
                    statuses.push(StatusCode::Good);
                    clauses.push(clause);
                }
                Err(status) => {
                    statuses.push(status);
                    has_error = true;
                }
            }
        }

        let statuses = if statuses.is_empty() {
            None
        } else {
            Some(statuses)
        };

        if has_error {
            (statuses, Err(StatusCode::BadMonitoredItemFilterUnsupported))
        } else {
            (statuses, Ok(Self { clauses }))
        }
    }

    /// Extracts selected event fields in the same order requested by the client.
    pub fn extract_event_fields(&self, event: &dyn Event, client_handle: u32) -> EventFieldList {
        let fields = self
            .clauses
            .iter()
            .map(|clause| {
                event.get_field(
                    &clause.type_definition_id,
                    clause.attribute_id,
                    &clause.index_range,
                    &clause.browse_path,
                )
            })
            .collect();

        EventFieldList {
            client_handle,
            event_fields: Some(fields),
        }
    }
}

fn validate_select_clause(
    clause: SimpleAttributeOperand,
    type_tree: &dyn TypeTree,
) -> Result<ParsedSimpleAttributeOperand, StatusCode> {
    let Some(browse_path) = clause.browse_path else {
        return Err(StatusCode::BadNodeIdUnknown);
    };

    let attribute_id = AttributeId::from_u32(clause.attribute_id)
        .map_err(|_| StatusCode::BadAttributeIdInvalid)?;

    if clause.type_definition_id == ObjectTypeId::BaseEventType {
        if attribute_id != AttributeId::NodeId && attribute_id != AttributeId::Value {
            return Err(StatusCode::BadAttributeIdInvalid);
        }

        return Ok(ParsedSimpleAttributeOperand {
            type_definition_id: clause.type_definition_id,
            browse_path,
            attribute_id,
            index_range: clause.index_range,
        });
    }

    let node = type_tree
        .find_type_prop_by_browse_path(&clause.type_definition_id, &browse_path)
        .ok_or(StatusCode::BadNodeIdUnknown)?;

    let is_valid = match node.node_class {
        NodeClass::Object => attribute_id == AttributeId::NodeId,
        NodeClass::Variable => attribute_id == AttributeId::Value,
        _ => false,
    };

    if !is_valid {
        return Err(StatusCode::BadAttributeIdInvalid);
    }

    Ok(ParsedSimpleAttributeOperand {
        type_definition_id: clause.type_definition_id,
        browse_path,
        attribute_id,
        index_range: clause.index_range,
    })
}

#[cfg(test)]
mod tests {
    use opcua_nodes::{BaseEventType, DefaultTypeTree};
    use opcua_types::{
        AttributeId, ByteString, NodeId, NumericRange, ObjectTypeId, SimpleAttributeOperand,
        StatusCode, Variant,
    };

    use super::SelectClauses;

    #[test]
    fn extracts_selected_fields_in_requested_order() {
        let type_tree = DefaultTypeTree::new();
        let base_event_type = NodeId::from(ObjectTypeId::BaseEventType);
        let (_, select) = SelectClauses::parse(
            Some(vec![
                SimpleAttributeOperand::new_value(base_event_type.clone(), "Severity"),
                SimpleAttributeOperand::new_value(base_event_type, "Message"),
            ]),
            &type_tree,
        );
        let select = select.expect("select clauses should parse");
        let event = BaseEventType::new(
            ObjectTypeId::BaseEventType,
            ByteString::from(b"event-id".as_slice()),
            "high-severity",
            opcua_types::DateTime::now(),
        )
        .set_severity(700);

        let fields = select
            .extract_event_fields(&event, 42)
            .event_fields
            .expect("selected fields should be present");

        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0], Variant::UInt16(700));
        assert!(
            matches!(&fields[1], Variant::LocalizedText(text) if text.text.as_ref() == "high-severity")
        );
    }

    #[test]
    fn rejects_invalid_select_clause_attribute() {
        let type_tree = DefaultTypeTree::new();
        let (statuses, select) = SelectClauses::parse(
            Some(vec![SimpleAttributeOperand::new(
                ObjectTypeId::BaseEventType,
                "Severity",
                AttributeId::DisplayName,
                NumericRange::None,
            )]),
            &type_tree,
        );

        assert_eq!(statuses, Some(vec![StatusCode::BadAttributeIdInvalid]));
        assert_eq!(
            select.expect_err("invalid select clause should fail parsing"),
            StatusCode::BadMonitoredItemFilterUnsupported
        );
    }
}
