//! Aggregate history read middleware (Part 13).
//! Intercepts processed history read requests and computes aggregates from raw backend data.

use crate::address_space::AddressSpace;
use crate::history::HistoryStorageBackend;
use crate::node_manager::HistoryNode;
use crate::node_manager::RequestContext;
use opcua_nodes::DefaultTypeTree;
use opcua_types::{
    AttributeId, BrowseDirection, DataEncoding, HistoryData, NodeId, NumericRange, QualifiedName,
    ReadProcessedDetails, ReferenceTypeId, StatusCode, TimestampsToReturn, Variant,
};
use std::sync::Arc;

/// Resolve the Part 13 HistoricalConfiguration Stepped property for a historized variable.
///
/// Missing configuration, missing property, or a non-Boolean value all default to stepped
/// interpolation as required by OPC 10000-13.
pub fn resolve_stepped(address_space: &AddressSpace, node_id: &NodeId) -> bool {
    let type_tree = DefaultTypeTree::new();
    let Some(config_ref) = address_space
        .find_references(
            node_id,
            Some((ReferenceTypeId::HasHistoricalConfiguration, false)),
            &type_tree,
            BrowseDirection::Forward,
        )
        .next()
    else {
        return true;
    };

    let Some(stepped_node) = address_space.find_node_by_browse_name(
        config_ref.target_node,
        Some((ReferenceTypeId::HasProperty, false)),
        &type_tree,
        BrowseDirection::Forward,
        QualifiedName::from("Stepped"),
    ) else {
        return true;
    };

    match stepped_node
        .as_node()
        .get_attribute(
            TimestampsToReturn::Neither,
            AttributeId::Value,
            &NumericRange::None,
            &DataEncoding::Binary,
        )
        .and_then(|data_value| data_value.value)
    {
        Some(Variant::Boolean(stepped)) => stepped,
        _ => true,
    }
}

/// Processes historical data and computes aggregates for each requested history node.
pub async fn read_processed_aggregates(
    backend: &Arc<dyn HistoryStorageBackend>,
    _context: &RequestContext,
    details: &ReadProcessedDetails,
    nodes: &mut [&mut &mut HistoryNode],
    _timestamps_to_return: TimestampsToReturn,
    stepped_per_node: &[bool],
) -> Result<(), StatusCode> {
    for (i, hn) in nodes.iter_mut().enumerate() {
        let node_id = hn.node_id();
        let stepped = stepped_per_node.get(i).copied().unwrap_or(true);

        // Match aggregate type for this node
        let aggregate_type = if let Some(ref agg_types) = details.aggregate_type {
            if i < agg_types.len() {
                agg_types[i].clone()
            } else if !agg_types.is_empty() {
                agg_types[0].clone()
            } else {
                return Err(StatusCode::BadAggregateNotSupported);
            }
        } else {
            return Err(StatusCode::BadAggregateNotSupported);
        };

        match backend
            .read_processed(
                node_id,
                details.start_time,
                details.end_time,
                details.processing_interval,
                &aggregate_type,
                &details.aggregate_configuration,
                stepped,
                None,
            )
            .await
        {
            Ok((processed_values, _continuation_point)) => {
                hn.set_result(HistoryData {
                    data_values: Some(processed_values),
                });
                hn.set_status(StatusCode::Good);
            }
            Err(status) => hn.set_status(status),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::resolve_stepped;
    use crate::address_space::{AddressSpace, ObjectBuilder, VariableBuilder};
    use opcua_types::{DataTypeId, NodeId, ReferenceTypeId, Variant};

    #[test]
    fn resolve_stepped_reads_historical_configuration() {
        let mut space = AddressSpace::new();
        space.add_namespace("urn:test", 1);

        let var = NodeId::new(1, "var");
        let cfg = NodeId::new(1, "cfg");
        let stepped = NodeId::new(1, "stepped");

        VariableBuilder::new(&var, "var", "var")
            .data_type(DataTypeId::Double)
            .insert(&mut space);
        ObjectBuilder::new(&cfg, "HA Configuration", "HA Configuration").insert(&mut space);
        VariableBuilder::new(&stepped, "Stepped", "Stepped")
            .data_type(DataTypeId::Boolean)
            .value(Variant::Boolean(false))
            .insert(&mut space);

        space.insert_reference(&var, &cfg, ReferenceTypeId::HasHistoricalConfiguration);
        space.insert_reference(&cfg, &stepped, ReferenceTypeId::HasProperty);

        // Configured HistoricalConfiguration/Stepped = false -> sloped interpolation.
        assert!(!resolve_stepped(&space, &var));

        // A variable with no HistoricalConfiguration defaults to stepped (true).
        let plain = NodeId::new(1, "plain");
        VariableBuilder::new(&plain, "plain", "plain")
            .data_type(DataTypeId::Double)
            .insert(&mut space);
        assert!(resolve_stepped(&space, &plain));
    }
}
