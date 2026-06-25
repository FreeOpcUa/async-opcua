//! Aggregate history read middleware (Part 13).
//! Intercepts processed history read requests and computes aggregates from raw backend data.

use crate::history::HistoryStorageBackend;
use crate::node_manager::HistoryNode;
use crate::node_manager::RequestContext;
use opcua_types::{HistoryData, ReadProcessedDetails, StatusCode, TimestampsToReturn};
use std::sync::Arc;

/// Processes historical data and computes aggregates for each requested history node.
pub async fn read_processed_aggregates(
    backend: &Arc<dyn HistoryStorageBackend>,
    _context: &RequestContext,
    details: &ReadProcessedDetails,
    nodes: &mut [&mut &mut HistoryNode],
    _timestamps_to_return: TimestampsToReturn,
) -> Result<(), StatusCode> {
    for (i, hn) in nodes.iter_mut().enumerate() {
        let node_id = hn.node_id();

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
