//! Aggregate history read middleware (Part 13).
//! Intercepts processed history read requests and computes aggregates from raw backend data.

use crate::aggregates::engine::{calculate_aggregate, get_value_timestamp, partition_intervals};
use crate::history::HistoryStorageBackend;
use crate::node_manager::HistoryNode;
use crate::node_manager::RequestContext;
use opcua_types::{DataValue, HistoryData, ReadProcessedDetails, StatusCode, TimestampsToReturn};
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

        // Read all raw values from the backend for the range
        let mut raw_values = Vec::new();
        let mut next_token = None;
        let mut read_failed = false;
        loop {
            let res = backend
                .read_raw_modified(
                    node_id,
                    details.start_time,
                    details.end_time,
                    100000, // Read a large number of values to ensure we get all data in this window
                    false,
                    next_token,
                )
                .await;

            match res {
                Ok((values, token)) => {
                    raw_values.extend(values);
                    if token.is_none() {
                        break;
                    }
                    next_token = token;
                }
                Err(status) => {
                    hn.set_status(status);
                    read_failed = true;
                    break;
                }
            }
        }

        if read_failed {
            continue;
        }

        // Sort raw values chronologically by timestamp
        raw_values.sort_by_key(|v| get_value_timestamp(v));

        // Generate intervals
        let intervals = partition_intervals(
            details.start_time,
            details.end_time,
            details.processing_interval,
        );

        let mut processed_values = Vec::new();

        for (int_start, int_end) in intervals {
            let (min_t, max_t) = if int_start <= int_end {
                (int_start, int_end)
            } else {
                (int_end, int_start)
            };

            // Filter raw values inside this interval
            let values_in_interval: Vec<&DataValue> = raw_values
                .iter()
                .filter(|v| {
                    let t = get_value_timestamp(v);
                    t >= min_t && t < max_t
                })
                .collect();

            // Calculate aggregate
            let result_dv =
                calculate_aggregate(&values_in_interval, &aggregate_type, int_start, int_end);
            processed_values.push(result_dv);
        }

        hn.set_result(HistoryData {
            data_values: Some(processed_values),
        });
        hn.set_status(StatusCode::Good);
    }

    Ok(())
}
