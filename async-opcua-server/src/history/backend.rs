use crate::aggregates::engine::{calculate_aggregate, get_value_timestamp, partition_intervals};
use async_trait::async_trait;
use opcua_types::{
    DataValue, DateTime, EventFilter, HistoryEventFieldList, NodeId, PerformUpdateType, StatusCode,
};

/// Trait representing a storage backend for OPC-UA Historical Data Access (HDA).
/// Custom backends (e.g. SQLite, In-Memory, etc.) implement this trait.
#[async_trait]
pub trait HistoryStorageBackend: Send + Sync {
    /// Reads raw data values from the history backend.
    async fn read_raw_modified(
        &self,
        node_id: &NodeId,
        start_time: DateTime,
        end_time: DateTime,
        num_values_per_node: u32,
        return_bounds: bool,
        continuation_point: Option<Vec<u8>>,
    ) -> Result<(Vec<DataValue>, Option<Vec<u8>>), StatusCode>;

    /// Reads processed aggregate values from the history backend.
    async fn read_processed(
        &self,
        node_id: &NodeId,
        start_time: DateTime,
        end_time: DateTime,
        processing_interval: f64,
        aggregate_type: &NodeId,
        continuation_point: Option<Vec<u8>>,
    ) -> Result<(Vec<DataValue>, Option<Vec<u8>>), StatusCode> {
        if continuation_point.is_some() {
            return Err(StatusCode::BadContinuationPointInvalid);
        }

        let mut raw_values = Vec::new();
        let mut next_token = None;
        loop {
            let (values, token) = self
                .read_raw_modified(node_id, start_time, end_time, 100_000, false, next_token)
                .await?;
            raw_values.extend(values);

            let Some(token) = token else {
                break;
            };
            next_token = Some(token);
        }

        raw_values.sort_by_key(get_value_timestamp);

        let processed_values = partition_intervals(start_time, end_time, processing_interval)
            .into_iter()
            .map(|(interval_start, interval_end)| {
                let (min_t, max_t) = if interval_start <= interval_end {
                    (interval_start, interval_end)
                } else {
                    (interval_end, interval_start)
                };

                let values_in_interval: Vec<&DataValue> = raw_values
                    .iter()
                    .filter(|value| {
                        let timestamp = get_value_timestamp(value);
                        timestamp >= min_t && timestamp < max_t
                    })
                    .collect();

                calculate_aggregate(
                    &values_in_interval,
                    aggregate_type,
                    interval_start,
                    interval_end,
                )
            })
            .collect();

        Ok((processed_values, None))
    }

    /// Reads historical events from the history backend.
    async fn read_events(
        &self,
        _node_id: &NodeId,
        _start_time: DateTime,
        _end_time: DateTime,
        _num_values_per_node: u32,
        _filter: &EventFilter,
        _continuation_point: Option<Vec<u8>>,
    ) -> Result<(Vec<HistoryEventFieldList>, Option<Vec<u8>>), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Reads annotation data values from the history backend.
    async fn read_annotations(
        &self,
        _node_id: &NodeId,
        _req_times: &[DateTime],
        _continuation_point: Option<Vec<u8>>,
    ) -> Result<(Vec<DataValue>, Option<Vec<u8>>), StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Updates or inserts historical data values.
    async fn update_data(
        &self,
        node_id: &NodeId,
        perform_insert_replace: PerformUpdateType,
        values: Vec<DataValue>,
    ) -> Result<Vec<StatusCode>, StatusCode>;

    /// Releases a backend-owned continuation point token.
    async fn release_continuation_point(&self, _token: Vec<u8>) -> Result<(), StatusCode> {
        Ok(())
    }
}
