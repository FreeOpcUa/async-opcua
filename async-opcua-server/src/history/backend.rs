use crate::aggregates::engine::{compute_processed_intervals, get_value_timestamp};
use async_trait::async_trait;
use moka::future::Cache;
use opcua_types::{
    AggregateConfiguration, DataValue, DateTime, EventFilter, HistoryEventFieldList,
    ModificationInfo, NodeId, PerformUpdateType, StatusCode,
};

/// Raw/modified HistoryRead result: values, modification metadata, continuation token.
pub type HistoryRawModifiedResult = (Vec<DataValue>, Vec<ModificationInfo>, Option<Vec<u8>>);

/// A cache for historical data values to avoid database hits.
#[derive(Clone)]
pub struct HistoryCache {
    cache: Cache<(NodeId, i64, i64), Vec<DataValue>>,
}

impl HistoryCache {
    /// Create a new HistoryCache with the given maximum capacity.
    pub fn new(max_capacity: u64) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(max_capacity)
                .time_to_idle(std::time::Duration::from_secs(300))
                .build(),
        }
    }

    /// Retrieve cached values.
    pub async fn get(&self, key: &(NodeId, DateTime, DateTime)) -> Option<Vec<DataValue>> {
        let cache_key = (key.0.clone(), key.1.ticks(), key.2.ticks());
        self.cache.get(&cache_key).await
    }

    /// Insert values into the cache.
    pub async fn insert(&self, key: (NodeId, DateTime, DateTime), values: Vec<DataValue>) {
        let cache_key = (key.0, key.1.ticks(), key.2.ticks());
        self.cache.insert(cache_key, values).await;
    }

    /// Get current size of cache.
    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }

    /// Invalidate all entries in the cache.
    pub fn invalidate_all(&self) {
        self.cache.invalidate_all();
    }

    /// Force cache tasks to run (useful for testing eviction immediately).
    pub async fn run_pending_tasks(&self) {
        self.cache.run_pending_tasks().await;
    }
}

/// Trait representing a storage backend for OPC-UA Historical Data Access (HDA).
/// Custom backends (e.g. SQLite, In-Memory, etc.) implement this trait.
///
/// HistoryUpdate write implementations for [`HistoryStorageBackend::update_data`],
/// [`HistoryStorageBackend::update_structure_data`], and
/// [`HistoryStorageBackend::update_event`] must support all [`PerformUpdateType`]
/// modes: [`PerformUpdateType::Insert`], [`PerformUpdateType::Replace`],
/// [`PerformUpdateType::Update`], and [`PerformUpdateType::Remove`].
#[async_trait]
pub trait HistoryStorageBackend: Send + Sync {
    /// Reads raw data values from the history backend.
    #[allow(clippy::too_many_arguments)]
    async fn read_raw_modified(
        &self,
        node_id: &NodeId,
        start_time: DateTime,
        end_time: DateTime,
        num_values_per_node: u32,
        return_bounds: bool,
        is_read_modified: bool,
        continuation_point: Option<Vec<u8>>,
    ) -> Result<HistoryRawModifiedResult, StatusCode>;

    /// Reads processed aggregate values from the history backend.
    // ponytail: 8 params (added AggregateConfiguration); a params struct isn't worth it — the
    // signature won't grow further (bounds flow through read_raw_modified, not here).
    #[allow(clippy::too_many_arguments)]
    async fn read_processed(
        &self,
        node_id: &NodeId,
        start_time: DateTime,
        end_time: DateTime,
        processing_interval: f64,
        aggregate_type: &NodeId,
        aggregate_configuration: &AggregateConfiguration,
        stepped: bool,
        continuation_point: Option<Vec<u8>>,
    ) -> Result<(Vec<DataValue>, Option<Vec<u8>>), StatusCode> {
        if continuation_point.is_some() {
            return Err(StatusCode::BadContinuationPointInvalid);
        }

        let mut raw_values = Vec::new();
        let mut next_token = None;
        loop {
            let (values, _modification_infos, token) = self
                .read_raw_modified(
                    node_id, start_time, end_time, 100_000, true, false, next_token,
                )
                .await?;
            raw_values.extend(values);

            let Some(token) = token else {
                break;
            };
            next_token = Some(token);
        }

        raw_values.sort_by_key(get_value_timestamp);

        let processed_values = compute_processed_intervals(
            &raw_values,
            aggregate_type,
            aggregate_configuration,
            start_time,
            end_time,
            processing_interval,
            stepped,
        );

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

    /// Updates annotation history data values.
    async fn update_structure_data(
        &self,
        _node_id: &NodeId,
        _perform: PerformUpdateType,
        _values: Vec<DataValue>,
    ) -> Result<Vec<StatusCode>, StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Updates historical event field lists.
    async fn update_event(
        &self,
        _node_id: &NodeId,
        _filter: &EventFilter,
        _events: Vec<HistoryEventFieldList>,
        _perform: PerformUpdateType,
    ) -> Result<Vec<StatusCode>, StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Deletes raw or modified historical data over a time range.
    async fn delete_raw_modified(
        &self,
        _node_id: &NodeId,
        _is_delete_modified: bool,
        _start_time: DateTime,
        _end_time: DateTime,
    ) -> Result<StatusCode, StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Deletes historical data values at requested timestamps.
    async fn delete_at_time(
        &self,
        _node_id: &NodeId,
        _req_times: Vec<DateTime>,
    ) -> Result<Vec<StatusCode>, StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Deletes historical events by event id.
    async fn delete_event(
        &self,
        _node_id: &NodeId,
        _event_ids: Vec<opcua_types::ByteString>,
    ) -> Result<Vec<StatusCode>, StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    /// Releases a backend-owned continuation point token.
    async fn release_continuation_point(&self, _token: Vec<u8>) -> Result<(), StatusCode> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A backend implementing ONLY the two required methods, to prove the five new
    // write methods default to Bad_HistoryOperationUnsupported (FR-011 backwards compat).
    struct MinimalBackend;

    #[async_trait]
    impl HistoryStorageBackend for MinimalBackend {
        async fn read_raw_modified(
            &self,
            _node_id: &NodeId,
            _start_time: DateTime,
            _end_time: DateTime,
            _num_values_per_node: u32,
            _return_bounds: bool,
            _is_read_modified: bool,
            _continuation_point: Option<Vec<u8>>,
        ) -> Result<HistoryRawModifiedResult, StatusCode> {
            Ok((Vec::new(), Vec::new(), None))
        }

        async fn update_data(
            &self,
            _node_id: &NodeId,
            _perform_insert_replace: PerformUpdateType,
            _values: Vec<DataValue>,
        ) -> Result<Vec<StatusCode>, StatusCode> {
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn new_write_methods_default_to_unsupported() {
        let b = MinimalBackend;
        let node = NodeId::null();
        assert_eq!(
            b.update_structure_data(&node, PerformUpdateType::Insert, Vec::new())
                .await,
            Err(StatusCode::BadHistoryOperationUnsupported)
        );
        assert_eq!(
            b.delete_at_time(&node, Vec::new()).await,
            Err(StatusCode::BadHistoryOperationUnsupported)
        );
        assert_eq!(
            b.delete_event(&node, Vec::new()).await,
            Err(StatusCode::BadHistoryOperationUnsupported)
        );
        assert_eq!(
            b.delete_raw_modified(&node, false, DateTime::null(), DateTime::null())
                .await,
            Err(StatusCode::BadHistoryOperationUnsupported)
        );
    }
}
