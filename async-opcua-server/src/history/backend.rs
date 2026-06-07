use async_trait::async_trait;
use opcua_types::{DataValue, DateTime, NodeId, PerformUpdateType, StatusCode};

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
