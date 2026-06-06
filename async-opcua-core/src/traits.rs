//! Shared protocol traits and common types for OPC-UA features.
//! Includes Alarms & Conditions, History Storage, PubSub, and Program execution.

use opcua_types::{DataValue, DateTime, LocalizedText, NodeId, PerformUpdateType, StatusCode};
use std::sync::Arc;

/// Dynamic condition acknowledgment is wired to OPC-UA Method callbacks.
pub trait ConditionMethodHandler: Send + Sync {
    /// Callback executed when a client invokes Acknowledge/Confirm methods.
    fn handle_acknowledgment(
        &self,
        session_id: &NodeId,
        condition_id: &NodeId,
        event_id: &[u8],
        comment: &LocalizedText,
    ) -> Result<StatusCode, StatusCode>;
}

/// Abstract historical storage backend interface.
#[async_trait::async_trait]
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
}

/// PubSub Connection Configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PubSubConnectionConfig {
    /// Connection identifier (UUID or String)
    pub connection_id: String,
    /// Connection address URL (e.g., mqtt://..., udp://...)
    pub address: String,
    /// List of writer group identifiers
    pub writer_groups: Vec<String>,
}

/// PubSub transport mapping publisher trait.
pub trait PubSubPublisher: Send + Sync {
    /// Starts cyclic data transmission using the connection config.
    fn start_publishing(
        &self,
        connection_config: PubSubConnectionConfig,
        cancel_token: tokio_util::sync::CancellationToken,
    ) -> Result<tokio::task::JoinHandle<()>, StatusCode>;
}

/// Program State representation for the execution engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ProgramState {
    /// Initial state, ready to start.
    Ready,
    /// Active execution task context.
    Running,
    /// Paused execution context.
    Suspended,
    /// Process is stopped and can only be reset.
    Halted,
}

/// Dynamic Program State Machine execution engine interface.
#[async_trait::async_trait]
pub trait ProgramExecutor: Send + Sync {
    /// Asynchronously runs a program step/recipe execution.
    async fn run_execution(
        &self,
        node_id: NodeId,
        program_state: Arc<tokio::sync::RwLock<ProgramState>>,
    ) -> Result<(), StatusCode>;
}
