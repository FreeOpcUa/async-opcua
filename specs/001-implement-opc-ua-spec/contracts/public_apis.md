# Public API Contracts: OPC-UA Compliance Features

This document details the public API signatures, traits, and interface contracts exposed by the library to developers integrating these compliance features.

## 1. Alarms & Conditions (Part 9) Method Handler Contract

### Method Call Signature
On the server side, dynamic condition acknowledgment is wired to OPC-UA Method callbacks.

```rust
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
```

---

## 2. Historical Data Access (Part 11) Storage Backend Trait

Developers implementing custom database storage backends must implement the following trait.

```rust
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
```

---

## 3. PubSub Configuration and Transport Interface (Part 14)

```rust
pub trait PubSubPublisher: Send + Sync {
    /// Starts cyclic data transmission using the connection config.
    fn start_publishing(
        &self,
        connection_config: PubSubConnectionConfig,
        cancel_token: tokio_util::sync::CancellationToken,
    ) -> Result<tokio::task::JoinHandle<()>, StatusCode>;
}
```

---

## 4. Program Execution (Part 10) Execution Engine Interface

```rust
#[async_trait::async_trait]
pub trait ProgramExecutor: Send + Sync {
    /// Asynchronously runs a program step/recipe execution.
    async fn run_execution(
        &self,
        node_id: NodeId,
        program_state: Arc<tokio::sync::RwLock<ProgramState>>,
    ) -> Result<(), StatusCode>;
}
```
