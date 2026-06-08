# Data Model & Entities

## 1. AddressSpace (Concurrent Graph)
*   **Structure**: `DashMap<NodeId, Arc<RwLock<Node>>>` (or completely lock-free via node-level atomic state).
*   **Lifecycle**: Nodes are inserted once and read constantly. The map itself does not block during traversal.

## 2. Safety Protocol Data Unit (SPDU)
*   **Fields**:
    *   `SafetyData`: The core payload (e.g., boolean emergency stop).
    *   `SafetySequenceNumber`: u32 monotonically increasing.
    *   `SafetyTimestamp`: Microsecond-precision hardware timestamp.
    *   `SafetyCRC`: 32-bit CRC signature computed over the payload + sequence + timestamp.
*   **Validation Rules**: A receiver MUST transition to safe-state if CRC fails, SequenceNumber is duplicated/skipped, or Timestamp exceeds safety timeout.

## 3. History Cache Entry
*   **Structure**: Managed by `moka::future::Cache`.
*   **Keys**: `(NodeId, ContinuationPoint)`
*   **Values**: `Vec<DataValue>` (Bounded slice of history).
*   **State Transitions**: Automatically evicted when memory bounds are reached or TTL expires.
