# Interface Contracts: Complete OPC UA Compliance

This document defines the key public trait and structure contracts exposed by the new library extensions.

## 1. PubSub Transport Trait (`async-opcua-pubsub`)

Any PubSub transport driver (MQTT, AMQP, WebSockets, UDP Multicast) must implement the following trait:

```rust
use async_trait::async_trait;
use async_opcua_types::pubsub::{UadpNetworkMessage, JsonNetworkMessage};

#[async_trait]
pub trait PubSubTransport: Send + Sync {
    /// Establishes connection to the broker or network interface.
    async fn connect(&mut self) -> Result<(), StatusCode>;

    /// Disconnects from the network/broker.
    async fn disconnect(&mut self) -> Result<(), StatusCode>;

    /// Publishes a raw binary UADP network message.
    async fn publish_binary(&self, topic: &str, message: &UadpNetworkMessage) -> Result<(), StatusCode>;

    /// Publishes a structured JSON network message.
    async fn publish_json(&self, topic: &str, message: &JsonNetworkMessage) -> Result<(), StatusCode>;

    /// Subscribes to a topic, receiving messages via a stream callback.
    async fn subscribe(&self, topic: &str, callback: Box<dyn Fn(Vec<u8>) + Send + Sync>) -> Result<(), StatusCode>;
}
```

---

## 2. Historical Storage Backend Trait (`async-opcua-server`)

The historical read and update RPC services delegate data persistence to this trait:

```rust
use async_trait::async_trait;
use async_opcua_types::{NodeId, DataValue, DateTime, StatusCode};

#[async_trait]
pub trait HistoryStorageBackend: Send + Sync {
    /// Reads raw data values from the backend for a given node within a half-open range [start, end).
    async fn read_raw(
        &self,
        node_id: &NodeId,
        start_time: DateTime,
        end_time: DateTime,
        max_values: u32,
        continuation_point: Option<Vec<u8>>,
    ) -> Result<(Vec<DataValue>, Option<Vec<u8>>), StatusCode>;

    /// Updates or inserts a historical data value.
    async fn update_data(&self, node_id: &NodeId, values: &[DataValue]) -> Result<(), StatusCode>;

    /// Deletes historical data values within the range.
    async fn delete_raw(&self, node_id: &NodeId, start_time: DateTime, end_time: DateTime) -> Result<(), StatusCode>;
}
```

---

## 3. OAuth2 Token Validator Trait (`async-opcua-crypto`)

Validates incoming JWT tokens against locally cached credentials:

```rust
use async_opcua_types::StatusCode;

pub struct ClaimProfile {
    pub username: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}

pub trait OAuth2IdentityValidator: Send + Sync {
    /// Validates signature, issuer, audience, and expiration of a JWT token against local trusted keys.
    fn validate_token(&self, token_jwt: &str) -> Result<ClaimProfile, StatusCode>;
}
```

---

## 4. Program Execution Engine Contract (`async-opcua-server`)

Controls spawned asynchronous background processes inside the Program State Machine:

```rust
use async_trait::async_trait;
use async_opcua_types::StatusCode;

#[async_trait]
pub trait ProgramEngine: Send + Sync {
    /// Starts the asynchronous execution of the program.
    async fn start(&self) -> Result<(), StatusCode>;

    /// Suspends execution, keeping resources in-memory.
    async fn suspend(&self) -> Result<(), StatusCode>;

    /// Resumes execution from a suspended state.
    async fn resume(&self) -> Result<(), StatusCode>;

    /// Abruptly halts the execution of the program.
    async fn halt(&self) -> Result<(), StatusCode>;

    /// Resets the program to the Ready state.
    async fn reset(&self) -> Result<(), StatusCode>;
}
```
