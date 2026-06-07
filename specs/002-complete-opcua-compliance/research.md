# Research Findings: Complete OPC UA Compliance

This document consolidates the architectural decisions, best practices, and integration patterns researched to address the compliance requirements.

## 1. PubSub Transport Mapping Libraries

* **Decision**: Integrate `rumqttc` for MQTT, `lapin` for AMQP, `tokio-tungstenite` for WebSockets, and standard `tokio::net::UdpSocket` for UDP multicast.
* **Rationale**: 
  - `rumqttc` is a pure-Rust, high-performance asynchronous MQTT client that runs cleanly on the Tokio runtime and has no C library dependencies, ensuring memory safety.
  - `lapin` is the most mature, pure-Rust asynchronous AMQP 0.9.1 client library, providing full integration with Tokio.
  - `tokio-tungstenite` is the de-facto standard for async WebSockets in Rust, offering a lightweight and robust implementation.
  - `tokio::net::UdpSocket` supports native IP multicast joining and asynchronous datagram transmission suitable for brokerless UADP messaging.
* **Alternatives considered**: 
  - `paho-mqtt` / `paho-amqp`: Rejected because they depend on external C libraries (Eclipse Paho C) which complicates cross-compilation and violates pure-Rust memory safety goals.

## 2. Historical Storage Interface

* **Decision**: Implement the `HistoryStorageBackend` using `rusqlite` via the existing `async-opcua-history-sqlite` crate structure.
* **Rationale**: Utilizing `rusqlite` provides a lightweight, serverless relational database engine that runs locally. It allows microsecond-precise UTC timestamp queries using standard SQL indexing, satisfying the half-open interval `[start, end)` lookup constraints.
* **Alternatives considered**: 
  - `sqlx`: Rejected because `rusqlite` is already partially referenced and sufficient for embedded and file-based local deployments, avoiding the compile-time complexity of `sqlx` macro queries.
  - In-memory B-Trees: Rejected because persistent HDA storage is required by the clarified spec.

## 3. GDS Push/Pull Certificate Management

* **Decision**: Implement the standard OPC UA GDS push/pull Method interfaces (`CreateSigningRequest`, `UpdateCertificate`, `GetRejectedList`, `StartSigningRequest`) on the server address space.
* **Rationale**: This guarantees full compatibility with industrial certificate managers and OPC UA Global Discovery Servers complying with IEC 62541-12.
* **Alternatives considered**: 
  - Custom file-watchers or out-of-band HTTPS APIs: Rejected because they do not conform to standard OPC UA GDS protocols and would fail third-party interoperability checks.

## 4. Program State Machine Execution

* **Decision**: Spawning background execution tasks using `tokio::task::spawn` and tracking their execution handles using synchronized map collections mapped to specific Program nodes.
* **Rationale**: This prevents blocking the main server session event loop, ensuring keep-alive messages continue to flow while programs execute. The `JoinHandle` allows standard control methods (`Halt`, `Suspend`, `Resume`) to signal or cancel the active task.
* **Alternatives considered**: 
  - Thread-spawning: Rejected due to high resource usage on constrained systems.
  - Co-routines/generators: Rejected as native Rust async/await with task cancellation is cleaner and fits the existing Tokio paradigm.

## 5. UADP and JSON PubSub Encodings

* **Decision**: Implement custom binary serialization/deserialization for the UADP binary protocol in `async-opcua-pubsub`, and use `serde` / `serde_json` for the JSON PubSub messages.
* **Rationale**: UADP requires byte-perfect binary packaging with specific field offsets (sequence numbers, flags). JSON messaging is best handled by `serde` due to its performance, security, and type safety.
* **Alternatives considered**: 
  - Manual string formatting for JSON: Rejected as it is highly prone to escaping bugs and formatting errors.
