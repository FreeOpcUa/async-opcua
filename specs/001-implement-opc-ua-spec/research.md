# Research Report: OPC-UA Compliance Design Choices

This report consolidates key technical research and design decisions for upgrading the `async-opcua` framework to full standard compliance.

## Technical Decisions & Rationales

### 1. Database Storage Engine for Historical Data Access (Part 11)
* **Decision**: Implement an optional reference historical storage engine using the `rusqlite` crate in a new sub-crate `async-opcua-history-sqlite`.
* **Rationale**: SQLite is an industry-standard, lightweight, single-file database ideal for edge and gateway systems. `rusqlite` provides type-safe, highly performant synchronous bindings. Because database operations can block the CPU/thread, the server will execute SQLite queries inside `tokio::task::spawn_blocking` blocks to safeguard the async Tokio runtime.
* **Alternatives Considered**: 
  * `sqlx` (Asynchronous SQLite): Rejected due to significantly larger compilation overhead, dependency tree size, and potential runtime thread-pinning issues on tiny embedded systems.
  * In-memory vectors: Rejected for production HDA due to lack of persistence, though suitable for basic unit tests.

### 2. PubSub Transport Protocol Client for MQTT (Part 14)
* **Decision**: Integrate `rumqttc` as the underlying MQTT client in the `async-opcua-pubsub` sub-crate.
* **Rationale**: `rumqttc` is a pure-Rust, robust, and asynchronous MQTT v5/v3.1.1 client that integrates natively with the Tokio runtime. It manages automatic reconnections and message queues natively, making it a perfect fit for the PubSub publisher engine.
* **Alternatives Considered**:
  * `paho-mqtt` (Eclipse Paho wrapper): Rejected due to its hard dependency on a C library wrapper (`libpaho-mqtt`), which complicates cross-compilation for ARM/embedded industrial targets.

### 3. Brokerless PubSub Transport Mapping (UDP Multicast)
* **Decision**: Implement brokerless UDP multicast publishing utilizing `tokio::net::UdpSocket` combined with standard socket options (`socket2` or `std::net::UdpSocket` configuration).
* **Rationale**: Reuses the core asynchronous event loop from Tokio. Standard socket configuration options like `join_multicast_v4` are standard, performant, and avoid any additional dependency bloat.
* **Alternatives Considered**:
  * Specialized networking libraries: Rejected as raw UDP socket mappings under standard library and Tokio cover all required mappings.

### 4. Legacy Cryptographic Policy Isolation (Phase 6)
* **Decision**: Isolate deprecated cryptographic security profiles (Basic128Rsa15, Basic256, Basic256Sha256) behind a `legacy-crypto` compile-time feature flag in the `async-opcua-crypto` crate.
* **Rationale**: Enforces a secure-by-default security posture for new installations, rejecting weak RSA-1024 or SHA-1 channels, while allowing developers to opt-in if they must communicate with old legacy machinery.
* **Alternatives Considered**:
  * Retaining them active but emitting logging warnings: Rejected because it does not prevent automated security audits from failing due to insecure options being compiled in.
  * Complete removal: Rejected because backward compatibility with older PLC systems is a major requirement for real-world brownfield industrial deployments.

### 5. Identity Verification via OAuth2 JWT Tokens
* **Decision**: Implement OAuth2 validation in the Session Activation routine by verifying JWT tokens using cached JSON Web Key Sets (JWKS).
* **Rationale**: Using standard JWT verification allows the server to integrate with centralized corporate IdPs without doing a remote roundtrip for every session request, preserving latency.
* **Alternatives Considered**:
  * OAuth2 introspect endpoint queries: Rejected because executing a synchronous or asynchronous HTTP request to an IdP during session activation blocks session creation and introduces external network dependencies.
