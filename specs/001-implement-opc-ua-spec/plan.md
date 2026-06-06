# Implementation Plan: Implement OPC-UA Standard Support Plan

**Branch**: `001-implement-opc-ua-spec` | **Date**: 2026-06-06 | **Spec**: [spec.md](file:///home/quackdcs/async-opcua/specs/001-implement-opc-ua-spec/spec.md)
**Input**: Feature specification from `/specs/001-implement-opc-ua-spec/spec.md`

## Summary

The primary objective is to implement full IEC 62541 OPC-UA standard compliance across advanced specifications for the `async-opcua` framework. The technical approach systematically upgrades the codebase across:
1. **Alarms and Conditions (Part 9)**: Server-side `ConditionStateMachine` engine managing active alarms, events routing, and Client Method acknowledgment handlers.
2. **Historical Data Access (Part 11)**: Abstract `HistoryStorageBackend` interface, Chronological sorting/filtering, and continuation point pagination middleware.
3. **PubSub Communication Model (Part 14)**: Dedicated workspace crate (`async-opcua-pubsub`) supporting UADP datagram multicast and JSON MQTT protocol mappings.
4. **Programs (Part 10)**: Dynamic Program State Machine execution engine with asynchronous task execution handles.
5. **Aggregates (Part 13)**: Historical aggregate mathematical processing middleware.
6. **Global Discovery Server (Part 12)**: dynamic X.509 certificate renewal client.
7. **Companion Spec CodeGen**: Hardening XML parser for complex NodeSets.
8. **Cryptographic Completeness**: Legacy security isolation and OAuth2 JWT authentication.

To keep implementation safe and predictable, all tasks are structured atomically, mapping directly to individual crates, and strictly respect the asynchronous non-blocking constraints of the Tokio event loops.

## Technical Context

**Language/Version**: Rust (Edition 2021, Rust 1.75+)  
**Primary Dependencies**: `tokio` (v1.x, full), `tracing` (v0.1.x), `rumqttc` (v0.24.x), `rusqlite` (v0.31.x), `quick-xml` (v0.37.x), `roxmltree` (v0.20.x)  
**Storage**: In-memory AddressSpace graph; optional sqlite-based historical storage backend  
**Testing**: `cargo test`, workspace unit tests, custom integration test harnesses in `codegen-tests` and `dotnet-tests`  
**Target Platform**: Cross-platform (Linux, macOS, Windows), optimized for edge devices and industrial telemetry gateways  
**Project Type**: Multi-crate Cargo Workspace library  
**Performance Goals**: PubSub event publication latency < 50ms for 1,000 variables; history read processing > 10,000 values/sec  
**Constraints**: Zero panic-inducing runtime states (no `.unwrap()` or `.expect()` in runtime code), asynchronous non-blocking design on Tokio threads, secure-by-default credential logging redaction  
**Scale/Scope**: Industrial scale (handling up to 100,000 historical telemetry records and multiple concurrent client sessions)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Rule 1: Asynchronous Non-blocking Execution**
  - *Status*: PASS. Long-running or heavy operations (e.g., historical file reads, aggregate computations, companion nodeset parsing) are delegated to dedicated blocking threads via `tokio::task::spawn_blocking` to preserve the event loop heartbeat.
- **Rule 2: Zero Panic Policy**
  - *Status*: PASS. No `.unwrap()` or `.expect()` calls are permitted in production paths; all error conditions map to standardized OPC-UA `StatusCode` values.
- **Rule 3: Secure-by-Default Observability**
  - *Status*: PASS. Tracing levels log unencrypted operations but enforce strict credentials masking and SHA-256 hashing for JWT authentication tokens.
- **Rule 4: Multi-Crate Workspace Modularity**
  - *Status*: PASS. New capabilities (PubSub, SQLite history backend) are isolated in dedicated workspace crates to prevent bloat in the core runtime.

## Project Structure

### Documentation (this feature)

```text
specs/001-implement-opc-ua-spec/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output
└── tasks.md             # Phase 2 output (created by speckit-tasks command)
```

### Source Code Crate Layout

```text
async-opcua/
├── async-opcua/             # Main library facade crate
├── async-opcua-core/        # Shared core protocol mappings & binary transport
├── async-opcua-types/       # Serialization, Binary/JSON/XML schemas, dynamic types
├── async-opcua-crypto/      # Security profiles, X.509 cert validation, legacy config
├── async-opcua-server/      # Server runtime, AddressSpace, ConditionStateMachine, Program engine
├── async-opcua-client/      # Client runtime, discovery, event callbacks, Session API
├── async-opcua-pubsub/      # [NEW] DataSetWriter config, MQTT & UDP Multicast transports
├── async-opcua-history-sqlite/ # [NEW] Reference SQLite storage engine implementation
├── async-opcua-xml/         # NodeSet XML parser & structure loader
└── async-opcua-codegen/     # Auto-generation tool for Companion Specifications
```

**Structure Decision**: Multi-crate Cargo Workspace. Existing crates will be modified to add core protocol capabilities, and two new optional sub-crates (`async-opcua-pubsub` and `async-opcua-history-sqlite`) will be introduced to segregate PubSub network drivers and historical DB dependencies.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| New crate `async-opcua-pubsub` | PubSub requires heavy network dependencies (e.g. MQTT clients, UDP multicast sockets) | Embedding directly in core/server would force all users to compile unused dependencies, bloating the runtime binary. |
| New crate `async-opcua-history-sqlite` | Reference HDA storage backend is required for testability and out-of-the-box edge deployment | Defining only abstract traits makes local integration testing of HDA functionality extremely difficult without mocking databases. |
