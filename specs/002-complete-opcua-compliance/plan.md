# Implementation Plan: Complete OPC UA Compliance

**Branch**: `002-complete-opcua-compliance` | **Date**: 2026-06-06 | **Spec**: [spec.md](file:///home/quackdcs/async-opcua/specs/002-complete-opcua-compliance/spec.md)
**Input**: Feature specification from `/specs/002-complete-opcua-compliance/spec.md`

## Summary

This plan outlines the architecture and execution strategy to achieve full IEC 62541 OPC UA standard compliance in the `async-opcua` framework. The implementation will deliver Alarms and Conditions (Part 9), Programs (Part 10), Historical Data Access (Part 11) backed by SQLite, Global Discovery Server push/pull certificate management (Part 12), Historical Aggregates (Part 13), and a comprehensive PubSub implementation (Part 14) supporting MQTT, AMQP, WebSockets, and UDP multicast.

## Technical Context

**Language/Version**: Rust 1.75+ (Edition 2021)  
**Primary Dependencies**: `tokio` (async runtime), `rumqttc` (MQTT client), `lapin`/`amqprs` (AMQP), `tokio-tungstenite` (WebSockets), `rusqlite`/`sqlx` (SQLite client), and standard Rust crypto crates in `async-opcua-crypto`.  
**Storage**: SQLite database for time-series HDA storage; configurable OS filesystem directory for session-scoped temporary file transfers.  
**Testing**: `cargo test` (unit, integration, and conformance test suites)  
**Target Platform**: Linux, macOS, Windows, and embedded targets  
**Project Type**: Multi-crate Rust library workspace  
**Performance Goals**: Bounded memory footprint for buffering; asynchronous, non-blocking lock primitives (`tokio::sync::RwLock`) to prevent event-loop stalls under heavy load.  
**Constraints**: Zero-panic/unwrap code policy; exact standard compliance; automatic and secure cleanup of temporary resources on disconnect/timeout.  
**Scale/Scope**: Telemetry throughput validation for PubSub UDP multicast up to network MTU boundaries; historical querying database performance validation (paging 100,000+ records).

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Principle 1: Library-First**: **Pass** (All features are encapsulated within reusable crates in the cargo workspace).
- **Principle 2: CLI Interface**: **Pass** (No direct CLI required, but test/sample applications will expose the implemented APIs).
- **Principle 3: Test-First**: **Pass** (Will implement integration and unit tests before merging).
- **Principle 4: Integration Testing**: **Pass** (Integration tests will verify PubSub, HDA, Alarms, GDS, and OAuth2).
- **Principle 5: Observability & Simplicity**: **Pass** (Standard logging and tracing used with strict token/credential redaction).

## Project Structure

### Documentation (this feature)

```text
specs/002-complete-opcua-compliance/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
└── contracts/           # Phase 1 output
    └── api.md           # API signature contracts
```

### Source Code (repository root)

The workspace layout maps the new modules and changes to the existing async-opcua architecture:

```text
async-opcua-pubsub/      # New crate for PubSub connection and serialization
├── Src/
│   ├── config.rs        # PubSubConnection, WriterGroup, DataSetWriter structs
│   ├── encoding/        # UADP and JSON serializers/deserializers
│   └── transport/       # MQTT, AMQP, WebSockets, UDP multicast drivers
│
async-opcua-server/      # Server modifications
├── Src/
│   ├── alarms/          # ConditionStateMachine and A&C event loop
│   ├── history/         # HistoryStorageBackend trait, sqlite driver, aggregates
│   ├── programs/        # ProgramStateMachineType execution engine
│   └── gds/             # Part 12 push/pull method callbacks
│
async-opcua-client/      # Client API updates
├── Src/
│   ├── history.rs       # Read/update HDA client methods
│   ├── discovery.rs     # GDS client APIs
│   └── pubsub.rs        # PubSub subscription client APIs
│
async-opcua-crypto/      # Cryptographic updates
├── Src/
│   ├── identity/        # OAuth2 token validation and claim mapper
│   └── security.rs      # Disable deprecated profiles by default; modernize defaults
```

**Structure Decision**: Workspace model using cargo workspace, creating `async-opcua-pubsub` as a new library crate, while augmenting `async-opcua-server`, `async-opcua-client`, and `async-opcua-crypto`.

## Complexity Tracking

*No current violations of the Constitution Check.*
