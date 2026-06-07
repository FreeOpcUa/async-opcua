# Implementation Plan: Advanced OPC UA Compliance

**Branch**: `003-advanced-opcua-compliance` | **Date**: 2026-06-07 | **Spec**: [spec.md](file:///home/quackdcs/async-opcua/specs/003-advanced-opcua-compliance/spec.md)
**Input**: Feature specification from `/specs/003-advanced-opcua-compliance/spec.md`

## Summary

Implement advanced OPC UA compliance features including PubSub security key distribution (UADP encryption), subscription EventFilters, RSA-OAEP EncryptedSecrets, and complex Graph Query services (QueryFirst/QueryNext). 

## Technical Context

**Language/Version**: Rust (2021 edition)
**Primary Dependencies**: `tokio`, `async-opcua-crypto`
**Storage**: In-memory (nodes), SQLite (historical data fallback)
**Testing**: `cargo test`
**Target Platform**: Linux/Windows/macOS
**Project Type**: Library/Server Framework
**Performance Goals**: Auth < 50ms, Queries < 100ms for 100k nodes
**Constraints**: Tarpitting on failed auth must not block async executors.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Library-First**: Yes, all implementations are inside core OPC UA library crates (`async-opcua-server`, `async-opcua-pubsub`, `async-opcua-crypto`).
- **CLI Interface**: N/A (this is a protocol library).
- **Test-First**: Yes, tests will be written before integration.
- **Integration Testing**: Yes, end-to-end client-server tests will be written for PubSub and Queries.

## Project Structure

### Documentation (this feature)

```text
specs/003-advanced-opcua-compliance/
├── plan.md              
├── research.md          
├── data-model.md        
├── quickstart.md        
├── contracts/api.md           
└── tasks.md             
```

### Source Code (repository root)

```text
async-opcua-pubsub/
├── src/security/
│   └── key_server.rs
async-opcua-server/
├── src/services/
│   ├── query.rs
│   └── subscription.rs
async-opcua-crypto/
├── src/identity/
│   └── rsa_oaep.rs
```

**Structure Decision**: Modifying existing Rust library crates (`async-opcua-server`, `async-opcua-pubsub`, `async-opcua-crypto`).

## Complexity Tracking

No violations found.
