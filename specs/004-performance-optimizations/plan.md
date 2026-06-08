# Implementation Plan: Performance Optimizations & Advanced Profiles

**Branch**: `004-performance-optimizations` | **Date**: 2026-06-07 | **Spec**: [spec.md](./spec.md)

## Summary

Refactor the core OPC-UA architecture to eliminate global locks via `DashMap`, implement zero-copy TCP parsing using `bytes`, introduce async-aware LRU caching for historical data, and deploy the new TSN and Safety profiles.

## Technical Context

**Language/Version**: Rust 1.75
**Primary Dependencies**: tokio, tokio-util, bytes, dashmap, moka, rusqlite
**Storage**: SQLite (History)
**Testing**: cargo test
**Target Platform**: Linux server (Alpine / x86_64-unknown-linux-musl)
**Project Type**: Library / Server Daemon
**Performance Goals**: Sub-50ms response under 10k clients, zero memory allocation on hot-path
**Constraints**: Requires strictly deterministic latency bounds (TSN), Linux capabilities (CAP_NET_RAW) for AF_XDP
**Scale/Scope**: Industrial scale SCADA integration

## Constitution Check

*   **Test-First**: Compliant. Tests will simulate concurrent load.
*   **Library-First**: Compliant.
*   **Simplicity**: DashMap and moka introduce dependencies but justify their inclusion by resolving massive P1 bottlenecks.

## Project Structure

### Documentation

```text
specs/004-performance-optimizations/
├── plan.md              
├── research.md          
├── data-model.md        
├── quickstart.md        
├── contracts/           
└── tasks.md             
```

### Source Code

```text
async-opcua-server/
├── src/
│   ├── address_space/      # DashMap refactor
│   ├── history/            # Moka LRU implementation
│   └── comms/              # Zero-copy Bytes integration
async-opcua-pubsub/
├── src/
│   ├── transport/
│   │   └── tsn/            # AF_XDP raw sockets implementation
async-opcua-safety/         # New crate for Part 15 Safety Profile
├── src/
│   ├── spdu.rs
│   ├── validator.rs
│   ├── cli.rs              # Constitution mandated CLI
│   └── bin/
│       └── main.rs         # Stdin/stdout processor
```

**Structure Decision**: Kept inside the main monorepo. Added a new dedicated `async-opcua-safety` crate for the SIL 3 implementation to maintain separation of concerns.
