# Implementation Plan: Implement Future Performance Optimizations

**Branch**: `006-implement-future-optimizations` | **Date**: 2026-06-08 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/006-implement-future-optimizations/spec.md`

## Summary

This feature implements the four major performance optimizations specified in `specs/005-future-performance-optimizations/spec.md`:
1. **O(1) Session Lookup**: Replaces the linear search lookup path with a concurrent `DashMap` keyed by `authentication_token` (NodeId).
2. **Zero-Copy Outbound Serialization**: Integrates direct serialization into connection-local reusable `BytesMut` write buffers, bypassing intermediate `Vec<u8>` heap allocations.
3. **Actor-Based Session State**: Isolates session mutable state inside single-threaded tokio actors using `mpsc` message queues, completely avoiding global lock contention on session objects.
4. **Notification Allocation Pooling**: Deploys a lock-free reuse pool for subscription notifications, enforcing a block/wait mechanism on pool exhaustion to guarantee strict memory bounds.

## Technical Context

**Language/Version**: Rust 1.75+  
**Primary Dependencies**: tokio, bytes, dashmap, lockfree-object-pool, metrics  
**Storage**: N/A (SQLite History backend is out of scope)  
**Testing**: cargo test (regression verification, unit tests, concurrent load tests)  
**Target Platform**: Linux server (x86_64-unknown-linux-musl)  
**Project Type**: Library / Server Daemon  
**Performance Goals**: Session lookup latency < 10µs, zero new heap allocations on transmit hot path, subscription memory footprint bounded under load  
**Constraints**: Requires strictly lock-free or lightweight concurrency models; connection-local buffer reuse; block/wait on pool exhaustion  
**Scale/Scope**: Industrial SCADA scale, supporting 20,000 concurrent sessions and 50,000 monitored items  

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

*   **Test-First**: Compliant. Load and benchmark tests will be written to assert the performance goals before final validation.
*   **Library-First**: Compliant. Core serialization is kept inside the existing modular crates (`async-opcua-core`, `async-opcua-server`).
*   **Simplicity / YAGNI**: Compliant. Reusing existing structures and lightweight actors avoids heavy external actor frameworks.
*   **Observability**: Compliant. Lightweight metrics instrument lookup times, pool sizes, and serialization errors.

## Project Structure

### Documentation (this feature)

```text
specs/006-implement-future-optimizations/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── checklists/
│   └── requirements.md  # Quality checklist
└── contracts/
    └── session_messages.md # Actor message contract definitions
```

### Source Code (repository root)

```text
async-opcua-core/
├── src/
│   └── comms/           # Zero-copy buffer serialization traits
async-opcua-server/
├── src/
│   ├── session/         # O(1) Session registry & Session actor
│   └── subscriptions/   # Notification object reuse pool
```

**Structure Decision**: Monorepo workspace crate layout. Changes are localized to `async-opcua-core` (for buffers/codecs) and `async-opcua-server` (for sessions/subscriptions).

## Complexity Tracking

*No violations to track. The architecture remains clean, simple, and standard.*
