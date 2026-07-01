# Implementation Plan: Lock Removal and Snapshot Concurrency

**Branch**: `046-lock-removal-snapshots` | **Date**: 2026-06-30 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/046-lock-removal-snapshots/spec.md`

## Summary

Implement the lock-audit recommendations as measured, independently verifiable slices. The MVP replaces hot-path TypeTree reads through `Arc<RwLock<DefaultTypeTree>>` with immutable published snapshots, preserving custom getter behavior and OPC UA service results. Later slices address response-size limit state, subscription route indexing, PubSub configuration/cache paths, SQLite history scaling, and SecureChannel renewal only after measurements and expected-red tests justify each change.

## Technical Context

**Language/Version**: Rust 1.75+ workspace  
**Primary Dependencies**: Existing workspace crates; `tokio`, `parking_lot`, `dashmap`, `crossbeam-queue`; candidate `arc-swap` only if not already usable  
**Storage**: N/A for TypeTree and response-size slices; SQLite history follow-up is limited to `async-opcua-history-sqlite`  
**Testing**: TDD with expected-red proof tests, targeted service tests, controlled localhost benchmark samples, `cargo fmt --check`, workspace `cargo test`, and clippy lock checks  
**Target Platform**: Linux developer and CI runners for async-opcua server/client workspace  
**Project Type**: Rust OPC UA library workspace with server, client, core, PubSub, and history crates  
**Performance Goals**: Remove TypeTree hot-path read-lock contention while recording at least three before/after controlled Read and Write benchmark samples; median throughput must not drop by more than 5% for either operation unless slice notes document measurement noise and an accepted rationale; require measurement before broader lock removal  
**Constraints**: Preserve OPC UA Part 4 service semantics, Part 6 SecureChannel ordering/security behavior, and Part 14 PubSub consistency; no raw seqlocks, unchecked custom unsafe lock-free structures, or relaxed memory ordering without a documented correctness proof  
**Scale/Scope**: One MVP TypeTree snapshot implementation plus planned, independently gated follow-up slices for five additional lock boundaries

## OPC UA Standard Grounding

- **OPC-10000-4 Attribute, Browse, Query, and Subscription service behavior**: Service paths that rely on type metadata must return the same externally visible results after snapshot conversion.
- **OPC-10000-4 response-size behavior**: Negotiated response limits and `BadResponseTooLarge` handling must remain channel-specific and protocol-compatible.
- **OPC-10000-6 SecureChannel behavior**: Renewal changes must preserve channel token ordering, request correlation, and failure semantics.
- **OPC-10000-14 PubSub configuration behavior**: Configuration reflection and transport cache changes must remain consistent for PubSub configuration methods.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Correctness Over Completion**: Pass. Each lock removal requires expected-red tests or measurements and must preserve protocol-visible behavior.
- **Do It Right Once**: Pass. The workflow uses immutable snapshots and channel-owned state rather than speculative custom lock-free primitives.
- **Individual Task Discipline**: Pass. Tasks are grouped by lock boundary and user story, with one independently reviewable slice per boundary.
- **Security Is Paramount**: Pass. Security-sensitive SecureChannel and certificate/session locks remain unless separately justified with focused tests.
- **Leave It Better Than You Found It**: Pass. The active plan pointer is updated, generated artifacts document gates, and verification includes lock-specific clippy checks.

## Project Structure

### Documentation (this feature)

```text
specs/046-lock-removal-snapshots/
|-- spec.md
|-- plan.md
|-- research.md
|-- data-model.md
|-- baseline.md
|-- slice-notes.md
|-- opcua-clause-matrix.md
|-- quickstart.md
|-- contracts/
|   `-- implementation-slices.md
|-- checklists/
|   `-- requirements.md
`-- tasks.md
```

### Source Code (repository root)

```text
async-opcua-server/src/
|-- info.rs                         # TypeTree ownership and getter compatibility
|-- server.rs                       # startup/publish wiring
|-- server_handle.rs                # public handle accessors if needed
|-- address_space/
|   `-- utils.rs                    # namespace/type-tree mutation publication
|-- diagnostics/
|   `-- node_manager.rs             # diagnostics browse/type metadata reads
|-- node_manager/
|   |-- context.rs                  # request context TypeTree access
|   `-- memory/mod.rs               # default manager initialization path
|-- session/
|   |-- actor.rs                    # session actor request context construction
|   |-- controller.rs               # response-size propagation boundary
|   |-- message_handler.rs          # service call usage checks
|   `-- services/
|       |-- monitored_items.rs      # monitored item type metadata access
|       |-- query.rs                # Query type metadata access
|       `-- view.rs                 # Browse/view type metadata access
`-- subscriptions/actor.rs          # subscription route follow-up boundary

async-opcua-core/src/comms/
|-- buffer.rs                       # response-size follow-up boundary
`-- secure_channel.rs               # channel-local response-size state

async-opcua-pubsub/src/
|-- config_methods.rs               # PubSub config follow-up boundary
`-- transport/                      # PubSub transport cache follow-up boundary

async-opcua-history-sqlite/src/
`-- backend.rs                      # SQLite history follow-up boundary

async-opcua-client/src/transport/
`-- channel.rs                      # SecureChannel renewal follow-up boundary

tests and crate-local test modules  # focused expected-red and regression tests
```

**Structure Decision**: Keep the implementation in existing crates and ownership boundaries. The MVP touches server TypeTree access paths; follow-up slices touch only the crate that owns the measured lock boundary.

## Phase 0 Research Summary

Research is captured in [research.md](./research.md). Key decisions:

- Use immutable TypeTree snapshots for the MVP because the audited state is read-mostly and currently protected by a hot global `RwLock`.
- Preserve existing session/security/channel ownership locks unless focused measurements show contention and tests can prove protocol fidelity.
- Use per-channel response-size state for the P2 slice instead of a process-wide map lock.
- Treat subscription route, PubSub, SQLite, and SecureChannel changes as measured follow-ups rather than one broad refactor.

## Phase 1 Design Summary

Design artifacts:

- [data-model.md](./data-model.md) defines the snapshot, publication, response-limit, route-index, slice, and verification-gate entities.
- [baseline.md](./baseline.md) records current lock baselines, test commands, benchmark commands, and dependency decisions used before implementation.
- [slice-notes.md](./slice-notes.md) records per-slice expected-red results, verification results, benchmark comparisons, rollback scopes, and final review evidence.
- [opcua-clause-matrix.md](./opcua-clause-matrix.md) maps each slice and verification gate to the relevant OPC UA standard clauses.
- [contracts/implementation-slices.md](./contracts/implementation-slices.md) defines the implementation contract for each lock boundary.
- [quickstart.md](./quickstart.md) documents setup, targeted verification, benchmark sampling, and final checks.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| None | N/A | N/A |
