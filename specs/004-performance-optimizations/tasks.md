---
description: "Task list template for feature implementation"
---

# Tasks: Performance Optimizations & Advanced Profiles

**Input**: Design documents from `/specs/004-performance-optimizations/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, quickstart.md

**Organization**: Tasks are grouped by user story. Constitution mandates Test-First implementation and CLI exposure.

## Phase 1: Setup (Shared Infrastructure)

- [X] T001 Update `Cargo.toml` in `async-opcua-server` to include `dashmap`.
- [X] T002 Update `Cargo.toml` in `async-opcua-server` to include `moka`.
- [X] T003 Update `Cargo.toml` in `async-opcua-pubsub` to include `xsk-rs` for AF_XDP.
- [X] T004 Create new crate `async-opcua-safety` in workspace `Cargo.toml`.
- [X] T005 Initialize `async-opcua-safety` crate with `cargo new --lib` and binary target setup.

---

## Phase 2: Foundational (Blocking Prerequisites)

- [X] T006 Define the core `DashMap` trait bounds in `async-opcua-server/src/address_space/mod.rs`.
- [X] T007 [P] Set up `bytes` integration types in `async-opcua-core/src/comms/mod.rs`.
- [X] T008 [P] Define `Spdu` foundational struct in `async-opcua-safety/src/spdu.rs`.

---

## Phase 3: User Story 1 - High-Concurrency Data Access (Priority: P1) 🎯 MVP

**Goal**: Refactor the AddressSpace to use DashMap to remove global RwLock bottleneck.

### Tests for User Story 1 (TEST-FIRST MANDATORY)
- [X] T009 [P] [US1] Write failing concurrent R/W throughput load test in `async-opcua-server/tests/address_space_concurrency.rs`.

### Implementation for User Story 1
- [X] T010 [US1] Refactor `AddressSpace` struct to use `DashMap` in `async-opcua-server/src/address_space/mod.rs`.
- [X] T011 [US1] Update `add_node` method to use DashMap API in `async-opcua-server/src/address_space/mod.rs`.
- [X] T012 [US1] Update `get_node` method to use DashMap API in `async-opcua-server/src/address_space/mod.rs`.
- [X] T013 [US1] Update `find_node` method to use DashMap API in `async-opcua-server/src/address_space/mod.rs`.
- [X] T014 [US1] Refactor read services to use `DashMap` lookups in `async-opcua-server/src/services/node_access.rs`.
- [X] T015 [US1] Refactor write services to use `DashMap` lookups in `async-opcua-server/src/services/node_access.rs`.
- [X] T016 [US1] Implement weakly consistent graph traversal for query in `async-opcua-server/src/services/query/traversal.rs`.

---

## Phase 4: User Story 2 - Real-Time Deterministic Communication (Priority: P1)

**Goal**: Implement OPC-UA over TSN (Time-Sensitive Networking) via raw AF_XDP sockets.

### Tests for User Story 2 (TEST-FIRST MANDATORY)
- [X] T017 [P] [US2] Write failing TSN socket jitter loopback test in `async-opcua-pubsub/tests/tsn_jitter.rs`.

### Implementation for User Story 2
- [X] T018 [P] [US2] Create AF_XDP socket bindings in `async-opcua-pubsub/src/transport/tsn/af_xdp.rs`.
- [X] T019 [P] [US2] Implement memory mapping (UMEM) for AF_XDP in `async-opcua-pubsub/src/transport/tsn/umem.rs`.
- [X] T020 [US2] Implement transmit queue (Tx) dispatch in `async-opcua-pubsub/src/transport/tsn/af_xdp.rs`.
- [X] T021 [US2] Implement receive queue (Rx) polling in `async-opcua-pubsub/src/transport/tsn/af_xdp.rs`.
- [X] T022 [P] [US2] Implement `tc taprio` UDP fallback driver by shelling out to `tc qdisc` commands via `std::process::Command` in `async-opcua-pubsub/src/transport/tsn/taprio.rs`.
- [X] T023 [US2] Integrate TSN driver into `async-opcua-pubsub/src/transport/mod.rs` routing.

---

## Phase 5: User Story 3 - Functional Safety Communication (Priority: P1)

**Goal**: Implement the OPC-UA Safety profile (Part 15) targeting SIL 3 and expose via CLI.

### Tests for User Story 3 (TEST-FIRST MANDATORY)
- [X] T024 [P] [US3] Write failing fault-injection harness (corrupts/drops/delays packets) in `async-opcua-safety/tests/fault_injection.rs`.

### Implementation for User Story 3
- [X] T025 [P] [US3] Implement SPDU sequence numbering in `async-opcua-safety/src/spdu.rs`.
- [X] T026 [P] [US3] Implement SPDU timestamp encoding in `async-opcua-safety/src/spdu.rs`.
- [X] T027 [P] [US3] Implement SIL 3 CRC calculation in `async-opcua-safety/src/crc.rs`.
- [X] T028 [US3] Implement `SpduBuilder` in `async-opcua-safety/src/builder.rs`.
- [X] T029 [US3] Implement safety validation checks (timeout, CRC, sequence) in `async-opcua-safety/src/validator.rs`.
- [X] T030 [US3] Integrate SPDU validation into server endpoints in `async-opcua-server/src/services/node_access.rs`.

### CLI Implementation
- [X] T031 [P] [US3] Implement CLI parser using `clap` for SPDU encoding/decoding in `async-opcua-safety/src/cli.rs`.
- [X] T032 [US3] Wire CLI commands to stdin/stdout processing in `async-opcua-safety/src/bin/main.rs`.

---

## Phase 6: User Story 4 - High-Throughput Network Serialization (Priority: P2)

**Goal**: Implement zero-copy TCP serialization using `bytes`.

### Tests for User Story 4 (TEST-FIRST MANDATORY)
- [X] T033 [P] [US4] Write failing memory allocation monitor test during massive parsing in `async-opcua-core/tests/zero_copy_alloc.rs`.

### Implementation for User Story 4
- [X] T034 [US4] Refactor `TcpCodec` to hold `BytesMut` in `async-opcua-core/src/comms/tcp_codec.rs`.
- [X] T035 [US4] Refactor `MessageChunk::decode` to accept `&mut Bytes` in `async-opcua-core/src/comms/message_chunk.rs`.
- [X] T036 [US4] Remove `Vec<u8>` allocation in `MessageChunk` serialization in `async-opcua-core/src/comms/message_chunk.rs`.
- [X] T037 [US4] Refactor chunk assembly to use zero-copy concatenation in `async-opcua-core/src/comms/secure_channel.rs`.

---

## Phase 7: User Story 5 - Efficient Historical Data Management (Priority: P3)

**Goal**: Switch history cache to async-aware LRU pruning.

### Tests for User Story 5 (TEST-FIRST MANDATORY)
- [X] T038 [P] [US5] Write failing memory-bounded eviction test for history caching in `async-opcua-server/tests/history_lru.rs`.

### Implementation for User Story 5
- [X] T039 [US5] Initialize `moka::future::Cache` in `async-opcua-server/src/history/backend.rs`.
- [X] T040 [US5] Replace `prune_continuation_points` sync Mutex loop with `moka` expiration policy in `async-opcua-server/src/history/continuation.rs`.
- [X] T041 [US5] Wire SQLite fetches to `moka` cache misses in `async-opcua-history-sqlite/src/backend.rs`.
- [X] T042 [US5] Implement memory bounding limits for `moka` cache in `async-opcua-server/src/history/backend.rs`.

---

## Phase 8: Polish & Cross-Cutting Concerns

- [ ] T043 Run integration tests for DashMap concurrent throughput.
- [ ] T044 Run load test simulating 10k connections.
- [ ] T045 Verify zero memory leaks using `valgrind` or similar during peak zero-copy parsing.
- [ ] T046 Verify TSN sub-millisecond jitter boundaries via hardware timers (SC-003).

---

## Dependencies & Execution Order

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Stories (Phase 3+)**: All depend on Foundational phase completion
- **Tests**: MUST run and fail before the implementation tasks for that user story begin.
