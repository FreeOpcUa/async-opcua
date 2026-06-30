# Implementation Plan: Hot Path Lock Optimization

**Branch**: `240-hot-path-lock-audit` | **Date**: 2026-06-30 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/044-hot-path-lock-optimization/spec.md`

## Summary

Reduce hot-path contention and callback deadlock risk by shortening lock scopes around server callbacks, client subscription callback delivery, sampled monitored item processing, subscription fanout, session request dispatch, and CreateSession. The plan is grounded in OPC UA service semantics from the MCP: Read/Write/Call behavior must remain externally unchanged, subscription and monitored-item notification ordering must be preserved, Session and SecureChannel authentication boundaries must remain intact, and PubSub routing/config views must not be weakened.

The implementation strategy is deliberately incremental: each future task changes one guard boundary in one owner module, adds one targeted regression/proof test, and stops before broader SPSC or snapshot work unless a measurement gate justifies it.

## Technical Context

**Language/Version**: Rust 1.75+ workspace
**Primary Dependencies**: Existing workspace crates; `tokio`, `parking_lot`, `dashmap`, existing `async-opcua-*` crates, no new dependency planned for P1/P2 lock-scope work
**Storage**: N/A for P1/P2; existing certificate stores and SQLite history storage are explicitly out of scope except read/write lock mode cleanup
**Testing**: `cargo test` with targeted package filters, concurrency/deadlock regression tests, optional lock tracing with `OPCUA_TRACE_LOCKS`, `cargo fmt --check`, and workspace clippy before completion
**Target Platform**: Linux CI and local developer environments
**Project Type**: Rust workspace OPC UA client/server/pubsub library implementation
**Performance Goals**: Remove arbitrary user callback execution, sampling work, and notification fanout from live internal guards; prevent added lock guards across `.await`; preserve or improve throughput without changing public OPC UA behavior
**Constraints**: OPC UA Part 4 service semantics and status behavior must remain stable; Part 4 Subscription/MonitoredItem queue, acknowledgement, sequence, and ownership semantics must remain stable; Part 6 SecureChannel ordering and message verification must remain single-owner/ordered; changes must be atomic and independently verifiable
**Scale/Scope**: Six primary implementation slices: server callback guards, client subscription delivery guard, `SyncSampler` guard, subscription route fanout guard, `SessionManager` dispatch guard, and CreateSession write guard; P3 snapshot/SPSC work is measurement gated

## OPC UA Standard Grounding

The following MCP references constrain task design:

- **OPC-10000-4 4.1**: Read and Write belong to the Attribute Service Set; Call belongs to the Method Service Set. Callback refactors must preserve externally visible Read, Write, and Call results.
- **OPC-10000-4 5.7.2 and 5.7.3**: CreateSession and ActivateSession establish Session identity and SecureChannel association. Lock narrowing must not weaken session creation, activation, or channel reassignment checks.
- **OPC-10000-4 7.32 and 7.35**: RequestHeader authentication tokens identify requests associated with a Session and are authenticated with SecureChannel or client certificate context. Session dispatch lock narrowing must preserve lookup and validation semantics.
- **OPC-10000-4 5.13.1.2 and 5.13.1.5**: MonitoredItems have sampling intervals and queues. `SyncSampler` changes must preserve sampling rate decisions and queue behavior.
- **OPC-10000-4 5.13.2 through 5.13.6**: Create/Modify/SetMonitoringMode/Delete MonitoredItems change monitored-item state immediately or as soon as practical, and delete races can still leave notifications in flight. Route snapshots must explicitly handle create/modify/delete races.
- **OPC-10000-4 5.14.1 and 5.14.5**: Subscriptions package notifications into NotificationMessages, manage sequence/retransmission state, and consume Publish acknowledgements. Client delivery and server fanout changes must preserve acknowledgement and sequence behavior.
- **OPC-10000-6 6.7.2.4 and 6.7.7**: SecureChannel message chunks use monotonically increasing sequence numbers and must be verified before interpretation. SecureChannel renewal and any future connection pipeline must keep single-owner ordered send state.
- **OPC-10000-14 5.4.1.2 and 6.3.2.1.1**: PubSub messages are formed by WriterGroup/DataSetWriter configuration and content masks. PubSub lock-mode cleanup must preserve data-plane routing and configuration consistency.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Correctness Over Completion**: Pass. Each slice must preserve cited OPC UA behavior and include a targeted proof test before being marked done.
- **Do It Right Once**: Pass. The plan rejects blanket lock replacement and only changes guard lifetimes where source evidence and tests justify it.
- **Individual Task Discipline**: Pass. Task generation must produce one lock-boundary change per task; task names may split as T005a/T005b/T005c when a boundary needs separate test, implementation, and verification work.
- **Security Is Paramount**: Pass. Session, SecureChannel, certificate store, and activation locks remain protected; no new lock guards across `.await` are allowed on network-facing paths.
- **Leave It Better Than You Found It**: Pass. Touched paths gain lock-scope regression tests, standard references, and cleanup of adjacent lock-mode mistakes only when directly scoped.

## Project Structure

### Documentation (this feature)

```text
specs/044-hot-path-lock-optimization/
|-- spec.md
|-- plan.md
|-- research.md
|-- data-model.md
|-- quickstart.md
|-- contracts/
|   |-- lock-optimization-traceability.md
|   `-- implementation-slices.md
`-- tasks.md              # Phase 2 output from /speckit-tasks, not created by /speckit-plan
```

### Source Code (repository root)

```text
async-opcua-server/src/
|-- node_manager/memory/
|   |-- simple.rs          # P1 server Read/Write/Call callback guard boundaries
|   `-- core.rs            # P1 context-aware method callback guard boundary
|-- node_manager/utils/
|   `-- sync_sampler.rs    # P1 sampled monitored-item guard boundary
|-- subscriptions/
|   |-- mod.rs             # P1 route snapshot and sampling closure boundary
|   `-- notify.rs          # P1 post-unlock actor enqueue boundary
`-- session/
    |-- controller.rs      # P2 normal dispatch and CreateSession lock scopes
    `-- manager.rs         # P2 CreateSession split/commit semantics

async-opcua-client/src/
`-- session/services/subscriptions/
    |-- service.rs         # P1 Publish handling state/delivery split
    |-- state.rs           # P1 delivery packet production
    `-- mod.rs             # P1 callback delivery surface

async-opcua-client/src/transport/
`-- channel.rs             # P2/P3 secure-channel renewal measurement gate; cert-store read-lock cleanup

async-opcua-pubsub/src/
`-- subscriber.rs          # P3 read-only write-lock cleanup where evidence confirms no mutation

async-opcua-server/tests/
async-opcua-client/tests/
async-opcua-pubsub/tests/
```

**Structure Decision**: Keep each lock-scope change in the module that owns the protected invariant. Add tests at the lowest layer that can prove guard release and OPC UA side-effect preservation; use integration tests only when a unit/package test cannot prove callback re-entry, Publish acknowledgement behavior, or subscription routing races.

## Phase 0 Research Summary

Research is captured in [research.md](./research.md). Key decisions:

- Callback, sampler, and fanout work must move outside guards before adding additional processing threads or queues.
- OPC UA Part 4 subscription and monitored-item semantics are the primary constraint on route snapshots and client callback delivery.
- Session and SecureChannel work is lock narrowing only, not security boundary removal.
- P1/P2 tasks do not need new dependencies; snapshot/SPSC work is deferred behind a measurement gate.
- Every future task must cite an OPC UA MCP section or the scoped lock-audit traceability contract.

## Phase 1 Design Summary

Design artifacts:

- [data-model.md](./data-model.md) defines callback snapshots, delivery packets, sampler work items, route snapshots, session lookup snapshots, CreateSession drafts, versioned metadata snapshots, and queue lanes.
- [contracts/implementation-slices.md](./contracts/implementation-slices.md) defines the atomic implementation slices, standard references, owner files, test proof, and task-splitting rules.
- [contracts/lock-optimization-traceability.md](./contracts/lock-optimization-traceability.md) remains the scoped evidence map from audit findings to code locations.
- [quickstart.md](./quickstart.md) describes task-local verification commands and the completion gate.

## Atomic Task Planning Rules

- One task changes one guard boundary in one owner surface.
- A task may be split into test, implementation, and verification subtasks when the proof is non-trivial.
- No task may combine server callback refactors with client callback delivery or subscription fanout.
- No task may introduce SPSC queues, `ArcSwap`, or versioned snapshots until the corresponding P1 guard-scope task and measurement gate are complete.
- Each task must name its OPC UA section, affected files, proof test, and targeted command.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| None | N/A | N/A |
