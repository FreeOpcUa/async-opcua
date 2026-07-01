# Contract: Lock Removal Implementation Slices

Each slice must be independently reviewable and must preserve OPC UA externally visible behavior.

## Slice 1: TypeTree Snapshot MVP

**Priority**: P1  
**Primary files**:

- `async-opcua-server/src/info.rs`
- `async-opcua-server/src/node_manager/context.rs`
- `async-opcua-server/src/node_manager/memory/mod.rs`
- `async-opcua-server/src/server.rs`
- `async-opcua-server/src/server_handle.rs`
- `async-opcua-server/src/session/message_handler.rs`
- `async-opcua-server/src/subscriptions/actor.rs`

**Pre-implementation proof**:

- Add a focused test that can detect hot-path reads trying to acquire the mutable/global TypeTree lock.
- Add a consistency test for snapshot publication after type metadata initialization.

**Implementation contract**:

- Build mutable TypeTree state only on setup or explicit mutation paths.
- Publish a complete immutable `TypeTreeSnapshot` atomically.
- Update service hot paths to borrow the snapshot view.
- Keep custom type-tree getter behavior explicit.

**Verification**:

- Focused TypeTree snapshot tests pass.
- Existing Browse, Query, Read, Write, subscription, and type metadata tests pass or targeted equivalents are documented.
- Clippy lock checks pass.

## Slice 2: Response Size Limit State

**Priority**: P2  
**Primary files**:

- `async-opcua-core/src/comms/buffer.rs`
- Channel/session call sites that currently register or read response-size limits

**Pre-implementation proof**:

- Add tests for nonzero limit, zero limit, oversized response, channel close, and concurrent channels with different limits.

**Implementation contract**:

- Move response limit ownership to channel-local or equivalent hot-path lock-free state.
- Preserve `BadResponseTooLarge` behavior.
- Ensure state is not shared across channels unless protected by a non-hot-path owner.

**Verification**:

- Response-size tests pass under concurrent channel scenarios.
- No global lock is required for steady-state response checks.

## Slice 3: Subscription Route Index Snapshot

**Priority**: P3  
**Primary files**:

- `async-opcua-server/src/subscriptions/actor.rs`
- Subscription manager and notification fanout call sites

**Pre-implementation proof**:

- Record contention or fanout evidence that route locking is material.
- Add tests for monitored item create, delete, modify, transfer, republish, and Publish notification behavior.

**Implementation contract**:

- Publish complete route-index snapshots for fanout only after route updates are consistent.
- Preserve subscription lifecycle semantics and notification ordering.

**Verification**:

- Subscription lifecycle tests pass.
- Benchmark or trace evidence shows the change improves or does not regress the measured scenario.

## Slice 4: PubSub Configuration and Transport Cache

**Priority**: P3  
**Primary files**:

- `async-opcua-pubsub/src/config_methods.rs`
- `async-opcua-pubsub/src/transport/`

**Pre-implementation proof**:

- Record contention evidence for config or cache locks.
- Add Part 14 focused tests for reflected configuration methods and transport cache updates.

**Implementation contract**:

- Use a config actor or draft/commit publication pattern.
- Use bounded async transport cache updates where backpressure matters.
- Preserve reflected configuration consistency.

**Verification**:

- PubSub config and transport tests pass.
- No unbounded queue growth is introduced.

## Slice 5: SQLite History Scaling

**Priority**: P3  
**Primary files**:

- `async-opcua-history-sqlite/src/backend.rs`

**Pre-implementation proof**:

- Record history read/write contention or throughput evidence.
- Add tests for continuation points, concurrent reads, writes, and failure behavior.

**Implementation contract**:

- Keep the current mutex if the backend is used as a reference implementation.
- If scaling is justified, move to a DB actor or read-pool/write-owner design with explicit continuation semantics.

**Verification**:

- History tests pass with unchanged query results and continuation behavior.

## Slice 6: SecureChannel Renewal

**Priority**: P3  
**Primary files**:

- `async-opcua-client/src/transport/channel.rs`

**Pre-implementation proof**:

- Record contention evidence showing renewal locking is material.
- Add tests for concurrent renewal waiters, cancellation, renewal failure, and request ordering.

**Implementation contract**:

- Keep the mutex unless measurements justify replacement.
- If replaced, use a single-flight renewal state machine with `Notify` or shared future semantics.
- Preserve SecureChannel token ordering and request correlation.

**Verification**:

- SecureChannel renewal tests pass.
- No duplicate renewal attempts are possible for the same channel state.
