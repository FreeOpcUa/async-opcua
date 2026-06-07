# Phase 0: Research & Clarifications

## Decision 1: QueryFirst Implementation (Complex Joining)
**Decision**: Implement a graph traversal iterator that leverages existing reference maps, executing complex joins dynamically during the `QueryFirst` execution.
**Rationale**: We need to support complex relationship joining. Since the nodes are likely stored in memory/sqlite, an iterator over the references allows following paths to match related nodes according to the OPC UA Query filter without loading everything into memory.
**Alternatives considered**: Pre-calculating indexes for all relations (rejected: too memory-intensive).

## Decision 2: Tarpitting for Auth Failures
**Decision**: Use a non-blocking `tokio::time::sleep` before returning `BadUserAccessDenied` on auth failure.
**Rationale**: `tokio::time::sleep` does not block the worker thread, ensuring the server remains responsive to other clients while effectively tarpitting the attacker.
**Alternatives considered**: IP-based lockout (rejected: complex and brittle behind NATs).

## Decision 3: Time-based Key Rotation
**Decision**: Use a dedicated Tokio background task (`tokio::spawn`) for the `Group Key Server` that periodically publishes new keys to the PubSub groups based on a configured `std::time::Duration`.
**Rationale**: Standard async background task is efficient and fits within the existing async Rust architecture.
**Alternatives considered**: Synchronous polling during message publish (rejected: adds latency to the hot path).
