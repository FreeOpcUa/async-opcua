# Feature Specification: Lock Removal and Snapshot Concurrency

**Feature Branch**: `046-lock-removal-snapshots`  
**Created**: 2026-06-30  
**Status**: Draft  
**Input**: User description: "Set up a Spec Kit workflow to implement the lock-audit suggested changes."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Type Metadata Reads Avoid Hot Locks (Priority: P1)

As an async-opcua server operator, I want read-mostly type metadata to be available through immutable snapshots so high-frequency Browse, Query, Read, and subscription paths do not contend on the global type-tree lock while producing the same service results.

**Why this priority**: The type-tree lock is the clearest read-mostly hot-path lock from the audit and has the best performance-to-risk ratio for an initial implementation.

**Independent Test**: Can be tested by converting only the type metadata access path, then running focused Browse, Query, Read, subscription, and type-loading tests plus a proof test that hot-path readers use the published snapshot rather than a global `RwLock` guard.

**Acceptance Scenarios**:

1. **Given** a server with the default address space and type metadata, **When** Browse, Query, Read, or subscription evaluation needs type information, **Then** it reads a consistent published snapshot without acquiring the global type-tree `RwLock`.
2. **Given** type metadata is initialized or extended during server setup, **When** the snapshot is published, **Then** subsequent service calls observe the updated metadata with the same OPC UA status codes and references as before.
3. **Given** a caller supplies a custom type tree getter, **When** the server context is built, **Then** existing custom behavior is preserved or the caller receives a documented compatibility path.

---

### User Story 2 - Response Size Enforcement Avoids Global Contention (Priority: P2)

As a client and server implementer, I want maximum response size checks to avoid a process-wide map lock so concurrent channels can enforce `maxResponseMessageSize` independently without changing protocol behavior.

**Why this priority**: The response-size lock is small but global. Removing it reduces cross-channel contention while preserving a narrow, testable Part 4 and Part 6 behavior surface.

**Independent Test**: Can be tested by changing only response-size state ownership, then verifying `maxResponseMessageSize`, zero-limit handling, and `BadResponseTooLarge` behavior across concurrent channels.

**Acceptance Scenarios**:

1. **Given** a client advertises a nonzero maximum response size, **When** the server prepares a response larger than that limit, **Then** the response is rejected with the same status behavior as the current implementation.
2. **Given** multiple channels have different response-size limits, **When** they process responses concurrently, **Then** each channel enforces only its own negotiated limit without reading a shared global lock.

---

### User Story 3 - Riskier Lock Removals Are Measurement-Gated (Priority: P3)

As a maintainer, I want subscription routing, PubSub configuration, SQLite history, and SecureChannel renewal changes broken into measured slices so the project removes locks only where contention is proven and OPC UA fidelity can be demonstrated.

**Why this priority**: These areas carry higher semantic risk. The workflow should prevent speculative lock-free rewrites that could break ordering, continuation, publication, or security semantics.

**Independent Test**: Can be tested by completing the measurement and expected-red proof task for each lock boundary before any implementation task for that boundary begins.

**Acceptance Scenarios**:

1. **Given** subscription fanout shows route-cache contention, **When** a route-index snapshot slice is implemented, **Then** monitored item creation, deletion, transfer, and Publish notifications remain externally unchanged.
2. **Given** PubSub configuration updates are modified, **When** reflected methods and transport caches observe changes, **Then** Part 14 configuration consistency and transport behavior are preserved.
3. **Given** SecureChannel renewal is considered for change, **When** no contention measurement justifies it, **Then** the existing mutex remains in place.

### Edge Cases

- Type metadata is extended during startup while a server context is already being constructed.
- A custom type tree getter exposes dynamic behavior that cannot be represented as a static snapshot.
- Browse or Query runs concurrently with snapshot publication and must see either the old complete snapshot or the new complete snapshot.
- A client advertises `maxResponseMessageSize` as zero, meaning no advertised limit, while another channel has a strict nonzero limit.
- Subscription monitored items are deleted, transferred, or modified while a route snapshot is being rebuilt.
- PubSub reflected configuration methods race with transport cache updates.
- SQLite history queries use continuation points while writes are still occurring.
- SecureChannel renewal fails or is cancelled while another request is waiting for a valid channel.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The implementation MUST remove hot-path type metadata read locking by publishing immutable type-tree snapshots for normal service reads.
- **FR-002**: The implementation MUST preserve OPC UA service behavior, status codes, namespace/type relationships, references, and access semantics for Browse, Query, Read, Write, subscription, and type-related operations affected by the snapshot path.
- **FR-003**: The implementation MUST include tests that fail before the TypeTree snapshot change and pass after it, including a proof that hot-path readers do not acquire the global type-tree `RwLock`.
- **FR-004**: The implementation MUST keep custom type tree getter compatibility explicit through existing APIs or a documented migration path.
- **FR-005**: Response size enforcement MUST be represented as channel-local or otherwise lock-free-per-hot-path state while preserving negotiated `maxResponseMessageSize` and `BadResponseTooLarge` behavior.
- **FR-006**: Subscription route, PubSub, SQLite history, and SecureChannel renewal lock removals MUST each have a baseline measurement or contention proof before implementation begins.
- **FR-007**: The workflow MUST NOT introduce raw seqlocks, unchecked custom unsafe lock-free data structures, or relaxed memory ordering without a documented correctness proof.
- **FR-008**: Existing locks for sessions, security token ownership, certificate stores, per-session actors, notification rings, and SecureChannel send ownership MUST remain unless a later task adds focused measurements and OPC UA conformance tests for that exact boundary.
- **FR-009**: Each lock-removal slice MUST be independently reviewable, testable, and reversible without depending on later lower-priority slices.
- **FR-010**: Final verification MUST run formatting, workspace tests or documented targeted substitutes, and clippy with `await_holding_lock` and `await_holding_refcell_ref` warnings enabled.

### Key Entities

- **TypeTreeSnapshot**: Immutable view of OPC UA type metadata used by service hot paths.
- **SnapshotPublication**: Versioned publication event that makes a complete snapshot visible to readers atomically.
- **ResponseLimitState**: Per-channel response-size limit state derived from negotiated message settings.
- **RouteIndexSnapshot**: Optional future immutable subscription route index used for notification fanout after measurement justifies it.
- **LockRemovalSlice**: Independently planned unit of work for one lock boundary with its own tests, implementation, and verification gate.
- **VerificationGate**: Evidence required before or after a slice, such as expected-red tests, baseline benchmarks, conformance tests, and clippy checks.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Focused tests demonstrate TypeTree hot-path reads no longer acquire the global type-tree `RwLock`.
- **SC-002**: Existing Browse, Query, Read, Write, subscription, and type metadata tests pass with unchanged externally visible OPC UA behavior.
- **SC-003**: `cargo clippy --workspace --all-targets --all-features --locked -- -W clippy::await_holding_lock -W clippy::await_holding_refcell_ref` completes without findings introduced by this work.
- **SC-004**: The TypeTree snapshot slice records at least three before/after controlled localhost Read and Write benchmark samples; the slice passes if median throughput does not drop by more than 5% for either operation, or if the slice notes document measurement noise and a maintainer-approved rationale for accepting the result.
- **SC-005**: Every P2/P3 lock boundary has a written baseline/proof gate before its implementation tasks are marked complete.

## Assumptions

- The first implementation increment is the TypeTree snapshot conversion; broader address-space structural snapshots are out of scope for the MVP.
- Rust 1.75+ and the existing workspace dependency policy remain in effect.
- Adding a small, established dependency such as `arc-swap` is acceptable only if it is not already available through the workspace and the plan records why it is needed.
- Changes that could affect OPC UA conformance are validated with existing service tests plus focused regression tests added by this feature.
- The Spec Kit workflow sets up the plan and tasks but does not implement the code changes until the implementation phase begins.
