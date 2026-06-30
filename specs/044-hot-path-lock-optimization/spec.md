# Feature Specification: Hot Path Lock Optimization

**Feature Branch**: `[240-hot-path-lock-audit]`
**Created**: 2026-06-30
**Status**: Draft
**Input**: User description: "Have an architect-review of the hot path lock audit report to make an implementation spec. spec-to-code-compliance should help in this effort too."

## Source Material

- Audit report: [docs/HOT_PATH_LOCK_AUDIT_2026-06-30.md](../../docs/HOT_PATH_LOCK_AUDIT_2026-06-30.md)
- Scoped compliance trace: [contracts/lock-optimization-traceability.md](./contracts/lock-optimization-traceability.md)
- Current Speckit project context: [specs/038-statuscode-test-matrix/plan.md](../038-statuscode-test-matrix/plan.md)

This specification converts the lock audit into implementation requirements. It does not assert that every lock is wrong. The architectural target is to remove user code, sampling work, and notification fanout from live internal guards while preserving OPC UA protocol invariants.

## Architectural Review Summary

### Architectural Impact: Medium-High

The affected paths sit on server Read, Write, Call, Publish/notification, sampled monitored items, client Publish delivery, session dispatch, CreateSession, and secure-channel renewal. These are high-traffic paths, but many existing locks protect real invariants. A blanket migration from synchronous locks to async locks is out of scope and would likely increase complexity without addressing the main risk.

### Design Direction

1. Shorten lock scopes before adding new concurrency.
2. Move arbitrary callback execution and fanout work outside internal guards.
3. Preserve single-owner ordered state for each SecureChannel writer.
4. Preserve session activation, certificate validation, and address-space structural mutation boundaries.
5. Use SPSC/actor lanes only where a lock currently protects ownership handoff or route fanout.
6. Prefer versioned immutable `Arc` snapshots for read-mostly metadata; do not use raw seqlocks over complex Rust-owned structures.

### Architecture Boundaries To Preserve

- SecureChannel send state remains single-writer and ordered.
- Session activation/security state remains guarded with re-checks around authentication and channel transfer semantics.
- Address-space structural writes remain protected by graph/type invariant boundaries.
- Certificate stores and SQLite history storage remain serialized where required by external resources.
- Existing subscription actors, bounded rings, and per-session routing concepts remain the foundation for notification delivery.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Invoke Server Extension Callbacks Outside Internal Locks (Priority: P1)

As a server integrator, I need Read, Write, and Call callbacks to run without address-space, type-tree, or callback-registry guards held so that callback code can safely perform normal server operations without self-deadlocking or extending hot lock hold time.

**Why this priority**: These callbacks are arbitrary user extension code on Read, Write, and Call hot paths. The audit found callback invocation while internal guards are live in `simple.rs` and `core.rs`.

**Independent Test**: Register callbacks that re-enter safe node-manager operations or intentionally block behind another operation. Verify the request completes and no callback is invoked while the relevant internal guard remains held.

**Acceptance Scenarios**:

1. **Given** a Read callback is registered for a node, **When** a Read request reaches that callback, **Then** the callback handle and required metadata are captured under locks and the callback is invoked only after those locks are released.
2. **Given** a Write callback is registered for a node, **When** a Write request reaches that callback, **Then** type-tree and callback-registry guards are not live during callback execution.
3. **Given** method callbacks are registered, **When** a Call request invokes them, **Then** callback registry guards are released before user callback code runs.
4. **Given** a callback returns a status or output value, **When** lock scope is reduced, **Then** public request status and output behavior remain unchanged.

---

### User Story 2 - Deliver Client Subscription Callbacks Outside `subscription_state` (Priority: P1)

As a client integrator, I need subscription notification callbacks to run after the client subscription-state mutex is released so that callback code can call client APIs or perform slower work without blocking Publish response processing.

**Why this priority**: Publish handling currently locks `subscription_state`, routes into notification handling, and invokes user callbacks through subscription callback objects.

**Independent Test**: Configure a subscription callback that calls back into subscription APIs or waits on another task requiring subscription state. A Publish response must be processed without deadlock and acknowledgements must still be queued correctly.

**Acceptance Scenarios**:

1. **Given** a Publish response with notification data, **When** the client handles it, **Then** acknowledgement state is updated under the mutex and delivery packets are produced before the mutex is released.
2. **Given** delivery packets are produced, **When** user callbacks are invoked, **Then** callback delivery occurs outside `subscription_state`.
3. **Given** monitored-item maps and client handles are exposed to callbacks, **When** callback delivery is moved outside the mutex, **Then** the callback receives a stable snapshot or equivalent immutable view.
4. **Given** `PreInsertMonitoredItems` ordering semantics, **When** callbacks are moved, **Then** existing ordering/race semantics are preserved.

---

### User Story 3 - Decouple Sampling And Notification Fanout From Global Guards (Priority: P1)

As a server operator, I need sampled monitored item and data-change notification processing to avoid holding sampler-map or subscription-cache guards during slow sampling, route fanout, or actor queue pushes.

**Why this priority**: Timer-driven sampling and data-change fanout are throughput-critical. Current code holds sampler or subscription cache guards while executing sampler callbacks, sample closures, and fanout into session actors.

**Independent Test**: Run sampling or data-change fanout with a slow sampler or many subscriptions while concurrently adding, updating, or removing samplers/subscriptions. Management operations must not be blocked by slow callback/fanout work beyond bounded snapshot time.

**Acceptance Scenarios**:

1. **Given** due samplers exist, **When** `SyncSampler` ticks, **Then** it identifies due work under the sampler lock and invokes sampler callbacks after releasing that lock.
2. **Given** sampled values are produced, **When** values are notified to subscriptions, **Then** notification fanout does not depend on the sampler-map guard lifetime.
3. **Given** a data-change notification is emitted, **When** subscription routes are found, **Then** matching routes are snapped under the cache guard and actor queue pushes happen after that guard is released.
4. **Given** no monitored items match a data-change source, **When** snapshot routing is used, **Then** the fast no-match path remains cheap and allocation-light.

---

### User Story 4 - Narrow Session And Connection Control Locks Safely (Priority: P2)

As a library maintainer, I need request dispatch, CreateSession, and secure-channel renewal locks to hold only the state that requires mutual exclusion so that high concurrency does not serialize behind avoidable work.

**Why this priority**: These paths are not the first correctness risk, but they run frequently or cover expensive operations. Some lock scopes are broader than necessary.

**Independent Test**: Add request-concurrency tests and benchmarks around normal request dispatch, CreateSession, and renewal. Behavior and public statuses must remain unchanged while lock hold time shrinks or is explicitly measured.

**Acceptance Scenarios**:

1. **Given** a normal session-scoped request, **When** dispatch looks up session state and actor sender, **Then** the `SessionManager` read guard is released before validation, audit-context setup, and message dispatch.
2. **Given** CreateSession receives a valid request, **When** certificate validation, endpoint construction, signatures, actor spawn, and allocation are performed, **Then** only the limit check and commit steps that require manager exclusivity remain under the manager write lock.
3. **Given** secure-channel renewal is already single-flight, **When** multiple requests need renewal, **Then** measurement is added before changing the `tokio::sync::Mutex` design.
4. **Given** renewal is later changed, **When** waiters observe a renewal in progress, **Then** they wait outside the renewal state lock through a `Notify`, shared future, or equivalent single-flight primitive.

---

### User Story 5 - Prepare Measured Snapshot And Queue Follow-Ups (Priority: P3)

As a performance maintainer, I need future SPSC and snapshot changes to be grounded in measurements and ownership boundaries so that larger concurrency changes do not weaken protocol correctness.

**Why this priority**: Queue and snapshot patterns are promising, but they should follow the P1 lock-scope fixes and benchmarks.

**Independent Test**: Prototype one route-index or type-tree snapshot behind benchmarks and stale-snapshot race tests before any broad address-space or connection-pipeline rewrite.

**Acceptance Scenarios**:

1. **Given** read-mostly type/reference metadata, **When** a snapshot design is selected, **Then** readers load immutable `Arc` snapshots and writers publish a new version after mutation completes.
2. **Given** subscription route indexes are hot, **When** route snapshots are implemented, **Then** create/delete/modify monitored-item races are covered by stale-version tests.
3. **Given** SPSC lanes are introduced, **When** producers outpace consumers, **Then** queues are bounded and backpressure/drop behavior is explicit.
4. **Given** a connection processing pipeline is introduced, **When** request handling fans out, **Then** each SecureChannel still has a single ordered response writer.

### Edge Cases

- User callbacks may re-enter read, write, browse, method registration, or subscription APIs.
- Callback registries may be modified concurrently with callback invocation.
- Slow or panicking callbacks must not poison internal lock state or permanently block unrelated requests.
- Subscription notifications may arrive while monitored items are being created, modified, disabled, or deleted.
- A publish callback may call back into subscription management APIs.
- Sampler add/update/remove may race with a timer tick.
- CreateSession limit checks must be re-checked at commit time after outside-lock work.
- Secure-channel renewal must preserve sequence, token, close-on-failure, and single-flight semantics.
- Address-space structural snapshots must not expose partially-mutated graph/type metadata.
- Startup-only lock-across-await waivers remain outside this feature unless a task directly touches those paths.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Server Read callback execution MUST occur after releasing address-space and read-callback registry guards.
- **FR-002**: Server Write callback execution MUST occur after releasing address-space, type-tree, and write-callback registry guards, while preserving existing write status behavior.
- **FR-003**: Server method callback execution MUST occur after releasing method callback registry guards in both simple and context-aware in-memory manager paths.
- **FR-004**: Callback invocation refactors MUST capture only the callback handles and immutable request/node metadata required to preserve current behavior.
- **FR-005**: Client Publish handling MUST update acknowledgement and subscription state under `subscription_state`, then invoke user callbacks after releasing `subscription_state`.
- **FR-006**: Client callback delivery MUST provide stable monitored-item/client-handle views that do not require the subscription-state mutex to remain held.
- **FR-007**: `SyncSampler` MUST not execute sampler callbacks or subscription notification fanout while holding the sampler-map mutex.
- **FR-008**: Subscription data-change and event fanout MUST snapshot matching route information under the subscription-cache guard and release that guard before sampling closures or actor queue pushes.
- **FR-009**: Normal session request dispatch MUST scope the `SessionManager` read guard to lookup-only data collection before validation and dispatch.
- **FR-010**: CreateSession refactoring MUST split outside-lock validation/crypto/construction from short locked commit steps and MUST re-check session limits during commit.
- **FR-011**: Secure-channel renewal changes MUST be preceded by measurement. If changed, renewal waiters MUST await outside the lock while preserving single-flight behavior.
- **FR-012**: PubSub and certificate-store cleanup tasks MUST replace write locks with read locks only where code evidence shows no mutation occurs.
- **FR-013**: Trace-lock instrumentation MAY be changed only if trace mode remains diagnostically useful and normal operation remains unaffected.
- **FR-014**: Any SPSC queue introduced by this feature MUST be bounded or explicitly backpressured.
- **FR-015**: Any snapshot design introduced by this feature MUST publish immutable versioned data and MUST avoid raw seqlock-style unsafely shared mutation over complex Rust-owned structures.
- **FR-016**: The implementation MUST NOT introduce new lock guards held across `.await` in hot request, notification, sampler, or callback paths.
- **FR-017**: Every behavior-changing task MUST include a regression test that proves callbacks, sampling, fanout, or dispatch occur outside the targeted guard.
- **FR-018**: Every performance-motivated task MUST include either a benchmark/measurement or a documented reason why the task is a correctness risk rather than a measured throughput change.

### Non-Functional Requirements

- **NFR-001**: Public OPC UA request statuses, ordering, and side effects MUST remain unchanged unless a later spec-grounded conformance task explicitly changes them.
- **NFR-002**: Lock-scope reduction MUST favor local refactors over broad concurrency rewrites.
- **NFR-003**: Added snapshots, delivery packets, or route batches MUST avoid unbounded allocation on high-cardinality subscription paths.
- **NFR-004**: Queue and actor changes MUST expose backpressure behavior in tests.
- **NFR-005**: Larger address-space/type-tree snapshot work MUST be gated by benchmarks after P1 lock-scope fixes land.

### Explicit Non-Goals

- Replacing all synchronous locks with async locks.
- Removing session activation/security locks.
- Removing address-space structural write locks.
- Rewriting the whole address space around RCU/snapshots in the first implementation slice.
- Building a full multi-threaded connection pipeline before callback and fanout lock scopes are fixed.
- Changing SQLite history serialization or certificate trust-store semantics.

### Key Entities

- **Callback Handle Snapshot**: An owned or reference-counted callback handle plus immutable metadata captured under lock and invoked after unlock.
- **Client Delivery Packet**: A notification payload, acknowledgement outcome, and stable monitored-item view produced under `subscription_state` for later callback delivery.
- **Sampler Work Item**: A due sampler descriptor captured under the sampler lock and executed after the lock is released.
- **Notification Route Snapshot**: A stable list of session/subscription/monitored-item routing targets captured under the subscription-cache guard.
- **Versioned Metadata Snapshot**: An immutable `Arc`-published view of read-mostly metadata such as type-tree, reference classification, or route indexes.
- **Single-Owner Writer Lane**: The queue/actor boundary that serializes outbound SecureChannel writes and preserves protocol ordering.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Tests prove server Read, Write, and Call callbacks can re-enter safe APIs without deadlocking on the refactored locks.
- **SC-002**: Tests prove client subscription callbacks are not invoked while `subscription_state` is held.
- **SC-003**: Tests prove `SyncSampler` add/update/remove operations are not blocked by slow sampler callback execution while the sampler mutex is held.
- **SC-004**: Tests prove subscription route lookup and actor queue push do not keep the global subscription-cache guard live across sampling/fanout work.
- **SC-005**: Request-dispatch tests and/or lock tracing show the `SessionManager` read guard is released before normal request validation and dispatch.
- **SC-006**: CreateSession tests preserve current public statuses for limit, certificate, endpoint, and allocation failures after lock-scope reduction.
- **SC-007**: Existing workspace tests and targeted crate tests pass for every implementation slice.
- **SC-008**: At least one before/after measurement is recorded before any P3 queue/snapshot expansion beyond local lock-scope refactors.

## Implementation Order

1. Server in-memory Read/Write/Call callback lock-scope refactors.
2. Client subscription Publish delivery split into state mutation plus post-unlock callback delivery.
3. `SyncSampler` work collection and post-unlock sampling/notification.
4. Subscription notification route snapshot and post-unlock actor enqueue.
5. `SessionManager` request-dispatch read-guard narrowing.
6. CreateSession two-phase refactor with commit-time re-checks.
7. Small read/write lock mode cleanups in PubSub and client certificate-store access.
8. Measurement gate for secure-channel renewal and any snapshot/SPSC prototype.

## Assumptions

- The hot path lock audit report is the authoritative scope for this feature.
- This feature optimizes throughput and deadlock risk without changing OPC UA conformance behavior.
- Some current locks are necessary for correctness; tasks must justify each lock-scope change with local evidence.
- The scoped compliance trace is an evidence map for this feature, not a claim of exhaustive repository-wide compliance analysis.
