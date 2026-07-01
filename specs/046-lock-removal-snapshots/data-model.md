# Data Model: Lock Removal and Snapshot Concurrency

## TypeTreeSnapshot

**Purpose**: Immutable OPC UA type metadata view used by service hot paths.

**Key attributes**:

- `version`: Monotonic publication version for tests, tracing, and debugging.
- `metadata`: Complete type tree view for the published server state.
- `source`: Default server initialization, custom getter adapter, or test fixture.

**Relationships**:

- Published by `SnapshotPublication`.
- Read by Browse, Query, Read, subscription, and type helper paths.

**Validation rules**:

- A snapshot must be complete before publication.
- Readers must not observe partially updated metadata.
- Snapshot publication must not change externally visible OPC UA service results.

## SnapshotPublication

**Purpose**: Atomic handoff from a builder/mutator path to read-only service paths.

**Key attributes**:

- `previous_version`: Version visible before publication.
- `next_version`: Version visible after publication.
- `published_at`: Trace/debug timestamp if existing tracing supports it.

**State transitions**:

1. `Building`: Metadata is mutable and not yet visible to hot-path readers.
2. `Ready`: Metadata is complete and can be published.
3. `Published`: Readers can atomically acquire the new immutable view.

## ResponseLimitState

**Purpose**: Per-channel response-size enforcement state derived from negotiated message settings.

**Key attributes**:

- `channel_id`: SecureChannel or transport owner identity.
- `max_response_message_size`: Negotiated client limit; zero means no advertised limit.
- `effective_limit`: Internal normalized representation used by checks.

**Validation rules**:

- One channel must not read or apply another channel's limit.
- `BadResponseTooLarge` behavior must match the existing implementation.
- State is removed or becomes unreachable when the channel closes.

## RouteIndexSnapshot

**Purpose**: Optional immutable subscription route index for notification fanout after measurement justifies it.

**Key attributes**:

- `version`: Route publication version.
- `subscriptions`: Mapping from source/event/value ownership to subscription delivery targets.
- `monitored_items`: Monitored item membership and delivery metadata.

**Validation rules**:

- Deletions and transfers must publish complete replacement views.
- Publish responses must not include notifications for deleted monitored items after the deletion is visible.
- Transfer and republish behavior must remain protocol-compatible.

## LockRemovalSlice

**Purpose**: Independently reviewable unit of work for one lock boundary.

**Key attributes**:

- `boundary`: TypeTree, response-size, subscription route, PubSub, SQLite history, or SecureChannel renewal.
- `priority`: P1, P2, or P3 from the spec.
- `baseline`: Required measurement or proof before implementation.
- `tests`: Expected-red proof tests and regression tests.
- `rollback`: Files and behavior that can be reverted without affecting other slices.

**Validation rules**:

- A slice cannot start implementation until its required baseline/proof exists.
- A slice cannot complete until its verification gate passes.

## VerificationGate

**Purpose**: Evidence that a slice preserves performance, functionality, and OPC UA fidelity.

**Key attributes**:

- `expected_red_tests`: Tests that fail before implementation.
- `regression_tests`: Existing or new tests that prove behavior is unchanged.
- `benchmark_samples`: Before/after measurements where performance is relevant.
- `static_checks`: Formatting, clippy, and lock-specific checks.

**Validation rules**:

- Expected-red tests must be recorded before code changes for the slice.
- Any skipped workspace-wide check must have a documented reason and targeted substitute.
