# Research: Lock Removal and Snapshot Concurrency

## Decision 1: Make TypeTree snapshots the MVP

**Decision**: Replace hot-path TypeTree reads that currently depend on `Arc<RwLock<DefaultTypeTree>>` with an immutable published snapshot API.

**Rationale**: The TypeTree is read-mostly after startup, appears in service paths, and has a contained semantic surface compared with session, SecureChannel, or address-space structure locks. The audit identified it as the best first target for lock removal.

**Alternatives considered**:

- Keep the lock and only narrow guard scopes. Rejected because the hot path still pays read-lock contention under fanout.
- Convert the entire address-space graph to versioned snapshots first. Rejected for MVP because structural mutations, references, and node lifecycle semantics are broader and riskier.

## Decision 2: Publish complete immutable views atomically

**Decision**: Readers should see either the previous complete type metadata view or the next complete view. Publication may use `ArcSwap` or an equivalent established atomic `Arc` snapshot mechanism.

**Rationale**: OPC UA service calls need internally consistent type metadata. Atomic publication keeps reader paths short without exposing partially built state.

**Alternatives considered**:

- Raw seqlocks or custom unsafe lock-free structures. Rejected because correctness burden is too high for this protocol surface.
- Clone on every read. Rejected because it preserves correctness but harms performance.

## Decision 3: Keep custom type-tree getter behavior explicit

**Decision**: The implementation must preserve existing custom getter behavior or introduce an explicit compatibility adapter/migration path.

**Rationale**: The current API exposes type-tree access customization. Removing locks must not silently remove caller-defined semantics.

**Alternatives considered**:

- Drop dynamic getter support. Rejected as a compatibility break outside this feature's scope.
- Keep the old lock only for custom getters. Possible fallback, but it must be documented and isolated so default hot paths are still lock-free.

## Decision 4: Move response-size limit state out of the global map

**Decision**: The P2 response-size slice should model negotiated response limits as per-channel state or another hot-path lock-free owner.

**Rationale**: Response-size checks are channel-specific. A global map lock creates avoidable cross-channel contention and has a narrow behavior surface for regression tests.

**Alternatives considered**:

- Continue using the global map. Rejected for the optimization slice because it keeps unnecessary shared contention.
- Use a global concurrent map. Lower risk than a mutex but still leaves global state for channel-local behavior.

## Decision 5: Gate subscription route snapshots by measurement

**Decision**: Do not immediately replace subscription route locks. First record contention or fanout evidence, then introduce an immutable route-index snapshot if justified.

**Rationale**: Subscription routes must preserve monitored item lifecycle, deletion, transfer, and Publish behavior. The risk is higher than TypeTree snapshots.

**Alternatives considered**:

- Convert route cache in the MVP. Rejected because it would expand review and test scope before the TypeTree slice proves the snapshot pattern.

## Decision 6: Keep SecureChannel renewal mutex until proven hot

**Decision**: Do not remove the SecureChannel renewal mutex without a focused measurement and a state-machine design.

**Rationale**: SecureChannel renewal is security-sensitive and ordering-sensitive under OPC UA Part 6. A mutex is acceptable if it prevents duplicate renewal and preserves token ordering.

**Alternatives considered**:

- Replace immediately with `Notify` or a shared future. Rejected until profiling shows contention and tests cover cancellation/failure ordering.

## Decision 7: Treat PubSub and SQLite as separate follow-up slices

**Decision**: PubSub config/cache locks and SQLite history locking remain separate P3 slices with their own baselines and tests.

**Rationale**: PubSub touches Part 14 configuration consistency and transport cache behavior. SQLite history may be correct for a reference backend and only needs an actor/read-pool design if history benchmarks show lock contention.

**Alternatives considered**:

- Rewrite both as part of the TypeTree work. Rejected because their correctness boundaries and performance evidence are independent.
