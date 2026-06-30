# Research: Hot Path Lock Optimization

## Decision 1: Shorten lock scopes before adding concurrency

**Decision**: Implement P1 guard-scope reductions before adding request worker fanout, SPSC routing, or snapshot publication.

**Rationale**: The audit found that user callbacks, sampler callbacks, sampling closures, and actor queue pushes execute while internal guards are live. More worker tasks would increase pressure on those same guarded sections. OPC-10000-4 4.1 identifies Read, Write, and Call as normal service surfaces, so public service results must remain stable while internal guard lifetimes shrink.

**Alternatives considered**:

- Replace synchronous locks with async locks. Rejected because the main risk is arbitrary work under guards, not blocking a Tokio worker across `.await`.
- Add processing threads first. Rejected because it can increase contention before the guarded callback/fanout work is removed.

## Decision 2: Preserve OPC UA service semantics while moving server callbacks

**Decision**: Server Read, Write, and Call tasks will clone callback handles and immutable request/node metadata under lock, release guards, then invoke callbacks.

**Rationale**: OPC-10000-4 4.1 places Read/Write in the Attribute Service Set and Call in the Method Service Set. The refactor is internal and must preserve request results, per-node statuses, method outputs, and diagnostics. The callback registry and address-space/type-tree guards protect lookup consistency, but they do not need to cover arbitrary callback execution once required handles and metadata are captured.

**Alternatives considered**:

- Invoke callbacks through an actor immediately. Rejected for P1 because it changes execution ordering and error propagation more than needed.
- Keep locks and document callback restrictions. Rejected because arbitrary user extension callbacks are a known deadlock and throughput risk.

## Decision 3: Split client Publish handling into state mutation and delivery

**Decision**: Client Publish handling will update acknowledgements and subscription state under `subscription_state`, produce delivery packets or immutable callback views, then invoke user callbacks after unlock.

**Rationale**: OPC-10000-4 5.14.5 defines Publish acknowledgement handling, and 5.14.1 defines Subscription notification message behavior. The mutex protects client-side subscription state and acknowledgement bookkeeping, but user callback delivery does not need to hold the mutex if it receives a stable delivery view.

**Alternatives considered**:

- Clone the whole subscription state for callbacks. Rejected because it risks excessive allocation and stale data beyond the callback contract.
- Push callbacks to an unbounded queue. Rejected because backpressure must be explicit for high-rate Publish traffic.

## Decision 4: Treat `SyncSampler` as a two-phase timer path

**Decision**: `SyncSampler` will identify due sampler entries and update scheduling state under its mutex, then perform sampler callback execution and subscription notification after releasing the mutex.

**Rationale**: OPC-10000-4 5.13.1.2 defines sampling interval behavior, and 5.13.1.5 defines monitored-item queueing. The sampler mutex needs to protect sampler registration and timing state. It does not need to protect slow callback execution or downstream fanout as long as due/not-due decisions and `last_sample` updates stay coherent.

**Alternatives considered**:

- Actorize every sampler immediately. Rejected because the smaller two-phase refactor addresses the P1 risk with lower behavioral blast radius.
- Hold the mutex but spawn notification work. Rejected because the sampler callback itself can be slow or re-entrant.

## Decision 5: Snapshot subscription routes before sampling and fanout

**Decision**: Subscription notification paths will snapshot matching monitored-item routes under the cache guard, then release the guard before sample closures and per-session actor queue pushes.

**Rationale**: OPC-10000-4 5.13.2 through 5.13.6 define create, modify, monitoring mode, and delete behavior for MonitoredItems. OPC-10000-4 5.14.1 defines Subscription notification packaging and retransmission sequence behavior. Route snapshots must make races explicit: a notification already in flight can still be delivered after a modify/delete boundary when current code and the standard allow it, but new route lookup must not hold the global guard across slow sampling or actor enqueue.

**Alternatives considered**:

- Replace the global cache with a concurrent map in the first slice. Rejected because the immediate problem is guard lifetime, not the map implementation.
- Drop notifications on route changes. Rejected because it would alter subscription queue/retransmission semantics.

## Decision 6: Keep Session and SecureChannel security boundaries intact

**Decision**: Session dispatch and CreateSession tasks will only narrow lock scopes after collecting the exact state needed for validation or commit. Secure-channel renewal changes are measurement gated.

**Rationale**: OPC-10000-4 5.7.2 ties CreateSession to SecureChannel context and client certificate continuity. OPC-10000-4 7.32 and 7.35 define authentication token use with Session and SecureChannel/client-certificate context. OPC-10000-6 6.7.2.4 and 6.7.7 require ordered SecureChannel sequence handling and verification before interpretation. These rules make security boundary removal unacceptable; only lock lifetime reduction is allowed.

**Alternatives considered**:

- Move all session validation outside locks without a snapshot/re-check. Rejected because session closure, activation, token, and transfer state can change concurrently.
- Replace renewal single-flight immediately. Rejected until measurement shows the async mutex is a throughput problem.

## Decision 7: Defer versioned snapshots and SPSC lanes behind measurement

**Decision**: Versioned immutable snapshots and SPSC lanes remain P3 follow-ups until after the P1 lock-scope fixes and one before/after measurement.

**Rationale**: The audit identified plausible snapshot candidates such as type-tree metadata and subscription route indexes. However, raw seqlocks are not appropriate for complex Rust-owned data. If pursued, readers should load immutable `Arc` snapshots and writers should publish complete new versions. Queue lanes must be bounded because subscription and PubSub traffic can be high-rate.

**Alternatives considered**:

- Use raw seqlocks. Rejected because readers could observe partially-mutated complex data without unsafe-heavy guarantees.
- Add unbounded SPSC/MPMC queues. Rejected because resource bounds are part of the repository constitution and OPC UA server robustness expectations.

## Decision 8: Task generation must stay atomic

**Decision**: `/speckit-tasks` must generate one task per lock-boundary proof. Larger items should be split with suffixes such as T005a/T005b/T005c.

**Rationale**: The constitution requires individual task discipline. Lock-scope work is easy to over-batch because multiple paths look similar, but server callbacks, client callbacks, sampler work, and notification fanout have different invariants and tests.

**Alternatives considered**:

- Group by crate. Rejected because `async-opcua-server` contains several unrelated guard boundaries.
- Group by priority only. Rejected because all P1 work is not interchangeable; each path has different OPC UA behavior to preserve.
