# async-opcua - Hot Path Lock Audit

**Date:** 2026-06-30
**Branch:** `240-hot-path-lock-audit`
**Scope:** Synchronous lock usage on async hot paths across server request handling, in-memory node
manager access, subscriptions, client subscription delivery, PubSub, and secure-channel transport.
**Method:** Static source audit with targeted `rg` searches, five independent subagent review passes
(async correctness, hot-path contention, architecture ownership, Rust performance idioms, and
contrarian review), plus a one-shot Antigravity query through `agy -p`.

No live profiling or benchmarks were run for the original audit. Findings are ranked by hot-path
position and contention or deadlock risk, not measured wall-clock impact. The follow-up
implementation run used focused proof-test gates and targeted inspection/measurement notes; it did
not perform full throughput profiling.

---

## Executive Summary

The audit does **not** support a blanket rewrite from synchronous locks to async locks. Most
`parking_lot`/sync lock usage is short, synchronous, and not held across `.await`. Several locks are
protecting real OPC UA invariants, especially session activation, certificate validation, address
space structural mutation, and subscription routing indexes.

The real performance and correctness risks cluster around **user code or fanout work executed while
internal locks are live**:

1. Server read/write/method callbacks run while address-space, type-tree, or callback-registry guards
   are held.
2. Client subscription callbacks run while the client subscription-state mutex is held.
3. `SyncSampler` holds its sampler map mutex while executing sampler callbacks and notification
   fanout.
4. Subscription notification helpers hold the global subscription-cache read guard while sampling and
   while routing work to per-session actors.

Before adding broader multi-threaded request processing, shorten these lock scopes. More worker
threads without these fixes can increase contention by piling more tasks onto the same locks.

---

## Implementation Follow-Up Status

The current follow-up feature is
[`specs/046-lock-removal-snapshots/`](../specs/046-lock-removal-snapshots/).
Its append-only evidence log is
[`slice-notes.md`](../specs/046-lock-removal-snapshots/slice-notes.md), and the
completed task ranges are tracked in
[`tasks.md`](../specs/046-lock-removal-snapshots/tasks.md).

Completed implementation slices:

- [Slice 1: TypeTree Snapshot MVP](../specs/046-lock-removal-snapshots/slice-notes.md#slice-1-typetree-snapshot-mvp)
  moved TypeTree hot-path reads to immutable published snapshots. Focused
  evidence includes `cargo test -p async-opcua-server type_tree_snapshot -- --nocapture`
  plus Browse, Query, Read, Write, and subscription regression runs recorded in
  the slice notes. The SC-004 throughput comparison remains inconclusive:
  prior scratch samples from Feature 045 exist, but the current 046 after
  samples were collected with a different build/mode shape and raw comparison
  does not show an improvement. This is snapshot implementation evidence, not a
  full performance claim.
- [Slice 2: Response-Size Limit State](../specs/046-lock-removal-snapshots/slice-notes.md#slice-2-response-size-limit-state)
  moved response-size enforcement from global state to per-`SecureChannel`
  state. Focused evidence includes
  `cargo test -p async-opcua-core --test response_limit_state -- --nocapture`,
  `cargo test -p async-opcua-server max_response_message_size -- --nocapture`,
  and the recorded clippy await-holding-lock check.

Completed P3 evidence gates, with implementation intentionally deferred:

- [Slice 3: Subscription Route Index Snapshot](../specs/046-lock-removal-snapshots/slice-notes.md#slice-3-subscription-route-index-snapshot)
  passed for follow-up planning/evidence via
  `cargo test -p async-opcua-server subscription_route_snapshot -- --nocapture`.
  This does not claim a full route-index snapshot or SPSC ownership refactor.
- [Slice 4: PubSub Configuration and Transport Cache](../specs/046-lock-removal-snapshots/slice-notes.md#slice-4-pubsub-configuration-and-transport-cache)
  passed for follow-up planning/evidence via
  `cargo test -p async-opcua-pubsub config_snapshot_consistency -- --nocapture`.
  This does not claim a PubSub config/cache lock-removal refactor.
- [Slice 5: SQLite History Scaling](../specs/046-lock-removal-snapshots/slice-notes.md#slice-5-sqlite-history-scaling)
  passed for follow-up planning/evidence via
  `cargo test -p async-opcua-history-sqlite history_lock_scaling -- --nocapture`.
  This does not claim a DB actor or read-pool/write-owner implementation.
- [Slice 6: SecureChannel Renewal](../specs/046-lock-removal-snapshots/slice-notes.md#slice-6-securechannel-renewal)
  passed for follow-up planning/evidence via
  `cargo test -p async-opcua-client secure_channel_renewal_singleflight -- --nocapture`.
  This does not claim SecureChannel renewal mutex removal or a single-flight
  renewal state-machine implementation.

The earlier `044-hot-path-lock-optimization` guard-lifetime work remains the
baseline for callback, sampler, subscription fanout, request-dispatch,
CreateSession, certificate-store, and PubSub subscriber-target guard-scope
changes. The 046 feature adds the two completed snapshot/state implementation
slices above and records P3 gates for later, separately scoped implementation
work.

---

## Async Processing and Network Ownership

The server can use multiple processing tasks/threads between the network reader and writer. The safe
shape is:

```text
connection reader -> decode/request dispatch -> worker lanes -> response queue -> connection writer
```

For a single SecureChannel, keep socket writes single-owner. Chunk order, sequence numbers, security
tokens, and outbound framing are connection-local state. The middle stages can fan out, but the final
writer should serialize responses through one queue.

This aligns with pieces already present in the codebase:

- Request handlers spawn async work in `async-opcua-server/src/session/message_handler.rs`.
- Read/Write requests route through a per-session actor in
  `async-opcua-server/src/session/actor.rs`.
- Subscriptions already use per-session actors and bounded rings in
  `async-opcua-server/src/subscriptions/actor.rs`.

---

## SPSC Queue Opportunities

The QuackPLC-style fanned-out SPSC pattern is a good fit where the current lock protects routing or
ownership handoff rather than an invariant-heavy data structure.

### Good Candidates

- **Sampler pipeline:** producer lane per sampler/source, sampler majordomo batches due samples, then
  notification lane. This directly targets `SyncSampler` lock scope.
- **Subscription notification fanout:** notification producers enqueue work to a routing majordomo,
  which fans out to per-session actor SPSC lanes. This can shrink the global subscription-cache guard
  to a route snapshot lookup.
- **Client subscription callbacks:** publish handling can mutate state and produce delivery packets
  under the mutex, then callback delivery runs on a separate lane after unlock.
- **Connection processing:** one connection reader and writer remain single-owner, while request
  processing fans out through per-session or per-service lanes.

### Poor First Candidates

- **Address-space structural mutation:** graph/reference/type invariants still need atomic mutation
  boundaries. Actor ownership is possible, but it would turn hot reads into request/response messages
  unless paired with snapshots.
- **Session activation/security state:** existing lock/recheck patterns protect replay,
  cross-channel transfer, and token semantics.
- **Certificate store and SQLite history:** these are naturally serialized resources; SQLite is
  already handled inside `spawn_blocking`.

---

## Seqlock-Inspired Snapshot Opportunities

Seqlocks are attractive for read-mostly state, but a raw Linux-style seqlock is not a good first fit
for rich Rust data structures such as `AddressSpace`, `DefaultTypeTree`, `NodeId`, `Variant`, `Vec`,
`String`, and `HashMap`. A classic seqlock allows readers to observe data while a writer is mutating
it and then retry if the sequence changed. That model is only straightforward for atomics or plain
copyable data; applying it to complex owned Rust values tends to require unsafe code and careful
handling of torn reads.

The safer shape for this codebase is **seqlock-inspired RCU/versioned immutable snapshots**:

```text
writer lock / writer actor
  build or clone a new immutable snapshot
  increment version
  publish Arc<Snapshot>

reader
  load Arc<Snapshot>
  read without taking a lock
```

This keeps the useful part of seqlocks -- cheap readers and strong serialized writes -- without
exposing readers to partially-mutated structures.

### Strong Candidates

- **Type tree:** very strong candidate. The type tree is read-mostly after startup and is cloned or
  consulted by request and subscription paths. A versioned `Arc<DefaultTypeTree>` or `ArcSwap`-style
  publication would remove read locking from hot browse, method, and subscription delivery paths.
- **Address-space structural metadata:** good candidate if separated from node values. Keep node
  value mutation on existing node-local/DashMap paths, but publish immutable snapshots for
  namespaces, reference-type classification, and read-mostly graph/type metadata.
- **Subscription route index:** good candidate. Notification fanout needs a stable view of
  monitored-item routes. Writers are create/delete/modify operations; readers are frequent
  notifications. A versioned route table could let notifiers load a snapshot and enqueue without
  holding the global cache guard.
- **PubSub runtime configuration views:** plausible where data-plane readers need a stable config
  view and writes are admin/config operations.

### Poor Candidates

- **Session activation/security state:** use the current lock/recheck pattern or actor ownership.
  Optimistic stale snapshots are wrong for nonce, token, replay, and cross-channel checks.
- **SecureChannel send/receive state:** sequence numbers, security tokens, chunking, and socket write
  ownership are ordered mutable protocol state.
- **Hot variable values:** avoid raw seqlocks unless values are moved to immutable `Arc<DataValue>`
  snapshots. The current `DashMap`/node-local mutation shape is safer.
- **SQLite and certificate stores:** these are externally serialized resources and do not benefit
  much from optimistic snapshots.

### Combined Queue + Snapshot Pattern

The queue and snapshot approaches compose well:

```text
update producer SPSC lanes -> majordomo/writer actor -> publish Arc<Snapshot>
readers / notifiers -> load snapshot -> enqueue work without global lock
```

This is the most promising design for subscription routing and read-mostly type/reference metadata:
SPSC lanes move write/update work to one owner, and readers use immutable snapshots.

---

## Findings - Change First

These finding sections preserve the original audit evidence. See
`Implementation Follow-Up Status` for the completed follow-up outcomes and deferred decisions.

### P1 - Server Callbacks Run Under Internal Locks

**Evidence**

- `async-opcua-server/src/node_manager/memory/simple.rs:192` and `:193` hold address-space and
  read-callback map guards before invoking read callbacks later in the read path.
- `async-opcua-server/src/node_manager/memory/simple.rs:303` to `:305` hold address-space,
  type-tree, and write-callback map guards before invoking write callbacks.
- `async-opcua-server/src/node_manager/memory/simple.rs:343` to `:355` invoke method callbacks
  while method callback maps are locked.
- `async-opcua-server/src/node_manager/memory/core.rs:691` to `:693` invokes
  `method_with_context_cbs` callbacks while the registry read guard is held.

**Risk**

User callbacks are arbitrary extension code. A callback that reads, writes, browses, registers
methods, or indirectly notifies subscriptions can self-deadlock, extend hot lock hold time, or block
executor workers. This affects Read, Write, and Call hot paths.

**Recommended fix**

Clone `Arc` callback handles and required node metadata while locked, release guards, then invoke
callbacks. Callback registries are good candidates for copy-on-write snapshots or `ArcSwap` because
registration is rare and invocation is hot.

### P1 - Client Subscription Callbacks Run Under Subscription Mutex

**Evidence**

- `async-opcua-client/src/session/services/subscriptions/service.rs:2367` locks
  `subscription_state`.
- The locked path reaches notification handling in
  `async-opcua-client/src/session/services/subscriptions/state.rs:219`.
- User callbacks are invoked through
  `async-opcua-client/src/session/services/subscriptions/mod.rs:347` and callback implementations in
  `callbacks.rs`.

**Risk**

Client callback code can call back into subscription APIs or do slow work while the subscription-state
mutex is held. This can self-deadlock or stall Publish response processing.

**Recommended fix**

Have state mutation produce delivery packets or monitored-item snapshots under the mutex. Release the
mutex, then invoke callbacks on a separate delivery path, possibly backed by an SPSC lane.

### P1 - `SyncSampler` Holds Mutex Through Sampling and Notification

**Evidence**

- `async-opcua-server/src/node_manager/utils/sync_sampler.rs:181` locks the sampler map.
- `sync_sampler.rs:195` invokes `FnMut` sampler callbacks under that lock.
- `sync_sampler.rs:199` passes a lazy iterator into `subscriptions.notify_data_change(...)`, so
  notification work is also tied to the sampler guard lifetime.

**Risk**

A slow sampler or large notification fanout blocks sampler add/update/remove and occupies a Tokio
worker. This is a timer hot path for sampled monitored items.

**Recommended fix**

Collect due sampler work or sampled values, release the sampler mutex, then notify. Longer term,
split into per-sampler SPSC producer lanes with a sampler majordomo.

### P1 - Subscription Notification Fanout Holds Global Cache Guard

**Evidence**

- `async-opcua-server/src/subscriptions/mod.rs:634` returns a `SubscriptionDataNotifier` holding a
  global cache read guard.
- `mod.rs:675` to `:687` executes the `maybe_notify` sampling closure while that guard is live.
- `async-opcua-server/src/subscriptions/notify.rs:129` to `:140` pushes work to per-session actors
  in the notifier `Drop` path while still carrying the read guard.

**Risk**

The subscription actor/ring architecture is good, but the remaining global read guard is broad.
Sampling closures can take other locks, and drop-time routing can hold the global cache guard across
fanout.

**Recommended fix**

Snapshot matching routes under the cache guard, then release it before sampling and before pushing
work to actor queues. If this remains hot after measurement, shard or replace the reverse
`monitored_items` index with a more read-concurrent structure.

---

## Findings - Shrink or Measure

### P2 - SessionManager Read Guard Is Wider Than Necessary

`async-opcua-server/src/session/controller.rs:786` opens a `SessionManager` read guard for normal
session-scoped requests and keeps it through lookup, validation, audit context setup, and
`handle_message` dispatch.

This is not a guard-across-await issue, but it is on every Read, Write, Browse, Publish, and
subscription request. Scope the guard only around `(session, actor_sender, session_was_closed)`
lookup, then drop it before validation and dispatch.

### P2 - CreateSession Holds Manager Write Lock Around Nontrivial Work

`async-opcua-server/src/session/controller.rs:525` takes the manager write lock and
`SessionManager::create_session` performs certificate validation, endpoint construction, server
signature creation, session allocation, actor spawn, and metrics while the write guard is live
(`async-opcua-server/src/session/manager.rs:399` onward).

Use a two-phase create path where validation and crypto happen outside the manager write lock where
semantics allow, then re-check limits and commit under a short write lock.

### P2 - Secure-Channel Renewal Single-Flight Holds Tokio Mutex Across Network Await

`async-opcua-client/src/transport/channel.rs:195` locks `issue_channel_lock`, then awaits the renew
request at `:209` and can await close at `:212`. This is an async mutex, so it does not block a
worker thread, and the single-flight semantics are intentional. Still, waiters serialize behind
network I/O.

Measure before changing. A more scalable design is a small mutex-protected renewal state plus
`Notify` or a shared renewal future so waiters await outside the lock.

### P2 - Address-Space Read Locks Cover Whole Browse/Query Loops

The in-memory manager wraps `AddressSpace` in `Arc<RwLock<_>>`, while `AddressSpace` already uses
`DashMap` for node storage. Runtime value access often uses the outer read guard plus interior node
mutability, which is much better than the type suggests. However, Browse, Query, and some
monitored-item validation paths hold address-space and type-tree read guards for whole request-sized
loops, for example `async-opcua-server/src/node_manager/memory/mod.rs:861` and `:939`.

Treat the outer `RwLock` as the structural graph lock. Do not remove it blindly; first narrow hot
value paths and notification fanout. Move toward snapshots or RCU for read-mostly type/reference
metadata only after measurement. If this is pursued, prefer versioned immutable snapshots over raw
seqlocks.

### P2 - PubSub Read-Only Work Uses Write Locks in Some Paths

The Rust-idiom and contrarian passes flagged low-risk PubSub cleanup:

- `async-opcua-pubsub/src/subscriber.rs:312` to `:320` uses an address-space write lock for
  read-only validation before reacquiring a write lock for mutation.
- MQTT/TSN publisher paths hold address-space read guards wider than AMQP/WebSocket/UDP equivalents.

These are good small cleanup tasks after the P1 server/client callback work.

### P3 - Lock Trace Macros Do Post-Acquire Work While Guard Is Live

`async-opcua-core/src/lib.rs:174`, `:200`, and `:226` acquire the lock and then emit the
"lock completed" trace while the guard is already held. This is gated by `OPCUA_TRACE_LOCKS`, so it
is low risk in normal operation.

If trace-lock mode is used for production diagnosis, consider dropping the post-acquire trace or
using a guard wrapper that records timing on drop.

### P3 - Client Connect Uses Certificate-Store Write Lock for Reads

`async-opcua-client/src/transport/channel.rs:358` takes a certificate-store write lock to read cert
and key. Unless those reads mutate hidden store state, this can be a read lock.

---

## Keep - Do Not Rewrite Blindly

- **Session activation locks:** keep. `activate_session` snapshots state, releases locks for
  authentication `.await`, then re-checks and commits under per-session write lock. This protects OPC
  UA replay, nonce, and cross-channel semantics.
- **Address-space structural write locks:** keep. Node/reference/type mutation needs graph invariant
  protection.
- **Subscription actors and rings:** keep. Per-session actors, bounded rings, and chunked refresh
  draining are the right direction.
- **Client `PreInsertMonitoredItems`:** keep the ordering/race semantics; only move user callback
  invocation outside the mutex.
- **SQLite history mutexes:** keep. `rusqlite::Connection` is synchronous and serialized inside
  `spawn_blocking`.
- **Certificate-store locks:** keep for trust material and validation. Shrink read/write mode where
  obviously wrong, but do not remove the boundary.
- **Startup lock-across-await waivers:** keep for now. `server.rs:517` and
  `node_manager/memory/mod.rs:749` are startup-only and documented, though fragile for custom
  managers that re-enter initialization locks.

---

## Recommended Work Order

As of the implementation follow-up, items 1 through 6 and the small read/write lock mode cleanups in
item 8 have scoped completions. The subscription route index snapshot/SPSC part of item 7 remains
deferred, and item 9 remains required before larger queue or snapshot rewrites.

1. Refactor server in-memory read/write/method callbacks to clone callback handles and invoke after
   locks are released.
2. Refactor client subscription publish handling to deliver user callbacks after releasing
   `subscription_state`.
3. Refactor `SyncSampler` to sample and notify outside the sampler map mutex.
4. Refactor subscription notification fanout to snapshot routes under the cache guard, then enqueue
   outside it.
5. Shrink `SessionManager` read guard on normal request dispatch.
6. Split `CreateSession` into short lock commit plus outside-lock validation/crypto where semantics
   allow.
7. Prototype versioned immutable snapshots for either the type tree or subscription route index
   before attempting broader address-space snapshotting.
8. Sweep small read/write lock mode issues in PubSub and client certificate-store access.
9. Add targeted benchmarks before larger address-space/type-tree snapshot or SPSC-pipeline rewrites.

---

## Validation Plan for Future Changes

- Add concurrency tests that callbacks can call safe server/client APIs without deadlocking.
- Add a regression test for Publish callback delivery outside `subscription_state`.
- Add a sampler test with a slow sampler and concurrent add/update/remove to catch lock scope
  regressions.
- Add benchmark or lock-tracing comparisons around Read, Write, Publish, notification fanout, and
  sampled monitored items before and after queue-based changes.
- Add stale-snapshot/version tests for any RCU-style route/type-tree snapshots, especially around
  monitored-item create/modify/delete races.
- Add bounded queue backpressure tests before accepting any subscription route SPSC lane.
- Keep OPC UA ordering semantics explicit in any connection worker pipeline: one reader and one
  writer per SecureChannel, with ordered response enqueueing where the spec or implementation state
  requires it.

---

## External Audit Artifact

Antigravity generated an additional local report at:

`/home/quackdcs/.gemini/antigravity-cli/brain/0773a2c0-3c93-4660-99e4-1d3906345075/lock_audit_report.md`

That report agreed with the main triage: callback-under-lock is the highest-value fix, startup
lock-across-await is acceptable, and the existing subscription actor/ring design should be preserved.
