# Baseline: Lock Removal and Snapshot Concurrency

## T001 TypeTree Lock-Audit Baseline

**Current lock boundary**: the server-wide TypeTree is `ServerInfo::type_tree:
Arc<RwLock<DefaultTypeTree>>` in `async-opcua-server/src/info.rs`. It is created
in `async-opcua-server/src/server.rs`, copied into `ServerContext` and
`RequestContextInner`, exposed through `ServerHandle::type_tree()`, and used by
the default `TypeTreeForUser`/`TypeTreeForUserStatic` implementations in
`async-opcua-server/src/node_manager/context.rs`. The default user getter
currently returns a read guard from `trace_read_lock!(ctx.type_tree)`, so default
per-user and subscription event paths still acquire the same global TypeTree
`RwLock`.

**Current mutation boundary**: startup builds and initializes the mutable
`DefaultTypeTree` under the server write lock while node managers load type
metadata. Additional mutation paths exist for namespace/type-node additions in
node manager builders, diagnostics setup, node-management services, and
`async-opcua-server/src/address_space/utils.rs`. There is no separate immutable
snapshot publication boundary today.

**Known hot-path readers and call sites**:

- Browse/view paths in `async-opcua-server/src/session/services/view.rs` and
  `async-opcua-server/src/node_manager/memory/mod.rs` read TypeTree metadata for
  reference-type validation, Browse result construction, continuation handling,
  and external-reference resolution.
- Query paths in `async-opcua-server/src/session/services/query.rs`,
  `async-opcua-server/src/services/query/`, and
  `async-opcua-server/src/node_manager/memory/mod.rs` read type metadata while
  parsing node type descriptions and filters.
- Read/Write-related validation paths in
  `async-opcua-server/src/address_space/utils.rs`,
  `async-opcua-server/src/node_manager/memory/simple.rs`, and
  `async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs` read TypeTree
  metadata while validating data types, reference types, and type definitions.
- Subscription and monitored-item paths in
  `async-opcua-server/src/session/services/monitored_items.rs`,
  `async-opcua-server/src/subscriptions/actor.rs`, and
  `async-opcua-server/src/subscriptions/mod.rs` read TypeTree metadata while
  creating/modifying monitored items and evaluating event filters.
- Helper/diagnostic paths in `async-opcua-server/src/server_handle.rs` and
  `async-opcua-server/src/diagnostics/node_manager.rs` read the same lock for
  namespace lookup and diagnostics browse metadata.

**Why this is P1**: TypeTree metadata is read-mostly after startup, shared by
multiple service and subscription fanout paths, and has a contained semantic
surface compared with session, SecureChannel, address-space structure, PubSub,
or SQLite history locks. The MVP can remove default hot-path read-lock
contention by publishing complete immutable TypeTree snapshots while keeping
custom type-tree getter behavior explicit and preserving OPC UA-visible Browse,
Query, Read, Write, and subscription results.

**Required evidence before implementation**: add focused expected-red tests that
detect default hot-path TypeTree reads acquiring the mutable/global lock and
prove the startup snapshot is complete after type metadata initialization. Later
baseline tasks should record the exact focused TypeTree, Browse, Query, Read,
Write, subscription, clippy lock-check, and controlled benchmark commands before
code changes begin. This T001 entry records source inspection only; no tests,
clippy runs, or benchmarks have been run for this baseline.

**Required evidence after implementation**: record passing focused TypeTree
snapshot tests, targeted Browse/Query/Read/Write/subscription regressions,
clippy lock-check results, and controlled Read/Write before-and-after benchmark
samples in the slice notes. The after-state should show default hot-path readers
borrowing an atomically published immutable snapshot while explicit custom
getter compatibility remains documented.

## T002 Response-Size Global-State Baseline

**Current global state/lock boundary**: client response body limits are stored in
`async-opcua-core/src/comms/buffer.rs` as a process-wide
`OnceLock<Mutex<HashMap<ClientResponseBodyLimitKey, usize>>>`. The lookup key is
derived from `SecureChannel::secure_channel_id()` plus the channel encoding
context pointer. `SecureChannel` itself currently owns the channel id and
encoding context, but not the negotiated response-size limit.

**Current registration and cleanup call sites**:
`CreateSessionRequest.max_response_message_size` is copied into
`Session::max_response_message_size` when
`async-opcua-server/src/session/manager.rs` creates a `Session`.
`async-opcua-server/src/session/controller.rs` passes the current channel key
into `SessionManager::commit_create_session_draft`, and
`SessionManager::refresh_client_response_body_limit_for_channel` scans live,
non-closed sessions for the channel, uses the minimum nonzero session limit, and
calls `set_client_response_body_limit` or `clear_client_response_body_limit`.
Refresh/cleanup is also reached on CreateSession commit, ActivateSession channel
changes, CloseSession, session expiry, and secure-channel cleanup. The manager
keeps a separate `DashMap<u32, ClientResponseBodyLimitKey>` by secure channel id
so it can clear the global map later.

**Current read/enforcement call site**: `SendBuffer::write` in
`async-opcua-core/src/comms/buffer.rs` takes the global mutex for each
server-side non-`ServiceFault` response, reads the optional body limit, compares
it with `message.byte_len(ctx)`, and rejects oversized responses before
chunking.

**Protocol behavior to preserve**: OPC UA Part 4 `maxResponseMessageSize`
behavior is body-size based and channel/session negotiated. A value of zero
means no advertised client-side response limit, so the current implementation
removes the map entry and allows responses. A nonzero effective limit must remain
channel-specific, must not leak between concurrent channels, and oversized
responses must still fail with `StatusCode::BadResponseTooLarge` while
preserving the current request context on the error. The current check also
continues to allow `ServiceFault` responses through this limit path.

**Required evidence before implementation**: add expected-red response-limit
tests for zero limit, nonzero limit, oversized response, `BadResponseTooLarge`
status, independent concurrent channels, and channel-close cleanup. Record the
pre-implementation `cargo test -p async-opcua-core response_limit_state -- --nocapture`
result in slice notes before moving the state out of the global map. This T002
entry records source inspection only; no tests, clippy runs, or benchmarks have
been run for this baseline.

**Required evidence after implementation**: record passing response-limit unit
tests, the existing `cargo test -p async-opcua-server max_response_message_size -- --nocapture`
integration coverage, and the lock-focused clippy result in slice notes. The
after-state should show steady-state response-size checks reading channel-owned
or otherwise hot-path lock-free state, with cleanup making closed-channel limits
unreachable.

## T003 Subscription Route Lock Baseline

**Current cache/route lock boundary**: subscription routing state is held in
`SubscriptionCache::inner: RwLock<SubscriptionCacheInner>` in
`async-opcua-server/src/subscriptions/mod.rs`. The guarded state contains
session-to-actor entries, subscription-to-session ownership, and the reverse
`monitored_items` route index from node/attribute to monitored item handles.
Per-session subscription state is actor-owned in `SessionSubscriptions`; the
cache lock is the cross-session route and ownership index, not the owner of
Publish queues or subscription contents.

**Current route lookup and fanout call sites**: data fanout uses
`data_route_snapshot()` to copy matched routes under a short read lock before
`notify_for`, `notify_data_change`, and `maybe_notify` push work to subscription
actors. That current `NotificationRouteSnapshot` is an owned per-lookup copy,
not the proposed published `RouteIndexSnapshot`. Event fanout still enters
through `event_notifier()`/`notify_events()`, where `SubscriptionEventNotifier`
owns a cache read guard until the notifier is dropped. `refresh_subscription_events`
also reads the cache to validate subscription ownership before pushing refresh
work.

**Current lifecycle update behavior to preserve**:

- CreateMonitoredItems validates the service request and node-manager create
  path first, then `SubscriptionCache::create_monitored_items` calls the
  per-session actor and inserts only successful monitored items into the reverse
  route index under a cache write lock. If cache insertion fails after node
  manager creation, the service path performs node-manager cleanup before
  returning the service fault.
- ModifyMonitoredItems updates actor-owned monitored item parameters and returns
  per-item results before the node-manager modify callback runs for successful
  items. The current cache reverse index is not rewritten by
  `modify_monitored_items`; any future route snapshot must preserve the same
  route membership and per-item result behavior.
- DeleteMonitoredItems calls the actor first, then removes only successful item
  refs from the reverse route index under a cache write lock before the service
  invokes node-manager delete callbacks for successful refs. Once a deletion is
  visible in the route index, future Publish/data fanout must not route
  notifications for the deleted monitored item.

**Publish, Republish, and transfer behavior to preserve**: Publish requests are
enqueued through `SubscriptionCache::enqueue_publish_request`, then handled by
the per-session actor after draining queued notification work. `SessionSubscriptions`
processes acknowledgements, emits Publish responses, updates retransmission
state, reports available sequence numbers, and sets `more_notifications` only
on the last response in the current batch. Republish reads the current
session/subscription route, resets the lifetime counter, and returns the stored
retransmission message or the existing error statuses. Transfer creates or
finds the destination session actor, validates the transfer user key, clones the
subscription plus retransmission state, inserts it into the destination,
optionally marks data for resend, marks the source as transferring, updates
`subscription_to_session`, removes the source copy, and queues the old-session
`GoodSubscriptionTransferred` status change. A future route-index snapshot must
publish complete replacement views around these ownership changes so Publish,
Republish, acknowledgement, resend, and transfer-status behavior remain
protocol-compatible.

**Gate status and required evidence**: this is a P3 measurement gate and
follow-up baseline only; it is not approval to implement subscription route lock
removal. Before any P3 implementation, record contention or fanout evidence for
this cache lock, add focused tests for monitored item create/delete/modify,
subscription transfer, Republish, and Publish notification routing, and record
the `cargo test -p async-opcua-server subscription_route_snapshot -- --nocapture`
result plus a gate decision tied to OPC-10000-4 5.13, 5.14, and 6.7. This T003
entry records source inspection only; no tests, clippy runs, traces, or
benchmarks have been run for this baseline.

## T004 PubSub Config/Cache Lock Baseline

**Current config manager/address-space lock boundary**: writable PubSub
configuration Methods share `Arc<Mutex<PubSubConfigManager>>` and
`Arc<RwLock<AddressSpace>>` in `async-opcua-pubsub/src/config_methods.rs`.
The manager owns current `PubSubConnectionConfig` entries plus
`PublishedDataItemsConfig` entries. The method handlers currently mutate the
manager under the mutex, then acquire the address-space write lock and reflect
the manager contents into the information model with `reflect_pubsub_config` or
`reflect_published_data_sets`. This means the manager mutex is live across the
address-space reflection work for add/remove connection, writer group, reader
group, DataSetWriter, DataSetReader, PublishedDataSet, and variable-list
updates.

**Current transport cache/runtime boundary**: runtime publishing uses cloned
`PubSubConnectionConfig` values when `PubSubEngine::start` starts transport
loops in `async-opcua-pubsub/src/engine.rs`; `add_connection` and
`remove_connection` mutate only the engine's stored vector before start/restart.
MQTT uses `type MessageCache = Arc<Mutex<VecDeque<(String, Vec<u8>)>>>` with
`MAX_CACHE_SIZE = 1000` in `async-opcua-pubsub/src/transport/mqtt.rs`.
AMQP has the same bounded cache pattern in `transport/amqp.rs`. The cache is
written by `publish_immediate` and cyclic publisher tasks, drained by sender
loops, and requeues failed sends at the front. UDP and WebSocket do not share
that cache; their listed publisher paths build payloads from an address-space
read guard and then perform async sends after payload construction.

**Relevant call sites**:

- `register_pubsub_config_methods` routes Part 14 configuration Methods to
  handlers for Add/RemoveConnection, Add/RemoveGroup, Add/RemoveDataSetWriter,
  Add/RemoveDataSetReader, Add/RemovePublishedDataSet, AddVariables, and
  RemoveVariables.
- `add_connection`, `remove_connection`, `add_writer_group`,
  `add_reader_group`, `remove_group`, `add_dataset_writer`,
  `remove_dataset_writer`, `add_dataset_reader`, and
  `remove_dataset_reader` update `manager.connections` and re-run
  `reflect_pubsub_config`.
- `add_published_data_items`, `remove_published_data_set`, `add_variables`,
  and `remove_variables` update `manager.published_data_sets` and re-run
  `reflect_published_data_sets`; `add_variables`/`remove_variables` preserve
  Part 14 configuration-version checks and version increments.
- `MqttPublisher::publish_immediate`, MQTT cyclic writer tasks, and the MQTT
  sender loop are the listed transport-cache call sites. WebSocket and UDP
  publisher loops are relevant comparison call sites because they build
  WriterGroup payloads without a shared transport cache.

**Part 14 behavior to preserve**: reflected PubSub configuration must stay
internally consistent with the manager state. `reflect_pubsub_config` creates
deterministic NodeIds and references for `PubSubConnection`, `WriterGroup`,
`ReaderGroup`, `DataSetWriter`, and `DataSetReader` objects, including identity
properties such as `WriterGroupId`, `ReaderGroupId`, `DataSetWriterId`, and
`DataSetReaderId`. Any future config actor or draft/commit publication pattern
must publish complete reflected views so OPC-10000-14 9.1.5.2 connection
configuration, 9.1.7.2 DataSetWriter configuration, and 9.1.10.1 PubSubStatus
visibility do not observe partial manager/address-space states. PublishedDataSet
configuration-version matching for AddVariables/RemoveVariables must continue
to reject stale versions before mutation.

**DataSetReader/status consistency to preserve**: subscriber runtime status is
currently exposed as `DataSetReaderStatus` with a `PubSubState`, and
`reflect_pubsub_config_with_status` reflects reader status beside the
DataSetReader configuration. A future snapshot/cache design must keep
DataSetReader identity, target-variable count, and status snapshots aligned
with the same published configuration view; transport caches must not deliver
messages built from a mixture of stale writer configuration and newer reflected
configuration unless the gate explicitly proves that behavior is acceptable
under OPC-10000-14 5.4.1.2.

**Gate status and required evidence**: this is a P3 measured follow-up gate and
baseline only; it is not approval to refactor PubSub config or transport
caches. Before any P3 implementation, record contention evidence for the config
manager/address-space lock boundary and the bounded transport cache, add focused
tests for PubSubConnection configuration, DataSetWriter configuration,
DataSetReader/PubSubStatus consistency, and transport-cache message sending,
then record the `cargo test -p async-opcua-pubsub config_snapshot_consistency -- --nocapture`
result plus a gate decision tied to OPC-10000-14 5.4.1.2, 9.1.5.2, 9.1.7.2,
and 9.1.10.1. This T004 entry records source inspection and lock-scan evidence
only; no tests, clippy runs, traces, or benchmarks have been run for this
baseline.

## T005 SQLite History Lock Baseline

**Current lock boundaries**: `SqliteHistoryBackend` in
`async-opcua-history-sqlite/src/backend.rs` owns a single
`Arc<Mutex<Connection>>` plus an
`Arc<Mutex<HashMap<Vec<u8>, CachedContinuationPoint>>>`. `new` and
`new_in_memory` run migrations before wrapping the synchronous
`rusqlite::Connection`; the public `connection()` accessor exposes the same
mutex for direct callers and tests. The continuation-point mutex is separate
from the database mutex and stores backend-local raw/modified read cursors with
a 300 second retention window.

**Relevant read/query call sites**: `read_raw_modified` prunes stale
continuation points, removes any supplied backend token, and then reads a page
through `spawn_blocking` while holding the connection mutex in
`fetch_raw_modified_values` or `fetch_modified_values`. Raw reads use
`query::fetch_bounds`/`query::fetch_interval` and modified reads query
`modified_historical_data` by `(source_timestamp, modification_time, rowid)`.
`read_processed` rejects caller-supplied continuation points, loops
`read_raw_modified` to gather raw pages, and reads annotations for the
AnnotationCount aggregate. `read_events` and `read_annotations` also reject
continuation points and perform their SQLite queries inside `spawn_blocking`
under the same connection mutex. `migration.rs` creates the current
`historical_data`, `modified_historical_data`, `historical_annotations`, and
`historical_events` tables and query indexes.

**Relevant write/update call sites**: `update_data`, `update_structure_data`,
`update_event`, `delete_raw_modified`, `delete_at_time`, and `delete_event`
prune continuation points, enter `spawn_blocking`, lock the same connection,
and perform SQLite transactions. The current implementation therefore serializes
reads, writes, and deletes at the backend connection boundary even when callers
issue HistoryRead and HistoryUpdate work concurrently.

**OPC UA behavior to preserve**: the server HistoryRead path validates
`nodesToRead`, applies the history-read operation limits, prepares one
`HistoryNode` per requested node, and returns results in request order. The
memory node manager then calls the backend once per node and wraps backend
tokens in session-owned history continuation points. Any future DB actor or
read-pool design must preserve this per-node status/result isolation for
OPC-10000-4 5.11.3.2, including invalid continuation-point handling and release
semantics. Raw/modified continuation tokens currently resume from the stored
cursor and are consumed on use; `release_continuation_point` removes the backend
token. Events and annotations currently do not page and return
`BadContinuationPointInvalid` for supplied tokens.

**Part 11 history semantics to preserve**: HistoryUpdate data, annotation, and
event operations must keep the current Part 11 result behavior for insert,
replace, update, remove, range delete, at-time delete, and event-id delete.
Modified history rows must continue to record replacement/delete provenance for
`read_modified`, corrupt stored event or value blobs must still map to
`BadDataLost` without deleting valid rows, and writes during reads must have an
explicit ordering/snapshot contract at least as clear as the current single
connection mutex serialization.

**Gate status and required evidence**: this is a P3 measured follow-up gate and
baseline only. The current SQLite mutex remains acceptable, especially for a
reference backend, unless history read/write contention or throughput evidence
justifies a DB actor or read-pool/write-owner design with explicit continuation
semantics. Before any P3 implementation, record SQLite history contention
evidence, add focused tests for OPC-10000-11 6.3 continuation points,
OPC-10000-4 5.11.3.2 `nodesToRead`, concurrent reads, and writes during reads,
then record the `cargo test -p async-opcua-history-sqlite history_lock_scaling -- --nocapture`
result plus a gate decision. This T005 entry records source inspection only; no
tests, clippy runs, traces, or benchmarks have been run for this baseline.

## T006 SecureChannel Renewal Lock Baseline

**Current renewal lock/single-flight boundary**:
`AsyncSecureChannel::issue_channel_lock: tokio::sync::Mutex<()>` in
`async-opcua-client/src/transport/channel.rs` guards the renewal path only.
`AsyncSecureChannel::send` checks `SecureChannel::should_renew_security_token`,
then `renew_secure_channel` takes the mutex, rechecks the token state, creates a
Renew `OpenSecureChannelRequest`, and awaits its response while the mutex is
held. This intentionally serializes concurrent renewal waiters so only one
renewal is in flight for the current channel state; the mutex is async and does
not block an executor thread, but waiters can queue behind network I/O.

**Relevant call sites and state updates**: initial Issue requests are created in
`connect_no_retry` without this renewal mutex. Both Issue and Renew requests use
`SecureChannelState::begin_issue_or_renew_secure_channel`, which sets the client
role, creates a fresh local nonce, builds the request header, and sends an
`OpenSecureChannelRequest` with the requested lifetime. Incoming
`OpenSecureChannelResponse` chunks are correlated through transport request IDs
and processed in `TransportState::process_chunk`; successful responses call
`SecureChannelState::end_issue_or_renew_secure_channel` before the waiter sees
the response, so the channel token, clock offset, server nonce, and derived keys
are updated before later messages use the renewed state. Renewal send failure
currently closes the channel.

**OPC UA Part 6 behavior to preserve**: renewal changes must preserve Part 6
OpenSecureChannel token ordering and request correlation. The current code
renews after roughly 75% of token lifetime, rejects an
`OpenSecureChannelResponse` that changes a nonzero channel id, installs the new
token id and revised lifetime, keeps previous remote keys through the overlap
window, and prunes expired keys on later renewals. Outbound chunks are produced
by a single transport writer: `SendBuffer::next_request_id` assigns the request
id, the send buffer increments sequence numbers per chunk, `SequenceHeader`
carries both sequence number and request id, OpenSecureChannel chunks use the
asymmetric security header, and normal message chunks use the current symmetric
token id. Incoming chunks are validated for sequence/order and matched back to
`message_states` by `sequence_header.request_id`. Any replacement must preserve
no duplicate Renew attempts for one channel state, cancellation/failure behavior,
token update ordering, old-token overlap, and request-id response matching.

**Gate status and required evidence**: this is a P3 measured follow-up gate and
baseline only. The current mutex remains acceptable unless contention evidence
shows renewal waiters materially queue behind network I/O and justifies a
replacement state machine. Before any P3 implementation, record renewal
contention evidence for `issue_channel_lock` wait time or waiter count, then add
focused tests for concurrent renewal waiters, cancellation, renewal failure, and
renewal request ordering. Record the
`cargo test -p async-opcua-client secure_channel_renewal_singleflight -- --nocapture`
result and a gate decision tied to OPC-10000-6 6.7.4 and 6.7.2.4. If the gate
passes, the replacement should be a small single-flight renewal state machine
using `Notify` or shared-future semantics so waiters await outside the mutex
without weakening Part 6 ordering/security behavior. This T006 entry records
source inspection and existing audit/test references only; no new tests, clippy
runs, traces, or benchmarks have been run for this baseline.

## T007 Current Clippy Await-Holding-Lock Result

**Command run from repository root**:

```bash
cargo clippy --workspace --all-targets --all-features --locked -- \
  -W clippy::await_holding_lock \
  -W clippy::await_holding_refcell_ref
```

**Run timestamp**: 2026-06-30T23:30:57+02:00

**Exit status**: 0

**Result summary**: clippy completed successfully for the workspace with all
targets and all features. No `clippy::await_holding_lock` or
`clippy::await_holding_refcell_ref` warnings were reported.

**Relevant output**:

```text
Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.34s
```

## T008 Controlled Read Benchmark Baseline Placeholder

**Command to run later from repository root**:

```bash
cargo run -p async-opcua-localhost-bench -- run --op read --port 4840 --warmup 1.0 --measure 5.0
```

**Placeholder status**: this entry only records the controlled Read benchmark
command for later TypeTree slice measurement. The benchmark was not run for
T008, and this section does not claim throughput, latency, pass/fail status, or
any other benchmark result.

**SC-004 expectation**: during the TypeTree snapshot slice, record at least
three before and at least three after controlled localhost Read samples using
the command above. Compare the before/after Read samples by median throughput;
the Read portion passes only if median throughput does not drop by more than
5%, or if the slice notes document measurement noise and a maintainer-approved
rationale for accepting the result.

## T009 Controlled Write Benchmark Baseline Placeholder

**Command to run later from repository root**:

```bash
cargo run -p async-opcua-localhost-bench -- run --op write --port 4840 --warmup 1.0 --measure 5.0
```

**Placeholder status**: this entry only records the controlled Write benchmark
command for later TypeTree slice measurement. T009 does not run the benchmark,
and this section does not claim throughput, latency, pass/fail status, or any
other benchmark result.

**SC-004 expectation**: during the TypeTree snapshot slice, record at least
three before and at least three after controlled localhost Write samples using
the command above. Compare the before/after Write samples by median throughput;
the Write portion passes only if median throughput does not drop by more than
5%, or if the slice notes document measurement noise and a maintainer-approved
rationale for accepting the result.

## T011 TypeTree Snapshot Dependency Decision

**Decision**: use the existing workspace/server `arc-swap` dependency for
atomic `Arc` snapshot publication if the TypeTree snapshot implementation needs
it. Do not add a new dependency for TypeTree snapshots.

**Dependency evidence**:

- Root `Cargo.toml` already declares `arc-swap = "^1"` in workspace
  dependencies.
- `async-opcua-server/Cargo.toml` already enables the dependency with
  `arc-swap = { workspace = true }`.
- `cargo tree -p async-opcua-server --locked` resolves `arc-swap v1.8.2`.
- `async-opcua-server/src/server.rs` already imports `arc_swap::ArcSwap` and
  uses it for server status/start-time state.

**Rationale**: the feature spec allows adding a small established dependency
such as `arc-swap` only if it is not already available through the workspace,
and the plan lists `arc-swap` as a candidate dependency only under that
condition. Research Decision 2 calls for readers to observe either the previous
complete TypeTree metadata view or the next complete view, using `ArcSwap` or
an equivalent established atomic `Arc` snapshot mechanism. Because the server
crate already depends on and uses `ArcSwap`, existing workspace primitives are
enough for the RCU-style immutable snapshot publication pattern.

**Manifest impact**: no `Cargo.toml` or lockfile change is required for the
TypeTree snapshot MVP.

## T012 TypeTree Focused Test Command List

**Focused command to run for the TypeTree expected-red and verification
checks**:

```bash
cargo test -p async-opcua-server type_tree_snapshot -- --nocapture
```

**Expected focused test file**:
`async-opcua-server/tests/type_tree_snapshot.rs`.

**Planned test names from T023-T027**:

- `hot_path_reads_use_type_tree_snapshot`
- `browse_reference_description_preserves_part4_5_9_2_2_and_7_29`
- `query_type_path_preserves_part4_b_2_3`
- `published_snapshot_is_complete_after_startup`
- `custom_type_tree_getter_remains_compatible`

**Requirement and slice coverage**: these tests are the focused TypeTree
snapshot proof required by FR-003 and SC-001. They support Slice 1 by proving
default service hot paths use the published TypeTree snapshot without acquiring
the global TypeTree `RwLock`, while Browse and Query behavior remains tied to
the OPC UA Part 4 behavior named in the test cases and custom type-tree getter
compatibility remains explicit.

**Current pre-test state**: `async-opcua-server/tests/type_tree_snapshot.rs`
has not been created yet. The current discovery check builds but lists zero
matching tests:

```bash
cargo test -p async-opcua-server type_tree_snapshot -- --list
```

This baseline entry does not claim that expected-red testing has run. T028
will run the `-- --nocapture` command later after T023-T027 add the focused
tests, and T029 will record that expected-red result in slice notes.

## T013 Browse/Query/Read/Write/Subscription Regression Command List

These commands are the focused US1 service regression list for FR-002 and
SC-002 after the TypeTree snapshot implementation. They are intentionally
recorded as commands for later verification tasks only; this T013 baseline
entry does not run the regression bodies or claim pass/fail results.

| Category | Later task | Command | OPC UA clauses | Current discovery note |
|----------|------------|---------|----------------|------------------------|
| Browse | T049 | `cargo test -p async-opcua-server browse -- --nocapture` | OPC-10000-4 5.9.2.2 and 7.29 | Broad filter. `cargo test -p async-opcua-server browse -- --list` currently lists 8 matching unit tests, including Browse node traversal, Browse permission filtering, duplicate browse-name handling, and browse/query continuation-point eviction. |
| Query | T051 | `cargo test -p async-opcua-server query -- --nocapture` | OPC-10000-4 B.2.3 | Broad filter. `cargo test -p async-opcua-server query -- --list` currently lists 18 matching tests: 14 library unit tests, 3 tests from `async-opcua-server/tests/query_tests.rs`, and 1 performance-oriented query scan test. |
| Read | T053 | `cargo test -p async-opcua-server read -- --nocapture` | OPC-10000-4 5.11.2.2 | Broad filter. `cargo test -p async-opcua-server read -- --list` currently lists 34 matching tests across attribute/value access semantics, history read behavior, GDS read access, read callback lock scope, query unreadable-result filtering, and max-response-size read-response coverage. |
| Write | T055 | `cargo test -p async-opcua-server write -- --nocapture` | OPC-10000-4 5.11.4.2 | Broad filter. `cargo test -p async-opcua-server write -- --list` currently lists 15 matching tests across value/attribute write access semantics, condition property writes, history write defaults, address-space read/write concurrency, and write callback lock scope. |
| Subscription | T057 | `cargo test -p async-opcua-server subscription -- --nocapture` | OPC-10000-4 5.13 and 5.14 | Broad filter. `cargo test -p async-opcua-server subscription -- --list` currently lists 47 matching tests covering subscription filters, monitored items, retransmission queues, Publish/Republish behavior, reverse-index cleanup, and existing subscription route snapshot lock-scope checks. |

The filters above are broad by design because the current test suite does not
yet provide one narrow TypeTree-specific regression file for each service
category. Later tasks T049/T051/T053/T055/T057 should record the exact command
output in slice notes after implementation. If new focused service regression
tests are added before those tasks run, record the replacement or supplemental
command there rather than treating this baseline as evidence that behavior has
already passed.

## T014 Response-Size Focused Test Command List

**Focused command to run for the response-size expected-red and verification
checks**:

```bash
cargo test -p async-opcua-core response_limit_state -- --nocapture
```

**Expected focused test file**:
`async-opcua-core/tests/response_limit_state.rs`.

**Planned test names from T064-T069**:

- `zero_limit_preserves_part4_5_7_2_2_unbounded_response_size`
- `nonzero_limit_applies_part4_5_7_2_2_response_body_limit`
- `oversized_response_returns_part4_5_3_bad_response_too_large`
- `bad_response_too_large_matches_part4_7_38_2_status`
- `concurrent_channels_use_independent_response_limits`
- `closed_channel_drops_response_limit_state`

**Requirement and slice coverage**: these tests are the focused response-size
state proof required by FR-005. They support User Story 2 and Slice 2 by
proving negotiated response limits are enforced from channel-local or otherwise
hot-path lock-free state while preserving OPC-10000-4 5.7.2.2
`maxResponseMessageSize` handling and response-size behavior,
OPC-10000-4 5.3 ServiceFault/service error behavior surface, and
OPC-10000-4 7.38.2 `BadResponseTooLarge` status semantics.

**Current pre-test state**: `async-opcua-core/tests/response_limit_state.rs`
has not been created yet. The current discovery check builds but lists zero
matching tests:

```bash
cargo test -p async-opcua-core response_limit_state -- --list
```

This baseline entry does not claim that expected-red testing has run. T070
will run the `-- --nocapture` command later after T064-T069 add the focused
tests, and T071 will record that expected-red result in slice notes.

## T015 Subscription Route Contention Measurement Command/Source

**Focused command/source to use for the P3 subscription route gate**:

```bash
cargo test -p async-opcua-server subscription_route_snapshot -- --nocapture
```

T086 should use this command as the repeatable evidence source for the
subscription route-cache contention and fanout gate, then record the actual
output in slice notes. This T015 entry records the source only; it does not run
the `-- --nocapture` command as evidence, does not claim contention has been
measured, and does not approve any route-index snapshot implementation.

**Existing source files tied to this command/source**:

- `async-opcua-server/src/subscriptions/mod.rs`, including
  `SubscriptionCache::inner: RwLock<SubscriptionCacheInner>` and the current
  data-change/event route behavior that later work must preserve.
- `async-opcua-server/src/subscriptions/notify.rs`, including the owned route
  snapshot and notification route lookup paths used to reason about cache guard
  lifetime.
- `async-opcua-server/tests/subscription_route_snapshot_enqueue.rs`, covering
  whether route lookup releases the cache guard before actor enqueue/fanout.
- `async-opcua-server/tests/subscription_route_snapshot_no_match.rs`, covering
  no-match route allocation and fanout behavior.
- `async-opcua-server/tests/subscription_route_snapshot_sampling.rs`, covering
  sampling/delete race behavior and cache guard scope during sampling.

**Evidence intent**: the command/source is meant to capture proof about
route-cache guard scope, no-match route allocation/fanout behavior, and
sampling/delete race behavior before any lock-removal or route-index snapshot
change is accepted. The gate should show that subscription routing preserves
the current externally visible semantics while reducing or eliminating the
measured contention source.

**OPC UA references for this gate**: OPC-10000-4 5.13, 5.13.2.1, 5.13.3.1,
5.14, 5.14.1.2, and 6.7.

**Current discovery note**: the allowed discovery command builds and lists the
current matching tests without running the evidence command:

```bash
cargo test -p async-opcua-server subscription_route_snapshot -- --list
```

At baseline time it lists the existing enqueue and no-match integration tests
under the `subscription_route_snapshot` filter; the sampling source file exists
as part of the route snapshot gate sources and may be included or expanded by
later T087-T092 work. T093 will run the focused `-- --nocapture` command after
the gate tests are in their final form, and T095 will record the route gate
decision separately.

## T016 PubSub Config/Cache Contention Measurement Command/Source

**Focused command/source to use for the P3 PubSub config/cache gate**:

```bash
cargo test -p async-opcua-pubsub config_snapshot_consistency -- --nocapture
```

T096 should use this command as the repeatable evidence source for PubSub
configuration-manager and transport-cache contention or consistency proof, then
record the actual output in slice notes. This T016 entry records the
measurement command/source only; it does not run the `-- --nocapture` command
as evidence, does not claim contention has been measured, and does not approve
PubSub config/cache refactoring.

**Expected focused test file**:
`async-opcua-pubsub/tests/config_snapshot_consistency.rs`.

**Current discovery note**: the focused test file does not exist yet. Until
T097-T100 add it, the current supporting discovery sources for T096 are:

- `async-opcua-pubsub/src/config_methods.rs`, including
  `Arc<Mutex<PubSubConfigManager>>`, address-space reflection, and Part 14
  configuration Methods.
- `async-opcua-pubsub/src/engine.rs`, including the copied
  `PubSubConnectionConfig` values used when transport loops start.
- `async-opcua-pubsub/src/pubsub_model.rs`, including PubSub configuration,
  DataSetWriter, DataSetReader, and status model types.
- `async-opcua-pubsub/tests/pubsub_model_tests.rs`,
  `async-opcua-pubsub/tests/engine_tests.rs`,
  `async-opcua-pubsub/tests/pubsub_tests.rs`,
  `async-opcua-pubsub/tests/datasetreader_tests.rs`, and
  `async-opcua-pubsub/tests/subscriber_status_tests.rs` as current related
  PubSub behavior tests, not substitutes for the planned focused gate test.

**Evidence intent**: the command/source is meant to capture config manager lock
contention, reflected Part 14 configuration consistency,
DataSetWriter/DataSetReader/PubSubStatus consistency, transport message sending
cache behavior, or equivalent proof before any PubSub config/cache lock removal
is accepted.

**OPC UA references for this gate**: OPC-10000-14 5.4.1.2, 9.1.5.2, 9.1.7.2,
and 9.1.10.1.

T101 will run the focused `-- --nocapture` command after
`async-opcua-pubsub/tests/config_snapshot_consistency.rs` exists and the gate
tests are in their final form. T103 will record the PubSub gate decision
separately.

## T017 SQLite History Contention Measurement Command/Source

**Focused command/source to use for the P3 SQLite history gate**:

```bash
cargo test -p async-opcua-history-sqlite history_lock_scaling -- --nocapture
```

T104 should use this command as the repeatable evidence source for SQLite
history read/write lock contention or throughput proof, then record the actual
output in slice notes. This T017 entry records the measurement command/source
only; it does not run the `-- --nocapture` command as evidence, does not claim
contention has been measured, and does not approve SQLite history lock-removal
implementation or any DB actor/read-pool design.

**Expected focused test file**:
`async-opcua-history-sqlite/tests/history_lock_scaling.rs`.

**Current discovery note**: the focused test file does not exist yet. Until
T105-T108 add it, the current supporting discovery sources for T104 are:

- `async-opcua-history-sqlite/src/backend.rs`, including the current
  `Arc<Mutex<Connection>>` SQLite connection boundary around history reads,
  writes, deletes, and continuation-point-backed raw/modified reads.
- `async-opcua-history-sqlite/src/query.rs`, including the raw/modified
  history query helpers used under the backend connection mutex.
- `async-opcua-history-sqlite/tests/history_update_data.rs`,
  `async-opcua-history-sqlite/tests/history_events.rs`, and
  `async-opcua-history-sqlite/tests/query_migration.rs` as current related
  backend behavior tests, not substitutes for the planned focused gate test.
- `async-opcua-server/src/services/history_read.rs`, including the server
  `HistoryRead` handling for `nodesToRead`, request-order result behavior,
  operation limits, and session-owned continuation-point wrapping.

**Evidence intent**: the command/source is meant to capture SQLite history
read/write lock contention or throughput, continuation-point behavior,
OPC-10000-4 5.11.3.2 `HistoryRead` `nodesToRead` behavior, concurrent reads,
writes during reads, or equivalent proof before any SQLite history lock removal
is accepted.

**OPC UA references for this gate**: OPC-10000-11 6.3 and OPC-10000-4
5.11.3.2.

T109 will run the focused `-- --nocapture` command after
`async-opcua-history-sqlite/tests/history_lock_scaling.rs` exists and the gate
tests are in their final form. T111 will record the SQLite history gate
decision separately.

## T018 SecureChannel Renewal Contention Measurement Command/Source

**Focused command/source to use for the P3 SecureChannel renewal gate**:

```bash
cargo test -p async-opcua-client secure_channel_renewal_singleflight -- --nocapture
```

T112 should use this command as the repeatable evidence source for
SecureChannel renewal contention or protocol-fidelity proof, then record the
actual output in slice notes. This T018 entry records the measurement
command/source only; it does not run the `-- --nocapture` command as evidence,
does not claim contention has been measured, does not approve mutex removal or
single-flight/state-machine implementation, and preserves the current
`issue_channel_lock` mutex absent gate evidence.

**Expected focused test file**:
`async-opcua-client/tests/secure_channel_renewal_singleflight.rs`.

**Current discovery note**: the focused test file does not exist yet. The
allowed discovery command builds and lists the current matching tests without
running the evidence command:

```bash
cargo test -p async-opcua-client secure_channel_renewal_singleflight -- --list
```

At baseline time it lists zero tests under the
`secure_channel_renewal_singleflight` filter. Until T113-T116 add the focused
test file, the current supporting discovery sources for T112 are:

- `async-opcua-client/src/transport/channel.rs`, including
  `AsyncSecureChannel::issue_channel_lock: tokio::sync::Mutex<()>`,
  `renew_secure_channel`, the renewal recheck while holding the mutex, and
  renewal send/response handling.
- `async-opcua-client/src/transport/state.rs`, including
  `SecureChannelState::begin_issue_or_renew_secure_channel` and
  `SecureChannelState::end_issue_or_renew_secure_channel` request correlation,
  token update, nonce/key update, and failure behavior.
- `async-opcua-client/src/transport/core.rs`, including OpenSecureChannel
  response dispatch into `end_issue_or_renew_secure_channel` and request-order
  handling.
- `async-opcua-client/tests/hostile_server.rs` and
  `async-opcua-client/tests/common/hostile_server.rs`, including the current
  stalled-renewal hostile-server behavior and discovery scaffolding, not a
  substitute for the planned focused gate test.

**Evidence intent**: the command/source is meant to capture
`issue_channel_lock` wait time or waiter count, concurrent renewal waiters,
renewal cancellation, renewal failure, renewal request ordering, or equivalent
proof before any SecureChannel renewal mutex removal or single-flight
implementation is accepted.

**OPC UA references for this gate**: OPC-10000-6 6.7.4 and 6.7.2.4.

T117 will run the focused `-- --nocapture` command after
`async-opcua-client/tests/secure_channel_renewal_singleflight.rs` exists and
the gate tests are in their final form. T119 will record the SecureChannel
renewal gate decision separately; this baseline section records no gate
decision.

## T019 Controlled Benchmark Comparison Rule (SC-004)

**Controlled sample rule**: the TypeTree snapshot slice must record at least
three before and at least three after controlled localhost benchmark samples for
both Read and Write operations.

**Benchmark commands**: use the controlled Read command recorded in T008 and
the controlled Write command recorded in T009 as the repeatable measurement
commands for the TypeTree snapshot slice.

**Comparison rule**: compare the before and after samples by median throughput
for each operation separately: Read median throughput before versus after, and
Write median throughput before versus after.

**Pass rule**: each operation passes if its median throughput drops by no more
than 5%. If either operation drops by more than 5%, the slice may be accepted
only if slice notes document measurement noise and a maintainer-approved
rationale for accepting the result.

**Later task flow**: T059-T060 run and record the controlled Read benchmark
result, T061-T062 run and record the controlled Write benchmark result, and
T063 records the SC-004 benchmark comparison conclusion in slice notes.

**Scope of this entry**: T019 records the SC-004 controlled benchmark
comparison rule only. It does not run either benchmark and does not claim any
throughput, latency, pass/fail status, comparison conclusion, or other
benchmark result.
