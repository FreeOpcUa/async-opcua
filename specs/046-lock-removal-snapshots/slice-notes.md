# Slice Notes: Lock Removal and Snapshot Concurrency

Use this file as the append-only evidence log for each independently reviewable
lock-removal slice. Replace `Pending` only when the task that produced real
evidence has run, and keep prior dated entries when adding follow-up results.

Gate decisions should be one of: `Pending`, `Pass`, `Defer`, or `Fail`. A
passing gate must cite the relevant OPC UA clauses, verification commands,
benchmark or measurement evidence where required, rollback scope, and final
review notes.

## Slice 1: TypeTree Snapshot MVP

- **Boundary**: TypeTree hot-path reads move from the global mutable TypeTree
  lock to immutable published snapshots.
- **Priority**: P1
- **Baseline reference**: `baseline.md` T001, T007, T008, T009
- **Contract reference**: `contracts/implementation-slices.md` Slice 1
- **Requirements and criteria**: FR-003, FR-009, FR-010; SC-001, SC-002,
  SC-003, SC-004
- **Primary scope**: `async-opcua-server/src/info.rs`,
  `async-opcua-server/src/node_manager/context.rs`,
  `async-opcua-server/src/node_manager/memory/mod.rs`,
  `async-opcua-server/src/server.rs`,
  `async-opcua-server/src/server_handle.rs`,
  `async-opcua-server/src/session/message_handler.rs`,
  `async-opcua-server/src/subscriptions/actor.rs`
- **OPC UA clause references**: OPC-10000-4 5.9.2.2, 7.29, B.2.3, 5.11.2.2,
  5.11.4.2, 5.13, 5.14
- **Expected-red evidence**:
  - Test or command: `cargo test -p async-opcua-server type_tree_snapshot -- --nocapture`
  - Result: Exit code `101`; compile-red failure:
    `error[E0599]: no method named type_tree_snapshot found for reference &Arc<ServerInfo>`
    at `async-opcua-server/tests/type_tree_snapshot.rs:190:10`.
  - Notes: Expected-red pre-implementation result from T028. The focused
    TypeTree suite fails to compile because T026 intentionally references the
    future `ServerInfo::type_tree_snapshot()` accessor, which implementation
    tasks T030-T036 are expected to add. This is acceptable expected-red proof,
    not an unrelated syntax/setup failure and not a regression in existing
    production code. T023 separately has an intended assertion-red condition for
    global `RwLock` guard use, but T028 stops at the earlier compile-red missing
    API.
- **Implementation notes**:
  - Implemented immutable `TypeTreeSnapshot` publication on `ServerInfo` using
    the mature `arc-swap` crate instead of a custom unsafe lock-free
    structure.
  - Updated TypeTree hot-path consumers in request/session/subscription
    context construction and Browse, Query, Read, Write, monitored-item, and
    diagnostics paths to use snapshot reads while preserving the existing
    compatibility accessor for callers that still need the mutable TypeTree.
  - Published snapshots after startup and TypeTree namespace mutations,
    including the generic in-memory builder path required by the controlled
    localhost benchmark namespace.
- **Verification command/results**:
  - Focused TypeTree tests: 2026-07-01 `cargo test -p async-opcua-server type_tree_snapshot -- --nocapture`
    exited `0`; filtered run passed with
    `hot_path_reads_use_type_tree_snapshot ... ok` in
    `async-opcua-server/tests/type_tree_snapshot.rs` and summary `1 passed`,
    `0 failed`. Other test binaries reported `0 tests` because Cargo's
    `type_tree_snapshot` test-name filter was used. Warning recorded:
    `unused import: TypeTree` at
    `async-opcua-server/tests/type_tree_snapshot.rs:17:36`.
  - Browse regression: 2026-07-01 `cargo test -p async-opcua-server browse -- --nocapture`
    exited `0`; focused Browse regression run passed with `9` tests run,
    `9 passed`, `0 failed`. Relevant focused test:
    `browse_reference_description_preserves_part4_5_9_2_2_and_7_29 ... ok`.
    Warning recorded: `unused import: TypeTree` at
    `async-opcua-server/tests/type_tree_snapshot.rs:17:36`. This supports
    OPC-10000-4 5.9.2.2 Browse ReferenceDescription behavior and OPC-10000-4
    7.29 ReferenceDescription field preservation after TypeTree snapshot
    conversion.
  - Query regression: 2026-07-01 `cargo test -p async-opcua-server query -- --nocapture`
    exited `0`; focused Query regression run passed after the stale
    TypeTree snapshot publication failure was fixed, including the 3
    `async-opcua-server/tests/query_tests.rs` tests that cover query type,
    path, and continuation behavior. Warning recorded: `unused import:
    TypeTree` at `async-opcua-server/tests/type_tree_snapshot.rs:17:36`.
    This supports OPC-10000-4 B.2.3 Query behavior after TypeTree snapshot
    conversion.
  - Read regression: 2026-07-01 `cargo test -p async-opcua-server read -- --nocapture`
    exited `0`; focused Read regression run passed with `35` tests run,
    `35 passed`, `0 failed`. Warning recorded: `unused import: TypeTree` at
    `async-opcua-server/tests/type_tree_snapshot.rs:17:36`. This supports
    OPC-10000-4 5.11.2.2 Read behavior after TypeTree snapshot conversion.
  - Write regression: 2026-07-01 `cargo test -p async-opcua-server write -- --nocapture`
    exited `0`; focused Write regression run passed with `15` tests run,
    `15 passed`, `0 failed`. Warning recorded: `unused import: TypeTree` at
    `async-opcua-server/tests/type_tree_snapshot.rs:17:36`. This supports
    OPC-10000-4 5.11.4.2 Write behavior after TypeTree snapshot conversion.
  - Subscription regression: 2026-07-01 `cargo test -p async-opcua-server subscription -- --nocapture`
    exited `0`; focused subscription regression run passed with `47` tests
    under the filter: `45 passed`, `0 failed`, `2 ignored`. Failed test
    names: none. Warning recorded: `unused import: TypeTree` at
    `async-opcua-server/tests/type_tree_snapshot.rs:17:36`. This supports
    OPC-10000-4 5.13 Subscription service behavior and OPC-10000-4 5.14
    MonitoredItem and Publish behavior after TypeTree snapshot conversion.
  - Static lock checks: Covered by the final cross-slice clippy lock-check
    recorded below; no `clippy::await_holding_lock` or
    `clippy::await_holding_refcell_ref` diagnostics were emitted.
- **Benchmark/measurement results**:
  - Controlled Read before/after samples: 2026-07-01 accepted TypeTree
    snapshot controlled Read measurement for SC-004 using the baseline
    T008/T019 command
    `cargo run -p async-opcua-localhost-bench -- run --op read --port 4840 --warmup 1.0 --measure 5.0`.
    Accepted run exited `0`; accepted JSON sample:
    `{"endpoint":"opc.tcp://127.0.0.1:4840","op":"read","node":"ns=2;i=1000","warmup_ok":6568,"warmup_bad":0,"ok":32284,"bad":0,"seconds":5.000077657,"ops_per_sec":6456.699718413993,"first_bad":"0x00000000"}`.
    Controller corroborating run exited `0` with `ops_per_sec`
    `6303.338064660845` and `first_bad` `0x00000000`. Earlier pre-fix
    run exited `1` with blocker `bench namespace was not registered`; the
    controller fixed stale generic in-memory builder TypeTree snapshot
    publication before the accepted run. This records measurement evidence
    only; T063 owns the SC-004 comparison conclusion.
  - Controlled Write before/after samples: 2026-07-01 accepted TypeTree
    snapshot controlled Write measurement for SC-004 using the baseline
    T009/T019 command
    `cargo run -p async-opcua-localhost-bench -- run --op write --port 4840 --warmup 1.0 --measure 5.0`.
    Accepted run exited `0`; accepted JSON sample:
    `{"endpoint":"opc.tcp://127.0.0.1:4840","op":"write","node":"ns=2;i=1000","warmup_ok":5096,"warmup_bad":0,"ok":30512,"bad":0,"seconds":5.000027359,"ops_per_sec":6102.366609070389,"first_bad":"0x00000000"}`.
    Cargo printed `Blocking waiting for file lock on build directory` before
    the run, then completed successfully. This records measurement evidence
    only; T063 owns the SC-004 comparison conclusion.
  - Prior comparison samples from Feature 045: local scratch artifacts from
    `../scratch/opcua-localhost-bench/` provide candidate before samples from
    the previous controlled-benchmark work. Relevant async-opcua samples
    include `perf-20260630-b92d983f-4e74d40-async-read.client.log`
    (`50393.997` ops/sec), `perf-20260630-b92d983f-4e74d40-async-write.client.log`
    (`46948.077` ops/sec), `perf-async-read-client.log` (`101017.898`
    ops/sec), and `perf-async-write-client.log` (`96784.516` ops/sec). These
    were release/standalone profiler-style samples, not the non-release
    one-shot `cargo run` samples recorded above.
  - SC-004 comparison conclusion: Inconclusive for Slice 1, and no performance
    improvement is proven. Baseline.md T019 requires at least three controlled
    localhost before and at least three after samples for both Read and Write,
    compared by median throughput. The current committed evidence has fewer
    than three accepted after-change samples, and the current after samples are
    not apples-to-apples with the prior scratch samples because they were run
    with a different build/mode shape. If compared anyway, the result is a
    large throughput drop, not an improvement: the accepted Read sample
    (`6456.699718413993` ops/sec) is about `87.19%` below the lower prior
    scratch Read sample and about `93.61%` below the later scratch Read sample;
    the accepted Write sample (`6102.366609070389` ops/sec) is about `87.00%`
    below the lower prior scratch Write sample and about `93.69%` below the
    later scratch Write sample. Follow-up needed to prove SC-004: capture at
    least three before and three after samples with the same command, build
    profile, run mode, warmup, measurement duration, node, and machine
    conditions, compare medians, and document any drop over 5% with accepted
    noise/rationale.
- **Gate decision**:
  - Decision: Pass for implemented TypeTree snapshot behavior; SC-004
    throughput comparison remains inconclusive and does not show a measured
    improvement.
  - Rationale: Focused TypeTree, Browse, Query, Read, Write, and subscription
    verification passed with the OPC-10000-4 clause coverage recorded above.
    Snapshot publication removes the global TypeTree read lock from hot-path
    metadata lookups without changing the service semantics covered by
    OPC-10000-4 5.9.2.2, 7.29, B.2.3, 5.11.2.2, 5.11.4.2, 5.13, and 5.14.
    The performance acceptance claim is limited because the prior scratch
    samples and current after samples are not comparable as recorded, and raw
    comparison would show a throughput drop rather than an improvement.
  - Reviewer/date: Codex, 2026-07-01
- **Rollback scope**: Revert or inspect only the TypeTree snapshot changes in
  `async-opcua-server/src/info.rs`,
  `async-opcua-server/src/node_manager/context.rs`,
  `async-opcua-server/src/node_manager/memory/mod.rs`,
  `async-opcua-server/src/server.rs`,
  `async-opcua-server/src/server_handle.rs`,
  `async-opcua-server/src/session/message_handler.rs`,
  `async-opcua-server/src/session/services/view.rs`,
  `async-opcua-server/src/session/services/query.rs`,
  `async-opcua-server/src/session/services/monitored_items.rs`,
  `async-opcua-server/src/subscriptions/actor.rs`,
  `async-opcua-server/src/address_space/utils.rs`, and
  `async-opcua-server/src/diagnostics/node_manager.rs`, plus focused
  TypeTree snapshot tests if they must be aligned. Preserve P3 gate evidence
  and unrelated slices. After rollback, re-run or inspect Browse, Query, Read,
  Write, and Subscription coverage for the cited OPC UA clauses before
  accepting the rollback.
- **Final review notes**: Complete for this feature. The implemented slice is
  limited to TypeTree snapshot publication and hot-path snapshot reads; no P3
  lock-boundary implementation is included here.

## Slice 2: Response-Size Limit State

- **Boundary**: Response-size enforcement moves from shared global state to
  channel-local or equivalent hot-path lock-free state.
- **Priority**: P2
- **Baseline reference**: `baseline.md` T002, T007
- **Contract reference**: `contracts/implementation-slices.md` Slice 2
- **Requirements and criteria**: FR-009, FR-010; SC-002, SC-003
- **Primary scope**: `async-opcua-core/src/comms/buffer.rs`,
  `async-opcua-core/src/comms/secure_channel.rs`,
  `async-opcua-server/src/session/manager.rs`,
  `async-opcua-server/src/session/controller.rs`
- **OPC UA clause references**: OPC-10000-4 5.7.2.2, 5.3, 7.38.2
- **Expected-red evidence**:
  - Date: 2026-07-01
  - Test or command: `cargo test -p async-opcua-core response_limit_state -- --nocapture`
  - Result: Exit code `101`; compile failed with `E0599` because
    `SecureChannel` does not yet have `set_client_response_body_limit` or
    `client_response_body_limit`. All errors are from
    `async-opcua-core/tests/response_limit_state.rs` at calls to those future
    APIs, for example lines 72, 73, 90, 91, 111, 131, 151, 159, 161, 162,
    176, 177, 189, 190, 192, and 193.
  - Notes: Worker confirmed this is expected-red for the future channel-local
    response-limit API and not an unrelated syntax/import issue. Tests
    T064-T069 cover OPC-10000-4 5.7.2.2 `maxResponseMessageSize`
    zero/nonzero behavior, OPC-10000-4 5.3 oversized response error surface,
    and OPC-10000-4 7.38.2 `BadResponseTooLarge` status semantics.
- **Implementation notes**:
  - Security-focused review for T072-T078: Response-size state moved from a
    process-wide `OnceLock<Mutex<HashMap<...>>>` in
    `async-opcua-core/src/comms/buffer.rs` to per-`SecureChannel` storage in
    `async-opcua-core/src/comms/secure_channel.rs`. `SendBuffer::write` now
    reads `secure_channel.client_response_body_limit()` directly for
    server-side non-ServiceFault response bodies, preserving
    `BadResponseTooLarge` status and request context on oversized responses.
    `SessionManager` now recomputes the minimum nonzero live, non-closed
    session `maxResponseMessageSize` for the current channel and applies it
    via `SecureChannel::set_client_response_body_limit`; zero or no live limit
    clears the channel state. `SessionController` now passes
    `&mut self.channel` through CreateSession commit instead of global
    body-limit keys. Security/fidelity notes: zero means unlimited per
    OPC-10000-4 5.7.2.2; nonzero limits are per channel/session with no global
    leakage; ServiceFault exclusion is preserved; stale CreateSession draft
    rejection remains based on the channel id; this removes a global mutex from
    the response hot path without changing OPC UA status semantics.
    Verification available so far: `cargo check -p async-opcua-core` passed
    after T076, and `cargo check -p async-opcua-server` passed after T078.
    Post-implementation response-limit tests are not claimed here; T080/T081
    own that evidence.
- **Verification command/results**:
  - Response-limit unit tests: 2026-07-01 required task command
    `cargo test -p async-opcua-core response_limit_state -- --nocapture`
    exited `0`; Cargo's name filter ran one matching test,
    `closed_channel_drops_response_limit_state`, and it passed. Controller
    follow-up for full integration file coverage,
    `cargo test -p async-opcua-core --test response_limit_state -- --nocapture`,
    exited `0`; all 6 tests passed: `zero_limit_preserves_part4_5_7_2_2_unbounded_response_size`,
    `nonzero_limit_applies_part4_5_7_2_2_response_body_limit`,
    `oversized_response_returns_part4_5_3_bad_response_too_large`,
    `bad_response_too_large_matches_part4_7_38_2_status`,
    `concurrent_channels_use_independent_response_limits`, and
    `closed_channel_drops_response_limit_state`; summary `6 passed`,
    `0 failed`. Both runs emitted the same warning:
    `async-opcua-core/tests/response_limit_state.rs` triggered
    `missing documentation for the crate` due to `-W missing-docs`. This
    verifies OPC-10000-4 5.7.2.2 zero/nonzero `maxResponseMessageSize`
    behavior and channel/session-specific response body limits, OPC-10000-4
    5.3 oversized response service-error surfacing, and OPC-10000-4 7.38.2
    `BadResponseTooLarge` status value.
  - maxResponseMessageSize integration tests: 2026-07-01
    `cargo test -p async-opcua-server max_response_message_size -- --nocapture`
    exited `0`; targeted integration test passed:
    `max_response_message_size_rejects_serialized_read_response_body_above_client_limit ... ok`.
    Failed test names: none. Warning recorded: `unused import: TypeTree` at
    `async-opcua-server/tests/type_tree_snapshot.rs:17:36`. This verifies
    OPC-10000-4 5.7.2.2 `maxResponseMessageSize` behavior for rejecting
    serialized Read response bodies above the client limit.
  - Static lock checks: 2026-07-01
    `cargo clippy --workspace --all-targets --all-features --locked -- -W clippy::await_holding_lock -W clippy::await_holding_refcell_ref`
    exited `0`; no `clippy::await_holding_lock` or
    `clippy::await_holding_refcell_ref` diagnostics were emitted. Observed
    warnings, not fixed here: `async-opcua-core/tests/response_limit_state.rs:56:9`
    `clippy::unimplemented`,
    `async-opcua-core/tests/response_limit_state.rs:1:1` `missing-docs`, and
    `async-opcua-server/tests/type_tree_snapshot.rs:17:36` unused import
    `TypeTree`. This supports the response-size slice's hot-path lock goal by
    showing no await-holding lock/refcell diagnostics after moving response
    limit state to `SecureChannel`.
- **Benchmark/measurement results**: Not separately benchmarked for this
  feature. Evidence is the removal of the global response-limit map from the
  response serialization path plus focused Part 4 behavior tests and clippy
  lock checks.
- **Gate decision**:
  - Decision: Pass for implemented response-size state behavior.
  - Rationale: Response-size enforcement is now channel-owned on
    `SecureChannel`; focused unit and integration tests passed for
    OPC-10000-4 5.7.2.2 zero/nonzero `maxResponseMessageSize`,
    OPC-10000-4 5.3 oversized response handling, and OPC-10000-4 7.38.2
    `BadResponseTooLarge` status semantics. The final clippy lock-check
    emitted no await-holding lock/refcell diagnostics.
  - Reviewer/date: Codex, 2026-07-01
- **Rollback scope**: Revert or inspect only the response-limit state changes
  in `async-opcua-core/src/comms/buffer.rs`,
  `async-opcua-core/src/comms/secure_channel.rs`,
  `async-opcua-server/src/session/manager.rs`, and
  `async-opcua-server/src/session/controller.rs`. Keep TypeTree snapshot work,
  P3 gate evidence, and unrelated slices intact. After rollback, re-run or
  inspect response-limit coverage for OPC-10000-4 5.7.2.2 zero/nonzero
  `maxResponseMessageSize`, OPC-10000-4 5.3 oversized response handling, and
  OPC-10000-4 7.38.2 `BadResponseTooLarge` status semantics before accepting
  the rollback.
- **Final review notes**: Complete for this feature. The slice moved
  response-size state to `SecureChannel` and preserved the OPC UA Part 4 error
  surface covered by the focused tests.

## Slice 3: Subscription Route Index Snapshot

- **Boundary**: Subscription routing and fanout may move to a measured
  route-index snapshot only after proof that the route lock is material.
- **Priority**: P3
- **Baseline reference**: `baseline.md` T003
- **Contract reference**: `contracts/implementation-slices.md` Slice 3
- **Requirements and criteria**: FR-006, FR-009, FR-010; SC-005
- **Primary scope**: `async-opcua-server/src/subscriptions/actor.rs`,
  subscription manager and notification fanout call sites
- **OPC UA clause references**: OPC-10000-4 5.13, 5.13.2.1, 5.13.3.1,
  5.14, 5.14.1.2, 6.7
- **Expected-red evidence**:
  - Test or command: Not applicable for this P3 gate-only slice.
  - Result: Deferred implementation; focused gate tests were added and run
    before any route-index snapshot implementation is accepted.
  - Notes: This feature records route-index evidence and regression coverage
    only.
- **Implementation notes**: No subscription route-index snapshot
  implementation was performed in this feature. The source changes for this
  slice are limited to focused gate tests and evidence notes.
- **Verification command/results**:
  - Subscription route tests: 2026-07-01 PASS. Command:
    `cargo test -p async-opcua-server subscription_route_snapshot -- --nocapture`.
    Exit code: 0. Tests run: 8; passed: 8; failed: 0; ignored: 0. Failed
    test names: none. Important warnings: none emitted. Coverage includes the
    T087-T092 monitored-item create/delete/modify, subscription transfer,
    Republish, and Publish notification probes plus existing route snapshot
    guard/no-match/sampling tests, grounded in OPC-10000-4 5.13, 5.13.2.1,
    5.13.3.1, 5.14, 5.14.1.2, and 6.7.
  - Protocol regression checks: Covered by the focused subscription route gate
    command above, including create/delete/modify, transfer, Republish, and
    Publish route behavior.
- **Benchmark/measurement results**:
  - Contention or fanout evidence: 2026-07-01 baseline/evidence-source
    registration only. Use the baseline T015 focused command
    `cargo test -p async-opcua-server subscription_route_snapshot -- --nocapture`
    as the repeatable source for later subscription route-cache contention and
    fanout evidence. Relevant current sources are
    `async-opcua-server/src/subscriptions/mod.rs`, including
    `SubscriptionCache::inner: RwLock<SubscriptionCacheInner>` and current route
    behavior; `async-opcua-server/src/subscriptions/notify.rs`, including the
    owned route snapshot and lookup paths; and the existing focused test
    sources `async-opcua-server/tests/subscription_route_snapshot_enqueue.rs`,
    `async-opcua-server/tests/subscription_route_snapshot_no_match.rs`, and
    `async-opcua-server/tests/subscription_route_snapshot_sampling.rs`. Evidence
    intent is to capture proof about route-cache guard scope, no-match route
    allocation/fanout behavior, and sampling/delete race behavior before any
    lock-removal or route-index snapshot implementation is accepted, tied to
    OPC-10000-4 5.13, 5.13.2.1, 5.13.3.1, 5.14, 5.14.1.2, and 6.7. This entry
    does not run the focused command, is not a gate pass, and is not approval to
    implement route-index snapshots; T093 owns the final focused run after
    T087-T092 add tests, and T095 records the completed Slice 3 gate decision.
  - Before/after comparison if implemented: Not applicable here because the
    route-index implementation is deferred.
- **Gate decision**:
  - Decision: Pass for follow-up planning; implementation deferred from this
    feature.
  - Rationale: T086 recorded baseline/evidence-source registration only, not a
    gate pass and not approval for a route-index snapshot implementation. T094
    then ran
    `cargo test -p async-opcua-server subscription_route_snapshot -- --nocapture`
    with exit code `0`, `8` tests run, `8` passed, `0` failed, `0` ignored,
    and no warnings. The focused coverage now documents the current route
    semantics to preserve before any route-index snapshot change is planned:
    monitored-item create/delete/modify and subscription transfer behavior
    under OPC-10000-4 5.13, including 5.13.2.1 and 5.13.3.1; MonitoredItem,
    Publish, and Republish behavior under OPC-10000-4 5.14, including
    5.14.1.2; and service error/status preservation under OPC-10000-4 6.7.
    Because this P3 gate produced measurement/proof evidence but no lock
    removal implementation, it passes only for creating/planning a follow-up
    implementation feature and explicitly defers implementation from this
    feature.
  - Reviewer/date: Codex, 2026-07-01
- **Rollback scope**: Remove only the Slice 3 focused gate tests and evidence
  notes if this gate evidence must be backed out. Do not revert the TypeTree
  snapshot or response-size implemented slices.
- **Final review notes**: Complete as a follow-up planning gate. Route-index
  implementation remains out of scope for this feature.

## Slice 4: PubSub Configuration and Transport Cache

- **Boundary**: PubSub configuration and transport cache locks may move to a
  config actor or draft/commit publication pattern after measurement.
- **Priority**: P3
- **Baseline reference**: `baseline.md` T004
- **Contract reference**: `contracts/implementation-slices.md` Slice 4
- **Requirements and criteria**: FR-006, FR-009, FR-010; SC-005
- **Primary scope**: `async-opcua-pubsub/src/config_methods.rs`,
  `async-opcua-pubsub/src/transport/`
- **OPC UA clause references**: OPC-10000-14 5.4.1.2, 9.1.5.2, 9.1.7.2,
  9.1.10.1
- **Expected-red evidence**:
  - Test or command: Not applicable for this P3 gate-only slice.
  - Result: Deferred implementation; focused PubSub config/cache tests were
    added and run before any PubSub lock-removal implementation is accepted.
  - Notes: This feature records PubSub gate evidence only.
- **Implementation notes**: No PubSub config/cache actor or draft/commit
  implementation was performed in this feature. The only source change in this
  area is narrow `#[doc(hidden)]` AMQP cache inspection visibility used by the
  gate test.
- **Verification command/results**:
  - PubSub config/cache tests: 2026-07-01 PASS after T100 corrective pass.
    Focused command:
    `cargo test -p async-opcua-pubsub config_snapshot_consistency -- --nocapture`.
    Exit status: `0`. For
    `async-opcua-pubsub/tests/config_snapshot_consistency.rs`, `4` tests ran,
    `4` passed, `0` failed, and `0` ignored. No compiler warnings or failures
    were present. The four focused tests cover OPC-10000-14 9.1.5.2
    PubSubConnection configuration, OPC-10000-14 9.1.7.2 DataSetWriter
    configuration, OPC-10000-14 9.1.10.1 PubSubStatus consistency, and
    OPC-10000-14 5.4.1.2 transport message sending cache behavior. History:
    an earlier T101 run failed to compile because AMQP cache inspection helpers
    were not visible to integration tests; T100 exposed narrow
    `#[doc(hidden)]` inspection methods without changing behavior, and the
    post-fix focused command passed.
  - Protocol regression checks: Covered by the focused PubSub
    `config_snapshot_consistency` gate command above.
- **Benchmark/measurement results**:
  - Config or cache contention evidence: 2026-07-01 baseline/evidence-source
    registration only. Use the baseline T016 focused command
    `cargo test -p async-opcua-pubsub config_snapshot_consistency -- --nocapture`
    as the repeatable source for later PubSub configuration-manager and
    transport-cache contention or consistency evidence. The expected focused
    test file is
    `async-opcua-pubsub/tests/config_snapshot_consistency.rs`; baseline T016
    records that it does not exist yet and that T101 owns the final focused
    run after T097-T100 add the gate tests. Current supporting discovery
    sources are `async-opcua-pubsub/src/config_methods.rs`, including
    `Arc<Mutex<PubSubConfigManager>>`, address-space reflection, and Part 14
    configuration Methods; `async-opcua-pubsub/src/engine.rs`, including
    copied `PubSubConnectionConfig` values used when transport loops start;
    `async-opcua-pubsub/src/pubsub_model.rs`, including PubSub configuration,
    DataSetWriter, DataSetReader, and status model types; and the current
    related behavior tests `async-opcua-pubsub/tests/pubsub_model_tests.rs`,
    `async-opcua-pubsub/tests/engine_tests.rs`,
    `async-opcua-pubsub/tests/pubsub_tests.rs`,
    `async-opcua-pubsub/tests/datasetreader_tests.rs`, and
    `async-opcua-pubsub/tests/subscriber_status_tests.rs`. Evidence intent is
    to capture config manager lock contention, reflected Part 14 configuration
    consistency, DataSetWriter/DataSetReader/PubSubStatus consistency,
    transport message sending cache behavior, or equivalent proof before any
    PubSub config/cache lock removal is accepted, tied to OPC-10000-14
    5.4.1.2, 9.1.5.2, 9.1.7.2, and 9.1.10.1. This entry does not run the
    focused command, is not a gate pass, and is not approval to implement
    PubSub config/cache refactoring; T103 records the completed Slice 4 gate
    decision.
  - Before/after comparison if implemented: Not applicable here because the
    PubSub config/cache implementation is deferred.
- **Gate decision**:
  - Decision: Pass for follow-up planning/evidence; implementation deferred
    from this feature.
  - Rationale: The Slice 4 PubSub gate has sufficient focused evidence to plan
    a follow-up PubSub configuration/transport-cache lock-removal feature, but
    this feature does not claim or accept a full PubSub config/cache
    implementation. The post-fix focused command
    `cargo test -p async-opcua-pubsub config_snapshot_consistency -- --nocapture`
    exited `0` with `4` tests run, `4` passed, `0` failed, and `0` ignored,
    with no warnings. The passing tests cover OPC-10000-14 9.1.5.2
    PubSubConnection configuration, OPC-10000-14 9.1.7.2 DataSetWriter
    configuration, OPC-10000-14 9.1.10.1 PubSubStatus consistency, and
    OPC-10000-14 5.4.1.2 transport message sending cache behavior. The narrow
    AMQP `#[doc(hidden)]` cache-inspection visibility fix enabled integration
    gate evidence without changing behavior.
  - Reviewer/date: Codex, 2026-07-01
- **Rollback scope**: Remove only the PubSub focused gate test, AMQP
  inspection-helper visibility change, and Slice 4 evidence notes if this gate
  evidence must be backed out. Do not revert the implemented TypeTree or
  response-size slices.
- **Final review notes**: Complete as a follow-up planning gate. PubSub
  config/cache lock-removal implementation remains out of scope for this
  feature.

## Slice 5: SQLite History Scaling

- **Boundary**: SQLite history backend locking may move to a DB actor or
  read-pool/write-owner design only if measurement justifies scaling.
- **Priority**: P3
- **Baseline reference**: `baseline.md` T005
- **Contract reference**: `contracts/implementation-slices.md` Slice 5
- **Requirements and criteria**: FR-006, FR-009, FR-010; SC-005
- **Primary scope**: `async-opcua-history-sqlite/src/backend.rs`
- **OPC UA clause references**: OPC-10000-11 6.3; OPC-10000-4 5.11.3.2
- **Expected-red evidence**:
  - Test or command:
    `cargo test -p async-opcua-history-sqlite history_lock_scaling -- --nocapture`
  - Result: Not run for T104. T109 owns the final focused command run after
    `async-opcua-history-sqlite/tests/history_lock_scaling.rs` exists.
  - Notes: Evidence source registered from `baseline.md` T017. The focused
    file does not exist yet; until T105-T108 add it, supporting discovery
    sources remain `async-opcua-history-sqlite/src/backend.rs`,
    `async-opcua-history-sqlite/src/query.rs`,
    `async-opcua-history-sqlite/tests/history_update_data.rs`,
    `async-opcua-history-sqlite/tests/history_events.rs`,
    `async-opcua-history-sqlite/tests/query_migration.rs`, and
    `async-opcua-server/src/services/history_read.rs`.
- **Implementation notes**: No SQLite DB actor, read-pool, or write-owner
  implementation was performed in this feature. The source changes for this
  slice are limited to focused gate tests and evidence notes.
- **Verification command/results**:
  - Focused command:
    `cargo test -p async-opcua-history-sqlite history_lock_scaling -- --nocapture`
  - Result: Exit status 0. For
    `async-opcua-history-sqlite/tests/history_lock_scaling.rs`, 4 tests ran,
    4 passed, 0 failed, and 0 ignored.
  - Notes: No compiler warnings or failures were present. Other test binaries
    ran 0 tests because the filter excluded their tests.
  - Coverage: The four focused tests cover OPC-10000-11 6.3 continuation-point
    behavior, OPC-10000-4 5.11.3.2 `HistoryRead` `nodesToRead`
    request-order/node isolation, concurrent SQLite raw reads, and
    write-during-continuation-read ordered visibility.
- **Benchmark/measurement results**:
  - Read/write contention evidence: Deferred final measurement. T104 baseline
    registration uses the T017 command/source to target SQLite history
    read/write lock contention or throughput, continuation-point behavior,
    OPC-10000-4 5.11.3.2 `HistoryRead` `nodesToRead` behavior, concurrent
    reads, writes during reads, or equivalent proof before SQLite history lock
    removal is accepted.
  - Before/after comparison if implemented: Not applicable here because the
    SQLite history lock-removal implementation is deferred.
- **Gate decision**:
  - Decision: Pass for follow-up planning/evidence; SQLite history lock-removal
    implementation remains deferred from this feature.
  - Rationale: The focused SQLite history scaling command
    `cargo test -p async-opcua-history-sqlite history_lock_scaling -- --nocapture`
    exited `0` with 4 tests run, 4 passed, 0 failed, 0 ignored, and no
    warnings. The evidence covers OPC-10000-11 6.3 continuation-point behavior
    and OPC-10000-4 5.11.3.2 `HistoryRead` `nodesToRead`
    request-order/node isolation, plus concurrent SQLite raw reads and
    write-during-continuation-read ordered visibility. This is sufficient to
    record the Slice 5 gate as planned evidence for a future SQLite history
    scaling follow-up, but it does not claim a completed DB actor,
    read-pool/write-owner design, or full SQLite history lock-removal
    implementation.
  - Reviewer/date: Codex, 2026-07-01
- **Rollback scope**: Remove only the SQLite history focused gate test and
  Slice 5 evidence notes if this gate evidence must be backed out. Do not
  revert the implemented TypeTree or response-size slices.
- **Final review notes**: Complete as a follow-up planning gate. SQLite
  history lock-removal implementation remains out of scope for this feature.

## Slice 6: SecureChannel Renewal

- **Boundary**: SecureChannel renewal locking may move to a single-flight state
  machine only after contention proof and ordering/cancellation tests.
- **Priority**: P3
- **Baseline reference**: `baseline.md` T006
- **Contract reference**: `contracts/implementation-slices.md` Slice 6
- **Requirements and criteria**: FR-006, FR-009, FR-010; SC-005
- **Primary scope**: `async-opcua-client/src/transport/channel.rs`
- **OPC UA clause references**: OPC-10000-6 6.7.4, 6.7.2.4
- **Expected-red evidence**:
  - Test or command: Not applicable for this P3 gate-only slice.
  - Result: Deferred implementation; focused SecureChannel renewal tests were
    added and run before any mutex-removal/single-flight implementation is
    accepted.
  - Notes: This feature records renewal gate evidence only.
- **Implementation notes**: No SecureChannel renewal mutex removal or
  single-flight state-machine implementation was performed in this feature.
  The source changes for this slice are limited to focused gate tests and
  evidence notes.
- **Verification command/results**:
  - SecureChannel renewal tests: 2026-07-01 PASS. Command:
    `cargo test -p async-opcua-client secure_channel_renewal_singleflight -- --nocapture`.
    Exit code: 0. Test file:
    `async-opcua-client/tests/secure_channel_renewal_singleflight.rs`.
    Tests run: 4; passed: 4; failed: 0; ignored: 0. Failed test names: none.
    No compiler warnings were emitted. Cargo printed package-cache and
    build-directory lock waits before running tests; the command still
    completed successfully. Coverage includes OPC-10000-6 6.7.4 concurrent
    renewal waiters, renewal cancellation, and renewal failure, plus
    OPC-10000-6 6.7.2.4 renewal request ordering/correlation.
  - Ordering/correlation regression checks: Covered by the focused
    `secure_channel_renewal_singleflight` run above.
- **Benchmark/measurement results**:
  - Renewal contention evidence: 2026-07-01 baseline/evidence-source
    registration only. Use the baseline T018 focused command
    `cargo test -p async-opcua-client secure_channel_renewal_singleflight -- --nocapture`
    as the repeatable source for later SecureChannel renewal contention and
    protocol-fidelity evidence. The expected focused test file is
    `async-opcua-client/tests/secure_channel_renewal_singleflight.rs`; it does
    not exist yet and T113-T116 own adding the concurrent-renewal-waiters,
    renewal-cancellation, renewal-failure, and renewal-request-ordering tests.
    T117 owns the final focused run. Supporting discovery sources before that
    file exists are `async-opcua-client/src/transport/channel.rs`,
    `async-opcua-client/src/transport/state.rs`,
    `async-opcua-client/src/transport/core.rs`,
    `async-opcua-client/tests/hostile_server.rs`, and
    `async-opcua-client/tests/common/hostile_server.rs`. Evidence must show
    `issue_channel_lock` wait time or waiter count, concurrent renewal waiters,
    renewal cancellation, renewal failure, renewal request ordering, or
    equivalent proof before any SecureChannel renewal mutex removal or
    single-flight implementation is accepted. This T112 registration cites
    OPC-10000-6 6.7.4 and 6.7.2.4, records no executed `-- --nocapture`
    result, and does not mark the Slice 6 gate as passed.
  - Before/after comparison if implemented: Not applicable here because the
    SecureChannel renewal implementation is deferred.
- **Gate decision**:
  - Decision: Pass for follow-up planning/evidence; implementation deferred
    from this feature.
  - Rationale: Pass for follow-up planning and recorded evidence only. The
    focused Slice 6 command
    `cargo test -p async-opcua-client secure_channel_renewal_singleflight -- --nocapture`
    exited `0` on 2026-07-01 with 4 tests run, 4 passed, 0 failed, 0 ignored,
    and no compiler warnings. That evidence covers OPC-10000-6 6.7.4
    concurrent renewal waiters, cancellation, and failure behavior, and
    OPC-10000-6 6.7.2.4 renewal request ordering/correlation. This gate does
    not claim a completed SecureChannel renewal mutex removal or single-flight
    state-machine implementation; those remain deferred from this feature until
    a separately scoped follow-up has sufficient contention proof and
    implementation evidence.
  - Reviewer/date: Codex, 2026-07-01
- **Rollback scope**: Remove only the SecureChannel renewal focused gate test
  and Slice 6 evidence notes if this gate evidence must be backed out. Do not
  revert the implemented TypeTree or response-size slices.
- **Final review notes**: Complete as a follow-up planning gate.
  SecureChannel renewal mutex-removal/single-flight implementation remains out
  of scope for this feature.

## Cross-Slice Final Evidence

- **Formatting result**: Pass. Initial `cargo fmt --check` failed only on
  `async-opcua-client/tests/secure_channel_renewal_singleflight.rs`; after a
  narrow formatting pass for that file, repository-root `cargo fmt --check`
  exited 0 with no output.
- **Final clippy lock-check result**: Pass. 2026-07-01
  `cargo clippy --workspace --all-targets --all-features --locked -- -W clippy::await_holding_lock -W clippy::await_holding_refcell_ref`
  exited `0`; no `clippy::await_holding_lock` or
  `clippy::await_holding_refcell_ref` diagnostics were emitted, and no other
  warnings or failures were present.
- **Workspace test result or targeted substitute rationale**: Pass. 2026-07-01
  repository-root `cargo test --workspace --all-targets --all-features --locked`
  exited `0`; the workspace built successfully and all captured test suites
  completed with `ok`, including examples with `297` integration tests passing,
  `301` server unit tests passing with `2` ignored, and the new
  snapshot-related tests passing. No Rust compiler warnings were captured.
  Expected `ERROR` log lines from negative-path/security tests and bench
  harness messages `Gnuplot not found, using plotters backend` were present,
  but the affected tests and harnesses still reported success.
- **No raw seqlock/custom unsafe lock-free/relaxed-ordering audit**:
  2026-07-01 scoped static audit result: Pass for this feature's changed
  source files and feature-relevant workspace paths. Commands used `rg` for
  seqlock terms, unsafe/custom-pointer terms, atomic/relaxed-ordering terms,
  and lock-free crate/pattern terms. No raw seqlock terms were found in
  `async-opcua-core`, `async-opcua-server`, `async-opcua-client`,
  `async-opcua-pubsub`, or `async-opcua-history-sqlite`. The changed TypeTree
  publication uses the mature `arc-swap` crate
  (`ServerInfo::type_tree_snapshot`) rather than a custom unsafe pointer
  structure, and the response-limit slice moves state onto `SecureChannel`
  without adding a custom atomic algorithm. Existing unrelated or pre-existing
  hits were limited to metrics/ID/port counters using `Ordering::Relaxed`,
  mature crate structures such as `DashMap` and `crossbeam_queue::ArrayQueue`,
  and allocation instrumentation `unsafe impl GlobalAlloc` in
  `async-opcua-server/src/subscriptions/subscription.rs`; these are not new
  raw seqlocks, custom unsafe lock-free structures, or relaxed-ordering schemes
  introduced by this feature.
- **Excluded lock-boundary diff audit**:
  2026-07-01 audit result: Pass. The tracked diff stayed within the
  implemented TypeTree snapshot and response-size per-channel state slices,
  plus P3 gate tests/evidence, and did not implement the excluded/deferred
  lock-boundary refactors: subscription route-index snapshot/SPSC, PubSub
  config/cache actor or draft/commit refactor, SQLite DB actor/read-pool/write-
  owner, or SecureChannel renewal mutex removal/state-machine. Inspected
  tracked diff with `git diff --stat`, `git diff --name-only`, and targeted
  diffs for response-size, subscription actor, PubSub AMQP transport, and the
  excluded owner paths. Source paths reviewed at a high level included
  `async-opcua-server/src` TypeTree/session/subscription files,
  `async-opcua-core/src/comms/{buffer.rs,secure_channel.rs}`,
  `async-opcua-pubsub/src/{config_methods.rs,transport/}`,
  `async-opcua-history-sqlite/src/backend.rs`, and
  `async-opcua-client/src/transport/channel.rs`. Test/evidence paths reviewed
  included the untracked focused gate tests under
  `async-opcua-server/tests`, `async-opcua-core/tests`,
  `async-opcua-pubsub/tests`, `async-opcua-history-sqlite/tests`, and
  `async-opcua-client/tests`. Because `specs/046-lock-removal-snapshots/` and
  the new focused tests are untracked, `git diff` could not show their content;
  this audit compensated by direct file inspection and `rg` sweeps for the
  excluded designs. The PubSub source diff was limited to exposing narrow
  `#[doc(hidden)]` AMQP cache inspection helpers for the gate test and was not
  a PubSub config/cache refactor.
- **OPC UA clause-matrix completion check**: Pass. 2026-07-01
  `specs/046-lock-removal-snapshots/opcua-clause-matrix.md` records final
  coverage status for every OPC UA clause cited by the implemented slices and
  P3 gates. Implemented TypeTree and response-size slices are covered by
  passing focused verification recorded in this file; P3 coverage remains
  explicitly limited to gate evidence for follow-up planning.
- **Final review checkpoint summary**: Complete for T134 on 2026-07-01. Final
  evidence records implemented TypeTree snapshot and response-size
  per-channel state slices, plus passing cross-slice `cargo fmt --check`,
  clippy lock-check, workspace test, raw seqlock/custom unsafe lock-free/
  relaxed-ordering, excluded-boundary, and OPC UA clause-matrix checks. P3
  subscription route, PubSub config/cache, SQLite history, and SecureChannel
  renewal gates passed for follow-up planning/evidence only; their
  implementations remain deferred from this feature.
