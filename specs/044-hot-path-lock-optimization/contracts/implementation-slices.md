# Contract: Hot Path Lock Optimization Implementation Slices

Each future task generated from this plan must map to exactly one slice below unless explicitly split into smaller test/implementation/verification subtasks.

## Slice HPL-001: Server Read Callback Guard Boundary

- **Priority**: P1
- **Files**: `async-opcua-server/src/node_manager/memory/simple.rs`
- **Current evidence**: Read path holds address-space and read-callback registry guards before calling `read_node_value`.
- **OPC UA grounding**: OPC-10000-4 4.1 Attribute Service Set; Read behavior and per-node results must remain stable.
- **Required proof**: A Read callback can re-enter a safe node-manager operation or otherwise prove callback invocation occurs after read guards are released.
- **Task rule**: Do not combine with Write or Call callback changes unless tasks are explicitly split and verified separately.

## Slice HPL-002: Server Write Callback Guard Boundary

- **Priority**: P1
- **Files**: `async-opcua-server/src/node_manager/memory/simple.rs`
- **Current evidence**: Write path holds address-space, type-tree, and write-callback registry guards before calling `write_node_value`.
- **OPC UA grounding**: OPC-10000-4 4.1 Attribute Service Set; Write statuses and side effects must remain stable.
- **Required proof**: A Write callback runs outside address-space, type-tree, and callback-registry guards while preserving current status mapping.
- **Task rule**: Keep source write collection and subscription notification behavior unchanged unless a later slice owns it.

## Slice HPL-003: Server Method Callback Guard Boundary

- **Priority**: P1
- **Files**: `async-opcua-server/src/node_manager/memory/simple.rs`, `async-opcua-server/src/node_manager/memory/core.rs`
- **Current evidence**: Method callback registries are held while invoking plain and context-aware callbacks.
- **OPC UA grounding**: OPC-10000-4 4.1 Method Service Set and 5.12 method behavior; Call outputs and status behavior must remain stable.
- **Required proof**: Method callbacks execute outside registry guards in both simple and context-aware paths.
- **Task rule**: Split simple and core paths if one proof cannot cover both.

## Slice HPL-004: Client Publish Delivery Boundary

- **Priority**: P1
- **Files**: `async-opcua-client/src/session/services/subscriptions/service.rs`, `state.rs`, `mod.rs`
- **Current evidence**: Publish response handling locks `subscription_state` and reaches user callback delivery through `on_notification`.
- **OPC UA grounding**: OPC-10000-4 5.14.1 and 5.14.5; NotificationMessages, sequence numbers, and Publish acknowledgements must remain correct.
- **Required proof**: A callback can call back into subscription APIs without deadlocking and acknowledgements remain queued for notification data.
- **Task rule**: Delivery packet/view design must avoid borrowing guarded state after unlock.

## Slice HPL-005: `SyncSampler` Sampling Boundary

- **Priority**: P1
- **Files**: `async-opcua-server/src/node_manager/utils/sync_sampler.rs`
- **Current evidence**: Sampler map mutex is held while invoking sampler callbacks and `notify_data_change`.
- **OPC UA grounding**: OPC-10000-4 5.13.1.2 and 5.13.1.5; sampling interval and monitored-item queue behavior must remain stable.
- **Required proof**: Slow sampler execution does not hold the sampler map mutex and concurrent add/update/remove operations make progress.
- **Task rule**: Do not introduce per-sampler queues until this two-phase refactor is complete and measured.

## Slice HPL-006: Subscription Route Snapshot Boundary

- **Priority**: P1
- **Files**: `async-opcua-server/src/subscriptions/mod.rs`, `async-opcua-server/src/subscriptions/notify.rs`
- **Current evidence**: Notifier carries a global cache read guard through sampling closure execution and drop-time actor enqueue.
- **OPC UA grounding**: OPC-10000-4 5.13.2 through 5.13.6 and 5.14.1; monitored-item create/modify/delete races, notification queues, retransmission, and sequence behavior must remain stable.
- **Required proof**: Route lookup happens under the cache guard, while sampling closures and actor pushes occur after unlock.
- **Task rule**: Snapshot route metadata only; do not replace the route index structure in this slice.

## Slice HPL-007: SessionManager Dispatch Lookup Boundary

- **Priority**: P2
- **Files**: `async-opcua-server/src/session/controller.rs`
- **Current evidence**: Normal request dispatch opens a `SessionManager` read guard before lookup and proceeds toward validation in the same scope.
- **OPC UA grounding**: OPC-10000-4 7.32 and 7.35; authentication token lookup must remain tied to Session and SecureChannel/client-certificate context.
- **Required proof**: The read guard is released before validation and dispatch while current closed-session and invalid-session statuses remain unchanged.
- **Task rule**: Do not modify ActivateSession semantics in this task.

## Slice HPL-008: CreateSession Two-Phase Boundary

- **Priority**: P2
- **Files**: `async-opcua-server/src/session/controller.rs`, `async-opcua-server/src/session/manager.rs`
- **Current evidence**: Controller holds manager write guard while `create_session` performs limit checks, endpoint work, certificate work, session allocation, actor spawn, and metrics.
- **OPC UA grounding**: OPC-10000-4 5.7.2; CreateSession returns session identifiers/authentication token and is associated with SecureChannel context.
- **Required proof**: Public statuses for session limit, endpoint, certificate, and allocation cases remain unchanged; session limits are re-checked at commit.
- **Task rule**: Split into preparation, commit, and tests if needed; never publish a partially-created session.

## Slice HPL-009: Read/Write Lock Mode Cleanup

- **Priority**: P3
- **Files**: `async-opcua-client/src/transport/channel.rs`, `async-opcua-pubsub/src/subscriber.rs`
- **Current evidence**: Some read-only paths use write guards.
- **OPC UA grounding**: OPC-10000-6 SecureChannel certificate/security behavior; OPC-10000-14 PubSub message configuration/routing behavior.
- **Required proof**: Code evidence confirms no mutation occurs under the write guard being downgraded, and existing tests still pass.
- **Task rule**: One lock-mode cleanup per task unless the second is only a test fixture update.

## Slice HPL-010: Measurement Gate For Snapshot/SPSC Follow-Ups

- **Priority**: P3
- **Files**: `specs/044-hot-path-lock-optimization/snapshot-queue-baseline.md`, `async-opcua-server/src/subscriptions/mod.rs`, `async-opcua-server/src/subscriptions/notify.rs`
- **Current evidence**: Audit identifies the subscription route index as the selected read-mostly snapshot candidate for the measurement gate.
- **OPC UA grounding**: OPC-10000-4 5.13 and 5.14 for route snapshots; OPC-10000-6 6.7 for SecureChannel ordering if connection pipeline work is proposed.
- **Required proof**: Baseline measurement exists before design change; stale-snapshot or queue-backpressure tests exist before implementation is accepted.
- **Task rule**: This slice may create planning/benchmark scaffolding only; no broad rewrite without a new spec or explicit plan update.
