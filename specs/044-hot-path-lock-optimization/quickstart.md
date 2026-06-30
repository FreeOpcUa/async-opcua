# Quickstart: Hot Path Lock Optimization

Use the focused command for each atomic task before starting the next one. Replace `<exact_test_name>` with the test introduced by the task.

## Server Callback Guard Tasks

```bash
cargo test -p async-opcua-server <exact_test_name> -- --exact --nocapture
cargo test -p async-opcua-server node_manager -- --nocapture
```

Expected evidence:

- Read callback test proves callback execution after read guards are released.
- Write callback test proves callback execution after address-space, type-tree, and write-callback guards are released.
- Method callback test proves plain and context-aware callback registries are not held during invocation.
- Public Read, Write, and Call statuses remain unchanged.

## Client Subscription Delivery Task

```bash
cargo test -p async-opcua-client <exact_test_name> -- --exact --nocapture
cargo test -p async-opcua-client subscription -- --nocapture
```

Expected evidence:

- Publish acknowledgements are still queued before delivery.
- User callbacks execute outside `subscription_state`.
- Callback views do not borrow guarded subscription state after unlock.

## Sampler And Subscription Fanout Tasks

```bash
cargo test -p async-opcua-server <exact_test_name> -- --exact --nocapture
cargo test -p async-opcua-server subscription -- --nocapture
```

Expected evidence:

- Slow sampler callback does not hold the sampler map mutex.
- Concurrent sampler add/update/remove makes progress.
- Subscription route lookup occurs under cache guard, but sample closures and actor queue pushes happen after unlock.
- MonitoredItem create/modify/delete race expectations are tested.
- No-match route snapshots avoid sampling and fanout work.

## Session And CreateSession Tasks

```bash
cargo test -p async-opcua-server <exact_test_name> -- --exact --nocapture
cargo test -p async-opcua-server session -- --nocapture
```

Expected evidence:

- `SessionManager` read guard is lookup-only for normal dispatch.
- Validation and dispatch preserve invalid-session, closed-session, and activation behavior.
- CreateSession public statuses are unchanged.
- Session limits are re-checked during commit.

## P3 Measurement Or Cleanup Tasks

```bash
cargo test -p async-opcua-client <exact_test_name> -- --exact --nocapture
cargo test -p async-opcua-pubsub <exact_test_name> -- --exact --nocapture
```

For any snapshot, queue, or renewal design change, record a baseline first. The exact benchmark or tracing command must be named in that task before implementation begins.

## Full Completion Gate

```bash
cargo fmt --check
cargo test --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

## Documentation Evidence

Every completed task should update or cite:

- `specs/044-hot-path-lock-optimization/contracts/implementation-slices.md`
- `specs/044-hot-path-lock-optimization/contracts/lock-optimization-traceability.md`
- The OPC UA MCP reference named in the task
