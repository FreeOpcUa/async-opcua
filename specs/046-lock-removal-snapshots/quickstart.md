# Quickstart: Lock Removal and Snapshot Concurrency

## 1. Confirm Active Feature

```bash
git branch --show-current
cat .specify/feature.json
```

Expected branch: `046-lock-removal-snapshots`

## 2. Baseline Lock Checks

```bash
cargo clippy --workspace --all-targets --all-features --locked -- \
  -W clippy::await_holding_lock \
  -W clippy::await_holding_refcell_ref
```

Record any new findings in the active slice notes before implementing a lock-removal task.

## 3. TypeTree Snapshot MVP Checks

Add expected-red tests first, then run the focused tests while implementing Slice 1:

```bash
cargo test -p async-opcua-server type_tree_snapshot -- --nocapture
cargo test -p async-opcua-server browse -- --nocapture
cargo test -p async-opcua-server query -- --nocapture
cargo test -p async-opcua-server read -- --nocapture
cargo test -p async-opcua-server write -- --nocapture
cargo test -p async-opcua-server subscription -- --nocapture
```

If a focused filter does not match existing tests, add the missing test named for the behavior it proves and record the replacement command in the slice notes.

## 4. Controlled Benchmark Sample

Use the controlled localhost benchmark feature as the measurement harness once available:

```bash
cargo run -p async-opcua-localhost-bench -- run --operation read --iterations 1000 --json
cargo run -p async-opcua-localhost-bench -- run --operation write --iterations 1000 --json
```

Record before/after samples for the TypeTree slice and for any P2/P3 slice that claims a performance improvement.

## 5. Response-Size Slice Checks

Before Slice 2 implementation, add tests for:

- zero advertised response limit
- nonzero response limit
- oversized response rejection
- multiple concurrent channels with different limits
- channel close cleanup

Run the final response-size checks:

```bash
cargo test -p async-opcua-core --test response_limit_state -- --nocapture
cargo test -p async-opcua-server max_response_message_size -- --nocapture
```

The task filter command
`cargo test -p async-opcua-core response_limit_state -- --nocapture` only runs
the matching test name; use `--test response_limit_state` for full integration
file coverage. Then rerun clippy lock checks.

## 6. P3 Slice Gate

Before implementing subscription route, PubSub, SQLite, or SecureChannel changes, create or update a slice note with:

- lock boundary and files
- baseline contention or throughput evidence
- expected-red tests
- OPC UA behavior that must remain unchanged
- rollback scope

## 7. Final Verification

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
```

If full workspace verification is not practical in the current environment, document the failure reason and run the narrowest targeted substitute that exercises every changed slice.
