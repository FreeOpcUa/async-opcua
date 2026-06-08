# Quickstart: Verifying Performance Optimizations

This guide explains how to compile, test, and benchmark the performance optimizations implemented in this phase.

---

## 1. Prerequisites & Compilation

Ensure you have Rust 1.75+ installed. Build the workspace in release mode to enable optimizations:

```bash
cargo build --release
```

---

## 2. Running Verification Tests

Run the full workspace unit and integration test suite to verify no regressions were introduced:

```bash
# Run all workspace tests (requires legacy-crypto feature for config compat if testing all features)
cargo test --workspace --all-features
```

To run the specific concurrency and load tests for the session lookups and address space:

```bash
cargo test -p async-opcua-server --test address_space_concurrency
```

---

## 3. Benchmarking Success Criteria

To quantitatively verify the success criteria defined in the specification:

### Session Lookup Latency (SC-001)
Verify that O(1) session lookups execute in under 10 microseconds.
Run the micro-benchmarks:
```bash
cargo bench -p async-opcua-server
```

### Outbound Heap Allocations (SC-002)
Verify that steady-state serialization has zero new heap allocations.
Run the server under a memory profiler (such as `dhat` or `valgrind`):
```bash
cargo test --profile release -p async-opcua-core --test serialization_profile
```

### Session Task Contention (SC-003)
Verify a 40% reduction in response latency under high concurrent read/write and publishing tasks on a single session.
Run the contention load simulation:
```bash
cargo run --release --bin session-load-simulator
```
