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
Verify that O(1) session lookups stay sub-microsecond and effectively constant
from 1,000 to 10,000 sessions, including under concurrent access:
```bash
cargo test -p async-opcua-server --features test-utils --test session_lookup
```

### Outbound Heap Allocations (SC-002)
Verify the zero-copy receive path (no buffer copies) and that serialization
metrics track the outbound write path:
```bash
cargo test -p async-opcua-core --test zero_copy_alloc --test serialization_alloc
```

### Session Task Contention (SC-003)
Verify the session actor sustains high-volume concurrent read/write traffic
from many tasks without lock contention, with read-after-write consistency:
```bash
cargo test -p async-opcua-server --features test-utils --test session_actor_load
```

### Notification Memory Stability (SC-004)
Verify the notification pool performs zero allocations at steady state and
blocks (rather than allocating) on exhaustion:
```bash
cargo test -p async-opcua-server --test subscription_pooling
```
