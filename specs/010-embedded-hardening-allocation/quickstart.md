# Quickstart / Verification: Embedded Hardening & Allocation Follow-ups

How to verify each story. All commands run from the workspace root.

## Gate before any change (baseline)

```bash
cargo fmt --all --check
cargo clippy --locked -- -D warnings
cargo test --workspace                              # full unit + integration; record pass count
cargo test -p async-opcua --test integration_tests  # the 98-test integration suite
# record the publish-allocation baseline:
cargo test -p async-opcua-server publish_allocation_baseline_reports_construction_and_clone -- --ignored --nocapture
```

## US1 — Hostile-input safety (P1) — SC-001/SC-002

- **Codec size guard (FR-002)**: regression test — a chunk declaring `message_size > max_message_size` is rejected with a protocol error and does not buffer toward it.
- **Recursion bound (FR-003)**: regression test — a structure nested past `max_decode_depth` returns a decode error (no stack overflow); at-limit succeeds.
- **GDS caps (FR-004)**: test — drive the registry past its cap; assert bounded size + defined overflow (FIFO-evict) behavior.
- **Panic sweep (FR-001)**: `cargo clippy` with the new scoped `deny` lints passes (zero unjustified panicking constructs); the fuzz pass finds **no panic/abort**:
  ```bash
  cargo +nightly fuzz run fuzz_deserialize -- -max_total_time=<n>   # and the other decode targets
  ```
- **Acceptance**: zero process aborts across the crafted/malformed/oversized/deeply-nested corpus; other clients stay served.

## US2 — Steady-state allocation (P2) — SC-003/SC-004/SC-005

- **Event-Vec pool (FR-005)**: extend the baseline harness to the event path; assert steady-state per-tick allocation is **constant** (independent of event count) after the pool primes; add a no-stale-data regression test (decreasing event-batch sizes).
- **Dispatch fast-path (FR-006)**: measure small-read per-request allocation before/after; assert a reduction with unchanged results.
- **Wire identity (FR-009)**: byte-equality — the full integration suite (98) passes and notification/response/republish bytes are unchanged.

## US3 — Embedded guidance + lean decode (P3) — SC-006/SC-007

- **Zero-copy decode (FR-007)**: measure string/bytestring/array decode allocations before/after on a shareable `Bytes` source; assert fewer allocations and identical decoded values.
- **Docs (FR-008)**: `docs/setup.md` contains a verifiable embedded-deployment section (recommended `current_thread` runtime + size-optimized build profile, trade-offs stated).

## Final gate (every story / before merge)

```bash
cargo fmt --all --check
cargo clippy --locked -- -D warnings
cargo test --workspace            # zero failures
```
Record before/after allocation numbers in each PR body (FR-010). Generated code untouched
(`verify-clean-codegen` green).
