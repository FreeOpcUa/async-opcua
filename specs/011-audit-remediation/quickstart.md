# Quickstart / Verification: Audit Remediation

All commands from the workspace root. Each user story is independently verifiable.

## Baseline gate (before any change)

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --workspace
cargo test -p async-opcua --test integration_tests   # the 98-test suite
```

## US1 — Bounded history reads (SC-001)

- Regression test (async-opcua-history-sqlite): populate a large interval, call `read_raw_modified`
  with a wide range and small `num_values_per_node`; assert rows fetched ≈ cap (not range), a
  continuation token is returned, and `HistoryReadNext` returns the remainder in order with no dup/gap.
- Assert memory proportional to page, not range (allocation/row-count assertion in the test harness).

## US2 — Replay-safe session activation (SC-002)

- Race test (async-opcua-server session): two `ActivateSession` against the same session; force one to
  rotate the nonce before the other commits; assert the late one is rejected with
  `BadNonceInvalid`/`BadSessionIdInvalid` and identity/nonce are not overwritten.
- Assert uncontended activation still succeeds (no common-path regression); secured transfer still allowed.

## US3 — Bounded decode allocations (SC-003)

- PubSub: craft UADP messages with maximal `field_count`/dataset counts; assert decode errors before
  allocation; valid in-limit messages decode byte-identically.
- custom_struct: dimensions chosen to overflow `u32`; assert a decode error (no wrap, no panic).
- Fuzz: `cargo +nightly fuzz run fuzz_deserialize -- -max_total_time=<n>` → zero aborts.

## US4 — No growth over long uptime (SC-004)

- Soak test: N cycles of create/delete data-change monitored items; assert global `monitored_items`
  and `subscription_to_session` return to baseline size.
- Browse/query continuation: open and abandon points; assert TTL eviction reclaims them without
  session close.
- Engine: drop a suspended `Engine`; assert the background task is aborted (no leaked task).

## US5 — Config & defense-in-depth (SC-005)

- Config validation rejects `max_chunk_count: 0` + `max_message_size: 0`.
- `read_bytes` enforces `max_message_size` (or is removed; assert no callers).
- `ByteString`/UADP do not pre-allocate from a declared length before the stream is confirmed.
- Load `micro`/`gateway`/`server` profiles from `deploy-profiles.md`; assert parse + server start.

## Final gate (every story / before each per-story commit)

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --workspace
```
Record before/after allocation or size numbers in each story's PR/commit body. Generated code
untouched (`verify-clean-codegen` green). One commit per user story; one task per codex dispatch.
