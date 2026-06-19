# Research: Embedded Hardening & Allocation Follow-ups

Most approaches are pre-decided by the 009 embedded audit (§5/§6) and the 2026-06-19 sweep. This records the chosen approach, rationale, and alternatives per item. No unresolved `NEEDS CLARIFICATION`.

## R1 — Codec `max_message_size` enforcement (FR-002)

- **Decision**: In `TcpCodec::decode` (async-opcua-core), after reading the 8-byte header, reject `message_size > max_message_size` (when nonzero) with a protocol error (`BadTcpMessageTooLarge`) *before* waiting to buffer that many bytes. Make `MessageHeader::decode` actually use the `DecodingOptions` it is passed.
- **Rationale**: The decoder currently only checks `buf.len() >= message_size` for an attacker-declared `u32`; a peer that streams bytes can grow the per-connection read buffer toward 4 GB. Rejecting at header-read bounds the buffer to the negotiated maximum. Small, localized, no wire change for compliant peers.
- **Alternatives**: Wrapping `FramedRead` with a `max_frame_length` codec (more churn, changes the framing type); relying on chunk-count/timeout (bounds count/duration, not single-frame size). Rejected as heavier / incomplete.

## R2 — Decode-recursion depth bound (FR-003)

- **Decision**: Add a `max_decode_depth` to `DecodingOptions` (default a safe value, e.g. 100) and a depth counter applied at the recursive nesting points (ExtensionObject → Variant → Array → ExtensionObject; the dynamic/custom-struct decode). Exceeding it returns a decode error.
- **Rationale**: Current nesting is bounded only indirectly by message size — a thin margin on small per-task stacks (Pi-class). An explicit, cheap counter is deterministic and stack-safe. Mirrors the existing `depth_lock()` pattern already added for the C1 recursion fixes in 009.
- **Alternatives**: Rely on message-size limit (indirect, stack-size-dependent); increase stack size (fragile). Rejected.

## R3 — GDS registry caps (FR-004)

- **Decision**: Bound each GDS push/pull registry (`signing_requests`, `created_requests`, `rejected/updated/finished` cert lists) with a configurable cap; on overflow, evict oldest (FIFO) and/or apply a TTL, mirroring the retransmission-queue cap and the history continuation-point LRU+TTL already in the codebase. Overflow behavior documented.
- **Rationale**: These grow without limit under sustained authorized GDS traffic. Privileged/feature-gated, so lower severity, but still a soak leak. Reuse existing bounding patterns for consistency.
- **Alternatives**: Unbounded (status quo, rejected); hard reject-when-full only (loses newest legitimate requests — FIFO-evict preferred, configurable).

## R4 — Panic-surface sweep (FR-001, SC-001)

- **Decision**: Scope `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]` to the network-facing crates (`-types`, `-core`, `-crypto`, and the decode/transport paths of `-server`/`-client`), drive findings to zero by replacing with `Result`/checked operations, and allow only proven-safe sites with an explicit justifying `#[allow(...)]` comment. Back it with a panic-hunting fuzz pass (extend the existing `fuzz/` targets; run under a constrained stack). **Not** `panic = "abort"` — a bad chunk must drop the connection, not kill the process.
- **Rationale**: The 4 discovered remote-reachable panics are fixed; this proves the *rest* of the surface clean and prevents regressions via the lints. The lints are the durable guard; the fuzz pass is the empirical check.
- **Alternatives**: Manual one-time audit (no regression guard); `panic=abort` (wrong for a connection-oriented server — converts a recoverable drop into a process kill). Rejected.
- **Risk/Staging**: Large surface; will be split per-crate (one task each) so each is reviewable, with `#[allow]` justifications captured inline (Principle II).

## R5 — Event-notification Vec pool (FR-005, SC-003)

- **Decision**: Extend the existing `DataChangeNotificationVecPool` pattern (or a sibling pool) to the `EventFieldList` vector built in `make_notification_message`. Draw a cleared, capacity-checked Vec; reclaim at the `NonAckedPublish` drop site via `Arc::into_inner` + `into_inner_as::<EventNotificationList>` + `take` + clear, with graceful fallback. Same clear-on-draw-and-reclaim invariant proven for data-change in 2b.
- **Rationale**: 2a pre-sized the event vector but left it allocating per tick and escaping into the message (like data-change before 2b). For event/alarm-heavy subscriptions this is the same churn. Reuses a proven, correctness-safe mechanism.
- **Alternatives**: Leave events unpooled (status quo; fine for data-change-only deployments but not event-heavy). Pursued as a contained extension.

## R6 — Per-request dispatch allocation / M2 (FR-006, SC-004) — ARCHITECTURAL, measure-first

- **Decision**: Add an **inline fast path** for small single-node-manager Reads in the server message handler that avoids the per-request `Box`+`tokio::spawn`, falling back to the spawned path otherwise. Gate on a measured benefit; preserve request isolation (a panic in the fast path must still not take down the connection-handling task improperly — keep the catch boundary).
- **Rationale**: Per-request box+spawn is steady-state churn + cross-core work-stealing frees. An inline fast path for the common cheap case removes both for that case without rewriting the whole dispatch/isolation model.
- **Alternatives**: Full dispatch rewrite (too risky — changes panic isolation broadly); leave as-is. Inline-fast-path is the bounded, measure-first middle.
- **Staging**: If measurement does not show a clear win, or isolation cannot be preserved cleanly, this task is **deferred within the feature** with a recorded rationale (Principle I/II over completion).

## R7 — Zero-copy decode / M4 (FR-007, SC-006) — ARCHITECTURAL, measure-first

- **Decision**: Thread the source `Bytes` through the binary decode path so `ByteString`/`String`/array decode slices/`split` from the shared buffer instead of copying into a fresh `Vec`. Covers the per-array-field decode `Vec` (encoding.rs array decode). Preserve identical decoded values; keep `SimpleBinaryDecodable` working where a `Bytes` source is unavailable (fallback to copy).
- **Rationale**: Decode currently copies bytes before wrapping; the receive buffer is already `BytesMut`/`Bytes`, so sharing is feasible. Largest decode-path allocation reduction.
- **Alternatives**: Leave copy-on-decode (status quo). The refactor is `-types`-wide; pursued measure-first and **may be staged/deferred** if the trait-surface change proves too invasive for the demonstrated benefit (Principle I/II).

## R8 — Embedded deployment docs (FR-008, SC-007)

- **Decision**: Document in `docs/setup.md` (a) the `current_thread` tokio runtime as the recommended low-jitter embedded config (removes work-stealing → no cross-core frees), with the throughput trade-off stated, and (b) a size-optimized release profile (LTO, `opt-level = "z"`, `panic` left as unwind for the connection-drop semantics, feature-minimal build). Cross-reference the existing crypto-backend / cargo-zigbuild guidance.
- **Rationale**: The single-threaded runtime is the biggest cross-core-jitter lever and is a config choice, not code. Pairs with the existing musl/cargo-zigbuild section.
- **Alternatives**: None needed; additive docs.

## Cross-cutting: measurement harness

- **Decision**: Reuse and extend the `#[ignore]`d counting-allocator baseline harness from the publish-path work for the event-pool and dispatch measurements; add a fuzz-driven panic check for SC-001. Record before/after numbers in the relevant commit/PR bodies.
