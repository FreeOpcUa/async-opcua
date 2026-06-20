# Research & Design Decisions: Audit Remediation

One decision block per non-trivial finding. Trivial fixes (checked_mul, Engine Drop, config
validation) are listed at the end without extended rationale.

## US1 — Bounded history reads (FR-001/FR-002)

- **Decision**: Push `LIMIT (num_values_per_node + 1)` into `query::fetch_interval` (rusqlite 0.31).
  Replace the materialized `CachedContinuationPoint { values: Vec<DataValue> }` remainder with a
  **keyset cursor**: store `(node_id, range bounds, direction, last source_timestamp seen,
  remaining-bounds flags)`. `HistoryReadNext` re-queries from `last_timestamp` with the same `LIMIT`.
- **Rationale**: Keyset (seek) pagination is O(page) memory and avoids the OFFSET full-scan
  anti-pattern; SQLite indexes on `(node_id, source_timestamp)` make it efficient. Memory becomes
  proportional to the returned page, satisfying SC-001.
- **Alternatives rejected**: (a) `LIMIT/OFFSET` — still scans skipped rows, degrades over deep
  paging; (b) keep the Vec but cap its size — loses values silently or errors on legitimate large
  ranges; (c) stream a live SQLite cursor across requests — holds a connection/statement open across
  client round-trips, contends the single `spawn_blocking` worker.
- **Edge**: `num_values_per_node == 0` keeps current "return all in range" semantics but MUST still
  cap via a server-side hard ceiling to preserve the DoS fix; document the ceiling.

## US2 — Replay-safe session activation (FR-003/FR-004)

- **Decision**: Capture the observed `session_nonce` under the read lock (already done), and under
  the **write lock that commits `activate()`** re-read `session.session_nonce()` and compare to the
  observed value; if changed, return `BadNonceInvalid`/`BadSessionIdInvalid` and do not mutate. Keep
  the existing `is_cross_channel_transfer_forbidden` check (it governs the `SecurityPolicy::None`
  case and legitimate secured transfer).
- **Rationale**: Minimal, fail-closed, and serializes the freshness check with the mutation under one
  lock — closing the TOCTOU window opened by the `authenticate_endpoint().await`. Nonce equality is a
  sufficient generation marker because `activate()` rotates the nonce on every success.
- **Alternatives rejected**: (a) hold the write lock across the `.await` — would serialize all
  activations and risk holding a lock across async work (constitution lock-discipline); (b) a
  separate `AtomicU64` activation generation — more moving parts than nonce-equality needs.
- **Disclosure**: This is an upstream-relevant auth gap — hold upstream PR pending private
  disclosure to the maintainer.

## US3 — Bounded decode allocations (FR-005/FR-006)

- **Decision (PubSub)**: Add PubSub decode limits to the decode `Context`/`DecodingOptions` surface
  (e.g. `max_dataset_fields`, `max_dataset_messages`, `max_secured_payload_len`). In
  `uadp.rs` validate `field_count`/dataset counts against the limit **before** `Vec::with_capacity`;
  in `security/codec.rs` reject payloads over `max_secured_payload_len` before copy/decrypt.
- **Decision (custom struct)**: Replace `len *= *dim as u32` with `checked_mul`, erroring on overflow,
  and compare each running product against `max_array_length` so the bound is enforced *during* the
  fold, not only after.
- **Rationale**: `DecodingOptions` is already threaded through every decoder via `Context`, so this
  is the idiomatic, framework-consistent place (constitution: use the existing decoding framework).
  Defaults chosen to accept conformant real-world dataset messages (see contracts).
- **Alternatives rejected**: a PubSub-only bespoke limits struct passed separately — duplicates the
  existing options plumbing.

## US4 — No growth over long uptime (FR-007/FR-008/FR-009)

- **Decision (monitored_items index)**: Introduce a single centralized removal path on
  `SubscriptionCache` that, given deleted subscriptions, returns all `MonitoredItemRef`s and removes
  **every** `monitored_items` handle (all attributes, not just `EventNotifier`) plus the
  `subscription_to_session` mapping. Call it from both `delete_subscriptions` and the expiry path in
  `SessionSubscriptions::tick()` (which must return removed IDs/refs to the cache holder).
- **Decision (browse/query continuation)**: Replace the plain `HashMap`s in `session/instance.rs`
  with the same moka TTL/LRU pattern used by `history/continuation.rs`; `0` no longer means
  unlimited for these (apply the configured cap/TTL).
- **Decision (Engine)**: `impl Drop for Engine` that calls `cancel_token.cancel()` and/or
  `handle.abort()`; also wake the `suspend_notify` so a suspended task observes cancellation.
- **Rationale**: Reuses the proven moka eviction model; centralization removes the
  attribute-specific gap at its root (constitution: fix root cause).
- **Alternatives rejected**: periodic full-scan sweep of the index — O(n) churn vs. exact removal at
  delete time.

## US5 — Config & defense-in-depth (FR-010..FR-013)

- **FR-010**: `effective_max_chunk_count` / config validation rejects `max_chunk_count == 0 &&
  max_message_size == 0` (or applies a hard ceiling). Fail-closed at config load.
- **FR-011**: `MessageHeader::read_bytes` has **zero callers** — bound it against
  `max_message_size` before allocating; prefer removal if no public consumer needs it (confirm in
  tasks).
- **FR-012**: `ByteString::decode` (+ UADP buffers) allocate only after confirming available stream
  length (read incrementally / `take`-limited reader), avoiding pre-alloc thrash.
- **FR-013**: `max_notifications_per_publish` default `0 → ` a bounded value; ship `micro`/`gateway`/
  `server` limit profiles (drafted in `deploy-profiles.md`).

## Trivial / mechanical

- checked arithmetic (FR-006), `Drop` impl (FR-009), config-validation reject (FR-010): direct edits
  with unit tests; no design alternatives.

## Deferred (recorded, out of scope this feature)

- u32 ID-wraparound collision (session/subscription/monitored-item/connection IDs): manifests only
  after ~4.3 B creations; irrelevant to low-churn industrial use. Revisit for high-churn gateways via
  `u64` internal IDs or collision-aware allocation.
