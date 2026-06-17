# async-opcua — Performance Audit

**Date:** 2026-06-16
**Scope:** Hot-path performance of the protocol stack — binary encode/decode
(`async-opcua-types`), the comms/transmit/receive path (`async-opcua-core/src/comms/`,
secure channel + crypto), and the server runtime (`async-opcua-server`: subscription tick,
monitored-item evaluation, per-request service path, shared-state contention).
**Method:** Source analysis of the highest-frequency operations. The recent commits already
optimized large parts of the transmit path ("allocation-free transmit path via streaming chunk
encoder", "MessageChunk.data Vec<u8> → bytes::Bytes"), so this audit distinguishes **what is already
well-optimized** from **what remains**. No live profiling was run — findings are ranked by where they
sit on the hot path (per-chunk / per-request / per-tick vs. per-connection / cold) rather than by
measured wall-clock, and the top recommendation is to add benchmarks to *quantify* them.

Companion docs: `CODE_REVIEW`, `SECURITY_AUDIT`, `ARCHITECTURE_REVIEW`, `NETWORK_REVIEW` (all dated
2026-06-16).

---

## Executive summary

This is a **well-optimized codebase** in its recently-touched areas: the unencrypted transmit path is
genuinely allocation-free (reused `BytesMut` + scratch, with a regression test pinning the buffer
pointer), array/string decode is correctly pre-sized, session lookup uses `DashMap`, the
subscription tick is **dirty-set driven** (no per-tick scan of idle items), and key derivation is
per-token, not per-message. Credit where due.

The remaining wins cluster in two places:

1. **The secured path gives back some of the transmit-path gains.** As soon as Sign/SignAndEncrypt is
   enabled, each chunk re-allocates a padding/signature buffer, re-instantiates the HMAC and AES key
   schedule, and the **receive path allocates + memcpy's every inbound chunk** instead of slicing the
   `Bytes` it already has. These are per-chunk, throughput-bound.
2. **Idle-server overhead in the subscription engine.** Every 100 ms tick allocates and sorts a
   priority vector per session even when nothing is happening, and the tick holds a cache read-lock
   across the whole session loop, blocking subscription/monitored-item creation.

None are architectural; all are localized optimizations behind missing benchmarks.

---

## Already well-optimized (preserve — do not "re-fix")

- **Allocation-free unencrypted transmit.** `ChunkingStream` writes all chunks into a reused
  connection-local `BytesMut` and emits each as a zero-copy `split_to().freeze()`
  (`chunker.rs:242-245`); `SendBuffer` reuses `chunk_storage`/`chunk_scratch` (`buffer.rs:46-48,
  151-159`) with a regression test asserting pointer/capacity stability (`buffer.rs:417-466`).
- **Pre-sized decode.** Array/`Option<Vec<T>>`/`Variant::Array` decode all `Vec::with_capacity(len)`
  after bounds-checking against `max_array_length` (`encoding.rs:559`, `variant/mod.rs:400`) — no
  per-element realloc, no collect-then-iterate.
- **Per-token key derivation.** `AesDerivedKeys` derived once per security token and cached in
  `local_keys`/`remote_keys` with spec-compliant retention (`secure_channel.rs:454-462`); the PRF is
  **not** run per message.
- **Dirty-set subscription tick.** `tick_monitored_items` (`subscription.rs:701-743`) iterates only
  `notified_monitored_items.drain()` — items mark themselves dirty on change. Per-tick cost is
  **O(changed items)**, not O(total). The full O(items) scan only runs on the rare `resend_data`
  (transfer) path.
- **Lock-free node map.** `AddressSpace.node_map` is a `DashMap` (value reads *and* writes go through
  a read guard + interior mutability), so the `Arc<RwLock<AddressSpace>>` only truly serializes
  structural add/delete — contention is far lower than the type signature suggests.
- **Good map/index choices.** `DashMap` session lookup; `Equivalent`-based borrow-free reverse index
  for notify lookups (`mod.rs:47-73`, avoids allocating a `NodeId` key); lock-free `LinearObjectPool`
  for notification buffers with capacity retention.
- **No lock held across `.await`** on the read path (`address_space/mod.rs:754-782` scopes the guard
  before the async `read_values`), and a `SyncMessage` fast path avoids spawning for
  Republish/ModifySubscription/SetPublishingMode.

---

## Findings — encode/decode & comms hot path

### P1 — Receive path allocates + copies every inbound chunk · **High (per-chunk, throughput)**
`tcp_codec.rs:252-256` already holds the chunk bytes in a `BytesMut` (zero-copy-sliceable), but
`MessageChunk::decode` (`message_chunk.rs:184-198`) does `let data = vec![0u8; message_size]`,
re-encodes the header into it, and `read_exact`-copies the body — a full heap alloc + memcpy per
inbound chunk. This is the biggest receive-path miss and it undoes, on receive, the zero-copy work
done on transmit.
**→ In the codec, peek `message_size` and `bytes_mut.split_to(message_size).freeze()` directly into
`MessageChunk { data }`.** Keep the `SimpleBinaryDecodable` impl for other callers but bypass it on
the codec hot path. Zero-copy, no re-encode.

### P2 — Per-chunk allocations on the secured path · **High (per-chunk on Sign/SignAndEncrypt)**
The streaming encoder is allocation-free *until security is enabled*:
- `add_space_for_padding_and_signature` (`secure_channel.rs:599-603`) does
  `Vec::with_capacity(...)` + a full `write_all(data)` copy **per chunk** on any secured connection.
- `symmetric_decrypt_and_verify` allocates `decrypted_tmp = vec![0u8; ciphertext_size + 16]` **per
  inbound secured chunk** (`secure_channel.rs:1412`).
**→ Carry reusable scratch buffers on `SecureChannel`** (mirroring what `SendBuffer` already does for
the plaintext path) for the padded/signed intermediate and the decrypt temp. Removes one heap alloc
per chunk per direction on every secured connection.

### P3 — HMAC and AES key schedule recomputed per chunk · **Medium–High (per-chunk on secured conns)**
Keys are cached, but the *primitives* are rebuilt every message:
- `HmacSha256::new_from_slice(key)` on every sign/verify (`hash.rs:115, 172`) re-runs the
  ipad/opad key schedule each chunk.
- `Aes128/256CbcEnc::new(key, iv)` per call (`aeskey.rs:47, 62, 77, 92`) recomputes the AES key
  schedule each chunk.
**→ Cache a pre-keyed `HmacSha256` template in `AesDerivedKeys` and `.clone()` per message; cache the
keyed AES block cipher in `AesKey` and only build the lightweight CBC wrapper per call.** The CBC IV
is fixed per channel (spec), so only the key schedule needs caching.

### P4 — Dual-pass `byte_len()` + `encode()` · **Medium (per-message, scales with payload)**
`Chunker::encode_into` computes `message_size = byte_len()` up front (`chunker.rs:420, 441`) then
`encode()` walks the whole object graph again (`:457-460`). An N-element array is traversed ~2N times
(`byte_len_variant_value` per element mirrors `encode_value`). The size is *genuinely needed* up front
(over-limit rejection, chunk-count/reserve sizing, per-chunk header `message_size` written before the
body), so it isn't trivially removable.
**→ Two options:** (a) lower-risk — make `byte_len` O(1) for homogeneous primitive arrays
(`4 + len * elem_size` instead of a per-element match in `variant/mod.rs:250`, `encoding.rs:516/569`),
halving serialization cost for big arrays without touching the streaming design; (b) higher-effort —
write a placeholder size, stream-count the body, backfill the 4-byte header (works cleanly for the
single-chunk case, complex for multi-chunk). Start with (a).

### P5 — `ByteString`/`UAString` decode zero-init + copy · **Medium (binary-heavy payloads)**
`vec![0u8; len]` + `read_exact` zero-initializes then overwrites (`string.rs:131`,
`byte_string.rs:174`). More importantly, `ByteString.value: Option<Vec<u8>>` (`byte_string.rs:24`)
forces a copy out of the `Bytes`-backed chunk on every decode.
**→ Read into uninitialized capacity to drop the zero-init; longer-term, make `ByteString`
`Bytes`-backed so large byte strings decode zero-copy** (the single biggest decode-path win for
binary-heavy payloads, but a type change with API impact).

---

## Findings — server runtime hot path

### P6 — Per-tick priority-sort allocation per session, even when idle · **Medium (per-tick, idle CPU)**
`session_subscriptions.rs tick:638-647` allocates a `Vec<(u32,u8)>` of all subscriptions and
`sort_by_key`s by priority **every tick** (every 100 ms per session), even with no publish request
queued and nothing to publish. With thousands of mostly-idle subscriptions this is pure idle overhead.
**→ Skip the sort/alloc when the publish queue is empty and no subscription has notifications; or
cache the priority-sorted order and re-sort only on add/modify/priority-change.** Low risk.

### P7 — Cache read-lock held across the whole tick loop blocks subscription creation · **Medium**
`mod.rs periodic_tick:234-245` holds `trace_read_lock!(self.inner)` across the entire
`for (session_id, sub) in lck.session_subscriptions.iter()` loop. It's a *read* lock so ticks/notifies
coexist, but `create_subscription`/`create_monitored_items`/`delete_subscriptions` take the **write**
lock and block for the full tick duration — with many sessions, a CreateMonitoredItems stalls behind
a tick iterating thousands of session mutexes.
**→ Snapshot `Vec<Arc<Mutex<SessionSubscriptions>>>` under a brief read lock, drop the guard, then
tick over the snapshot** — shrinks the write-blocking window from "entire tick" to "clone the Arc
list." A session deleted mid-tick is ticked once more (harmless).

### P8 — Notification pool can block a tokio worker at capacity · **Medium (under load)**
`pool.rs:114-126`: `acquire()` is lock-free in steady state (CAS on the active counter), but when all
`capacity` slots are checked out it falls into a **blocking parking_lot `Condvar::wait` on the async
tick thread**, parking the entire tokio worker. Unlikely with the single periodic-tick consumer, but
reachable if `max_notification_pool_size` is small relative to concurrent publish-driven ticks.
**→ Size the pool ≥ worker count + expected concurrent ticks, or replace the condvar wait with
allocate-on-exhaustion** (trades the hard memory cap for never parking a worker). (Also flagged in the
code review / architecture review.)

### P9 — `tokio::spawn` + Arc-clone churn per service request · **Medium (per-request, high rate)**
`message_handler.rs:147-164` (`async_service_call!`) spawns a task per Browse/Call/HistoryRead/Read/
Write, each cloning `node_managers`/`info`/`subscriptions` Arcs and building a fresh `RequestContext`
(`Arc::new` + ~10 atomic bumps, `context():130-143`). Justified for genuine multi-node-manager
fan-out, but adds a task alloc + Arc churn + latency to the common single-node-manager small Read.
**→ Add an inline fast path for small single-node-manager Reads** (run without spawning), keeping the
spawn for multi-manager fan-out. Tradeoff: loses per-request panic isolation; measure first (P12).

### P10 — Deep clones in the notify/retransmission path · **Medium (per-notification / per-publish)**
The deepest steady-state clones: `notify.rs:27-37` clones the full `DataValue` (incl. owned
`Variant` arrays/strings) **once per matched monitored item** (one update → N items = N deep clones);
and `session_subscriptions.rs:585, 750` clone the whole `NotificationMessage` into the retransmission
queue **per published message** (required for Republish).
**→ `Arc`-back large `Variant` array payloads (`Arc<[T]>`) so item fan-out is a refcount bump, and
hold the retransmission entry as `Arc<NotificationMessage>` shared with the response.** Larger
refactor — sequence behind benchmarks.

### P11 — Minor: O(n) linear scans on the retransmission queue · **Low**
`process_subscription_acks` / `find_notification_message` / `available_sequence_numbers`
(`session_subscriptions.rs:745-817`) linear-scan a `VecDeque`. The code comments justify it (short,
needs both ordered and unordered removal); acceptable unless `max_retransmission_queue_len` is large
and acks are frequent.

---

## P12 — Benchmark coverage gap (do this first) · **High leverage**
Only `session_lookup` and `notification_pool` benches exist — both server-side data-structure
microbenchmarks. **The entire wire path the recent commits optimized has no regression benchmark.**
Missing: encode/decode throughput (small ReadRequest, large array `DataValue`, big `ByteString`),
`byte_len` cost in isolation (P4), `Chunker` round-trip across None/Sign/SignAndEncrypt (P1–P3),
TcpCodec decode (P1), and a subscription-tick bench at scale (P6–P8).
**→ Add `criterion` benches to `async-opcua-types` (encode/decode of representative messages) and
`async-opcua-core` (full `encode_into → apply_security → verify_and_remove_security` round trip).**
These both lock in the streaming-encoder gains and let every optimization below be quantified instead
of guessed. Without them, P1–P10 are educated estimates.

---

## Prioritized action list

| # | Optimization | Hotness | Effort |
|---|--------------|---------|--------|
| P12 | Add encode/decode/crypto/tick benchmarks | — (enables all) | Medium |
| P1 | Zero-copy inbound chunk (`split_to().freeze()`) | per-chunk | Low |
| P2 | Reusable scratch for padding/sig + decrypt temp | per-chunk (secured) | Low–Med |
| P3 | Cache keyed HMAC + AES key schedule | per-chunk (secured) | Low–Med |
| P7 | Snapshot sessions; don't hold cache lock across tick | per-tick | Low |
| P6 | Skip/cache per-tick priority sort when idle | per-tick (idle) | Low |
| P8 | Non-blocking notification-pool exhaustion | per-tick (load) | Low |
| P4 | O(1) `byte_len` for primitive arrays | per-message | Low–Med |
| P9 | Inline fast path for small Reads | per-request | Medium |
| P5 | `Bytes`-backed `ByteString` (zero-copy decode) | per-message | High |
| P10 | `Arc`-back Variant arrays / retransmission msgs | per-notification | High |
| P11 | Retransmission-queue scan | per-ack | Low |

**Start with P12 then P1–P3.** P1–P3 are the highest-value remaining work: they restore on the
*secured, received* path the allocation-free property the recent commits achieved on the *plaintext,
sent* path — and secured connections are the production norm. P6–P8 cut idle-server CPU and a
latent worker-blocking risk for cheap. The deeper type-system changes (P5, P10) should wait behind
the benchmarks so their payoff can be measured against their API cost.
