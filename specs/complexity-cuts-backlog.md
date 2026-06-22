# Complexity-cuts backlog (Big-O triage)

## Status after running the loop (2026-06-21)

All tiers were taken through the complexity-cuts loop. The disciplined result: **one genuine,
attacker-amplifiable, asymptotic win — applied; everything else hits a documented stop-condition**
(bounded input, not-hot, or structural/maintenance risk disproportionate to a bounded payoff). The
parallel audit over-flagged; per-item code verification corrected it.

- **APPLIED — Tier 1a** (`b6d41637`): the two O(n²) `VecDeque::remove(idx)`-in-a-loop queue cleanups
  (`remove_retransmission_notifications`, `remove_expired_publish_requests`) → single `mem::take` +
  partition pass. **O(n²)→O(n)**, semantics preserved (side-effects run in order), server tests green
  before/after. Asymptotic only (queues capped; no bench harness). This was the real quadratic.
- **DEFER — Tier 1b** (retransmission key-index): after 1a the lookups are O(n)/O(k·n) over a queue
  **capped** by `max_retransmission_queue_len`; a `HashMap` synced with VecDeque FIFO-eviction +
  ordered `AvailableSequenceNumbers` is an unwritten-invariant trap. Bounded payoff < correctness risk.
- **DEFER — Tier 2a** (`is_subtype_of` memo): the type-tree depth T is a **small, server-defined
  constant** (not attacker-controlled); the attacker dim R is request-limit-bounded. Memoization needs
  interior-mutability+locking (contention) or build-time precompute+invalidation (staleness). Bounded
  small input → stop-condition.
- **DEFER — Tier 2b** (TranslateBrowsePaths `(parent,BrowseName)` index): M is data-dependent (server
  address-space shape), request is limit-bounded; a dynamic-address-space index has invalidation risk.
  No benchmark shows it slow → don't add structural risk without a measured win.
- **DEFER — Tier 3 #5** (client `next_publish_time` recompute): O(S), but called ~once per publishing
  interval (≈1 Hz) over a capped, typically-tiny S — **not a hot path**. Stop-condition (bounded + cold).
- **DEFER — Tier 3 #6** (CreateSession O(sessions) scan): per-handshake, n capped by `max_sessions`
  AND the rate capped by the per-IP connection limit; an O(1) per-channel counter has a multi-site
  maintenance invariant (create/activate/close/expiry). Bounded n + bounded rate → marginal; risk > payoff.
- **DEFER — Tier 3 #7** (priority re-sort per publish tick): O(S log S), S capped, per publishing
  interval (not per message); caching needs invalidation on every priority/membership change. Bounded + cold.
- **DEFER — Tier 3 #8** (chunk `chunk_info` parsed in both validate + decode): for the steady-state
  **symmetric** path this is 2× a cheap header parse; the expensive sender-cert read is only on the rare
  **asymmetric** OpenSecureChannel path. Marginal constant-factor on a security path + API-threading
  risk → stop.
- **VERIFIED NOT PROBLEMS** (audit mis-claims, corrected): secure-channel padding loop bounded by
  `checked_sub` (not O(65535)); `AddressSpace::find` is O(1) HashMap (PubSub loop not O(address-space));
  length-validated-before-alloc decode paths.

**Net:** the one true quadratic is fixed; the remainder are bounded by the existing caps/limits/rate
controls or are small server-defined constants. If you want any *bounded* item done anyway as a
deliberate choice (e.g. the CreateSession per-channel counter), it can be applied through the same loop.

The original triage detail follows.

---

**Scope:** hand-written hot paths across the core stack (`-types`, `-core`, `-server`, `-client`,
`-nodes`, `-pubsub`). Generated code (`-core-namespace`, `-types/src/generated/`) excluded. Tests
excluded.

**Lens (this is a network protocol stack):** the priority is **bounded work on attacker-influenced
input** — superlinear or unbounded work driven by a wire-/remote-controlled dimension is a DoS vector
(Constitution IV). Per-request O(n) that is *inherent* (e.g. Read of k nodes is O(k)) is NOT a defect.

**Method:** read-only parallel audit (2026-06-21), then per-claim verification by code-read. Current
Big-O is stated per item (complexity-cuts rule 1). **No transformations applied** — each fix, when
done, follows the verify-revert-stop loop with green tests before/after and a measured ratio.

**Already-bounded by prior work (do not re-flag):** decoder recursion-depth guards; `max_array_length`
/ `max_string_length` / `max_byte_string_length` validated *before* allocation; `max_chunk_count`,
`max_message_size`; per-source-IP / per-channel / per-subscription caps; O(1) session lookup (DashMap);
references indexed `by_source`/`by_target`; node lookup is `HashMap` (O(1)).

---

## Tier 1 — superlinear within an attacker-influenceable bound (fix first)

| # | Finding | file:line | Current Big-O | Dominant dim (attacker?) | Fix |
|---|---------|-----------|---------------|--------------------------|-----|
| 1 | **`Vec::remove(idx)` in a filter loop over the retransmission queue** — per-subscription-expiry / per-publish removal shifts the tail each time. | `async-opcua-server/src/subscriptions/session_subscriptions.rs:622` (`remove_retransmission_notifications`), `:910` (`remove_expired_publish_requests`) | **O(n²)** time | n = retransmission / publish-request queue depth, capped at `max_publish_requests*2` but **attacker-inflatable up to the cap** (create subscriptions + flood PublishRequests) | one-pass `VecDeque::retain` (O(n)); or index the queue by `subscription_id` (`HashMap<u32, VecDeque<…>>`) so per-subscription removal is O(m), not O(n²) |
| 2 | **Linear scan + `remove` per ack / per available-seq inside the publish loop** — `find()`/`filter()` over the whole retransmission queue, once per ack and once per response. Code carries a comment assuming "queue is short / element is first" that fails under load. | `session_subscriptions.rs:924` (`process_subscription_acks`), `:961` (`available_sequence_numbers`), `:894` (`find_notification_message`) | **O(k·n)** per publish / per Republish | k = acks or responses per tick, n = queue depth — both attacker-inflatable | index the queue by `(subscription_id, sequence_number)` → O(1) lookup/removal; cache `available_sequence_numbers` per subscription while building responses |

> Tier 1 is bounded in *absolute* terms by the queue caps, but the quadratic shape means cost grows
> with the square of an attacker-driven queue depth under a publish flood — the highest-value cut.

## Tier 2 — bounded but multiplicative amplification (index / memoize)

| # | Finding | file:line | Current Big-O | Dominant dim | Fix |
|---|---------|-----------|---------------|--------------|-----|
| 3 | **`is_subtype_of` linear type-tree walk per reference**, no memoization, during Browse / TranslateBrowsePaths / Query filtering. | `async-opcua-nodes/src/type_tree.rs:97`; called from `async-opcua-server/src/node_manager/view.rs:288` | **O(R·T)** per request | R = references evaluated (≤ browse/read request limits), T = type-hierarchy depth (server-defined, bounded). Both bounded → constant-factor amplification, not unbounded. | memoize results in `HashMap<(NodeId,NodeId),bool>`, or precompute ancestor sets per type at load |
| 4 | **TranslateBrowsePaths nested scan** — per path element, iterate all currently-matching nodes and call `find_references()` on each. | `async-opcua-server/src/node_manager/view.rs:759` (`impl_translate_browse_paths_using_browse`); `node_manager/memory/mod.rs:366` | **O(D·M·R)** | D = path length, M = nodes matching at a level, R = refs/node; D attacker-supplied (cap it if not), M depends on address space | build a `(parent NodeId, BrowseName) → [child NodeId]` index for O(1) per-element resolution |

## Tier 3 — per-tick / per-handshake O(n) recompute (cache / hoist; latency, not DoS)

| # | Finding | file:line | Current Big-O | Fix |
|---|---------|-----------|---------------|-----|
| 5 | Client recomputes min publish interval / keep-alive / publish-limits by scanning **all** subscriptions on every tick & on every subscription change. | `async-opcua-client/src/session/services/subscriptions/state.rs:46, 241, 253` | O(S) per tick/change | cache with a dirty flag; maintain a running min, update incrementally on add/remove/modify |
| 6 | CreateSession scans **all** sessions to count unactivated-per-channel. | `async-opcua-server/src/session/manager.rs:~196` (`create_session`) | O(total sessions) per handshake (≤ `max_sessions`) | index sessions by `secure_channel_id` (`HashMap<u32, count>` / set) |
| 7 | Subscriptions re-sorted by priority on **every** publish tick. | `session_subscriptions.rs:832` (`subscription_ids_by_priority`) | O(S log S) per tick | keep a priority-ordered structure; re-sort only on priority change |
| 8 | Chunk headers (incl. sender-certificate decode) re-parsed per chunk per validation pass (≈ twice). | `async-opcua-core/src/comms/chunker.rs:352, 506` | O(chunk_count · header) ×2 | parse `ChunkInfo` once, reuse across validation + decode |
| 9 | Browse external-reference resolution iterates node managers sequentially. | `async-opcua-server/src/node_manager/memory/mod.rs:309` | O(E·N), N = node managers (usually small) | batch/parallel resolve; low priority unless many node managers |

## Overlaps existing backlog

- **`Variant::range_of` MultipleRanges** (`async-opcua-types/src/variant/mod.rs:1609`): O(n·m), bounded
  by `MAX_INDICES=10` (10× over the array) — a constant-factor, not a DoS. Fold the perf cleanup into
  **conformance-gap-backlog Tier 2 #4 (NumericRange)** when that disjoint-range work is done
  (sorted-merge the intervals, single pass).

## Verified NOT a problem — do NOT re-investigate

- **Secure-channel padding verification** (`secure_channel.rs:~1372`): `padding_end.checked_sub(padding_size+2)`
  rejects any padding larger than the chunk, so the verify loop is **O(chunk_size)** (already capped),
  not O(65535). (An earlier audit pass mis-flagged this as an unbounded loop.)
- **PubSub `space.find()` per publish cycle** (`async-opcua-pubsub/src/bridge.rs`): `AddressSpace`
  node lookup is a `HashMap` (`node_map.get`, O(1)); the publish loop is O(W·D·V) of O(1) lookups,
  **not** O(W·D·V·A). (Mis-flagged as a linear address-space scan.) A startup node-handle cache is a
  micro-opt only.
- **Decode of arrays / strings / byte-strings / ExtensionObject body** (`-types`): all validate the
  wire-declared length against a configured max *before* allocating; O(n)-bounded and inherent.
- **Read / RegisterNodes of k items**: O(k) is inherent and request-limit-bounded — not a defect.

## Notes

- Tier 1 is the clear win (true O(n²) on an attacker-driven queue). Tier 2 closes multiplicative
  amplification on the Browse/Translate paths. Tier 3 is latency hygiene, not DoS.
- Each item → a `complexity-cuts` transformation: characterization test green first, one transformation,
  re-verify, then report `before → after · N× faster` (or `asymptotic only`). One commit per fix.

---

## YAGNI / over-build backlog (ponytail-audit, 2026-06-22)

- **`yagni`** — context-aware typed-method variant (`MethodHandlerWithContext` trait + 7 macro arity
  impls + `typed_method_with_context()` + the `node_manager` re-export), `async-opcua-server/src/
  node_manager/method_typed.rs`. Only caller is the test written to test it; no demo/sample/production
  use. The raw `add_method_callback_with_context` already covers context. **Cut ≈ -80 lines** (trait +
  impls + wrapper + re-export + `methods.rs` test). Add back when a real consumer needs typed context.
  Low priority — merged + green, so cutting is churn-only.

### Repo-wide ponytail-audit (since fork f7ab8d72, 2026-06-22)

- **`native`** — `async-opcua-pubsub` + `async-opcua-history-sqlite` are NON-optional deps of
  `async-opcua` (`async-opcua/Cargo.toml:87-88`, no `optional = true`), unlike client/server/nodes/xml
  which are feature-gated. They are always compiled, forcing AMQP/MQTT/WebSocket + libsqlite3-sys onto
  every async-opcua user. **Fix:** `optional = true` + `pubsub`/`history` features. Cut = 2 always-on
  subsystems + their transitive deps from default builds.
- **`delete`** — `async-opcua-safety/src/cli.rs` (135 lines): a CLI module inside the safety *library*
  crate (`pub mod cli`), wired to no `[[bin]]`, nothing runs it. The crate's `Spdu`/`SafetyValidator`
  ARE used (server `node_access.rs`); only the `cli` submodule is dead. Delete it + the `pub mod cli`.
- **Scope (not a code cut)** — breadth question: PubSub (3 transports), GDS push+pull, FOTA, programs
  engine, OAuth2, Safety/SPDU were added to tick OPC UA facets. Whether the deployment needs each is a
  product call. Real signal to gather: which of these subsystems have zero tests/callers.
