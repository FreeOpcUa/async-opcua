# Complexity-cuts backlog (Big-O triage)

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
