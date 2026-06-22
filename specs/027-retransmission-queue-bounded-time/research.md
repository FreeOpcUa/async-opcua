# Research: Bounded-Time Subscription Retransmission Queue

Grounded by reading `async-opcua-server/src/subscriptions/session_subscriptions.rs` and
`…/subscriptions/mod.rs` (2026-06-22).

## Bottleneck inventory (current code)

| Site | Operation | Current cost |
|---|---|---|
| `remove(sub)` (L150) | `while` loop of `VecDeque::remove(idx)` | O(n²) on teardown |
| `process_subscription_acks` (L926) | per-ack `iter().find` + `remove(idx)` | O(acks·n) |
| `republish` → message lookup (L903) | `iter().find` | O(n) per Republish |
| `available_sequence_numbers` (L962) | `iter().filter` | O(n), returns **insertion order** |
| `remove_retransmission_notifications` (L622) | `mem::take` + single-pass rebuild | O(n) per call, BUT called **per-subscription** in teardown loops (L536 over an id-set, L827/L846 per removed sub) → O(removed·n) |
| `enqueue_retransmission_notification` (L588) | `push_back` + `pop_front` evict | O(1) (already fine) |

Invariants observed (must preserve):
- **Global-FIFO eviction**: when full, `pop_front` drops the globally oldest entry by insertion
  order, independent of subscription. Per-subscription sequence order ≠ global insertion order.
- **Reclaim-to-pool**: every removed/evicted entry is passed to `reclaim_non_acked_publish` (returns
  its data-change Vec to `data_change_notification_pool` for reuse — a feature-010 embedded
  allocation optimization). The refactor MUST keep reclaiming on ack, teardown, and eviction.
- `available_sequence_numbers(sub)` returns the subscription's sequence numbers in **queue
  insertion order** (front-to-back), and `None` when the queue is empty or the sub has none.
- `remove(sub)` returns the removed entries in queue (insertion) order (re-used by subscription
  transfer via `insert`, which re-`push_back`s them).
- Ack status mapping (in `process_subscription_acks`): unknown subscription →
  `BadSubscriptionIdInvalid`; known sub but `(sub,seq)` absent → `BadSequenceNumberUnknown`; present
  → `Good` (and the entry is removed + reclaimed).
- `NonAckedPublish { message: Arc<NotificationMessage>, subscription_id: u32 }`; the sequence number
  is `message.sequence_number`. Key = `(subscription_id, sequence_number)`.

## Decision — encapsulate a `RetransmissionQueue` struct (std-only)

New module `async-opcua-server/src/subscriptions/retransmission_queue.rs` owning all retransmission
state, replacing the bare `VecDeque<NonAckedPublish>` field. Internals:

- `entries: BTreeMap<u64, NonAckedPublish>` — keyed by a **monotonic global insertion id**; ordered
  iteration = insertion order; `pop_first()` = O(log n) global-oldest eviction.
- `index: HashMap<(u32 subscription_id, u32 sequence_number), u64 insertion_id>` — O(1) keyed lookup
  for ack / republish / membership.
- `by_subscription: HashMap<u32, BTreeSet<u64 insertion_id>>` — per-subscription insertion ids in
  order → O(k log n) teardown and **insertion-ordered** `available_sequence_numbers`.
- `next_id: u64` — insertion counter.

Resulting costs: enqueue O(log n); ack O(log n); republish lookup O(1)+clone; teardown O(k log n);
available_sequence_numbers O(k); eviction O(log n). All sub-quadratic; the O(n²)/O(acks·n)/O(removed·n)
paths are gone.

**Rationale**: std-only (`BTreeMap`/`HashMap`/`BTreeSet`) → FR-008 satisfied, no new dep. The
insertion-id BTreeMap preserves *exact* global insertion order for both eviction and the returned/
listed orders, so behavior is identical (not just equivalent). Encapsulation localizes the change
and makes the queue unit-testable in isolation (the current static `enqueue_retransmission_notification`
already operates on the bare queue, so the test surface is natural).

**Alternatives considered**:
- Keep `VecDeque` + a `HashMap` index with tombstones — eviction/teardown still shift O(n); tombstone
  bookkeeping is fiddlier than a BTreeMap. Rejected.
- `BTreeMap<(sub,seq), entry>` keyed directly — loses global insertion order (per-sub seq ≠ global
  order), breaking FIFO eviction (FR-004). Rejected.
- A new crate (indexmap/ordermap) — unnecessary; std covers it (FR-008). Rejected.

**Uniqueness invariant**: `(subscription_id, sequence_number)` is unique within the queue —
sequence numbers are assigned strictly monotonically per subscription and the queue is length-bounded,
so a `(sub,seq)` cannot recur without a u32 wrap (~4.3e9 messages) inside the bounded window. codex
adds a `debug_assert!` that an enqueue never overwrites an existing index key; in release a
(theoretical) collision would orphan the older entry until evicted — acceptable and not reachable in
practice. Documented.

## Behavior-preserving rewiring (all in session_subscriptions.rs unless noted)

- `enqueue_retransmission_notification` → `RetransmissionQueue::enqueue(&mut self, pool, max_len,
  sub_id, message)` (keep-alive skip unchanged; evict+reclaim on full).
- `remove(sub)` → `queue.remove_subscription(sub)` returning entries in insertion order.
- `process_subscription_acks` → keep the `self.subscriptions.contains_key` check for
  `BadSubscriptionIdInvalid`; then `queue.ack(sub, seq)` → `Some(entry)` ⇒ reclaim + `Good`, `None` ⇒
  `BadSequenceNumberUnknown`.
- `republish` message lookup → `queue.get_message(sub, seq)`.
- `available_sequence_numbers` → `queue.available_sequence_numbers(sub)`.
- `remove_retransmission_notifications(predicate)` callers (L536 id-set, L827/L846 single sub) →
  `queue.remove_subscription(sub)` per sub (reclaiming each), eliminating the per-sub full scan.

## Verification strategy (Iron Law)

- **Baseline (before)**: the full existing `async-opcua-server` unit + integration suite is green on
  current code — that is the behavioral characterization that must still pass after (SC-003).
- **New behavior tests (Claude)** on the `RetransmissionQueue` struct: global-FIFO eviction order,
  ack returns Some/None matching present/absent keys, insertion-ordered `available_sequence_numbers`,
  republish lookup hit/miss, per-subscription removal returns insertion order + leaves other subs
  intact, reclaim invoked on every removal path. Expected values derived from Part-4 + the current
  code's semantics — not from codex output.
- **Scaling test**: drive the queue to large N (e.g. 50k), then ack-flood and teardown; assert each
  completes within a generous ABSOLUTE wall-clock bound (a quadratic impl blows past it by orders of
  magnitude; sub-quadratic passes comfortably). Absolute bound avoids ratio-timing flakiness in CI.
- Keep/port the two existing tests (`keep_alive_messages_are_not_queued…`,
  `status_change_messages_are_queued…`) to the struct API.

## Open items
- None blocking. (The `debug_assert` on key uniqueness is the only judgement call; documented above.)
