# Data Model: Bounded-Time Subscription Retransmission Queue

## RetransmissionQueue (new struct, `retransmission_queue.rs`)

Encapsulates the per-session sent-but-unacknowledged notification store.

| Field | Type | Purpose |
|---|---|---|
| `entries` | `BTreeMap<u64, NonAckedPublish>` | insertion_id → entry; ordered = global insertion order; `pop_first()` = oldest. |
| `index` | `HashMap<(u32, u32), u64>` | `(subscription_id, sequence_number)` → insertion_id; O(1) keyed lookup. |
| `by_subscription` | `HashMap<u32, BTreeSet<u64>>` | subscription_id → its insertion_ids, ordered. |
| `next_id` | `u64` | monotonic insertion counter. |

`NonAckedPublish { message: Arc<NotificationMessage>, subscription_id: u32 }` is unchanged (lives in
`mod.rs`); the sequence number is `message.sequence_number`.

### Invariants
- `(subscription_id, sequence_number)` is unique within the queue (seqs strictly monotonic per sub +
  bounded length ⇒ no recurrence without a u32 wrap). `debug_assert!` no index overwrite on enqueue.
- `entries`, `index`, and `by_subscription` are always consistent: every entries key appears in
  exactly one `by_subscription` set and once in `index`, and vice versa.
- `entries.len()` ≤ `max_retransmission_queue_len`.

### Operations (all sub-quadratic)
| Method | Behavior | Cost |
|---|---|---|
| `enqueue(pool, max_len, sub, message)` | skip keep-alive (no notification_data); if at capacity, `pop_first` oldest + reclaim-to-pool; assign next_id; insert into all three maps. | O(log n) |
| `ack(sub, seq) -> Option<NonAckedPublish>` | remove `(sub,seq)` from index→insertion_id, remove from entries + by_subscription; return the entry (caller reclaims) or `None`. | O(log n) |
| `remove_subscription(sub) -> Vec<NonAckedPublish>` | drain `by_subscription[sub]` (ascending insertion_id = insertion order), remove each from entries + index; return entries in insertion order. | O(k log n) |
| `available_sequence_numbers(sub) -> Option<Vec<u32>>` | map `by_subscription[sub]` (ordered) to `entries[id].message.sequence_number`; `None` if queue empty or sub has none. | O(k) |
| `get_message(sub, seq) -> Option<Arc<NotificationMessage>>` | index → entries → clone `message`. | O(1)+clone |
| `len` / `is_empty` | entries length. | O(1) |

### Reclaim-to-pool
`ack`, `remove_subscription`, and capacity eviction all surface or perform reclaim of the removed
`NonAckedPublish` into the `DataChangeNotificationVecPool` exactly as the current code does (enqueue
performs eviction-reclaim internally; ack/remove return the entries so the caller reclaims, matching
today's flow).

## Behavior preserved (client-observable)
- Global-FIFO eviction order (by insertion id).
- Ack status: `BadSubscriptionIdInvalid` (unknown sub, checked against `subscriptions`),
  `BadSequenceNumberUnknown` (ack returns `None`), `Good` (ack returns `Some`).
- `available_sequence_numbers` insertion ordering and `None`-when-empty.
- Republish hit/miss and message bytes.
- `remove_subscription` returns entries in insertion order (for subscription transfer re-enqueue).
