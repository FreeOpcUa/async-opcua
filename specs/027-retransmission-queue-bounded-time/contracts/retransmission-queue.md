# Contract: RetransmissionQueue

Behavioral contract for the new `RetransmissionQueue` (internal to `async-opcua-server`). "MUST"
items are test acceptance criteria. Anchored to OPC UA Part 4 Publish/Republish semantics + the
pre-refactor behavior.

## Construction & capacity
- A new queue is empty; `is_empty()` true, `len()` 0.
- `enqueue` MUST skip messages with no notification data (keep-alive) — they never enter the queue.
- When `len() == max_retransmission_queue_len`, the next `enqueue` MUST first evict the **globally
  oldest** entry (smallest insertion id, i.e. earliest pushed, regardless of subscription) and
  reclaim it to the pool, then insert the new entry. `len()` never exceeds the max.

## Keyed operations
- `ack(sub, seq)` MUST return `Some(entry)` and remove it iff `(sub, seq)` is present; otherwise
  `None`, leaving the queue unchanged.
- `get_message(sub, seq)` (Republish) MUST return the stored `Arc<NotificationMessage>` iff present,
  else `None`.
- `(sub, seq)` is treated as unique; enqueuing a duplicate key is a protocol-impossible case
  (`debug_assert`), not a supported scenario.

## Per-subscription operations
- `remove_subscription(sub)` MUST remove and return ALL of that subscription's entries **in
  insertion order**, leave every other subscription's entries untouched, and return an empty vec for
  an unknown/empty subscription.
- `available_sequence_numbers(sub)` MUST return that subscription's sequence numbers in **insertion
  order**, `None` when the queue is empty or the subscription has no entries.

## Caller-level (session_subscriptions) status mapping — unchanged
- Ack of an unknown subscription → `BadSubscriptionIdInvalid` (checked before the queue).
- Ack returning `None` → `BadSequenceNumberUnknown`.
- Ack returning `Some` → `Good` (entry reclaimed to pool).

## Complexity (SC-001)
- enqueue / ack / evict: O(log n). remove_subscription: O(k log n). available_sequence_numbers:
  O(k). get_message: O(1)+clone. No operation is O(n²) / O(acks·n) / O(removed·n).

## Non-functional
- No new runtime dependency (std collections only).
- Reclaim-to-pool occurs on every removal path (ack, remove_subscription, eviction).
- No client-observable behavior change vs. the pre-refactor implementation.
