# Feature 029 — STATUS

Spec is authoritative (user decision 2026-06-23): where the implementation diverges from OPC UA Part
4 1.05.07 §5.13, the implementation is wrong and is fixed to conform.

## US1 — MonitoredItem queue overflow (§5.13.1.5): DONE (3 bugs fixed + 1 dead-state removed)

How deep the hole went, all confirmed with spec-anchored tests driving `enqueue_notification` with a
known-empty start, and fixed in `async-opcua-server/src/subscriptions/monitored_item.rs`:

- **A — overflow-bit placement (FIXED)**: with `discardOldest=TRUE` the impl flagged the *newest*
  appended value (and accumulated flags across repeated overflows). Spec: delete the oldest and flag
  "the NEXT value in the queue" (the new front); only the current front is ever flagged. Fixed.
- **B — QueueSize==1 (FIXED)**: the impl set the Overflow bit at queue size 1. Spec sets it only when
  "the size of the queue is larger than one"; at size 1 the discard policy is ignored and no bit is
  set. Fixed (bit gated on `queue_size > 1`).
- **C — `modify()` queue-shrink discarded the WRONG end (FIXED)**: the shrink loop's discard
  direction was INVERTED vs `enqueue_notification` — `discardOldest=TRUE` dropped the newest and vice
  versa. A client resizing a monitored-item queue smaller would lose the wrong values. Fixed to match
  enqueue (`discardOldest=TRUE → pop_front`).
- **E — dead `queue_overflow` field (REMOVED)**: written on overflow but never read anywhere;
  removed so the state isn't misleading.
- `discardOldest=FALSE` overflow ("replace last-added, flag the new value") was already correct —
  locked with a regression test.
- The pre-existing `monitored_item_overflow` test encoded bug A; corrected to the spec (flag on the
  front), not weakened.

Tests: 4 new `part4_overflow_*` tests + corrected existing test; full `async-opcua-server` suite and
9 end-to-end `async-opcua` integration subscription tests green.

## US2 — Republish / ack / sequence-number behavior: DONE

- Republish now has coverage for held messages and evicted messages returning
  `Bad_MessageNotAvailable`.
- Publish acknowledgement result coverage verifies ordered `Good`, `Bad_SequenceNumberUnknown`, and
  `Bad_SubscriptionIdInvalid` responses.
- Live subscription coverage verifies sequence numbers skip 0, roll over to 1, and remain
  republishable after the wrap.

## US3 — Lifecycle / request-queue behavior: DONE

- Lifetime expiry coverage verifies `Bad_Timeout` `StatusChangeNotification`, subscription removal,
  and post-expiry monitored-item ownership failure.
- Publish-request queue pressure coverage verifies the oldest request is rejected with
  `Bad_TooManyPublishRequests` and newer queued requests still complete.
- Event queue overflow is implemented and covered end-to-end by
  `event_queue_overflow_inserts_overflow_event`: the first discarded event inserts a single
  `EventQueueOverflowEventType` in addition to the retained event queue.

## Remaining in this feature

- Polish verification (T011) and final PR/sync bookkeeping (T012).
