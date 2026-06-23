# Subscription delivery-path conformance audit (vs Part 4 1.05.07 §5.13)

Continuation of the §5.13 audit after feature 029 (queue-overflow: 3 bugs fixed + merged). Each
finding cites the code and the exact spec rule (extracted text in /tmp/part4.txt during the audit;
authoritative source ~/opcua-specs Part 4 1.05.07). Table 79 = the subscription state-machine table.

## FIXED in this feature
- **#4 — Republish does not reset the lifetime counter** (`session_subscriptions.rs::republish`).
  Table 79 rows 20 (message found) & 21 (not found) + rule (h): a Republish on a valid SubscriptionId
  `ResetLifetimeCounter()`. FIXED: republish is now `&mut self`, resets the matched subscription's
  lifetime counter before the message lookup. (Caller in mod.rs takes a mutable guard.)

## CONFIRMED divergences — NOT fixed here (each needs deliberate work)

### #1 — `Normal` Publish-request guard wrong; `Normal5` is dead code  [conformance, currently masked]
`subscription.rs:400` Normal4 guard: `self.publishing_enabled || !self.publishing_enabled && !p.more_notifications`
→ simplifies to `enabled || !more`. Table 79 row 4 condition is `PublishingEnabled == FALSE ||
(PublishingEnabled == TRUE && MoreNotifications == FALSE)` = `!enabled || !more`. The first disjunct's
truth value is flipped (`enabled` vs `!enabled`). Consequence: for `(enabled, more)` the code matches
Normal4 (`UpdateStateAction::None`) and **Normal5 (`reset_lifetime_counter()` + `ReturnNotifications`,
row 5) is unreachable**.
- Observable impact: LOW in normal operation — the missed lifetime reset is compensated by the
  `IntervalElapsed6` timer-tick arm (`subscription.rs` handle_state_transition), and queued messages
  are drained at the session level regardless. But it is a real conformance + dead-code gap; under
  unusual timing the missed reset / deferred return could surface.
- Fix: change the Normal4 guard's first disjunct to `!self.publishing_enabled` so row 4/row 5 match
  the spec and Normal5 becomes reachable. RISK: state-machine change — must re-verify the existing
  lifetime/keep-alive counter tests (subscription.rs ~1538-1639) and add a focused test that an
  enabled subscription with queued notifications returns them + resets the counter on a Publish
  request.

### #2 — `TransferSubscriptions` omits `Good_SubscriptionTransferred` + lifetime reset  [missing action]
`mod.rs::transfer` (lines 807-829) removes the sub from the old session and inserts into the new, but
never (a) issues a StatusChangeNotification with `Good_SubscriptionTransferred` to the OLD session, nor
(b) resets the lifetime counter. Table 79 row 23: `TransferSubscriptions && SessionChanged==TRUE →
SetSession() / ResetLifetimeCounter() / ReturnResponse() / IssueStatusChangeNotification()`; row 22
(SessionChanged==FALSE) also `ResetLifetimeCounter()`. Spec body: "the Server shall issue a
StatusChangeNotification ... Good_SubscriptionTransferred to the old Session."
- Fix complexity: MODERATE/HIGH — (a) needs a mechanism for the OLD session to deliver a status change
  for a subscription it no longer owns (the sub + its queued messages move to the new session), e.g. a
  per-session list of pending "departed-subscription" status notifications drained on the old session's
  next Publish. Not a one-liner.

### D — Event-queue overflow: `EventQueueOverflowEventType` not produced  [missing feature]
§5.13.1.5: on the FIRST discarded Event on an event MonitoredItem, an `EventQueueOverflowEventType`
Event is placed in the queue IN ADDITION to QueueSize (front if discardOldest, else end; never itself
discarded). `monitored_item.rs::enqueue_notification` sets no overflow indicator for events and never
constructs this event. Missing feature — needs building the EventQueueOverflowEventType EventFieldList
per the subscription's event filter.

## Verified CONFORMANT (checked, no change needed)
- Sequence numbers: `Handle::new(1)` — +1, skip 0, first 1, roll over to 1 (rule + handle.rs). ✓
- Keep-alive: `peek_next()` (no increment); first-message keep-alive carries seq 1. ✓
- Retransmission queue overflow deletes the globally oldest; sized ≥ 2× publish requests; transfer
  moves queued messages to the new session (feature 029 + rule (i)). ✓
- Status codes: Republish (`BadSubscriptionIdInvalid`/`BadMessageNotAvailable`), Acknowledge
  (`Good`/`BadSequenceNumberUnknown`/`BadSubscriptionIdInvalid`), `BadTooManyPublishRequests`
  (de-queues oldest), `BadNoSubscription`. ✓ (Tables 89-93)
- `available_sequence_numbers` empty → None, prepared after enqueue. ✓
- Lifetime close at counter==1 (functionally equivalent to spec). ✓

## Suggested order for the follow-up fixes
1. #1 (state guard) — small diff, but state-machine; do with focused + regression tests.
2. #2 (Good_SubscriptionTransferred + transfer lifetime reset) — needs the old-session delivery
   mechanism; design first.
3. D (EventQueueOverflowEventType) — additive feature.
