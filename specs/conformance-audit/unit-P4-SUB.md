# Subscription reliable-delivery conformance audit — master plan

**What this is:** the top-down tracker for the server reliable-delivery-path audit that has so far run
piece-by-piece (feature 029 = queue overflow, feature 030 = state machine). It grew past what a single
feature spec can hold, so this file is the one board: full surface, what's audited, what's open, and
the order to finish it.

**Scope:** the OPC UA **Subscription / MonitoredItem reliable-delivery path** — the server behaviour a
producer-faster-than-consumer (DCS→PLC telegram) design leans on: per-MonitoredItem queues + overflow
signalling, the Publish/Acknowledge/Republish handshake, the retransmission queue, subscription
lifecycle (lifetime/keep-alive), and TransferSubscriptions. That maps to **Part 4 1.05.07 §5.13
(MonitoredItem Service Set)** and **§5.14 (Subscription Service Set)**.

**Spec source:** `~/opcua-specs/OPC 10000-4 - UA Specification Part 4 - Services 1.05.07.pdf`
(extracted to `/tmp/part4.txt` during an audit). The spec is authoritative — where the impl diverges,
the impl is wrong and is fixed to conform (user decision, 2026-06-23). Table 79 = the subscription
state table (§5.14.1.2, lines ~4947-5072 of the extract).

**Verification protocol (locked):** codex implements any production fix one task at a time (no tests,
no git); Claude authors all tests independently, anchored to the cited Part 4 text — never to the code.
This caught rigged tests before. PRs target the fork `occamsshavingkit/async-opcua`; wait for its full
Actions CI. One commit per piece (user story), not per finding.

**Out of scope:** Part 15 Safety re-sync; PubSub (UDP fire-and-forget) delivery; client-side library;
redundancy/failover. General service-shape conformance (status codes for Create/Modify/Delete) is
covered by the CTT smoke (feature 020) and is only pulled in here where it touches the delivery path.

---

## Status legend
- ✅ **conformant** — checked against spec text, no change needed (do NOT re-investigate)
- 🔧 **fixed** — divergence found and corrected in a merged feature
- 🟥 **open gap** — confirmed divergence, deliberately deferred (needs real work; see queue below)
- ⬜ **not yet audited** — in scope, not yet read against the spec
- ▫️ **low priority** — in §5.13/§5.14 but peripheral to the overload/delivery path; CTT smoke covers
  the request/response shape

---

## §5.13 MonitoredItem Service Set

| Subsection | Area | Status | Where |
|---|---|---|---|
| 5.13.1.2 | Sampling interval (revise, 0=fastest, neg=publishing rate) | ⬜ | `monitored_item.rs`, `subscription.rs` |
| 5.13.1.3 | Monitoring mode (Disabled/Sampling/Reporting → queueing) | ⬜ | `monitored_item.rs` SetMonitoringMode |
| 5.13.1.4 | Filter (DataChangeFilter deadband/trigger; EventFilter) | ⬜ | filter handling |
| 5.13.1.5 | **Queue parameters** — data-change overflow, Overflow bit, ordering | 🔧 029 | `monitored_item.rs::enqueue_notification` |
| 5.13.1.5 | **Event-queue overflow → EventQueueOverflowEventType** | 🟥 **D** | not built |
| 5.13.1.6 | Triggering model (triggering links pull triggered items) | ⬜ | SetTriggering path |
| 5.13.2-.6 | Create/Modify/SetMonitoringMode/SetTriggering/Delete — params + status codes | ▫️ | service handlers; CTT smoke (020) |

## §5.14 Subscription Service Set

| Subsection | Area | Status | Where |
|---|---|---|---|
| 5.14.1.2 | **State table (Table 79)** — transitions/actions | 🔧 030 | `subscription.rs` handle_state_transition |
| 5.14.1.2 | **Normal4/Normal5 guard** — first disjunct flipped, Normal5 dead | 🟥 **#1** | `subscription.rs:400` |
| 5.14.1.3/.4 | State variables, lifetime + keep-alive counters | ✅ 030 | lifetime close at 1; keep-alive `peek_next()` |
| 5.14.5 | **Publish** — request queue, NotificationMessage assembly, ordering | ◑ partly | `session_subscriptions.rs`, `mod.rs` |
| 5.14.5 | Publish-request queue overflow → `BadTooManyPublishRequests` | ✅ 030 | de-queues oldest |
| 5.14.6 | **Republish** — lifetime reset on valid id (rows 20/21) | 🔧 030 #4 | `session_subscriptions.rs::republish` |
| 5.14.6 | Republish status codes (`BadSubscriptionIdInvalid`/`BadMessageNotAvailable`) | ✅ 030 | Tables 89-93 |
| 5.14.7 | **TransferSubscriptions** — move sub + queued messages to new session | ◑ partly | `mod.rs::transfer` |
| 5.14.7 | **`Good_SubscriptionTransferred` to old session + lifetime reset** (rows 22/23) | 🟥 **#2** | `mod.rs::transfer` |
| 5.14.8 | DeleteSubscriptions — delete monitored items, final state | ⬜ | delete path |
| rule (i) | Retransmission queue — bounded ≥2× publish reqs, oldest-evicted, transfer-carried | ✅ 027/029 | `RetransmissionQueue` |
| — | Sequence numbers — +1, skip 0, first 1, roll to 1 | ✅ 029 | `Handle::new(1)` |
| Tables 89-93 | Acknowledge status codes (Good/`BadSequenceNumberUnknown`/`BadSubscriptionIdInvalid`) | ✅ 030 | ack path |

---

## Open gaps — the actionable queue (fix order)

These three are confirmed divergences, deliberately deferred from 029/030 because each needs a real
mechanism or a risky state-machine change. Fix in this order (cheapest/most-contained first):

### 1. #1 — Normal4/Normal5 Publish guard (state-machine, small diff) — **next**
`subscription.rs:400` Normal4 guard's first disjunct is `self.publishing_enabled` where Table 79 row 4
says `PublishingEnabled == FALSE`. Effect: `(enabled, more)` wrongly matches Normal4 (None) so
**Normal5** (`reset_lifetime_counter()` + `ReturnNotifications`, row 5) is **dead code**. Masked today
by the `IntervalElapsed6` timer tick resetting the counter → low live harm, but a real conformance +
dead-code gap.
- **Fix:** first disjunct → `!self.publishing_enabled`.
- **Risk:** state-machine change. Must re-verify existing lifetime/keep-alive tests
  (`subscription.rs` ~1538-1639) and add a focused test: an *enabled* subscription with queued
  notifications returns them + resets the counter on a Publish request.
- **Size:** S (one-line prod change, the work is the regression + focused test).

### 2. D — EventQueueOverflowEventType (additive feature)
§5.13.1.5: on the **first** discarded Event on an event MonitoredItem, place an
`EventQueueOverflowEventType` Event in the queue **in addition to** QueueSize (front if discardOldest,
else end; itself never discarded). `monitored_item.rs::enqueue_notification` sets no event overflow
indicator and never constructs the event.
- **Fix:** build the EventQueueOverflowEventType EventFieldList per the subscription's event filter,
  enqueue-on-first-discard with correct placement, exempt it from discard.
- **Risk:** additive, self-contained; the work is constructing a spec-correct event that satisfies the
  client's select clauses.
- **Size:** M.

### 3. #2 — TransferSubscriptions: Good_SubscriptionTransferred + lifetime reset (needs a mechanism)
`mod.rs::transfer` moves the sub to the new session but never (a) issues a StatusChangeNotification
with `Good_SubscriptionTransferred` to the **old** session, nor (b) resets the lifetime counter
(Table 79 rows 22/23; §5.14.7 body).
- **Fix:** (b) is a one-liner. (a) needs a per-session list of pending "departed-subscription" status
  notifications, drained on the old session's next Publish — the sub and its queued messages have
  already moved away.
- **Risk:** MODERATE/HIGH — design the old-session delivery mechanism first. Not a drive-by.
- **Size:** L.

---

## Not-yet-audited areas — future audit pieces (priority order)

Each is a candidate next feature, read against the cited spec text with the verification protocol
above. Prioritised by relevance to the overload/reliable-delivery path:

1. **§5.13.1.3 Monitoring mode + §5.13.1.2 Sampling interval** — how/when samples enter the queue
   (Disabled = no sampling, Sampling = sample-no-report, Reporting = both; interval revision, 0 and
   negative semantics). Directly governs producer rate into the bounded queue. **High.**
2. **§5.13.1.4 DataChangeFilter** — deadband + trigger (Status/StatusValue/StatusValueTimestamp)
   decide which samples are even queued; wrong filtering = wrong overflow behaviour. **High.**
3. **§5.14.5 Publish assembly** — NotificationMessage packing, multiple subscriptions per session,
   keep-alive vs data, publishing-interval timer correctness end-to-end (live test, not just counters).
   **Medium-High.**
4. **§5.13.1.6 Triggering model** — triggered items report when a linked triggering item fires.
   **Medium.**
5. **§5.14.8 DeleteSubscriptions / §5.13.6 DeleteMonitoredItems** — final-state cleanup, queued-message
   disposition. **Low-Medium.**
6. **§5.13.2-.6 / §5.14.2-.4 service shapes** — Create/Modify params + status codes. **Low** (CTT smoke
   already exercises the matrix; only audit if a real defect surfaces).

---

## Verified conformant (do NOT re-investigate)
From 029/030, checked against spec text:
- Sequence numbers: +1, skip 0, first 1, roll over to 1 (`Handle::new(1)`, handle.rs).
- Keep-alive: `peek_next()` (no increment); first-message keep-alive carries seq 1.
- Retransmission queue: bounded ≥2× publish requests, oldest-evicted on overflow, queued messages move
  to the new session on transfer (027 + 029, rule (i)).
- Status codes: Republish, Acknowledge, `BadTooManyPublishRequests` (de-queues oldest), `BadNoSubscription`
  (Tables 89-93).
- `available_sequence_numbers`: empty → None, prepared after enqueue.
- Lifetime close at counter==1 (functionally equivalent to spec).
- Data-change queue overflow: both discard modes, Overflow-bit placement, QueueSize 1 vs >1, ordering
  (029, the four `part4_overflow_*` tests).

---

## Done
- **Feature 029** (merged): §5.13.1.5 data-change queue overflow — 3 bugs fixed + 1 dead state removed.
- **Feature 030** (merged): §5.14.1.2 state-machine/lifecycle audit; fixed #4 (Republish lifetime reset).
