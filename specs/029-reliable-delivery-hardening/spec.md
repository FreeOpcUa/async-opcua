# Feature Specification: Reliable Notification-Delivery Hardening

**Feature Branch**: `029-reliable-delivery-hardening`
**Created**: 2026-06-22
**Status**: Draft
**Input**: Harden + characterize the OPC UA server reliable notification-delivery path (MonitoredItem
queues, overflow, Publish/Acknowledge/Republish, subscription lifecycle) for the
producer-faster-than-consumer pattern a DCS→PLC telegram design relies on. Spec behavior is anchored
EXACTLY to the local OPC UA spec at `~/opcua-specs/OPC 10000-4 - UA Specification Part 4 - Services
1.05.07.pdf` (§5.13).

## Background & Problem Statement

A control system that pushes data faster than a consumer drains it relies on OPC UA's
subscription-side reliable delivery: per-MonitoredItem queues with a discard policy + Overflow
signal, ordered NotificationMessages with sequence numbers, the Publish/Acknowledge handshake, the
retransmission queue + Republish for loss recovery, and defined lifecycle timeouts. An assessment of
`async-opcua-server` found this path is **implemented**, but the **failure modes that matter under
overload are largely untested** — exactly the conditions a telegram producer hits. Untested behavior
on a reliability path is a latent correctness risk; a subtle bug (e.g. wrong discard-newest handling,
or a missing Overflow bit) would mean silent telegram loss with no signal.

This feature characterizes and hardens those failure modes with tests anchored to the exact Part 4
rules, and fixes any production defect a test uncovers. It is behavior-verifying, not
behavior-changing — except where the current behavior is found to violate the spec, in which case the
fix makes it conform.

## Exact spec rules being verified (Part 4 1.05.07)

- **§5.13.1.5 Queue overflow**: queue full + new Notification → either discard oldest and queue the
  new, or **replace the last value added** with the new. If a Notification is discarded for a
  DataValue **and queue size > 1**, the **Overflow bit (InfoBits of the DataValue statusCode) is
  set**. `discardOldest=TRUE` → oldest deleted, the **next** value in the queue gets the flag.
  `discardOldest=FALSE` → the **last value added is replaced** with the new value, and **the new
  value gets the flag**. **Queue size == 1 ⇒ discard policy ignored** (always newest; no Overflow).
  Notifications for an item are returned **in queue order**.
- **§5.13.1.5 Events**: on first discard, an **EventQueueOverflowEventType** Event is placed in the
  queue **in addition to** QueueSize (not displacing others); `discardOldest=TRUE` → at the
  beginning (never discarded), else at the end.
- **Lifetime (h)**: the lifetime counter counts consecutive publishing cycles with no Publish request
  available; reset by any SubscriptionId service call or a processed Publish response; on reaching the
  lifetime, the Subscription is **closed, its MonitoredItems deleted, and a StatusChangeNotification
  with `Bad_Timeout` issued**.
- **Retransmission (i)**: NotificationMessages retained until acknowledged; queue ≥ 2× the session's
  Publish-request count; **overflow deletes the oldest**; a non-empty `availableSequenceNumbers`
  obliges the Client to acknowledge; on subscription transfer the queued messages move to the new
  Session.
- **Sequence numbers**: unsigned 32-bit, +1 per NotificationMessage, **0 is never used, the first is
  1, and on roll-over it returns to 1**. Republish of an unavailable message → `Bad_MessageNotAvailable`;
  ack of an unknown sequence → `Bad_SequenceNumberUnknown`; unknown subscription → `Bad_SubscriptionIdInvalid`.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Consumer falls behind without silent loss (Priority: P1)

When a subscribing consumer drains slower than the producer, the server's bounded queues absorb the
burst and any loss is **signaled** (Overflow bit / discarded-message count / available-sequence
reporting), never silent.

**Why this priority**: Silent telegram loss is the worst failure for a control system; the consumer
must be able to detect it.

**Independent test**: drive a MonitoredItem and a subscription past their queue bounds with a slow
consumer; assert the documented overflow signals appear and ordering holds.

**Acceptance Scenarios**:
1. **Given** a data-change MonitoredItem with QueueSize N>1 and `discardOldest=TRUE`, **When** more
   than N notifications arrive before a publish, **Then** the oldest are dropped, the surviving
   next value carries the **Overflow bit**, and the queue is delivered in order.
2. **Given** the same item with `discardOldest=FALSE`, **When** the queue overflows, **Then** the
   **last-added value is replaced** by the newest and **that newest value carries the Overflow bit**
   (Part 4 §5.13.1.5).
3. **Given** QueueSize == 1, **When** values over-sample, **Then** the newest is always delivered and
   **no Overflow bit** is set (discard policy ignored).
4. **Given** a subscription whose queued NotificationMessages exceed `max_queued_notifications`,
   **When** the consumer lags, **Then** the oldest are dropped, `discarded_message_count` increases,
   and `availableSequenceNumbers` reports only still-held messages.

---

### User Story 2 - Loss recovery and acknowledgement correctness (Priority: P2)

The Publish/Acknowledge/Republish handshake recovers lost messages while still held and reports
precise status codes at the boundaries.

**Why this priority**: This is the reliable-delivery handshake the telegram design leans on; its
boundary behavior (still-held vs evicted) must be exact.

**Independent test**: exercise Republish for a still-held sequence and for one just evicted past the
retransmission bound; exercise ack of valid/unknown sequences and unknown subscriptions.

**Acceptance Scenarios**:
1. **Given** a held NotificationMessage, **When** the consumer Republishes its sequence number,
   **Then** the exact message is returned.
2. **Given** a sequence number evicted past the retransmission-queue bound (oldest deleted on
   overflow), **When** Republished, **Then** `Bad_MessageNotAvailable`.
3. **Given** acknowledgements, **When** processed, **Then** present → Good, absent sequence →
   `Bad_SequenceNumberUnknown`, unknown subscription → `Bad_SubscriptionIdInvalid`.
4. **Given** sequence numbers across many publishes, **When** observed, **Then** they are strictly
   +1, skip 0, start at 1, and roll over to 1 — verified in a live subscription, not just the counter.

---

### User Story 3 - Lifecycle timeouts behave per spec (Priority: P3)

A quiet or unserviced subscription times out exactly as Part 4 specifies, and request-queue pressure
is reported, so a telegram channel neither silently dies nor floods.

**Why this priority**: Surprise subscription death or unhandled request-queue overflow disrupts a
long-lived telegram channel.

**Independent test**: starve a subscription of Publish requests until lifetime expiry; flood
publish requests past the session bound.

**Acceptance Scenarios**:
1. **Given** a subscription with no Publish requests available for its full lifetime, **When** the
   lifetime counter expires, **Then** a `Bad_Timeout` StatusChangeNotification is issued and the
   subscription (and its MonitoredItems) is removed.
2. **Given** a session at its Publish-request limit, **When** another Publish request arrives,
   **Then** `Bad_TooManyPublishRequests` is returned and earlier requests still complete.

### Edge Cases
- discardOldest=FALSE with QueueSize 1 (policy ignored) vs QueueSize 2 (replace-last + flag-newest).
- Event-queue overflow: an `EventQueueOverflowEventType` event is enqueued on first discard, in
  addition to QueueSize (verify presence/placement if implemented; document as a gap if not).
- Republish exactly at the eviction boundary (oldest still-held vs just-evicted).
- Sequence roll-over to 1 (never 0) with Republish still working after the wrap.
- Subscription transfer carrying queued NotificationMessages to the new session.

## Requirements *(mandatory)*

### Functional Requirements
- **FR-001**: A characterization/integration test suite MUST verify the §5.13.1.5 overflow rules for
  data-change items in BOTH discard modes and for QueueSize 1 vs >1, including the exact Overflow-bit
  placement, anchored to Part 4.
- **FR-002**: Tests MUST verify subscription-level queue pressure: oldest dropped past
  `max_queued_notifications`, `discarded_message_count` incremented, `availableSequenceNumbers`
  reflecting only held messages.
- **FR-003**: Tests MUST verify Republish of a held message returns it and Republish past the
  retransmission bound returns `Bad_MessageNotAvailable`; ack status codes per spec.
- **FR-004**: Tests MUST verify sequence-number semantics in a live subscription: +1, skip 0, start
  1, roll over to 1.
- **FR-005**: Tests MUST verify lifetime expiry → `Bad_Timeout` StatusChangeNotification + monitored
  items removed; and Publish-request-queue overflow → `Bad_TooManyPublishRequests`.
- **FR-006**: Any production behavior a test finds to VIOLATE the cited Part 4 rule MUST be fixed so
  it conforms (minimal, fail-closed); behavior that already conforms MUST NOT change.
- **FR-007**: Where a documented rule is NOT implemented (e.g. EventQueueOverflowEventType), the
  feature MUST either implement it minimally or record it as a documented gap with a test marked
  accordingly — never silently leave it unverified.
- **FR-008**: No client-observable behavior changes except spec-conformance fixes; no new runtime
  dependency.

### Key Entities *(include if data involved)*
- **MonitoredItem queue**: bounded per-item notification queue (QueueSize, discardOldest, Overflow bit).
- **Subscription notification queue**: bounded per-subscription message queue (`max_queued_notifications`,
  `discarded_message_count`).
- **Retransmission queue**: sent-but-unacked NotificationMessages (027), bounded, oldest-evicted.
- **NotificationMessage**: sequence-numbered payload; `availableSequenceNumbers` lists held ones.

## Success Criteria *(mandatory)*

### Measurable Outcomes
- **SC-001**: Every §5.13.1.5 overflow rule (both discard modes, QueueSize 1 vs >1, Overflow-bit
  placement, queue ordering) has a passing test anchored to the spec text.
- **SC-002**: Consumer-lag, Republish-boundary, ack-status, sequence-number (incl. roll-over), and
  lifecycle-timeout behaviors each have a passing test.
- **SC-003**: Any spec violation found is fixed and re-verified; the pre-existing server suite stays
  green; no client-observable change beyond conformance fixes.
- **SC-004**: No new dependency; clippy `-D warnings` (all-features + no-default-features) and fmt
  clean; the fork's full Actions CI is green.

## Assumptions
- Behavior is judged against the LOCAL Part 4 1.05.07 spec text (cited above), not memory.
- Verification division: Claude authors all tests (anchored to Part 4); codex implements any
  production fix a failing test reveals (one task per dispatch, no tests, no git).
- PRs target the fork `occamsshavingkit/async-opcua`.

## Out of Scope
- The SIL-3 Safety (Part 15) re-sync handshake (separate feature).
- PubSub-side delivery (UDP fire-and-forget) — this is the Subscription/Publish path only.
- Client-side (consumer) library changes — server-side reliable-delivery path only.
- Redundancy / failover.
