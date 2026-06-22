# Feature Specification: Bounded-Time Subscription Retransmission Queue

**Feature Branch**: `027-retransmission-queue-bounded-time`
**Created**: 2026-06-22
**Status**: Draft
**Input**: Performance backlog Tier 1 — remove the O(n²) blowup in the server per-session
retransmission queue so a publish/acknowledge flood or a many-subscription teardown cannot spike
latency or be used as a cheap denial of service.

## Background & Problem Statement

The OPC UA server keeps, per session, a **retransmission queue** of sent-but-not-yet-acknowledged
notification messages (so a client can Republish a lost message). Today this queue is a flat FIFO
(`retransmission_queue: VecDeque<NonAckedPublish>` in
`async-opcua-server/src/subscriptions/session_subscriptions.rs`) bounded by a maximum length, with
the oldest entry evicted when full.

Two operations on it are quadratic and are reachable from ordinary, attacker-influenceable client
traffic:

1. **Subscription teardown** — `SessionSubscriptions::remove(subscription_id)` drains every entry
   belonging to one subscription with a `while` loop calling `VecDeque::remove(idx)`. Each removal
   shifts the deque (O(n)); looped over all matches → **O(n²)**.
2. **Acknowledgement processing** — `process_subscription_acks` handles each acknowledgement in a
   PublishRequest with a linear search (`iter().enumerate().find(...)`) followed by
   `VecDeque::remove(idx)`. A request carrying many acknowledgements → **O(acks · n) ≈ O(n²)**. (The
   code already carries a comment conceding this is "potentially inefficient" on the assumption the
   queue is short — an assumption that fails under load.)

For a control-system (PLC/DCS) server handling many subscriptions and high notification rates, this
turns a busy-period publish/ack burst into a latency spike, and gives a malicious or misbehaving
client a cheap asymmetric DoS: a single PublishRequest with many acknowledgements, or repeated
subscription churn, forces quadratic server work.

This feature replaces the retransmission-queue data structure so these operations run in
sub-quadratic time, **with no change to behavior observable by clients** — same eviction order, same
acknowledgement status codes, same available-sequence-number reporting.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Sub-quadratic acknowledgement and teardown (Priority: P1)

A server under a flood of acknowledgements (one PublishRequest carrying many
SubscriptionAcknowledgements) or a burst of subscription deletions processes them in sub-quadratic
time, so per-request latency stays bounded and the work cannot be amplified into a denial of
service. The externally observable results are identical to today.

**Why this priority**: This is the fix. It removes the only quadratic path in the retransmission
queue and is what protects a loaded control-system server.

**Independent test**: Drive the queue to its bound, then (a) acknowledge a large batch in one
request and (b) tear down a subscription with many queued entries; assert the results match the
current implementation's results and that the time/work scales sub-quadratically with queue length.

**Acceptance Scenarios**:

1. **Given** a retransmission queue holding many unacknowledged messages for a subscription,
   **When** that subscription is deleted, **Then** all of its entries are removed, entries for other
   subscriptions are untouched, and the work done scales sub-quadratically with queue length.
2. **Given** a full retransmission queue, **When** a single PublishRequest acknowledges many
   sequence numbers, **Then** each acknowledgement yields exactly the status code it yields today
   (Good for a present `(subscription, sequence)`, BadSequenceNumberUnknown for an absent sequence,
   BadSubscriptionIdInvalid for an unknown subscription) and the batch is processed in sub-quadratic
   time.
3. **Given** the queue is at its maximum length, **When** a new notification is enqueued, **Then**
   the globally oldest entry (by insertion order, across all subscriptions) is evicted — exactly as
   today — and a Republish for an evicted message fails as it does today.

---

### User Story 2 - Behavior-preserving characterization & scaling guarantees (Priority: P2)

The change is locked in by tests that (a) capture the current observable behavior and pass both
before and after the refactor, and (b) demonstrate the absence of quadratic growth.

**Why this priority**: The Iron Law for a complexity refactor — a faster-but-wrong queue is worse
than a slow-but-right one. The tests are the proof the refactor preserved Part-4 Publish/Republish
semantics.

**Independent test**: Run the characterization suite against the pre-refactor code (it passes) and
against the post-refactor code (it still passes); run the scaling assertion and confirm growth is
sub-quadratic.

**Acceptance Scenarios**:

1. **Given** the characterization suite (eviction order, acknowledgement status codes,
   available-sequence-number ordering, removal correctness), **When** it runs against the current
   implementation, **Then** it passes — establishing the behavioral baseline.
2. **Given** the same suite, **When** it runs against the refactored implementation, **Then** it
   still passes unchanged (no assertion weakened or removed).
3. **Given** a scaling probe over increasing queue sizes for the ack-flood and teardown paths,
   **When** measured, **Then** the work/time does not exhibit quadratic growth (consistent with
   sub-quadratic complexity).

### Edge Cases

- Acknowledging a `(subscription, sequence)` that is not in the queue → BadSequenceNumberUnknown
  (unchanged); an acknowledgement for an unknown subscription → BadSubscriptionIdInvalid (unchanged).
- Deleting a subscription with **zero** queued entries → no-op, other subscriptions untouched.
- Two subscriptions interleaved in the queue with overlapping per-subscription sequence numbers
  (sequence numbers are per-subscription, so duplicates across subscriptions are normal) → removal
  and acknowledgement affect only the addressed `(subscription, sequence)`.
- Capacity eviction while entries for several subscriptions are interleaved → the *globally oldest*
  entry is evicted regardless of which subscription it belongs to (global insertion order, NOT
  `(subscription, sequence)` order).
- `available_sequence_numbers(subscription)` returns that subscription's sequence numbers in the
  same order as today.
- Empty-queue operations (acknowledge / available-sequence-numbers / remove) behave as today.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Removing all retransmission entries for a subscription MUST run in sub-quadratic time
  with respect to the total queue length (target: O(k log n) for k removed of n total, or better).
- **FR-002**: Processing a batch of acknowledgements MUST run in sub-quadratic time with respect to
  queue length (target: O(acks · log n) or better; no per-acknowledgement linear scan of the queue).
- **FR-003**: Acknowledgement status codes MUST be unchanged: Good when the `(subscription,
  sequence)` is present, BadSequenceNumberUnknown when absent, BadSubscriptionIdInvalid when the
  subscription is unknown.
- **FR-004**: Capacity-bounded eviction MUST remain **global FIFO** — when the queue is full the
  globally oldest entry by insertion order is evicted, independent of subscription — preserving
  today's behavior (note: per-subscription sequence-number order is NOT global insertion order).
- **FR-005**: `available_sequence_numbers(subscription)` MUST return the same sequence numbers in the
  same order as today.
- **FR-006**: Republish MUST continue to return a stored message when present and the same failure
  status when the message has been evicted or acknowledged, exactly as today.
- **FR-007**: The change MUST be behavior-preserving — no difference observable by an OPC UA client
  in status codes, message availability, eviction, or ordering.
- **FR-008**: The change MUST add no new runtime dependency (prefer the standard library; only use an
  already-present crate if the standard library is clearly worse, and call it out).
- **FR-009**: A characterization test capturing the current observable behavior MUST pass against the
  pre-refactor code and continue to pass against the refactored code, with no assertion weakened.
- **FR-010**: A scaling assertion MUST demonstrate the ack-flood and teardown paths do not grow
  quadratically with queue length.

### Key Entities *(include if data involved)*

- **Retransmission queue**: the per-session collection of sent-but-unacknowledged notification
  messages, bounded by a maximum length, evicted global-oldest-first.
- **NonAckedPublish entry**: one stored notification, keyed for lookup/removal by `(subscription_id,
  sequence_number)` and ordered for eviction by global insertion order.
- **Subscription acknowledgement**: a client-supplied `(subscription_id, sequence_number)` pair that
  removes the matching entry and yields a status code.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Acknowledging N entries in one request and tearing down a subscription with N queued
  entries each complete in sub-quadratic time — measured work/time grows no worse than `n log n`
  across increasing N (no quadratic curve).
- **SC-002**: 100% of acknowledgement status codes, eviction outcomes, available-sequence-number
  orderings, and Republish results are identical to the pre-refactor implementation across the
  characterization suite.
- **SC-003**: The existing async-opcua-server unit and integration suites pass unchanged.
- **SC-004**: No new runtime dependency is added; `cargo clippy --all-targets --all-features`, the
  `no-default-features` leg, and the `json`-off leg are clean under `-D warnings`; the fork's full
  Actions CI is green.

## Assumptions

- The retransmission queue's maximum length and global-FIFO eviction policy are intentional and must
  be preserved; this feature changes only the data structure's time complexity, not its policy.
- OPC UA sequence numbers are per-subscription, so `(subscription_id, sequence_number)` is a unique
  key within the queue while a single `sequence_number` is not.
- A standard-library structure (e.g. a keyed map plus an order index) is sufficient; no new crate is
  expected (re-raised with the user if that proves false).
- Verification division holds: the production refactor is implemented by codex (no tests, no git);
  all tests are authored and run independently by Claude, anchored to OPC UA Part 4 Publish/Republish
  semantics and the pre-refactor behavior, not to the implementation under test.
- PRs target the fork `occamsshavingkit/async-opcua`, not upstream `FreeOpcUa/async-opcua`.

## Out of Scope

- The `publish_request_queue` — it already uses O(1) front/back operations and a single-pass rebuild
  for expiry; it is not quadratic and is not changed here.
- Other performance-backlog items (is_subtype_of memoization, TranslateBrowsePaths child index,
  per-tick subscription recompute, chunk-header re-parse) — separate features.
- Any change to subscription/monitored-item semantics, limits, or the wire protocol.
