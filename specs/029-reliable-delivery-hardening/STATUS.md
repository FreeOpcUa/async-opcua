# Feature 029 — STATUS: spec'd + scoped; implementation PAUSED for awake review

**Date**: 2026-06-23 (overnight). Spec/plan/tasks committed on branch
`029-reliable-delivery-hardening`. **Not implemented, not merged.**

## Why paused
Implementation began with the MonitoredItem queue-overflow characterization (§5.13.1.5). Driving the
overflow logic surfaced more subtlety than the assessment implied — enough that rushing it overnight
risked shipping confused tests/findings on a safety-relevant path. Stopping was the
correctness-over-completion call.

## What was learned (must verify when resuming, NOT yet conclusions)
1. **MonitoredItem queues do not start empty** — a freshly built item already holds an initial entry,
   so any "fill to capacity then overflow" test must account for the actual starting queue state
   (an off-by-one over-fills and triggers an extra overflow). The clean way to characterise
   §5.13.1.5 is to drive `monitored_item.rs::enqueue_notification` directly with a KNOWN starting
   state, not via `notify_data_value` (whose sampling/skip logic confounds the queue contents).
2. **Two CANDIDATE conformance questions vs Part 4 1.05.07 §5.13.1.5** (need confirmation + are
   interop-affecting BEHAVIOR-CHANGE decisions, so they are USER decisions, not auto-fixes):
   - **discardOldest=TRUE overflow-bit placement**: spec says "the oldest is deleted and the NEXT
     value in the queue gets the flag" (the new front); the impl (`enqueue_notification` ~line 608)
     sets the Overflow bit on the newly appended value (the back). The existing test
     `monitored_item_overflow` encodes the impl's placement.
   - **QueueSize==1**: spec sets the Overflow bit only when "the size of the queue is larger than
     one"; the impl computes `overflow = len == queue_size` and sets the bit at size 1 too.
   Both must be re-verified with a correct known-start-state harness before deciding to change shipped
   behavior (changing overflow semantics affects every subscribing client / interop).

## How to resume
- Write §5.13.1.5 tests against `enqueue_notification` directly, seeding a known queue state.
- Confirm/deny the two findings; if confirmed, treat the fixes as conformance behavior changes for
  explicit approval (they break the existing `monitored_item_overflow` test, which must then be
  corrected to the spec, not weakened).
- Then proceed to US2 (republish/ack/sequence — much of this is testable via the existing
  `async-opcua/tests/integration/subscriptions.rs` harness) and US3 (lifecycle/request-queue).
- The retransmission queue + sequence-number Handle already have good coverage (027 + handle.rs).
