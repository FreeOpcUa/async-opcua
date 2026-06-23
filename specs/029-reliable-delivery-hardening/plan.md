# Implementation Plan: Reliable Notification-Delivery Hardening

**Branch**: `029-reliable-delivery-hardening` | **Date**: 2026-06-22 | **Spec**: [spec.md](./spec.md)

## Summary
Characterize + harden the `async-opcua-server` Subscription/Publish reliable-delivery path against
the exact Part 4 1.05.07 §5.13 rules, for producer-faster-than-consumer. Primarily a test feature;
production changes only where a test proves a spec violation (FR-006/007), minimal + fail-closed.

## Technical Context
- **Crate**: `async-opcua-server` (+ integration tests in `async-opcua/tests/integration/`).
- **Spec source**: local `~/opcua-specs/OPC 10000-4 … 1.05.07.pdf` §5.13 (overflow, lifecycle,
  retransmission, sequence numbers) — quoted in spec.md. Extracted text cached at /tmp/part4.txt.
- **Code anchors** (from the assessment): MonitoredItem overflow `monitored_item.rs:596-615`;
  subscription-level queue + `discarded_message_count` `subscription.rs:221,689-705,977`; sequence
  `subscription.rs:217,752-785` + `async-opcua-core/src/handle.rs:27-35`; lifetime/state-machine
  `subscription.rs:387-498,669-680`; acks/republish `session_subscriptions.rs:275-287,880-938`;
  retransmission `subscriptions/retransmission_queue.rs`.
- **Constraints**: behavior-preserving except conformance fixes; no new dep; clippy `-D warnings`
  (all-features + no-default-features) + fmt clean; existing suite green.

## Constitution Check
- **I Correctness** PASS — locks reliability-path behavior to the spec; fixes any real violation.
- **IV Security** PASS — reliable delivery under overload is a control-system robustness/DoS-adjacent
  concern; overflow signalling prevents silent loss.
- **II/V** PASS — adds the missing characterization tests; removes a "works but unverified" debt.
No violations.

## Project Structure
```
async-opcua-server/src/subscriptions/   # in-crate #[cfg(test)] for queue/overflow/sequence/lifetime mechanics
async-opcua/tests/integration/          # end-to-end publish/ack/republish/consumer-lag/timeout (existing harness)
```
Tests at both levels: unit (drive MonitoredItem/Subscription/retransmission structures directly) +
integration (reuse `subscriptions.rs` harness: create/monitor/publish/ack/republish/transfer).

## Verification Division
- **Claude** authors ALL tests, each citing the Part-4 rule it checks.
- A test that reveals a Part-4 violation → **codex** fixes the production code (one task/dispatch, no
  tests, no git, branch-guarded, minimal fail-closed diff). codex is NOT dispatched unless a test
  fails against a cited rule.
- PR to fork `occamsshavingkit/async-opcua`; one commit per user story.

## Phasing
US1 overflow + consumer-lag → US2 republish/ack/sequence → US3 lifecycle/request-queue → polish.
Each US: write the spec-anchored tests; if red against the spec, dispatch codex to fix, re-verify.
