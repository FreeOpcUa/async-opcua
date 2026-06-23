# Feature Specification: Subscription State-Machine & Lifecycle Conformance Audit

**Feature Branch**: `030-subscription-statemachine-conformance`
**Created**: 2026-06-23
**Status**: Draft
**Input**: Continue the piece-by-piece audit of the server reliable-delivery path vs OPC UA Part 4
1.05.07 §5.13 (local spec ~/opcua-specs). Spec is authoritative; where the impl diverges it is wrong.
This piece covers the subscription STATE MACHINE + lifecycle (lifetime/keep-alive counters, Publish/
Acknowledge/Republish/Transfer actions), following the queue-overflow piece (feature 029, merged).

## Outcome of this audit

The full state-machine + lifecycle path was compared to the Part 4 state table (Table 79, lines
~4955-5072 of the extracted spec) and rules (h)/(i). Result: **one contained conformance bug fixed
here (#4); three further confirmed gaps documented for careful follow-up** (they each need a real
mechanism or a state-machine change too risky for a drive-by fix); and **several areas verified
CONFORMANT**. Full detail in [AUDIT.md](./AUDIT.md).

## User Stories & Requirements

### US1 — Republish resets the subscription lifetime counter (Priority: P1) — DONE
Part 4 state-table rows 20 & 21 (and rule (h)): a `Republish` on a valid SubscriptionId
`ResetLifetimeCounter()`, whether or not the requested message is found. The impl did not. Fixed in
`session_subscriptions.rs::republish` (now resets the counter for a valid subscription id before the
message lookup; `BadSubscriptionIdInvalid` / `BadMessageNotAvailable` paths unchanged).

- **FR-001**: A valid `Republish` MUST reset that subscription's lifetime counter (found or not found).
- **FR-002**: No other Republish behavior or status code changes; existing republish + server suites pass.

### Documented (NOT fixed here — see AUDIT.md, each needs careful follow-up)
- **FR-003 (gap #1)**: the `Normal` Publish-request guard does not match Table 79 rows 4/5 — the
  first disjunct is `publishing_enabled` where the spec says `PublishingEnabled == FALSE`, which makes
  `Normal5` (ReturnNotifications + ResetLifetimeCounter for enabled+more) **dead code**. Currently
  masked in normal operation (the `IntervalElapsed6` timer tick resets the counter), so low observable
  harm — but a real conformance/clarity gap. A fix is a state-machine change requiring careful
  regression testing of the existing lifetime/keep-alive counter tests.
- **FR-004 (gap #2)**: `TransferSubscriptions` does not (a) issue a `Good_SubscriptionTransferred`
  StatusChangeNotification to the OLD session, nor (b) `ResetLifetimeCounter` (Table 79 rows 22/23).
  (a) needs a mechanism for the old session to deliver a status change for a subscription it no longer
  holds — a real feature.
- **FR-005 (gap D)**: event-queue overflow does not place an `EventQueueOverflowEventType` Event in
  the queue on first discard (§5.13.1.5) — a missing feature.

## Success Criteria
- **SC-001**: Republish resets the lifetime counter (rows 20/21); server suite + the existing
  republish integration test stay green; clippy/fmt clean; fork CI green.
- **SC-002**: The remaining confirmed divergences (#1, #2, D) are documented with exact spec
  citations, code locations, observable-impact assessment, and implementation complexity, so each can
  be fixed deliberately.

## Out of Scope
- Fixing #1/#2/D in this PR (documented for careful follow-up). Safety Part-15; PubSub; client-side.

## Assumptions
- Behavior judged against local Part 4 1.05.07. Verification division: codex production, Claude tests.
  #4's lifetime-reset is verified by no-regression on the existing republish/server suites (a dedicated
  unit test needs the heavy SessionSubscriptions/Session harness — noted as follow-up rather than a
  flaky timing test). PRs to fork occamsshavingkit/async-opcua.
