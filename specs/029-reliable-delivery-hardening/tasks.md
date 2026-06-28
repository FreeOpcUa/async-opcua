# Tasks: Reliable Notification-Delivery Hardening

**Conventions**: [claude-test] = tests by Claude, each citing the Part-4 rule. [codex] = production
fix, dispatched ONLY when a [claude-test] proves a spec violation (one task/dispatch, no tests/git,
minimal fail-closed). One commit per user story. PR to fork.

## Phase 1: Baseline
- [X] T001 [claude-test] Run `cargo test -p async-opcua-server` + the subscription integration tests green on current code (baseline). Verified with `cargo test -p async-opcua-server`, `cargo test -p async-opcua --test integration_tests subscriptions`, and `cargo test -p async-opcua --test integration_tests datachange_overflow`.

## Phase 2: US1 — overflow + consumer-lag (P1)
- [X] T002 [claude-test] MonitoredItem overflow tests (§5.13.1.5): discardOldest=TRUE (oldest dropped, NEXT value gets Overflow bit), discardOldest=FALSE (last-added replaced, NEWEST value gets Overflow bit), QueueSize==1 (policy ignored, no Overflow bit), and queue-order preservation. Drive `MonitoredItem` directly in an in-crate test. Covered by `part4_overflow_*` tests in `monitored_item.rs`.
- [X] T003 [claude-test] Subscription-level queue pressure: exceed `max_queued_notifications` → oldest dropped, `discarded_message_count` increments, `availableSequenceNumbers` lists only held messages.
- [X] T004 [codex] (CONDITIONAL) If T002/T003 reveal a Part-4 violation (esp. discardOldest=FALSE overflow-bit placement), fix the production code minimally to conform. Skipped: T002/T003 passed against existing behavior; no production fix required.
- Commit US1.

## Phase 3: US2 — republish / ack / sequence (P2)
- [X] T005 [claude-test] Republish: held sequence → exact message returned; sequence evicted past the retransmission bound → `Bad_MessageNotAvailable`. Ack status: Good / `Bad_SequenceNumberUnknown` / `Bad_SubscriptionIdInvalid`.
- [X] T006 [claude-test] Sequence-number semantics in a LIVE subscription: strictly +1, never 0, first=1, rolls over to 1 (drive enough publishes or seed the Handle near u32::MAX); Republish still works after roll-over.
- [X] T007 [codex] (CONDITIONAL) Fix any spec violation T005/T006 reveals. Skipped: T005/T006 passed against existing behavior; no production fix required.
- Commit US2.

## Phase 4: US3 — lifecycle / request-queue (P3)
- [X] T008 [claude-test] Lifetime expiry: a subscription with no Publish requests for its full lifetime → `Bad_Timeout` StatusChangeNotification + MonitoredItems removed. Publish-request overflow → `Bad_TooManyPublishRequests` with earlier requests still completing.
- [X] T009 [claude-test] Event-queue overflow (§5.13.1.5): verify EventQueueOverflowEventType behavior if implemented; otherwise record a documented gap (test marked `#[ignore]` + a note) per FR-007 — do NOT silently skip.
- [X] T010 [codex] (CONDITIONAL) Fix any spec violation T008 reveals. Skipped: T008 passed against existing behavior; no production fix required.
- Commit US3.

## Phase 5: Polish & merge
- [ ] T011 [claude-test] Full `cargo test -p async-opcua-server` + integration suite green; clippy (`--all-features`, `--no-default-features` core crates) `-D warnings`; `cargo fmt --check`.
- [ ] T012 Push, PR to fork, merge when CI green; sync master; record findings (any bug fixed, any documented gap) in memory + the spec.

## Analyze
Coverage: FR-001→T002; FR-002→T003; FR-003→T005; FR-004→T006; FR-005→T008; FR-006→T004/T007/T010;
FR-007→T009; FR-008→T011. SC-001→T002; SC-002→T003/T005/T006/T008; SC-003→T001/T011 + codex fixes;
SC-004→T011/T012. No [NEEDS CLARIFICATION]; constitution clean; 0 critical/high. Risk noted:
discardOldest=FALSE (T002) is the most likely to surface a real bug — if so, T004 fixes it.
