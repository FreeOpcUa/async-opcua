# Session-Actor Subscription Delivery (the async-delivery invariant) — Design

Date: 2026-06-25 (rev 2 — pivoted from bounded-lock to lock-free session actor)
Status: approved (brainstorm + multi-AI cross-check); lock-free session-actor approach confirmed

## Purpose

Make a session's subscription handling **actually asynchronous**: never hold a lock across the
notification hot path. Today, per-session state (`SessionSubscriptions`) lives behind an
`Arc<Mutex<>>` taken by notification delivery, the periodic tick, Publish handling, and
subscription/monitored-item management alike. Measured (`bench_condition_refresh_lock_hold_scaling`):
ConditionRefresh holds that `Mutex` **O(N)** in retained conditions — ~43 µs/condition, **87 ms at
2 000**, extrapolating to ~430 ms at 10 000 — stalling every other operation on the session.

The lock-free first step (lock-free producer ring) is done. This design finishes the job: the lock
goes away entirely by giving each session's subscription state a **single owner** — a per-session
actor task — fed by the lock-free ring (hot path) and an unbounded command channel (ops needing a
result). No `Mutex` on the session hot path; the session is never blocked.

## Approach: per-session subscription actor

A **dedicated** per-session actor task (separate from the existing generic Read/Write `SessionActor`
in `session/actor.rs`, so subscription timing never queues behind node-manager work) **owns**
`SessionSubscriptions` outright. Inbox:

- **Notification ring** (already built: per-session `crossbeam_queue::ArrayQueue<NotificationWorkItem>`)
  for the hot, fire-and-forget path (`notify`/ConditionRefresh push and return). Paired with a
  `tokio::sync::Notify` so a push **wakes** the actor (an `ArrayQueue` cannot wake a sleeping task on
  its own).
- **Unbounded command channel** (`tokio::sync::mpsc::unbounded`) for operations that need a result —
  CreateSubscription, Create/Modify/Delete MonitoredItems, Set{PublishingMode,Triggering,MonitoringMode},
  Publish, Republish, GetMonitoredItems, ResendData, TransferSubscriptions. Each is `(request,
  oneshot reply)`. **Unbounded** is deliberate: a bounded channel deadlocks (the connection reader
  task blocks on `send().await` and can then no longer read the client's Delete/Close to clear the
  jam); the outstanding count is already protocol-bounded (`max_pending_publish_requests`, connection
  limits).

The actor loop `select!`s over `{ command received, Notify woken → drain ring, tick deadline }`,
applying everything to its owned state single-threaded — no lock — and yielding between messages.

### Incremental migration without a shared Mutex — the `LegacyCall` bridge

The actor becomes the **sole owner from phase 1** (a half-migrated shared `Mutex` is *worse* — a
blocked pool thread holding it would stall the actor). Services not yet ported reach the owned state
through one bridge command:
```rust
LegacyCall(Box<dyn FnOnce(&mut SessionSubscriptions) -> () + Send>, oneshot::Sender<R>)
```
This lets us migrate the service call-sites cluster-by-cluster while ownership is already correct.
The existing service call-sites are tractable for this: they are synchronous cache calls before/after
the async node-manager work, not locks held across awaits (verified: `session/services/*` resolve the
node manager first, then touch the cache).

### The one structure that stays shared

The global **node → monitored-item index** producers use to resolve "which items match this event"
stays in the cache behind a **read-mostly `RwLock`** (written only on item add/remove, read
concurrently by producers). That is not the invariant offender (the offender was the *per-session*
`Mutex` held across tick/deliver/Publish). The actor returns enough data from its create/delete
commands for the cache to update this reverse index; the actor **deregisters its items on teardown**.

## Correctness invariants (from the OPC UA spec + the multi-AI cross-check)

1. **Publish drains the ring first.** On a Publish command the actor must drain pending ring work
   BEFORE evaluating the request, so a keep-alive/Publish never overtakes already-pushed notifications
   (sequence-number + `more_notifications` correctness).
2. **`more_notifications` fast-path.** After a Publish with `more_notifications == true`, if another
   Publish request is queued, send the next batch immediately — do not wait for the next tick.
3. **Sequence / keep-alive / lifetime.** Keep-alive uses `peek_next_sequence_number` (no increment);
   notifications/status-changes increment. Compute lifetime/keep-alive from **elapsed wall-time**
   (`Instant` deltas → intervals passed), not raw tick counts, to survive async scheduling jitter.
4. **ConditionRefresh must not be silently dropped.** Losing RefreshStart/RefreshEnd or retained
   events is client-visible. Refresh goes via a path that applies real backpressure / returns a
   server-busy status on saturation — never the current "ring full → drop → return Ok". (Fixes an
   existing bug.)
5. **TransferSubscriptions — two-phase, routing-aware.** Prepare on the source actor (drain its ring,
   validate the transfer key, remove the `Subscription` + its retransmission entries **in insertion
   order** + unsent publishes, return them); commit on the destination actor (insert, append, tick);
   only THEN flip the global `subscription_to_session` mapping; then have the source queue
   `Good_SubscriptionTransferred`. Guard producer routing during the move with a per-subscription
   "transferring" state (buffer at destination) so notifications are neither dropped nor misrouted.
   Roll back into the source if the destination rejects on limits.
6. **Connection-drop grace.** A disconnect must NOT tear the actor down — it keeps ticking (queueing
   to the configured limits) until the session lifetime expires, so the client can reconnect and
   TransferSubscriptions.

## Components

1. `SubscriptionActor` (new, `subscriptions/actor.rs`) — owns `SessionSubscriptions`; holds the ring
   `Arc` + `Notify`, the command receiver, and a single earliest-deadline tick timer; runs the loop.
2. `SubscriptionCommand` enum — the request/reply messages above + `LegacyCall`.
3. Cache handle per session — `{ ring: Arc<ArrayQueue>, notify: Arc<Notify>, commands: UnboundedSender<SubscriptionCommand>, dropped: AtomicU64 }`, replacing today's `Arc<Mutex<SessionSubscriptions>>` entry. Producers push to the ring + `notify_one()`; services `commands.send(cmd)` + await the oneshot.
4. **Tick scheduler** — one `tokio::time::Sleep` per actor, reset to the soonest subscription deadline;
   on fire, tick all due subscriptions (lifetime by elapsed time), recompute, reset.
5. Producer rewiring — `notify.rs` notifier `Drop` pushes to the ring + `notify_one()` instead of
   taking the `Mutex` (replaces the bounded-lock drain entirely).

## Phased migration (subscription + alarms suites green at every step)

- **Phase 1:** introduce `SubscriptionActor` as sole owner; ring (`Notify`-woken) + unbounded command
  channel; route **delivery + Publish** through it; all other services reach state via `LegacyCall`.
  Replace the bounded-lock drain. (Delete the per-session `Mutex` type usage from the hot path;
  `LegacyCall` runs the closure on the owned state inside the actor.)
- **Phase 2:** migrate management services off `LegacyCall` into typed commands, cluster by cluster
  (monitored-items create/modify/delete/set-modes; subscription create/modify/delete; get-monitored-items;
  resend) — returning reverse-index updates to the cache.
- **Phase 3:** per-actor earliest-deadline tick (retire the central `periodic_tick` scan);
  TransferSubscriptions two-phase between actors; connection-drop grace.
- **Phase 4:** delete `LegacyCall` and confirm there is no `Mutex` anywhere on the session path.

## Testing (Claude authors; before each phase merges)

- **Invariant:** the benchmark shows ConditionRefresh Call time flat-in-N AND a concurrent op on the
  same session no longer stalls with N (re-uses + extends `bench_condition_refresh_lock_hold_scaling`).
- **Ordering:** Publish after ring push preserves order; refresh + interleaved events keep
  RefreshStart-before-RefreshEnd; keep-alive doesn't overtake notifications.
- **State machine unchanged:** full Part 4 §5.13 subscription suite + alarms/limit-alarm suites green
  at every phase.
- **Transfer:** Republish after transfer returns the moved retransmission messages; old session gets
  `Good_SubscriptionTransferred`; rollback on destination limit; no notification loss during transfer.
- **Backpressure/health:** ConditionRefresh on a saturated path fails loudly (not silent Ok); command
  channel never deadlocks; lifetime expiry deregisters reverse-index entries + runs node-manager
  cleanup as today.

## Implementation split

**codex implements** the actor, channels, `Notify` wake, `LegacyCall` bridge, producer rewiring, tick
scheduler, and the phased service migration; **Claude authors/validates** the benchmark + the
correctness/ordering/transfer/state-machine tests and runs the before/after numbers. One concern per
codex dispatch; scope-escape rule + "run `cargo fmt`" in every brief; no-git guardrail; branch verified
after each. This is a multi-PR effort — one PR per phase, each green on the full CI gate.

## Provenance

Cross-checked with Gemini (Antigravity) and codex (read-only, code-grounded) on 2026-06-25; their
critiques drove: the `Notify` wake, the unbounded command channel (deadlock avoidance), the
`LegacyCall` sole-owner-from-day-1 bridge, the dedicated (not shared) subscription actor, the
earliest-deadline single tick, elapsed-time lifetime, Publish-drains-first, the two-phase routing-aware
Transfer, ConditionRefresh non-silent-drop, connection-drop grace, and index deregistration on teardown.
See [[multi-ai-audit-crosscheck]] and [[async-delivery-invariant]].
