# Bounded-Ring Notification Delivery Implementation Plan

> **For agentic workers:** Implementation tasks (T1–T4) go to **codex** (one concern per dispatch,
> no-git guardrail, scope-escape rule + "run `cargo fmt` on files you touch" in every brief, branch
> verified after each). The before/after benchmark + correctness tests (T5) are **authored by Claude**.
> Each codex task must leave the workspace compiling and `cargo test -p async-opcua-server --lib` green.

**Goal:** Producers never hold the per-session subscription `Mutex`; a majordomo drains a bounded
lock-free ring into the existing monitored-item queues in bounded chunks. Fixes the measured O(N)
ConditionRefresh lock-hold (87 ms @ 2 000 conditions).

**Architecture:** See `docs/superpowers/specs/2026-06-25-bounded-notification-delivery-design.md`. The
ring (`crossbeam-queue::ArrayQueue`, crossbeam already a dep) lives BESIDE the session `Mutex` (reachable
via the `SubscriptionCacheInner` read lock) so producers push lock-free. The drain runs inside the
existing `periodic_tick`. Filter/deadband/overflow eval stays in `notify_event`/`notify_data_value`,
now called from the drain (chunked) instead of the producer flush.

**Key grounding (from the code):**
- Session entry: `SubscriptionCacheInner.session_subscriptions: HashMap<u32, Arc<Mutex<SessionSubscriptions>>>`
  (`mod.rs:90`). The ring is added as a sibling `Arc<ArrayQueue<NotificationWorkItem>>` per session.
- Filter eval needs item state → drain-side: `MonitoredItem::notify_event` / `notify_data_value` already
  apply EventFilter / deadband / `EventQueueOverflow` under the `Mutex`.
- Events are owned via `Box<dyn Event + Send>` (ConditionRefresh constructs `RefreshStartEvent`,
  `AlarmEvent`s, `RefreshEndEvent` — all owned). If the `Event` trait is not `Send`, STOP and report.

---

### Task T1 (codex): NotificationWorkItem + per-session ring

**Files:** `async-opcua-server/src/subscriptions/mod.rs` (session entry + ring), a new
`async-opcua-server/src/subscriptions/ring.rs` (or inline) for the work item.

- Add `crossbeam-queue` to `async-opcua-server/Cargo.toml` (crossbeam is already in the tree; use the
  same version family). If it pulls a new transitive crate, note it.
- Define:
  ```rust
  pub(crate) enum NotificationWorkItem {
      Data { handle: MonitoredItemHandle, value: DataValue },
      Refresh { subscription_id: u32, monitored_item: Option<MonitoredItemHandle>, events: Vec<Box<dyn Event + Send>> },
  }
  ```
- Add a per-session ring beside the `Mutex`: change the session map value (or add a parallel map) so
  each session has `Arc<ArrayQueue<NotificationWorkItem>>` with a fixed capacity (e.g. a const
  `NOTIFICATION_RING_CAPACITY` sized from the subscription limits; pick a sane default like 8192 and
  centralize it). Create it wherever `SessionSubscriptions::new` is wrapped (`mod.rs:362`/`:791`); drop
  it with the session (`mod.rs:252`).
- Add a per-session overflow counter (`AtomicU64`) beside the ring for accounting; a helper
  `push_work(session_id, item)` that does the read-lock lookup, `ring.push(item)`, and on `Err`
  increments the overflow counter (never blocks/panics). Not wired to producers yet (no behavior
  change).

**Acceptance:** `cargo build -p async-opcua-server` clean; existing subscription unit tests green.
SCOPE-ESCAPE: if `Event` isn't `Send`, or the session-entry change ripples beyond `subscriptions/`, STOP
and report.

---

### Task T2 (codex): majordomo drain in periodic_tick

**Files:** `async-opcua-server/src/subscriptions/mod.rs` (`periodic_tick`), `session_subscriptions.rs`.

- Add `fn drain_ring(session_subs: &mut SessionSubscriptions, ring: &ArrayQueue<NotificationWorkItem>,
  type_tree, budget: usize)`: pop up to `CHUNK` (const, e.g. 256) items, apply each
  (`Data` → `notify_data_value`; `Refresh` → for the target subscription's event items, enqueue
  RefreshStart → each event → RefreshEnd via `notify_event`), then return so the caller can release +
  re-acquire the `Mutex` between chunks; loop to `budget` total items per tick so one session can't
  starve others.
- Call the drain at the START of each session's step in `periodic_tick` (before the existing tick
  logic), taking the session `Mutex` per chunk (release between chunks). Also drain when a Publish
  request is serviced for the session, so a Publish sees freshly-drained notifications.
- A `Refresh` whose subscription/item is gone → drop it (log), no panic.

**Acceptance:** `cargo build -p async-opcua-server` clean; existing tests green (ring still unused by
producers, so behavior unchanged). SCOPE-ESCAPE applies.

---

### Task T3 (codex): route ConditionRefresh through the ring  ← fixes the measured pathology

**Files:** `async-opcua-server/src/subscriptions/mod.rs` (`refresh_subscription_events`),
`async-opcua-server/src/alarms/methods.rs` (the refresh handler builds owned events).

- Change `SubscriptionCache::refresh_subscription_events` so that instead of taking the session `Mutex`
  and delivering inline, it: validates the subscription exists (still returns `BadSubscriptionIdInvalid`
  / `BadMonitoredItemIdInvalid` synchronously by checking under the read lock), then PUSHES one
  `NotificationWorkItem::Refresh { subscription_id, monitored_item, events }` to the session ring and
  returns. The events Vec is the owned `Box<dyn Event + Send>` list (RefreshStart, the retained
  condition events, RefreshEnd) the handler already builds.
- The drain (T2) performs the actual chunked delivery. Net: the ConditionRefresh Call returns after an
  O(1) push, not an O(N) locked delivery.

**Acceptance:** `cargo build -p async-opcua-server` clean. The existing alarms integration tests still
pass (I run them); the ConditionRefresh late-subscriber/Refresh2/empty/bad-sub behavior is unchanged
from the client's view (events still arrive, just drained on the next tick). SCOPE-ESCAPE applies.

---

### Task T4 (codex): route notify_data_change through the ring

**Files:** `async-opcua-server/src/subscriptions/mod.rs` (`notify_data_change`, `maybe_notify`),
`notify.rs` (the `SubscriptionDataNotifier` flush on Drop).

- Change the data-change flush so that, instead of taking the session `Mutex` on `Drop` and enqueuing,
  it pushes `NotificationWorkItem::Data { handle, value }` per resolved item to the session ring (the
  target-item resolution under the read lock is unchanged). The drain applies the deadband filter +
  enqueues. Keep `maybe_notify`'s sampling behavior (it resolves values lazily; push the sampled value).

**Acceptance:** `cargo build -p async-opcua-server` clean; data-change subscription integration tests
green. (General `notify_events` for arbitrary borrowed `&dyn Event` is OUT OF SCOPE — it needs an
owned-event API change; note it as deferred.) SCOPE-ESCAPE applies.

---

### Task T5 (Claude): before/after benchmark + correctness

**Files:** `async-opcua/tests/integration/alarms.rs` (extend the existing bench + add correctness),
authored by Claude.

1. **Flat-in-N**: extend `bench_condition_refresh_lock_hold_scaling` to assert the ConditionRefresh
   *Call* time is now ~constant in N (push-only), not O(N).
2. **Concurrent-stall**: while a 2 000-condition refresh is in flight on a session, time a small op on
   the same session (e.g. a second tiny refresh on another subscription) and assert its latency no
   longer scales with N.
3. **Behavior unchanged**: the full alarms + subscription suites stay green (late-subscriber refresh,
   Refresh2 targeting, ack/confirm, limit alarms, data-change, EventQueueOverflow).
4. **Ordering**: a refresh + interleaved normal events still arrive RefreshStart-before-RefreshEnd with
   per-subscription order preserved.
5. **Overflow**: push past ring capacity; assert overflow is indicated (no panic, bounded memory) and
   the subscription recovers.

**Acceptance:** new tests green; `cargo test -p async-opcua --test integration_tests` (alarms +
subscription) green; `clippy -D warnings` clean; default + `--no-default-features` build; `cargo fmt
--all -- --check` clean before PR.

---

## Self-review

- **Spec coverage:** ring+work-item (T1), majordomo drain (T2), ConditionRefresh→ring (T3, the measured
  fix), data-change→ring (T4), bench+correctness (T5). General `notify_events` is explicitly deferred
  (owned-event API change) — noted in spec scope.
- **Type consistency:** `NotificationWorkItem`/`Data`/`Refresh`/`push_work`/`drain_ring` used identically
  across tasks.
- **Dependencies:** T2 needs T1; T3 needs T1+T2; T4 needs T1+T2; T5 needs all. Order T1→T2→T3→T4, then T5.
- **Risk:** the `Event: Send` assumption (T1 scope-escape if false) and the periodic_tick integration are
  the two places most likely to surface a snag → codex returns a summary rather than expanding scope.
