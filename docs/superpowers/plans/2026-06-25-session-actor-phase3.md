# Session Actor — Phase 3 Plan (per-actor earliest-deadline tick + reaper)

> codex implements; Claude validates. Scope-escape rule + `cargo fmt` in every brief; no-git guardrail.
> Design: `docs/superpowers/specs/2026-06-25-bounded-notification-delivery-design.md` (rev 2), phase 3.
> Phase 1 merged (PR #140). This finishes the *valuable* remainder: retire the central
> O(sessions)-per-interval tick scan; each session actor sleeps until its own earliest subscription
> deadline. Subscription (Part 4 §5.13) + alarms suites green throughout.

## Why (and what we are NOT doing)

The central `periodic_tick` (`subscriptions/mod.rs:305`, driven by `server.rs:run_subscription_ticks`)
wakes every fixed interval and sends a `legacy` tick command to **every** session, even idle ones —
O(sessions) channel round-trips per interval. Phase 3 makes each actor self-tick on its own timer.

**Explicitly out of scope (ceremony, no functional gain):** phase 2 (convert `legacy(|subs| …)`
call-sites to typed command variants) and phase 4 (delete `LegacyCall`). `legacy<R>` is already
type-safe; converting is churn. Leave `LegacyCall` for management services. Revisit only if asked.

## The one coupling: cleanup

`periodic_tick` does two jobs: (a) tick each session, (b) when a tick returns
`removed_subscriptions` / `is_ready_to_delete`, run cleanup — `cleanup_removed_subscriptions` on the
cache `inner` write-lock, remove+`stop()` the session entry, update diagnostics, and
`delete_expired_monitored_items` via `ServerContext` node-managers. An actor owns `SessionSubscriptions`
but NOT the cache or context, so it cannot do (b). Phase 3 splits them: actors self-tick (a); a small
central **reaper** task drains a cleanup channel and does (b) on demand (no scan).

## Deadline computation

A subscription's next wall-clock trigger is `last_time_publishing_interval_elapsed + publishing_interval`
(`subscription.rs:219,191`). Keep-alive/lifetime are counted in publishing-interval ticks, so the only
timer that matters is the publishing interval elapsing. Earliest deadline for a session = min over its
subscriptions. No subscriptions → no timer (park until a command arrives).

---

### Task P3.1 (codex): `SessionSubscriptions::next_tick_deadline`

**Files:** `async-opcua-server/src/subscriptions/session_subscriptions.rs`,
`async-opcua-server/src/subscriptions/subscription.rs`.

- On `Subscription` add `pub(super) fn next_publish_deadline(&self) -> Instant` returning
  `self.last_time_publishing_interval_elapsed + self.publishing_interval`.
- On `SessionSubscriptions` add
  `pub(super) fn next_tick_deadline(&self) -> Option<Instant>` = the min of `next_publish_deadline()`
  across all subscriptions; `None` if there are none.
- Pure read-only accessors; no behavior change.

**Acceptance:** `cargo build -p async-opcua-server` clean; `cargo test -p async-opcua-server --lib`
green. SCOPE-ESCAPE: if `last_time_publishing_interval_elapsed`/`publishing_interval` aren't reachable
without restructuring, STOP and report. Run `cargo fmt` on touched files.

---

### Task P3.2 (codex): cleanup channel + reaper, fed by the actor

**Files:** `async-opcua-server/src/subscriptions/actor.rs`,
`async-opcua-server/src/subscriptions/mod.rs`, `async-opcua-server/src/server.rs`.

- Define in `mod.rs` (or `ring.rs`):
  ```rust
  pub(crate) struct SubscriptionCleanup {
      pub session_id: u32,
      pub session: Option<Arc<RwLock<Session>>>,      // Some when there are expired subs to delete
      pub removed_subscriptions: Vec<RemovedSubscription>,
      pub ready_to_delete: bool,
  }
  ```
- The cache owns `cleanup_tx: mpsc::UnboundedSender<SubscriptionCleanup>` /
  `cleanup_rx` (created once when the cache is built). `spawn(...)` gains a `cleanup_tx` clone +
  the `session_id` so the actor can report. Thread these through `SessionEntry::new`/the spawn path.
- Add `SubscriptionCache::run_cleanup(&self, context: &ServerContext, rx: …)` — a loop:
  `while let Some(c) = rx.recv().await { … }` doing exactly what `periodic_tick`'s tail does today:
  `cleanup_removed_subscriptions`, then on `ready_to_delete` remove the entry +`handle.stop()`, update
  `set_current_subscription_count`, and on `session.is_some()` call the existing
  `delete_expired_monitored_items`. Reuse those functions verbatim — do not reimplement.
- `server.rs`: replace the body of `run_subscription_ticks` so it drives `run_cleanup` instead of the
  fixed-interval scan (the `interval == 0` → `pending()` disable path can stay as a guard around
  spawning the reaper; if that's awkward, STOP and report rather than changing disable semantics).
- Do NOT wire the actor's timer yet (P3.3). After P3.2 the reaper exists but receives nothing; keep
  `periodic_tick` working so tests still pass. Zero behavior change.

**Acceptance:** builds clean; full `cargo test -p async-opcua-server --lib` green; `periodic_tick`
still functions. SCOPE-ESCAPE if it spreads beyond these three files. Run `cargo fmt` on touched files.

---

### Task P3.3 (codex): actor self-tick; retire the central scan

**Files:** `async-opcua-server/src/subscriptions/actor.rs`,
`async-opcua-server/src/subscriptions/mod.rs`, and the `periodic_tick` test site.

- Add a `tick` arm to `SubscriptionActor::run`'s `select!`: a `tokio::time::Sleep` reset (via
  `Pin`/`reset`) to `self.subs.next_tick_deadline()`; when `None`, use a far-future deadline (or skip
  the arm) so the actor parks. On fire:
  ```rust
  let now = Utc::now(); let now_instant = Instant::now();
  let mut buffer = NotificationBuffer::new();
  let removed = self.subs.tick(&now, now_instant, TickReason::TickTimerFired, &mut buffer);
  let ready = self.subs.is_ready_to_delete();
  if !removed.is_empty() || ready {
      let session = (!removed.is_empty()).then(|| self.subs.session().clone());
      let _ = self.cleanup_tx.send(SubscriptionCleanup {
          session_id: self.session_id, session,
          removed_subscriptions: removed, ready_to_delete: ready });
  }
  ```
  Recompute the deadline after EVERY arm (commands create/modify/delete subs → deadline changes; a
  tick advances `last_..._elapsed`). Drain the ring before ticking (ordering), as the other arms do.
- Remove the per-session tick loop from `SubscriptionCache::periodic_tick`. Either delete
  `periodic_tick` and update the one test caller (`mod.rs:1391`) to drive a tick another way (e.g. a
  test-only `legacy(|s| s.tick(...))` or awaiting the actor), or keep a thin `periodic_tick` that only
  exists for that test — pick the smaller diff and say which. `server.rs` no longer calls
  `periodic_tick`.
- Lifetime/keep-alive still derive from `tick`'s counter logic (unchanged); we only changed WHO calls
  `tick` and WHEN.

**Acceptance:** builds clean; full subscription + alarms lib tests green. SCOPE-ESCAPE if the test
coupling forces changes outside `subscriptions/` + `server.rs`. Run `cargo fmt` on touched files.

---

### Task P3.T (Claude): validation

- Full Part 4 §5.13 subscription suite + alarms/limit-alarm suites green
  (`cargo test -p async-opcua --test integration_tests`).
- Keep-alive timing: a subscription with no data still emits keep-alives on schedule (publishing
  interval × max-keep-alive-count) — proves self-tick fires on time.
- Lifetime expiry: an unacked subscription with no publish requests still expires and is cleaned up
  (proves the reaper path runs without the central scan): subscription removed, session diagnostics
  decremented, monitored items deleted.
- Idle sessions don't busy-loop (sanity: a parked actor with no subscriptions consumes no ticks).
- Gate: clippy `--all-targets -D warnings`, `--no-default-features` build, codegen-clean (codegen +
  `cargo fmt --all`), `cargo fmt --all -- --check`.

---

## Self-review

- **Coverage:** deadline accessor (P3.1), reaper+channel (P3.2), self-tick + scan retirement (P3.3),
  validation (P3.T). Cleanup logic is REUSED (`cleanup_removed_subscriptions`,
  `delete_expired_monitored_items`), not rewritten.
- **Risk:** (1) test coupling on `periodic_tick` (P3.3 scope-escape covers it); (2) `interval == 0`
  disable semantics (P3.2 scope-escape covers it); (3) deadline must be recomputed after every arm or
  a created/modified subscription won't tick until the old deadline — called out in P3.3.
- **Order:** P3.1 → P3.2 → P3.3 → P3.T. Each leaves the tree green.
