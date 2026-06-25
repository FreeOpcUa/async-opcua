# Session Actor — Phase 1 Plan (delivery + Publish through a sole-owner actor)

> codex implements; Claude validates. Scope-escape rule + `cargo fmt` in every brief; no-git guardrail.
> Design: `docs/superpowers/specs/2026-06-25-bounded-notification-delivery-design.md` (rev 2).
> Goal of phase 1: the per-session subscription state has a single owner (no `Mutex`); the hot path
> (notify/refresh) is the lock-free ring (Notify-woken); all other access goes through the actor
> (typed Publish command + `LegacyCall` bridge for everything not yet migrated). Subscription +
> alarms suites green throughout.

### P1.1 (codex): actor scaffolding (compiles, not yet wired — zero behavior change)

**Files:** new `async-opcua-server/src/subscriptions/actor.rs`; `mod.rs` add `mod actor;`.

- `pub(crate) enum SubscriptionCommand` with at least:
  - `LegacyCall(Box<dyn FnOnce(&mut SessionSubscriptions) + Send>, oneshot::Sender<()>)` — the bridge
    that runs an arbitrary closure on the owned state and signals completion. (A generic-return variant
    can come later; start with `()` + have closures capture their own `oneshot` for typed results, or
    use `Box<dyn FnOnce(&mut SessionSubscriptions) -> Box<dyn Any + Send> + Send>` — pick the simplest
    that lets a caller get a typed result back; document the choice.)
  - `Stop` — graceful shutdown.
- `pub(crate) struct SubscriptionActorHandle { ring: Arc<ArrayQueue<NotificationWorkItem>>, notify: Arc<tokio::sync::Notify>, commands: tokio::sync::mpsc::UnboundedSender<SubscriptionCommand>, dropped: Arc<AtomicU64> }`
  with helpers: `push_notification(item)` (ring push; on full bump `dropped`; then `notify.notify_one()`),
  and `legacy<R>(&self, f: impl FnOnce(&mut SessionSubscriptions) -> R + Send + 'static) -> impl Future<Output = R>`
  (sends a `LegacyCall` + awaits the oneshot).
- `pub(crate) struct SubscriptionActor { subs: SessionSubscriptions, ring, notify, commands_rx, /* tick state */ }`
  with `async fn run(self)`: a `select!` loop over `{ commands_rx.recv() → handle (LegacyCall runs the
  closure on &mut self.subs; Stop → break), self.notify.notified() → drain the ring into self.subs
  (reuse the existing event-chunked drain logic, but now WITHOUT a Mutex since self owns subs) }`. Tick
  arm is a stub for phase 3 (a no-op interval is fine for now).
- A `spawn` constructor that takes a `SessionSubscriptions` + the ring/notify/dropped, builds the
  channel, `tokio::spawn`s `run`, and returns the `SubscriptionActorHandle`.

This file is NOT referenced by the cache yet — it must compile (dead-code `#[allow(dead_code)]` where
needed) with zero runtime change. Acceptance: `cargo build -p async-opcua-server` clean; `cargo test -p
async-opcua-server --lib` green. SCOPE-ESCAPE: stay within `subscriptions/`; if `SessionSubscriptions`
can't be owned/moved (borrows tie it to the cache), STOP and report.

### P1.2 (codex): ownership move — wire the actor in, delete the per-session Mutex

Replace the `SessionEntry.subs: Arc<Mutex<SessionSubscriptions>>` with the `SubscriptionActorHandle`
(spawn the actor when the entry is created; send `Stop` + drop on teardown). Convert every current
`cache … .subs.lock()` access: hot notify path → `handle.push_notification` (+ the notifier `Drop`
pushes to the ring, no `Mutex`); the central `periodic_tick` per-session drain is removed (the actor
drains on `Notify`); all service/management/tick access → `handle.legacy(|subs| …).await`. Publish is
done as a `LegacyCall` for now (typed command in P1.3) and MUST drain the ring first inside the actor.
Keep behavior identical. (This is the big, careful step — validate the full subscription + alarms
suites.) SCOPE-ESCAPE if it spreads beyond `subscriptions/` + the service call-sites.

### P1.3 (codex): typed Publish command + Publish-drains-first + Notify wake on push

Promote Publish from `LegacyCall` to a typed `Publish`/`Republish` command; ensure the actor drains the
ring before evaluating it (sequence-number ordering) and honors the `more_notifications` fast-path.

### P1.T (Claude): validation

Subscription state-machine suite + alarms/limit-alarm suites green; extend
`bench_condition_refresh_lock_hold_scaling` to show flat-in-N + concurrent-stall-gone; ordering test
(keep-alive doesn't overtake notifications); no `Mutex` remains on the session path.
