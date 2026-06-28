# Tasks: Bounded-Time Subscription Retransmission Queue

**Feature**: `027-retransmission-queue-bounded-time` | [spec](./spec.md) · [plan](./plan.md) · [research](./research.md)

## Conventions
- **[codex]** = production code (one task/dispatch, no tests, no git, branch-guarded, minimal diff,
  preserve every documented behavior + reclaim-to-pool). **[claude-test]** = tests by Claude,
  anchored to Part-4 + pre-refactor behavior, never codex loopback.
- One commit per user story. PR to fork `occamsshavingkit/async-opcua`.

## Phase 1: Baseline (Iron Law)

- [X] T001 [claude-test] Confirm the pre-refactor behavioral baseline: run `cargo test -p async-opcua-server` on the current branch tip and record it green (this existing suite is the characterization that must still pass after the refactor — SC-003).

## Phase 2: User Story 1 — sub-quadratic queue (P1)

- [X] T002 [codex] Add `async-opcua-server/src/subscriptions/retransmission_queue.rs` with a `RetransmissionQueue` struct: `entries: BTreeMap<u64, NonAckedPublish>`, `index: HashMap<(u32,u32), u64>`, `by_subscription: HashMap<u32, BTreeSet<u64>>`, `next_id: u64`. Methods per contracts/data-model: `enqueue(pool, max_len, sub, message)` (skip keep-alive; evict global-oldest via `pop_first` + reclaim when full; `debug_assert` no duplicate `(sub,seq)`), `ack(sub,seq) -> Option<NonAckedPublish>`, `remove_subscription(sub) -> Vec<NonAckedPublish>` (insertion order), `available_sequence_numbers(sub) -> Option<Vec<u32>>` (insertion order, None when empty), `get_message(sub,seq) -> Option<Arc<NotificationMessage>>`, `len`/`is_empty`. Declare `mod retransmission_queue;` in `subscriptions/mod.rs`. Keep all three maps consistent. No new dependency (std only).
- [X] T003 [codex] Rewire `async-opcua-server/src/subscriptions/session_subscriptions.rs` to use `RetransmissionQueue` in place of the bare `VecDeque<NonAckedPublish>` field: `enqueue_retransmission_notification` → `queue.enqueue(...)`; `remove(sub)` → `queue.remove_subscription(sub)`; `process_subscription_acks` keeps the `subscriptions.contains_key` → `BadSubscriptionIdInvalid` check then uses `queue.ack(sub,seq)` (Some ⇒ reclaim + Good, None ⇒ BadSequenceNumberUnknown); `republish` message lookup → `queue.get_message(...)`; `available_sequence_numbers` → `queue.available_sequence_numbers(...)`; replace the `remove_retransmission_notifications(predicate)` teardown callers (L536 id-set, L827/L846 single sub) with per-sub `queue.remove_subscription(...)` reclaiming each entry. Preserve reclaim-to-pool on every removal path and all observable behavior. Build the crate.

## Phase 3: User Story 2 — characterization + scaling (P2)

- [X] T004 [claude-test] In `retransmission_queue.rs` tests: global-FIFO eviction order (interleaved subs); ack Some/None (present/absent key); insertion-ordered `available_sequence_numbers` + None-when-empty; `remove_subscription` insertion order + other-subs-untouched + empty-for-unknown; `get_message` hit/miss; reclaim invoked on eviction/ack/remove (assert via pool reuse). Port the two existing tests (`keep_alive_messages_are_not_queued…`, `status_change_messages_are_queued…`) to the struct API.
- [X] T005 [claude-test] Scaling test: push N≈50k entries across a few subscriptions, then (a) ack a large batch and (b) tear down a subscription; assert each completes within a generous ABSOLUTE wall-clock bound (a quadratic impl misses it by orders of magnitude; sub-quadratic passes comfortably). No ratio timing (CI-robust).

## Phase 4: Polish & merge

- [X] T006 [claude-test] Run `cargo test -p async-opcua-server` (still green = SC-003), the three clippy legs (`--all-features`, `--no-default-features` core crates, json-off) under `-D warnings`, and `cargo fmt --check`.
- [ ] T007 Push branch, open PR to `occamsshavingkit/async-opcua`, merge when CI green; sync master.

## Dependencies & order
T001 → T002 → T003 (same files, sequential) → T004/T005 → T006 → T007. MVP = T002+T003 (sub-quadratic, behavior-identical); T004/T005 prove it.
