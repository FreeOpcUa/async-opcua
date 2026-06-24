# A&C Subscriber End-to-End (ConditionRefresh) Implementation Plan

> **For agentic workers:** Implementation tasks (T1–T6) are dispatched to **codex** (one concern per
> dispatch, no-git guardrail, branch verified after each). The acceptance/behavioral tests (T7) are
> **authored by Claude**, independent of the implementation, anchored to Part 9 §5.5.7 and the spec.
> Codex tasks must leave the workspace compiling (`cargo build -p <crate>`); Claude validates the
> whole feature at the end.

**Goal:** Implement Part 9 ConditionRefresh/ConditionRefresh2 with targeted per-subscription delivery,
RefreshStart/End marker events, an app-populated condition registry, thin client helpers, and a
demo-server example — so async-opcua works as an A&C subscriber target.

**Architecture:** See `docs/superpowers/specs/2026-06-24-ac-subscriber-conditionrefresh-design.md`.
Conditions stay app-owned (`ConditionStateMachine`, Clone). A new `ConditionRegistry`
(`Arc<RwLock<…>>`) lets the refresh handler enumerate retained conditions; refresh delivers a burst
(Start → replayed events → End) to the requesting subscription only via a new targeted-delivery API.

**Tech Stack:** Rust; `async-opcua-server` (alarms, subscriptions), `async-opcua-client` (session
services), `async-opcua-types` generated NodeIds; existing `Event`/`ServerAlarmEvent`/`notify_events`
machinery; demo-server.

**Verified NodeIds:** ConditionType=2782, ConditionRefresh=3875, ConditionRefresh2=12912,
Acknowledge=9111, Confirm=9113, RefreshStartEventType=2787, RefreshEndEventType=2788.

---

### Task T1 (codex): RefreshStart/RefreshEnd marker events

**Files:** Create `async-opcua-server/src/alarms/refresh_events.rs`; export from `alarms/mod.rs`.

- Implement two event types, `RefreshStartEvent` and `RefreshEndEvent`, that implement the same
  `Event` trait `ServerAlarmEvent` does (see `alarms/dispatch.rs` for the pattern).
- Standard fields: `EventId` (fresh ByteString per instance), `EventType` =
  `ObjectTypeId::RefreshStartEventType` (2787) / `RefreshEndEventType` (2788), `SourceNode` =
  `ObjectId::Server`, `SourceName` = "Server", `Time` = now, `ReceiveTime` = now,
  `Severity` = 0 (markers), `Message` = "Condition refresh start"/"…end".
- Field resolution must satisfy the alarm select clauses (`get_alarm_event_select_clauses` in the
  client) so a subscriber selecting standard fields receives these markers cleanly.

**Acceptance:** `cargo build -p async-opcua-server`; the two types construct and resolve EventType +
EventId via the `Event` trait.

---

### Task T2 (codex): ConditionRegistry

**Files:** Create `async-opcua-server/src/alarms/registry.rs`; export from `alarms/mod.rs`.

- `ConditionRegistry` wrapping `Arc<RwLock<Vec<ConditionStateMachine>>>` (or a map keyed by
  `condition_id`). `Clone` so the same shared set is captured by both the creation site and the
  refresh callback.
- `register(&self, condition: ConditionStateMachine)` inserts (idempotent by `condition_id`).
- `iter_retained(&self, address_space: &AddressSpace) -> Vec<ConditionStateMachine>` returns the
  conditions whose `Retain` state variable reads `true` (read Retain via the existing state-machine
  getter / address space).

**Acceptance:** `cargo build -p async-opcua-server`; unit-level sanity (codex may add a small inline
test that register + iter_retained reflects Retain).

---

### Task T3 (codex): Targeted per-subscription event delivery

**Files:** Modify `async-opcua-server/src/subscriptions/session_subscriptions.rs` (and
`subscriptions/mod.rs` if a pass-through is needed). Reference existing `notify_events`
(session_subscriptions.rs:1018, mod.rs:524) and `MonitoredItemHandle`.

- Add `refresh_subscription_events(&mut self, subscription_id: u32,
  monitored_item: Option<MonitoredItemHandle>, events: &[&dyn Event], type_tree: &dyn TypeTree)`.
- Behavior: locate the subscription by id within this session; if absent return a status the caller
  maps to `BadSubscriptionIdInvalid`. Deliver each event, in order, to that subscription's **event**
  monitored items (all of them, or only `monitored_item` when `Some`; if `Some` and the item is not
  an event item of that subscription, signal `BadMonitoredItemIdInvalid`). Reuse the existing
  per-item event-enqueue path (`MonitoredItem::notify_event`) so EventFilter select/where applies and
  queue-overflow handling is unchanged.
- **Bad_RefreshInProgress (Part 9 §5.5.7):** do NOT implement a flag. Delivery is synchronous/atomic
  under `&mut self` and OPC UA serializes calls, so no in-progress window exists across calls — the
  result code is vacuously satisfied (never returned). Add a `// ponytail:` comment noting the upgrade
  path (add the per-subscription flag + this code only if refresh becomes async/throttled).
- Must NOT broadcast to other subscriptions/sessions.

**Acceptance:** `cargo build -p async-opcua-server`. Compiles; existing subscription tests still pass.

---

### Task T4 (codex): ConditionRefresh / ConditionRefresh2 handlers

**Files:** Modify `async-opcua-server/src/alarms/methods.rs` (add refresh handlers, likely on a
handler that owns a `ConditionRegistry` + `Arc<RwLock<AddressSpace>>`), and wherever ConditionType
methods get callbacks registered (mirror how Acknowledge/Confirm are wired in
`namespace/init.rs` / the demo). Depends on T1, T2, T3.

- `handle_condition_refresh(&self, context: &RequestContext, args: &[Variant])`:
  - Parse `args[0]` as the SubscriptionId (UInt32); error → `BadInvalidArgument`.
  - Build the ordered event list: `RefreshStartEvent`, then for each
    `registry.iter_retained(&address_space)` its current `ServerAlarmEvent`, then `RefreshEndEvent`.
  - Call `context.subscriptions.refresh_subscription_events(sub_id, None, &events, type_tree)`;
    map a missing subscription to `BadSubscriptionIdInvalid`.
  - Return empty outputs on success.
- `handle_condition_refresh2(&self, context, args)`: `args[0]`=SubscriptionId, `args[1]`=
  MonitoredItemId (UInt32); same flow with `Some(item_handle)`; unknown item →
  `BadMonitoredItemIdInvalid`.
- Register both as **context-aware** method callbacks (`add_method_callback_with_context` /
  `typed_method_with_context`) on the ConditionType ConditionRefresh (3875) / ConditionRefresh2
  (12912) method nodes, sharing the `ConditionRegistry`.

**Acceptance:** `cargo build -p async-opcua-server`.

---

### Task T5 (codex): Thin client Session helpers

**Files:** Modify `async-opcua-client/src/session/services/method.rs` (or the alarms client module
`async-opcua-client/src/alarms/`). Reference existing `Session::call_one` and the alarms client
(`get_alarm_event_select_clauses`, `parse_alarm_event`).

- `Session::refresh_conditions(&self, subscription_id: u32) -> Result<(), Error>` →
  `call_one((ObjectTypeId::ConditionType, MethodId::ConditionType_ConditionRefresh,
  Some(vec![Variant::from(subscription_id)])))`; map a non-Good operation status to `Error`.
- `Session::refresh_conditions_for_item(&self, subscription_id: u32, monitored_item_id: u32)` →
  ConditionRefresh2 (12912) with `[subscription_id, monitored_item_id]`.
- `Session::acknowledge_condition(&self, condition_id: &NodeId, event_id: ByteString,
  comment: impl Into<LocalizedText>) -> Result<(), Error>` →
  `call_one((condition_id, MethodId::AcknowledgeableConditionType_Acknowledge,
  Some(vec![event_id.into(), comment.into().into()])))`.
- `Session::confirm_condition(...)` → same with Confirm (9113).

**Acceptance:** `cargo build -p async-opcua-client`.

---

### Task T6 (codex): Demo-server alarm example

**Files:** Modify `samples/demo-server/src/` (add an alarm module or extend `methods.rs`/`customs.rs`
pattern). Reference the integration test `async-opcua/tests/integration/alarms.rs` for how a
condition is created, registered for Ack/Confirm, and triggered. Depends on T1–T5.

- Create one alarm condition on a demo variable; register it in a `ConditionRegistry`; wire
  Acknowledge/Confirm/ConditionRefresh/ConditionRefresh2 callbacks.
- Drive it Active/Inactive on a timer or via a method, so a connected client can demonstrate
  subscribe → refresh → ack → confirm.

**Acceptance:** `cargo build -p async-opcua-demo-server`; demo server runs and exposes the alarm.

---

### Task T7 (Claude): Independent integration tests

**Files:** Modify `async-opcua/tests/integration/alarms.rs` (+ harness wiring if needed). Authored by
Claude, not codex. Anchored to Part 9 §5.5.7.

1. **Late-subscriber sync (key proof):** drive an alarm to Active; create a *fresh* subscription +
   event MonitoredItem; `refresh_conditions`; assert received order: RefreshStartEvent (EventType
   2787) → retained active ConditionEvent (ActiveState/Severity/Message match) → RefreshEndEvent
   (2788).
2. **ConditionRefresh2 targeting:** two event monitored items; refresh one; assert only that item got
   the burst.
3. **Validation:** bogus subscriptionId → `BadSubscriptionIdInvalid`; Refresh2 bogus monitoredItemId
   → `BadMonitoredItemIdInvalid`. (`BadRefreshInProgress` is not deterministically triggerable against
   a synchronous delivery without races, so it is verified by code review of the guard, not a
   timing-flaky test.)
4. **No-retained:** refresh with nothing active → Start/End, no condition events between.
5. **Helpers round-trip:** `acknowledge_condition`/`confirm_condition` drive the transitions the
   existing raw-call test asserts.

**Acceptance:** `cargo test -p async-opcua --test integration alarms` green; no regressions in the
existing alarms tests; full `cargo build` + clippy clean before PR.

---

## Self-review

- **Spec coverage:** ConditionRefresh (T4), ConditionRefresh2 (T4), marker events (T1), registry
  (T2/approach A), targeted delivery (T3), client helpers (T5), demo (T6), tests (T7) — all spec
  sections mapped.
- **Type consistency:** NodeId symbols, `ConditionRegistry`/`refresh_subscription_events`/handler
  names used identically across T1–T7.
- **Dependencies:** T4 needs T1+T2+T3; T6 needs T1–T5; T7 needs all. Dispatch order T1→T2→T3→T4→T5
  →T6, then Claude T7.
