# Alarms & Conditions — Subscriber End-to-End (ConditionRefresh + client helpers) — Design

Date: 2026-06-24
Status: approved (brainstorm); approach A confirmed

## Purpose

Make async-opcua usable as an **A&C subscriber** target — the "Channel A" alarms piece both
consumer projects (QuackPLC server, QuackDCS supervisory client) need. The trigger→Acknowledge→
Confirm lifecycle, event-filter subscription, and EventId validation already work. The blocking gap
is **ConditionRefresh**: today a client that subscribes *after* an alarm is already active sees
nothing until the next state change. Per Part 9 §5.5.7, `ConditionRefresh` re-sends the current
state of every retained condition to the requesting subscription, bracketed by RefreshStart/End
events — this is how a freshly-connected DCS HMI learns about existing alarms. We also add thin
client helpers so consumers call refresh/acknowledge/confirm without hand-building `CallMethodRequest`s.

## Scope

**In scope**
- Server `ConditionRefresh` (Part 9 §5.5.7) and `ConditionRefresh2` (per-monitored-item) method
  handlers, delivering RefreshStart → retained condition events → RefreshEnd to the *requesting
  subscription only* (Refresh2: to one monitored item only).
- `RefreshStartEventType` (i=2787) / `RefreshEndEventType` (i=2788) event generation.
- A lightweight, app-populated condition registry the refresh handler iterates (approach A).
- A targeted subscription-delivery path (one subscription / one monitored item) distinct from the
  existing broadcast `notify_events`.
- Thin client `Session` helpers: `refresh_conditions`, `refresh_conditions_for_item`,
  `acknowledge_condition`, `confirm_condition`.
- A runnable demo-server alarm example wired for Ack/Confirm/Refresh.

**Out of scope** (later slices / deferred)
- LimitAlarmType / ExclusiveLimitAlarmType and the broader condition-type hierarchy (next slice).
- Condition history / branching (Part 9 §5.3), HistoryRead on condition events.
- Managed/stateful client "AlarmSubscription" helper (chose thin wrappers).
- Automatic state-machine transitions / continuous source monitoring.

## Verified NodeIds (from `async-opcua-types/src/generated/node_ids.rs`)

| Symbol | Enum | Id |
|---|---|---|
| ConditionType (call objectId for refresh) | `ObjectTypeId::ConditionType` | 2782 |
| ConditionRefresh method | `MethodId::ConditionType_ConditionRefresh` | 3875 |
| ConditionRefresh2 method | `MethodId::ConditionType_ConditionRefresh2` | 12912 |
| Acknowledge method | `MethodId::AcknowledgeableConditionType_Acknowledge` | 9111 |
| Confirm method | `MethodId::AcknowledgeableConditionType_Confirm` | 9113 |
| RefreshStartEventType | `ObjectTypeId::RefreshStartEventType` | 2787 |
| RefreshEndEventType | `ObjectTypeId::RefreshEndEventType` | 2788 |

## Architecture

Conditions are app-owned `ConditionStateMachine`s (`async-opcua-server/src/alarms/state_machine.rs`,
`#[derive(Clone)]`, state lives in the `AddressSpace`). `ServerAlarmEvent`
(`alarms/dispatch.rs`) rebuilds a condition's current event from that state. `AlarmMethodHandler`
(`alarms/methods.rs`) already fires ack/confirm events via `context.subscriptions.notify_events()` —
but that **broadcasts to all subscriptions**. ConditionRefresh needs the opposite: a *targeted*
burst to one subscription. So we add (1) the marker events, (2) an enumerable condition source,
(3) the refresh handlers, (4) targeted delivery — and the thin client wrappers.

```
Client: Session::refresh_conditions(sub_id)
   └─ Call(objectId=ConditionType i=2782, methodId=ConditionRefresh i=3875, [sub_id])
        ▼  (server, context-aware method callback)
   validate sub_id belongs to session  ──fail──▶ BadSubscriptionIdInvalid
        ▼
   deliver to sub_id's event monitored items, in order:
     RefreshStartEvent (i=2787)
     for each retained condition in ConditionRegistry: its current ServerAlarmEvent
     RefreshEndEvent   (i=2788)
```

## Components (one responsibility each)

1. **Refresh marker events** — `RefreshStartEvent` / `RefreshEndEvent` types implementing the
   `Event` trait (mirror `BaseEventType`/`ServerAlarmEvent`), carrying the standard event fields
   (EventId, EventType=2787/2788, SourceNode=Server, Time, Severity, Message). New file
   `async-opcua-server/src/alarms/refresh_events.rs`.
2. **`ConditionRegistry`** (approach A) — holds the set of `ConditionStateMachine`s (clones) the app
   has created; exposes `iter_retained(&AddressSpace) -> impl Iterator<…>` returning the conditions
   whose `Retain == true`. App registers each condition when it builds it. Lives alongside the alarms
   module (e.g. `alarms/registry.rs`). Shared via `Arc<RwLock<…>>` (interior mutability) so the same
   set is seen by both the condition-creation site and the refresh-method callback closure that
   iterates it. App registers a condition by inserting its `ConditionStateMachine` clone.
3. **Refresh handlers** — `handle_condition_refresh(context, args)` and
   `handle_condition_refresh2(context, args)` (on a handler that owns the `ConditionRegistry` +
   `Arc<RwLock<AddressSpace>>`). Validate args/subscription, build the marker + replayed events,
   call the targeted-delivery API. Registered as context-aware method callbacks on the
   ConditionType refresh methods.
4. **Targeted delivery** — new `subscriptions` API
   `refresh_subscription_events(subscription_id, monitored_item: Option<MonitoredItemHandle>,
   events: Vec<&dyn Event>)` that resolves the target subscription's event monitored item(s) and
   enqueues the events to them in order, without touching other subscriptions. Distinct from the
   broadcast `notify_events`.
5. **Client helpers** (`async-opcua-client/src/session/services/...`, thin):
   - `refresh_conditions(&self, subscription_id) -> Result<(), Error>`
   - `refresh_conditions_for_item(&self, subscription_id, monitored_item_id) -> Result<(), Error>`
   - `acknowledge_condition(&self, condition_id, event_id, comment) -> Result<(), Error>`
   - `confirm_condition(&self, condition_id, event_id, comment) -> Result<(), Error>`
   Each builds the `CallMethodRequest` with the verified ids and maps the operation status to a
   `Result`. Compose with the existing `get_alarm_event_select_clauses`/`parse_alarm_event`.
6. **Demo-server example** — register an alarm condition that toggles Active/Inactive, wired into the
   `ConditionRegistry` and the Ack/Confirm/Refresh method callbacks, so both consumers have a
   runnable reference.

## Data flow

App creates conditions → registers them in `ConditionRegistry`. A client subscribes to events
(EventNotifier MonitoredItem with the alarm select clauses) → calls `refresh_conditions(sub_id)` →
server validates, emits RefreshStart, replays each retained condition's current `ServerAlarmEvent`,
emits RefreshEnd, all targeted to `sub_id` → client receives the burst and updates its alarm view.
Acknowledge/Confirm continue to flow through the existing `AlarmMethodHandler` path (broadcast),
unchanged.

## Error handling

Result codes per MCP-confirmed Part 9 §5.5.7 (ConditionRefresh) / §5.5.8 (ConditionRefresh2);
RefreshStart/RefreshEndEvent defined in §5.11.2:
- Unknown/foreign `subscriptionId` → `BadSubscriptionIdInvalid` (Refresh2 unknown monitoredItemId →
  `BadMonitoredItemIdInvalid`). Validate against the *calling session's* subscriptions only.
- **`BadRefreshInProgress`** (Part 9 §5.5.7 / Table 137) models a refresh that *spans multiple
  publish cycles*, leaving a window where a second refresh could arrive mid-stream. async-opcua's
  wire **transmission** is async (events drain from the monitored-item queues via Publish), BUT the
  refresh **enqueue** is synchronous and atomic: method callbacks are a synchronous
  `Fn(&[Variant]) -> Result<…>` (no `async`), and `SubscriptionCache::refresh_subscription_events`
  runs the whole `&mut self` enqueue under the per-session `cache.lock()`. So RefreshStart → replayed
  events → RefreshEnd land in the queue as one contiguous, uninterruptible block, and two concurrent
  ConditionRefresh calls serialize on that lock — neither observes the other "in progress." The
  condition is therefore vacuously satisfied (never returned); we do **not** add an unreachable flag
  (dead code). A `// ponytail:` comment notes the upgrade path: if refresh ever becomes
  async/throttled (spanning publishes), add the per-subscription in-progress flag + this result code.
- No retained conditions → a valid RefreshStart/RefreshEnd pair with no events between (spec-correct:
  the client learns "nothing currently retained").
- Refresh delivery never blocks ack/confirm or normal event flow; it only appends to the target
  subscription's event queue (subject to the existing queue-overflow handling).
- Per Part 9, RefreshStart/End EventIds are fresh per refresh; markers carry SourceNode = Server.
- Scope note: refresh covers retained **Conditions**; retained condition **Branches** (§5.5.x) are
  deferred with the broader branching work, so only the conditions in the registry are replayed.

## Testing (Claude authors, independent of the codex implementation; anchored to Part 9 §5.5.7)

Extend `async-opcua/tests/integration/alarms.rs`:
1. **Late-subscriber sync (the key proof):** drive an alarm to Active; *then* create a fresh
   subscription + event MonitoredItem; call `refresh_conditions`; assert the client receives, in
   order, `RefreshStartEvent` (EventType i=2787) → the retained active ConditionEvent (matching the
   condition's current ActiveState/Severity/Message) → `RefreshEndEvent` (i=2788).
2. **ConditionRefresh2 targeting:** with two event monitored items, refresh one; assert only that
   item received the burst.
3. **Validation:** refresh with a bogus subscriptionId → `BadSubscriptionIdInvalid`.
4. **No-retained case:** refresh when nothing is active → Start/End with no condition events between.
5. **Thin helpers round-trip:** `acknowledge_condition` / `confirm_condition` drive the same state
   transitions the existing raw-call test asserts (reuse the existing alarms.rs patterns).

## Implementation split

Per project workflow: **codex implements** the server refresh handlers + marker events +
`ConditionRegistry` + targeted delivery + client wrappers + demo wiring (feature/library code);
**Claude authors/validates** the independent integration tests above. Dispatched as focused codex
tasks (one concern each), no-git guardrail, branch verified after each.
