# Phase 1 Data Model: Automatic alarm source monitoring

## Existing entities (reused, not changed)

- **`ExclusiveLimitAlarmType` / `NonExclusiveLimitAlarmType`** (`alarms/limit.rs`): hold limits,
  deadband, state machine; `update_value(&mut AddressSpace, value: f64) -> Option<AlarmEvent>`.
- **Discrete / off-normal alarm** (`alarms/discrete.rs`): `update_value(...)` for its value type.
- **`ConditionRegistry`** (`alarms/registry.rs`): `condition_id → ConditionStateMachine` (unchanged).
- **`AlarmEvent`** (`async-opcua-core`) + **`ServerAlarmEvent`** / `dispatch_alarm_event`
  (`alarms/dispatch.rs`): the event + its dispatch to subscription buffers.
- **`RequestContext`** (`node_manager/context.rs`): exposes `subscriptions(): &SubscriptionCache`.

## New / extended entities

### `SourceMonitoredAlarm` (trait, `alarms/source_monitor.rs`)
A common re-evaluation surface across alarm types:
- `source_node(&self) -> &NodeId` — the bound InputNode (source Variable).
- `re_evaluate(&self, space: &mut AddressSpace, value: &DataValue) -> Option<AlarmEvent>` — extract the
  alarm's value type from `value` and delegate to the existing `update_value`; returns the event to
  dispatch, or `None` (no transition / unusable value).

### Alarm-source binding
The association `(alarm) → (source Variable NodeId)`:
- In code: an entry in the source index.
- In the address space: the AlarmConditionType `InputNode` property set to the source NodeId, plus a
  `HasCondition` reference from the source node to the alarm (Part 9 §5.8.2 / §4.4).
- Optional `sampling_interval` (None = write-driven only).

### `AlarmSourceRegistry` (`alarms/source_monitor.rs`, held by `InMemoryNodeManager`)
- `bindings: RwLock<HashMap<NodeId /*source*/, Vec<Arc<dyn SourceMonitoredAlarm>>>>`.
- `register(source, alarm)` / `unregister(...)`; `alarms_for(source) -> Vec<Arc<dyn ...>>`.
- One source may map to many alarms (FR-004).

## Behavioural rules

- **Trigger**: a successful Value write (or programmatic set) to a node N → for each alarm in
  `alarms_for(N)`, call `re_evaluate(space, written_value)`; dispatch each `Some(event)` via
  `context.subscriptions().notify_events`.
- **Enabled gating**: `re_evaluate` (through `update_value`) returns `None` for a disabled alarm
  (FR-010).
- **Bad input**: null / non-numeric / Bad-status value → `re_evaluate` returns `None`; the write still
  succeeds (FR-002 side-effect, Constitution IV).
- **Idempotence**: re-evaluating with an unchanged in-limits value emits no event (existing deadband /
  state-transition logic), so write + sampling never double-fire.
