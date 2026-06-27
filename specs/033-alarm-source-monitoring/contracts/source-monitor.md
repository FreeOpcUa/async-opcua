# Contract: alarm source monitoring

## `SourceMonitoredAlarm` trait (`async-opcua-server/src/alarms/source_monitor.rs`)

```text
pub trait SourceMonitoredAlarm: Send + Sync {
    /// The bound InputNode — the source Variable this alarm monitors (Part 9 §5.8.2).
    fn source_node(&self) -> &NodeId;

    /// Re-evaluate the alarm against a new source value, returning the AlarmEvent to dispatch
    /// (or None: no transition, disabled, or value not usable). Delegates to the alarm's existing
    /// update_value — does NOT reimplement limit/discrete evaluation.
    fn re_evaluate(&self, space: &mut AddressSpace, value: &DataValue) -> Option<AlarmEvent>;
}
```

Implemented by `ExclusiveLimitAlarmType`, `NonExclusiveLimitAlarmType` (extract f64 → `update_value`),
and the discrete/off-normal alarm (its value type). The implementations contain NO new evaluation
logic — only value extraction + delegation.

## `AlarmSourceRegistry` (held by `InMemoryNodeManager`)

```text
register(source: NodeId, alarm: Arc<dyn SourceMonitoredAlarm>)   // also sets InputNode + HasCondition
unregister(source: &NodeId, condition_id: &NodeId)
alarms_for(source: &NodeId) -> Vec<Arc<dyn SourceMonitoredAlarm>>  // empty if none → write is a no-op
```

## Write-path hook (node manager) — runs AFTER the write batch (analyze C1)

The write loop holds the address space under a **read** lock and `re_evaluate` needs `&mut AddressSpace`,
so the hook runs in `InMemoryNodeManager::write` *after* the per-node loop:
1. During the loop (read lock held): for each node `N` that wrote `Good` and has
   `!registry.alarms_for(N).is_empty()`, push `(N, written DataValue)` into a `source_writes` vec.
   (Zero allocation/cost when no written node is an alarm source.)
2. After the loop: **drop the read lock**; if `source_writes` is non-empty, acquire a **write** lock.
3. For each `(source, value)` and each `alarm in alarms_for(source)`:
   `if let Some(ev) = alarm.re_evaluate(&mut space, &value) { context.subscriptions().notify_events(once((&ServerAlarmEvent{event:&ev} as &dyn Event, &ev.source_node))); }`
4. The Write service result is fully determined BEFORE step 2 and is unaffected by any alarm-eval
   outcome (Constitution IV). A re-eval error is logged and swallowed.

## Programmatic source updates (analyze C2)

`InMemoryNodeManager::set_source_value(source: &NodeId, value: DataValue)` — write the Value and run the
same re-evaluate-and-dispatch path. This is the ONLY programmatic entry point that drives alarms;
direct address-space mutation is not intercepted (FR-011 scope).

## Configuration helper

A one-call binding (US3): attach an alarm to a source Variable — sets the InputNode property + the
HasCondition reference + registers the source→alarm index. After this, writes to the source drive the
alarm with no further calls.

## Sampling (opt-in)

A per-binding `sampling_interval`: when set, a server task reads the InputNode Value each interval and
calls `re_evaluate` + dispatch. Idempotent vs. write-driven (no-change → no event). OFF by default.

## Invariants

- A write to a node with no bound alarm does no extra work and emits nothing.
- Disabled alarm → no re-eval/event. Bad/null/non-numeric source value → no event, write still OK.
- `update_value` remains public and unchanged; manually-driven alarms keep working.
- No panic on any source value in the write path.
