# Phase 0 Research: Automatic alarm source monitoring

## D1 — Re-evaluate AFTER the write batch under a fresh write lock (not inside the read-locked write)

**Decision**: Re-evaluate bound alarms in the `InMemoryNodeManager::write` method, AFTER the per-node
write loop completes, NOT inside `write_node_value` and NOT via `add_write_callback`. Concretely:
1. The existing write loop holds the address space under a **read** lock (`trace_read_lock!`) and
   mutates nodes via guards. During the loop, collect `(source NodeId, written DataValue)` for nodes
   that (a) wrote successfully AND (b) are registered alarm sources (`registry.alarms_for(node)` is
   non-empty).
2. After the loop, **drop the read lock**, then acquire a **write** lock on the address space, and for
   each collected `(source, value)`: for each bound alarm, call `re_evaluate(&mut space, &value)` and
   dispatch any `Some(AlarmEvent)` via `context.subscriptions().notify_events(...)`.

**Rationale (this is the analyze C1 fix)**: `re_evaluate`/`update_value` need `&mut AddressSpace` (they
write the alarm's state nodes), but the write loop only has a **read** lock — so the hook cannot run
inside the loop. Deferring to after the batch lets us re-acquire a write lock cleanly. It also
*improves* Constitution-IV isolation: the client's Write result is fully determined before any alarm
re-evaluation runs. `add_write_callback(id, Fn(DataValue,&NumericRange)->StatusCode)` is rejected
anyway — it is synchronous, returns a status, and has no access to the event sink.

**Alternatives rejected**: change `update_value` to take `&AddressSpace` + interior-mutability (touches
stable public alarm code for no benefit); extend `add_write_callback` to dispatch events (duplicates
event plumbing, widens a public signature); a separate async write-notification subscriber (more moving
parts, lag vs. synchronous-after-batch).

## D2 — `SourceMonitoredAlarm` trait so all alarm types share one re-eval path

**Decision**: A trait (in `alarms/source_monitor.rs`):
```text
trait SourceMonitoredAlarm: Send + Sync {
    fn source_node(&self) -> &NodeId;                 // the InputNode
    fn re_evaluate(&self, space: &mut AddressSpace, value: &DataValue) -> Option<AlarmEvent>;
}
```
`ExclusiveLimitAlarmType`/`NonExclusiveLimitAlarmType` implement it by extracting an `f64` and
delegating to the existing `update_value`; discrete/off-normal alarms implement it via their own
`update_value`. The registry stores `Arc<dyn SourceMonitoredAlarm>`.

**Rationale**: one re-evaluation entry point reused by every alarm type (Constitution II); the
existing per-type evaluation logic is untouched.

## D3 — `AlarmSourceRegistry`: source NodeId → bound alarms

**Decision**: `HashMap<NodeId /*source*/, Vec<Arc<dyn SourceMonitoredAlarm>>>` behind a lock, in
`source_monitor.rs`, held by the `InMemoryNodeManager` (which owns the address space and the write
path). Supports multiple alarms per source (FR-004). The existing `ConditionRegistry`
(condition_id → state machine) is left as-is; the source index is a sibling.

**Rationale**: the write hook needs a fast source→alarms lookup; keeping it on the node manager puts
it where the write happens and avoids threading a global through the server.

## D4 — Value extraction + no-panic on bad input

**Decision**: For numeric limit alarms, extract `f64` from the written `DataValue.value` (numeric
Variant cast). If the value is null, non-numeric, or the DataValue status is Bad, SKIP re-evaluation
for that alarm (no transition, no event) — never panic, never fail the underlying write (Constitution
IV). Discrete alarms extract their configured value type. The write itself always completes per the
existing Write semantics; alarm re-eval is a best-effort side effect that runs after.

## D5 — InputNode property + ConditionSource/HasCondition references

**Decision**: When a binding is created, set the alarm's `InputNode` property node to the source
NodeId (Part 9 §5.8.2), and add the `HasCondition` reference from the source node to the alarm so the
binding is browsable (Part 9 §4.4 ConditionSource). Reuse the existing alarm address-space wiring in
`limit.rs`/`discrete.rs`.

## D6 — Opt-in periodic sampling

**Decision**: A per-binding optional sampling interval. When enabled, a server-side async task reads
the InputNode's current Value on each tick and calls `re_evaluate`. The existing `update_value`
deadband/state logic makes a no-change re-eval idempotent (no duplicate transition event), so
write-driven + sampling cannot double-emit for one change. Sampling is OFF by default; write-driven is
the always-on path.

**Rationale**: Part 9 implies continuous source monitoring, but most sources change via Write; sampling
covers out-of-band updates without imposing a polling cost on the common case.

## D7 — Error isolation from the Write result

**Decision**: Alarm re-evaluation runs AFTER the write value is applied/committed. Any error in
re-eval or dispatch is logged and swallowed; it MUST NOT alter the Write service result returned to the
client (Constitution IV — the write is the client's operation; alarm eval is a server side effect).

## D9 — Programmatic source updates go through an explicit helper (analyze C2 fix)

**Decision**: A server-side programmatic value update triggers alarm re-evaluation only through an
explicit `InMemoryNodeManager::set_source_value(source: &NodeId, value: DataValue)` helper that writes
the Value AND runs the same re-evaluate-and-dispatch path as D1. Arbitrary direct address-space
mutations are NOT intercepted (there is no universal hook for them, and trying to add one would be
fragile and costly).

**Rationale**: FR-011 ("a programmatic server-side set MUST also trigger re-evaluation") is satisfiable
cleanly only by giving integrators one intended entry point; an integrator who mutates the address
space directly bypasses the alarm system by definition. Scoping FR-011 to `set_source_value` keeps the
guarantee precise and testable.

## D8 — Backwards compatibility

**Decision**: `update_value` stays `pub` and behaviourally unchanged; manually-driven alarms (no
binding registered) are unaffected. Registering a binding is purely additive. All new code builds
under `--no-default-features` and `--all-features`.
