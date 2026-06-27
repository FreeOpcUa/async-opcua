# Tasks: Automatic alarm source monitoring

**Feature**: `specs/033-alarm-source-monitoring` | **Branch**: `033-alarm-source-monitoring`
**Spec**: [spec.md](spec.md) · **Plan**: [plan.md](plan.md) · **Contract**: [contracts/source-monitor.md](contracts/source-monitor.md)

Format: `[ID] [P?] [Story?] Description (Spec: Part/§)`. Tasks are **atomic** (one concern each) and
**cite the OPC UA Part/§** they touch so the implementer grounds them via the reference MCP. [P] =
parallelizable (different files, no incomplete deps). Codex implements one task per dispatch (no-git);
Claude authors the `[Claude]` test tasks and runs the full suite (codex sandbox can't bind sockets).

---

## Phase 1: Setup

- [X] T001 Inventory the reuse surface: `update_value` in `async-opcua-server/src/alarms/limit.rs`, `ConditionRegistry` in `alarms/registry.rs`, `dispatch_alarm_event`/`ServerAlarmEvent` in `alarms/dispatch.rs`, `RequestContext::subscriptions()` in `node_manager/context.rs`, and the Value-write path in `node_manager/memory/simple.rs` (Spec: Part 9 §5.8.2; Part 4 §11.x Write)
- [X] T002 [P] Confirm `cargo test -p async-opcua-server` and the `async-opcua` alarms integration suite are green at baseline (Spec: SC-004)

## Phase 2: Foundational (BLOCKING — all stories depend on this)

- [X] T003 Define the `SourceMonitoredAlarm` trait (`source_node()`, `re_evaluate(&AddressSpace mut, &DataValue) -> Option<AlarmEvent>`) in a NEW `async-opcua-server/src/alarms/source_monitor.rs`; register the module in `alarms/mod.rs` (Spec: Part 9 §5.8.2 AlarmConditionType.InputNode)
- [X] T004 Implement `AlarmSourceRegistry` (`RwLock<HashMap<NodeId source, Vec<Arc<dyn SourceMonitoredAlarm>>>>` with `register`/`unregister`/`alarms_for`) in `alarms/source_monitor.rs`; multiple alarms per source (Spec: Part 9 §4.4 ConditionSource / HasCondition)
- [X] T005 Hold an `AlarmSourceRegistry` on the `InMemoryNodeManager` (`node_manager/memory/mod.rs`) + an accessor reachable from the write path; default-empty (Spec: Part 9 §4.4)
- [X] T006 [P] [Claude] Unit test the registry index: register, `alarms_for` returns all bound alarms, multiple-per-source, unknown source → empty (Spec: Part 9 §4.4)

**Checkpoint**: trait + registry exist; nothing is wired into the write path yet.

---

## Phase 3: User Story 1 — Write-driven auto re-evaluation + dispatch (P1) 🎯 MVP

**Goal**: writing a value past a limit on a bound source auto-activates the alarm and emits the event,
no manual `update_value`. **Independent test**: bind an ExclusiveLimitAlarm, write above High, assert
Active(High) + event with no manual call.

- [X] T007 [US1] Implement `SourceMonitoredAlarm` for `ExclusiveLimitAlarmType` in `alarms/limit.rs`: `source_node()` returns the bound InputNode (the InputNode property is on AlarmConditionType); `re_evaluate` extracts the value and delegates to the existing `update_value` (no new evaluation logic) (Spec: Part 9 §5.8.18 ExclusiveLimitAlarmType; §5.8.2 AlarmConditionType.InputNode)
- [X] T008 [US1] Add a value-extraction helper (`DataValue` → `f64`) used by `re_evaluate`: null / non-numeric / Bad-status → `None` (skip), never panic (Spec: Part 9 §5.8.2; Constitution IV)
- [X] T009 [US1] In `InMemoryNodeManager::write` (`node_manager/memory/simple.rs`), DURING the read-locked per-node loop, collect `(source NodeId, written DataValue)` for each node that wrote `Good` AND has a non-empty `alarms_for(node)` — zero cost when no written node is an alarm source (Spec: Part 4 §11.x Write; Part 9 §4.4)
- [X] T010 [US1] AFTER the write loop, drop the read lock and (if any sources were collected) acquire a WRITE lock; for each `(source, value)` and each bound alarm call `re_evaluate(&mut space, &value)` and dispatch each `Some(AlarmEvent)` via `context.subscriptions().notify_events` using `ServerAlarmEvent` (reuse `dispatch.rs`) (Spec: Part 9 §5.8 event reporting; Part 4 §5.12 Notification)
- [X] T011 [US1] Isolate alarm re-evaluation from the Write result: the Write status is fully set before the post-loop re-eval; log+swallow any eval/dispatch error; the Write service result MUST be unchanged (Spec: Part 4 §11.x Write; Constitution IV)
- [X] T011a [US1] Add `InMemoryNodeManager::set_source_value(source: &NodeId, value: DataValue)` — write the Value AND run the same re-evaluate-and-dispatch path (the only programmatic entry point that drives alarms; FR-011) (Spec: Part 9 §5.8 / §4.4; FR-011)
- [X] T012 [US1] Confirm the Enabled gate: a disabled alarm's `re_evaluate` returns `None` (via `update_value`'s existing enabled check), so no auto-fire (Spec: Part 9 §5.5.2 EnabledState)
- [X] T013 [P] [US1] [Claude] Integration test (`async-opcua/tests/integration/alarms.rs`): bind alarm, write above High → Active(High) + AlarmEvent auto-dispatched, no `update_value` call (Spec: Part 9 §5.8.2)
- [X] T014 [P] [US1] [Claude] Integration test: from Active, write back within limits (honoring deadband) → Inactive + clearing event (Spec: Part 9 §5.8.2 / §5.5.3)
- [X] T015 [P] [US1] [Claude] Integration test: two alarms bound to one source both re-evaluate on a single write (Spec: Part 9 §4.4)
- [X] T016 [P] [US1] [Claude] Integration test: writing a source with no bound alarm is a no-op (no error, no event) (Spec: Part 9 §4.4)
- [X] T017 [P] [US1] [Claude] Integration test: a disabled alarm does not fire when its source changes (Spec: Part 9 §5.5.2)
- [X] T018 [P] [US1] [Claude] Test: non-numeric / null / Bad-status write to a source → no panic, the write still succeeds, no event emitted (Spec: Part 4 §11.x; Constitution IV)
- [X] T018a [P] [US1] [Claude] Integration test: a programmatic `set_source_value` above a limit auto-activates the alarm + emits the event (FR-011 path) (Spec: Part 9 §5.8 / §4.4)

**Checkpoint**: the closed loop works for ExclusiveLimitAlarmType end-to-end.

---

## Phase 4: User Story 2 — Browsable source binding (P2)

**Goal**: the InputNode property + HasCondition references make the binding discoverable.
**Independent test**: read the alarm's InputNode and browse the source's conditions.

- [ ] T019 [US2] On binding, set the AlarmConditionType `InputNode` property node to the source Variable's NodeId in the address space (Spec: Part 9 §5.8.2 InputNode)
- [ ] T020 [US2] On binding, add a `HasCondition` reference from the source node to the alarm so the alarm is reachable from its source (Spec: Part 9 §4.4 ConditionSource / HasCondition)
- [ ] T021 [P] [US2] [Claude] Integration test: read the alarm's `InputNode` property → returns the source NodeId (Spec: Part 9 §5.8.2)
- [ ] T022 [P] [US2] [Claude] Integration test: browse the source node's `HasCondition` references → reach the bound alarm (Spec: Part 9 §4.4)

**Checkpoint**: the binding is spec-conformantly browsable.

---

## Phase 5: User Story 3 — Declarative configuration helper (P2)

**Goal**: one call attaches an alarm to a source (InputNode + HasCondition + index).
**Independent test**: helper binds in one call; source writes drive the alarm and the binding is browsable.

- [ ] T023 [US3] Add `InMemoryNodeManager::monitor_alarm_source(source: &NodeId, alarm)` that sets the InputNode property (T019), adds HasCondition (T020), and registers the source→alarm index (T004) in one call (Spec: Part 9 §5.8.2 / §4.4)
- [ ] T024 [P] [US3] [Claude] Integration test: after `monitor_alarm_source`, a source write drives the alarm (US1) and the binding is browsable (US2) (Spec: Part 9 §5.8.2)
- [ ] T025 [US3] Wire an alarm to a writable source variable in the demo server (`samples/demo-server`) using the helper (Spec: Part 9 §5.8.2; FR-006)

**Checkpoint**: integrators declare the binding once; the server handles the rest.

---

## Phase 6: User Story 4 — Opt-in periodic sampling (P3)

**Goal**: poll the InputNode each interval for out-of-band sources.
**Independent test**: change the source out-of-band → alarm activates within one interval.

- [ ] T026 [US4] Add an optional per-binding `sampling_interval` (None = write-driven only) to the registry/binding in `alarms/source_monitor.rs` (Spec: Part 9 §4.4 continuous source monitoring)
- [ ] T027 [US4] Implement a server-side sampling task: each interval, read the InputNode's current Value, call `re_evaluate`, and dispatch any event — reusing the US1 dispatch path (Spec: Part 9 §4.4 / §5.8)
- [ ] T028 [US4] Verify idempotence: an unchanged in-limits value on a sampling tick emits no event (rely on the existing deadband/state-transition logic; no write+sample double-fire) (Spec: Part 9 §5.8.2 deadband)
- [ ] T029 [P] [US4] [Claude] Integration test: with sampling enabled, an out-of-band source change to exceed a limit activates the alarm within one interval (Spec: Part 9 §4.4)
- [ ] T030 [P] [US4] [Claude] Integration test: with sampling OFF, an out-of-band change re-evaluates only on the next write (Spec: Part 9 §4.4)

**Checkpoint**: out-of-band sources covered without polling cost on the common case.

---

## Phase 7: User Story 5 — All alarm types with an InputNode (P3)

**Goal**: NonExclusive + discrete/off-normal alarms self-trigger too.
**Independent test**: repeat US1 for NonExclusiveLimitAlarmType and a discrete alarm.

- [ ] T031 [US5] Implement `SourceMonitoredAlarm` for `NonExclusiveLimitAlarmType` in `alarms/limit.rs` (extract f64 → its `update_value`) (Spec: Part 9 §5.8.19–§5.8.20 NonExclusiveLimitAlarmType; §5.8.2 InputNode)
- [ ] T032 [US5] Implement `SourceMonitoredAlarm` for the discrete / off-normal alarm in `alarms/discrete.rs` (its value type → `update_value`) (Spec: Part 9 §5.8.3 DiscreteAlarmType / §5.8.4 OffNormalAlarmType; §5.8.2 InputNode)
- [ ] T033 [P] [US5] [Claude] Integration test: NonExclusiveLimitAlarm — a value crossing multiple limits auto-activates the Hi/HiHi/Lo/LoLo states (Spec: Part 9 §5.8.19–§5.8.20)
- [ ] T034 [P] [US5] [Claude] Integration test: a discrete/off-normal alarm enters its off-normal value via a source write → auto-activates (Spec: Part 9 §5.8.4 OffNormalAlarmType)

**Checkpoint**: source monitoring generalizes across the alarm types.

---

## Phase 8: Polish & cross-cutting

- [ ] T035 [P] Run the FULL `cargo test -p async-opcua-server` (all binaries) + the `async-opcua` alarms integration suite — zero regressions, manual `update_value` unaffected (Spec: SC-004)
- [ ] T036 [P] Build + test under `--no-default-features` and `--all-features`; fix any feature-gating gaps (Spec: SC-007; FR-012)
- [ ] T037 [P] `cargo clippy --workspace --all-targets` (default + no-default legs) + `cargo fmt --all --check` clean (Spec: Constitution V)
- [ ] T038 [P] Security review of the write-path hook: no panic on any source value, work bounded to the bound-alarm set, Write result isolated from alarm-eval errors (Spec: Constitution IV)
- [ ] T039 [P] Add a docs section (`docs/server.md` or `docs/advanced_server.md`) on alarm source monitoring + `monitor_alarm_source`, mirroring quickstart.md (Spec: Part 9 §5.8.2)
- [ ] T040 Update `specs/SESSION-HANDOFF.md` + memory with the alarm source-monitoring outcome (Spec: project process)

---

## Dependencies & order

- **Phase 2 (Foundational) blocks everything** — trait + registry + node-manager wiring land first.
- **US1 (P1)** is the MVP (write-driven loop). **US2/US3** layer the browsable binding + ergonomic
  helper on top. **US4** (sampling) and **US5** (more alarm types) are independent P3 extensions of US1.
- One PR per user story (squash-merged on the fork). Codex one atomic task per dispatch; Claude authors
  the `[Claude]` tests and runs the full suite each story.

## Implementation strategy

MVP = Phase 2 + US1 (an ExclusiveLimitAlarm that self-fires on a source write). Each later story is an
independently shippable increment: browsable binding (US2), one-call config (US3), sampling (US4),
NonExclusive + discrete (US5).
