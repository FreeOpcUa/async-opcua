# Process Limit Alarms Implementation Plan

> **For agentic workers:** Implementation tasks (T1–T5) go to **codex** (one concern per dispatch,
> no-git guardrail, branch verified after each, scope-escape rule in every brief). The evaluator
> vectors + integration tests (T6) are **authored by Claude**, independent of the implementation.
> Codex tasks must leave the workspace compiling and `cargo test -p async-opcua-server --lib` green.

**Goal:** Add ExclusiveLimitAlarmType + NonExclusiveLimitAlarmType (Hi/HiHi/Lo/LoLo) with deadband
hysteresis, composing the existing condition lifecycle.

**Architecture:** See `docs/superpowers/specs/2026-06-25-process-limit-alarms-design.md`. A pure
`LimitEvaluator` computes active limit state(s) + severity from (value, config, prev); a `LimitAlarm`
owns a `ConditionStateMachine` + the limit nodes and writes the evaluation result into the address
space + returns the resulting `AlarmEvent` for dispatch. Ack/Confirm/ConditionRefresh are reused.

**Tech stack:** Rust; `async-opcua-server` `alarms` module; generated NodeIds in `async-opcua-types`;
the existing `ConditionStateMachine` / `dispatch_alarm_event` / `ConditionRegistry` /
`register_condition_methods`.

**Verified NodeIds:** ExclusiveLimitAlarmType=9341, ExclusiveLimitStateMachineType=9318 (states
HighHigh=9329/High=9331/Low=9333/LowLow=9335), ExclusiveLimitAlarmType_LimitState=9455,
NonExclusiveLimitAlarmType=9906 (states HighHighState=10020/HighState=10029/LowState=10038/
LowLowState=10047), LimitAlarmType limits HighHighLimit=11124/HighLimit=11125/LowLimit=11126/
LowLowLimit=11127, deadbands HighHighDeadband=24774/HighDeadband=24775/LowDeadband=24776/
LowLowDeadband=24777.

---

### Task T1 (codex): LimitConfig + LimitEvaluator (pure logic + deadband)

**Files:** Create `async-opcua-server/src/alarms/limit.rs`; export the public types from
`async-opcua-server/src/alarms/mod.rs`.

Define (names are normative — later tasks/tests use them verbatim):
- `pub enum LimitMode { Exclusive, NonExclusive }`
- `pub enum LimitLevel { HighHigh, High, Low, LowLow }`
- `pub struct LimitDef { pub value: f64, pub deadband: f64, pub severity: u16 }`
- `pub struct LimitConfig { pub mode: LimitMode, high_high: Option<LimitDef>, high: Option<LimitDef>, low: Option<LimitDef>, low_low: Option<LimitDef> }`
  with a builder: `LimitConfig::new(mode)` + `with_high_high(LimitDef)` / `with_high` / `with_low` /
  `with_low_low`, and `fn validate(&self) -> Result<(), StatusCode>` enforcing ordering
  `HighHighLimit >= HighLimit >= LowLimit >= LowLowLimit` (only among the limits that are set) and
  that each deadband is non-negative and smaller than the gap to the adjacent set limit. The builder
  finalizer (e.g. `build()`) returns `Result<LimitConfig, StatusCode>` (BadOutOfRange on inconsistency).
- `pub struct NonExclusiveState { pub high_high: bool, pub high: bool, pub low: bool, pub low_low: bool }`
- `pub enum ActiveLimits { Exclusive(Option<LimitLevel>), NonExclusive(NonExclusiveState) }` —
  `Exclusive(None)` / all-false = inactive.
- `pub struct LimitOutcome { pub limits: ActiveLimits, pub active: bool, pub severity: u16, pub message: String }`
- `pub struct LimitEvaluator;` with
  `pub fn evaluate(value: f64, cfg: &LimitConfig, prev: &ActiveLimits) -> LimitOutcome`.

Evaluation rules:
- A high limit L (value `L`, deadband `d`): considered exceeded when `value > L`; once exceeded it
  remains exceeded until `value < L - d` (use `prev` to know if it was exceeded). Low limit L:
  exceeded when `value < L`; remains until `value > L + d`.
- **Exclusive**: `limits = Exclusive(most_severe_exceeded)` where order of severity is
  HighHigh ≻ High ≻ Low ≻ LowLow; `active = Some(_)`; `severity` = that limit's `severity`;
  `message` names the limit (e.g. "HighHigh limit exceeded"). Inactive → `Exclusive(None)`,
  `active=false`, `severity=0`/a configured normal severity, message "Normal".
- **NonExclusive**: each set limit's boolean computed independently with its own hysteresis;
  `active = any true`; `severity` = max severity among active; message names the active set (or the
  highest). Unset limits are always false.
- `value.is_nan()` or non-finite → return a `LimitOutcome` reflecting `prev` unchanged.

Do NOT write behavioral/acceptance tests (Claude owns those in T6). A trivial `#[cfg(test)]` smoke
test that the module compiles and a single obvious crossing returns the expected level is acceptable
but not required.

**Acceptance:** `cargo build -p async-opcua-server` clean (no warnings); types exported from `mod.rs`.
SCOPE-ESCAPE: if you must touch files outside `alarms/limit.rs` + `alarms/mod.rs`, stop and report.

---

### Task T2 (codex): ExclusiveLimitAlarm node + update_value wiring

**Files:** `async-opcua-server/src/alarms/limit.rs` (+ reuse `state_machine.rs`, `dispatch.rs`).

- `pub struct LimitAlarm` owning: a `ConditionStateMachine` (base lifecycle), the `LimitConfig`,
  the relevant limit node ids, and an interior-mutable previous `ActiveLimits`
  (`std::sync::Mutex<ActiveLimits>` or the project's lock) for hysteresis.
- Node creation for the **exclusive** case (a constructor like
  `LimitAlarm::create_exclusive_in_address_space(address_space, ids…, cfg) -> LimitAlarm`):
  build the base condition (reuse `ConditionStateMachine::create_in_address_space`), set
  `HasTypeDefinition` to `ExclusiveLimitAlarmType` (i=9341), add the configured limit properties
  (i=11124/11125/11126/11127) and deadband properties (i=24774/24775/24776/24777) with their values,
  and add a `LimitState` component (`ExclusiveLimitAlarmType_LimitState` i=9455) of
  `ExclusiveLimitStateMachine` (i=9318) with a `CurrentState`/`CurrentState.Id`.
- `pub fn update_value(&self, address_space: &mut AddressSpace, value: f64) -> Option<AlarmEvent>`:
  lock prev, `LimitEvaluator::evaluate`, store new state. Write to the address space: base
  `ActiveState` (active), `Severity`, `Message`, and `Retain` (`active || !acked || !confirmed`,
  matching `transitions.rs`); for exclusive, set `LimitState.CurrentState` + `CurrentState.Id` to the
  state node (HighHigh=9329/High=9331/Low=9333/LowLow=9335) or **null when inactive**. Return the
  `AlarmEvent` describing the new condition state when it changed (None if unchanged), built the same
  way `trigger_alarm_transition` builds its event, so the caller dispatches via the existing
  `dispatch_alarm_event` / `subscriptions.notify_events` path.

**Acceptance:** `cargo build -p async-opcua-server` clean. SCOPE-ESCAPE applies (alarms module only).

---

### Task T3 (codex): NonExclusiveLimitAlarm node + wiring

**Files:** `async-opcua-server/src/alarms/limit.rs`.

- A constructor `LimitAlarm::create_non_exclusive_in_address_space(...)`: base condition +
  `HasTypeDefinition` `NonExclusiveLimitAlarmType` (i=9906); the configured limit + deadband
  properties; the configured `*State` `TwoStateVariable`s (HighHighState=10020/HighState=10029/
  LowState=10038/LowLowState=10047), each with the standard TwoState `Id` + TrueState/FalseState.
- Extend `update_value` (or share its core) so that for a non-exclusive alarm it writes each
  configured `*State` TwoStateVariable from the `NonExclusiveState` booleans, plus base
  ActiveState/Severity/Message/Retain, and returns the event on change.

**Acceptance:** `cargo build -p async-opcua-server` clean. SCOPE-ESCAPE applies.

---

### Task T4 (codex): register_limit_alarm + registry/ack/confirm integration

**Files:** `async-opcua-server/src/namespace/init.rs` (mirror `register_alarm_condition`) +
`async-opcua-server/src/alarms/mod.rs` exports.

- `pub fn register_limit_alarm(address_space, node_manager, device, alarm_name, source_node_id, cfg: LimitConfig) -> LimitAlarm`:
  picks the exclusive vs non-exclusive constructor by `cfg.mode`, creates the node, and returns the
  `LimitAlarm`. Expose `LimitAlarm::condition_state_machine(&self) -> ConditionStateMachine` (clone)
  so the caller can `registry.register(alarm.condition_state_machine())` — that makes Acknowledge
  (i=9111) / Confirm (i=9113) / ConditionRefresh work via the existing
  `register_condition_methods` path with no new code.

**Acceptance:** `cargo build -p async-opcua-server` clean. SCOPE-ESCAPE: if more than init.rs + the
alarms module is needed, stop and report.

---

### Task T5 (codex): demo-server limit-alarm example

**Files:** `samples/demo-server/src/alarms.rs` (extend the existing demo alarm module) + main wiring.

- Add an `ExclusiveLimitAlarmType` on a simulated analog source variable; configure HighHigh/High/
  Low/LowLow with deadbands and escalating severities. On a tokio interval, walk the value through a
  ramp/sine that crosses the limits, call `update_value`, and dispatch the returned event (mirror how
  the existing demo alarm dispatches). Register it in the demo's `ConditionRegistry` (already created
  in the demo) so ack/confirm/refresh work.

**Acceptance:** `cargo build -p async-opcua-demo-server` clean; demo runs. SCOPE-ESCAPE applies.

---

### Task T6 (Claude): independent evaluator vectors + integration tests

**Files:** a new `async-opcua-server` unit-test module for the evaluator (or `#[cfg(test)]` in a
separate test file) + `async-opcua/tests/integration/alarms.rs` for the integration cases. Authored
by Claude, anchored to Part 9 §5.8.18–§5.8.20.

1. **Evaluator vectors (pure):** for both modes, drive a value sequence up through HighHigh and back
   down, and down through LowLow and back; assert the exclusive `CurrentState` escalates/de-escalates
   and the non-exclusive booleans match; assert **deadband hysteresis** — a value crossing a limit
   then retreating within the deadband stays active; clears only past `limit ∓ deadband`.
2. **Integration exclusive:** register an exclusive limit alarm, `update_value` across the bands; a
   subscribed client sees condition events with the right Severity; `LimitState.CurrentState` reads
   the right state; Acknowledge via i=9111 works.
3. **Integration non-exclusive:** the `*State` variables toggle independently.
4. **Refresh:** a late subscriber `ConditionRefresh` replays an active limit alarm.
5. **Edge:** unset limits skipped; NaN no-op; inconsistent `LimitConfig` rejected at build.

**Acceptance:** new tests green; `cargo test -p async-opcua --test integration_tests integration::alarms`
+ `cargo test -p async-opcua-server --lib` green; clippy `-D warnings` clean before PR.

---

## Self-review

- **Spec coverage:** evaluator+deadband (T1), exclusive node (T2), non-exclusive node (T3),
  registration+ack/confirm (T4), demo (T5), tests (T6) — all spec sections mapped.
- **Type consistency:** `LimitConfig`/`LimitDef`/`LimitMode`/`LimitLevel`/`ActiveLimits`/
  `NonExclusiveState`/`LimitOutcome`/`LimitEvaluator::evaluate`/`LimitAlarm`/`update_value`/
  `register_limit_alarm` used identically across tasks.
- **Dependencies:** T2/T3 need T1; T4 needs T2+T3; T5 needs T4; T6 needs all. Order T1→T2→T3→T4→T5,
  then Claude T6.
