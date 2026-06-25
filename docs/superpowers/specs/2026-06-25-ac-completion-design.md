# A&C Completion (DiscreteAlarm · Shelving/Suppression · Branching · AnalogItem) — Design

Date: 2026-06-25
Status: approved (scope "Full AC1–AC4" chosen by user)

## Purpose

Finish the Part-9 Alarms & Conditions surface on top of the existing foundation
(`ConditionStateMachine`, `LimitAlarm`/`LimitEvaluator`, `ConditionRegistry`, ack/confirm methods,
ConditionRefresh from PRs #138/#139). Four phases, each a green PR; codex implements, Claude authors
oracle tests, every behavior grounded via the `opc-ua-reference` MCP and pasted into the codex brief
(codex does not call the MCP).

## Existing foundation (compose on this)

- `alarms/state_machine.rs::ConditionStateMachine` — condition lifecycle (EventId, AckedState,
  ConfirmedState, Retain) in the address space + `create_in_address_space`.
- `alarms/limit.rs::LimitAlarm` — Exclusive/NonExclusive limit alarms: `create_*_in_address_space`
  builds the ConditionStateMachine + the alarm-type instance + its state machine/variables;
  `LimitEvaluator::evaluate(value, cfg, prev) -> LimitOutcome`; `update_value(address_space, value) ->
  Option<AlarmEvent>`.
- `namespace/init.rs::register_limit_alarm` — wires an alarm into the address space + exposes the
  shared Acknowledge/Confirm methods.
- `alarms/dispatch.rs`, `refresh_events.rs`, `registry.rs`, `transitions.rs`, `methods.rs`.

## Phases

### AC1 — DiscreteAlarm / OffNormalAlarm (+ TripAlarm)
Discrete-state alarms: active when the monitored value deviates from a configured normal state.
- `DiscreteAlarm` (alarms module) paralleling `LimitAlarm`: `create_offnormal_in_address_space(...)`
  builds a `ConditionStateMachine` + an OffNormalAlarmType (i=10637) instance with the `NormalState`
  property; `update_value` sets Active when `value != normal` and emits the `AlarmEvent`.
- DiscreteAlarmType i=10523 (abstract base); OffNormalAlarmType i=10637; TripAlarmType (OffNormal
  subtype) is the same mechanics with its own type id.
- `register_offnormal_alarm` in init.rs (+ Ack/Confirm methods, like the limit alarms).

### AC2 — ShelvedStateMachine + Suppression
The alarm-management layer on AlarmConditionType.
- `ShelvedStateMachineType` (§5.8.17): Unshelved / OneShotShelved / TimedShelved states + the
  `Shelve` / `OneShotShelve` / `TimedShelve` / `Unshelve` methods (TimedShelve takes a duration;
  auto-returns to Unshelved on expiry). Materialize the ShelvingState sub-state-machine on the alarm.
- Server-driven `SuppressedState` + `OutOfServiceState`, and the computed `SuppressedOrShelved`
  flag that gates whether the alarm is reported.
- New methods registered like Ack/Confirm; the state machine in the address space + a Rust-side model.

### AC3 — Condition branching (Part 9 §5.5.x) — the hard one
A condition can have multiple concurrent **branches** (prior unacknowledged states kept alive while a
new state arises). 
- A `BranchId` per branch; the current state is `BranchId = null`. Each branch carries its own
  AckedState/ConfirmedState/Retain and is independently acknowledgeable by `(ConditionId, EventId)`.
- ConditionRefresh must replay all retained branches (not just the current condition).
- Acknowledge/Confirm routed to the correct branch by EventId.
- Extends `ConditionStateMachine`/the registry to hold branches; the event model emits branch events.

### AC4 — AnalogItem / EURange integration
Limit alarms source their range/engineering units from an `AnalogItemType` (EURange property) instead
of hard-coded config, and clamp/validate limits against EURange.

## Testing (Claude authors, independent)

Per phase, integration tests over a running server (mirroring `tests/integration/alarms.rs`):
- AC1: an OffNormal alarm goes Active when value ≠ normal and Inactive when it returns; Ack/Confirm
  + ConditionRefresh deliver it; event carries the right type + ActiveState.
- AC2: Shelve/OneShotShelve/TimedShelve/Unshelve transitions + timed auto-unshelve; SuppressedOrShelved
  gating; the methods return the right status codes (BadConditionAlreadyShelved, etc.).
- AC3: a condition with two branches — both retained, each independently acknowledgeable by EventId,
  both replayed by ConditionRefresh; acking one branch doesn't ack the other.
- AC4: a limit alarm picks up limits from an AnalogItem EURange.

## Provenance
Part 9 §5.8.24 (Discrete/OffNormal), §5.8.17 (ShelvedStateMachine), §5.8.x (Suppressed/OutOfService),
§5.5.x (branching) grounded via the `opc-ua-reference` MCP 2026-06-25. NodeIds from the vendored
nodeset. Builds on [[feature-ac-subscriber-conditionrefresh]] + [[feature-process-limit-alarms]].
