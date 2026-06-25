# Process Limit Alarms (Exclusive + NonExclusive, with deadband) — Design

Date: 2026-06-25
Status: approved (brainstorm); approach B confirmed

## Purpose

Add the analog **limit alarm** types a process DCS/PLC actually configures — Hi / HiHi / Lo / LoLo —
on top of the existing A&C lifecycle. Today async-opcua only has the generic `AlarmConditionType`
(active/inactive, driven manually). This slice adds **ExclusiveLimitAlarmType** (one active limit at a
time, the classic escalating analog alarm) and **NonExclusiveLimitAlarmType** (independent limit
states), each driven automatically from a monitored value compared against optional limits, with
**deadband (hysteresis)** to prevent alarm chatter.

This composes the previous A&C subscriber slice (see
`2026-06-24-ac-subscriber-conditionrefresh-design.md`): limit alarms reuse the condition lifecycle
(ActiveState/Acked/Confirmed/Retain/Severity/Message), the standard Acknowledge/Confirm methods
(i=9111/i=9113), ConditionRefresh, and event dispatch — they only add the *evaluation layer* that
decides when the condition is active and at what severity.

## Scope

**In scope**
- `ExclusiveLimitAlarmType` (i=9341) instances with a `LimitState` `ExclusiveLimitStateMachine`
  (i=9318) exposing `CurrentState` ∈ {HighHigh, High, Low, LowLow} or inactive.
- `NonExclusiveLimitAlarmType` (i=9906) instances with independent `HighHighState`/`HighState`/
  `LowState`/`LowLowState` `TwoStateVariable`s.
- The four optional limit properties + the four optional deadband properties (Part 9 §5.8.18).
- A pure evaluation engine (value + limits + deadbands + previous state → active limit state(s) +
  severity), with deadband hysteresis.
- A server-side `update_value(value)` driver (the app calls it on each new source value) that writes
  the resulting state into the address space and dispatches the condition event.
- A `register_limit_alarm` helper + ConditionRegistry / Acknowledge / Confirm integration.
- A demo-server example (a simulated analog value crossing limits) + independent integration tests.

**Out of scope** (later / not needed now)
- Automatic monitoring of a source variable (the app drives `update_value`, matching the existing
  `trigger_alarm_transition` model). No sampling/subscription wiring inside the alarm.
- AnalogItem/EURange integration, adaptive `Base*Limit` limits, ShelvedState/suppression/silence,
  rate-of-change / DiscreteAlarm types, condition Branches.

## Verified NodeIds (from `async-opcua-types/src/generated/node_ids.rs`)

| Symbol | Id | | Symbol | Id |
|---|---|---|---|---|
| LimitAlarmType | 2955 | | ExclusiveLimitStateMachineType | 9318 |
| ExclusiveLimitAlarmType | 9341 | | NonExclusiveLimitAlarmType | 9906 |
| LimitAlarmType_HighHighLimit | 11124 | | …_HighLimit / _LowLimit / _LowLowLimit | 11125 / 11126 / 11127 |
| LimitAlarmType_HighHighDeadband | 24774 | | …_HighDeadband / _LowDeadband / _LowLowDeadband | 24775 / 24776 / 24777 |
| ExclusiveLimitStateMachineType_HighHigh | 9329 | | …_High / _Low / _LowLow | 9331 / 9333 / 9335 |
| ExclusiveLimitAlarmType_LimitState | 9455 | | NonExclusive…_HighHighState/HighState/LowState/LowLowState | 10020 / 10029 / 10038 / 10047 |

## Architecture (approach B — a `LimitAlarm` layer that composes `ConditionStateMachine`)

```
update_value(v)
   └─ LimitEvaluator::evaluate(v, &limits, &deadbands, prev) -> LimitOutcome
        ▼
   write to AddressSpace:
     - Exclusive:    LimitState.CurrentState = HighHigh|High|Low|LowLow|<inactive>
     - NonExclusive: HighHighState/HighState/LowState/LowLowState (each TwoState)
     - base: ConditionStateMachine.set_active(any_limit_active), Severity, Message, Retain
        ▼
   dispatch ServerAlarmEvent (reuses existing alarms/dispatch.rs)
```

The existing `ConditionStateMachine` provides the lifecycle; a new `LimitAlarm` owns a
`ConditionStateMachine` plus the limit configuration and the limit-specific nodes, and drives the
former from the evaluation result. Acknowledge/Confirm/ConditionRefresh need no new work — a limit
alarm is registered in the `ConditionRegistry` and exposes i=9111/i=9113 like any condition.

## Components (one responsibility each)

1. **`LimitConfig`** — the four optional limits, four optional deadbands, and per-limit severity
   (e.g. `LimitLevel -> u16`, defaulting to an escalating map: LowLow/HighHigh > Low/High).
2. **`LimitEvaluator`** (pure, no address space; the heart of the slice) —
   `evaluate(value: f64, cfg: &LimitConfig, prev: LimitState) -> LimitOutcome`.
   - **Exclusive**: returns the single most-severe latched band. Entry threshold = the limit value;
     exit (toward normal) = limit ∓ deadband (high limits clear below `limit - deadband`, low limits
     clear above `limit + deadband`). Severity order HighHigh ≻ High and LowLow ≻ Low.
   - **NonExclusive**: returns the boolean of each configured limit independently, each with its own
     deadband hysteresis.
   - `LimitOutcome` carries: active (bool), the exclusive `CurrentState` (or per-limit booleans),
     the effective severity, and a message string.
   - Edge cases: unset limits are skipped; `NaN` value → no change (return `prev`); limits asserted
     consistent (HighHigh ≥ High ≥ Low ≥ LowLow when present) — inconsistent config is a
     construction-time error, not a runtime panic.
3. **Typed node creation** — extend the alarms namespace builder to create, in the address space:
   - **Exclusive**: an `ExclusiveLimitAlarmType` (i=9341) instance + a `LimitState` component of
     `ExclusiveLimitStateMachine` (i=9318) with `CurrentState`/`CurrentState.Id`; the configured
     limit + deadband properties. The state machine has only the four states (HighHigh/High/Low/LowLow)
     — when the alarm is **inactive**, `CurrentState`/`CurrentState.Id` is null (no sub-state) and the
     base `ActiveState.Id` is false; an active alarm sets both `ActiveState` and the `CurrentState`.
   - **NonExclusive**: a `NonExclusiveLimitAlarmType` (i=9906) instance + the configured
     `*State` `TwoStateVariable`s; the limit + deadband properties.
   - Both also get the base condition state vars (reuse `ConditionStateMachine::create_in_address_space`).
4. **`LimitAlarm::update_value(&self, address_space, value)`** — runs the evaluator against the prior
   state, writes the outcome (LimitState/CurrentState or the TwoStateVars; ActiveState; Severity;
   Message; Retain), and dispatches the condition event via the existing `dispatch_alarm_event`.
5. **`register_limit_alarm(...)`** — mirrors `register_alarm_condition`: creates the typed node from a
   `LimitConfig`, returns the `LimitAlarm` (which embeds a `ConditionStateMachine`), and is added to a
   `ConditionRegistry` by the caller so Acknowledge/Confirm/ConditionRefresh work unchanged.

## Deadband semantics (Part 9 §5.8.18)

A high limit L with deadband d: active once `value > L`; clears once `value < L - d`.
A low limit L with deadband d: active once `value < L`; clears once `value > L + d`.
`d = 0` (or unset) → plain threshold crossing. The hysteresis state is the previous `LimitState`
passed into `evaluate`, so the engine is a pure function of (value, config, prev) — fully testable
with crossing vectors, no address space.

## Severity & message

Each active limit maps to a Severity (configurable; sensible escalating default). Exclusive: the
Severity is the active band's. NonExclusive: the highest active limit's Severity. Message is a short
human string naming the limit (e.g. "High High limit exceeded"). These feed the existing event
fields, so the A&C subscriber slice's client parsing/refresh shows limit alarms with correct severity.

## Error handling

- Inconsistent limit ordering or a deadband larger than the gap between adjacent limits → error at
  `LimitConfig` construction (`Result`), never a runtime panic.
- No limits configured → a valid but never-active alarm.
- `NaN`/non-finite value → state unchanged (treated as "no new sample").
- All address-space writes go through the same locked path the existing condition transitions use.

## Testing (Claude authors, independent; anchored to Part 9 §5.8.18–§5.8.20)

1. **Evaluator unit vectors** (pure, no server): ramps and steps through the bands for both modes —
   assert the exclusive `CurrentState` escalates/de-escalates correctly and the non-exclusive booleans
   match; assert **deadband hysteresis** (a value that crosses a limit then retreats within the
   deadband stays active; clears only past `limit ∓ deadband`).
2. **Integration — exclusive**: register an `ExclusiveLimitAlarmType`, drive `update_value` across
   HighHigh/High/normal/Low/LowLow; a subscribed client sees the condition events with the right
   Severity, and `LimitState.CurrentState` reads the right state; Acknowledge via i=9111 works.
3. **Integration — non-exclusive**: independent `*State` variables toggle as expected.
4. **Integration — refresh**: a late subscriber `ConditionRefresh` replays an active limit alarm
   (reuses the prior slice).
5. **Edge**: unset limits skipped; NaN no-op; inconsistent config rejected at construction.

## Implementation split

Per project workflow: **codex implements** the evaluator, typed-node creation, `update_value`,
`register_limit_alarm`, and the demo (feature code); **Claude authors/validates** the independent
evaluator vectors + integration tests. One concern per codex dispatch; each brief carries the
scope-escape rule (if it must reach outside the stated files, stop and return a summary). No-git
guardrail; branch verified after each.

## Decomposition (→ implementation plan)

- T1 (codex): `LimitConfig` + `LimitEvaluator` (pure logic + deadband; both modes).
- T2 (codex): ExclusiveLimitAlarm node creation (i=9341 + LimitState/i=9318) + `update_value` wiring.
- T3 (codex): NonExclusiveLimitAlarm node creation (i=9906 + `*State` TwoStateVars) + wiring.
- T4 (codex): `register_limit_alarm` + ConditionRegistry / Acknowledge / Confirm integration.
- T5 (codex): demo-server simulated analog value crossing limits.
- T6 (Claude): independent evaluator vectors + integration tests.
