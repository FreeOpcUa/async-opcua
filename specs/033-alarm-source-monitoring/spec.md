# Feature Specification: Automatic alarm source monitoring

**Feature Branch**: `033-alarm-source-monitoring`
**Created**: 2026-06-27
**Status**: Draft
**Input**: Make alarms self-trigger from their source variable (OPC UA Part 9 §5.8.2 AlarmConditionType.InputNode / §4.4 ConditionSource), instead of requiring the integrator to drive evaluation manually.

## User Scenarios & Testing *(mandatory)*

A "user" here is a server integrator wiring an alarm to a process variable, or an OPC UA client
observing the alarm. Today the limit-alarm types evaluate correctly but only when the integrator
manually calls `update_value(value)`; nothing ties an alarm to a source variable. This feature closes
the loop: bind an alarm to its `InputNode` (a source Variable), and the server automatically
re-evaluates the alarm and emits the AlarmEvent whenever that variable's Value changes.

### User Story 1 - Alarm fires automatically when its source variable crosses a limit (Priority: P1)

An integrator binds a limit alarm to a source Variable and configures its limits. When a value that
exceeds a limit is written to that Variable, the alarm becomes Active and emits the AlarmEvent — with
no manual evaluation call.

**Why this priority**: this is the core value — a working closed loop. Without it the alarm types are
inert until hand-driven; this makes them usable as real alarms.

**Independent Test**: Bind an ExclusiveLimitAlarmType to a source Variable, write a value above the
High limit, and assert the alarm transitions to Active(High) and an AlarmEvent is dispatched — without
calling `update_value` directly.

**Acceptance Scenarios**:

1. **Given** an alarm bound to source Variable V with a High limit, **When** a value above High is written to V, **Then** the alarm becomes Active(High) and an AlarmEvent is emitted automatically.
2. **Given** the alarm is Active(High), **When** a value back within limits (honoring deadband) is written to V, **Then** the alarm returns to Inactive and a clearing AlarmEvent is emitted.
3. **Given** two alarms bound to the same source V, **When** V is written, **Then** both alarms re-evaluate.
4. **Given** a source Variable with no alarm bound, **When** it is written, **Then** nothing happens (no error, no event).
5. **Given** an alarm whose Enabled state is false, **When** its source is written, **Then** the alarm does not re-evaluate or emit.

### User Story 2 - Source binding is browsable in the address space (Priority: P2)

A client browsing an alarm can see which source it monitors: the AlarmConditionType `InputNode`
property resolves to the source Variable, and the source exposes the alarm via the standard
`HasCondition` / ConditionSource references.

**Why this priority**: Part 9 §5.8.2/§4.4 require the binding to be discoverable; clients rely on it
to relate alarms to their source. Independent of the evaluation mechanism.

**Independent Test**: Bind an alarm to a source, then read the alarm's `InputNode` property and browse
the source's conditions, asserting they reference each other.

**Acceptance Scenarios**:

1. **Given** an alarm bound to source V, **When** a client reads the alarm's `InputNode` property, **Then** it returns V's NodeId.
2. **Given** the binding, **When** a client browses V for `HasCondition` references (or ConditionSource), **Then** the bound alarm is reachable.

### User Story 3 - Declarative configuration of the alarm↔source binding (Priority: P2)

An integrator declares "this alarm monitors that variable" once through a builder/helper; the server
sets the InputNode, registers the reverse index, and thereafter handles re-evaluation and event
emission with no further calls.

**Why this priority**: turns the mechanism into an ergonomic API; without it integrators would wire
the binding by hand. Depends on US1/US2 existing.

**Independent Test**: Use the configuration helper to attach an alarm to a source in one call, then
verify writes to the source drive the alarm (US1) and the binding is browsable (US2).

**Acceptance Scenarios**:

1. **Given** the configuration helper, **When** an integrator attaches an alarm to a source Variable, **Then** the InputNode is set, the reverse index is registered, and subsequent source writes drive the alarm.

### User Story 4 - Periodic sampling for sources that change outside the write path (Priority: P3)

For a source whose Value changes without going through the server's Write service (e.g. updated by a
device-facing callback), the integrator can enable a sampling interval; the server polls the InputNode
and re-evaluates the alarm on each tick.

**Why this priority**: write-driven covers client-driven sources; sampling completes coverage for
externally-updated sources per Part 9's continuous-monitoring intent. Lower frequency, opt-in.

**Independent Test**: Bind an alarm with sampling enabled, change the source Value out-of-band, and
assert the alarm re-evaluates within one sampling interval.

**Acceptance Scenarios**:

1. **Given** an alarm with sampling enabled on its source, **When** the source Value changes out-of-band to exceed a limit, **Then** the alarm becomes Active within one sampling interval.
2. **Given** sampling is not enabled, **When** the source changes out-of-band, **Then** the alarm re-evaluates only on the next Write (no sampling overhead).

### User Story 5 - Applies across the alarm types with an InputNode (Priority: P3)

Source monitoring works for ExclusiveLimitAlarmType and NonExclusiveLimitAlarmType, and for the
discrete / off-normal alarm types where an InputNode applies.

**Why this priority**: completeness across the alarm types that have a monitored input; the mechanism
generalizes once US1 exists.

**Independent Test**: Repeat the US1 write-drives-alarm test for NonExclusiveLimitAlarmType and a
discrete alarm.

**Acceptance Scenarios**:

1. **Given** a NonExclusiveLimitAlarmType bound to a source, **When** a value crosses multiple limits, **Then** the corresponding Hi/HiHi/Lo/LoLo states activate automatically.
2. **Given** a discrete/off-normal alarm bound to a source, **When** the source enters its off-normal value, **Then** the alarm activates automatically.

### Edge Cases

- A non-numeric or null value written to a numeric-limit alarm's source is handled without panic (no transition, or an appropriate quality result), never crashing the write path.
- Writing the same in-limits value repeatedly does not emit duplicate events (only state transitions emit).
- A source bound to many alarms re-evaluates all of them deterministically on a single write.
- Removing/disabling the alarm or deleting the source stops auto-evaluation cleanly (no dangling re-eval).
- Write-driven and sampling must not double-emit for the same change within one tick.
- Bad-status or out-of-range source values follow the existing `update_value` handling (this feature only changes *who triggers* evaluation, not the evaluation result).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST let an alarm be bound to a source Variable identified by its NodeId (the AlarmConditionType `InputNode`).
- **FR-002**: When the bound source Variable's Value changes via the server's Write path, the system MUST automatically re-evaluate every alarm bound to that source using the existing limit/discrete evaluation, with no manual call.
- **FR-003**: The system MUST dispatch any AlarmEvent produced by an automatic re-evaluation through the existing event/notification path, exactly as a manual `update_value` would.
- **FR-004**: The system MUST maintain a source→alarm reverse index supporting multiple alarms per source, extending the existing condition registry.
- **FR-005**: The system MUST populate the alarm's `InputNode` property node and the ConditionSource / `HasCondition` references so the binding is browsable (Part 9 §5.8.2 / §4.4).
- **FR-006**: The system MUST provide a configuration/builder helper that attaches an alarm to a source in one declaration (sets InputNode + registers the binding).
- **FR-007**: The system MUST support an opt-in periodic sampling interval that polls a bound source's Value and re-evaluates its alarms, for sources updated outside the Write path.
- **FR-008**: Automatic source monitoring MUST work for ExclusiveLimitAlarmType and NonExclusiveLimitAlarmType, and for the discrete/off-normal alarm types where an InputNode applies.
- **FR-009**: The system MUST reuse the existing alarm evaluation, AlarmEvent dispatch, and condition registry — it MUST NOT reimplement limit/discrete evaluation. The manual `update_value` API MUST remain public and behavior-unchanged (backwards compatible).
- **FR-010**: Automatic re-evaluation MUST respect the alarm's Enabled state — a disabled alarm does not re-evaluate or emit (matching existing `update_value` gating).
- **FR-011**: A programmatic source-value update performed through the provided server-side helper (a `set_source_value`-style call, not via the Write service) MUST also trigger automatic re-evaluation of bound alarms. (Direct, unmediated address-space mutation is out of scope — it bypasses the alarm system by definition; the helper is the intended programmatic entry point.)
- **FR-012**: All changes MUST build and pass under `--no-default-features` and `--all-features`.

### Key Entities *(include if feature involves data)*

- **InputNode binding**: the association `(alarm condition id) → (source Variable NodeId)`; mirrored as the AlarmConditionType InputNode property in the address space.
- **Source→alarm index**: `(source Variable NodeId) → set of alarm condition ids`, used to find which alarms to re-evaluate on a source change (an extension of the existing condition registry).
- **Alarm condition** (existing): the ExclusiveLimitAlarmType / NonExclusiveLimitAlarmType / discrete alarm with its limits, deadband, state machine, and `update_value` evaluation.
- **Sampling configuration** (optional): a per-binding interval governing out-of-band polling.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Writing a value past a configured limit on a bound source causes the alarm to become Active and emit an AlarmEvent with zero manual evaluation calls — verified end-to-end.
- **SC-002**: Writing a value back within limits causes the alarm to return Inactive and emit a clearing event automatically.
- **SC-003**: When multiple alarms are bound to one source, a single source write re-evaluates all of them.
- **SC-004**: Existing manually-driven alarms (no InputNode bound) continue to work with `update_value` unchanged — no regression in the alarm test suite.
- **SC-005**: A disabled alarm does not auto-fire when its source changes.
- **SC-006**: An out-of-band source change is reflected in the alarm within one sampling interval when sampling is enabled, and not until the next write when it is not.
- **SC-007**: The workspace builds and tests pass under `--no-default-features` and `--all-features`, with `clippy` and `fmt` clean.

## Assumptions

- The existing `update_value` evaluation (limits, deadband, severity, branch/ack handling) and the
  AlarmEvent dispatch are correct and are reused unchanged; this feature changes only *what triggers*
  evaluation.
- The primary, always-on trigger is the server Write path (and programmatic value sets); periodic
  sampling is an opt-in addition, since most demo/integration sources change via Write.
- "Source change" means a change to the source Variable's Value attribute; other attribute changes do
  not trigger alarm re-evaluation.
- Re-evaluation runs synchronously in the write path (or on the sampling tick); event dispatch follows
  the existing condition-event mechanism. Concurrency follows the existing alarm/address-space locking.
- Where the discrete alarms' InputNode handling differs from the numeric limit alarms, the numeric
  limit alarms are the primary target; discrete support is included where it generalizes cheaply.

## Spec Traceability

| Requirement | OPC UA reference |
|---|---|
| FR-001 / FR-005 InputNode + references | Part 9 §5.8.2 (AlarmConditionType InputNode); §4.4 (ConditionSource / HasCondition) |
| FR-002 / FR-003 auto re-evaluate + emit | Part 9 §5.5–5.8 (condition evaluation + event reporting) |
| FR-007 sampling | Part 9 §4.4 (continuous source monitoring intent) |
| FR-008 alarm types | Part 9 §5.8.2 (ExclusiveLimit/NonExclusiveLimit); §5.8.3 (discrete/off-normal) |
| FR-010 enabled gating | Part 9 §5.5.2 (Enabled state) |
