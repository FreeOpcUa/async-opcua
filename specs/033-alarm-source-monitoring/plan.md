# Implementation Plan: Automatic alarm source monitoring

**Branch**: `033-alarm-source-monitoring` | **Date**: 2026-06-27 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `specs/033-alarm-source-monitoring/spec.md`

## Summary

Bind an alarm to its source Variable (`InputNode`) and have the server auto-re-evaluate + emit the
AlarmEvent on every source Value change, reusing the existing alarm evaluation/dispatch. The
mechanism: (1) an **alarm-source registry** mapping source NodeId → bound alarm handles; (2) in the
node manager's `write` method, collect written alarm-source values during the read-locked loop, then
**after the batch** re-evaluate bound alarms under a fresh **write** lock (since `update_value` needs
`&mut AddressSpace`) and dispatch via `context.subscriptions()`; (3) the **InputNode property +
ConditionSource/HasCondition** references in the address space; (4) a **configuration helper** + a
**`set_source_value`** programmatic entry point; (5) an opt-in **periodic sampling** task for
out-of-band sources.

## Technical Context

**Language/Version**: Rust (workspace edition, async/await)
**Primary Dependencies**: `async-opcua-server` (alarms module, node managers, subscription cache), `async-opcua-core` (`AlarmEvent`), `async-opcua-nodes` (`Event`)
**Storage**: In-memory (address space + in-process registry); no persistence
**Testing**: `cargo test` — unit tests in `async-opcua-server`, integration tests in `async-opcua/tests/integration/alarms.rs`
**Target Platform**: Linux (CI), cross-platform library
**Project Type**: OPC UA server library
**Performance Goals**: Re-evaluation is O(alarms-bound-to-the-written-node) per write; no added cost for writes to non-source nodes. Sampling is opt-in and per-binding.
**Constraints**: No panic on non-numeric/bad/null source values in the write path (network-reachable); builds under `--no-default-features` and `--all-features`; existing manual `update_value` API and behaviour unchanged.
**Scale/Scope**: 5 user stories; ~55–75 atomic tasks.

## Constitution Check

*GATE: must pass before Phase 0; re-checked after Phase 1.*

- **I. Correctness Over Completion** — Auto-evaluation reuses the proven `update_value` (limits/deadband/branch/ack) unchanged, so transition correctness is inherited; tasks assert the full activate/clear/disabled/multi-alarm matrix end-to-end. PASS.
- **II. Do It Right Once** — One alarm-source registry + one write-path hook + one `SourceMonitoredAlarm` trait that Exclusive/NonExclusive/discrete implement; no per-type re-evaluation copy. PASS.
- **III. Individual Task Discipline** — tasks.md keeps one concern per task, each citing the OPC UA Part/§; codex executes one task per dispatch (one PR per user story). PASS.
- **IV. Security Is Paramount** — the write path is network-reachable: the re-evaluation hook must bound work to the bound-alarm set, reject/skip non-numeric/null/bad source values without panic, and never block or fail the underlying Write (an alarm-eval error must not corrupt the write result). PASS (explicit no-panic tasks).
- **V. Leave It Better** — superseding the manual-driving requirement with an automatic loop, while keeping `update_value` public, strictly improves the alarm subsystem. PASS.

No violations → Complexity Tracking omitted.

## Project Structure

### Documentation (this feature)

```text
specs/033-alarm-source-monitoring/
├── plan.md              # This file
├── research.md          # Phase 0 — design decisions (hook point, registry, trait, sampling)
├── data-model.md        # Phase 1 — entities (binding, source index, SourceMonitoredAlarm)
├── quickstart.md        # Phase 1 — declare an alarm that monitors a variable
├── contracts/           # Phase 1 — the SourceMonitoredAlarm trait + write-hook + registry contract
└── tasks.md             # Phase 2 — /speckit-tasks output (atomic, spec-cited)
```

### Source Code (repository root)

```text
async-opcua-server/src/
├── alarms/
│   ├── registry.rs           # ConditionRegistry — ADD source→alarm index (or a sibling AlarmSourceRegistry)
│   ├── source_monitor.rs     # NEW — SourceMonitoredAlarm trait + binding store + re-evaluate/dispatch helper
│   ├── limit.rs              # ExclusiveLimit/NonExclusiveLimit — impl SourceMonitoredAlarm (reuse update_value)
│   ├── discrete.rs           # discrete/off-normal — impl SourceMonitoredAlarm where InputNode applies
│   └── dispatch.rs           # dispatch_alarm_event (reused; ServerAlarmEvent)
└── node_manager/memory/
    ├── simple.rs             # Value-write path → after apply, re-evaluate bound alarms + dispatch via context.subscriptions()
    └── mod.rs (InMemoryNodeManager) # hold/reach the alarm-source registry + the InputNode property wiring

async-opcua/tests/integration/alarms.rs   # e2e: write source → alarm auto-fires (no manual update_value)
async-opcua-server/tests/                  # unit: registry index, value extraction, no-panic edges
samples/demo-server/                        # an alarm wired to a writable source variable (US3/demo)
```

**Structure Decision**: A new `alarms/source_monitor.rs` owns the `SourceMonitoredAlarm` trait and the
binding store; the in-memory node manager holds the registry and hooks its Value-write path (it owns
the address space and intercepts writes). Event dispatch reuses `context.subscriptions().notify_events`
exactly as `dispatch_alarm_event` does today. `update_value` stays the single evaluation entry point.

## Complexity Tracking

No constitution violations — section intentionally empty.
