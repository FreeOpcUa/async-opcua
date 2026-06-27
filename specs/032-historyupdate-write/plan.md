# Implementation Plan: Historical Access write — full HistoryUpdate service

**Branch**: `032-historyupdate-write` | **Date**: 2026-06-27 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `specs/032-historyupdate-write/spec.md`

## Summary

Complete the OPC UA Part 11 HistoryUpdate write surface behind the existing dispatch/RBAC framework.
The protocol layer (`HistoryUpdateDetails`, per-node dispatch, `required_permission()` gating,
`HistoryUpdateNode` result API) already exists. The work is: (1) **extend the `HistoryStorageBackend`
trait** (`async-opcua-server/src/history/backend.rs`) with the five missing write operations as
default-`Bad_HistoryOperationUnsupported` methods (preserving backwards compatibility); (2) **wire the
node-manager `history_update` dispatch** to call them per `HistoryUpdateDetails` variant and size
`operationResults[]`; (3) **build a new in-memory historical-data backend** mirroring
`InMemoryEventHistory`; (4) **complete the `async-opcua-history-sqlite` backend** for all six
operations plus modified-history tracking; (5) **wire end-to-end** (server example + client coverage).

## Technical Context

**Language/Version**: Rust (workspace edition, async/await, `async-trait`)
**Primary Dependencies**: `async-opcua-server` (history module + node managers), `async-opcua-history-sqlite` (rusqlite reference backend), `async-opcua-types` (HistoryUpdate detail/result types), `async-opcua` (client `history_update`)
**Storage**: SQLite (reference persistence backend) + a new in-process in-memory store (default path)
**Testing**: `cargo test` — unit tests in each crate, integration tests in `async-opcua/tests/integration`, sqlite-backend tests in `async-opcua-history-sqlite`
**Target Platform**: Linux (CI), cross-platform library
**Project Type**: Protocol library (OPC UA server + history backends)
**Performance Goals**: No regression; HistoryUpdate is a low-frequency administrative service. In-memory store O(log n) insert/lookup by timestamp; sqlite indexed by `(node_id, source_timestamp)`.
**Constraints**: Must build/test under `--no-default-features` and `--all-features`; no panics on attacker-influenced input (empty arrays, inverted ranges); per-entry results, never whole-request failure.
**Scale/Scope**: 6 HistoryUpdate operations × 2 backends + modified-history + e2e wiring; ~120–150 tasks across 7 user stories.

## Constitution Check

*GATE: must pass before Phase 0; re-checked after Phase 1.*

- **I. Correctness Over Completion** — Each operation's full result-code matrix (Insert/Replace/Update/Remove, Bad_EntryExists/Bad_NoEntryExists/Bad_NoData) is specified and tested; no operation reported done while a result-code case is wrong. PASS.
- **II. Do It Right Once** — Extend the shared `HistoryStorageBackend` trait once; both backends implement the same contract; the in-memory store and sqlite backend behave identically for spec-defined cases. No parallel ad-hoc paths. PASS.
- **III. Individual Task Discipline** — tasks.md keeps one operation/mode/backend per task; codex executes one task per dispatch (one PR per user story). PASS.
- **IV. Security Is Paramount** — HistoryUpdate is network-reachable: all handlers bound allocations to the request's entry count, reject malformed input (inverted ranges, empty lists) with a status code, and never panic. RBAC history-permission gating is unchanged (fail-closed, already enforced). PASS.
- **V. Leave It Better** — superseding the `Bad_HistoryOperationUnsupported` stubs with real implementations + tests strictly improves the touched code. PASS.

No violations → Complexity Tracking omitted.

## Project Structure

### Documentation (this feature)

```text
specs/032-historyupdate-write/
├── plan.md              # This file
├── research.md          # Phase 0 — decisions (trait extension, modified-history model, key design)
├── data-model.md        # Phase 1 — entities (data/modified/annotation/event entries, result shape)
├── quickstart.md        # Phase 1 — end-to-end HistoryUpdate usage
├── contracts/           # Phase 1 — the extended HistoryStorageBackend trait contract + result semantics
└── tasks.md             # Phase 2 — /speckit-tasks output
```

### Source Code (repository root)

```text
async-opcua-server/src/
├── history/
│   ├── backend.rs            # HistoryStorageBackend trait — ADD update_structure_data/update_event/
│   │                         #   delete_raw_modified/delete_at_time/delete_event (default Unsupported);
│   │                         #   EXTEND read_raw_modified to also return Vec<ModificationInfo> (T007a)
│   ├── read.rs               # populate HistoryModifiedData.modification_infos (was hardcoded None)
│   ├── event_history.rs      # InMemoryEventHistory — ADD update_event/delete_event impls
│   ├── data_history.rs       # NEW — InMemoryDataHistory: read_raw_modified + all update/delete + modified-history
│   └── mod.rs                # re-exports
├── node_manager/
│   ├── history.rs            # HistoryUpdateDetails dispatch → new backend methods; size operationResults
│   └── mod.rs                # trait default history_update stays Bad_HistoryOperationUnsupported
└── ...

async-opcua-history-sqlite/src/
└── backend.rs                # update_data Remove mode; update_structure_data (annotations); update_event;
                              # delete_raw_modified; delete_at_time; delete_event; modified_history table

async-opcua/tests/integration/
└── history_update.rs         # NEW — e2e per-operation tests (default in-memory path)

async-opcua-history-sqlite/   # backend unit/integration tests for each operation
samples/demo-server/          # historized variable + event source accepting HistoryUpdate (US7)
```

**Structure Decision**: The shared `HistoryStorageBackend` trait in `async-opcua-server/src/history/backend.rs`
is the single contract. Extending it once (with default-`Unsupported` methods) keeps backwards
compatibility (FR-011) and lets the dispatch in `node_manager/history.rs` call uniformly. Two backends
implement it: the new `InMemoryDataHistory` (default path, US2) and the sqlite reference backend.

## Complexity Tracking

No constitution violations — section intentionally empty.
