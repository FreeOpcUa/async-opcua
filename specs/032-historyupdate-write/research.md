# Phase 0 Research: HistoryUpdate write

## D1 — Extend `HistoryStorageBackend`, don't add a new trait

**Decision**: Add the five missing write operations to the existing
`async-opcua-server/src/history/backend.rs::HistoryStorageBackend` trait as `async` methods with a
default body returning `Bad_HistoryOperationUnsupported`:
`update_structure_data`, `update_event`, `delete_raw_modified`, `delete_at_time`, `delete_event`
(`update_data` already exists). 

**Rationale**: backends already implement this trait; default-`Unsupported` methods preserve
backwards compatibility (FR-011 — a backend that overrides nothing still reports unsupported), and the
`node_manager/history.rs` dispatch can call one uniform contract. Adding a parallel trait would
fragment the dispatch and violate Constitution II.

**Alternatives rejected**: separate `HistoryWriteBackend` trait (fragments dispatch); per-backend
ad-hoc methods (no shared contract).

## D2 — Modified-history model

**Decision**: On Replace, Update-over-existing, and any Delete, retain the superseded raw entry as a
*modified* entry carrying its `HistoryUpdateType` (Insert/Replace/Update/Delete) and modification
metadata (server time of the update + requesting user). `read_raw_modified(is_read_modified=true)`
returns these instead of the live raw values (Part 11 §6.5).
- sqlite: a `modified_historical_data` table parallel to `historical_data`, keyed by
  `(node_id, source_timestamp, modification_time)` with an `update_type` column.
- in-memory: a parallel `BTreeMap` of superseded entries per node.

**Rationale**: matches the spec's modified-values semantics and the existing `read_raw_modified`
signature which already takes the modified flag. Keeping modified entries separate avoids polluting raw
reads.

**Alternatives rejected**: in-place versioning column (complicates raw reads/deletes); no modified
tracking (fails FR-006 / Part 11 §6.5).

## D3 — In-memory data store mirrors `InMemoryEventHistory`

**Decision**: New `InMemoryDataHistory` in `async-opcua-server/src/history/data_history.rs`: a
`Mutex`/`RwLock`-guarded `HashMap<NodeId, BTreeMap<i64 source-ticks, DataValue>>` for raw values plus a
parallel structure for modified entries, with an optional bounded capacity per node. Implements
`HistoryStorageBackend` (`read_raw_modified` + all update/delete methods).

**Rationale**: directly parallels the shipped `InMemoryEventHistory` (same module, same trait), so the
default `InMemoryNodeManager`/`SimpleNodeManager` can offer history with no external DB (FR-009). The
`BTreeMap` keyed by source-timestamp ticks gives ordered reads and O(log n) point ops.

## D4 — Result sizing and overall status

**Decision**: For each `HistoryUpdateDetails` object the handler returns a `Vec<StatusCode>` sized to
its entry count (values / timestamps / event-ids), set into `HistoryUpdateNode` via
`set_operation_results`; the node's overall `statusCode` is `Good` when the operation ran (even if
individual entries failed), except where the spec makes the operation itself fail (`DeleteRawModified`
with an empty range → operation `Bad_NoData`). Follows Part 4 §11.7 result tables.

## D5 — Per-operation result-code matrix (Part 4 §11.7 / Part 11 §6)

| Operation | Mode / case | Result |
|---|---|---|
| UpdateData | Insert, no existing entry | `Good_EntryInserted` |
| UpdateData | Insert, entry exists | `Bad_EntryExists` |
| UpdateData | Replace, entry exists | `Good_EntryReplaced` |
| UpdateData | Replace, no entry | `Bad_NoEntryExists` |
| UpdateData | Update, no entry | `Good_EntryInserted` |
| UpdateData | Update, entry exists | `Good_EntryReplaced` |
| UpdateData | Remove, entry exists | `Good` |
| UpdateData | Remove, no entry | `Bad_NoEntryExists` |
| DeleteRawModified | range non-empty | `Good` (operation) |
| DeleteRawModified | range empty | `Bad_NoData` (operation) |
| DeleteAtTime | per timestamp present | `Good` |
| DeleteAtTime | per timestamp absent | `Bad_NoEntryExists` |
| DeleteEvent | per id present | `Good` |
| DeleteEvent | per id absent | `Bad_NoEntryExists` |
| UpdateStructureData / UpdateEvent | same Insert/Replace/Update matrix as UpdateData | as above |

## D6 — Event-history write keying

**Decision**: Events are keyed by their `EventId` (ByteString) for `UpdateEvent`/`DeleteEvent`; on
`UpdateEvent` the event fields are stored per the supplied `EventFilter`'s select clauses (matching
the existing `read_events` field-list shape). `DeleteEvent` removes by `EventId` list with per-id
results. Reuse the event field/filter handling already used by `InMemoryEventHistory::read_events` and
the sqlite `read_events`/`read_annotations` paths.

## D7 — Annotations

**Decision**: `UpdateStructureData` whose entries are `Annotation`-valued `DataValue`s are stored in
the annotation store keyed by source timestamp, returned by the existing `read_annotations` path. Same
Insert/Replace/Update/Remove matrix as UpdateData.

## D9 — `read_raw_modified` must carry `ModificationInfo` (gap found in analyze)

**Decision**: Extend `HistoryStorageBackend::read_raw_modified` to return a parallel
`Vec<ModificationInfo>` alongside the `Vec<DataValue>` (e.g. `-> (Vec<DataValue>, Vec<ModificationInfo>,
Option<Vec<u8>>)`). Today it returns only `(Vec<DataValue>, Option<Vec<u8>>)`, and the read dispatch
hardcodes `HistoryModifiedData { modification_infos: None }` (`node_manager/memory/simple.rs`,
`memory_mgr_impl.rs`) — so a HistoryReadModified can never return the update type / modification
metadata Part 11 §6.5 requires. `ModificationInfo { modification_time, update_type:
HistoryUpdateType, user_name }` and `HistoryUpdateType` already exist in `async-opcua-types`; reuse
them.

**Rationale**: this is a prerequisite for FR-006 / US4. Changing the shared trait signature is a
foundational change so US1/US2 implementors adopt the final signature once (Constitution II — no
rework). Existing implementors return an empty `ModificationInfo` vec until US4 populates it.

**Alternatives rejected**: a separate `read_modified` method (duplicates range/continuation logic);
leaving `modification_infos: None` (fails Part 11 §6.5 — modified reads would omit update type/user).

## D8 — Backwards compatibility & feature gating

**Decision**: The node-manager trait default `history_update` stays `Bad_HistoryOperationUnsupported`
(FR-011). The in-memory store lives in `async-opcua-server` (always built); the sqlite work stays in
`async-opcua-history-sqlite`. All new code builds under `--no-default-features` and `--all-features`.
