# Phase 1 Data Model: HistoryUpdate write

## Existing types (reused, not changed)

- **`HistoryUpdateDetails`** (`node_manager/history.rs`) — 6 variants: `UpdateData`,
  `UpdateStructureData`, `UpdateEvent`, `DeleteRawModified`, `DeleteAtTime`, `DeleteEvent`. Has
  `node_id()`, `required_permission()` (RBAC), and `from_extension_object()`.
- **`HistoryUpdateNode`** — per-node update carrier with `details()`, `set_status()`,
  `set_operation_results(Vec<StatusCode>)`.
- **`HistoryUpdateResult`** (types) — `statusCode` + `operationResults[]` + `diagnosticInfos[]`.
- **`PerformUpdateType`** — `Insert | Replace | Update | Remove`.
- Detail payloads (types): `UpdateDataDetails { node_id, perform_insert_replace, update_values:
  Vec<DataValue> }`, `UpdateStructureDataDetails`, `UpdateEventDetails { filter, event_data }`,
  `DeleteRawModifiedDetails { node_id, is_delete_modified, start_time, end_time }`,
  `DeleteAtTimeDetails { node_id, req_times }`, `DeleteEventDetails { node_id, event_ids }`.

## New / extended storage entities

### Historical data entry (raw)
`(node_id, source_timestamp, server_timestamp, value, status_code)`.
- sqlite: existing `historical_data` table (one row per entry).
- in-memory: `BTreeMap<source_ticks i64, DataValue>` per node.
- Key: `(node_id, source_timestamp)` — at most one raw value per timestamp.

### Modified-history entry
A superseded raw entry retained on Replace/Update/Delete:
`(node_id, source_timestamp, value, status_code, update_type, modification_time, modification_user)`.
- `update_type`: the `HistoryUpdateType` that produced it (Insert/Replace/Update/Delete).
- sqlite: new `modified_historical_data` table.
- in-memory: parallel `BTreeMap<source_ticks, Vec<ModifiedEntry>>` per node.
- Read via `read_raw_modified(is_read_modified = true)`.

### Annotation history entry
`(node_id, source_timestamp, annotation)` where `annotation` is an `Annotation` (message, user,
annotation time). One annotation per timestamp; same Insert/Replace/Update/Remove matrix.
- sqlite: extend the annotation store written via `update_structure_data`, read via `read_annotations`.
- in-memory: `BTreeMap<source_ticks, Annotation>` per node.

### Event history entry
`(node_id source, event_id, field_values per EventFilter select clauses)`.
- Keyed by `EventId` (ByteString) for update/delete.
- sqlite: extend the events store written via `update_event`, read via `read_events`.
- in-memory: `InMemoryEventHistory` extended with `update_event`/`delete_event` keyed by EventId.

## Result-shape rules

- `operationResults[]` length == number of entries in the details object (values / req_times /
  event_ids). For range deletes (`DeleteRawModified`) there is no per-entry list — the node
  `statusCode` carries the result (`Good` / `Bad_NoData`).
- The overall request never fails because one node/entry fails; per-node `statusCode` +
  per-entry `operationResults` carry the detail (Part 4 §11.7).
