# Contract: extended `HistoryStorageBackend` + HistoryUpdate dispatch

## Extended trait (`async-opcua-server/src/history/backend.rs`)

Add these `async` methods to `HistoryStorageBackend`, each with a default body returning
`Err(StatusCode::BadHistoryOperationUnsupported)` (backwards compatible — FR-011). Signatures are
illustrative; final argument types follow the existing detail structs.

```text
async fn update_data(node_id, perform: PerformUpdateType, values: Vec<DataValue>)
    -> Result<Vec<StatusCode>, StatusCode>;                       // EXISTS — extend with Remove mode

async fn update_structure_data(node_id, perform: PerformUpdateType, values: Vec<DataValue>)
    -> Result<Vec<StatusCode>, StatusCode>;                       // NEW — annotations

async fn update_event(node_id, filter: &EventFilter, events: Vec<HistoryEventFieldList>,
                      perform: PerformUpdateType)
    -> Result<Vec<StatusCode>, StatusCode>;                       // NEW

async fn delete_raw_modified(node_id, is_delete_modified: bool, start: DateTime, end: DateTime)
    -> Result<StatusCode, StatusCode>;                            // NEW — operation-level result

async fn delete_at_time(node_id, req_times: Vec<DateTime>)
    -> Result<Vec<StatusCode>, StatusCode>;                       // NEW — per-timestamp

async fn delete_event(node_id, event_ids: Vec<ByteString>)
    -> Result<Vec<StatusCode>, StatusCode>;                       // NEW — per-id
```

## Dispatch contract (`node_manager/history.rs` / the in-memory manager `history_update`)

For each `HistoryUpdateNode`:
1. Match `node.details()` to the corresponding backend method.
2. Call the backend; on `Ok(Vec<StatusCode>)` → `set_operation_results(Some(results))` and node
   `statusCode = Good`. On `Ok(StatusCode)` (range delete) → set node `statusCode`. On
   `Err(code)` → node `statusCode = code` (e.g. `Bad_HistoryOperationUnsupported` for an unhistorized
   node).
3. RBAC: the existing `required_permission()` gate runs before dispatch — unchanged.

## Result-code contract (Part 4 §11.7 / Part 11 §6)

| Method | Per-entry / operation result |
|---|---|
| `update_data(Insert)` | `Good_EntryInserted` if absent, else `Bad_EntryExists` |
| `update_data(Replace)` | `Good_EntryReplaced` if present, else `Bad_NoEntryExists` |
| `update_data(Update)` | `Good_EntryInserted` (new) or `Good_EntryReplaced` (overwrite) |
| `update_data(Remove)` | `Good` if present, else `Bad_NoEntryExists` |
| `update_structure_data(*)` | same matrix as `update_data`, on the annotation store |
| `update_event(*)` | same Insert/Replace/Update matrix, keyed by EventId |
| `delete_raw_modified` | operation `Good` if range non-empty, else `Bad_NoData` |
| `delete_at_time` | per timestamp `Good` / `Bad_NoEntryExists` |
| `delete_event` | per id `Good` / `Bad_NoEntryExists` |

## Modified-history contract

Any `Replace`, `Update` over an existing value, or any `Delete` (raw) MUST append a modified-history
entry capturing the superseded value + `HistoryUpdateType` + modification time/user.
`read_raw_modified(is_read_modified = true)` MUST return modified entries; with `false`, only live raw
values. (Part 11 §6.5.)

`read_raw_modified` is extended to return a parallel `Vec<ModificationInfo>` alongside the
`Vec<DataValue>` (today it returns only DataValues and the read dispatch hardcodes
`HistoryModifiedData.modification_infos = None`). The read dispatch MUST populate
`HistoryModifiedData.modification_infos` from this vector. `ModificationInfo { modification_time,
update_type, user_name }` and `HistoryUpdateType` already exist in `async-opcua-types`.

## Invariants

- No handler panics on empty value/timestamp/event-id arrays or `start > end`; each returns the
  appropriate status.
- `operationResults` length equals the input entry count for the per-entry operations.
- Backends without an override return `Bad_HistoryOperationUnsupported` (unchanged behaviour).
