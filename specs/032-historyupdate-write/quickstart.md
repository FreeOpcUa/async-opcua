# Quickstart: HistoryUpdate write

## Server: enable history on a variable (default in-memory store)

Attach an `InMemoryDataHistory` backend to a node manager's historized variable. Once attached,
HistoryRead (raw + modified) and all HistoryUpdate operations work with no external database.

```rust ignore
use opcua::server::history::InMemoryDataHistory;

// Register the in-memory data-history backend for a historized variable.
let history = InMemoryDataHistory::new();
// ... wire `history` into the node manager's history dispatch for `var_id`
```

## Client: write and read back

```rust ignore
use opcua::types::{
    HistoryUpdateDetails, UpdateDataDetails, PerformUpdateType, DataValue, DateTime,
};

// Insert two values into history.
session.history_update(&[HistoryUpdateDetails::UpdateData(UpdateDataDetails {
    node_id: var_id.clone(),
    perform_insert_replace: PerformUpdateType::Insert,
    update_values: Some(vec![
        DataValue::new_at(1.0f64, t0),
        DataValue::new_at(2.0f64, t1),
    ]),
})]).await?;   // per-value results: [Good_EntryInserted, Good_EntryInserted]

// Replace the value at t0.
session.history_update(&[HistoryUpdateDetails::UpdateData(UpdateDataDetails {
    node_id: var_id.clone(),
    perform_insert_replace: PerformUpdateType::Replace,
    update_values: Some(vec![DataValue::new_at(9.0f64, t0)]),
})]).await?;   // [Good_EntryReplaced]

// Read raw — returns the current values; read modified — returns the superseded 1.0 at t0.
```

## Delete

```rust ignore
// Delete a time range.
HistoryUpdateDetails::DeleteRawModified(DeleteRawModifiedDetails {
    node_id, is_delete_modified: false, start_time: t0, end_time: t_end,
});  // Good, or Bad_NoData if the range is empty

// Delete specific timestamps.
HistoryUpdateDetails::DeleteAtTime(DeleteAtTimeDetails {
    node_id, req_times: Some(vec![t0, t_absent]),
});  // [Good, Bad_NoEntryExists]
```

## Verify

- HistoryRead raw returns live values; HistoryRead modified (`isReadModified`) returns superseded
  values tagged with their update type.
- A session lacking `InsertHistory` / `ModifyHistory` / `DeleteHistory` is denied (existing RBAC).
- A node manager with no history backend returns `Bad_HistoryOperationUnsupported`.
