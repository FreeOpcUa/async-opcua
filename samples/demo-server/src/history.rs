// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! One historizing variable, backed by an in-memory SQLite history store and seeded with sample
//! values, so HistoryRead returns real data. Used by the interop harness to exercise an actual
//! HistoryRead (not just the rejection path).

use std::sync::Arc;

use opcua::server::address_space::{AccessLevel, VariableBuilder};
use opcua::server::history::HistoryStorageBackend;
use opcua::server::node_manager::memory::SimpleNodeManager;
use opcua::types::*;
use opcua_history_sqlite::SqliteHistoryBackend;

/// Attach the SQLite history backend, add a historizing Double variable, and seed it with 20
/// one-second-spaced samples ending "now". Returns the node id of the historizing variable.
pub async fn add_history(
    manager: Arc<SimpleNodeManager>,
    backend: Arc<SqliteHistoryBackend>,
    ns: u16,
) {
    manager.inner().set_history_backend(backend.clone());

    let node_id = NodeId::new(ns, "HistoricalDouble");
    {
        let address_space = manager.address_space();
        let mut address_space = address_space.write();
        let access = AccessLevel::HISTORY_READ
            | AccessLevel::HISTORY_WRITE
            | AccessLevel::CURRENT_READ
            | AccessLevel::CURRENT_WRITE;
        VariableBuilder::new(&node_id, "HistoricalDouble", "HistoricalDouble")
            .data_type(DataTypeId::Double)
            .historizing(true)
            .value(0.0f64)
            .access_level(access)
            .user_access_level(access)
            .organized_by(NodeId::objects_folder_id())
            .insert(&mut *address_space);
    }

    // Seed historical values so a HistoryRead returns data immediately (no need to wait for sampling).
    let now = DateTime::now();
    let values: Vec<DataValue> = (0..20)
        .map(|i| {
            let ts = DateTime::from(now.ticks() - ((20 - i) as i64) * 10_000_000);
            let mut dv = DataValue::value_only(Variant::from(i as f64));
            dv.source_timestamp = Some(ts);
            dv.server_timestamp = Some(ts);
            dv.status = Some(StatusCode::Good);
            dv
        })
        .collect();

    if let Err(e) = backend
        .update_data(&node_id, PerformUpdateType::Update, values)
        .await
    {
        log::warn!("failed to seed history for {node_id}: {e}");
    }
}
