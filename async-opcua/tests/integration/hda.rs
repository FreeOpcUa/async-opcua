use std::{sync::Arc, time::Duration};

use crate::utils::{default_server, Tester};
use opcua::{
    server::{
        address_space::{AccessLevel, VariableBuilder},
        node_manager::memory::{simple_node_manager, SimpleNodeManager},
    },
    types::{DataTypeId, DataValue, DateTime, NodeId, PerformUpdateType, StatusCode, Variant},
};
use opcua_history_sqlite::SqliteHistoryBackend;
use tokio::time::timeout;

pub async fn setup_hda() -> (
    Tester,
    Arc<SimpleNodeManager>,
    Arc<opcua_client::Session>,
    Arc<SqliteHistoryBackend>,
) {
    let namespace = opcua::server::diagnostics::NamespaceMetadata {
        namespace_uri: "urn:rustopcuatestserver".to_owned(),
        namespace_index: 2,
        ..Default::default()
    };
    let simple_mgr = simple_node_manager(namespace, "test");
    let server = default_server().with_node_manager(simple_mgr);
    let mut tester = Tester::new(server, false).await;
    let nm = tester
        .handle
        .node_managers()
        .get_of_type::<SimpleNodeManager>()
        .expect("SimpleNodeManager not found");

    // Create the SQLite backend
    let backend = Arc::new(SqliteHistoryBackend::new_in_memory().unwrap());
    nm.inner().set_history_backend(backend.clone());

    let (session, lp) = tester.connect_default().await.unwrap();
    lp.spawn();
    timeout(Duration::from_secs(2), session.wait_for_connection())
        .await
        .unwrap();

    (tester, nm, session, backend)
}

#[tokio::test]
async fn test_hda_integration() {
    let (_tester, nm, session, _backend) = setup_hda().await;

    // 1. Create a source node with History Read/Write access level in the AddressSpace
    let node_id = NodeId::new(2, "MyHistoricalVar");
    {
        let mut space = nm.address_space().write();
        let var = VariableBuilder::new(&node_id, "MyHistoricalVar", "MyHistoricalVar")
            .data_type(DataTypeId::Double)
            .historizing(true)
            .value(0.0f64)
            .user_access_level(
                AccessLevel::HISTORY_READ
                    | AccessLevel::HISTORY_WRITE
                    | AccessLevel::CURRENT_READ
                    | AccessLevel::CURRENT_WRITE,
            )
            .access_level(
                AccessLevel::HISTORY_READ
                    | AccessLevel::HISTORY_WRITE
                    | AccessLevel::CURRENT_READ
                    | AccessLevel::CURRENT_WRITE,
            )
            .build();
        space.insert(var, None::<&[(_, &NodeId, _)]>);
    }

    // 2. Prepare 10 data values to insert/update in history
    let now = DateTime::now();
    let mut values = Vec::new();
    for i in 0..10 {
        let timestamp = DateTime::from(now.ticks() + (i as i64) * 10_000_000);
        let mut dv = DataValue::value_only(Variant::from(i as f64));
        dv.source_timestamp = Some(timestamp);
        dv.server_timestamp = Some(timestamp);
        dv.status = Some(StatusCode::Good);
        values.push(dv);
    }

    // 3. Perform history update
    let update_results = session
        .history_update_data(node_id.clone(), PerformUpdateType::Update, values.clone())
        .await
        .unwrap();

    assert_eq!(update_results.len(), 10);
    for status in update_results {
        assert!(status.is_good() || status == StatusCode::GoodEntryInserted);
    }

    // 4. Read raw history with page size limit = 3
    let start_time = DateTime::from(now.ticks() - 10_000_000);
    let end_time = DateTime::from(now.ticks() + 11 * 10_000_000);

    let mut retrieved_values = Vec::new();
    let (mut chunk, mut cp) = session
        .history_read_raw(node_id.clone(), start_time, end_time, 3, false, None)
        .await
        .unwrap();

    retrieved_values.append(&mut chunk);

    // Page through using continuation points
    while let Some(token) = cp {
        let (mut next_chunk, next_cp) = session
            .history_read_raw(node_id.clone(), start_time, end_time, 3, false, Some(token))
            .await
            .unwrap();
        retrieved_values.append(&mut next_chunk);
        cp = next_cp;
    }

    // 5. Verify retrieved values
    assert_eq!(retrieved_values.len(), 10);
    for (i, dv) in retrieved_values.iter().enumerate().take(10) {
        let val = dv
            .value
            .as_ref()
            .unwrap()
            .clone()
            .try_cast_to::<f64>()
            .unwrap();
        assert_eq!(val, i as f64);
    }
}
