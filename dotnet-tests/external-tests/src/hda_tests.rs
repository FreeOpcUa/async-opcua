use crate::client::ClientTestState;
use opcua::client::Session;
use opcua::types::{DataValue, DateTime, NodeId, PerformUpdateType, StatusCode, Variant};
use std::sync::Arc;

pub async fn test_hda(session: Arc<Session>, _ctx: &mut ClientTestState) {
    let node_id = NodeId::new(2, "VarDouble");

    // 1. Prepare 10 data values to insert/update in history
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

    // 2. Perform history update
    let update_results = match session
        .history_update_data(node_id.clone(), PerformUpdateType::Update, values.clone())
        .await
    {
        Ok(res) => res,
        Err(e) => {
            if e.status() == StatusCode::BadHistoryOperationUnsupported {
                println!("HDA Update not supported by server, skipping remaining HDA test");
                return;
            }
            panic!("History update failed: {:?}", e);
        }
    };

    assert_eq!(update_results.len(), 10);
    for status in update_results {
        assert!(
            status.is_good()
                || status == StatusCode::GoodEntryInserted
                || status == StatusCode::GoodEntryReplaced
        );
    }

    // 3. Read raw history with page size limit = 3
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

    // 4. Verify retrieved values
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
