//! Independent US6 tests for the sqlite UpdateEvent/DeleteEvent path (Part 11 §6.8.4 / §6.9.4),
//! mirroring the InMemoryEventHistory semantics.

use opcua_history_sqlite::SqliteHistoryBackend;
use opcua_server::history::HistoryStorageBackend;
use opcua_types::{
    AttributeId, ByteString, DateTime, EventFilter, HistoryEventFieldList, NodeId, NumericRange,
    ObjectTypeId, PerformUpdateType, QualifiedName, SimpleAttributeOperand, StatusCode, Variant,
};

fn node() -> NodeId {
    NodeId::new(2, "EventSource")
}

fn eventid_filter() -> EventFilter {
    EventFilter {
        select_clauses: Some(vec![SimpleAttributeOperand {
            type_definition_id: ObjectTypeId::BaseEventType.into(),
            browse_path: Some(vec![QualifiedName::new(0, "EventId")]),
            attribute_id: AttributeId::Value as u32,
            index_range: NumericRange::None,
        }]),
        where_clause: Default::default(),
    }
}

fn event(id: &[u8]) -> HistoryEventFieldList {
    HistoryEventFieldList {
        event_fields: Some(vec![Variant::ByteString(ByteString::from(id.to_vec()))]),
    }
}

async fn read_event_ids(b: &SqliteHistoryBackend, n: &NodeId) -> Vec<Vec<u8>> {
    let (lists, _cp) = b
        .read_events(
            n,
            DateTime::from(0),
            DateTime::from(i64::MAX),
            1000,
            &eventid_filter(),
            None,
        )
        .await
        .expect("read events");
    let mut ids: Vec<Vec<u8>> = lists
        .into_iter()
        .filter_map(
            |l| match l.event_fields.and_then(|f| f.into_iter().next()) {
                Some(Variant::ByteString(bs)) => Some(bs.as_ref().to_vec()),
                _ => None,
            },
        )
        .collect();
    ids.sort();
    ids
}

#[tokio::test]
async fn update_event_insert_replace_and_read() {
    let b = SqliteHistoryBackend::new_in_memory().unwrap();
    let n = node();
    let r = b
        .update_event(
            &n,
            &eventid_filter(),
            vec![event(b"e1"), event(b"e2")],
            PerformUpdateType::Insert,
        )
        .await
        .unwrap();
    assert_eq!(
        r,
        vec![StatusCode::GoodEntryInserted, StatusCode::GoodEntryInserted]
    );
    assert_eq!(
        read_event_ids(&b, &n).await,
        vec![b"e1".to_vec(), b"e2".to_vec()]
    );

    assert_eq!(
        b.update_event(
            &n,
            &eventid_filter(),
            vec![event(b"e1")],
            PerformUpdateType::Insert
        )
        .await
        .unwrap(),
        vec![StatusCode::BadEntryExists]
    );
    assert_eq!(
        b.update_event(
            &n,
            &eventid_filter(),
            vec![event(b"e1")],
            PerformUpdateType::Replace
        )
        .await
        .unwrap(),
        vec![StatusCode::GoodEntryReplaced]
    );
    assert_eq!(
        b.update_event(
            &n,
            &eventid_filter(),
            vec![event(b"x")],
            PerformUpdateType::Replace
        )
        .await
        .unwrap(),
        vec![StatusCode::BadNoEntryExists]
    );
}

#[tokio::test]
async fn delete_event_by_id() {
    let b = SqliteHistoryBackend::new_in_memory().unwrap();
    let n = node();
    b.update_event(
        &n,
        &eventid_filter(),
        vec![event(b"e1"), event(b"e2")],
        PerformUpdateType::Insert,
    )
    .await
    .unwrap();
    let r = b
        .delete_event(
            &n,
            vec![
                ByteString::from(b"e1".to_vec()),
                ByteString::from(b"gone".to_vec()),
            ],
        )
        .await
        .unwrap();
    assert_eq!(r, vec![StatusCode::Good, StatusCode::BadNoEntryExists]);
    assert_eq!(read_event_ids(&b, &n).await, vec![b"e2".to_vec()]);
}

#[tokio::test]
async fn event_without_eventid_is_rejected_and_empty_delete_is_noop() {
    let b = SqliteHistoryBackend::new_in_memory().unwrap();
    let n = node();
    let empty = HistoryEventFieldList {
        event_fields: Some(vec![]),
    };
    assert_eq!(
        b.update_event(
            &n,
            &eventid_filter(),
            vec![empty],
            PerformUpdateType::Insert
        )
        .await
        .unwrap(),
        vec![StatusCode::BadInvalidArgument]
    );
    assert!(b.delete_event(&n, vec![]).await.unwrap().is_empty());
}
