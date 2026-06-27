//! Independent US6 tests for InMemoryEventHistory UpdateEvent/DeleteEvent (Part 11 §6.8.4 / §6.9.4).

use opcua_server::history::{HistoryStorageBackend, InMemoryEventHistory};
use opcua_types::{
    AttributeId, ByteString, DateTime, EventFilter, HistoryEventFieldList, NodeId, NumericRange,
    ObjectTypeId, PerformUpdateType, QualifiedName, SimpleAttributeOperand, StatusCode, Variant,
};

fn node() -> NodeId {
    NodeId::new(2, "EventSource")
}

/// An EventFilter selecting only BaseEventType/EventId (field 0).
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

async fn read_event_ids(b: &InMemoryEventHistory, n: &NodeId) -> Vec<Vec<u8>> {
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
    lists
        .into_iter()
        .filter_map(
            |l| match l.event_fields.and_then(|f| f.into_iter().next()) {
                Some(Variant::ByteString(bs)) => Some(bs.as_ref().to_vec()),
                _ => None,
            },
        )
        .collect()
}

#[tokio::test]
async fn update_event_insert_and_read_back() {
    let b = InMemoryEventHistory::new();
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
    let mut ids = read_event_ids(&b, &n).await;
    ids.sort();
    assert_eq!(ids, vec![b"e1".to_vec(), b"e2".to_vec()]);

    // Insert over an existing EventId → BadEntryExists.
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
}

#[tokio::test]
async fn update_event_replace_existing() {
    let b = InMemoryEventHistory::new();
    let n = node();
    b.update_event(
        &n,
        &eventid_filter(),
        vec![event(b"e1")],
        PerformUpdateType::Insert,
    )
    .await
    .unwrap();
    // Replace present id → GoodEntryReplaced; absent → BadNoEntryExists.
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
            vec![event(b"nope")],
            PerformUpdateType::Replace
        )
        .await
        .unwrap(),
        vec![StatusCode::BadNoEntryExists]
    );
}

#[tokio::test]
async fn delete_event_by_id() {
    let b = InMemoryEventHistory::new();
    let n = node();
    b.update_event(
        &n,
        &eventid_filter(),
        vec![event(b"e1"), event(b"e2")],
        PerformUpdateType::Insert,
    )
    .await
    .unwrap();
    // [present e1, absent gone] → [Good, BadNoEntryExists].
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
async fn event_without_eventid_field_is_rejected() {
    let b = InMemoryEventHistory::new();
    let n = node();
    // A field-list with no fields → can't extract EventId → BadInvalidArgument, no panic.
    let empty = HistoryEventFieldList {
        event_fields: Some(vec![]),
    };
    let r = b
        .update_event(
            &n,
            &eventid_filter(),
            vec![empty],
            PerformUpdateType::Insert,
        )
        .await
        .unwrap();
    assert_eq!(r, vec![StatusCode::BadInvalidArgument]);
    // Empty event-id list for delete → empty vec.
    assert!(b.delete_event(&n, vec![]).await.unwrap().is_empty());
}
