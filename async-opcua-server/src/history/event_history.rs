//! In-memory event history storage.

use std::collections::{hash_map::Entry, HashMap, VecDeque};

use async_trait::async_trait;
use opcua_core::{events::AlarmEvent, sync::RwLock};
use opcua_nodes::DefaultTypeTree;
use opcua_types::{
    ByteString, DataValue, DateTime, EventFilter, HistoryEventFieldList, NodeId, ObjectTypeId,
    PerformUpdateType, QualifiedName, SimpleAttributeOperand, StatusCode, Variant,
};

use crate::{
    alarms::ServerAlarmEvent,
    history::{HistoryRawModifiedResult, HistoryStorageBackend},
    services::subscription::filter::ParsedEventFilter,
};

const DEFAULT_MAX_EVENTS_PER_NODE: usize = 1000;
const EVENT_ID_FIELD_NAME: &str = "EventId";

type AlarmEventStore = HashMap<NodeId, VecDeque<AlarmEvent>>;
type InsertedEventFieldsById = HashMap<ByteString, HistoryEventFieldList>;
type InsertedEventStore = HashMap<NodeId, InsertedEventFieldsById>;

/// In-memory historical event backend for condition events.
pub struct InMemoryEventHistory {
    events: RwLock<AlarmEventStore>,
    inserted_events: RwLock<InsertedEventStore>,
    max_per_node: usize,
}

impl InMemoryEventHistory {
    /// Creates an in-memory event history backend with a default per-node cap.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_EVENTS_PER_NODE)
    }

    /// Creates an in-memory event history backend with the given per-node cap.
    pub fn with_capacity(max_per_node: usize) -> Self {
        Self {
            events: RwLock::new(HashMap::new()),
            inserted_events: RwLock::new(HashMap::new()),
            max_per_node,
        }
    }

    /// Records an event against the source node, evicting the oldest events beyond the cap.
    pub fn record_event(&self, source_node: NodeId, event: AlarmEvent) {
        let mut events = self.events.write();
        let node_events = events.entry(source_node).or_default();
        node_events.push_back(event);
        while node_events.len() > self.max_per_node {
            node_events.pop_front();
        }
    }
}

impl Default for InMemoryEventHistory {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HistoryStorageBackend for InMemoryEventHistory {
    async fn read_events(
        &self,
        node_id: &NodeId,
        start_time: DateTime,
        end_time: DateTime,
        num_values_per_node: u32,
        filter: &EventFilter,
        _continuation_point: Option<Vec<u8>>,
    ) -> Result<(Vec<HistoryEventFieldList>, Option<Vec<u8>>), StatusCode> {
        let type_tree = DefaultTypeTree::new();
        let (_, parsed) = ParsedEventFilter::parse(filter.clone(), &type_tree);
        let parsed = parsed?;

        let mut events = self
            .events
            .read()
            .get(node_id)
            .map(|events| events.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        events.sort_by_key(|event| event.time);

        let limit = (num_values_per_node > 0).then_some(num_values_per_node as usize);
        let mut field_lists = Vec::new();
        for event in events
            .into_iter()
            .filter(|event| event_time_in_range(event.time, start_time, end_time))
        {
            // ponytail: reverse reads use the same inclusive range but keep ascending order.
            if !has_event_read_capacity(limit, field_lists.len()) {
                // ponytail: this backend truncates to num_values_per_node without a continuation.
                break;
            }

            let event = ServerAlarmEvent { event: &event };
            if let Some(fields) = parsed.evaluate(&event, 0, &type_tree) {
                field_lists.push(HistoryEventFieldList {
                    event_fields: fields.event_fields,
                });
            }
        }

        if has_event_read_capacity(limit, field_lists.len()) {
            let inserted_events = self
                .inserted_events
                .read()
                .get(node_id)
                .map(|events| events.values().cloned().collect::<Vec<_>>())
                .unwrap_or_default();

            for event in inserted_events {
                // ponytail: inserted events are returned with the field shape they were written
                // with, without cross-filter re-evaluation. Upgrade path: store the full event
                // and re-evaluate it against the read filter.
                if !has_event_read_capacity(limit, field_lists.len()) {
                    break;
                }
                field_lists.push(event);
            }
        }

        Ok((field_lists, None))
    }

    async fn read_raw_modified(
        &self,
        _node_id: &NodeId,
        _start_time: DateTime,
        _end_time: DateTime,
        _num_values_per_node: u32,
        _return_bounds: bool,
        _is_read_modified: bool,
        _continuation_point: Option<Vec<u8>>,
    ) -> Result<HistoryRawModifiedResult, StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    async fn update_data(
        &self,
        _node_id: &NodeId,
        _perform_insert_replace: PerformUpdateType,
        _values: Vec<DataValue>,
    ) -> Result<Vec<StatusCode>, StatusCode> {
        Err(StatusCode::BadHistoryOperationUnsupported)
    }

    async fn update_event(
        &self,
        node_id: &NodeId,
        filter: &EventFilter,
        events: Vec<HistoryEventFieldList>,
        perform: PerformUpdateType,
    ) -> Result<Vec<StatusCode>, StatusCode> {
        if events.is_empty() {
            return Ok(Vec::new());
        }

        let Some(event_id_index) = event_id_select_clause_index(filter) else {
            return Ok(vec![StatusCode::BadInvalidArgument; events.len()]);
        };

        let mut results = Vec::with_capacity(events.len());
        let mut inserted_events = self.inserted_events.write();
        let node_events = inserted_events.entry(node_id.clone()).or_default();

        for event in events {
            let Some(event_id) = event_id_from_field_list(&event, event_id_index) else {
                results.push(StatusCode::BadInvalidArgument);
                continue;
            };

            let status = match perform {
                PerformUpdateType::Insert => match node_events.entry(event_id) {
                    Entry::Vacant(entry) => {
                        entry.insert(event);
                        StatusCode::GoodEntryInserted
                    }
                    Entry::Occupied(_) => StatusCode::BadEntryExists,
                },
                PerformUpdateType::Replace => match node_events.entry(event_id) {
                    Entry::Occupied(mut entry) => {
                        entry.insert(event);
                        StatusCode::GoodEntryReplaced
                    }
                    Entry::Vacant(_) => StatusCode::BadNoEntryExists,
                },
                PerformUpdateType::Update => match node_events.entry(event_id) {
                    Entry::Occupied(mut entry) => {
                        entry.insert(event);
                        StatusCode::GoodEntryReplaced
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(event);
                        StatusCode::GoodEntryInserted
                    }
                },
                PerformUpdateType::Remove => {
                    if node_events.remove(&event_id).is_some() {
                        StatusCode::Good
                    } else {
                        StatusCode::BadNoEntryExists
                    }
                }
            };
            results.push(status);
        }

        Ok(results)
    }

    async fn delete_event(
        &self,
        node_id: &NodeId,
        event_ids: Vec<ByteString>,
    ) -> Result<Vec<StatusCode>, StatusCode> {
        if event_ids.is_empty() {
            return Ok(Vec::new());
        }

        let mut inserted_events = self.inserted_events.write();
        let Some(node_events) = inserted_events.get_mut(node_id) else {
            return Ok(vec![StatusCode::BadNoEntryExists; event_ids.len()]);
        };

        let mut results = Vec::with_capacity(event_ids.len());
        for event_id in event_ids {
            if node_events.remove(&event_id).is_some() {
                results.push(StatusCode::Good);
            } else {
                results.push(StatusCode::BadNoEntryExists);
            }
        }

        Ok(results)
    }
}

fn event_id_select_clause_index(filter: &EventFilter) -> Option<usize> {
    filter
        .select_clauses
        .as_deref()?
        .iter()
        .position(is_event_id_select_clause)
}

fn is_event_id_select_clause(clause: &SimpleAttributeOperand) -> bool {
    clause.type_definition_id == ObjectTypeId::BaseEventType
        && is_event_id_browse_path(clause.browse_path.as_deref())
}

fn is_event_id_browse_path(browse_path: Option<&[QualifiedName]>) -> bool {
    matches!(
        browse_path,
        Some([name]) if name.namespace_index == 0 && name.name.as_ref() == EVENT_ID_FIELD_NAME
    )
}

fn event_id_from_field_list(
    event: &HistoryEventFieldList,
    event_id_index: usize,
) -> Option<ByteString> {
    match event.event_fields.as_ref()?.get(event_id_index) {
        Some(Variant::ByteString(event_id)) => Some(event_id.clone()),
        _ => None,
    }
}

fn has_event_read_capacity(limit: Option<usize>, len: usize) -> bool {
    match limit {
        Some(limit) => len < limit,
        None => true,
    }
}

fn event_time_in_range(event_time: DateTime, start_time: DateTime, end_time: DateTime) -> bool {
    let start_tick = start_time.ticks();
    let end_tick = end_time.ticks();

    let after_start = is_unbounded_start(start_tick) || event_time.ticks() >= start_tick;
    let before_end = is_unbounded_end(end_tick) || event_time.ticks() <= end_tick;
    if start_tick <= end_tick || is_unbounded_start(start_tick) || is_unbounded_end(end_tick) {
        return after_start && before_end;
    }

    event_time.ticks() >= end_tick && event_time.ticks() <= start_tick
}

fn is_unbounded_start(ticks: i64) -> bool {
    ticks <= DateTime::null().ticks()
}

fn is_unbounded_end(ticks: i64) -> bool {
    ticks == DateTime::null().ticks() || ticks == i64::MAX
}
