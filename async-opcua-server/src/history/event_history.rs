//! In-memory event history storage.

use std::collections::{HashMap, VecDeque};

use async_trait::async_trait;
use opcua_core::{events::AlarmEvent, sync::RwLock};
use opcua_nodes::DefaultTypeTree;
use opcua_types::{
    DataValue, DateTime, EventFilter, HistoryEventFieldList, ModificationInfo, NodeId,
    PerformUpdateType, StatusCode,
};

use crate::{
    alarms::ServerAlarmEvent, history::HistoryStorageBackend,
    services::subscription::filter::ParsedEventFilter,
};

const DEFAULT_MAX_EVENTS_PER_NODE: usize = 1000;

/// In-memory historical event backend for condition events.
pub struct InMemoryEventHistory {
    events: RwLock<HashMap<NodeId, VecDeque<AlarmEvent>>>,
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
            if limit.is_some_and(|limit| field_lists.len() >= limit) {
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

        Ok((field_lists, None))
    }

    async fn read_raw_modified(
        &self,
        _node_id: &NodeId,
        _start_time: DateTime,
        _end_time: DateTime,
        _num_values_per_node: u32,
        _return_bounds: bool,
        _continuation_point: Option<Vec<u8>>,
    ) -> Result<(Vec<DataValue>, Vec<ModificationInfo>, Option<Vec<u8>>), StatusCode> {
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
