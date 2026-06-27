//! In-memory historical data storage.

use std::collections::{BTreeMap, HashMap};

use async_trait::async_trait;
use opcua_core::sync::RwLock;
use opcua_types::{
    Annotation, DataValue, DateTime, HistoryUpdateType, ModificationInfo, NodeId,
    PerformUpdateType, StatusCode, UAString, Variant,
};

use crate::history::{HistoryRawModifiedResult, HistoryStorageBackend};

const DEFAULT_MAX_VALUES_PER_NODE: usize = 10_000;

/// A superseded value retained when a raw entry is replaced, updated-over, or deleted.
type ModifiedEntry = (DataValue, ModificationInfo);
/// Per-node modified-history store: original source-ticks → the superseded entries at that timestamp.
type ModifiedStore = HashMap<NodeId, BTreeMap<i64, Vec<ModifiedEntry>>>;
/// Per-node annotation-history store: source-ticks → annotation `DataValue`.
type AnnotationStore = HashMap<NodeId, BTreeMap<i64, DataValue>>;

/// In-memory historical data backend for raw `DataValue` history.
pub struct InMemoryDataHistory {
    raw_values: RwLock<HashMap<NodeId, BTreeMap<i64, DataValue>>>,
    modified_values: RwLock<ModifiedStore>,
    annotation_values: RwLock<AnnotationStore>,
    max_per_node: usize,
}

impl InMemoryDataHistory {
    /// Creates an in-memory data history backend with a default per-node cap.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_VALUES_PER_NODE)
    }

    /// Creates an in-memory data history backend with the given per-node cap.
    pub fn with_capacity(max_per_node: usize) -> Self {
        Self {
            raw_values: RwLock::new(HashMap::new()),
            modified_values: RwLock::new(HashMap::new()),
            annotation_values: RwLock::new(HashMap::new()),
            max_per_node,
        }
    }

    fn record_modified(
        &self,
        node_id: &NodeId,
        source_ticks: i64,
        value: DataValue,
        update_type: HistoryUpdateType,
    ) {
        // ponytail: user_name is empty because the storage layer has no request context.
        let info = ModificationInfo {
            modification_time: DateTime::now(),
            update_type,
            user_name: UAString::null(),
        };

        let mut modified_values = self.modified_values.write();
        modified_values
            .entry(node_id.clone())
            .or_default()
            .entry(source_ticks)
            .or_default()
            .push((value, info));
    }

    fn enforce_raw_capacity(&self, values: &mut BTreeMap<i64, DataValue>) {
        while values.len() > self.max_per_node {
            let Some(oldest_tick) = values.keys().next().copied() else {
                break;
            };
            values.remove(&oldest_tick);
        }
    }

    fn read_modified_values(
        &self,
        node_id: &NodeId,
        start_tick: i64,
        end_tick: i64,
        num_values_per_node: u32,
        continuation_point: Option<Vec<u8>>,
    ) -> Result<HistoryRawModifiedResult, StatusCode> {
        let Some(node_values) = self.modified_values.read().get(node_id).cloned() else {
            return Ok((Vec::new(), Vec::new(), None));
        };

        let continuation_position = decode_modified_continuation_position(continuation_point)?;
        let (effective_start, skip_at_start) =
            modified_effective_start(start_tick, continuation_position);
        let limit = (num_values_per_node > 0).then_some(num_values_per_node as usize);

        let capacity = limit.unwrap_or(0).min(node_values.len());
        let mut values = Vec::with_capacity(capacity);
        let mut modification_infos = Vec::with_capacity(capacity);
        let mut next_token = None;

        'ticks: for (tick, entries) in node_values.range(effective_start..end_tick) {
            let entry_start = if *tick == effective_start {
                skip_at_start
            } else {
                0
            };

            for (entry_index, (value, info)) in entries.iter().enumerate().skip(entry_start) {
                if limit.is_some_and(|limit| values.len() >= limit) {
                    next_token = Some(encode_modified_continuation_position(*tick, entry_index));
                    break 'ticks;
                }

                values.push(value.clone());
                modification_infos.push(info.clone());
            }
        }

        Ok((values, modification_infos, next_token))
    }
}

impl Default for InMemoryDataHistory {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HistoryStorageBackend for InMemoryDataHistory {
    async fn read_raw_modified(
        &self,
        node_id: &NodeId,
        start_time: DateTime,
        end_time: DateTime,
        num_values_per_node: u32,
        _return_bounds: bool,
        is_read_modified: bool,
        continuation_point: Option<Vec<u8>>,
    ) -> Result<HistoryRawModifiedResult, StatusCode> {
        let start_tick = start_time.ticks();
        let end_tick = end_time.ticks();
        if start_tick > end_tick {
            return Ok((Vec::new(), Vec::new(), None));
        }

        if is_read_modified {
            if start_tick == end_tick {
                return Ok((Vec::new(), Vec::new(), None));
            }

            return self.read_modified_values(
                node_id,
                start_tick,
                end_tick,
                num_values_per_node,
                continuation_point,
            );
        }

        let Some(node_values) = self.raw_values.read().get(node_id).cloned() else {
            return Ok((Vec::new(), Vec::new(), None));
        };

        let continuation_tick = decode_continuation_tick(continuation_point)?;
        let effective_start = continuation_tick.map_or(start_tick, |tick| tick.max(start_tick));
        let limit = (num_values_per_node > 0).then_some(num_values_per_node as usize);

        let mut values = Vec::with_capacity(limit.unwrap_or(0).min(node_values.len()));
        let mut next_token = None;
        for (tick, value) in node_values.range(effective_start..end_tick) {
            if limit.is_some_and(|limit| values.len() >= limit) {
                next_token = Some(encode_continuation_tick(*tick));
                break;
            }
            values.push(value.clone());
        }

        Ok((values, Vec::new(), next_token))
    }

    async fn read_annotations(
        &self,
        node_id: &NodeId,
        req_times: &[DateTime],
        continuation_point: Option<Vec<u8>>,
    ) -> Result<(Vec<DataValue>, Option<Vec<u8>>), StatusCode> {
        if continuation_point.is_some() {
            return Err(StatusCode::BadContinuationPointInvalid);
        }

        let annotation_values = self.annotation_values.read();
        let Some(node_values) = annotation_values.get(node_id) else {
            return Ok((Vec::new(), None));
        };

        if req_times.is_empty() {
            return Ok((node_values.values().cloned().collect(), None));
        }

        let mut values = Vec::with_capacity(req_times.len());
        for req_time in req_times {
            if let Some(value) = node_values.get(&req_time.ticks()) {
                values.push(value.clone());
            }
        }

        Ok((values, None))
    }

    async fn update_data(
        &self,
        node_id: &NodeId,
        perform_insert_replace: PerformUpdateType,
        values: Vec<DataValue>,
    ) -> Result<Vec<StatusCode>, StatusCode> {
        if values.is_empty() {
            return Ok(Vec::new());
        }

        let mut results = Vec::with_capacity(values.len());
        let mut raw_values = self.raw_values.write();
        let node_values = raw_values.entry(node_id.clone()).or_default();

        for value in values {
            let source_ticks = source_ticks(&value);
            let status = match perform_insert_replace {
                PerformUpdateType::Insert => {
                    if let std::collections::btree_map::Entry::Vacant(entry) =
                        node_values.entry(source_ticks)
                    {
                        entry.insert(value);
                        self.enforce_raw_capacity(node_values);
                        StatusCode::GoodEntryInserted
                    } else {
                        StatusCode::BadEntryExists
                    }
                }
                PerformUpdateType::Replace => {
                    if let Some(old_value) = node_values.get(&source_ticks).cloned() {
                        self.record_modified(
                            node_id,
                            source_ticks,
                            old_value,
                            HistoryUpdateType::Replace,
                        );
                        node_values.insert(source_ticks, value);
                        StatusCode::GoodEntryReplaced
                    } else {
                        StatusCode::BadNoEntryExists
                    }
                }
                PerformUpdateType::Update => {
                    if let Some(old_value) = node_values.get(&source_ticks).cloned() {
                        self.record_modified(
                            node_id,
                            source_ticks,
                            old_value,
                            HistoryUpdateType::Update,
                        );
                        node_values.insert(source_ticks, value);
                        StatusCode::GoodEntryReplaced
                    } else {
                        node_values.insert(source_ticks, value);
                        self.enforce_raw_capacity(node_values);
                        StatusCode::GoodEntryInserted
                    }
                }
                PerformUpdateType::Remove => {
                    if let Some(value) = node_values.remove(&source_ticks) {
                        self.modified_values
                            .write()
                            .entry(node_id.clone())
                            .or_default()
                            .entry(source_ticks)
                            .or_default()
                            .push((value, delete_modification_info()));
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

    async fn update_structure_data(
        &self,
        node_id: &NodeId,
        perform: PerformUpdateType,
        values: Vec<DataValue>,
    ) -> Result<Vec<StatusCode>, StatusCode> {
        if values.is_empty() {
            return Ok(Vec::new());
        }

        let mut results = Vec::with_capacity(values.len());
        let mut annotation_values = self.annotation_values.write();
        let node_values = annotation_values.entry(node_id.clone()).or_default();

        for value in values {
            if !is_annotation_data_value(&value) {
                results.push(StatusCode::BadTypeMismatch);
                continue;
            }

            let source_ticks = source_ticks(&value);
            let status = match perform {
                PerformUpdateType::Insert => {
                    if let std::collections::btree_map::Entry::Vacant(entry) =
                        node_values.entry(source_ticks)
                    {
                        entry.insert(value);
                        StatusCode::GoodEntryInserted
                    } else {
                        StatusCode::BadEntryExists
                    }
                }
                PerformUpdateType::Replace => {
                    if let std::collections::btree_map::Entry::Occupied(mut entry) =
                        node_values.entry(source_ticks)
                    {
                        entry.insert(value);
                        StatusCode::GoodEntryReplaced
                    } else {
                        StatusCode::BadNoEntryExists
                    }
                }
                PerformUpdateType::Update => {
                    if let std::collections::btree_map::Entry::Occupied(mut entry) =
                        node_values.entry(source_ticks)
                    {
                        entry.insert(value);
                        StatusCode::GoodEntryReplaced
                    } else {
                        node_values.insert(source_ticks, value);
                        StatusCode::GoodEntryInserted
                    }
                }
                PerformUpdateType::Remove => {
                    if node_values.remove(&source_ticks).is_some() {
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

    async fn delete_raw_modified(
        &self,
        node_id: &NodeId,
        is_delete_modified: bool,
        start_time: DateTime,
        end_time: DateTime,
    ) -> Result<StatusCode, StatusCode> {
        let start_ticks = start_time.ticks();
        let end_ticks = end_time.ticks();
        if start_ticks >= end_ticks {
            return Ok(StatusCode::BadNoData);
        }

        if is_delete_modified {
            let mut modified_values = self.modified_values.write();
            let Some(node_modified_values) = modified_values.get_mut(node_id) else {
                return Ok(StatusCode::BadNoData);
            };

            let ticks_to_remove = node_modified_values
                .range(start_ticks..end_ticks)
                .map(|(tick, _)| *tick)
                .collect::<Vec<_>>();

            let mut removed_count = 0;
            for tick in ticks_to_remove {
                if let Some(entries) = node_modified_values.remove(&tick) {
                    removed_count += entries.len();
                }
            }

            if node_modified_values.is_empty() {
                modified_values.remove(node_id);
            }

            return Ok(if removed_count > 0 {
                StatusCode::Good
            } else {
                StatusCode::BadNoData
            });
        }

        let mut raw_values = self.raw_values.write();
        let Some(node_values) = raw_values.get_mut(node_id) else {
            return Ok(StatusCode::BadNoData);
        };

        let values_to_delete = node_values
            .range(start_ticks..end_ticks)
            .map(|(tick, value)| (*tick, value.clone()))
            .collect::<Vec<_>>();

        if values_to_delete.is_empty() {
            return Ok(StatusCode::BadNoData);
        }

        {
            let mut modified_values = self.modified_values.write();
            let node_modified_values = modified_values.entry(node_id.clone()).or_default();
            for (tick, value) in &values_to_delete {
                node_modified_values
                    .entry(*tick)
                    .or_default()
                    .push((value.clone(), delete_modification_info()));
            }
        }

        for (tick, _) in values_to_delete {
            node_values.remove(&tick);
        }

        Ok(StatusCode::Good)
    }

    async fn delete_at_time(
        &self,
        node_id: &NodeId,
        req_times: Vec<DateTime>,
    ) -> Result<Vec<StatusCode>, StatusCode> {
        if req_times.is_empty() {
            return Ok(Vec::new());
        }

        let mut status_codes = Vec::with_capacity(req_times.len());
        let mut raw_values = self.raw_values.write();
        let Some(node_values) = raw_values.get_mut(node_id) else {
            for _ in req_times {
                status_codes.push(StatusCode::BadNoEntryExists);
            }
            return Ok(status_codes);
        };

        let mut modified_values = self.modified_values.write();
        for req_time in req_times {
            let source_ticks = req_time.ticks();
            if let Some(value) = node_values.remove(&source_ticks) {
                modified_values
                    .entry(node_id.clone())
                    .or_default()
                    .entry(source_ticks)
                    .or_default()
                    .push((value, delete_modification_info()));
                status_codes.push(StatusCode::Good);
            } else {
                status_codes.push(StatusCode::BadNoEntryExists);
            }
        }

        Ok(status_codes)
    }
}

fn source_ticks(value: &DataValue) -> i64 {
    value.source_timestamp.unwrap_or_else(DateTime::now).ticks()
}

fn is_annotation_data_value(value: &DataValue) -> bool {
    matches!(
        value.value.as_ref(),
        Some(Variant::ExtensionObject(object)) if object.inner_as::<Annotation>().is_some()
    )
}

fn delete_modification_info() -> ModificationInfo {
    ModificationInfo {
        modification_time: DateTime::now(),
        update_type: HistoryUpdateType::Delete,
        // ponytail: user_name is empty because the storage layer has no request context.
        user_name: UAString::null(),
    }
}

fn decode_continuation_tick(token: Option<Vec<u8>>) -> Result<Option<i64>, StatusCode> {
    let Some(token) = token else {
        return Ok(None);
    };
    let bytes: [u8; 8] = token
        .as_slice()
        .try_into()
        .map_err(|_| StatusCode::BadContinuationPointInvalid)?;
    Ok(Some(i64::from_le_bytes(bytes)))
}

fn encode_continuation_tick(tick: i64) -> Vec<u8> {
    tick.to_le_bytes().to_vec()
}

fn modified_effective_start(
    start_tick: i64,
    continuation_position: Option<(i64, usize)>,
) -> (i64, usize) {
    match continuation_position {
        Some((tick, entry_index)) if tick >= start_tick => (tick, entry_index),
        _ => (start_tick, 0),
    }
}

fn decode_modified_continuation_position(
    token: Option<Vec<u8>>,
) -> Result<Option<(i64, usize)>, StatusCode> {
    let Some(token) = token else {
        return Ok(None);
    };

    match token.len() {
        8 => {
            let tick = decode_continuation_tick(Some(token))?;
            Ok(tick.map(|tick| (tick, 0)))
        }
        16 => {
            let tick_bytes: [u8; 8] = token[..8]
                .try_into()
                .map_err(|_| StatusCode::BadContinuationPointInvalid)?;
            let index_bytes: [u8; 8] = token[8..]
                .try_into()
                .map_err(|_| StatusCode::BadContinuationPointInvalid)?;
            let entry_index = usize::try_from(u64::from_le_bytes(index_bytes))
                .map_err(|_| StatusCode::BadContinuationPointInvalid)?;
            Ok(Some((i64::from_le_bytes(tick_bytes), entry_index)))
        }
        _ => Err(StatusCode::BadContinuationPointInvalid),
    }
}

fn encode_modified_continuation_position(tick: i64, entry_index: usize) -> Vec<u8> {
    let mut token = encode_continuation_tick(tick);
    if entry_index > 0 {
        token.extend_from_slice(&(entry_index as u64).to_le_bytes());
    }
    token
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_constructs_in_memory_data_history() {
        let _history = InMemoryDataHistory::default();
    }
}
