//! SQLite implementation of the OPC UA history storage backend.

use crate::{migration::run_migrations, query};
use async_trait::async_trait;
use opcua_server::{
    aggregates::engine::{calculate_aggregate, get_value_timestamp, partition_intervals},
    history::HistoryStorageBackend,
};
use opcua_types::{
    BinaryEncodable, ContextOwned, DataValue, DateTime, EventFilter, HistoryEventFieldList, NodeId,
    PerformUpdateType, StatusCode,
};
use parking_lot::Mutex;
use rusqlite::{params, Connection, Error as SqliteError, OptionalExtension};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Reference SQLite-based storage engine implementation for OPC UA HDA.
pub struct SqliteHistoryBackend {
    connection: Arc<Mutex<Connection>>,
    continuation_points: Arc<Mutex<HashMap<Vec<u8>, CachedContinuationPoint>>>,
}

struct CachedContinuationPoint {
    values: Vec<DataValue>,
    created_at: Instant,
}

impl SqliteHistoryBackend {
    /// Creates a new SQLite history backend using the database at `path`.
    pub fn new(path: &str) -> Result<Self, SqliteError> {
        let connection = Connection::open(path)?;
        run_migrations(&connection)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            continuation_points: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Creates a new in-memory SQLite history backend.
    pub fn new_in_memory() -> Result<Self, SqliteError> {
        let connection = Connection::open_in_memory()?;
        run_migrations(&connection)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            continuation_points: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn prune_continuation_points(&self) {
        let mut cps = self.continuation_points.lock();
        let max_age = Duration::from_secs(300);
        cps.retain(|_, cp| cp.created_at.elapsed() < max_age);
    }
}

#[async_trait]
impl HistoryStorageBackend for SqliteHistoryBackend {
    async fn read_raw_modified(
        &self,
        node_id: &NodeId,
        start_time: DateTime,
        end_time: DateTime,
        num_values_per_node: u32,
        return_bounds: bool,
        continuation_point: Option<Vec<u8>>,
    ) -> Result<(Vec<DataValue>, Option<Vec<u8>>), StatusCode> {
        self.prune_continuation_points();

        if let Some(ref token) = continuation_point {
            let mut cps = self.continuation_points.lock();
            if let Some(cp) = cps.remove(token) {
                let mut values = cp.values;
                if num_values_per_node > 0 && values.len() > num_values_per_node as usize {
                    let remaining = values.split_off(num_values_per_node as usize);
                    let new_token = uuid::Uuid::new_v4().as_bytes().to_vec();
                    cps.insert(
                        new_token.clone(),
                        CachedContinuationPoint {
                            values: remaining,
                            created_at: Instant::now(),
                        },
                    );
                    return Ok((values, Some(new_token)));
                }
                return Ok((values, None));
            }
            return Err(StatusCode::BadContinuationPointInvalid);
        }

        let conn = self.connection.clone();
        let node_id_str = node_id.to_string();
        let start_ticks = start_time.ticks();
        let end_ticks = end_time.ticks();
        let chronological = start_ticks < end_ticks;

        let result: Result<Vec<DataValue>, SqliteError> = tokio::task::spawn_blocking(move || {
            let conn = conn.lock();
            let mut all_values = Vec::new();

            if return_bounds {
                let find_prev = chronological;
                if let Some(value) =
                    query::fetch_bounds(&conn, &node_id_str, start_ticks, find_prev)?
                {
                    all_values.push(value);
                }
            }

            all_values.extend(query::fetch_interval(
                &conn,
                &node_id_str,
                start_ticks,
                end_ticks,
                chronological,
            )?);

            if return_bounds {
                let find_prev = !chronological;
                if let Some(value) = query::fetch_bounds(&conn, &node_id_str, end_ticks, find_prev)?
                {
                    all_values.push(value);
                }
            }

            Ok(all_values)
        })
        .await
        .map_err(|_| StatusCode::BadInternalError)?;

        let mut values = result.map_err(|err| {
            tracing::error!("SQLite error in read_raw_modified: {:?}", err);
            StatusCode::BadInternalError
        })?;

        opcua_server::history::sort_historical_values(&mut values, start_time, end_time);
        values.dedup_by(|a, b| a.source_timestamp == b.source_timestamp);

        if num_values_per_node > 0 && values.len() > num_values_per_node as usize {
            let remaining = values.split_off(num_values_per_node as usize);
            let token = uuid::Uuid::new_v4().as_bytes().to_vec();
            self.continuation_points.lock().insert(
                token.clone(),
                CachedContinuationPoint {
                    values: remaining,
                    created_at: Instant::now(),
                },
            );
            Ok((values, Some(token)))
        } else {
            Ok((values, None))
        }
    }

    async fn read_processed(
        &self,
        node_id: &NodeId,
        start_time: DateTime,
        end_time: DateTime,
        processing_interval: f64,
        aggregate_type: &NodeId,
        continuation_point: Option<Vec<u8>>,
    ) -> Result<(Vec<DataValue>, Option<Vec<u8>>), StatusCode> {
        if continuation_point.is_some() {
            return Err(StatusCode::BadContinuationPointInvalid);
        }

        let mut raw_values = Vec::new();
        let mut next_token = None;
        loop {
            let (values, token) = self
                .read_raw_modified(node_id, start_time, end_time, 100_000, false, next_token)
                .await?;
            raw_values.extend(values);

            let Some(token) = token else {
                break;
            };
            next_token = Some(token);
        }

        raw_values.sort_by_key(get_value_timestamp);

        let processed_values = partition_intervals(start_time, end_time, processing_interval)
            .into_iter()
            .map(|(interval_start, interval_end)| {
                let (min_t, max_t) = if interval_start <= interval_end {
                    (interval_start, interval_end)
                } else {
                    (interval_end, interval_start)
                };

                let values_in_interval: Vec<&DataValue> = raw_values
                    .iter()
                    .filter(|value| {
                        let timestamp = get_value_timestamp(value);
                        timestamp >= min_t && timestamp < max_t
                    })
                    .collect();

                calculate_aggregate(
                    &values_in_interval,
                    aggregate_type,
                    interval_start,
                    interval_end,
                )
            })
            .collect();

        Ok((processed_values, None))
    }

    async fn read_events(
        &self,
        _node_id: &NodeId,
        _start_time: DateTime,
        _end_time: DateTime,
        _num_values_per_node: u32,
        _filter: &EventFilter,
        continuation_point: Option<Vec<u8>>,
    ) -> Result<(Vec<HistoryEventFieldList>, Option<Vec<u8>>), StatusCode> {
        if continuation_point.is_some() {
            return Err(StatusCode::BadContinuationPointInvalid);
        }

        Ok((Vec::new(), None))
    }

    async fn read_annotations(
        &self,
        _node_id: &NodeId,
        _req_times: &[DateTime],
        continuation_point: Option<Vec<u8>>,
    ) -> Result<(Vec<DataValue>, Option<Vec<u8>>), StatusCode> {
        if continuation_point.is_some() {
            return Err(StatusCode::BadContinuationPointInvalid);
        }

        Ok((Vec::new(), None))
    }

    async fn update_data(
        &self,
        node_id: &NodeId,
        perform_insert_replace: PerformUpdateType,
        values: Vec<DataValue>,
    ) -> Result<Vec<StatusCode>, StatusCode> {
        self.prune_continuation_points();

        let conn = self.connection.clone();
        let node_id_str = node_id.to_string();

        let results: Result<Vec<StatusCode>, SqliteError> =
            tokio::task::spawn_blocking(move || {
                let mut conn = conn.lock();
                let tx = conn.transaction()?;
                let mut status_codes = Vec::with_capacity(values.len());

                for value in values {
                    let source_ticks = value.source_timestamp.unwrap_or_else(DateTime::now).ticks();
                    let server_ticks = value.server_timestamp.unwrap_or_else(DateTime::now).ticks();
                    let status_val = value.status.map(|status| status.bits() as i64).unwrap_or(0);

                    let ctx_owned = ContextOwned::default();
                    let ctx = ctx_owned.context();
                    let blob = value.encode_to_vec(&ctx);

                    let exists = tx
                        .query_row(
                            "SELECT 1 FROM historical_data
                         WHERE node_id = ?1 AND source_timestamp = ?2",
                            params![node_id_str, source_ticks],
                            |_| Ok(1),
                        )
                        .optional()?
                        .is_some();

                    match perform_insert_replace {
                        PerformUpdateType::Insert => {
                            if exists {
                                status_codes.push(StatusCode::BadEntryExists);
                            } else {
                                tx.execute(
                                    "INSERT INTO historical_data (
                                    node_id,
                                    source_timestamp,
                                    server_timestamp,
                                    value_blob,
                                    status_code
                                ) VALUES (?1, ?2, ?3, ?4, ?5)",
                                    params![
                                        node_id_str,
                                        source_ticks,
                                        server_ticks,
                                        blob,
                                        status_val
                                    ],
                                )?;
                                status_codes.push(StatusCode::GoodEntryInserted);
                            }
                        }
                        PerformUpdateType::Replace => {
                            if exists {
                                tx.execute(
                                    "UPDATE historical_data
                                 SET server_timestamp = ?3,
                                     value_blob = ?4,
                                     status_code = ?5
                                 WHERE node_id = ?1 AND source_timestamp = ?2",
                                    params![
                                        node_id_str,
                                        source_ticks,
                                        server_ticks,
                                        blob,
                                        status_val
                                    ],
                                )?;
                                status_codes.push(StatusCode::GoodEntryReplaced);
                            } else {
                                status_codes.push(StatusCode::BadNoEntryExists);
                            }
                        }
                        PerformUpdateType::Update => {
                            if exists {
                                tx.execute(
                                    "UPDATE historical_data
                                 SET server_timestamp = ?3,
                                     value_blob = ?4,
                                     status_code = ?5
                                 WHERE node_id = ?1 AND source_timestamp = ?2",
                                    params![
                                        node_id_str,
                                        source_ticks,
                                        server_ticks,
                                        blob,
                                        status_val
                                    ],
                                )?;
                                status_codes.push(StatusCode::GoodEntryReplaced);
                            } else {
                                tx.execute(
                                    "INSERT INTO historical_data (
                                    node_id,
                                    source_timestamp,
                                    server_timestamp,
                                    value_blob,
                                    status_code
                                ) VALUES (?1, ?2, ?3, ?4, ?5)",
                                    params![
                                        node_id_str,
                                        source_ticks,
                                        server_ticks,
                                        blob,
                                        status_val
                                    ],
                                )?;
                                status_codes.push(StatusCode::GoodEntryInserted);
                            }
                        }
                        _ => {
                            status_codes.push(StatusCode::BadHistoryOperationUnsupported);
                        }
                    }
                }

                tx.commit()?;
                Ok(status_codes)
            })
            .await
            .map_err(|_| StatusCode::BadInternalError)?;

        results.map_err(|err| {
            tracing::error!("SQLite error in update_data: {:?}", err);
            StatusCode::BadInternalError
        })
    }

    async fn release_continuation_point(&self, token: Vec<u8>) -> Result<(), StatusCode> {
        self.continuation_points.lock().remove(&token);
        Ok(())
    }
}
