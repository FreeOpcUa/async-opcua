//! OPC UA History SQLite backend implementation.

use async_trait::async_trait;
use opcua_server::history::HistoryStorageBackend;
use opcua_types::{
    BinaryDecodable, BinaryEncodable, ContextOwned, DataValue, DateTime, NodeId, PerformUpdateType,
    StatusCode,
};
use parking_lot::Mutex;
use rusqlite::{params, Connection, Error as SqliteError, OptionalExtension};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Reference SQLite-based storage engine implementation for OPC-UA Historical Data Access (HDA).
pub struct SqliteHistoryBackend {
    connection: Arc<Mutex<Connection>>,
    continuation_points: Arc<Mutex<HashMap<Vec<u8>, CachedContinuationPoint>>>,
}

struct CachedContinuationPoint {
    values: Vec<DataValue>,
    created_at: Instant,
}

impl SqliteHistoryBackend {
    /// Creates a new SqliteHistoryBackend with the SQLite database at the specified path.
    pub fn new(path: &str) -> Result<Self, SqliteError> {
        let connection = Connection::open(path)?;
        Self::init_db(&connection)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            continuation_points: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Creates a new in-memory SqliteHistoryBackend.
    pub fn new_in_memory() -> Result<Self, SqliteError> {
        let connection = Connection::open_in_memory()?;
        Self::init_db(&connection)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            continuation_points: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn init_db(connection: &Connection) -> Result<(), SqliteError> {
        connection.execute(
            "CREATE TABLE IF NOT EXISTS historical_data (
                node_id TEXT NOT NULL,
                source_timestamp INTEGER NOT NULL,
                server_timestamp INTEGER NOT NULL,
                value_blob BLOB NOT NULL,
                status_code INTEGER NOT NULL,
                PRIMARY KEY (node_id, source_timestamp)
            )",
            [],
        )?;
        Ok(())
    }

    fn prune_continuation_points(&self) {
        let mut cps = self.continuation_points.lock();
        let max_age = Duration::from_secs(300); // 5 minutes eviction
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

        // If a continuation point token was passed, retrieve the remaining values
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
                } else {
                    return Ok((values, None));
                }
            } else {
                return Err(StatusCode::BadContinuationPointInvalid);
            }
        }

        // Otherwise, read from database
        let conn = self.connection.clone();
        let node_id_str = node_id.to_string();
        let start_ticks = start_time.ticks();
        let end_ticks = end_time.ticks();
        let chronological = start_ticks < end_ticks;

        let result: Result<Vec<DataValue>, SqliteError> = tokio::task::spawn_blocking(move || {
            let conn = conn.lock();
            let mut all_values = Vec::new();

            // 1. Fetch start boundary if return_bounds is true
            if return_bounds {
                let query = if chronological {
                    "SELECT source_timestamp, server_timestamp, value_blob, status_code \
                     FROM historical_data \
                     WHERE node_id = ?1 AND source_timestamp <= ?2 \
                     ORDER BY source_timestamp DESC LIMIT 1"
                } else {
                    "SELECT source_timestamp, server_timestamp, value_blob, status_code \
                     FROM historical_data \
                     WHERE node_id = ?1 AND source_timestamp >= ?2 \
                     ORDER BY source_timestamp ASC LIMIT 1"
                };
                let mut stmt = conn.prepare(query)?;
                let mut rows = stmt.query(params![node_id_str, start_ticks])?;
                if let Some(row) = rows.next()? {
                    all_values.push(row_to_datavalue(&row)?);
                }
            }

            // 2. Fetch interval values
            let interval_query = if chronological {
                "SELECT source_timestamp, server_timestamp, value_blob, status_code \
                 FROM historical_data \
                 WHERE node_id = ?1 AND source_timestamp >= ?2 AND source_timestamp < ?3 \
                 ORDER BY source_timestamp ASC"
            } else {
                "SELECT source_timestamp, server_timestamp, value_blob, status_code \
                 FROM historical_data \
                 WHERE node_id = ?1 AND source_timestamp <= ?2 AND source_timestamp > ?3 \
                 ORDER BY source_timestamp DESC"
            };
            let mut stmt = conn.prepare(interval_query)?;
            let mut rows = stmt.query(params![node_id_str, start_ticks, end_ticks])?;
            while let Some(row) = rows.next()? {
                all_values.push(row_to_datavalue(&row)?);
            }

            // 3. Fetch end boundary if return_bounds is true
            if return_bounds {
                let query = if chronological {
                    "SELECT source_timestamp, server_timestamp, value_blob, status_code \
                     FROM historical_data \
                     WHERE node_id = ?1 AND source_timestamp >= ?2 \
                     ORDER BY source_timestamp ASC LIMIT 1"
                } else {
                    "SELECT source_timestamp, server_timestamp, value_blob, status_code \
                     FROM historical_data \
                     WHERE node_id = ?1 AND source_timestamp <= ?2 \
                     ORDER BY source_timestamp DESC LIMIT 1"
                };
                let mut stmt = conn.prepare(query)?;
                let mut rows = stmt.query(params![node_id_str, end_ticks])?;
                if let Some(row) = rows.next()? {
                    all_values.push(row_to_datavalue(&row)?);
                }
            }

            Ok(all_values)
        })
        .await
        .map_err(|_| StatusCode::BadInternalError)?;

        let mut values = result.map_err(|e| {
            tracing::error!("SQLite error in read_raw_modified: {:?}", e);
            StatusCode::BadInternalError
        })?;

        // 4. Sort and deduplicate values using the middleware
        opcua_server::history::sort_historical_values(&mut values, start_time, end_time);
        values.dedup_by(|a, b| a.source_timestamp == b.source_timestamp);

        // 5. Handle pagination
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

    async fn update_data(
        &self,
        node_id: &NodeId,
        perform_insert_replace: PerformUpdateType,
        values: Vec<DataValue>,
    ) -> Result<Vec<StatusCode>, StatusCode> {
        self.prune_continuation_points();

        let conn = self.connection.clone();
        let node_id_str = node_id.to_string();

        let results: Result<Vec<StatusCode>, SqliteError> = tokio::task::spawn_blocking(move || {
            let mut conn = conn.lock();
            let tx = conn.transaction()?;
            let mut status_codes = Vec::with_capacity(values.len());

            for val in values {
                let source_ticks = val.source_timestamp.unwrap_or_else(DateTime::now).ticks();
                let server_ticks = val.server_timestamp.unwrap_or_else(DateTime::now).ticks();
                let status_val = val.status.map(|s| s.bits() as i64).unwrap_or(0);

                let ctx_owned = ContextOwned::default();
                let ctx = ctx_owned.context();
                let blob = val.encode_to_vec(&ctx);

                // Check if entry already exists
                let exists: bool = tx
                    .query_row(
                        "SELECT 1 FROM historical_data WHERE node_id = ?1 AND source_timestamp = ?2",
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
                                "INSERT INTO historical_data (node_id, source_timestamp, server_timestamp, value_blob, status_code) \
                                 VALUES (?1, ?2, ?3, ?4, ?5)",
                                params![node_id_str, source_ticks, server_ticks, blob, status_val],
                            )?;
                            status_codes.push(StatusCode::GoodEntryInserted);
                        }
                    }
                    PerformUpdateType::Replace => {
                        if exists {
                            tx.execute(
                                "UPDATE historical_data \
                                 SET server_timestamp = ?3, value_blob = ?4, status_code = ?5 \
                                 WHERE node_id = ?1 AND source_timestamp = ?2",
                                params![node_id_str, source_ticks, server_ticks, blob, status_val],
                            )?;
                            status_codes.push(StatusCode::GoodEntryReplaced);
                        } else {
                            status_codes.push(StatusCode::BadNoEntryExists);
                        }
                    }
                    PerformUpdateType::Update => {
                        if exists {
                            tx.execute(
                                "UPDATE historical_data \
                                 SET server_timestamp = ?3, value_blob = ?4, status_code = ?5 \
                                 WHERE node_id = ?1 AND source_timestamp = ?2",
                                params![node_id_str, source_ticks, server_ticks, blob, status_val],
                            )?;
                            status_codes.push(StatusCode::GoodEntryReplaced);
                        } else {
                            tx.execute(
                                "INSERT INTO historical_data (node_id, source_timestamp, server_timestamp, value_blob, status_code) \
                                 VALUES (?1, ?2, ?3, ?4, ?5)",
                                params![node_id_str, source_ticks, server_ticks, blob, status_val],
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

        results.map_err(|e| {
            tracing::error!("SQLite error in update_data: {:?}", e);
            StatusCode::BadInternalError
        })
    }
}

fn row_to_datavalue(row: &rusqlite::Row) -> Result<DataValue, SqliteError> {
    let source_ticks: i64 = row.get(0)?;
    let server_ticks: i64 = row.get(1)?;
    let blob: Vec<u8> = row.get(2)?;
    let status_val: i64 = row.get(3)?;

    let ctx_owned = ContextOwned::default();
    let ctx = ctx_owned.context();
    let mut cursor = std::io::Cursor::new(blob);
    let mut val = DataValue::decode(&mut cursor, &ctx).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(e))
    })?;

    val.source_timestamp = Some(DateTime::from(source_ticks));
    val.server_timestamp = Some(DateTime::from(server_ticks));
    val.status = Some(opcua_types::StatusCode::from(status_val as u32));

    Ok(val)
}
