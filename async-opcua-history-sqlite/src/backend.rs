//! SQLite implementation of the OPC UA history storage backend.

use crate::{migration::run_migrations, query};
use async_trait::async_trait;
use opcua_server::{
    aggregates::{compute_processed_intervals, engine::get_value_timestamp},
    history::{HistoryRawModifiedResult, HistoryStorageBackend},
};
use opcua_types::{
    AggregateConfiguration, Annotation, BinaryDecodable, BinaryEncodable, ByteString, ContextOwned,
    DataValue, DateTime, EventFilter, HistoryEventFieldList, HistoryUpdateType, ModificationInfo,
    NodeId, ObjectTypeId, PerformUpdateType, QualifiedName, SimpleAttributeOperand, StatusCode,
    UAString, Variant,
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
    cursor: HistoryReadCursor,
    created_at: Instant,
}

#[derive(Clone)]
struct HistoryReadCursor {
    node_id: NodeId,
    start_time: DateTime,
    end_time: DateTime,
    read_modified: bool,
    chronological: bool,
    return_bounds: bool,
    last_source_timestamp: i64,
    last_modification_time: i64,
    last_modified_rowid: i64,
}

struct RawModifiedPageRequest {
    node_id: String,
    start_ticks: i64,
    end_ticks: i64,
    chronological: bool,
    include_start_bound: bool,
    include_end_bound: bool,
    resume_after: Option<i64>,
    page_size: usize,
}

struct ModifiedPageRequest {
    node_id: String,
    start_ticks: i64,
    end_ticks: i64,
    resume_after: Option<ModifiedContinuationKey>,
    page_size: usize,
}

struct ModifiedPageRow {
    value: DataValue,
    modification_info: ModificationInfo,
    continuation_key: ModifiedContinuationKey,
}

#[derive(Clone, Copy)]
struct ModifiedContinuationKey {
    source_ticks: i64,
    modification_ticks: i64,
    rowid: i64,
}

type ModifiedPageResult = (
    Vec<DataValue>,
    Vec<ModificationInfo>,
    Option<ModifiedContinuationKey>,
);

const CONTINUATION_POINT_MAX_AGE: Duration = Duration::from_secs(300);

// OPC UA treats num_values_per_node == 0 as "return all". Keep that API
// behavior paged, but cap each SQL read so one request cannot scan forever.
const READ_RAW_MODIFIED_UNBOUNDED_HARD_LIMIT: usize = 100_000;
const EVENT_ID_FIELD_NAME: &str = "EventId";
const EVENT_TIME_FIELD_NAME: &str = "Time";

fn insert_modified_historical_data(
    tx: &rusqlite::Transaction<'_>,
    node_id: &str,
    source_ticks: i64,
    server_ticks: i64,
    value_blob: &[u8],
    status_val: i64,
    update_type: i64,
) -> Result<(), SqliteError> {
    tx.execute(
        "INSERT INTO modified_historical_data (
            node_id,
            source_timestamp,
            server_timestamp,
            value_blob,
            status_code,
            update_type,
            modification_time,
            user_name
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            node_id,
            source_ticks,
            server_ticks,
            value_blob,
            status_val,
            update_type,
            DateTime::now().ticks(),
            // ponytail: user is not threaded yet; optional field, pass session user later.
            ""
        ],
    )?;
    Ok(())
}

fn is_annotation_data_value(value: &DataValue) -> bool {
    matches!(
        value.value.as_ref(),
        Some(Variant::ExtensionObject(object)) if object.inner_as::<Annotation>().is_some()
    )
}

fn event_id_select_clause_index(filter: &EventFilter) -> Option<usize> {
    base_event_field_select_clause_index(filter, EVENT_ID_FIELD_NAME)
}

fn event_time_select_clause_index(filter: &EventFilter) -> Option<usize> {
    base_event_field_select_clause_index(filter, EVENT_TIME_FIELD_NAME)
}

fn base_event_field_select_clause_index(filter: &EventFilter, field_name: &str) -> Option<usize> {
    filter
        .select_clauses
        .as_deref()?
        .iter()
        .position(|clause| is_base_event_field_select_clause(clause, field_name))
}

fn is_base_event_field_select_clause(clause: &SimpleAttributeOperand, field_name: &str) -> bool {
    clause.type_definition_id == ObjectTypeId::BaseEventType
        && is_base_event_field_browse_path(clause.browse_path.as_deref(), field_name)
}

fn is_base_event_field_browse_path(
    browse_path: Option<&[QualifiedName]>,
    field_name: &str,
) -> bool {
    matches!(
        browse_path,
        Some([name]) if name.namespace_index == 0 && name.name.as_ref() == field_name
    )
}

fn event_id_bytes_from_field_list(
    event: &HistoryEventFieldList,
    event_id_index: usize,
) -> Option<Vec<u8>> {
    match event.event_fields.as_ref()?.get(event_id_index) {
        Some(Variant::ByteString(event_id)) => Some(event_id.as_ref().to_vec()),
        _ => None,
    }
}

fn event_time_from_field_list(
    event: &HistoryEventFieldList,
    event_time_index: Option<usize>,
) -> i64 {
    event_time_index
        .and_then(|index| event.event_fields.as_ref()?.get(index))
        .and_then(|field| match field {
            Variant::DateTime(time) => Some(time.ticks()),
            _ => None,
        })
        .unwrap_or(0)
}

fn encode_history_event_field_list(event: &HistoryEventFieldList) -> Vec<u8> {
    let ctx_owned = ContextOwned::default();
    let ctx = ctx_owned.context();
    event.encode_to_vec(&ctx)
}

fn row_to_history_event_field_list(
    row: &rusqlite::Row<'_>,
) -> Result<HistoryEventFieldList, SqliteError> {
    let blob: Vec<u8> = row.get(0)?;
    let ctx_owned = ContextOwned::default();
    let ctx = ctx_owned.context();
    let mut cursor = std::io::Cursor::new(blob);
    HistoryEventFieldList::decode(&mut cursor, &ctx)
        .map_err(|err| query::history_blob_decode_error(0, err))
}

fn map_history_read_sqlite_error(operation: &str, err: SqliteError) -> StatusCode {
    let status = if query::is_history_blob_decode_error(&err) {
        StatusCode::BadDataLost
    } else {
        StatusCode::BadInternalError
    };
    tracing::error!("SQLite error in {}: {:?}", operation, err);
    status
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

    /// Returns the underlying database connection.
    pub fn connection(&self) -> Arc<Mutex<Connection>> {
        self.connection.clone()
    }

    /// Reads processed aggregate values using the Part 13 default stepped interpolation.
    // Keep the concrete backend source-compatible for direct callers; the trait method carries
    // the per-variable Stepped value resolved by the server middleware.
    #[allow(clippy::too_many_arguments)]
    pub async fn read_processed(
        &self,
        node_id: &NodeId,
        start_time: DateTime,
        end_time: DateTime,
        processing_interval: f64,
        aggregate_type: &NodeId,
        aggregate_configuration: &AggregateConfiguration,
        continuation_point: Option<Vec<u8>>,
    ) -> Result<(Vec<DataValue>, Option<Vec<u8>>), StatusCode> {
        <Self as HistoryStorageBackend>::read_processed(
            self,
            node_id,
            start_time,
            end_time,
            processing_interval,
            aggregate_type,
            aggregate_configuration,
            true,
            continuation_point,
        )
        .await
    }

    fn prune_continuation_points(&self) {
        let mut cps = self.continuation_points.lock();
        cps.retain(|_, cp| cp.created_at.elapsed() < CONTINUATION_POINT_MAX_AGE);
    }

    fn page_size(num_values_per_node: u32) -> usize {
        if num_values_per_node == 0 {
            READ_RAW_MODIFIED_UNBOUNDED_HARD_LIMIT
        } else {
            num_values_per_node as usize
        }
    }

    fn insert_continuation_point(&self, cursor: HistoryReadCursor) -> Vec<u8> {
        let token = uuid::Uuid::new_v4().as_bytes().to_vec();
        self.continuation_points.lock().insert(
            token.clone(),
            CachedContinuationPoint {
                cursor,
                created_at: Instant::now(),
            },
        );
        token
    }

    async fn fetch_raw_modified_page(
        &self,
        cursor: &HistoryReadCursor,
        page_size: usize,
        resume_after: Option<i64>,
    ) -> Result<(Vec<DataValue>, bool), StatusCode> {
        let conn = self.connection.clone();
        let request = Self::raw_modified_page_request(cursor, page_size, resume_after);

        let result: Result<(Vec<DataValue>, bool), SqliteError> =
            tokio::task::spawn_blocking(move || Self::fetch_raw_modified_values(conn, request))
                .await
                .map_err(|_| StatusCode::BadInternalError)?;

        let (mut values, interval_has_more) =
            result.map_err(|err| map_history_read_sqlite_error("read_raw_modified", err))?;

        let has_trimmed_values = Self::sort_dedup_and_trim_page(
            &mut values,
            cursor.start_time,
            cursor.end_time,
            page_size,
        );
        Ok((values, interval_has_more || has_trimmed_values))
    }

    async fn fetch_modified_page(
        &self,
        cursor: &HistoryReadCursor,
        page_size: usize,
        resume_after: Option<ModifiedContinuationKey>,
    ) -> Result<ModifiedPageResult, StatusCode> {
        let conn = self.connection.clone();
        let request = Self::modified_page_request(cursor, page_size, resume_after);

        let result: Result<ModifiedPageResult, SqliteError> =
            tokio::task::spawn_blocking(move || Self::fetch_modified_values(conn, request))
                .await
                .map_err(|_| StatusCode::BadInternalError)?;

        result
            .map_err(|err| map_history_read_sqlite_error("read_raw_modified modified branch", err))
    }

    fn raw_modified_page_request(
        cursor: &HistoryReadCursor,
        page_size: usize,
        resume_after: Option<i64>,
    ) -> RawModifiedPageRequest {
        RawModifiedPageRequest {
            node_id: cursor.node_id.to_string(),
            start_ticks: cursor.start_time.ticks(),
            end_ticks: cursor.end_time.ticks(),
            chronological: cursor.chronological,
            include_start_bound: cursor.return_bounds && resume_after.is_none(),
            include_end_bound: cursor.return_bounds,
            resume_after,
            page_size,
        }
    }

    fn modified_page_request(
        cursor: &HistoryReadCursor,
        page_size: usize,
        resume_after: Option<ModifiedContinuationKey>,
    ) -> ModifiedPageRequest {
        ModifiedPageRequest {
            node_id: cursor.node_id.to_string(),
            start_ticks: cursor.start_time.ticks(),
            end_ticks: cursor.end_time.ticks(),
            resume_after,
            page_size,
        }
    }

    fn fetch_raw_modified_values(
        conn: Arc<Mutex<Connection>>,
        request: RawModifiedPageRequest,
    ) -> Result<(Vec<DataValue>, bool), SqliteError> {
        let conn = conn.lock();
        let query_limit = request.page_size.saturating_add(1);
        let mut values = Vec::with_capacity(query_limit);

        Self::push_start_bound(&conn, &request, &mut values)?;
        let interval_has_more =
            Self::push_interval_values(&conn, &request, query_limit, &mut values)?;
        Self::push_end_bound(&conn, &request, interval_has_more, &mut values)?;

        Ok((values, interval_has_more))
    }

    fn fetch_modified_values(
        conn: Arc<Mutex<Connection>>,
        request: ModifiedPageRequest,
    ) -> Result<ModifiedPageResult, SqliteError> {
        let conn = conn.lock();
        let query_limit = request.page_size.saturating_add(1);
        let resume_source_ticks = request.resume_after.map(|key| key.source_ticks);
        let resume_modification_ticks = request.resume_after.map(|key| key.modification_ticks);
        let resume_rowid = request.resume_after.map(|key| key.rowid);

        let mut stmt = conn.prepare(
            "SELECT source_timestamp,
                    server_timestamp,
                    value_blob,
                    status_code,
                    update_type,
                    modification_time,
                    user_name,
                    rowid
             FROM modified_historical_data
             WHERE node_id = ?1
               AND source_timestamp >= ?2
               AND source_timestamp < ?3
               AND (
                   ?4 IS NULL
                   OR source_timestamp > ?4
                   OR (source_timestamp = ?4 AND modification_time > ?5)
                   OR (source_timestamp = ?4 AND modification_time = ?5 AND rowid > ?6)
               )
             ORDER BY source_timestamp ASC, modification_time ASC, rowid ASC
             LIMIT ?7",
        )?;
        let rows = stmt.query_map(
            params![
                request.node_id,
                request.start_ticks,
                request.end_ticks,
                resume_source_ticks,
                resume_modification_ticks,
                resume_rowid,
                query_limit
            ],
            Self::row_to_modified_page_row,
        )?;

        let mut rows = rows.collect::<Result<Vec<_>, _>>()?;
        let has_more = rows.len() > request.page_size;
        if has_more {
            rows.truncate(request.page_size);
        }
        let continuation_key = if has_more {
            rows.last().map(|row| row.continuation_key)
        } else {
            None
        };

        let mut values = Vec::with_capacity(rows.len());
        let mut modification_infos = Vec::with_capacity(rows.len());
        for row in rows {
            values.push(row.value);
            modification_infos.push(row.modification_info);
        }

        Ok((values, modification_infos, continuation_key))
    }

    fn row_to_modified_page_row(row: &rusqlite::Row<'_>) -> Result<ModifiedPageRow, SqliteError> {
        let source_ticks: i64 = row.get(0)?;
        let value = query::row_to_datavalue(row)?;
        let update_type = Self::history_update_type_from_i64(row.get(4)?)?;
        let modification_ticks: i64 = row.get(5)?;
        let user_name: String = row.get(6)?;
        let rowid: i64 = row.get(7)?;

        Ok(ModifiedPageRow {
            value,
            modification_info: ModificationInfo {
                modification_time: DateTime::from(modification_ticks),
                update_type,
                user_name: UAString::from(user_name),
            },
            continuation_key: ModifiedContinuationKey {
                source_ticks,
                modification_ticks,
                rowid,
            },
        })
    }

    fn history_update_type_from_i64(update_type: i64) -> Result<HistoryUpdateType, SqliteError> {
        match update_type {
            1 => Ok(HistoryUpdateType::Insert),
            2 => Ok(HistoryUpdateType::Replace),
            3 => Ok(HistoryUpdateType::Update),
            4 => Ok(HistoryUpdateType::Delete),
            _ => Err(SqliteError::FromSqlConversionFailure(
                4,
                rusqlite::types::Type::Integer,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid HistoryUpdateType value {update_type}"),
                )),
            )),
        }
    }

    fn push_start_bound(
        conn: &Connection,
        request: &RawModifiedPageRequest,
        values: &mut Vec<DataValue>,
    ) -> Result<(), SqliteError> {
        if request.include_start_bound {
            let find_prev = request.chronological;
            if let Some(value) =
                query::fetch_bounds(conn, &request.node_id, request.start_ticks, find_prev)?
            {
                values.push(value);
            }
        }
        Ok(())
    }

    fn push_interval_values(
        conn: &Connection,
        request: &RawModifiedPageRequest,
        query_limit: usize,
        values: &mut Vec<DataValue>,
    ) -> Result<bool, SqliteError> {
        let interval_values = query::fetch_interval(
            conn,
            &request.node_id,
            request.start_ticks,
            request.end_ticks,
            request.chronological,
            request.resume_after,
            query_limit,
        )?;
        let interval_has_more = interval_values.len() > request.page_size;
        values.extend(interval_values);
        Ok(interval_has_more)
    }

    fn push_end_bound(
        conn: &Connection,
        request: &RawModifiedPageRequest,
        interval_has_more: bool,
        values: &mut Vec<DataValue>,
    ) -> Result<(), SqliteError> {
        if request.include_end_bound && !interval_has_more {
            let find_prev = !request.chronological;
            if let Some(value) =
                query::fetch_bounds(conn, &request.node_id, request.end_ticks, find_prev)?
            {
                values.push(value);
            }
        }
        Ok(())
    }

    fn sort_dedup_and_trim_page(
        values: &mut Vec<DataValue>,
        start_time: DateTime,
        end_time: DateTime,
        page_size: usize,
    ) -> bool {
        opcua_server::history::sort_historical_values(values, start_time, end_time);
        values.dedup_by(|a, b| a.source_timestamp == b.source_timestamp);

        let has_trimmed_values = values.len() > page_size;
        if has_trimmed_values {
            values.truncate(page_size);
        }

        has_trimmed_values
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
        is_read_modified: bool,
        continuation_point: Option<Vec<u8>>,
    ) -> Result<HistoryRawModifiedResult, StatusCode> {
        self.prune_continuation_points();
        let page_size = Self::page_size(num_values_per_node);

        let (cursor, resume_after) = if let Some(token) = continuation_point {
            let cp = self
                .continuation_points
                .lock()
                .remove(&token)
                .ok_or(StatusCode::BadContinuationPointInvalid)?;
            let resume_after = Some(cp.cursor.last_source_timestamp);
            (cp.cursor, resume_after)
        } else {
            let chronological = start_time.ticks() < end_time.ticks();
            (
                HistoryReadCursor {
                    node_id: node_id.clone(),
                    start_time,
                    end_time,
                    read_modified: is_read_modified,
                    chronological,
                    return_bounds,
                    last_source_timestamp: start_time.ticks(),
                    last_modification_time: 0,
                    last_modified_rowid: 0,
                },
                None,
            )
        };

        if cursor.read_modified {
            let modified_resume_after = resume_after.map(|source_ticks| ModifiedContinuationKey {
                source_ticks,
                modification_ticks: cursor.last_modification_time,
                rowid: cursor.last_modified_rowid,
            });
            let (values, modification_infos, continuation_key) = self
                .fetch_modified_page(&cursor, page_size, modified_resume_after)
                .await?;

            if let Some(continuation_key) = continuation_key {
                let token = self.insert_continuation_point(HistoryReadCursor {
                    last_source_timestamp: continuation_key.source_ticks,
                    last_modification_time: continuation_key.modification_ticks,
                    last_modified_rowid: continuation_key.rowid,
                    ..cursor
                });
                Ok((values, modification_infos, Some(token)))
            } else {
                Ok((values, modification_infos, None))
            }
        } else {
            let (values, has_more) = self
                .fetch_raw_modified_page(&cursor, page_size, resume_after)
                .await?;

            if has_more {
                let Some(last_value) = values.last() else {
                    return Ok((values, Vec::new(), None));
                };
                let Some(last_source_timestamp) = last_value.source_timestamp.map(|ts| ts.ticks())
                else {
                    return Ok((values, Vec::new(), None));
                };

                let token = self.insert_continuation_point(HistoryReadCursor {
                    last_source_timestamp,
                    ..cursor
                });
                Ok((values, Vec::new(), Some(token)))
            } else {
                Ok((values, Vec::new(), None))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn read_processed(
        &self,
        node_id: &NodeId,
        start_time: DateTime,
        end_time: DateTime,
        processing_interval: f64,
        aggregate_type: &NodeId,
        aggregate_configuration: &AggregateConfiguration,
        stepped: bool,
        continuation_point: Option<Vec<u8>>,
    ) -> Result<(Vec<DataValue>, Option<Vec<u8>>), StatusCode> {
        if continuation_point.is_some() {
            return Err(StatusCode::BadContinuationPointInvalid);
        }

        let mut raw_values = Vec::new();
        let mut next_token = None;
        loop {
            let (values, _modification_infos, token) = self
                .read_raw_modified(
                    node_id, start_time, end_time, 100_000, true, false, next_token,
                )
                .await?;
            raw_values.extend(values);

            let Some(token) = token else {
                break;
            };
            next_token = Some(token);
        }

        raw_values.sort_by_key(get_value_timestamp);

        let annotation_times: Vec<DateTime> = if aggregate_type == &NodeId::new(0u16, 2351u32) {
            match self.read_annotations(node_id, &[], None).await {
                Ok((dvs, _)) => {
                    let mut timestamps: Vec<DateTime> = dvs
                        .iter()
                        .map(get_value_timestamp)
                        .filter(|timestamp| *timestamp >= start_time && *timestamp <= end_time)
                        .collect();
                    timestamps.sort();
                    timestamps
                }
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        };

        let processed_values = compute_processed_intervals(
            &raw_values,
            aggregate_type,
            aggregate_configuration,
            start_time,
            end_time,
            processing_interval,
            stepped,
            &annotation_times,
        );

        Ok((processed_values, None))
    }

    async fn read_events(
        &self,
        node_id: &NodeId,
        _start_time: DateTime,
        _end_time: DateTime,
        num_values_per_node: u32,
        _filter: &EventFilter,
        continuation_point: Option<Vec<u8>>,
    ) -> Result<(Vec<HistoryEventFieldList>, Option<Vec<u8>>), StatusCode> {
        if continuation_point.is_some() {
            return Err(StatusCode::BadContinuationPointInvalid);
        }

        let conn = self.connection.clone();
        let node_id_str = node_id.to_string();
        let row_limit = if num_values_per_node > 0 {
            num_values_per_node as i64
        } else {
            i64::MAX
        };

        let events: Result<Vec<HistoryEventFieldList>, SqliteError> =
            tokio::task::spawn_blocking(move || {
                let conn = conn.lock();
                let mut stmt = conn.prepare(
                    "SELECT field_blob
                     FROM historical_events
                     WHERE node_id = ?1
                     ORDER BY event_time ASC, rowid ASC
                     LIMIT ?2",
                )?;
                // ponytail: inserted events are returned with the written field shape, without
                // cross-filter re-evaluation, matching the in-memory backend.
                let rows = stmt.query_map(
                    params![node_id_str, row_limit],
                    row_to_history_event_field_list,
                )?;
                rows.collect()
            })
            .await
            .map_err(|_| StatusCode::BadInternalError)?;

        events
            .map(|events| (events, None))
            .map_err(|err| map_history_read_sqlite_error("read_events", err))
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

        let conn = self.connection.clone();
        let node_id_str = node_id.to_string();
        let req_ticks = req_times
            .iter()
            .map(|timestamp| timestamp.ticks())
            .collect::<Vec<_>>();

        let values: Result<Vec<DataValue>, SqliteError> = tokio::task::spawn_blocking(move || {
            let conn = conn.lock();

            if req_ticks.is_empty() {
                let mut stmt = conn.prepare(
                    "SELECT source_timestamp, server_timestamp, value_blob, status_code
                         FROM historical_annotations
                         WHERE node_id = ?1
                         ORDER BY source_timestamp ASC",
                )?;
                let rows = stmt.query_map(params![node_id_str], query::row_to_datavalue)?;
                rows.collect()
            } else {
                let mut stmt = conn.prepare(
                    "SELECT source_timestamp, server_timestamp, value_blob, status_code
                         FROM historical_annotations
                         WHERE node_id = ?1 AND source_timestamp = ?2",
                )?;
                let mut values = Vec::with_capacity(req_ticks.len());
                for source_ticks in req_ticks {
                    if let Some(value) = stmt
                        .query_row(params![&node_id_str, source_ticks], query::row_to_datavalue)
                        .optional()?
                    {
                        values.push(value);
                    }
                }
                Ok(values)
            }
        })
        .await
        .map_err(|_| StatusCode::BadInternalError)?;

        values
            .map(|values| (values, None))
            .map_err(|err| map_history_read_sqlite_error("read_annotations", err))
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

                    let existing = tx
                        .query_row(
                            "SELECT server_timestamp, value_blob, status_code FROM historical_data
                         WHERE node_id = ?1 AND source_timestamp = ?2",
                            params![node_id_str, source_ticks],
                            |row| {
                                Ok((
                                    row.get::<_, i64>(0)?,
                                    row.get::<_, Vec<u8>>(1)?,
                                    row.get::<_, i64>(2)?,
                                ))
                            },
                        )
                        .optional()?;

                    match perform_insert_replace {
                        PerformUpdateType::Insert => {
                            if existing.is_some() {
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
                            if let Some((old_server_ticks, old_blob, old_status_val)) = existing {
                                insert_modified_historical_data(
                                    &tx,
                                    &node_id_str,
                                    source_ticks,
                                    old_server_ticks,
                                    &old_blob,
                                    old_status_val,
                                    2,
                                )?;
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
                            if let Some((old_server_ticks, old_blob, old_status_val)) = existing {
                                insert_modified_historical_data(
                                    &tx,
                                    &node_id_str,
                                    source_ticks,
                                    old_server_ticks,
                                    &old_blob,
                                    old_status_val,
                                    3,
                                )?;
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
                        PerformUpdateType::Remove => {
                            if let Some((old_server_ticks, old_blob, old_status_val)) = existing {
                                insert_modified_historical_data(
                                    &tx,
                                    &node_id_str,
                                    source_ticks,
                                    old_server_ticks,
                                    &old_blob,
                                    old_status_val,
                                    4,
                                )?;
                                tx.execute(
                                    "DELETE FROM historical_data
                                 WHERE node_id = ?1 AND source_timestamp = ?2",
                                    params![node_id_str, source_ticks],
                                )?;
                                status_codes.push(StatusCode::Good);
                            } else {
                                status_codes.push(StatusCode::BadNoEntryExists);
                            }
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

    async fn update_structure_data(
        &self,
        node_id: &NodeId,
        perform: PerformUpdateType,
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
                    if !is_annotation_data_value(&value) {
                        status_codes.push(StatusCode::BadTypeMismatch);
                        continue;
                    }

                    let source_ticks = value.source_timestamp.unwrap_or_else(DateTime::now).ticks();
                    let server_ticks = value.server_timestamp.unwrap_or_else(DateTime::now).ticks();
                    let status_val = value.status.map(|status| status.bits() as i64).unwrap_or(0);

                    let ctx_owned = ContextOwned::default();
                    let ctx = ctx_owned.context();
                    let blob = value.encode_to_vec(&ctx);

                    let existing = tx
                        .query_row(
                            "SELECT 1 FROM historical_annotations
                             WHERE node_id = ?1 AND source_timestamp = ?2",
                            params![node_id_str, source_ticks],
                            |_| Ok(()),
                        )
                        .optional()?;

                    match perform {
                        PerformUpdateType::Insert => {
                            if existing.is_some() {
                                status_codes.push(StatusCode::BadEntryExists);
                            } else {
                                tx.execute(
                                    "INSERT INTO historical_annotations (
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
                            if existing.is_some() {
                                tx.execute(
                                    "UPDATE historical_annotations
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
                            if existing.is_some() {
                                tx.execute(
                                    "UPDATE historical_annotations
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
                                    "INSERT INTO historical_annotations (
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
                        PerformUpdateType::Remove => {
                            if existing.is_some() {
                                tx.execute(
                                    "DELETE FROM historical_annotations
                                     WHERE node_id = ?1 AND source_timestamp = ?2",
                                    params![node_id_str, source_ticks],
                                )?;
                                status_codes.push(StatusCode::Good);
                            } else {
                                status_codes.push(StatusCode::BadNoEntryExists);
                            }
                        }
                    }
                }

                tx.commit()?;
                Ok(status_codes)
            })
            .await
            .map_err(|_| StatusCode::BadInternalError)?;

        results.map_err(|err| {
            tracing::error!("SQLite error in update_structure_data: {:?}", err);
            StatusCode::BadInternalError
        })
    }

    async fn update_event(
        &self,
        node_id: &NodeId,
        filter: &EventFilter,
        events: Vec<HistoryEventFieldList>,
        perform: PerformUpdateType,
    ) -> Result<Vec<StatusCode>, StatusCode> {
        self.prune_continuation_points();

        if events.is_empty() {
            return Ok(Vec::new());
        }

        let Some(event_id_index) = event_id_select_clause_index(filter) else {
            return Ok(vec![StatusCode::BadInvalidArgument; events.len()]);
        };
        let event_time_index = event_time_select_clause_index(filter);

        let conn = self.connection.clone();
        let node_id_str = node_id.to_string();

        let results: Result<Vec<StatusCode>, SqliteError> =
            tokio::task::spawn_blocking(move || {
                let mut conn = conn.lock();
                let tx = conn.transaction()?;
                let mut status_codes = Vec::with_capacity(events.len());

                for event in events {
                    let Some(event_id) = event_id_bytes_from_field_list(&event, event_id_index)
                    else {
                        status_codes.push(StatusCode::BadInvalidArgument);
                        continue;
                    };

                    let field_blob = encode_history_event_field_list(&event);
                    let event_time = event_time_from_field_list(&event, event_time_index);
                    let existing = tx
                        .query_row(
                            "SELECT 1 FROM historical_events
                             WHERE node_id = ?1 AND event_id = ?2",
                            params![node_id_str, &event_id],
                            |_| Ok(()),
                        )
                        .optional()?;

                    match perform {
                        PerformUpdateType::Insert => {
                            if existing.is_some() {
                                status_codes.push(StatusCode::BadEntryExists);
                            } else {
                                tx.execute(
                                    "INSERT INTO historical_events (
                                        node_id,
                                        event_id,
                                        field_blob,
                                        event_time
                                    ) VALUES (?1, ?2, ?3, ?4)",
                                    params![node_id_str, &event_id, field_blob, event_time],
                                )?;
                                status_codes.push(StatusCode::GoodEntryInserted);
                            }
                        }
                        PerformUpdateType::Replace => {
                            if existing.is_some() {
                                tx.execute(
                                    "UPDATE historical_events
                                     SET field_blob = ?3,
                                         event_time = ?4
                                     WHERE node_id = ?1 AND event_id = ?2",
                                    params![node_id_str, &event_id, field_blob, event_time],
                                )?;
                                status_codes.push(StatusCode::GoodEntryReplaced);
                            } else {
                                status_codes.push(StatusCode::BadNoEntryExists);
                            }
                        }
                        PerformUpdateType::Update => {
                            if existing.is_some() {
                                tx.execute(
                                    "UPDATE historical_events
                                     SET field_blob = ?3,
                                         event_time = ?4
                                     WHERE node_id = ?1 AND event_id = ?2",
                                    params![node_id_str, &event_id, field_blob, event_time],
                                )?;
                                status_codes.push(StatusCode::GoodEntryReplaced);
                            } else {
                                tx.execute(
                                    "INSERT INTO historical_events (
                                        node_id,
                                        event_id,
                                        field_blob,
                                        event_time
                                    ) VALUES (?1, ?2, ?3, ?4)",
                                    params![node_id_str, &event_id, field_blob, event_time],
                                )?;
                                status_codes.push(StatusCode::GoodEntryInserted);
                            }
                        }
                        PerformUpdateType::Remove => {
                            if existing.is_some() {
                                tx.execute(
                                    "DELETE FROM historical_events
                                     WHERE node_id = ?1 AND event_id = ?2",
                                    params![node_id_str, &event_id],
                                )?;
                                status_codes.push(StatusCode::Good);
                            } else {
                                status_codes.push(StatusCode::BadNoEntryExists);
                            }
                        }
                    }
                }

                tx.commit()?;
                Ok(status_codes)
            })
            .await
            .map_err(|_| StatusCode::BadInternalError)?;

        results.map_err(|err| {
            tracing::error!("SQLite error in update_event: {:?}", err);
            StatusCode::BadInternalError
        })
    }

    async fn delete_raw_modified(
        &self,
        node_id: &NodeId,
        is_delete_modified: bool,
        start_time: DateTime,
        end_time: DateTime,
    ) -> Result<StatusCode, StatusCode> {
        self.prune_continuation_points();

        let conn = self.connection.clone();
        let node_id_str = node_id.to_string();
        let start_ticks = start_time.ticks();
        let end_ticks = end_time.ticks();

        let deleted_count: Result<usize, SqliteError> = tokio::task::spawn_blocking(move || {
            let mut conn = conn.lock();
            let tx = conn.transaction()?;

            let deleted_count = if start_ticks >= end_ticks {
                0
            } else if is_delete_modified {
                tx.execute(
                    "DELETE FROM modified_historical_data
                     WHERE node_id = ?1
                       AND source_timestamp >= ?2
                       AND source_timestamp < ?3",
                    params![node_id_str, start_ticks, end_ticks],
                )?
            } else {
                let rows = {
                    let mut stmt = tx.prepare(
                        "SELECT source_timestamp, server_timestamp, value_blob, status_code
                         FROM historical_data
                         WHERE node_id = ?1
                           AND source_timestamp >= ?2
                           AND source_timestamp < ?3",
                    )?;
                    let rows =
                        stmt.query_map(params![node_id_str, start_ticks, end_ticks], |row| {
                            Ok((
                                row.get::<_, i64>(0)?,
                                row.get::<_, i64>(1)?,
                                row.get::<_, Vec<u8>>(2)?,
                                row.get::<_, i64>(3)?,
                            ))
                        })?;
                    rows.collect::<Result<Vec<_>, _>>()?
                };

                for (source_ticks, server_ticks, value_blob, status_val) in &rows {
                    insert_modified_historical_data(
                        &tx,
                        &node_id_str,
                        *source_ticks,
                        *server_ticks,
                        value_blob,
                        *status_val,
                        4,
                    )?;
                }

                tx.execute(
                    "DELETE FROM historical_data
                     WHERE node_id = ?1
                       AND source_timestamp >= ?2
                       AND source_timestamp < ?3",
                    params![node_id_str, start_ticks, end_ticks],
                )?
            };

            tx.commit()?;
            Ok(deleted_count)
        })
        .await
        .map_err(|_| StatusCode::BadInternalError)?;

        deleted_count
            .map(|count| {
                if count > 0 {
                    StatusCode::Good
                } else {
                    StatusCode::BadNoData
                }
            })
            .map_err(|err| {
                tracing::error!("SQLite error in delete_raw_modified: {:?}", err);
                StatusCode::BadInternalError
            })
    }

    async fn delete_at_time(
        &self,
        node_id: &NodeId,
        req_times: Vec<DateTime>,
    ) -> Result<Vec<StatusCode>, StatusCode> {
        self.prune_continuation_points();

        let conn = self.connection.clone();
        let node_id_str = node_id.to_string();

        let results: Result<Vec<StatusCode>, SqliteError> =
            tokio::task::spawn_blocking(move || {
                let mut conn = conn.lock();
                let tx = conn.transaction()?;
                let mut status_codes = Vec::with_capacity(req_times.len());

                for req_time in req_times {
                    let source_ticks = req_time.ticks();
                    let existing = tx
                        .query_row(
                            "SELECT server_timestamp, value_blob, status_code FROM historical_data
                             WHERE node_id = ?1 AND source_timestamp = ?2",
                            params![node_id_str, source_ticks],
                            |row| {
                                Ok((
                                    row.get::<_, i64>(0)?,
                                    row.get::<_, Vec<u8>>(1)?,
                                    row.get::<_, i64>(2)?,
                                ))
                            },
                        )
                        .optional()?;

                    if let Some((server_ticks, value_blob, status_val)) = existing {
                        insert_modified_historical_data(
                            &tx,
                            &node_id_str,
                            source_ticks,
                            server_ticks,
                            &value_blob,
                            status_val,
                            4,
                        )?;
                        tx.execute(
                            "DELETE FROM historical_data
                             WHERE node_id = ?1 AND source_timestamp = ?2",
                            params![node_id_str, source_ticks],
                        )?;
                        status_codes.push(StatusCode::Good);
                    } else {
                        status_codes.push(StatusCode::BadNoEntryExists);
                    }
                }

                tx.commit()?;
                Ok(status_codes)
            })
            .await
            .map_err(|_| StatusCode::BadInternalError)?;

        results.map_err(|err| {
            tracing::error!("SQLite error in delete_at_time: {:?}", err);
            StatusCode::BadInternalError
        })
    }

    async fn delete_event(
        &self,
        node_id: &NodeId,
        event_ids: Vec<ByteString>,
    ) -> Result<Vec<StatusCode>, StatusCode> {
        self.prune_continuation_points();

        if event_ids.is_empty() {
            return Ok(Vec::new());
        }

        let conn = self.connection.clone();
        let node_id_str = node_id.to_string();

        let results: Result<Vec<StatusCode>, SqliteError> =
            tokio::task::spawn_blocking(move || {
                let mut conn = conn.lock();
                let tx = conn.transaction()?;
                let mut status_codes = Vec::with_capacity(event_ids.len());

                for event_id in event_ids {
                    let event_id_bytes = event_id.as_ref();
                    let existing = tx
                        .query_row(
                            "SELECT 1 FROM historical_events
                             WHERE node_id = ?1 AND event_id = ?2",
                            params![node_id_str, event_id_bytes],
                            |_| Ok(()),
                        )
                        .optional()?;

                    if existing.is_some() {
                        tx.execute(
                            "DELETE FROM historical_events
                             WHERE node_id = ?1 AND event_id = ?2",
                            params![node_id_str, event_id_bytes],
                        )?;
                        status_codes.push(StatusCode::Good);
                    } else {
                        status_codes.push(StatusCode::BadNoEntryExists);
                    }
                }

                tx.commit()?;
                Ok(status_codes)
            })
            .await
            .map_err(|_| StatusCode::BadInternalError)?;

        results.map_err(|err| {
            tracing::error!("SQLite error in delete_event: {:?}", err);
            StatusCode::BadInternalError
        })
    }

    async fn release_continuation_point(&self, token: Vec<u8>) -> Result<(), StatusCode> {
        self.continuation_points.lock().remove(&token);
        Ok(())
    }
}
