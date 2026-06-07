//! Query helpers for SQLite historical data reads.

use opcua_types::{BinaryDecodable, ContextOwned, DataValue, DateTime, StatusCode};
use rusqlite::{params, Connection, Error, OptionalExtension, Row};

/// Fetches the nearest historical value at or before/after `timestamp`.
pub fn fetch_bounds(
    conn: &Connection,
    node_id: &str,
    timestamp: i64,
    find_prev: bool,
) -> Result<Option<DataValue>, Error> {
    let query = if find_prev {
        "SELECT source_timestamp, server_timestamp, value_blob, status_code
         FROM historical_data
         WHERE node_id = ?1 AND source_timestamp <= ?2
         ORDER BY source_timestamp DESC
         LIMIT 1"
    } else {
        "SELECT source_timestamp, server_timestamp, value_blob, status_code
         FROM historical_data
         WHERE node_id = ?1 AND source_timestamp >= ?2
         ORDER BY source_timestamp ASC
         LIMIT 1"
    };

    conn.query_row(query, params![node_id, timestamp], row_to_datavalue)
        .optional()
}

/// Fetches historical values in a half-open interval using source timestamp order.
pub fn fetch_interval(
    conn: &Connection,
    node_id: &str,
    start_ticks: i64,
    end_ticks: i64,
    chronological: bool,
) -> Result<Vec<DataValue>, Error> {
    let query = if chronological {
        "SELECT source_timestamp, server_timestamp, value_blob, status_code
         FROM historical_data
         WHERE node_id = ?1 AND source_timestamp >= ?2 AND source_timestamp < ?3
         ORDER BY source_timestamp ASC"
    } else {
        "SELECT source_timestamp, server_timestamp, value_blob, status_code
         FROM historical_data
         WHERE node_id = ?1 AND source_timestamp <= ?2 AND source_timestamp > ?3
         ORDER BY source_timestamp DESC"
    };

    let mut stmt = conn.prepare(query)?;
    let rows = stmt.query_map(params![node_id, start_ticks, end_ticks], row_to_datavalue)?;
    rows.collect()
}

pub(crate) fn row_to_datavalue(row: &Row<'_>) -> Result<DataValue, Error> {
    let source_ticks: i64 = row.get(0)?;
    let server_ticks: i64 = row.get(1)?;
    let blob: Vec<u8> = row.get(2)?;
    let status_val: i64 = row.get(3)?;

    let ctx_owned = ContextOwned::default();
    let ctx = ctx_owned.context();
    let mut cursor = std::io::Cursor::new(blob);
    let mut value = DataValue::decode(&mut cursor, &ctx).map_err(|err| {
        Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(err))
    })?;

    value.source_timestamp = Some(DateTime::from(source_ticks));
    value.server_timestamp = Some(DateTime::from(server_ticks));
    value.status = Some(StatusCode::from(status_val as u32));

    Ok(value)
}
