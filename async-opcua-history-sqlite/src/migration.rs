//! SQLite schema migrations for historical data storage.

use rusqlite::{Connection, Error};

/// Creates the historical data tables and query indexes if they do not exist.
pub fn run_migrations(conn: &Connection) -> Result<(), Error> {
    conn.execute(
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
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_historical_data_query
         ON historical_data (node_id, source_timestamp ASC)",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS modified_historical_data (
            node_id TEXT NOT NULL,
            source_timestamp INTEGER NOT NULL,
            server_timestamp INTEGER NOT NULL,
            value_blob BLOB NOT NULL,
            status_code INTEGER NOT NULL,
            update_type INTEGER NOT NULL,
            modification_time INTEGER NOT NULL,
            user_name TEXT NOT NULL
        )",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_modified_historical_data_query
         ON modified_historical_data (node_id, source_timestamp ASC, modification_time ASC)",
        [],
    )?;
    Ok(())
}
