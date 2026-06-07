//! SQLite schema migrations for historical data storage.

use rusqlite::{Connection, Error};

/// Creates the historical data table and query index if they do not exist.
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
    Ok(())
}
