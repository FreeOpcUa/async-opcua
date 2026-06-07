//! SQLite history migration and query behavior tests.

use opcua_history_sqlite::{
    migration::run_migrations,
    query::{fetch_bounds, fetch_interval},
};
use opcua_types::{BinaryEncodable, ContextOwned, DataValue, DateTime, StatusCode, Variant};
use rusqlite::{params, Connection};

fn insert_value(conn: &Connection, node_id: &str, ticks: i64, value: f64) {
    let data_value = DataValue::new_at(Variant::from(value), DateTime::from(ticks));
    let ctx_owned = ContextOwned::default();
    let blob = data_value.encode_to_vec(&ctx_owned.context());

    conn.execute(
        "INSERT INTO historical_data (
            node_id,
            source_timestamp,
            server_timestamp,
            value_blob,
            status_code
        ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![node_id, ticks, ticks, blob, StatusCode::Good.bits() as i64],
    )
    .expect("insert historical data");
}

fn source_ticks(value: &DataValue) -> i64 {
    value.source_timestamp.expect("source timestamp").ticks()
}

#[test]
fn run_migrations_creates_historical_data_table_and_query_index() {
    let conn = Connection::open_in_memory().expect("open database");

    run_migrations(&conn).expect("run migrations");

    let table_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'historical_data'",
            [],
            |row| row.get(0),
        )
        .expect("query table");
    let index_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_historical_data_query'",
            [],
            |row| row.get(0),
        )
        .expect("query index");

    assert_eq!(table_count, 1);
    assert_eq!(index_count, 1);
}

#[test]
fn fetch_interval_uses_half_open_bounds_and_requested_order() {
    let conn = Connection::open_in_memory().expect("open database");
    run_migrations(&conn).expect("run migrations");
    let node_id = "ns=2;s=Temperature";
    for ticks in [100_i64, 200, 300] {
        insert_value(&conn, node_id, ticks, ticks as f64);
    }

    let forward = fetch_interval(&conn, node_id, 100, 300, true).expect("fetch forward interval");
    let reverse = fetch_interval(&conn, node_id, 300, 100, false).expect("fetch reverse interval");

    assert_eq!(
        forward.iter().map(source_ticks).collect::<Vec<_>>(),
        vec![100, 200]
    );
    assert_eq!(
        reverse.iter().map(source_ticks).collect::<Vec<_>>(),
        vec![300, 200]
    );
}

#[test]
fn fetch_bounds_finds_adjacent_values() {
    let conn = Connection::open_in_memory().expect("open database");
    run_migrations(&conn).expect("run migrations");
    let node_id = "ns=2;s=Temperature";
    for ticks in [100_i64, 200, 300] {
        insert_value(&conn, node_id, ticks, ticks as f64);
    }

    let previous = fetch_bounds(&conn, node_id, 250, true)
        .expect("fetch previous bound")
        .expect("previous bound");
    let next = fetch_bounds(&conn, node_id, 250, false)
        .expect("fetch next bound")
        .expect("next bound");

    assert_eq!(source_ticks(&previous), 200);
    assert_eq!(source_ticks(&next), 300);
}
