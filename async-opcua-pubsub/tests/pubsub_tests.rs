//! Integration tests for PubSub transport mapping lifecycle configuration.

use std::sync::Arc;
use std::time::Duration;

use opcua_core::sync::RwLock;
use opcua_pubsub::{
    MessageEncoding, PubSubConnectionConfig, PubSubEngine, TransportKind, UadpNetworkMessage,
    WriterGroupConfig,
};
use opcua_server::address_space::AddressSpace;
use opcua_types::{BinaryDecodable, ContextOwned, DecodingOptions, NamespaceMap, StatusCode};

fn address_space() -> Arc<RwLock<AddressSpace>> {
    Arc::new(RwLock::new(AddressSpace::new()))
}

fn connection(connection_id: &str, address: &str) -> PubSubConnectionConfig {
    PubSubConnectionConfig {
        reader_groups: Vec::new(),
        connection_id: connection_id.to_string(),
        name: connection_id.to_string(),
        address: address.to_string(),
        writer_groups: vec![WriterGroupConfig {
            writer_group_id: 1,
            publishing_interval: 10,
            encoding: MessageEncoding::Json,
            dataset_writers: Vec::new(),
        }],
    }
}

async fn assert_engine_lifecycle(connection: PubSubConnectionConfig, expected: TransportKind) {
    assert_eq!(
        TransportKind::from_address(&connection.address).unwrap(),
        expected
    );

    let mut engine = PubSubEngine::with_connections(address_space(), vec![connection.clone()]);

    assert_eq!(engine.connection_configs(), &[connection]);
    assert!(!engine.is_running());
    assert_eq!(engine.active_handle_count(), 0);

    engine.start().unwrap();

    assert!(engine.is_running());
    assert_eq!(engine.active_handle_count(), 1);

    tokio::time::timeout(Duration::from_secs(1), engine.stop())
        .await
        .unwrap();

    assert!(!engine.is_running());
    assert_eq!(engine.active_handle_count(), 0);
}

#[tokio::test]
async fn starts_and_stops_mqtt_pubsub_connection() {
    assert_engine_lifecycle(
        connection("mqtt-pubsub", "mqtt://127.0.0.1:1"),
        TransportKind::Mqtt,
    )
    .await;
}

#[tokio::test]
async fn starts_and_stops_udp_pubsub_connection() {
    assert_engine_lifecycle(
        connection("udp-pubsub", "udp://127.0.0.1:4840"),
        TransportKind::Udp,
    )
    .await;
}

#[tokio::test]
async fn starts_and_stops_amqp_pubsub_connection() {
    assert_engine_lifecycle(
        connection("amqp-pubsub", "amqp://127.0.0.1:1/opcua.telemetry"),
        TransportKind::Amqp,
    )
    .await;
}

#[tokio::test]
async fn starts_and_stops_websocket_pubsub_connection() {
    assert_engine_lifecycle(
        connection("websocket-pubsub", "ws://127.0.0.1:1/opcua"),
        TransportKind::WebSocket,
    )
    .await;
}

#[test]
fn uadp_dataset_message_rejects_field_count_above_decoding_limit() {
    let options = DecodingOptions {
        max_dataset_fields: 8,
        ..DecodingOptions::test()
    };
    let ctx_owned = ContextOwned::new_default(NamespaceMap::new(), options);
    let ctx = ctx_owned.context();

    let payload = [
        0x61, // UADP v1 + GroupHeader + PayloadHeader
        0x0f, // GroupFlags: WriterGroupId + GroupVersion + NetworkMessageNumber + SequenceNumber
        0x01, 0x00, // writer_group_id
        0x00, 0x00, 0x00, 0x00, // group_version
        0x00, 0x00, // network_message_number
        0x01, 0x00, // NetworkMessage-level sequence_number
        0x01, // dataset_writer_count
        0x65, 0x00, // payload header dataset_writer_id (not repeated in the body)
        0x09, // valid + sequence number enabled
        0x01, 0x00, // dataset message sequence_number
        0xff, 0xff, // field_count: 65535
    ];

    let err = UadpNetworkMessage::decode(&mut &payload[..], &ctx)
        .expect_err("oversized UADP field_count must be rejected before allocation");

    assert_eq!(err.status(), StatusCode::BadDecodingError);
    let err = err.to_string();
    assert!(
        err.contains("field_count") && err.contains("max_dataset_fields"),
        "expected field-count limit error, got {err}"
    );
}
