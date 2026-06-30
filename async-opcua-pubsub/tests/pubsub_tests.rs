//! Integration tests for PubSub transport mapping lifecycle configuration.

use std::sync::Arc;
use std::time::Duration;

use opcua_core::sync::RwLock;
use opcua_pubsub::{
    DataSetReaderConfig, MessageEncoding, PubSubConnectionConfig, PubSubEngine, ReaderGroupConfig,
    SubscriberRuntime, TransportKind, UadpNetworkMessage, WriterGroupConfig,
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

fn subscriber_connection(reader_id: u16) -> PubSubConnectionConfig {
    PubSubConnectionConfig {
        reader_groups: vec![ReaderGroupConfig {
            reader_group_id: 1,
            dataset_readers: vec![DataSetReaderConfig {
                dataset_reader_id: reader_id,
                dataset_writer_id: 42,
                ..DataSetReaderConfig::default()
            }],
            ..ReaderGroupConfig::default()
        }],
        connection_id: "subscriber".to_string(),
        name: "subscriber".to_string(),
        address: "udp://127.0.0.1:4840".to_string(),
        writer_groups: Vec::new(),
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

fn assert_malformed_uadp_datagram_decode_rejected(
    payload: &[u8],
    options: DecodingOptions,
    expected_error_fragments: &[&str],
) {
    let ctx_owned = ContextOwned::new_default(NamespaceMap::new(), options);
    let ctx = ctx_owned.context();

    let err = UadpNetworkMessage::decode(&mut &payload[..], &ctx)
        .expect_err("malformed UADP datagram must be rejected during decode");

    assert_eq!(err.status(), StatusCode::BadDecodingError);

    let err = err.to_string();
    for fragment in expected_error_fragments {
        assert!(
            err.contains(fragment),
            "expected decode error to contain {fragment:?}, got {err}"
        );
    }
}

fn assert_malformed_uadp_datagram_subscriber_state_unchanged(
    payload: &[u8],
    options: DecodingOptions,
) {
    const READER_ID: u16 = 1;

    let ctx_owned = ContextOwned::new_default(NamespaceMap::new(), options);
    let ctx = ctx_owned.context();
    let mut runtime = SubscriberRuntime::with_connections(
        address_space(),
        vec![subscriber_connection(READER_ID)],
    )
    .expect("subscriber test fixture must be valid");

    let before = runtime
        .reader_status(READER_ID)
        .expect("subscriber test fixture must expose reader status");

    assert!(
        runtime.process_datagram(payload, &ctx).is_err(),
        "malformed UADP datagram must be rejected before subscriber state can change"
    );

    let after = runtime
        .reader_status(READER_ID)
        .expect("subscriber test fixture must expose reader status");
    assert_eq!(
        after, before,
        "malformed UADP datagram must not change subscriber status"
    );
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
fn uadp_network_message_rejects_invalid_flag_before_subscriber_state_update() {
    let payload = [
        0xe1, // UADP v1 + ExtendedFlags1 + GroupHeader + PayloadHeader
        0x40, // ExtendedFlags1: PicoSeconds enabled while Timestamp is false
        0x0f, // GroupFlags: WriterGroupId + GroupVersion + NetworkMessageNumber + SequenceNumber
        0x01, 0x00, // writer_group_id
        0x00, 0x00, 0x00, 0x00, // group_version
        0x00, 0x00, // network_message_number
        0x01, 0x00, // NetworkMessage-level sequence_number
        0x01, // dataset_writer_count
        0x2a, 0x00, // payload header dataset_writer_id
        0x09, // valid + sequence number enabled
        0x01, 0x00, // dataset message sequence_number
        0x00, 0x00, // field_count
    ];

    assert_malformed_uadp_datagram_subscriber_state_unchanged(&payload, DecodingOptions::test());
    assert_malformed_uadp_datagram_decode_rejected(
        &payload,
        DecodingOptions::test(),
        &["ExtendedFlags1", "PicoSeconds", "Timestamp"],
    );
}

#[test]
fn uadp_dataset_message_rejects_field_count_above_decoding_limit() {
    let options = DecodingOptions {
        max_dataset_fields: 8,
        ..DecodingOptions::test()
    };
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

    assert_malformed_uadp_datagram_decode_rejected(
        &payload,
        options,
        &["field_count", "max_dataset_fields"],
    );

    let options = DecodingOptions {
        max_dataset_fields: 8,
        ..DecodingOptions::test()
    };
    assert_malformed_uadp_datagram_subscriber_state_unchanged(&payload, options);
}

#[test]
fn uadp_network_message_rejects_dataset_message_count_above_decoding_limit() {
    let options = DecodingOptions {
        max_dataset_messages: 1,
        ..DecodingOptions::test()
    };
    let payload = [
        0x61, // UADP v1 + GroupHeader + PayloadHeader
        0x0f, // GroupFlags: WriterGroupId + GroupVersion + NetworkMessageNumber + SequenceNumber
        0x01, 0x00, // writer_group_id
        0x00, 0x00, 0x00, 0x00, // group_version
        0x00, 0x00, // network_message_number
        0x01, 0x00, // NetworkMessage-level sequence_number
        0x02, // dataset_writer_count exceeds max_dataset_messages
    ];

    assert_malformed_uadp_datagram_decode_rejected(
        &payload,
        options,
        &["dataset message count", "max_dataset_messages"],
    );

    let options = DecodingOptions {
        max_dataset_messages: 1,
        ..DecodingOptions::test()
    };
    assert_malformed_uadp_datagram_subscriber_state_unchanged(&payload, options);
}
