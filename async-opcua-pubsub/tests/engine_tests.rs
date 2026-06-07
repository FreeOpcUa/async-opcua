//! PubSub engine coordinator tests.

use std::sync::Arc;

use opcua_core::sync::RwLock;
use opcua_pubsub::{
    engine::PubSubEngine, PubSubConnectionConfig, TransportKind, WriterGroupConfig,
};
use opcua_server::address_space::AddressSpace;
use opcua_types::StatusCode;

fn empty_connection(connection_id: &str, address: &str) -> PubSubConnectionConfig {
    PubSubConnectionConfig {
        connection_id: connection_id.to_string(),
        name: connection_id.to_string(),
        address: address.to_string(),
        writer_groups: Vec::<WriterGroupConfig>::new(),
    }
}

fn address_space() -> Arc<RwLock<AddressSpace>> {
    Arc::new(RwLock::new(AddressSpace::new()))
}

#[test]
fn classifies_all_supported_pubsub_transport_addresses() {
    assert_eq!(
        TransportKind::from_address("mqtt://broker.local:1883").unwrap(),
        TransportKind::Mqtt
    );
    assert_eq!(
        TransportKind::from_address("udp://239.0.0.1:4840").unwrap(),
        TransportKind::Udp
    );
    assert_eq!(
        TransportKind::from_address("amqp://broker.local:5672/opcua.telemetry").unwrap(),
        TransportKind::Amqp
    );
    assert_eq!(
        TransportKind::from_address("ws://broker.local:9001/pubsub").unwrap(),
        TransportKind::WebSocket
    );
}

#[tokio::test]
async fn manages_connection_configs_and_udp_publisher_lifecycle() {
    let mut engine = PubSubEngine::new(address_space());
    let config = empty_connection("udp-1", "udp://127.0.0.1:4840");

    engine.add_connection(config.clone());

    assert_eq!(engine.connection_configs(), &[config]);
    assert_eq!(engine.active_handle_count(), 0);

    engine.start().unwrap();

    assert!(engine.is_running());
    assert_eq!(engine.active_handle_count(), 1);

    engine.stop().await;

    assert!(!engine.is_running());
    assert_eq!(engine.active_handle_count(), 0);
}

#[test]
fn rejects_unknown_transport_addresses() {
    assert!(TransportKind::from_address("ftp://broker.local/pubsub").is_err());
}

#[test]
fn start_rejects_unknown_transport_without_marking_engine_running() {
    let mut engine = PubSubEngine::new(address_space());
    engine.add_connection(empty_connection("bad-1", "ftp://broker.local/pubsub"));

    assert_eq!(engine.start().unwrap_err(), StatusCode::BadInvalidArgument);
    assert!(!engine.is_running());
    assert_eq!(engine.active_handle_count(), 0);
}
