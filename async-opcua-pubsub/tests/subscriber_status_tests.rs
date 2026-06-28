//! Subscriber status and diagnostics integration tests.

use std::sync::Arc;
use std::time::{Duration, Instant};

use opcua_core::sync::RwLock;
use opcua_pubsub::{
    DataSetReaderConfig, FieldTargetConfig, PubSubConnectionConfig, PublisherId, ReaderGroupConfig,
    SubscriberError, SubscriberRuntime, UadpDataSetMessage, UadpNetworkMessage,
};
use opcua_server::address_space::{AddressSpace, VariableBuilder};
use opcua_types::{DataTypeId, NodeId, PubSubState, StatusCode, Variant};

fn target_space() -> (Arc<RwLock<AddressSpace>>, NodeId) {
    let mut space = AddressSpace::new();
    space.add_namespace("urn:test", 1);
    let target = NodeId::new(1, "Target");
    VariableBuilder::new(&target, "Target", "Target")
        .data_type(DataTypeId::Double)
        .value(Variant::Double(0.0))
        .insert(&mut space);
    (Arc::new(RwLock::new(space)), target)
}

fn connection(target: NodeId) -> PubSubConnectionConfig {
    PubSubConnectionConfig {
        connection_id: "conn".to_string(),
        name: "conn".to_string(),
        address: "udp://127.0.0.1:4840".to_string(),
        writer_groups: Vec::new(),
        reader_groups: vec![ReaderGroupConfig {
            reader_group_id: 1,
            dataset_readers: vec![DataSetReaderConfig {
                name: Some("reader".to_string()),
                dataset_reader_id: 1,
                dataset_writer_id: 42,
                publisher_id: Some(PublisherId::UInt16(11)),
                writer_group_id: Some(7),
                network_message_number: Some(3),
                message_receive_timeout: Some(Duration::from_millis(10)),
                metadata_major_version: Some(1),
                target_variables: vec![FieldTargetConfig::value(0, target)],
                ..DataSetReaderConfig::default()
            }],
            ..ReaderGroupConfig::default()
        }],
    }
}

fn message(sequence_number: u16) -> UadpNetworkMessage {
    UadpNetworkMessage {
        publisher_id: PublisherId::UInt16(11),
        writer_group_id: 7,
        network_message_number: 3,
        sequence_number,
        dataset_messages: vec![UadpDataSetMessage {
            dataset_writer_id: 42,
            sequence_number,
            timestamp: None,
            status: None,
            fields: vec![Variant::Double(sequence_number as f64)],
        }],
    }
}

#[test]
fn first_valid_message_moves_reader_to_operational() {
    let (space, target) = target_space();
    let now = Instant::now();
    let mut runtime = SubscriberRuntime::with_connections(space, vec![connection(target)]).unwrap();

    assert_eq!(
        runtime.reader_status(1).unwrap().state,
        PubSubState::PreOperational
    );
    runtime
        .process_network_message_at(&message(1), now)
        .unwrap();

    let status = runtime.reader_status(1).unwrap();
    assert_eq!(status.state, PubSubState::Operational);
    assert_eq!(status.accepted_count, 1);
}

#[test]
fn message_receive_timeout_moves_operational_reader_to_error() {
    let (space, target) = target_space();
    let now = Instant::now();
    let mut runtime = SubscriberRuntime::with_connections(space, vec![connection(target)]).unwrap();
    runtime
        .process_network_message_at(&message(1), now)
        .unwrap();

    runtime.check_timeouts_at(now + Duration::from_millis(11));

    let status = runtime.reader_status(1).unwrap();
    assert_eq!(status.state, PubSubState::Error);
    assert_eq!(
        status.last_error,
        Some(SubscriberError::MessageReceiveTimeout)
    );
    assert_eq!(status.timeout_count, 1);
}

#[test]
fn next_valid_message_recovers_timeout_error() {
    let (space, target) = target_space();
    let now = Instant::now();
    let mut runtime = SubscriberRuntime::with_connections(space, vec![connection(target)]).unwrap();
    runtime
        .process_network_message_at(&message(1), now)
        .unwrap();
    runtime.check_timeouts_at(now + Duration::from_millis(11));

    runtime
        .process_network_message_at(&message(2), now + Duration::from_millis(12))
        .unwrap();

    assert_eq!(
        runtime.reader_status(1).unwrap().state,
        PubSubState::Operational
    );
}

#[test]
fn sequence_gap_and_duplicate_are_diagnosed() {
    let (space, target) = target_space();
    let now = Instant::now();
    let mut runtime = SubscriberRuntime::with_connections(space, vec![connection(target)]).unwrap();

    runtime
        .process_network_message_at(&message(1), now)
        .unwrap();
    runtime
        .process_network_message_at(&message(3), now + Duration::from_millis(1))
        .unwrap();
    runtime
        .process_network_message_at(&message(3), now + Duration::from_millis(2))
        .unwrap();

    let status = runtime.reader_status(1).unwrap();
    assert_eq!(status.sequence_gap_count, 1);
    assert_eq!(status.duplicate_count, 1);
    assert_eq!(status.last_sequence_number, Some(3));
}

#[test]
fn metadata_major_version_gap_errors_after_receive_timeout() {
    let (space, target) = target_space();
    let now = Instant::now();
    let mut runtime = SubscriberRuntime::with_connections(space, vec![connection(target)]).unwrap();
    runtime
        .process_network_message_at(&message(1), now)
        .expect("first message");

    runtime
        .observe_metadata_major_version_at(1, 2, now + Duration::from_millis(1))
        .unwrap();
    runtime.check_timeouts_at(now + Duration::from_millis(12));

    let status = runtime.reader_status(1).unwrap();
    assert_eq!(status.state, PubSubState::Error);
    assert_eq!(
        status.last_error,
        Some(SubscriberError::MetadataMajorVersionMismatch)
    );
}

#[test]
fn unknown_reader_metadata_observation_returns_bad_not_found() {
    let (space, target) = target_space();
    let mut runtime = SubscriberRuntime::with_connections(space, vec![connection(target)]).unwrap();

    assert_eq!(
        runtime
            .observe_metadata_major_version_at(99, 2, Instant::now())
            .unwrap_err(),
        StatusCode::BadNotFound
    );
}
