//! Plain UADP subscriber runtime integration tests.

use std::sync::Arc;
use std::time::Duration;

use opcua_core::sync::RwLock;
use opcua_pubsub::{
    transport::udp::{bind_subscriber_socket, UdpSubscriberEndpoint},
    DataSetFieldEncoding, DataSetMessageKind, DataSetReaderConfig, FieldTargetConfig,
    MessageEncoding, PubSubConnectionConfig, PublisherId, ReaderGroupConfig, SubscriberError,
    SubscriberRuntime, UadpDataSetMessage, UadpNetworkMessage,
};
use opcua_server::address_space::{AddressSpace, VariableBuilder};
use opcua_types::{
    AttributeId, BinaryEncodable, ContextOwned, DataEncoding, DataTypeId, NodeId, NumericRange,
    OverrideValueHandling, StatusCode, TimestampsToReturn, Variant,
};
use tokio::net::UdpSocket;

fn target_value(space: &AddressSpace, node: &NodeId) -> Option<Variant> {
    space
        .find(node)?
        .as_node()
        .get_attribute(
            TimestampsToReturn::Neither,
            AttributeId::Value,
            &NumericRange::None,
            &DataEncoding::Binary,
        )?
        .value
}

fn insert_target(space: &mut AddressSpace, name: &str, value: Variant) -> NodeId {
    let node_id = NodeId::new(1, name);
    VariableBuilder::new(&node_id, name, name)
        .data_type(DataTypeId::Double)
        .value(value)
        .insert(space);
    node_id
}

fn dataset_msg(
    dataset_writer_id: u16,
    sequence_number: u16,
    fields: Vec<Variant>,
) -> UadpDataSetMessage {
    UadpDataSetMessage {
        dataset_writer_id,
        sequence_number,
        timestamp: None,
        status: None,
        fields,
    }
}

fn network_msg(message: UadpDataSetMessage) -> UadpNetworkMessage {
    UadpNetworkMessage {
        publisher_id: PublisherId::UInt16(11),
        writer_group_id: 7,
        network_message_number: 3,
        sequence_number: message.sequence_number,
        dataset_messages: vec![message],
    }
}

fn reader(targets: Vec<NodeId>) -> DataSetReaderConfig {
    DataSetReaderConfig {
        name: Some("reader-a".to_string()),
        dataset_reader_id: 1,
        dataset_writer_id: 42,
        publisher_id: Some(PublisherId::UInt16(11)),
        writer_group_id: Some(7),
        network_message_number: Some(3),
        message_receive_timeout: Some(Duration::from_millis(100)),
        target_variables: targets
            .into_iter()
            .enumerate()
            .map(|(index, target)| FieldTargetConfig::value(index, target))
            .collect(),
        ..DataSetReaderConfig::default()
    }
}

fn connection(reader: DataSetReaderConfig) -> PubSubConnectionConfig {
    PubSubConnectionConfig {
        connection_id: "conn".to_string(),
        name: "conn".to_string(),
        address: "udp://127.0.0.1:4840".to_string(),
        writer_groups: Vec::new(),
        reader_groups: vec![ReaderGroupConfig {
            reader_group_id: 1,
            dataset_readers: vec![reader],
            ..ReaderGroupConfig::default()
        }],
    }
}

#[test]
fn validation_rejects_duplicate_dataset_reader_names() {
    let mut first = reader(Vec::new());
    let mut second = reader(Vec::new());
    first.dataset_reader_id = 1;
    second.dataset_reader_id = 2;

    let mut cfg = connection(first);
    cfg.reader_groups[0].dataset_readers.push(second);

    assert_eq!(
        cfg.validate_subscriber_config().unwrap_err(),
        StatusCode::BadConfigurationError
    );
}

#[test]
fn validation_rejects_duplicate_target_variables() {
    let target = NodeId::new(1, "Target");
    let mut reader = reader(Vec::new());
    reader.target_variables = vec![
        FieldTargetConfig::value(0, target.clone()),
        FieldTargetConfig::value(1, target),
    ];

    assert_eq!(
        connection(reader).validate_subscriber_config().unwrap_err(),
        StatusCode::BadConfigurationError
    );
}

#[test]
fn legacy_subscribed_variables_map_to_value_attribute_targets() {
    let target = NodeId::new(1, "Target");
    let reader = DataSetReaderConfig {
        subscribed_variables: vec![target.clone()],
        ..DataSetReaderConfig::default()
    };

    let targets = reader.effective_target_variables();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].dataset_field_index, 0);
    assert_eq!(targets[0].target_node_id, target);
    assert_eq!(targets[0].attribute_id, AttributeId::Value);
    assert_eq!(
        targets[0].override_value_handling,
        OverrideValueHandling::Disabled
    );
}

#[test]
fn matching_key_frame_updates_targets_in_field_order() {
    let mut space = AddressSpace::new();
    space.add_namespace("urn:test", 1);
    let a = insert_target(&mut space, "A", Variant::Double(0.0));
    let b = insert_target(&mut space, "B", Variant::Double(0.0));
    let address_space = Arc::new(RwLock::new(space));
    let mut runtime = SubscriberRuntime::with_connections(
        address_space.clone(),
        vec![connection(reader(vec![a.clone(), b.clone()]))],
    )
    .unwrap();

    let outcome = runtime
        .process_network_message(&network_msg(dataset_msg(
            42,
            1,
            vec![Variant::Double(12.0), Variant::Double(34.0)],
        )))
        .unwrap();

    assert_eq!(outcome.applied_readers, 1);
    let space = address_space.read();
    assert_eq!(target_value(&space, &a), Some(Variant::Double(12.0)));
    assert_eq!(target_value(&space, &b), Some(Variant::Double(34.0)));
}

#[test]
fn nonmatching_filters_do_not_write_and_increment_filtered_count() {
    let mut space = AddressSpace::new();
    space.add_namespace("urn:test", 1);
    let target = insert_target(&mut space, "Target", Variant::Double(5.0));
    let address_space = Arc::new(RwLock::new(space));
    let mut runtime = SubscriberRuntime::with_connections(
        address_space.clone(),
        vec![connection(reader(vec![target.clone()]))],
    )
    .unwrap();

    for message in [
        UadpNetworkMessage {
            publisher_id: PublisherId::UInt16(99),
            ..network_msg(dataset_msg(42, 1, vec![Variant::Double(99.0)]))
        },
        UadpNetworkMessage {
            writer_group_id: 99,
            ..network_msg(dataset_msg(42, 2, vec![Variant::Double(99.0)]))
        },
        UadpNetworkMessage {
            network_message_number: 99,
            ..network_msg(dataset_msg(42, 3, vec![Variant::Double(99.0)]))
        },
        network_msg(dataset_msg(99, 4, vec![Variant::Double(99.0)])),
    ] {
        let outcome = runtime.process_network_message(&message).unwrap();
        assert_eq!(outcome.applied_readers, 0);
    }

    let space = address_space.read();
    assert_eq!(target_value(&space, &target), Some(Variant::Double(5.0)));
    assert_eq!(runtime.reader_status(1).unwrap().filtered_count, 4);
}

#[test]
fn wildcard_publisher_and_dataset_writer_filters_allow_matching_message() {
    let mut space = AddressSpace::new();
    space.add_namespace("urn:test", 1);
    let target = insert_target(&mut space, "Target", Variant::Double(0.0));
    let mut cfg_reader = reader(vec![target.clone()]);
    cfg_reader.publisher_id = None;
    cfg_reader.dataset_writer_id = 0;
    let address_space = Arc::new(RwLock::new(space));
    let mut runtime =
        SubscriberRuntime::with_connections(address_space.clone(), vec![connection(cfg_reader)])
            .unwrap();

    let outcome = runtime
        .process_network_message(&network_msg(dataset_msg(42, 1, vec![Variant::Double(8.0)])))
        .unwrap();

    assert_eq!(outcome.applied_readers, 1);
    assert_eq!(
        target_value(&address_space.read(), &target),
        Some(Variant::Double(8.0))
    );
}

#[test]
fn field_count_mismatch_is_atomic_and_reports_error() {
    let mut space = AddressSpace::new();
    space.add_namespace("urn:test", 1);
    let a = insert_target(&mut space, "A", Variant::Double(1.0));
    let b = insert_target(&mut space, "B", Variant::Double(2.0));
    let address_space = Arc::new(RwLock::new(space));
    let mut runtime = SubscriberRuntime::with_connections(
        address_space.clone(),
        vec![connection(reader(vec![a.clone(), b.clone()]))],
    )
    .unwrap();

    let outcome = runtime
        .process_network_message(&network_msg(dataset_msg(42, 1, vec![Variant::Double(9.0)])))
        .unwrap();

    assert_eq!(outcome.applied_readers, 0);
    let status = runtime.reader_status(1).unwrap();
    assert_eq!(status.last_error, Some(SubscriberError::FieldCountMismatch));
    let space = address_space.read();
    assert_eq!(target_value(&space, &a), Some(Variant::Double(1.0)));
    assert_eq!(target_value(&space, &b), Some(Variant::Double(2.0)));
}

#[test]
fn malformed_datagram_is_rejected_without_panic() {
    let ctx_owned = ContextOwned::default();
    let ctx = ctx_owned.context();
    let address_space = Arc::new(RwLock::new(AddressSpace::new()));
    let mut runtime =
        SubscriberRuntime::with_connections(address_space, vec![connection(reader(Vec::new()))])
            .unwrap();

    assert_eq!(
        runtime.process_datagram(&[0xff, 0x00], &ctx).unwrap_err(),
        StatusCode::BadDecodingError
    );
}

#[test]
fn process_datagram_rejects_custom_udp_fragment_header() {
    let ctx_owned = ContextOwned::default();
    let ctx = ctx_owned.context();
    let address_space = Arc::new(RwLock::new(AddressSpace::new()));
    let mut runtime =
        SubscriberRuntime::with_connections(address_space, vec![connection(reader(Vec::new()))])
            .unwrap();

    let fragment = [0x00, 0x01, 0x02, 0x00, 0x00, 0x01, 0x61];
    assert_eq!(
        runtime.process_datagram(&fragment, &ctx).unwrap_err(),
        StatusCode::BadNotSupported
    );
}

#[test]
fn validation_rejects_unsupported_subscriber_modes() {
    let mut broker = connection(reader(Vec::new()));
    broker.address = "mqtt://broker.local:1883".to_string();
    assert_eq!(
        broker.validate_subscriber_config().unwrap_err(),
        StatusCode::BadNotSupported
    );

    let mut json = reader(Vec::new());
    json.message_encoding = MessageEncoding::Json;
    assert_eq!(
        connection(json).validate_subscriber_config().unwrap_err(),
        StatusCode::BadNotSupported
    );

    let mut raw = reader(Vec::new());
    raw.field_encoding = DataSetFieldEncoding::RawData;
    assert_eq!(
        connection(raw).validate_subscriber_config().unwrap_err(),
        StatusCode::BadNotSupported
    );

    let mut delta = reader(Vec::new());
    delta.message_kind = DataSetMessageKind::DeltaFrame;
    assert_eq!(
        connection(delta).validate_subscriber_config().unwrap_err(),
        StatusCode::BadNotSupported
    );

    let mut event = reader(Vec::new());
    event.message_kind = DataSetMessageKind::Event;
    assert_eq!(
        connection(event).validate_subscriber_config().unwrap_err(),
        StatusCode::BadNotSupported
    );
}

#[tokio::test]
async fn udp_subscriber_bind_conflict_returns_bad_communication_error() {
    let held_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = UdpSubscriberEndpoint {
        bind_addr: held_socket.local_addr().unwrap(),
        multicast_addr: None,
    };

    let err = bind_subscriber_socket(endpoint).await.unwrap_err();

    // OPC-10000-14 5.4.6.2.2: UDP subscriber transport bind failures map to BadCommunicationError.
    assert_eq!(err, StatusCode::BadCommunicationError);
}

#[test]
fn encoded_key_frame_datagram_processes_through_decode_path() {
    let ctx_owned = ContextOwned::default();
    let ctx = ctx_owned.context();
    let mut space = AddressSpace::new();
    space.add_namespace("urn:test", 1);
    let target = insert_target(&mut space, "Target", Variant::Double(0.0));
    let address_space = Arc::new(RwLock::new(space));
    let mut runtime = SubscriberRuntime::with_connections(
        address_space.clone(),
        vec![connection(reader(vec![target.clone()]))],
    )
    .unwrap();
    let datagram = network_msg(dataset_msg(42, 1, vec![Variant::Double(55.0)])).encode_to_vec(&ctx);

    let outcome = runtime.process_datagram(&datagram, &ctx).unwrap();

    assert_eq!(outcome.applied_readers, 1);
    assert_eq!(
        target_value(&address_space.read(), &target),
        Some(Variant::Double(55.0))
    );
}
