//! FX4 (OPC UA FX Part 81 §E.2.2.1): ConnectionManager wires a writer↔reader pair and data flows end-to-end.

use opcua_pubsub::{
    apply_network_message, ConnectionManager, DataSetReaderConfig, DataSetWriterConfig,
    MessageEncoding, PubSubConnectionConfig, PublishedDataSetConfig, PublisherId,
    ReaderGroupConfig, UadpDataSetMessage, UadpNetworkMessage, WriterGroupConfig,
};
use opcua_server::address_space::{AddressSpace, VariableBuilder};
use opcua_types::{
    AttributeId, ConfigurationVersionDataType, DataEncoding, DataTypeId, NodeId, NumericRange,
    StatusCode, TimestampsToReturn, Variant,
};

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

fn version(major: u32, minor: u32) -> ConfigurationVersionDataType {
    ConfigurationVersionDataType {
        major_version: major,
        minor_version: minor,
    }
}

fn writer_group(cfg_version: ConfigurationVersionDataType) -> WriterGroupConfig {
    WriterGroupConfig {
        // Deliberately stale ids — the manager must overwrite them with reserved values.
        writer_group_id: 0,
        publishing_interval: 100,
        encoding: MessageEncoding::Uadp,
        dataset_writers: vec![DataSetWriterConfig {
            dataset_writer_id: 0,
            dataset_name: "DS".into(),
            published_dataset: PublishedDataSetConfig {
                published_variables: vec![NodeId::new(1, "Source")],
                configuration_version: cfg_version,
            },
        }],
    }
}

fn reader_group(target: &NodeId) -> ReaderGroupConfig {
    ReaderGroupConfig {
        reader_group_id: 1,
        dataset_readers: vec![DataSetReaderConfig {
            dataset_reader_id: 1,
            dataset_writer_id: 0,
            publisher_id: None,
            subscribed_variables: vec![target.clone()],
            ..DataSetReaderConfig::default()
        }],
        ..ReaderGroupConfig::default()
    }
}

#[test]
fn establish_connection_wires_writer_to_reader_and_data_flows() {
    let mut mgr = ConnectionManager::new();

    // An existing config already occupies writer-group 1 and dataset-writer 1.
    let existing = vec![PubSubConnectionConfig {
        connection_id: "old".into(),
        name: "old".into(),
        address: "udp://239.0.0.1:4840".into(),
        reader_groups: Vec::new(),
        writer_groups: vec![WriterGroupConfig {
            writer_group_id: 1,
            publishing_interval: 100,
            encoding: MessageEncoding::Uadp,
            dataset_writers: vec![DataSetWriterConfig {
                dataset_writer_id: 1,
                dataset_name: "x".into(),
                published_dataset: PublishedDataSetConfig {
                    published_variables: vec![],
                    configuration_version: Default::default(),
                },
            }],
        }],
    }];

    let target = NodeId::new(1, "Target");
    let conn = mgr
        .establish_connection(
            &existing,
            "c2c",
            writer_group(version(3, 0)),
            reader_group(&target),
        )
        .expect("establish");

    // Reserved ids avoid the in-use ones (1) and the writer/reader share the bound id.
    let reserved = conn.writer_group.dataset_writers[0].dataset_writer_id;
    assert_ne!(
        reserved, 1,
        "must not collide with existing dataset-writer 1"
    );
    assert_ne!(conn.writer_group.writer_group_id, 1);
    assert_ne!(conn.writer_group.writer_group_id, 0, "stale id overwritten");
    assert_eq!(
        conn.reader_group.dataset_readers[0].dataset_writer_id, reserved,
        "reader bound to writer's reserved id"
    );

    // End-to-end C2C: the publisher emits a message with the bound id; the subscriber applies it.
    let mut sub_space = AddressSpace::new();
    sub_space.add_namespace("urn:test", 1);
    VariableBuilder::new(&target, "Target", "Target")
        .data_type(DataTypeId::Double)
        .value(Variant::Double(0.0))
        .insert(&mut sub_space);

    let msg = UadpNetworkMessage {
        publisher_id: PublisherId::UInt16(1),
        writer_group_id: conn.writer_group.writer_group_id,
        network_message_number: 1,
        sequence_number: 1,
        dataset_messages: vec![UadpDataSetMessage {
            dataset_writer_id: reserved,
            sequence_number: 1,
            timestamp: None,
            status: None,
            fields: vec![Variant::Double(42.0)],
        }],
    };
    let applied = apply_network_message(
        &mut sub_space,
        &msg,
        std::slice::from_ref(&conn.reader_group),
    );
    assert_eq!(applied, 1);
    assert_eq!(
        target_value(&sub_space, &target),
        Some(Variant::Double(42.0))
    );
}

#[test]
fn mismatched_writer_reader_counts_are_rejected() {
    let mut mgr = ConnectionManager::new();
    let mut empty_readers = reader_group(&NodeId::new(1, "Target"));
    empty_readers.dataset_readers.clear();
    let err = mgr
        .establish_connection(&[], "bad", writer_group(version(1, 0)), empty_readers)
        .unwrap_err();
    assert_eq!(err, StatusCode::BadConfigurationError);
}

#[test]
fn is_current_detects_configuration_drift() {
    let mut mgr = ConnectionManager::new();
    let target = NodeId::new(1, "Target");
    let conn = mgr
        .establish_connection(&[], "c", writer_group(version(5, 1)), reader_group(&target))
        .expect("establish");

    // Same major (minor bumped) -> still current.
    assert!(conn.is_current(&[version(5, 9)]));
    // Major bumped -> drift detected.
    assert!(!conn.is_current(&[version(6, 0)]));
    // Length mismatch -> not current.
    assert!(!conn.is_current(&[]));
}
