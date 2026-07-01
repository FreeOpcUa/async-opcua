//! PubSub configuration consistency gates for OPC UA Part 14.

use opcua_core::sync::RwLock;
use opcua_pubsub::{
    pubsub_model::reflect_pubsub_config_with_status, AmqpPublisher, DataSetReaderConfig,
    DataSetReaderStatus, DataSetWriterConfig, MessageEncoding, PubSubConnectionConfig, PublisherId,
    ReaderGroupConfig,
};
use opcua_server::address_space::AddressSpace;
use opcua_types::{
    AttributeId, DataEncoding, DataSetReaderDataType, DataSetWriterDataType, MessageSecurityMode,
    NodeId, NumericRange, PubSubConnectionDataType, PubSubState, ReaderGroupDataType,
    TimestampsToReturn, UAString, Variant, WriterGroupDataType,
};
use std::sync::Arc;

fn reflected_value(space: &AddressSpace, node_id: NodeId) -> Option<Variant> {
    space
        .find(&node_id)?
        .as_node()
        .get_attribute(
            TimestampsToReturn::Neither,
            AttributeId::Value,
            &NumericRange::None,
            &DataEncoding::Binary,
        )?
        .value
}

#[test]
fn config_snapshot_consistency_part14_pubsub_connection_preserves_supported_fields() {
    let source = PubSubConnectionDataType {
        name: UAString::from("TelemetryConnection"),
        enabled: true,
        publisher_id: Variant::from("publisher-a"),
        transport_profile_uri: UAString::from("udp://239.0.0.1:4840"),
        writer_groups: Some(vec![WriterGroupDataType {
            name: UAString::from("writers"),
            enabled: true,
            writer_group_id: 42,
            publishing_interval: 100.0,
            data_set_writers: Some(vec![DataSetWriterDataType {
                name: UAString::from("writer-a"),
                enabled: true,
                data_set_writer_id: 7,
                data_set_name: UAString::from("TelemetryDataSet"),
                ..DataSetWriterDataType::default()
            }]),
            ..WriterGroupDataType::default()
        }]),
        reader_groups: Some(vec![ReaderGroupDataType {
            name: UAString::from("readers"),
            enabled: true,
            security_mode: MessageSecurityMode::Sign,
            security_group_id: UAString::from("security-group-a"),
            data_set_readers: Some(vec![DataSetReaderDataType {
                name: UAString::from("reader-a"),
                enabled: true,
                publisher_id: Variant::from("publisher-a"),
                writer_group_id: 42,
                data_set_writer_id: 7,
                message_receive_timeout: 1_500.0,
                security_mode: MessageSecurityMode::Sign,
                security_group_id: UAString::from("security-group-a"),
                ..DataSetReaderDataType::default()
            }]),
            ..ReaderGroupDataType::default()
        }]),
        ..PubSubConnectionDataType::default()
    };

    let snapshot = PubSubConnectionConfig::from_data_type(&source, "conn-1".to_string());

    assert_eq!(snapshot.connection_id, "conn-1");
    assert_eq!(snapshot.name, "TelemetryConnection");
    assert_eq!(snapshot.address, "udp://239.0.0.1:4840");

    let writer_group = snapshot.writer_groups.first().expect("writer group");
    assert_eq!(writer_group.writer_group_id, 42);
    assert_eq!(writer_group.publishing_interval, 100);
    assert_eq!(writer_group.encoding, MessageEncoding::Uadp);

    let writer = writer_group
        .dataset_writers
        .first()
        .expect("dataset writer");
    assert_eq!(writer.dataset_writer_id, 7);
    assert_eq!(writer.dataset_name, "TelemetryDataSet");

    let reader_group = snapshot.reader_groups.first().expect("reader group");
    assert_eq!(reader_group.reader_group_id, 1);
    assert_eq!(reader_group.security_mode, Some(MessageSecurityMode::Sign));
    assert_eq!(
        reader_group.security_group_id.as_deref(),
        Some("security-group-a")
    );

    let reader = reader_group
        .dataset_readers
        .first()
        .expect("dataset reader");
    assert_eq!(reader.name.as_deref(), Some("reader-a"));
    assert_eq!(reader.dataset_reader_id, 1);
    assert_eq!(
        reader.publisher_id,
        Some(PublisherId::String("publisher-a".to_string()))
    );
    assert_eq!(reader.writer_group_id, Some(42));
    assert_eq!(reader.dataset_writer_id, 7);
    assert_eq!(
        reader
            .message_receive_timeout
            .expect("receive timeout")
            .as_millis(),
        1_500
    );
    assert_eq!(reader.security_mode, Some(MessageSecurityMode::Sign));
    assert_eq!(
        reader.security_group_id.as_deref(),
        Some("security-group-a")
    );
}

#[test]
fn config_snapshot_consistency_part14_dataset_writer_preserves_supported_fields() {
    let source = DataSetWriterDataType {
        name: UAString::from("writer-config-a"),
        enabled: true,
        data_set_writer_id: 88,
        data_set_name: UAString::from("PlantTelemetry"),
        ..DataSetWriterDataType::default()
    };

    let snapshot = DataSetWriterConfig::from_data_type(&source);

    assert_eq!(snapshot.dataset_writer_id, 88);
    assert_eq!(snapshot.dataset_name, "PlantTelemetry");
    assert!(snapshot.published_dataset.published_variables.is_empty());

    let connection_source = PubSubConnectionDataType {
        name: UAString::from("TelemetryConnection"),
        enabled: true,
        publisher_id: Variant::from("publisher-a"),
        transport_profile_uri: UAString::from("udp://239.0.0.1:4840"),
        writer_groups: Some(vec![WriterGroupDataType {
            name: UAString::from("writers"),
            enabled: true,
            writer_group_id: 42,
            publishing_interval: 100.0,
            data_set_writers: Some(vec![source]),
            ..WriterGroupDataType::default()
        }]),
        ..PubSubConnectionDataType::default()
    };

    let connection_snapshot =
        PubSubConnectionConfig::from_data_type(&connection_source, "conn-1".to_string());
    let writer = connection_snapshot
        .writer_groups
        .first()
        .expect("writer group")
        .dataset_writers
        .first()
        .expect("dataset writer");

    assert_eq!(writer, &snapshot);
}

#[test]
fn config_snapshot_consistency_part14_9_1_10_1_pubsub_status_matches_runtime_snapshot() {
    let mut space = AddressSpace::new();
    space.add_namespace("urn:test", 1);
    let config = PubSubConnectionConfig {
        connection_id: "conn-status".to_string(),
        name: "TelemetryConnection".to_string(),
        address: "udp://239.0.0.1:4840".to_string(),
        writer_groups: Vec::new(),
        reader_groups: vec![ReaderGroupConfig {
            reader_group_id: 5,
            dataset_readers: vec![DataSetReaderConfig {
                name: Some("reader-status".to_string()),
                dataset_reader_id: 3,
                dataset_writer_id: 7,
                publisher_id: Some(PublisherId::String("publisher-a".to_string())),
                writer_group_id: Some(42),
                ..DataSetReaderConfig::default()
            }],
            ..ReaderGroupConfig::default()
        }],
    };
    let mut status = DataSetReaderStatus::default();
    status.state = PubSubState::Operational;
    status.accepted_count = 11;
    status.filtered_count = 2;
    status.dropped_count = 1;

    let map = reflect_pubsub_config_with_status(&mut space, 1, &[config], &[(3, status)]);

    assert_eq!(map.readers.len(), 1);
    assert_eq!(map.readers[0].0, 3);
    assert_eq!(
        reflected_value(
            &space,
            NodeId::new(1, "DataSetReader:conn-status:3:ReaderState")
        ),
        Some(Variant::Int32(PubSubState::Operational as i32))
    );
    assert_eq!(
        reflected_value(
            &space,
            NodeId::new(1, "DataSetReader:conn-status:3:AcceptedCount")
        ),
        Some(Variant::UInt64(11))
    );
    assert_eq!(
        reflected_value(
            &space,
            NodeId::new(1, "DataSetReader:conn-status:3:FilteredCount")
        ),
        Some(Variant::UInt64(2))
    );
    assert_eq!(
        reflected_value(
            &space,
            NodeId::new(1, "DataSetReader:conn-status:3:DroppedCount")
        ),
        Some(Variant::UInt64(1))
    );
}

#[test]
fn config_snapshot_consistency_part14_5_4_1_2_transport_message_sending_cache_is_bounded_fifo() {
    let publisher = AmqpPublisher::new(Arc::new(RwLock::new(AddressSpace::new())));

    for index in 0..1_001 {
        publisher.publish_immediate(format!("writer-group-{index}"), vec![index as u8]);
    }

    assert_eq!(publisher.cached_message_count(), 1_000);
    assert_eq!(
        publisher.pop_cached_message(),
        Some(("writer-group-1".to_string(), vec![1]))
    );
}
