//! FX1: production UADP DataSetReader binds incoming DataSet fields into target variables.

use opcua_pubsub::{
    apply_network_message, DataSetReaderConfig, PublisherId, ReaderGroupConfig, UadpDataSetMessage,
    UadpNetworkMessage,
};
use opcua_server::address_space::{AddressSpace, VariableBuilder};
use opcua_types::{
    AttributeId, DataEncoding, DataTypeId, NodeId, NumericRange, TimestampsToReturn, Variant,
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

fn dataset_msg(dataset_writer_id: u16, fields: Vec<Variant>) -> UadpDataSetMessage {
    UadpDataSetMessage {
        dataset_writer_id,
        sequence_number: 1,
        timestamp: None,
        status: None,
        fields,
    }
}

fn network_msg(messages: Vec<UadpDataSetMessage>) -> UadpNetworkMessage {
    UadpNetworkMessage {
        publisher_id: PublisherId::UInt16(1),
        writer_group_id: 1,
        network_message_number: 1,
        sequence_number: 1,
        dataset_messages: messages,
    }
}

#[test]
fn datasetreader_binds_incoming_fields_into_target_variables() {
    let mut space = AddressSpace::new();
    space.add_namespace("urn:test", 1);
    let target = NodeId::new(1, "Target");
    VariableBuilder::new(&target, "Target", "Target")
        .data_type(DataTypeId::Double)
        .value(Variant::Double(0.0))
        .insert(&mut space);

    let reader_groups = vec![ReaderGroupConfig {
        reader_group_id: 1,
        dataset_readers: vec![DataSetReaderConfig {
            dataset_reader_id: 1,
            dataset_writer_id: 7,
            publisher_id: None,
            subscribed_variables: vec![target.clone()],
            ..DataSetReaderConfig::default()
        }],
        ..ReaderGroupConfig::default()
    }];

    // A matching DataSetMessage (writer id 7) binds its field into the target variable.
    let applied = apply_network_message(
        &mut space,
        &network_msg(vec![dataset_msg(7, vec![Variant::Double(42.0)])]),
        &reader_groups,
    );
    assert_eq!(applied, 1);
    assert_eq!(target_value(&space, &target), Some(Variant::Double(42.0)));

    // A non-matching writer id (9) is ignored; the target keeps its value.
    let applied2 = apply_network_message(
        &mut space,
        &network_msg(vec![dataset_msg(9, vec![Variant::Double(99.0)])]),
        &reader_groups,
    );
    assert_eq!(applied2, 0);
    assert_eq!(target_value(&space, &target), Some(Variant::Double(42.0)));
}
