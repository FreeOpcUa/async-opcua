//! Read-only PubSub info-model reflection (Part 14): the FX-referenceable instance objects.

use opcua_nodes::DefaultTypeTree;
use opcua_pubsub::pubsub_model::{reflect_pubsub_config, PubSubModelMap};
use opcua_pubsub::{
    DataSetWriterConfig, MessageEncoding, PubSubConnectionConfig, PublishedDataSetConfig,
    WriterGroupConfig,
};
use opcua_server::address_space::AddressSpace;
use opcua_types::{
    AttributeId, BrowseDirection, DataEncoding, NodeId, NumericRange, ObjectTypeId, QualifiedName,
    ReferenceTypeId, TimestampsToReturn, Variant,
};

#[test]
fn reflect_pubsub_config_materializes_referenceable_instances() {
    let mut space = AddressSpace::new();
    space.add_namespace("urn:test", 1);

    let cfg = PubSubConnectionConfig {
        reader_groups: Vec::new(),
        connection_id: "conn1".into(),
        name: "Conn 1".into(),
        address: "udp://239.0.0.1:4840".into(),
        writer_groups: vec![WriterGroupConfig {
            writer_group_id: 42,
            publishing_interval: 100,
            encoding: MessageEncoding::Uadp,
            dataset_writers: vec![DataSetWriterConfig {
                dataset_writer_id: 7,
                dataset_name: "DS".into(),
                published_dataset: PublishedDataSetConfig {
                    published_variables: vec![],
                },
            }],
        }],
    };

    let map: PubSubModelMap = reflect_pubsub_config(&mut space, 1, &[cfg]);
    let tt = DefaultTypeTree::new();

    // The map locates the connection and the dataset writer by their config ids.
    assert_eq!(map.connections.len(), 1);
    assert_eq!(map.connections[0].0, "conn1");
    let conn_id = map.connections[0].1.clone();
    assert!(space.node_exists(&conn_id));

    let writer_id = map
        .writers
        .iter()
        .find(|(id, _)| *id == 7)
        .expect("writer id 7 in map")
        .1
        .clone();
    assert!(space.node_exists(&writer_id));

    // The DataSetWriter is a proper typed instance (HasTypeDefinition -> DataSetWriterType) —
    // the "FX can reference a DataSetWriter by NodeId" proof.
    let type_def = space
        .find_references(
            &writer_id,
            Some((ReferenceTypeId::HasTypeDefinition, false)),
            &tt,
            BrowseDirection::Forward,
        )
        .next()
        .expect("DataSetWriter HasTypeDefinition");
    assert_eq!(
        type_def.target_node,
        &NodeId::from(ObjectTypeId::DataSetWriterType)
    );

    // It carries the DataSetWriterId identity property = 7.
    let id_prop = space
        .find_node_by_browse_name(
            &writer_id,
            Some((ReferenceTypeId::HasProperty, false)),
            &tt,
            BrowseDirection::Forward,
            QualifiedName::from("DataSetWriterId"),
        )
        .expect("DataSetWriterId property");
    let id_value = id_prop
        .as_node()
        .get_attribute(
            TimestampsToReturn::Neither,
            AttributeId::Value,
            &NumericRange::None,
            &DataEncoding::Binary,
        )
        .and_then(|dv| dv.value);
    assert_eq!(id_value, Some(Variant::UInt16(7)));

    // The Connection -> WriterGroup chain is wired via HasWriterGroup, and the group carries
    // WriterGroupId = 42.
    let group = space
        .find_references(
            &conn_id,
            Some((ReferenceTypeId::HasWriterGroup, false)),
            &tt,
            BrowseDirection::Forward,
        )
        .next()
        .expect("Connection HasWriterGroup");
    let wg_prop = space
        .find_node_by_browse_name(
            group.target_node,
            Some((ReferenceTypeId::HasProperty, false)),
            &tt,
            BrowseDirection::Forward,
            QualifiedName::from("WriterGroupId"),
        )
        .expect("WriterGroupId property");
    let wg_value = wg_prop
        .as_node()
        .get_attribute(
            TimestampsToReturn::Neither,
            AttributeId::Value,
            &NumericRange::None,
            &DataEncoding::Binary,
        )
        .and_then(|dv| dv.value);
    assert_eq!(wg_value, Some(Variant::UInt16(42)));
}
