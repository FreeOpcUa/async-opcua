//! Read-only PubSub information-model reflection.

use crate::{
    config::{DataSetReaderConfig, PubSubConnectionConfig, PublishedDataItemsConfig},
    subscriber::DataSetReaderStatus,
};
use opcua_server::address_space::{AddressSpace, ObjectBuilder, VariableBuilder};
use opcua_types::{
    DataTypeId, NodeId, ObjectTypeId, PubSubState, ReferenceTypeId, VariableTypeId, Variant,
};

const PUBLISH_SUBSCRIBE_ID: u32 = 14443;
const PUBLISHED_DATA_SETS_ID: u32 = 17371;

/// NodeIds created for reflected PubSub configuration entities.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PubSubModelMap {
    /// Reflected PubSub connections, keyed by the configured connection id.
    pub connections: Vec<(String, NodeId)>,
    /// Reflected DataSetWriters, keyed by the configured DataSetWriter id.
    pub writers: Vec<(u16, NodeId)>,
    /// Reflected DataSetReaders, keyed by the configured DataSetReader id.
    pub readers: Vec<(u16, NodeId)>,
}

/// Reflects PubSub configuration into the server AddressSpace.
///
/// The function is idempotent for the deterministic NodeIds it creates. Existing
/// nodes are reused and still returned in the map.
#[must_use]
pub fn reflect_pubsub_config(
    address_space: &mut AddressSpace,
    namespace: u16,
    configs: &[PubSubConnectionConfig],
) -> PubSubModelMap {
    reflect_pubsub_config_with_status(address_space, namespace, configs, &[])
}

/// Reflects PubSub configuration and supplied subscriber status snapshots into the AddressSpace.
#[must_use]
pub fn reflect_pubsub_config_with_status(
    address_space: &mut AddressSpace,
    namespace: u16,
    configs: &[PubSubConnectionConfig],
    reader_statuses: &[(u16, DataSetReaderStatus)],
) -> PubSubModelMap {
    let mut map = PubSubModelMap {
        connections: Vec::with_capacity(configs.len()),
        writers: Vec::new(),
        readers: Vec::new(),
    };
    let publish_subscribe_id = NodeId::new(0, PUBLISH_SUBSCRIBE_ID);

    for config in configs {
        let connection_id = connection_node_id(namespace, &config.connection_id);
        ensure_object(
            address_space,
            &connection_id,
            &config.name,
            ObjectTypeId::PubSubConnectionType,
        );
        address_space.insert_reference(
            &publish_subscribe_id,
            &connection_id,
            ReferenceTypeId::HasPubSubConnection,
        );
        map.connections
            .push((config.connection_id.clone(), connection_id.clone()));

        for writer_group in &config.writer_groups {
            let writer_group_id = writer_group_node_id(
                namespace,
                &config.connection_id,
                writer_group.writer_group_id,
            );
            ensure_object(
                address_space,
                &writer_group_id,
                &writer_group.writer_group_id.to_string(),
                ObjectTypeId::WriterGroupType,
            );
            address_space.insert_reference(
                &connection_id,
                &writer_group_id,
                ReferenceTypeId::HasWriterGroup,
            );

            let writer_group_property_id = writer_group_id_property_node_id(
                namespace,
                &config.connection_id,
                writer_group.writer_group_id,
            );
            ensure_u16_property(
                address_space,
                &writer_group_property_id,
                &writer_group_id,
                "WriterGroupId",
                writer_group.writer_group_id,
            );

            for dataset_writer in &writer_group.dataset_writers {
                let dataset_writer_id = dataset_writer_node_id(
                    namespace,
                    &config.connection_id,
                    dataset_writer.dataset_writer_id,
                );
                ensure_object(
                    address_space,
                    &dataset_writer_id,
                    &dataset_writer.dataset_name,
                    ObjectTypeId::DataSetWriterType,
                );
                address_space.insert_reference(
                    &writer_group_id,
                    &dataset_writer_id,
                    ReferenceTypeId::HasDataSetWriter,
                );

                let dataset_writer_property_id = dataset_writer_id_property_node_id(
                    namespace,
                    &config.connection_id,
                    dataset_writer.dataset_writer_id,
                );
                ensure_u16_property(
                    address_space,
                    &dataset_writer_property_id,
                    &dataset_writer_id,
                    "DataSetWriterId",
                    dataset_writer.dataset_writer_id,
                );

                map.writers
                    .push((dataset_writer.dataset_writer_id, dataset_writer_id));
            }
        }

        for reader_group in &config.reader_groups {
            let reader_group_id = reader_group_node_id(
                namespace,
                &config.connection_id,
                reader_group.reader_group_id,
            );
            ensure_object(
                address_space,
                &reader_group_id,
                &reader_group.reader_group_id.to_string(),
                ObjectTypeId::ReaderGroupType,
            );
            address_space.insert_reference(
                &connection_id,
                &reader_group_id,
                ReferenceTypeId::HasReaderGroup,
            );

            let reader_group_property_id = reader_group_id_property_node_id(
                namespace,
                &config.connection_id,
                reader_group.reader_group_id,
            );
            ensure_u16_property(
                address_space,
                &reader_group_property_id,
                &reader_group_id,
                "ReaderGroupId",
                reader_group.reader_group_id,
            );

            for dataset_reader in &reader_group.dataset_readers {
                let dataset_reader_id = reflect_dataset_reader(
                    address_space,
                    namespace,
                    &config.connection_id,
                    &reader_group_id,
                    dataset_reader,
                    reader_statuses,
                );
                map.readers
                    .push((dataset_reader.dataset_reader_id, dataset_reader_id));
            }
        }
    }

    map
}

fn reflect_dataset_reader(
    address_space: &mut AddressSpace,
    namespace: u16,
    connection_id: &str,
    reader_group_id: &NodeId,
    dataset_reader: &DataSetReaderConfig,
    reader_statuses: &[(u16, DataSetReaderStatus)],
) -> NodeId {
    let dataset_reader_id =
        dataset_reader_node_id(namespace, connection_id, dataset_reader.dataset_reader_id);
    ensure_object(
        address_space,
        &dataset_reader_id,
        &dataset_reader.dataset_reader_id.to_string(),
        ObjectTypeId::DataSetReaderType,
    );
    address_space.insert_reference(
        reader_group_id,
        &dataset_reader_id,
        ReferenceTypeId::HasDataSetReader,
    );

    ensure_u16_property(
        address_space,
        &dataset_reader_id_property_node_id(
            namespace,
            connection_id,
            dataset_reader.dataset_reader_id,
        ),
        &dataset_reader_id,
        "DataSetReaderId",
        dataset_reader.dataset_reader_id,
    );
    ensure_u32_property(
        address_space,
        &dataset_reader_target_count_property_node_id(
            namespace,
            connection_id,
            dataset_reader.dataset_reader_id,
        ),
        &dataset_reader_id,
        "TargetVariableCount",
        dataset_reader.effective_target_variables().len() as u32,
    );
    reflect_dataset_reader_status(
        address_space,
        namespace,
        connection_id,
        &dataset_reader_id,
        dataset_reader.dataset_reader_id,
        reader_statuses
            .iter()
            .find(|(reader_id, _)| *reader_id == dataset_reader.dataset_reader_id)
            .map(|(_, status)| status),
    );

    dataset_reader_id
}

fn reflect_dataset_reader_status(
    address_space: &mut AddressSpace,
    namespace: u16,
    connection_id: &str,
    dataset_reader_node_id: &NodeId,
    dataset_reader_id: u16,
    status: Option<&DataSetReaderStatus>,
) {
    let state = status.map_or(PubSubState::PreOperational, |status| status.state);
    ensure_i32_property(
        address_space,
        &dataset_reader_state_property_node_id(namespace, connection_id, dataset_reader_id),
        dataset_reader_node_id,
        "ReaderState",
        state as i32,
    );
    ensure_u64_property(
        address_space,
        &dataset_reader_accepted_count_property_node_id(
            namespace,
            connection_id,
            dataset_reader_id,
        ),
        dataset_reader_node_id,
        "AcceptedCount",
        status.map_or(0, |status| status.accepted_count),
    );
    ensure_u64_property(
        address_space,
        &dataset_reader_filtered_count_property_node_id(
            namespace,
            connection_id,
            dataset_reader_id,
        ),
        dataset_reader_node_id,
        "FilteredCount",
        status.map_or(0, |status| status.filtered_count),
    );
    ensure_u64_property(
        address_space,
        &dataset_reader_dropped_count_property_node_id(namespace, connection_id, dataset_reader_id),
        dataset_reader_node_id,
        "DroppedCount",
        status.map_or(0, |status| status.dropped_count),
    );
}

/// Reflects the top-level PublishedDataItems DataSets under the `PublishedDataSets` folder.
///
/// Returns each DataSet's configured name paired with its reflected NodeId. Idempotent for the
/// deterministic NodeIds it creates.
#[must_use]
pub fn reflect_published_data_sets(
    address_space: &mut AddressSpace,
    namespace: u16,
    configs: &[PublishedDataItemsConfig],
) -> Vec<(String, NodeId)> {
    let folder = NodeId::new(0, PUBLISHED_DATA_SETS_ID);
    let mut map = Vec::with_capacity(configs.len());

    for config in configs {
        let node_id = published_data_set_node_id(namespace, &config.name);
        ensure_object(
            address_space,
            &node_id,
            &config.name,
            ObjectTypeId::PublishedDataItemsType,
        );
        // Part 14 §9.1.4.5.1: a DataSet is a HasComponent of its DataSetFolder.
        address_space.insert_reference(&folder, &node_id, ReferenceTypeId::HasComponent);
        // ponytail: the PublishedData / DataSetMetaData / ConfigurationVersion properties are not
        // reflected; the live config holds them and the Methods return ConfigurationVersion directly.
        map.push((config.name.clone(), node_id));
    }

    map
}

/// Deterministic NodeId for a reflected top-level PublishedDataItems DataSet.
pub(crate) fn published_data_set_node_id(namespace: u16, name: &str) -> NodeId {
    NodeId::new(namespace, format!("PublishedDataSet:{name}"))
}

fn ensure_object(
    address_space: &mut AddressSpace,
    node_id: &NodeId,
    name: &str,
    object_type: ObjectTypeId,
) {
    if address_space.node_exists(node_id) {
        return;
    }

    ObjectBuilder::new(node_id, name, name)
        .has_type_definition(object_type)
        .insert(address_space);
}

fn ensure_u16_property(
    address_space: &mut AddressSpace,
    node_id: &NodeId,
    parent_id: &NodeId,
    name: &str,
    value: u16,
) {
    if address_space.node_exists(node_id) {
        return;
    }

    VariableBuilder::new(node_id, name, name)
        .data_type(DataTypeId::UInt16)
        .has_type_definition(VariableTypeId::PropertyType)
        .value(Variant::UInt16(value))
        .property_of(parent_id.clone())
        .insert(address_space);
}

fn ensure_u32_property(
    address_space: &mut AddressSpace,
    node_id: &NodeId,
    parent_id: &NodeId,
    name: &str,
    value: u32,
) {
    if address_space.node_exists(node_id) {
        return;
    }

    VariableBuilder::new(node_id, name, name)
        .data_type(DataTypeId::UInt32)
        .has_type_definition(VariableTypeId::PropertyType)
        .value(Variant::UInt32(value))
        .property_of(parent_id.clone())
        .insert(address_space);
}

fn ensure_i32_property(
    address_space: &mut AddressSpace,
    node_id: &NodeId,
    parent_id: &NodeId,
    name: &str,
    value: i32,
) {
    if address_space.node_exists(node_id) {
        return;
    }

    VariableBuilder::new(node_id, name, name)
        .data_type(DataTypeId::Int32)
        .has_type_definition(VariableTypeId::PropertyType)
        .value(Variant::Int32(value))
        .property_of(parent_id.clone())
        .insert(address_space);
}

fn ensure_u64_property(
    address_space: &mut AddressSpace,
    node_id: &NodeId,
    parent_id: &NodeId,
    name: &str,
    value: u64,
) {
    if address_space.node_exists(node_id) {
        return;
    }

    VariableBuilder::new(node_id, name, name)
        .data_type(DataTypeId::UInt64)
        .has_type_definition(VariableTypeId::PropertyType)
        .value(Variant::UInt64(value))
        .property_of(parent_id.clone())
        .insert(address_space);
}

pub(crate) fn connection_node_id(namespace: u16, connection_id: &str) -> NodeId {
    NodeId::new(namespace, format!("PubSubConnection:{connection_id}"))
}

pub(crate) fn writer_group_node_id(
    namespace: u16,
    connection_id: &str,
    writer_group_id: u16,
) -> NodeId {
    NodeId::new(
        namespace,
        format!("WriterGroup:{connection_id}:{writer_group_id}"),
    )
}

pub(crate) fn reader_group_node_id(
    namespace: u16,
    connection_id: &str,
    reader_group_id: u16,
) -> NodeId {
    NodeId::new(
        namespace,
        format!("ReaderGroup:{connection_id}:{reader_group_id}"),
    )
}

pub(crate) fn dataset_writer_node_id(
    namespace: u16,
    connection_id: &str,
    dataset_writer_id: u16,
) -> NodeId {
    NodeId::new(
        namespace,
        format!("DataSetWriter:{connection_id}:{dataset_writer_id}"),
    )
}

pub(crate) fn dataset_reader_node_id(
    namespace: u16,
    connection_id: &str,
    dataset_reader_id: u16,
) -> NodeId {
    NodeId::new(
        namespace,
        format!("DataSetReader:{connection_id}:{dataset_reader_id}"),
    )
}

pub(crate) fn writer_group_id_property_node_id(
    namespace: u16,
    connection_id: &str,
    writer_group_id: u16,
) -> NodeId {
    NodeId::new(
        namespace,
        format!("WriterGroup:{connection_id}:{writer_group_id}:WriterGroupId"),
    )
}

pub(crate) fn reader_group_id_property_node_id(
    namespace: u16,
    connection_id: &str,
    reader_group_id: u16,
) -> NodeId {
    NodeId::new(
        namespace,
        format!("ReaderGroup:{connection_id}:{reader_group_id}:ReaderGroupId"),
    )
}

pub(crate) fn dataset_writer_id_property_node_id(
    namespace: u16,
    connection_id: &str,
    dataset_writer_id: u16,
) -> NodeId {
    NodeId::new(
        namespace,
        format!("DataSetWriter:{connection_id}:{dataset_writer_id}:DataSetWriterId"),
    )
}

pub(crate) fn dataset_reader_id_property_node_id(
    namespace: u16,
    connection_id: &str,
    dataset_reader_id: u16,
) -> NodeId {
    NodeId::new(
        namespace,
        format!("DataSetReader:{connection_id}:{dataset_reader_id}:DataSetReaderId"),
    )
}

fn dataset_reader_target_count_property_node_id(
    namespace: u16,
    connection_id: &str,
    dataset_reader_id: u16,
) -> NodeId {
    NodeId::new(
        namespace,
        format!("DataSetReader:{connection_id}:{dataset_reader_id}:TargetVariableCount"),
    )
}

fn dataset_reader_state_property_node_id(
    namespace: u16,
    connection_id: &str,
    dataset_reader_id: u16,
) -> NodeId {
    NodeId::new(
        namespace,
        format!("DataSetReader:{connection_id}:{dataset_reader_id}:ReaderState"),
    )
}

fn dataset_reader_accepted_count_property_node_id(
    namespace: u16,
    connection_id: &str,
    dataset_reader_id: u16,
) -> NodeId {
    NodeId::new(
        namespace,
        format!("DataSetReader:{connection_id}:{dataset_reader_id}:AcceptedCount"),
    )
}

fn dataset_reader_filtered_count_property_node_id(
    namespace: u16,
    connection_id: &str,
    dataset_reader_id: u16,
) -> NodeId {
    NodeId::new(
        namespace,
        format!("DataSetReader:{connection_id}:{dataset_reader_id}:FilteredCount"),
    )
}

fn dataset_reader_dropped_count_property_node_id(
    namespace: u16,
    connection_id: &str,
    dataset_reader_id: u16,
) -> NodeId {
    NodeId::new(
        namespace,
        format!("DataSetReader:{connection_id}:{dataset_reader_id}:DroppedCount"),
    )
}
