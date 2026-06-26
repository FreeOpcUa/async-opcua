//! Writable PubSub configuration methods exposed through the AddressSpace.

use std::sync::Arc;

use opcua_core::sync::{Mutex, RwLock};
use opcua_server::{address_space::AddressSpace, node_manager::memory::CoreNodeManager};
use opcua_types::{
    ConfigurationVersionDataType, MethodId, NodeId, PubSubConnectionDataType, StatusCode, UAString,
    Variant,
};

use crate::{
    config::{
        DataSetReaderConfig, DataSetWriterConfig, MessageEncoding, PubSubConnectionConfig,
        PublishedDataSetConfig, ReaderGroupConfig, WriterGroupConfig,
    },
    pubsub_model::reflect_pubsub_config,
};

/// Live writable PubSub configuration used by the configuration Methods.
#[derive(Debug, Clone)]
pub struct PubSubConfigManager {
    /// Current PubSub connections reflected into the AddressSpace.
    pub connections: Vec<PubSubConnectionConfig>,
    namespace: u16,
}

impl PubSubConfigManager {
    /// Creates an empty writable PubSub configuration manager for `namespace`.
    #[must_use]
    pub fn new(namespace: u16) -> Self {
        Self {
            connections: Vec::new(),
            namespace,
        }
    }

    fn unique_connection_id(&self, name: &str) -> String {
        let base = name.trim();
        if base.is_empty() {
            return self.unique_numbered_connection_id("Connection", 1);
        }

        if !self.connection_id_exists(base) {
            return base.to_string();
        }

        self.unique_numbered_connection_id(base, 1)
    }

    fn unique_numbered_connection_id(&self, base: &str, first_suffix: usize) -> String {
        let mut suffix = first_suffix;
        loop {
            let candidate = format!("{base}{suffix}");
            if !self.connection_id_exists(&candidate) {
                return candidate;
            }
            suffix += 1;
        }
    }

    fn connection_id_exists(&self, connection_id: &str) -> bool {
        self.connections
            .iter()
            .any(|connection| connection.connection_id == connection_id)
    }
}

impl PubSubConnectionConfig {
    /// Converts a Part 14 `PubSubConnectionDataType` into the local PubSub config model.
    #[must_use]
    pub fn from_data_type(
        value: &PubSubConnectionDataType,
        connection_id: String,
    ) -> PubSubConnectionConfig {
        // ponytail: PubSubConnectionConfig does not model Enabled, PublisherId,
        // the Address ExtensionObject, transport settings, message settings, or
        // configuration properties, so those fields are intentionally dropped.
        PubSubConnectionConfig {
            connection_id,
            name: ua_string_to_string(&value.name),
            address: ua_string_to_string(&value.transport_profile_uri),
            writer_groups: value
                .writer_groups
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|writer_group| WriterGroupConfig {
                    writer_group_id: writer_group.writer_group_id,
                    publishing_interval: writer_group.publishing_interval as u64,
                    encoding: MessageEncoding::Uadp,
                    dataset_writers: writer_group
                        .data_set_writers
                        .as_deref()
                        .unwrap_or_default()
                        .iter()
                        .map(|dataset_writer| DataSetWriterConfig {
                            dataset_writer_id: dataset_writer.data_set_writer_id,
                            dataset_name: ua_string_to_string(&dataset_writer.data_set_name),
                            published_dataset: empty_published_dataset(),
                        })
                        .collect(),
                })
                .collect(),
            reader_groups: value
                .reader_groups
                .as_deref()
                .unwrap_or_default()
                .iter()
                .enumerate()
                .map(|(reader_group_index, reader_group)| ReaderGroupConfig {
                    reader_group_id: one_based_u16_id(reader_group_index),
                    dataset_readers: reader_group
                        .data_set_readers
                        .as_deref()
                        .unwrap_or_default()
                        .iter()
                        .enumerate()
                        .map(
                            |(dataset_reader_index, dataset_reader)| DataSetReaderConfig {
                                dataset_reader_id: one_based_u16_id(dataset_reader_index),
                                dataset_writer_id: dataset_reader.data_set_writer_id,
                                publisher_id: None,
                                subscribed_variables: Vec::new(),
                            },
                        )
                        .collect(),
                })
                .collect(),
        }
    }
}

/// Registers PublishSubscribe AddConnection and RemoveConnection method callbacks.
pub fn register_pubsub_config_methods(
    core_node_manager: &CoreNodeManager,
    address_space: Arc<RwLock<AddressSpace>>,
    manager: Arc<Mutex<PubSubConfigManager>>,
) {
    {
        let address_space = Arc::clone(&address_space);
        let manager = Arc::clone(&manager);
        core_node_manager.inner().add_method_callback_with_context(
            MethodId::PublishSubscribe_AddConnection.into(),
            move |_context, _object_id, args| add_connection(&address_space, &manager, args),
        );
    }

    core_node_manager.inner().add_method_callback_with_context(
        MethodId::PublishSubscribe_RemoveConnection.into(),
        move |_context, _object_id, args| remove_connection(&address_space, &manager, args),
    );
}

fn add_connection(
    address_space: &Arc<RwLock<AddressSpace>>,
    manager: &Arc<Mutex<PubSubConfigManager>>,
    args: &[Variant],
) -> Result<Vec<Variant>, StatusCode> {
    let configuration = decode_connection_argument(args)?;

    let mut manager = manager.lock();
    let connection_id = manager.unique_connection_id(&ua_string_to_string(&configuration.name));
    let connection = PubSubConnectionConfig::from_data_type(configuration, connection_id.clone());
    manager.connections.push(connection);

    let mut space = address_space.write();
    let map = reflect_pubsub_config(&mut space, manager.namespace, &manager.connections);
    let node_id = map
        .connections
        .iter()
        .find_map(|(mapped_connection_id, node_id)| {
            (mapped_connection_id == &connection_id).then(|| node_id.clone())
        })
        .ok_or(StatusCode::BadInternalError)?;

    Ok(vec![Variant::from(node_id)])
}

fn remove_connection(
    address_space: &Arc<RwLock<AddressSpace>>,
    manager: &Arc<Mutex<PubSubConfigManager>>,
    args: &[Variant],
) -> Result<Vec<Variant>, StatusCode> {
    let node_id = decode_node_id_argument(args)?;

    let mut manager = manager.lock();
    let mut space = address_space.write();
    let map = reflect_pubsub_config(&mut space, manager.namespace, &manager.connections);
    let connection_id = map
        .connections
        .iter()
        .find_map(|(connection_id, reflected_node_id)| {
            (reflected_node_id == node_id).then(|| connection_id.clone())
        })
        .ok_or(StatusCode::BadNodeIdUnknown)?;

    let index = manager
        .connections
        .iter()
        .position(|connection| connection.connection_id == connection_id)
        .ok_or(StatusCode::BadNodeIdUnknown)?;
    manager.connections.remove(index);
    space.delete(node_id, true);

    Ok(Vec::new())
}

fn decode_connection_argument(args: &[Variant]) -> Result<&PubSubConnectionDataType, StatusCode> {
    let argument = args.first().ok_or(StatusCode::BadArgumentsMissing)?;
    let Variant::ExtensionObject(object) = argument else {
        return Err(StatusCode::BadInvalidArgument);
    };

    object
        .inner_as::<PubSubConnectionDataType>()
        .ok_or(StatusCode::BadInvalidArgument)
}

fn decode_node_id_argument(args: &[Variant]) -> Result<&NodeId, StatusCode> {
    let argument = args.first().ok_or(StatusCode::BadArgumentsMissing)?;
    let Variant::NodeId(node_id) = argument else {
        return Err(StatusCode::BadInvalidArgument);
    };

    Ok(node_id)
}

fn ua_string_to_string(value: &UAString) -> String {
    value.to_string()
}

fn empty_published_dataset() -> PublishedDataSetConfig {
    PublishedDataSetConfig {
        published_variables: Vec::new(),
        configuration_version: ConfigurationVersionDataType {
            major_version: 0,
            minor_version: 0,
        },
    }
}

fn one_based_u16_id(index: usize) -> u16 {
    u16::try_from(index.saturating_add(1)).unwrap_or(u16::MAX)
}
