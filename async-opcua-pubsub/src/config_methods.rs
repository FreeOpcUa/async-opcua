//! Writable PubSub configuration methods exposed through the AddressSpace.

use std::sync::Arc;

use opcua_core::sync::{Mutex, RwLock};
use opcua_server::{address_space::AddressSpace, node_manager::memory::CoreNodeManager};
use opcua_types::{
    ConfigurationVersionDataType, DataSetReaderDataType, DataSetWriterDataType, MethodId, NodeId,
    PubSubConnectionDataType, ReaderGroupDataType, StatusCode, UAString, Variant,
    WriterGroupDataType,
};

use crate::{
    config::{
        DataSetReaderConfig, DataSetWriterConfig, MessageEncoding, PubSubConnectionConfig,
        PublishedDataSetConfig, ReaderGroupConfig, WriterGroupConfig,
    },
    pubsub_model::{
        connection_node_id, dataset_reader_id_property_node_id, dataset_reader_node_id,
        dataset_writer_id_property_node_id, dataset_writer_node_id,
        reader_group_id_property_node_id, reader_group_node_id, reflect_pubsub_config,
        writer_group_id_property_node_id, writer_group_node_id,
    },
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

    /// Index of the connection whose reflected object NodeId is `object_id`.
    fn connection_index_for_node(&self, object_id: &NodeId) -> Option<usize> {
        self.connections.iter().position(|connection| {
            &connection_node_id(self.namespace, &connection.connection_id) == object_id
        })
    }

    /// `(connection index, writer-group index)` for the writer group reflected as `object_id`.
    fn writer_group_location(&self, object_id: &NodeId) -> Option<(usize, usize)> {
        for (ci, connection) in self.connections.iter().enumerate() {
            for (gi, group) in connection.writer_groups.iter().enumerate() {
                let id = writer_group_node_id(
                    self.namespace,
                    &connection.connection_id,
                    group.writer_group_id,
                );
                if &id == object_id {
                    return Some((ci, gi));
                }
            }
        }
        None
    }

    /// `(connection index, reader-group index)` for the reader group reflected as `object_id`.
    fn reader_group_location(&self, object_id: &NodeId) -> Option<(usize, usize)> {
        for (ci, connection) in self.connections.iter().enumerate() {
            for (gi, group) in connection.reader_groups.iter().enumerate() {
                let id = reader_group_node_id(
                    self.namespace,
                    &connection.connection_id,
                    group.reader_group_id,
                );
                if &id == object_id {
                    return Some((ci, gi));
                }
            }
        }
        None
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
                .map(WriterGroupConfig::from_data_type)
                .collect(),
            reader_groups: value
                .reader_groups
                .as_deref()
                .unwrap_or_default()
                .iter()
                .enumerate()
                .map(|(index, reader_group)| {
                    ReaderGroupConfig::from_data_type(reader_group, one_based_u16_id(index))
                })
                .collect(),
        }
    }
}

impl WriterGroupConfig {
    /// Converts a Part 14 `WriterGroupDataType` into the local writer-group config model.
    #[must_use]
    pub fn from_data_type(value: &WriterGroupDataType) -> WriterGroupConfig {
        WriterGroupConfig {
            writer_group_id: value.writer_group_id,
            publishing_interval: value.publishing_interval as u64,
            encoding: MessageEncoding::Uadp,
            dataset_writers: value
                .data_set_writers
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(DataSetWriterConfig::from_data_type)
                .collect(),
        }
    }
}

impl DataSetWriterConfig {
    /// Converts a Part 14 `DataSetWriterDataType` into the local dataset-writer config model.
    #[must_use]
    pub fn from_data_type(value: &DataSetWriterDataType) -> DataSetWriterConfig {
        DataSetWriterConfig {
            dataset_writer_id: value.data_set_writer_id,
            dataset_name: ua_string_to_string(&value.data_set_name),
            published_dataset: empty_published_dataset(),
        }
    }
}

impl ReaderGroupConfig {
    /// Converts a Part 14 `ReaderGroupDataType` into the local reader-group config model.
    ///
    /// `ReaderGroupDataType` has no group identifier, so the caller supplies one.
    #[must_use]
    pub fn from_data_type(value: &ReaderGroupDataType, reader_group_id: u16) -> ReaderGroupConfig {
        ReaderGroupConfig {
            reader_group_id,
            dataset_readers: value
                .data_set_readers
                .as_deref()
                .unwrap_or_default()
                .iter()
                .enumerate()
                .map(|(index, reader)| {
                    DataSetReaderConfig::from_data_type(reader, one_based_u16_id(index))
                })
                .collect(),
        }
    }
}

impl DataSetReaderConfig {
    /// Converts a Part 14 `DataSetReaderDataType` into the local dataset-reader config model.
    ///
    /// `DataSetReaderDataType` has no reader identifier, so the caller supplies one.
    #[must_use]
    pub fn from_data_type(
        value: &DataSetReaderDataType,
        dataset_reader_id: u16,
    ) -> DataSetReaderConfig {
        DataSetReaderConfig {
            dataset_reader_id,
            dataset_writer_id: value.data_set_writer_id,
            publisher_id: None,
            subscribed_variables: Vec::new(),
        }
    }
}

/// Registers the writable PubSub configuration Methods on the address space.
///
/// Covers the singleton `PublishSubscribe` object (AddConnection / RemoveConnection) plus the
/// per-instance connection, writer-group and reader-group Methods. The per-instance Methods are
/// registered against their `*Type` Method node and routed to the right config object via the
/// called object's NodeId.
pub fn register_pubsub_config_methods(
    core_node_manager: &CoreNodeManager,
    address_space: Arc<RwLock<AddressSpace>>,
    manager: Arc<Mutex<PubSubConfigManager>>,
) {
    // (Method node id, handler). Each handler gets the called object's NodeId so per-instance
    // Methods can resolve the target connection / group from the deterministic reflected ids.
    type Handler = fn(
        &Arc<RwLock<AddressSpace>>,
        &Arc<Mutex<PubSubConfigManager>>,
        &NodeId,
        &[Variant],
    ) -> Result<Vec<Variant>, StatusCode>;

    let methods: [(MethodId, Handler); 9] = [
        (MethodId::PublishSubscribe_AddConnection, add_connection),
        (
            MethodId::PublishSubscribe_RemoveConnection,
            remove_connection,
        ),
        (
            MethodId::PubSubConnectionType_AddWriterGroup,
            add_writer_group,
        ),
        (
            MethodId::PubSubConnectionType_AddReaderGroup,
            add_reader_group,
        ),
        (MethodId::PubSubConnectionType_RemoveGroup, remove_group),
        (
            MethodId::WriterGroupType_AddDataSetWriter,
            add_dataset_writer,
        ),
        (
            MethodId::WriterGroupType_RemoveDataSetWriter,
            remove_dataset_writer,
        ),
        (
            MethodId::ReaderGroupType_AddDataSetReader,
            add_dataset_reader,
        ),
        (
            MethodId::ReaderGroupType_RemoveDataSetReader,
            remove_dataset_reader,
        ),
    ];

    for (method_id, handler) in methods {
        let address_space = Arc::clone(&address_space);
        let manager = Arc::clone(&manager);
        core_node_manager.inner().add_method_callback_with_context(
            method_id.into(),
            move |_context, object_id, args| handler(&address_space, &manager, object_id, args),
        );
    }
}

fn add_connection(
    address_space: &Arc<RwLock<AddressSpace>>,
    manager: &Arc<Mutex<PubSubConfigManager>>,
    _object_id: &NodeId,
    args: &[Variant],
) -> Result<Vec<Variant>, StatusCode> {
    let configuration = decode_argument::<PubSubConnectionDataType>(args)?;

    let mut manager = manager.lock();
    let ns = manager.namespace;
    let connection_id = manager.unique_connection_id(&ua_string_to_string(&configuration.name));
    let connection = PubSubConnectionConfig::from_data_type(configuration, connection_id.clone());
    manager.connections.push(connection);

    let mut space = address_space.write();
    let _ = reflect_pubsub_config(&mut space, ns, &manager.connections);
    Ok(vec![Variant::from(connection_node_id(ns, &connection_id))])
}

fn remove_connection(
    address_space: &Arc<RwLock<AddressSpace>>,
    manager: &Arc<Mutex<PubSubConfigManager>>,
    _object_id: &NodeId,
    args: &[Variant],
) -> Result<Vec<Variant>, StatusCode> {
    let node_id = decode_node_id_argument(args)?;

    let mut manager = manager.lock();
    let ns = manager.namespace;
    let index = manager
        .connections
        .iter()
        .position(|connection| &connection_node_id(ns, &connection.connection_id) == node_id)
        .ok_or(StatusCode::BadNodeIdUnknown)?;
    let removed = manager.connections.remove(index);

    let mut space = address_space.write();
    delete_connection_nodes(&mut space, ns, &removed);
    let _ = reflect_pubsub_config(&mut space, ns, &manager.connections);
    Ok(Vec::new())
}

fn add_writer_group(
    address_space: &Arc<RwLock<AddressSpace>>,
    manager: &Arc<Mutex<PubSubConfigManager>>,
    object_id: &NodeId,
    args: &[Variant],
) -> Result<Vec<Variant>, StatusCode> {
    let configuration = decode_argument::<WriterGroupDataType>(args)?;

    let mut manager = manager.lock();
    let ns = manager.namespace;
    let ci = manager
        .connection_index_for_node(object_id)
        .ok_or(StatusCode::BadNodeIdUnknown)?;
    let connection_id = manager.connections[ci].connection_id.clone();

    let mut group = WriterGroupConfig::from_data_type(configuration);
    {
        let connection = &manager.connections[ci];
        if group.writer_group_id == 0 || writer_group_id_taken(connection, group.writer_group_id) {
            group.writer_group_id = next_writer_group_id(connection);
        }
        // Mint connection-unique dataset-writer ids so node ids never collide across groups.
        let mut next = next_dataset_writer_id(connection);
        for writer in &mut group.dataset_writers {
            writer.dataset_writer_id = next;
            next = next.saturating_add(1);
        }
    }
    let writer_group_id = group.writer_group_id;
    manager.connections[ci].writer_groups.push(group);

    let mut space = address_space.write();
    let _ = reflect_pubsub_config(&mut space, ns, &manager.connections);
    Ok(vec![Variant::from(writer_group_node_id(
        ns,
        &connection_id,
        writer_group_id,
    ))])
}

fn add_reader_group(
    address_space: &Arc<RwLock<AddressSpace>>,
    manager: &Arc<Mutex<PubSubConfigManager>>,
    object_id: &NodeId,
    args: &[Variant],
) -> Result<Vec<Variant>, StatusCode> {
    let configuration = decode_argument::<ReaderGroupDataType>(args)?;

    let mut manager = manager.lock();
    let ns = manager.namespace;
    let ci = manager
        .connection_index_for_node(object_id)
        .ok_or(StatusCode::BadNodeIdUnknown)?;
    let connection_id = manager.connections[ci].connection_id.clone();

    let reader_group_id = next_reader_group_id(&manager.connections[ci]);
    let mut group = ReaderGroupConfig::from_data_type(configuration, reader_group_id);
    {
        // Mint connection-unique dataset-reader ids so node ids never collide across groups.
        let mut next = next_dataset_reader_id(&manager.connections[ci]);
        for reader in &mut group.dataset_readers {
            reader.dataset_reader_id = next;
            next = next.saturating_add(1);
        }
    }
    manager.connections[ci].reader_groups.push(group);

    let mut space = address_space.write();
    let _ = reflect_pubsub_config(&mut space, ns, &manager.connections);
    Ok(vec![Variant::from(reader_group_node_id(
        ns,
        &connection_id,
        reader_group_id,
    ))])
}

fn remove_group(
    address_space: &Arc<RwLock<AddressSpace>>,
    manager: &Arc<Mutex<PubSubConfigManager>>,
    object_id: &NodeId,
    args: &[Variant],
) -> Result<Vec<Variant>, StatusCode> {
    let group_node = decode_node_id_argument(args)?;

    let mut manager = manager.lock();
    let ns = manager.namespace;
    let ci = manager
        .connection_index_for_node(object_id)
        .ok_or(StatusCode::BadNodeIdUnknown)?;
    let connection_id = manager.connections[ci].connection_id.clone();

    if let Some(gi) = manager.connections[ci]
        .writer_groups
        .iter()
        .position(|g| &writer_group_node_id(ns, &connection_id, g.writer_group_id) == group_node)
    {
        let removed = manager.connections[ci].writer_groups.remove(gi);
        let mut space = address_space.write();
        delete_writer_group_nodes(&mut space, ns, &connection_id, &removed);
        let _ = reflect_pubsub_config(&mut space, ns, &manager.connections);
        return Ok(Vec::new());
    }

    if let Some(gi) = manager.connections[ci]
        .reader_groups
        .iter()
        .position(|g| &reader_group_node_id(ns, &connection_id, g.reader_group_id) == group_node)
    {
        let removed = manager.connections[ci].reader_groups.remove(gi);
        let mut space = address_space.write();
        delete_reader_group_nodes(&mut space, ns, &connection_id, &removed);
        let _ = reflect_pubsub_config(&mut space, ns, &manager.connections);
        return Ok(Vec::new());
    }

    Err(StatusCode::BadNodeIdUnknown)
}

fn add_dataset_writer(
    address_space: &Arc<RwLock<AddressSpace>>,
    manager: &Arc<Mutex<PubSubConfigManager>>,
    object_id: &NodeId,
    args: &[Variant],
) -> Result<Vec<Variant>, StatusCode> {
    let configuration = decode_argument::<DataSetWriterDataType>(args)?;

    let mut manager = manager.lock();
    let ns = manager.namespace;
    let (ci, gi) = manager
        .writer_group_location(object_id)
        .ok_or(StatusCode::BadNodeIdUnknown)?;
    let connection_id = manager.connections[ci].connection_id.clone();

    let mut writer = DataSetWriterConfig::from_data_type(configuration);
    if writer.dataset_writer_id == 0
        || dataset_writer_id_taken(&manager.connections[ci], writer.dataset_writer_id)
    {
        writer.dataset_writer_id = next_dataset_writer_id(&manager.connections[ci]);
    }
    let dataset_writer_id = writer.dataset_writer_id;
    manager.connections[ci].writer_groups[gi]
        .dataset_writers
        .push(writer);

    let mut space = address_space.write();
    let _ = reflect_pubsub_config(&mut space, ns, &manager.connections);
    Ok(vec![Variant::from(dataset_writer_node_id(
        ns,
        &connection_id,
        dataset_writer_id,
    ))])
}

fn remove_dataset_writer(
    address_space: &Arc<RwLock<AddressSpace>>,
    manager: &Arc<Mutex<PubSubConfigManager>>,
    object_id: &NodeId,
    args: &[Variant],
) -> Result<Vec<Variant>, StatusCode> {
    let node = decode_node_id_argument(args)?;

    let mut manager = manager.lock();
    let ns = manager.namespace;
    let (ci, gi) = manager
        .writer_group_location(object_id)
        .ok_or(StatusCode::BadNodeIdUnknown)?;
    let connection_id = manager.connections[ci].connection_id.clone();

    let idx = manager.connections[ci].writer_groups[gi]
        .dataset_writers
        .iter()
        .position(|w| &dataset_writer_node_id(ns, &connection_id, w.dataset_writer_id) == node)
        .ok_or(StatusCode::BadNodeIdUnknown)?;
    let removed = manager.connections[ci].writer_groups[gi]
        .dataset_writers
        .remove(idx);

    let mut space = address_space.write();
    delete_dataset_writer_nodes(&mut space, ns, &connection_id, &removed);
    let _ = reflect_pubsub_config(&mut space, ns, &manager.connections);
    Ok(Vec::new())
}

fn add_dataset_reader(
    address_space: &Arc<RwLock<AddressSpace>>,
    manager: &Arc<Mutex<PubSubConfigManager>>,
    object_id: &NodeId,
    args: &[Variant],
) -> Result<Vec<Variant>, StatusCode> {
    let configuration = decode_argument::<DataSetReaderDataType>(args)?;

    let mut manager = manager.lock();
    let ns = manager.namespace;
    let (ci, gi) = manager
        .reader_group_location(object_id)
        .ok_or(StatusCode::BadNodeIdUnknown)?;
    let connection_id = manager.connections[ci].connection_id.clone();

    let dataset_reader_id = next_dataset_reader_id(&manager.connections[ci]);
    let reader = DataSetReaderConfig::from_data_type(configuration, dataset_reader_id);
    manager.connections[ci].reader_groups[gi]
        .dataset_readers
        .push(reader);

    let mut space = address_space.write();
    let _ = reflect_pubsub_config(&mut space, ns, &manager.connections);
    Ok(vec![Variant::from(dataset_reader_node_id(
        ns,
        &connection_id,
        dataset_reader_id,
    ))])
}

fn remove_dataset_reader(
    address_space: &Arc<RwLock<AddressSpace>>,
    manager: &Arc<Mutex<PubSubConfigManager>>,
    object_id: &NodeId,
    args: &[Variant],
) -> Result<Vec<Variant>, StatusCode> {
    let node = decode_node_id_argument(args)?;

    let mut manager = manager.lock();
    let ns = manager.namespace;
    let (ci, gi) = manager
        .reader_group_location(object_id)
        .ok_or(StatusCode::BadNodeIdUnknown)?;
    let connection_id = manager.connections[ci].connection_id.clone();

    let idx = manager.connections[ci].reader_groups[gi]
        .dataset_readers
        .iter()
        .position(|r| &dataset_reader_node_id(ns, &connection_id, r.dataset_reader_id) == node)
        .ok_or(StatusCode::BadNodeIdUnknown)?;
    let removed = manager.connections[ci].reader_groups[gi]
        .dataset_readers
        .remove(idx);

    let mut space = address_space.write();
    delete_dataset_reader_nodes(&mut space, ns, &connection_id, &removed);
    let _ = reflect_pubsub_config(&mut space, ns, &manager.connections);
    Ok(Vec::new())
}

fn writer_group_id_taken(connection: &PubSubConnectionConfig, id: u16) -> bool {
    connection
        .writer_groups
        .iter()
        .any(|group| group.writer_group_id == id)
}

fn dataset_writer_id_taken(connection: &PubSubConnectionConfig, id: u16) -> bool {
    connection
        .writer_groups
        .iter()
        .flat_map(|group| &group.dataset_writers)
        .any(|writer| writer.dataset_writer_id == id)
}

fn next_writer_group_id(connection: &PubSubConnectionConfig) -> u16 {
    next_id(connection.writer_groups.iter().map(|g| g.writer_group_id))
}

fn next_reader_group_id(connection: &PubSubConnectionConfig) -> u16 {
    next_id(connection.reader_groups.iter().map(|g| g.reader_group_id))
}

fn next_dataset_writer_id(connection: &PubSubConnectionConfig) -> u16 {
    next_id(
        connection
            .writer_groups
            .iter()
            .flat_map(|group| &group.dataset_writers)
            .map(|writer| writer.dataset_writer_id),
    )
}

fn next_dataset_reader_id(connection: &PubSubConnectionConfig) -> u16 {
    next_id(
        connection
            .reader_groups
            .iter()
            .flat_map(|group| &group.dataset_readers)
            .map(|reader| reader.dataset_reader_id),
    )
}

fn next_id(existing: impl Iterator<Item = u16>) -> u16 {
    existing.max().map_or(1, |max| max.saturating_add(1))
}

// `AddressSpace::delete` is not recursive, so removals delete the entity's whole reflected subtree.

fn delete_connection_nodes(space: &mut AddressSpace, ns: u16, connection: &PubSubConnectionConfig) {
    for group in &connection.writer_groups {
        delete_writer_group_nodes(space, ns, &connection.connection_id, group);
    }
    for group in &connection.reader_groups {
        delete_reader_group_nodes(space, ns, &connection.connection_id, group);
    }
    space.delete(&connection_node_id(ns, &connection.connection_id), true);
}

fn delete_writer_group_nodes(
    space: &mut AddressSpace,
    ns: u16,
    connection_id: &str,
    group: &WriterGroupConfig,
) {
    for writer in &group.dataset_writers {
        delete_dataset_writer_nodes(space, ns, connection_id, writer);
    }
    space.delete(
        &writer_group_id_property_node_id(ns, connection_id, group.writer_group_id),
        true,
    );
    space.delete(
        &writer_group_node_id(ns, connection_id, group.writer_group_id),
        true,
    );
}

fn delete_dataset_writer_nodes(
    space: &mut AddressSpace,
    ns: u16,
    connection_id: &str,
    writer: &DataSetWriterConfig,
) {
    space.delete(
        &dataset_writer_id_property_node_id(ns, connection_id, writer.dataset_writer_id),
        true,
    );
    space.delete(
        &dataset_writer_node_id(ns, connection_id, writer.dataset_writer_id),
        true,
    );
}

fn delete_reader_group_nodes(
    space: &mut AddressSpace,
    ns: u16,
    connection_id: &str,
    group: &ReaderGroupConfig,
) {
    for reader in &group.dataset_readers {
        delete_dataset_reader_nodes(space, ns, connection_id, reader);
    }
    space.delete(
        &reader_group_id_property_node_id(ns, connection_id, group.reader_group_id),
        true,
    );
    space.delete(
        &reader_group_node_id(ns, connection_id, group.reader_group_id),
        true,
    );
}

fn delete_dataset_reader_nodes(
    space: &mut AddressSpace,
    ns: u16,
    connection_id: &str,
    reader: &DataSetReaderConfig,
) {
    space.delete(
        &dataset_reader_id_property_node_id(ns, connection_id, reader.dataset_reader_id),
        true,
    );
    space.delete(
        &dataset_reader_node_id(ns, connection_id, reader.dataset_reader_id),
        true,
    );
}

fn decode_argument<T: Send + Sync + 'static>(args: &[Variant]) -> Result<&T, StatusCode> {
    let argument = args.first().ok_or(StatusCode::BadArgumentsMissing)?;
    let Variant::ExtensionObject(object) = argument else {
        return Err(StatusCode::BadInvalidArgument);
    };

    object.inner_as::<T>().ok_or(StatusCode::BadInvalidArgument)
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
