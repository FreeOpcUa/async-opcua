use opcua_types::{
    AttributeId, ConfigurationVersionDataType, Guid, MessageSecurityMode, NodeId,
    OverrideValueHandling, StatusCode,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{collections::HashSet, str::FromStr, time::Duration};

use crate::codec::uadp::PublisherId;

/// Message encoding formats supported by the PubSub implementation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MessageEncoding {
    /// JSON message encoding (usually over MQTT).
    Json,
    /// UADP binary message encoding (usually over UDP multicast).
    Uadp,
}

/// Helper function to serialize an array of `NodeId`s as strings.
pub fn serialize_node_ids<S>(node_ids: &[NodeId], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    use serde::ser::SerializeSeq;
    let mut seq = serializer.serialize_seq(Some(node_ids.len()))?;
    for node_id in node_ids {
        seq.serialize_element(&node_id.to_string())?;
    }
    seq.end()
}

/// Helper function to deserialize an array of `NodeId`s from strings.
pub fn deserialize_node_ids<'de, D>(deserializer: D) -> Result<Vec<NodeId>, D::Error>
where
    D: Deserializer<'de>,
{
    let strings: Vec<String> = serde::Deserialize::deserialize(deserializer)?;
    let mut node_ids = Vec::with_capacity(strings.len());
    for s in strings {
        let node_id = NodeId::from_str(&s).map_err(|e| {
            serde::de::Error::custom(format!("Invalid NodeId: {s}, error: {:?}", e))
        })?;
        node_ids.push(node_id);
    }
    Ok(node_ids)
}

fn serialize_node_id<S>(node_id: &NodeId, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&node_id.to_string())
}

fn deserialize_node_id<'de, D>(deserializer: D) -> Result<NodeId, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    NodeId::from_str(&s)
        .map_err(|e| serde::de::Error::custom(format!("Invalid NodeId: {s}, error: {e:?}")))
}

/// The collection of variables grouped together in a single payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublishedDataSetConfig {
    /// List of published variable NodeIds.
    #[serde(
        deserialize_with = "deserialize_node_ids",
        serialize_with = "serialize_node_ids"
    )]
    pub published_variables: Vec<NodeId>,
    /// Configuration version for the DataSet metadata.
    #[serde(default, with = "configuration_version_serde")]
    pub configuration_version: ConfigurationVersionDataType,
}

impl Eq for PublishedDataSetConfig {}

/// A named, top-level PublishedDataItems DataSet held under the `PublishedDataSets` folder.
///
/// Unlike [`PublishedDataSetConfig`] (which is embedded in a DataSetWriter), this is a
/// standalone DataSet addressable in the address space and mutated via the writable PubSub
/// configuration Methods (`AddPublishedDataItems` / `AddVariables` / ...).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublishedDataItemsConfig {
    /// Symbolic name of the DataSet (unique within the folder).
    pub name: String,
    /// List of published variable NodeIds, in field order.
    #[serde(
        deserialize_with = "deserialize_node_ids",
        serialize_with = "serialize_node_ids"
    )]
    pub published_variables: Vec<NodeId>,
    /// Configuration version for the DataSet metadata.
    #[serde(default, with = "configuration_version_serde")]
    pub configuration_version: ConfigurationVersionDataType,
}

impl Eq for PublishedDataItemsConfig {}

/// Maps specific variable NodeIds to outbound DataSets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataSetWriterConfig {
    /// Unique identifier for the dataset writer.
    pub dataset_writer_id: u16,
    /// Symbolic name of the dataset.
    pub dataset_name: String,
    /// The configuration of the published dataset.
    pub published_dataset: PublishedDataSetConfig,
}

/// Configures publishing interval cycle and message type (JSON vs. UADP).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WriterGroupConfig {
    /// Unique identifier for the writer group.
    pub writer_group_id: u16,
    /// Publishing interval in milliseconds.
    pub publishing_interval: u64,
    /// The encoding format to use for messages.
    pub encoding: MessageEncoding,
    /// List of dataset writers in this writer group.
    pub dataset_writers: Vec<DataSetWriterConfig>,
}

/// Supported field encodings for DataSetReader application.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum DataSetFieldEncoding {
    /// Supported Variant/DataValue-compatible field encoding.
    #[default]
    Variant,
    /// RawData field encoding is rejected by the subscriber runtime for this feature.
    RawData,
}

/// Supported DataSetMessage kinds for DataSetReader application.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum DataSetMessageKind {
    /// Supported key-frame DataSetMessage.
    #[default]
    KeyFrame,
    /// Delta frames are rejected by the subscriber runtime for this feature.
    DeltaFrame,
    /// Event DataSetMessages are rejected by the subscriber runtime for this feature.
    Event,
}

/// Maps a received DataSet field to a target Variable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldTargetConfig {
    /// Zero-based DataSet field index.
    pub dataset_field_index: usize,
    /// Optional stable DataSet field id from metadata.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_guid",
        serialize_with = "serialize_optional_guid"
    )]
    pub dataset_field_id: Option<Guid>,
    /// Target Variable NodeId.
    #[serde(
        deserialize_with = "deserialize_node_id",
        serialize_with = "serialize_node_id"
    )]
    pub target_node_id: NodeId,
    /// Target AttributeId. This feature supports Value only.
    #[serde(
        default = "default_value_attribute",
        deserialize_with = "deserialize_attribute_id",
        serialize_with = "serialize_attribute_id"
    )]
    pub attribute_id: AttributeId,
    /// Optional NumericRange string. Non-empty ranges are rejected until implemented.
    #[serde(default)]
    pub index_range: Option<String>,
    /// Override value handling. This feature supports Disabled only.
    #[serde(
        default = "default_override_value_handling",
        deserialize_with = "deserialize_override_value_handling",
        serialize_with = "serialize_override_value_handling"
    )]
    pub override_value_handling: OverrideValueHandling,
}

impl FieldTargetConfig {
    /// Creates a Value-attribute target for a field index.
    #[must_use]
    pub fn value(dataset_field_index: usize, target_node_id: NodeId) -> Self {
        Self {
            dataset_field_index,
            dataset_field_id: None,
            target_node_id,
            attribute_id: AttributeId::Value,
            index_range: None,
            override_value_handling: OverrideValueHandling::Disabled,
        }
    }
}

/// Maps received DataSet fields to target variables.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataSetReaderConfig {
    /// Optional human-readable reader name, unique within a ReaderGroup when present.
    #[serde(default)]
    pub name: Option<String>,
    /// Unique identifier for the dataset reader.
    pub dataset_reader_id: u16,
    /// The dataset writer ID this reader consumes.
    pub dataset_writer_id: u16,
    /// Optional PublisherId filter for incoming NetworkMessages.
    #[serde(default)]
    pub publisher_id: Option<PublisherId>,
    /// Optional UADP WriterGroupId filter.
    #[serde(default)]
    pub writer_group_id: Option<u16>,
    /// Optional UADP NetworkMessageNumber filter.
    #[serde(default)]
    pub network_message_number: Option<u16>,
    /// DataSetReader message receive timeout.
    #[serde(default)]
    pub message_receive_timeout: Option<Duration>,
    /// Configured metadata major version, if known.
    #[serde(default)]
    pub metadata_major_version: Option<u32>,
    /// DataSetReader security mode override.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_message_security_mode",
        serialize_with = "serialize_optional_message_security_mode"
    )]
    pub security_mode: Option<MessageSecurityMode>,
    /// DataSetReader security policy URI override.
    #[serde(default)]
    pub security_policy_uri: Option<String>,
    /// DataSetReader security group id override.
    #[serde(default)]
    pub security_group_id: Option<String>,
    /// Subscriber message encoding. Only UADP is supported for this feature.
    #[serde(default = "default_message_encoding")]
    pub message_encoding: MessageEncoding,
    /// Subscriber field encoding. RawData is rejected for this feature.
    #[serde(default)]
    pub field_encoding: DataSetFieldEncoding,
    /// Subscriber DataSetMessage kind. Delta/event messages are rejected for this feature.
    #[serde(default)]
    pub message_kind: DataSetMessageKind,
    /// FieldTargetDataType-equivalent target mappings.
    #[serde(default)]
    pub target_variables: Vec<FieldTargetConfig>,
    /// Target variable NodeIds in received field order.
    #[serde(default)]
    #[serde(
        deserialize_with = "deserialize_node_ids",
        serialize_with = "serialize_node_ids"
    )]
    pub subscribed_variables: Vec<NodeId>,
}

impl Default for DataSetReaderConfig {
    fn default() -> Self {
        Self {
            name: None,
            dataset_reader_id: 0,
            dataset_writer_id: 0,
            publisher_id: None,
            writer_group_id: None,
            network_message_number: None,
            message_receive_timeout: None,
            metadata_major_version: None,
            security_mode: None,
            security_policy_uri: None,
            security_group_id: None,
            message_encoding: MessageEncoding::Uadp,
            field_encoding: DataSetFieldEncoding::Variant,
            message_kind: DataSetMessageKind::KeyFrame,
            target_variables: Vec::new(),
            subscribed_variables: Vec::new(),
        }
    }
}

impl DataSetReaderConfig {
    /// Returns explicit target mappings or legacy subscribed-variable mappings in field order.
    #[must_use]
    pub fn effective_target_variables(&self) -> Vec<FieldTargetConfig> {
        if !self.target_variables.is_empty() {
            return self.target_variables.clone();
        }

        self.subscribed_variables
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, target)| FieldTargetConfig::value(index, target))
            .collect()
    }

    fn validate(&self) -> Result<(), StatusCode> {
        if self.message_encoding != MessageEncoding::Uadp {
            return Err(StatusCode::BadNotSupported);
        }
        if self.field_encoding != DataSetFieldEncoding::Variant {
            return Err(StatusCode::BadNotSupported);
        }
        if self.message_kind != DataSetMessageKind::KeyFrame {
            return Err(StatusCode::BadNotSupported);
        }

        let targets = self.effective_target_variables();
        let mut seen_targets = HashSet::with_capacity(targets.len());
        for target in targets {
            if target.attribute_id != AttributeId::Value {
                return Err(StatusCode::BadNotSupported);
            }
            if matches!(target.index_range.as_deref(), Some(range) if !range.is_empty()) {
                return Err(StatusCode::BadNotSupported);
            }
            if target.override_value_handling != OverrideValueHandling::Disabled {
                return Err(StatusCode::BadNotSupported);
            }
            if !seen_targets.insert(target.target_node_id) {
                return Err(StatusCode::BadConfigurationError);
            }
        }

        Ok(())
    }
}

/// Groups configured DataSetReaders for inbound PubSub traffic.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReaderGroupConfig {
    /// Unique identifier for the reader group.
    pub reader_group_id: u16,
    /// Shared ReaderGroup security mode for received NetworkMessages.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_message_security_mode",
        serialize_with = "serialize_optional_message_security_mode"
    )]
    pub security_mode: Option<MessageSecurityMode>,
    /// Shared ReaderGroup security policy URI.
    #[serde(default)]
    pub security_policy_uri: Option<String>,
    /// Shared ReaderGroup security group id.
    #[serde(default)]
    pub security_group_id: Option<String>,
    /// List of dataset readers in this reader group.
    pub dataset_readers: Vec<DataSetReaderConfig>,
}

/// Represents dataset publishing structures.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PubSubConnectionConfig {
    /// Uniquely identifies a transport adapter.
    pub connection_id: String,
    /// Symbolic name of the connection.
    pub name: String,
    /// Transport URL (e.g., `mqtt://broker.local:1883` or `udp://239.0.0.1:4840`).
    pub address: String,
    /// List of writer groups associated with this connection.
    pub writer_groups: Vec<WriterGroupConfig>,
    /// List of reader groups associated with this connection.
    #[serde(default)]
    pub reader_groups: Vec<ReaderGroupConfig>,
}

impl PubSubConnectionConfig {
    /// Validates subscriber-side ReaderGroup/DataSetReader configuration.
    pub fn validate_subscriber_config(&self) -> Result<(), StatusCode> {
        if self.reader_groups.is_empty() {
            return Ok(());
        }

        if !self.address.trim().starts_with("udp://") {
            return Err(StatusCode::BadNotSupported);
        }

        for reader_group in &self.reader_groups {
            validate_unique_reader_names(reader_group)?;
            for reader in &reader_group.dataset_readers {
                reader.validate()?;
                validate_security(reader_group, reader)?;
            }
        }

        Ok(())
    }
}

fn validate_unique_reader_names(reader_group: &ReaderGroupConfig) -> Result<(), StatusCode> {
    let mut names = HashSet::new();
    for reader in &reader_group.dataset_readers {
        let Some(name) = reader.name.as_deref().filter(|name| !name.is_empty()) else {
            continue;
        };
        if !names.insert(name) {
            return Err(StatusCode::BadConfigurationError);
        }
    }
    Ok(())
}

fn validate_security(
    reader_group: &ReaderGroupConfig,
    reader: &DataSetReaderConfig,
) -> Result<(), StatusCode> {
    let mode = reader.security_mode.or(reader_group.security_mode);
    if matches!(
        mode,
        Some(MessageSecurityMode::Sign | MessageSecurityMode::SignAndEncrypt)
    ) {
        let policy = reader
            .security_policy_uri
            .as_deref()
            .or(reader_group.security_policy_uri.as_deref())
            .unwrap_or_default();
        let group_id = reader
            .security_group_id
            .as_deref()
            .or(reader_group.security_group_id.as_deref())
            .unwrap_or_default();
        if policy.is_empty() || group_id.is_empty() {
            return Err(StatusCode::BadConfigurationError);
        }
    }

    Ok(())
}

const fn default_value_attribute() -> AttributeId {
    AttributeId::Value
}

const fn default_override_value_handling() -> OverrideValueHandling {
    OverrideValueHandling::Disabled
}

fn default_message_encoding() -> MessageEncoding {
    MessageEncoding::Uadp
}

fn serialize_optional_guid<S>(value: &Option<Guid>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    value
        .as_ref()
        .map(ToString::to_string)
        .serialize(serializer)
}

fn deserialize_optional_guid<'de, D>(deserializer: D) -> Result<Option<Guid>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    value
        .map(|value| {
            Guid::from_str(&value)
                .map_err(|error| serde::de::Error::custom(format!("Invalid Guid: {error:?}")))
        })
        .transpose()
}

fn serialize_attribute_id<S>(value: &AttributeId, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_u32(*value as u32)
}

fn deserialize_attribute_id<'de, D>(deserializer: D) -> Result<AttributeId, D::Error>
where
    D: Deserializer<'de>,
{
    let value = u32::deserialize(deserializer)?;
    AttributeId::from_u32(value)
        .map_err(|_| serde::de::Error::custom(format!("Invalid AttributeId: {value}")))
}

fn serialize_override_value_handling<S>(
    value: &OverrideValueHandling,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_i32(*value as i32)
}

fn deserialize_override_value_handling<'de, D>(
    deserializer: D,
) -> Result<OverrideValueHandling, D::Error>
where
    D: Deserializer<'de>,
{
    match i32::deserialize(deserializer)? {
        0 => Ok(OverrideValueHandling::Disabled),
        1 => Ok(OverrideValueHandling::LastUsableValue),
        2 => Ok(OverrideValueHandling::OverrideValue),
        value => Err(serde::de::Error::custom(format!(
            "Invalid OverrideValueHandling: {value}"
        ))),
    }
}

fn serialize_optional_message_security_mode<S>(
    value: &Option<MessageSecurityMode>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    value
        .as_ref()
        .map(|value| *value as i32)
        .serialize(serializer)
}

fn deserialize_optional_message_security_mode<'de, D>(
    deserializer: D,
) -> Result<Option<MessageSecurityMode>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<i32>::deserialize(deserializer)?;
    value.map(message_security_mode_from_i32).transpose()
}

fn message_security_mode_from_i32<E: serde::de::Error>(
    value: i32,
) -> Result<MessageSecurityMode, E> {
    match value {
        0 => Ok(MessageSecurityMode::Invalid),
        1 => Ok(MessageSecurityMode::None),
        2 => Ok(MessageSecurityMode::Sign),
        3 => Ok(MessageSecurityMode::SignAndEncrypt),
        value => Err(serde::de::Error::custom(format!(
            "Invalid MessageSecurityMode: {value}"
        ))),
    }
}

mod configuration_version_serde {
    use opcua_types::ConfigurationVersionDataType;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct ConfigurationVersionSerde {
        major_version: u32,
        minor_version: u32,
    }

    pub(super) fn serialize<S>(
        version: &ConfigurationVersionDataType,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ConfigurationVersionSerde {
            major_version: version.major_version,
            minor_version: version.minor_version,
        }
        .serialize(serializer)
    }

    pub(super) fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<ConfigurationVersionDataType, D::Error>
    where
        D: Deserializer<'de>,
    {
        let version = ConfigurationVersionSerde::deserialize(deserializer)?;
        Ok(ConfigurationVersionDataType {
            major_version: version.major_version,
            minor_version: version.minor_version,
        })
    }
}
