use opcua_types::{ConfigurationVersionDataType, NodeId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;

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

/// Maps received DataSet fields to target variables.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataSetReaderConfig {
    /// Unique identifier for the dataset reader.
    pub dataset_reader_id: u16,
    /// The dataset writer ID this reader consumes.
    pub dataset_writer_id: u16,
    /// Optional PublisherId filter for incoming NetworkMessages.
    pub publisher_id: Option<PublisherId>,
    /// Target variable NodeIds in received field order.
    #[serde(
        deserialize_with = "deserialize_node_ids",
        serialize_with = "serialize_node_ids"
    )]
    pub subscribed_variables: Vec<NodeId>,
}

/// Groups configured DataSetReaders for inbound PubSub traffic.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReaderGroupConfig {
    /// Unique identifier for the reader group.
    pub reader_group_id: u16,
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
