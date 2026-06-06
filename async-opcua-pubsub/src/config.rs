use opcua_types::NodeId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;

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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublishedDataSetConfig {
    /// List of published variable NodeIds.
    #[serde(
        deserialize_with = "deserialize_node_ids",
        serialize_with = "serialize_node_ids"
    )]
    pub published_variables: Vec<NodeId>,
}

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
}
