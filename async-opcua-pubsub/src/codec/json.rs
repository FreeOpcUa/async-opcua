use opcua_types::{
    json::{JsonDecodable, JsonEncodable},
    Context, Error,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Convert an OPC-UA `JsonEncodable` type into a `serde_json::Value`.
pub fn opcua_to_json_value<T: JsonEncodable>(value: &T, ctx: &Context<'_>) -> Result<Value, Error> {
    let json_str = opcua_types::json::to_string(value, ctx)?;
    let val = serde_json::from_str(&json_str).map_err(|e| Error::decoding(e.to_string()))?;
    Ok(val)
}

/// Convert a `serde_json::Value` into an OPC-UA `JsonDecodable` type.
pub fn json_value_to_opcua<T: JsonDecodable>(val: &Value, ctx: &Context<'_>) -> Result<T, Error> {
    let json_str = serde_json::to_string(val).map_err(|e| Error::decoding(e.to_string()))?;
    opcua_types::json::from_bytes(json_str.as_bytes(), ctx)
}

/// A DataSetMessage formatted as JSON.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonDataSetMessage {
    /// Unique identifier for the dataset writer.
    #[serde(rename = "DataSetWriterId")]
    pub dataset_writer_id: u16,
    /// Cyclic sequence number of the dataset message.
    #[serde(rename = "SequenceNumber")]
    pub sequence_number: u16,
    /// The payload containing the keys mapped to serialized JSON values.
    #[serde(rename = "Payload")]
    pub payload: HashMap<String, Value>,
}

/// A complete JSON NetworkMessage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonNetworkMessage {
    /// Unique identifier for the network message.
    #[serde(rename = "MessageId")]
    pub message_id: String,
    /// Type of message, e.g. "ua-data".
    #[serde(rename = "MessageType")]
    pub message_type: String,
    /// Uniquely identifies the publisher device.
    #[serde(rename = "PublisherId")]
    pub publisher_id: String,
    /// Unique identifier for the writer group.
    #[serde(rename = "WriterGroupId")]
    pub writer_group_id: u16,
    /// List of dataset messages included in the payload.
    #[serde(rename = "Messages")]
    pub messages: Vec<JsonDataSetMessage>,
}

impl JsonNetworkMessage {
    /// Serializes the network message into a JSON string.
    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserializes the network message from a JSON string.
    pub fn from_json_string(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}
