use opcua_types::NodeId;

#[derive(Debug, Clone, Default)]
/// History capabilities.
/// As all history is implemented by custom node managers,
/// this should be set according to what your node managers support.
pub struct HistoryServerCapabilities {
    /// Able to read historical data.
    pub access_history_data: bool,
    /// Able to read historical events.
    pub access_history_events: bool,
    /// Able to delete data at a specific time.
    pub delete_at_time: bool,
    /// Able to delete events.
    pub delete_event: bool,
    /// Able to delete raw data values.
    pub delete_raw: bool,
    /// Able to insert history annotations.
    pub insert_annotation: bool,
    /// Able to insert historical data values.
    pub insert_data: bool,
    /// Able to insert historical events.
    pub insert_event: bool,
    /// Maximum number of data values returned per history read request.
    pub max_return_data_values: u32,
    /// Maximum number of events returned per history read requset.
    pub max_return_event_values: u32,
    /// Able to replace historical data values.
    pub replace_data: bool,
    /// Able to replace historical events.
    pub replace_event: bool,
    /// Stores the time historical data arrived at the server,
    /// as well as its original timestamp.
    pub server_timestamp_supported: bool,
    /// Able to update historical data.
    pub update_data: bool,
    /// Able to update historical events.
    pub update_event: bool,
    /// Supported history aggregates
    pub aggregates: Vec<NodeId>,
}

#[derive(Debug, Clone, Default)]
/// Server capabilities object.
pub struct ServerCapabilities {
    /// Historical server capabilities.
    pub history: HistoryServerCapabilities,
    /// Supported server profiles.
    pub profiles: Vec<String>,
}
