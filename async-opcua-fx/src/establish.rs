//! Pure OPC UA FX EstablishConnections/CloseConnections command dispatch core.

use opcua_pubsub::{
    ConnectionManager, DataSetReaderConfig, DataSetWriterConfig, IdReservation, MessageEncoding,
    PubSubConnectionConfig, PublishedDataSetConfig, ReaderGroupConfig, WriterGroupConfig,
};
use opcua_types::{ConfigurationVersionDataType, NodeId, StatusCode, UAString, Variant};

use crate::{
    AssetVerificationDataType, AssetVerificationResultDataType,
    ConnectionEndpointConfigurationDataType, ConnectionEndpointConfigurationResultDataType,
    FxCommandMask, NodeIdValuePair, PubSubCommunicationConfigurationDataType,
    PubSubCommunicationConfigurationResultDataType, PubSubReserveCommunicationIds2DataType,
    PubSubReserveCommunicationIdsResult2DataType,
};

const COMMANDS_IN_SPEC_ORDER: [FxCommandMask; 9] = [
    FxCommandMask::VerifyAssetCmd,
    FxCommandMask::VerifyFunctionalEntityCmd,
    FxCommandMask::CreateConnectionEndpointCmd,
    FxCommandMask::EstablishControlCmd,
    FxCommandMask::SetConfigurationDataCmd,
    FxCommandMask::ReassignControlCmd,
    FxCommandMask::ReserveCommunicationIdsCmd,
    FxCommandMask::SetCommunicationConfigurationCmd,
    FxCommandMask::EnableCommunicationCmd,
];

/// Pure in-memory FX connection state used by command dispatch.
#[derive(Debug, Default)]
pub struct FxConnectionState {
    /// Current PubSub connection configurations.
    pub connections: Vec<PubSubConnectionConfig>,
    reservation: IdReservation,
    manager: ConnectionManager,
    endpoints: Vec<EstablishedEndpoint>,
}

/// Created ConnectionEndpoint state tracked by the pure dispatch layer.
#[derive(Debug, Clone, PartialEq)]
pub struct EstablishedEndpoint {
    /// NodeId of the ConnectionEndpoint.
    pub node_id: NodeId,
    /// ConnectionEndpoint configuration used to create the endpoint.
    pub config: ConnectionEndpointConfigurationDataType,
    /// Reserved WriterGroupIds associated with this endpoint.
    pub reserved_writer_group_ids: Vec<u16>,
    /// Reserved DataSetWriterIds associated with this endpoint.
    pub reserved_data_set_writer_ids: Vec<u16>,
    /// ConfigurationVersion values recorded at establishment time.
    pub configuration_versions: Vec<ConfigurationVersionDataType>,
    /// ConfigurationData values applied to this endpoint.
    pub configuration_data: Vec<NodeIdValuePair>,
    /// Whether communication for the endpoint is enabled in this pure state.
    pub enabled: bool,
    /// PubSub connection IDs associated with the endpoint.
    pub connection_ids: Vec<String>,
}

/// Per-command result arrays returned by EstablishConnections processing.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EstablishResults {
    /// Results for VerifyAssetCmd.
    pub asset_verification_results: Vec<AssetVerificationResultDataType>,
    /// Results for ConnectionEndpoint-related commands.
    pub connection_endpoint_results: Vec<ConnectionEndpointConfigurationResultDataType>,
    /// Results for ReserveCommunicationIdsCmd.
    pub reserve_results: Vec<PubSubReserveCommunicationIdsResult2DataType>,
    /// Results for SetCommunicationConfigurationCmd.
    pub communication_results: Vec<PubSubCommunicationConfigurationResultDataType>,
}

impl FxConnectionState {
    /// Create empty pure FX connection state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Access the reservation state.
    #[must_use]
    pub fn reservation(&self) -> &IdReservation {
        &self.reservation
    }

    /// Access the in-process connection manager.
    #[must_use]
    pub fn manager(&self) -> &ConnectionManager {
        &self.manager
    }

    /// Access tracked established endpoints.
    #[must_use]
    pub fn endpoints(&self) -> &[EstablishedEndpoint] {
        &self.endpoints
    }
}

/// Process a pure EstablishConnections command bundle.
#[must_use]
pub fn process_establish_connections(
    state: &mut FxConnectionState,
    command_mask: FxCommandMask,
    asset_verifications: &[AssetVerificationDataType],
    endpoint_configs: &[ConnectionEndpointConfigurationDataType],
    reserve_ids: &[PubSubReserveCommunicationIds2DataType],
    comm_configs: &[PubSubCommunicationConfigurationDataType],
) -> EstablishResults {
    let mut results = EstablishResults::default();
    let mut aborted = false;

    for command in COMMANDS_IN_SPEC_ORDER {
        if aborted || !command_mask.contains(command) {
            continue;
        }

        let command_result = if command == FxCommandMask::VerifyAssetCmd {
            unsupported_asset_verification(asset_verifications, &mut results)
        } else if command == FxCommandMask::VerifyFunctionalEntityCmd {
            unsupported_endpoint_command(
                endpoint_configs,
                &mut results,
                EndpointResultField::Verification,
            )
        } else if command == FxCommandMask::CreateConnectionEndpointCmd {
            create_connection_endpoints(state, endpoint_configs, &mut results)
        } else if command == FxCommandMask::EstablishControlCmd {
            unsupported_endpoint_command(
                endpoint_configs,
                &mut results,
                EndpointResultField::EstablishControl,
            )
        } else if command == FxCommandMask::SetConfigurationDataCmd {
            set_configuration_data(state, endpoint_configs, &mut results)
        } else if command == FxCommandMask::ReassignControlCmd {
            unsupported_endpoint_command(
                endpoint_configs,
                &mut results,
                EndpointResultField::ReassignControl,
            )
        } else if command == FxCommandMask::ReserveCommunicationIdsCmd {
            reserve_communication_ids(state, reserve_ids, &mut results)
        } else if command == FxCommandMask::SetCommunicationConfigurationCmd {
            set_communication_configuration(state, comm_configs, &mut results)
        } else {
            enable_communication(state, endpoint_configs, &mut results)
        };

        if command_result.is_err() {
            aborted = true;
        }
    }

    results
}

/// Process a pure CloseConnections request.
#[must_use]
pub fn process_close_connections(
    state: &mut FxConnectionState,
    connection_endpoints: &[NodeId],
    remove: bool,
) -> Vec<StatusCode> {
    connection_endpoints
        .iter()
        .map(|endpoint_id| close_connection_endpoint(state, endpoint_id, remove))
        .collect()
}

fn unsupported_asset_verification(
    asset_verifications: &[AssetVerificationDataType],
    results: &mut EstablishResults,
) -> Result<(), StatusCode> {
    // ponytail: filled by FX pieces 2b/3/4.
    let count = result_count(asset_verifications.len());
    results
        .asset_verification_results
        .extend((0..count).map(|_| asset_verification_result(StatusCode::BadNotSupported)));
    Err(StatusCode::BadNotSupported)
}

#[derive(Debug, Copy, Clone)]
enum EndpointResultField {
    Verification,
    ConnectionEndpoint,
    EstablishControl,
    ConfigurationData,
    ReassignControl,
}

fn unsupported_endpoint_command(
    endpoint_configs: &[ConnectionEndpointConfigurationDataType],
    results: &mut EstablishResults,
    field: EndpointResultField,
) -> Result<(), StatusCode> {
    // ponytail: filled by FX pieces 2b/3/4.
    let count = result_count(endpoint_configs.len());
    results.connection_endpoint_results.extend(
        (0..count).map(|_| endpoint_result_with_status(StatusCode::BadNotSupported, field)),
    );
    Err(StatusCode::BadNotSupported)
}

fn create_connection_endpoints(
    state: &mut FxConnectionState,
    endpoint_configs: &[ConnectionEndpointConfigurationDataType],
    results: &mut EstablishResults,
) -> Result<(), StatusCode> {
    for endpoint_config in endpoint_configs {
        let node_id = endpoint_config.connection_endpoint_node_id();
        let status = validate_connection_endpoint_config(endpoint_config);
        let mut result =
            endpoint_result_with_status(status, EndpointResultField::ConnectionEndpoint);
        result.connection_endpoint_id = node_id.clone();

        if !status.is_good() {
            results.connection_endpoint_results.push(result);
            return Err(status);
        }

        if let Some(endpoint) = state
            .endpoints
            .iter_mut()
            .find(|endpoint| endpoint.node_id == node_id)
        {
            endpoint.config = endpoint_config.clone();
        } else {
            state.endpoints.push(EstablishedEndpoint {
                node_id,
                config: endpoint_config.clone(),
                reserved_writer_group_ids: Vec::new(),
                reserved_data_set_writer_ids: Vec::new(),
                configuration_versions: Vec::new(),
                configuration_data: Vec::new(),
                enabled: false,
                connection_ids: Vec::new(),
            });
        }

        results.connection_endpoint_results.push(result);
    }

    Ok(())
}

fn set_configuration_data(
    state: &mut FxConnectionState,
    endpoint_configs: &[ConnectionEndpointConfigurationDataType],
    results: &mut EstablishResults,
) -> Result<(), StatusCode> {
    for endpoint_config in endpoint_configs {
        let node_id = endpoint_config.connection_endpoint_node_id();
        let configuration_data = endpoint_config
            .configuration_data
            .as_deref()
            .unwrap_or_default();
        let mut result =
            endpoint_result_with_status(StatusCode::Good, EndpointResultField::ConfigurationData);
        result.connection_endpoint_id = node_id.clone();
        result.configuration_data_result = endpoint_config
            .configuration_data
            .as_ref()
            .map(|data| vec![StatusCode::Good; data.len()]);

        let Some(endpoint) = state
            .endpoints
            .iter_mut()
            .find(|endpoint| endpoint.node_id == node_id)
        else {
            let status = StatusCode::BadNotFound;
            result.configuration_data_result = endpoint_config
                .configuration_data
                .as_ref()
                .map(|data| vec![status; data.len()]);
            results.connection_endpoint_results.push(result);
            return Err(status);
        };

        merge_configuration_data(&mut endpoint.configuration_data, configuration_data);
        results.connection_endpoint_results.push(result);
    }

    Ok(())
}

fn validate_connection_endpoint_config(
    endpoint_config: &ConnectionEndpointConfigurationDataType,
) -> StatusCode {
    if matches!(
        endpoint_config.connection_endpoint,
        crate::ConnectionEndpointDefinitionDataType::Null
    ) && endpoint_config.functional_entity_node.is_null()
    {
        StatusCode::BadInvalidArgument
    } else {
        StatusCode::Good
    }
}

fn merge_configuration_data(existing: &mut Vec<NodeIdValuePair>, updates: &[NodeIdValuePair]) {
    for update in updates {
        if let Some(existing_pair) = existing.iter_mut().find(|pair| pair.key == update.key) {
            *existing_pair = update.clone();
        } else {
            existing.push(update.clone());
        }
    }
}

fn reserve_communication_ids(
    state: &mut FxConnectionState,
    reserve_ids: &[PubSubReserveCommunicationIds2DataType],
    results: &mut EstablishResults,
) -> Result<(), StatusCode> {
    for request in reserve_ids {
        let (writer_group_ids, data_set_writer_ids) = state.reservation.reserve(
            &state.connections,
            request.num_req_writer_group_ids,
            request.num_req_data_set_writer_ids,
        );

        let status = if writer_group_ids.len() == usize::from(request.num_req_writer_group_ids)
            && data_set_writer_ids.len() == usize::from(request.num_req_data_set_writer_ids)
        {
            StatusCode::Good
        } else {
            StatusCode::BadResourceUnavailable
        };

        results
            .reserve_results
            .push(PubSubReserveCommunicationIdsResult2DataType {
                result: status,
                default_publisher_id: Variant::from(()),
                writer_group_ids: Some(writer_group_ids),
                data_set_writer_ids: Some(data_set_writer_ids),
                transport_specific_info: Variant::from(()),
            });

        if !status.is_good() {
            return Err(status);
        }
    }

    Ok(())
}

fn set_communication_configuration(
    state: &mut FxConnectionState,
    comm_configs: &[PubSubCommunicationConfigurationDataType],
    results: &mut EstablishResults,
) -> Result<(), StatusCode> {
    for comm_config in comm_configs {
        let status = apply_communication_configuration(state, comm_config);
        let good = status.is_good();
        results
            .communication_results
            .push(communication_result(status, good));

        if !good {
            return Err(status);
        }
    }

    Ok(())
}

fn apply_communication_configuration(
    state: &mut FxConnectionState,
    comm_config: &PubSubCommunicationConfigurationDataType,
) -> StatusCode {
    let Some(connections) = comm_config.pub_sub_configuration.connections.as_ref() else {
        return StatusCode::BadInvalidArgument;
    };

    if connections.is_empty() {
        return StatusCode::BadInvalidArgument;
    }

    if comm_config.require_complete_update {
        state.connections.clear();
    }

    for connection in connections {
        let converted = convert_connection(connection);
        let connection_id = converted.connection_id.clone();

        if let Some(existing) = state
            .connections
            .iter_mut()
            .find(|existing| existing.connection_id == connection_id)
        {
            *existing = converted;
        } else {
            state.connections.push(converted);
        }
    }

    StatusCode::Good
}

fn enable_communication(
    state: &mut FxConnectionState,
    endpoint_configs: &[ConnectionEndpointConfigurationDataType],
    results: &mut EstablishResults,
) -> Result<(), StatusCode> {
    if endpoint_configs.is_empty() {
        for endpoint in &mut state.endpoints {
            endpoint.enabled = true;
        }
        results
            .connection_endpoint_results
            .push(endpoint_result_with_status(
                StatusCode::Good,
                EndpointResultField::ConnectionEndpoint,
            ));
        return Ok(());
    }

    for endpoint_config in endpoint_configs {
        let node_id = endpoint_config.connection_endpoint_node_id();
        if let Some(endpoint) = state
            .endpoints
            .iter_mut()
            .find(|endpoint| endpoint.node_id == node_id)
        {
            endpoint.enabled = true;
        }

        let mut result =
            endpoint_result_with_status(StatusCode::Good, EndpointResultField::ConnectionEndpoint);
        result.connection_endpoint_id = node_id;
        result.enable_communication_result = StatusCode::Good;
        results.connection_endpoint_results.push(result);
    }

    Ok(())
}

fn close_connection_endpoint(
    state: &mut FxConnectionState,
    endpoint_id: &NodeId,
    remove: bool,
) -> StatusCode {
    let Some(endpoint_index) = state
        .endpoints
        .iter()
        .position(|endpoint| endpoint.node_id == *endpoint_id)
    else {
        return StatusCode::BadNotFound;
    };

    if remove {
        let endpoint = state.endpoints.remove(endpoint_index);
        state
            .connections
            .retain(|connection| !endpoint.connection_ids.contains(&connection.connection_id));
    } else if let Some(endpoint) = state.endpoints.get_mut(endpoint_index) {
        endpoint.enabled = false;
    }

    StatusCode::Good
}

fn convert_connection(
    connection: &opcua_types::PubSubConnectionDataType,
) -> PubSubConnectionConfig {
    let name = string_value(&connection.name);
    let connection_id = if name.is_empty() {
        stable_connection_id(connection)
    } else {
        name.clone()
    };

    PubSubConnectionConfig {
        connection_id,
        name,
        address: string_value(&connection.transport_profile_uri),
        writer_groups: connection
            .writer_groups
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(convert_writer_group)
            .collect(),
        reader_groups: connection
            .reader_groups
            .as_deref()
            .unwrap_or_default()
            .iter()
            .enumerate()
            .map(|(index, reader_group)| convert_reader_group(index, reader_group))
            .collect(),
    }
}

fn stable_connection_id(connection: &opcua_types::PubSubConnectionDataType) -> String {
    let publisher = if matches!(connection.publisher_id, Variant::Empty) {
        String::from("publisher-null")
    } else {
        format!("{:?}", connection.publisher_id)
    };
    format!(
        "{}:{}",
        string_value(&connection.transport_profile_uri),
        publisher
    )
}

fn convert_writer_group(writer_group: &opcua_types::WriterGroupDataType) -> WriterGroupConfig {
    WriterGroupConfig {
        writer_group_id: writer_group.writer_group_id,
        publishing_interval: duration_millis(writer_group.publishing_interval),
        encoding: MessageEncoding::Uadp,
        dataset_writers: writer_group
            .data_set_writers
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(convert_data_set_writer)
            .collect(),
    }
}

fn convert_data_set_writer(
    data_set_writer: &opcua_types::DataSetWriterDataType,
) -> DataSetWriterConfig {
    DataSetWriterConfig {
        dataset_writer_id: data_set_writer.data_set_writer_id,
        dataset_name: string_value(&data_set_writer.data_set_name),
        published_dataset: PublishedDataSetConfig {
            published_variables: Vec::new(),
            configuration_version: ConfigurationVersionDataType::default(),
        },
    }
}

fn convert_reader_group(
    index: usize,
    reader_group: &opcua_types::ReaderGroupDataType,
) -> ReaderGroupConfig {
    ReaderGroupConfig {
        reader_group_id: u16::try_from(index.saturating_add(1)).unwrap_or(u16::MAX),
        dataset_readers: reader_group
            .data_set_readers
            .as_deref()
            .unwrap_or_default()
            .iter()
            .enumerate()
            .map(|(reader_index, reader)| convert_data_set_reader(reader_index, reader))
            .collect(),
    }
}

fn convert_data_set_reader(
    index: usize,
    data_set_reader: &opcua_types::DataSetReaderDataType,
) -> DataSetReaderConfig {
    DataSetReaderConfig {
        dataset_reader_id: u16::try_from(index.saturating_add(1)).unwrap_or(u16::MAX),
        dataset_writer_id: data_set_reader.data_set_writer_id,
        publisher_id: None,
        subscribed_variables: Vec::new(),
    }
}

fn endpoint_result_with_status(
    status: StatusCode,
    field: EndpointResultField,
) -> ConnectionEndpointConfigurationResultDataType {
    let mut result = ConnectionEndpointConfigurationResultDataType {
        functional_entity_node_result: StatusCode::Good,
        connection_endpoint_result: StatusCode::Good,
        verification_status: StatusCode::Good,
        communication_links_result: StatusCode::Good,
        enable_communication_result: StatusCode::Good,
        ..ConnectionEndpointConfigurationResultDataType::default()
    };

    match field {
        EndpointResultField::Verification => result.functional_entity_node_result = status,
        EndpointResultField::ConnectionEndpoint => result.connection_endpoint_result = status,
        EndpointResultField::EstablishControl => {
            result.establish_control_result = Some(vec![status]);
        }
        EndpointResultField::ConfigurationData => {
            result.configuration_data_result = Some(vec![status]);
        }
        EndpointResultField::ReassignControl => {
            result.reassign_control_result = Some(vec![status]);
        }
    }

    result
}

fn asset_verification_result(status: StatusCode) -> AssetVerificationResultDataType {
    AssetVerificationResultDataType {
        verification_status: status,
        ..AssetVerificationResultDataType::default()
    }
}

fn communication_result(
    status: StatusCode,
    changes_applied: bool,
) -> PubSubCommunicationConfigurationResultDataType {
    PubSubCommunicationConfigurationResultDataType {
        result: status,
        changes_applied,
        ..PubSubCommunicationConfigurationResultDataType::default()
    }
}

fn result_count(input_count: usize) -> usize {
    input_count.max(1)
}

fn string_value(value: &UAString) -> String {
    value.value().clone().unwrap_or_default()
}

fn duration_millis(duration: opcua_types::Duration) -> u64 {
    if duration.is_finite() && duration > 0.0 {
        duration as u64
    } else {
        0
    }
}

trait ConnectionEndpointNodeId {
    fn connection_endpoint_node_id(&self) -> NodeId;
}

impl ConnectionEndpointNodeId for ConnectionEndpointConfigurationDataType {
    fn connection_endpoint_node_id(&self) -> NodeId {
        match &self.connection_endpoint {
            crate::ConnectionEndpointDefinitionDataType::Node(node_id) => node_id.clone(),
            crate::ConnectionEndpointDefinitionDataType::Parameter(_) => {
                self.functional_entity_node.clone()
            }
            crate::ConnectionEndpointDefinitionDataType::Null => {
                self.functional_entity_node.clone()
            }
        }
    }
}
