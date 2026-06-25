//! Server-callable OPC UA FX method adapters.

use std::sync::Arc;

use opcua::server::node_manager::memory::SimpleNodeManager;
use opcua::sync::Mutex;
use opcua_types::{
    DynEncodable, ExpandedMessageInfo, ExtensionObject, NodeId, StatusCode, TryFromVariant,
    Variant, VariantScalarTypeId,
};

use crate::{
    process_close_connections, process_establish_connections, AssetVerificationDataType,
    AssetVerificationResultDataType, ConnectionEndpointConfigurationDataType,
    ConnectionEndpointConfigurationResultDataType, FxCommandMask, FxConnectionState,
    PubSubCommunicationConfigurationDataType, PubSubCommunicationConfigurationResultDataType,
    PubSubReserveCommunicationIds2DataType, PubSubReserveCommunicationIdsResult2DataType,
};

/// Handle an FX EstablishConnections Method call.
///
/// # Errors
///
/// Returns a bad OPC UA status code when the input argument count or payload types are invalid.
pub fn handle_establish_connections(
    state: &mut FxConnectionState,
    args: &[Variant],
) -> Result<Vec<Variant>, StatusCode> {
    expect_arg_count(args, 5)?;

    let command_mask = decode_command_mask(&args[0])?;
    let asset_verifications = decode_ext_array::<AssetVerificationDataType>(&args[1])?;
    let endpoint_configs = decode_ext_array::<ConnectionEndpointConfigurationDataType>(&args[2])?;
    let reserve_ids = decode_ext_array::<PubSubReserveCommunicationIds2DataType>(&args[3])?;
    let comm_configs = decode_ext_array::<PubSubCommunicationConfigurationDataType>(&args[4])?;

    let results = process_establish_connections(
        state,
        command_mask,
        &asset_verifications,
        &endpoint_configs,
        &reserve_ids,
        &comm_configs,
    );

    Ok(vec![
        encode_ext_array::<AssetVerificationResultDataType>(results.asset_verification_results),
        encode_ext_array::<ConnectionEndpointConfigurationResultDataType>(
            results.connection_endpoint_results,
        ),
        encode_ext_array::<PubSubReserveCommunicationIdsResult2DataType>(results.reserve_results),
        encode_ext_array::<PubSubCommunicationConfigurationResultDataType>(
            results.communication_results,
        ),
    ])
}

/// Handle an FX CloseConnections Method call.
///
/// # Errors
///
/// Returns a bad OPC UA status code when the input argument count or payload types are invalid.
pub fn handle_close_connections(
    state: &mut FxConnectionState,
    args: &[Variant],
) -> Result<Vec<Variant>, StatusCode> {
    expect_arg_count(args, 2)?;

    let connection_endpoints = decode_array::<NodeId>(&args[0])?;
    let remove =
        bool::try_from_variant(args[1].clone()).map_err(|_| StatusCode::BadInvalidArgument)?;

    let results = process_close_connections(state, &connection_endpoints, remove);

    Ok(vec![Variant::from(results)])
}

/// Register the FX EstablishConnections and CloseConnections Method callbacks on a simple node manager.
pub fn register_fx_connection_methods(
    node_manager: &SimpleNodeManager,
    establish_method_id: NodeId,
    close_method_id: NodeId,
    state: Arc<Mutex<FxConnectionState>>,
) {
    let establish_state = Arc::clone(&state);
    node_manager
        .inner()
        .add_method_callback(establish_method_id, move |args| {
            let mut state = establish_state.lock();
            handle_establish_connections(&mut state, args)
        });

    node_manager
        .inner()
        .add_method_callback(close_method_id, move |args| {
            let mut state = state.lock();
            handle_close_connections(&mut state, args)
        });
}

fn expect_arg_count(args: &[Variant], expected: usize) -> Result<(), StatusCode> {
    match args.len().cmp(&expected) {
        std::cmp::Ordering::Less => Err(StatusCode::BadArgumentsMissing),
        std::cmp::Ordering::Greater => Err(StatusCode::BadTooManyArguments),
        std::cmp::Ordering::Equal => Ok(()),
    }
}

fn decode_command_mask(v: &Variant) -> Result<FxCommandMask, StatusCode> {
    let bits = i32::try_from_variant(v.clone()).map_err(|_| StatusCode::BadInvalidArgument)?;
    Ok(FxCommandMask::from_bits_truncate(bits))
}

fn decode_ext_array<T>(v: &Variant) -> Result<Vec<T>, StatusCode>
where
    T: Clone + Send + Sync + 'static,
{
    match v {
        Variant::Empty => Ok(Vec::new()),
        Variant::Array(array) if array.values.is_empty() => Ok(Vec::new()),
        Variant::Array(array) if array.value_type == VariantScalarTypeId::ExtensionObject => array
            .values
            .iter()
            .map(|value| {
                let Variant::ExtensionObject(obj) = value else {
                    return Err(StatusCode::BadDecodingError);
                };
                obj.inner_as::<T>()
                    .cloned()
                    .ok_or(StatusCode::BadDecodingError)
            })
            .collect(),
        _ => Err(StatusCode::BadInvalidArgument),
    }
}

fn decode_array<T>(v: &Variant) -> Result<Vec<T>, StatusCode>
where
    T: TryFromVariant,
{
    match v {
        Variant::Empty => Ok(Vec::new()),
        Variant::Array(array) if array.values.is_empty() => Ok(Vec::new()),
        _ => Vec::<T>::try_from_variant(v.clone()).map_err(|_| StatusCode::BadInvalidArgument),
    }
}

fn encode_ext_array<T>(items: Vec<T>) -> Variant
where
    T: ExpandedMessageInfo + DynEncodable + 'static,
{
    let values = items
        .into_iter()
        .map(ExtensionObject::from_message)
        .collect::<Vec<_>>();
    Variant::from((VariantScalarTypeId::ExtensionObject, values))
}
