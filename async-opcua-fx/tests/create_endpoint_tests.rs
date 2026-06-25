//! Independent tests for FX piece 2b: CreateConnectionEndpointCmd + SetConfigurationDataCmd,
//! plus the now-reachable create→close round trip.

use async_opcua_fx::{
    process_close_connections, process_establish_connections,
    ConnectionEndpointConfigurationDataType, ConnectionEndpointDefinitionDataType, FxCommandMask,
    FxConnectionState, NodeIdValuePair,
};
use opcua_types::{NodeId, StatusCode, Variant};

fn endpoint_config(
    node: &NodeId,
    config_data: Option<Vec<NodeIdValuePair>>,
) -> ConnectionEndpointConfigurationDataType {
    ConnectionEndpointConfigurationDataType {
        functional_entity_node: NodeId::new(1, "FE"),
        connection_endpoint: ConnectionEndpointDefinitionDataType::Node(node.clone()),
        configuration_data: config_data,
        ..Default::default()
    }
}

#[test]
fn create_connection_endpoint_tracks_endpoint() {
    let mut state = FxConnectionState::new();
    let ep = NodeId::new(2, "Endpoint1");
    let results = process_establish_connections(
        &mut state,
        FxCommandMask::CreateConnectionEndpointCmd,
        &[],
        &[endpoint_config(&ep, None)],
        &[],
        &[],
    );

    assert_eq!(results.connection_endpoint_results.len(), 1);
    assert_eq!(
        results.connection_endpoint_results[0].connection_endpoint_result,
        StatusCode::Good
    );
    assert_eq!(
        results.connection_endpoint_results[0].connection_endpoint_id,
        ep
    );
    assert_eq!(state.endpoints().len(), 1);
    assert_eq!(state.endpoints()[0].node_id, ep);
}

#[test]
fn set_configuration_data_stores_on_created_endpoint() {
    let mut state = FxConnectionState::new();
    let ep = NodeId::new(2, "Endpoint1");
    let kv = NodeIdValuePair {
        value: Variant::from(42i32),
        ..Default::default()
    };

    // Create + SetConfigurationData in one bundle (bit 4 runs before bit 16).
    let results = process_establish_connections(
        &mut state,
        FxCommandMask::CreateConnectionEndpointCmd | FxCommandMask::SetConfigurationDataCmd,
        &[],
        &[endpoint_config(&ep, Some(vec![kv.clone()]))],
        &[],
        &[],
    );

    // Two results: one from create, one from set-config (both Good).
    assert!(results
        .connection_endpoint_results
        .iter()
        .any(|r| r.configuration_data_result.as_deref() == Some(&[StatusCode::Good][..])));
    assert_eq!(state.endpoints()[0].configuration_data, vec![kv]);
}

#[test]
fn set_configuration_data_on_unknown_endpoint_is_not_found() {
    let mut state = FxConnectionState::new();
    let ep = NodeId::new(2, "Unknown");
    let kv = NodeIdValuePair::default();
    let results = process_establish_connections(
        &mut state,
        FxCommandMask::SetConfigurationDataCmd,
        &[],
        &[endpoint_config(&ep, Some(vec![kv]))],
        &[],
        &[],
    );
    assert_eq!(
        results.connection_endpoint_results[0].configuration_data_result,
        Some(vec![StatusCode::BadNotFound])
    );
}

#[test]
fn create_then_close_removes_endpoint() {
    let mut state = FxConnectionState::new();
    let ep = NodeId::new(2, "Endpoint1");
    let _ = process_establish_connections(
        &mut state,
        FxCommandMask::CreateConnectionEndpointCmd,
        &[],
        &[endpoint_config(&ep, None)],
        &[],
        &[],
    );
    assert_eq!(state.endpoints().len(), 1);

    let statuses = process_close_connections(&mut state, &[ep], true);
    assert_eq!(statuses, vec![StatusCode::Good]);
    assert!(
        state.endpoints().is_empty(),
        "remove=true must drop the endpoint"
    );
}
