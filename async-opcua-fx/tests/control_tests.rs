//! Independent tests for FX piece 4: EstablishControl / ReassignControl ControlGroup locking.

use async_opcua_fx::{
    process_establish_connections, ConnectionEndpointConfigurationDataType,
    ConnectionEndpointDefinitionDataType, FxCommandMask, FxConnectionState,
};
use opcua_types::{NodeId, StatusCode};

fn endpoint_with_groups(ep: &str, groups: &[NodeId]) -> ConnectionEndpointConfigurationDataType {
    ConnectionEndpointConfigurationDataType {
        connection_endpoint: ConnectionEndpointDefinitionDataType::Node(NodeId::new(2, ep)),
        control_groups: Some(groups.to_vec()),
        ..Default::default()
    }
}

fn establish_control(state: &mut FxConnectionState, ep: &str, groups: &[NodeId]) -> StatusCode {
    let results = process_establish_connections(
        state,
        FxCommandMask::EstablishControlCmd,
        &[],
        &[endpoint_with_groups(ep, groups)],
        &[],
        &[],
    );
    results.connection_endpoint_results[0]
        .establish_control_result
        .as_ref()
        .and_then(|v| v.first().copied())
        .unwrap_or(StatusCode::Good)
}

#[test]
fn establish_control_acquires_then_conflicts_for_other_owner() {
    let g = NodeId::new(3, "G");

    let mut state = FxConnectionState::new();
    state.set_lock_context("appA");
    assert_eq!(
        establish_control(&mut state, "EP", std::slice::from_ref(&g)),
        StatusCode::Good
    );

    // Same owner re-establishing is idempotent.
    assert_eq!(
        establish_control(&mut state, "EP", std::slice::from_ref(&g)),
        StatusCode::Good
    );

    // A different owner is locked out.
    state.set_lock_context("appB");
    assert_eq!(
        establish_control(&mut state, "EP", &[g]),
        StatusCode::BadLocked
    );
}

#[test]
fn establish_control_conflict_aborts_and_rolls_back_earlier_locks() {
    let g1 = NodeId::new(3, "G1");
    let g2 = NodeId::new(3, "G2");

    // appA owns G2.
    let mut state = FxConnectionState::new();
    state.set_lock_context("appA");
    assert_eq!(
        establish_control(&mut state, "EP", std::slice::from_ref(&g2)),
        StatusCode::Good
    );

    // appB tries [G1, G2]: G1 acquired, G2 conflicts -> abort + G1 rolled back.
    state.set_lock_context("appB");
    let results = process_establish_connections(
        &mut state,
        FxCommandMask::EstablishControlCmd,
        &[],
        &[endpoint_with_groups("EP", &[g1.clone(), g2])],
        &[],
        &[],
    );
    let statuses = results.connection_endpoint_results[0]
        .establish_control_result
        .clone()
        .unwrap();
    assert_eq!(statuses[0], StatusCode::Good); // G1 acquired...
    assert_eq!(statuses[1], StatusCode::BadLocked); // ...G2 conflicts

    // Proof of rollback: appC can now take G1 (it was released).
    state.set_lock_context("appC");
    assert_eq!(establish_control(&mut state, "EP", &[g1]), StatusCode::Good);
}

#[test]
fn reassign_requires_an_active_lock_then_transfers_ownership() {
    let g = NodeId::new(3, "G");
    let mut state = FxConnectionState::new();

    // Reassign on an unlocked group fails.
    let results = process_establish_connections(
        &mut state,
        FxCommandMask::ReassignControlCmd,
        &[],
        &[endpoint_with_groups("EP", std::slice::from_ref(&g))],
        &[],
        &[],
    );
    assert_eq!(
        results.connection_endpoint_results[0]
            .reassign_control_result
            .as_ref()
            .unwrap()[0],
        StatusCode::BadRequiresLock
    );

    // Lock it as appA, then reassign to the endpoint NodeId; appA is no longer the owner.
    state.set_lock_context("appA");
    assert_eq!(
        establish_control(&mut state, "EP", std::slice::from_ref(&g)),
        StatusCode::Good
    );
    let reassign = process_establish_connections(
        &mut state,
        FxCommandMask::ReassignControlCmd,
        &[],
        &[endpoint_with_groups("EP", std::slice::from_ref(&g))],
        &[],
        &[],
    );
    assert_eq!(
        reassign.connection_endpoint_results[0]
            .reassign_control_result
            .as_ref()
            .unwrap()[0],
        StatusCode::Good
    );
    // Ownership transferred away from appA -> appA can no longer re-establish.
    state.set_lock_context("appA");
    assert_eq!(
        establish_control(&mut state, "EP", &[g]),
        StatusCode::BadLocked
    );
}
