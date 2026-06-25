//! Independent tests for FX piece 3: VerifyAssetCmd + VerifyFunctionalEntityCmd via an injected FxVerifier.

use std::sync::Arc;

use async_opcua_fx::{
    process_establish_connections, AssetVerificationDataType, AssetVerificationResultDataType,
    AssetVerificationResultEnum, ConnectionEndpointConfigurationDataType,
    ConnectionEndpointDefinitionDataType, FxCommandMask, FxConnectionState, FxVerifier,
    NodeIdValuePair, PubSubReserveCommunicationIds2DataType,
};
use opcua_types::{NodeId, StatusCode};

struct MockVerifier {
    asset_result: AssetVerificationResultEnum,
    fe_status: StatusCode,
}

impl FxVerifier for MockVerifier {
    fn verify_asset(&self, _req: &AssetVerificationDataType) -> AssetVerificationResultDataType {
        AssetVerificationResultDataType {
            verification_status: StatusCode::Good,
            verification_result: self.asset_result,
            ..Default::default()
        }
    }
    fn verify_functional_entity(
        &self,
        _cfg: &ConnectionEndpointConfigurationDataType,
    ) -> StatusCode {
        self.fe_status
    }
}

fn asset_req() -> AssetVerificationDataType {
    AssetVerificationDataType {
        asset_to_verify: NodeId::new(1, "Asset"),
        expected_verification_result: AssetVerificationResultEnum::Match,
        ..Default::default()
    }
}

fn state_with(asset: AssetVerificationResultEnum, fe: StatusCode) -> FxConnectionState {
    let mut state = FxConnectionState::new();
    state.set_verifier(Arc::new(MockVerifier {
        asset_result: asset,
        fe_status: fe,
    }));
    state
}

#[test]
fn verify_asset_match_passes() {
    let mut state = state_with(AssetVerificationResultEnum::Match, StatusCode::Good);
    let results = process_establish_connections(
        &mut state,
        FxCommandMask::VerifyAssetCmd,
        &[asset_req()],
        &[],
        &[],
        &[],
    );
    assert_eq!(results.asset_verification_results.len(), 1);
    assert_eq!(
        results.asset_verification_results[0].verification_result,
        AssetVerificationResultEnum::Match
    );
    assert_eq!(
        results.asset_verification_results[0].verification_status,
        StatusCode::Good
    );
}

#[test]
fn verify_asset_mismatch_aborts_later_commands() {
    // Expected Match but the verifier reports Mismatch -> abort -> reserve (bit 64) is skipped.
    let mut state = state_with(AssetVerificationResultEnum::Mismatch, StatusCode::Good);
    let results = process_establish_connections(
        &mut state,
        FxCommandMask::VerifyAssetCmd | FxCommandMask::ReserveCommunicationIdsCmd,
        &[asset_req()],
        &[],
        &[PubSubReserveCommunicationIds2DataType {
            num_req_writer_group_ids: 1,
            ..Default::default()
        }],
        &[],
    );
    assert_eq!(results.asset_verification_results.len(), 1);
    assert!(
        results.reserve_results.is_empty(),
        "reserve must be skipped after the asset verification mismatch aborts"
    );
}

#[test]
fn verify_asset_without_verifier_is_not_supported() {
    let mut state = FxConnectionState::new(); // no verifier set
    let results = process_establish_connections(
        &mut state,
        FxCommandMask::VerifyAssetCmd,
        &[asset_req()],
        &[],
        &[],
        &[],
    );
    assert_eq!(
        results.asset_verification_results[0].verification_status,
        StatusCode::BadNotSupported
    );
}

#[test]
fn verify_functional_entity_only_checks_endpoints_with_expected_variables() {
    let mut state = state_with(AssetVerificationResultEnum::Match, StatusCode::Good);

    let with_vars = ConnectionEndpointConfigurationDataType {
        connection_endpoint: ConnectionEndpointDefinitionDataType::Node(NodeId::new(2, "EP1")),
        expected_verification_variables: Some(vec![NodeIdValuePair::default()]),
        ..Default::default()
    };
    let without_vars = ConnectionEndpointConfigurationDataType {
        connection_endpoint: ConnectionEndpointDefinitionDataType::Node(NodeId::new(2, "EP2")),
        expected_verification_variables: None,
        ..Default::default()
    };

    let results = process_establish_connections(
        &mut state,
        FxCommandMask::VerifyFunctionalEntityCmd,
        &[],
        &[with_vars, without_vars],
        &[],
        &[],
    );

    // Only the endpoint with expected variables gets a Verify result.
    assert_eq!(results.connection_endpoint_results.len(), 1);
    assert_eq!(
        results.connection_endpoint_results[0].functional_entity_node_result,
        StatusCode::Good
    );
}
