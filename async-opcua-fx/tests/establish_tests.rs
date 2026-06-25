//! Independent tests for the pure FX EstablishConnections/CloseConnections dispatch (piece 2a).

use async_opcua_fx::{
    process_close_connections, process_establish_connections, AssetVerificationDataType,
    FxCommandMask, FxConnectionState, PubSubCommunicationConfigurationDataType,
    PubSubReserveCommunicationIds2DataType,
};
use opcua_pubsub::{MessageEncoding, PubSubConnectionConfig, WriterGroupConfig};
use opcua_types::{
    NodeId, PubSubConfiguration2DataType, PubSubConnectionDataType, StatusCode, WriterGroupDataType,
};

fn reserve_request(num_wg: u16, num_dsw: u16) -> PubSubReserveCommunicationIds2DataType {
    PubSubReserveCommunicationIds2DataType {
        num_req_writer_group_ids: num_wg,
        num_req_data_set_writer_ids: num_dsw,
        ..Default::default()
    }
}

#[test]
fn reserve_communication_ids_returns_unused_ids() {
    let mut state = FxConnectionState::new();
    // Seed an existing config occupying writer-group 1.
    state.connections.push(PubSubConnectionConfig {
        connection_id: "existing".into(),
        name: "existing".into(),
        address: "udp://239.0.0.1:4840".into(),
        reader_groups: Vec::new(),
        writer_groups: vec![WriterGroupConfig {
            writer_group_id: 1,
            publishing_interval: 100,
            encoding: MessageEncoding::Uadp,
            dataset_writers: vec![],
        }],
    });

    let results = process_establish_connections(
        &mut state,
        FxCommandMask::ReserveCommunicationIdsCmd,
        &[],
        &[],
        &[reserve_request(2, 3)],
        &[],
    );

    assert_eq!(results.reserve_results.len(), 1);
    let r = &results.reserve_results[0];
    assert_eq!(r.result, StatusCode::Good);
    let wg = r.writer_group_ids.as_ref().unwrap();
    let dsw = r.data_set_writer_ids.as_ref().unwrap();
    assert_eq!(wg.len(), 2);
    assert_eq!(dsw.len(), 3);
    assert!(
        !wg.contains(&1),
        "reserved ids must avoid the in-use writer-group 1"
    );
}

#[test]
fn atomic_abort_skips_later_commands_on_first_error() {
    let mut state = FxConnectionState::new();
    // VerifyAssetCmd (bit 1) is not yet supported -> errors; it runs BEFORE
    // ReserveCommunicationIdsCmd (bit 64), so reserve must be skipped entirely.
    let mask = FxCommandMask::VerifyAssetCmd | FxCommandMask::ReserveCommunicationIdsCmd;
    let results = process_establish_connections(
        &mut state,
        mask,
        &[AssetVerificationDataType::default()],
        &[],
        &[reserve_request(1, 1)],
        &[],
    );

    assert_eq!(
        results.asset_verification_results[0].verification_status,
        StatusCode::BadNotSupported,
        "the verify command should have produced the aborting (BadNotSupported) result"
    );
    assert!(
        results.reserve_results.is_empty(),
        "reserve must be skipped after the earlier command aborted"
    );
}

#[test]
fn verify_asset_command_is_not_yet_supported() {
    let mut state = FxConnectionState::new();
    let results = process_establish_connections(
        &mut state,
        FxCommandMask::VerifyAssetCmd,
        &[AssetVerificationDataType::default()],
        &[],
        &[],
        &[],
    );
    assert_eq!(results.asset_verification_results.len(), 1);
    assert_eq!(
        results.asset_verification_results[0].verification_status,
        StatusCode::BadNotSupported
    );
}

#[test]
fn set_communication_configuration_applies_connections() {
    let mut state = FxConnectionState::new();
    let cfg = PubSubConfiguration2DataType {
        connections: Some(vec![PubSubConnectionDataType {
            name: "c1".into(),
            transport_profile_uri: "udp://239.0.0.1:4840".into(),
            writer_groups: Some(vec![WriterGroupDataType {
                writer_group_id: 7,
                ..Default::default()
            }]),
            ..Default::default()
        }]),
        ..Default::default()
    };
    let comm = PubSubCommunicationConfigurationDataType {
        pub_sub_configuration: cfg,
        require_complete_update: false,
        configuration_references: None,
    };

    let results = process_establish_connections(
        &mut state,
        FxCommandMask::SetCommunicationConfigurationCmd,
        &[],
        &[],
        &[],
        &[comm],
    );

    assert_eq!(results.communication_results.len(), 1);
    assert_eq!(results.communication_results[0].result, StatusCode::Good);
    assert_eq!(state.connections.len(), 1);
    assert_eq!(state.connections[0].connection_id, "c1");
    assert_eq!(state.connections[0].writer_groups[0].writer_group_id, 7);
}

#[test]
fn close_unknown_endpoint_is_not_found() {
    let mut state = FxConnectionState::new();
    let statuses = process_close_connections(&mut state, &[NodeId::new(1, "missing")], true);
    assert_eq!(statuses, vec![StatusCode::BadNotFound]);
}
