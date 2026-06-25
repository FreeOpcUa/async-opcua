//! Independent tests for the FX Method adapter (piece 2c): arg decode → dispatch → result encode.

use async_opcua_fx::{
    handle_close_connections, handle_establish_connections, FxCommandMask, FxConnectionState,
    PubSubReserveCommunicationIds2DataType, PubSubReserveCommunicationIdsResult2DataType,
};
use opcua_types::{
    ExtensionObject, NodeId, StatusCode, TryFromVariant, Variant, VariantScalarTypeId,
};

fn ext_array(values: Vec<ExtensionObject>) -> Variant {
    Variant::from((VariantScalarTypeId::ExtensionObject, values))
}

#[test]
fn establish_decodes_args_runs_dispatch_and_encodes_four_results() {
    let mut state = FxConnectionState::new();

    let reserve_req = PubSubReserveCommunicationIds2DataType {
        num_req_writer_group_ids: 1,
        num_req_data_set_writer_ids: 1,
        ..Default::default()
    };
    let args = vec![
        Variant::Int32(FxCommandMask::ReserveCommunicationIdsCmd.bits()),
        Variant::Empty, // AssetVerifications
        Variant::Empty, // ConnectionEndpointConfigurations
        ext_array(vec![ExtensionObject::from_message(reserve_req)]), // ReserveCommunicationIds
        Variant::Empty, // CommunicationConfigurations
    ];

    let out = handle_establish_connections(&mut state, &args).expect("establish ok");
    assert_eq!(out.len(), 4, "four output arrays in spec order");

    // Output[2] = ReserveCommunicationIdsResults — decode and check.
    let Variant::Array(arr) = &out[2] else {
        panic!("reserve results must be an array, got {:?}", out[2]);
    };
    assert_eq!(arr.values.len(), 1);
    let Variant::ExtensionObject(obj) = &arr.values[0] else {
        panic!("reserve result element must be an ExtensionObject");
    };
    let r = obj
        .inner_as::<PubSubReserveCommunicationIdsResult2DataType>()
        .expect("concrete reserve result");
    assert_eq!(r.result, StatusCode::Good);
    assert_eq!(r.writer_group_ids.as_ref().unwrap().len(), 1);
    assert_eq!(r.data_set_writer_ids.as_ref().unwrap().len(), 1);
}

#[test]
fn establish_rejects_wrong_arg_count() {
    let mut state = FxConnectionState::new();
    let too_few = vec![Variant::Int32(0); 4];
    assert_eq!(
        handle_establish_connections(&mut state, &too_few).unwrap_err(),
        StatusCode::BadArgumentsMissing
    );
    let too_many = vec![Variant::Int32(0); 6];
    assert_eq!(
        handle_establish_connections(&mut state, &too_many).unwrap_err(),
        StatusCode::BadTooManyArguments
    );
}

#[test]
fn close_decodes_nodeid_array_and_bool() {
    let mut state = FxConnectionState::new();
    let args = vec![
        Variant::from(vec![NodeId::new(1, "missing")]),
        Variant::Boolean(true),
    ];
    let out = handle_close_connections(&mut state, &args).expect("close ok");
    assert_eq!(out.len(), 1);
    let statuses = Vec::<StatusCode>::try_from_variant(out[0].clone()).expect("statuscode array");
    assert_eq!(statuses, vec![StatusCode::BadNotFound]);
}
