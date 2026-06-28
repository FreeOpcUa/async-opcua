use crate::types::url::*;

use opcua_types::StatusCode;

#[test]
fn endpoint_match() {
    assert!(url_matches_except_host(
        "opc.tcp://foo:4855/",
        "opc.tcp://bar:4855"
    ));
    assert!(url_matches_except_host(
        "opc.tcp://127.0.0.1:4855/",
        "opc.tcp://bar:4855"
    ));
    assert!(url_matches_except_host(
        "opc.tcp://foo:4855/",
        "opc.tcp://127.0.0.1:4855"
    ));
    assert!(url_matches_except_host(
        "opc.tcp://foo:4855/UAServer",
        "opc.tcp://127.0.0.1:4855/UAServer"
    ));
    assert!(!url_matches_except_host(
        "opc.tcp://foo:4855/UAServer",
        "opc.tcp://127.0.0.1:8888/UAServer"
    ));
}

#[test]
fn invalid_opc_tcp_endpoint_url_returns_bad_tcp_endpoint_url_invalid() {
    // OPC-10000-4 7.38.2: endpoint URL validation failures use BadTcpEndpointUrlInvalid.
    let err = hostname_port_from_url("opc.tcp://", 4840).unwrap_err();

    assert_eq!(err, StatusCode::BadTcpEndpointUrlInvalid);
}
