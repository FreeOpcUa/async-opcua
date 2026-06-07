//! Integration tests for GDS pull certificate management callbacks.

use opcua_server::gds::pull_methods::{
    finish_signing_request_method_id, get_rejected_list_method_id, update_certificate_method_id,
    GdsPullMethodHandler, GdsPullMethodRegistry,
};
use opcua_types::{Array, ByteString, NodeId, StatusCode, Variant, VariantScalarTypeId};

#[test]
fn pull_method_ids_match_task_contract() {
    assert_eq!(get_rejected_list_method_id(), NodeId::new(0, 22407));
    assert_eq!(update_certificate_method_id(), NodeId::new(0, 22402));
    assert_eq!(finish_signing_request_method_id(), NodeId::new(0, 22402));
}

#[test]
fn get_rejected_list_returns_recorded_certificates() {
    let registry = GdsPullMethodRegistry::default();
    registry.record_rejected_certificate(ByteString::from(b"rejected-cert"));
    let handler = GdsPullMethodHandler::new(registry);

    let outputs = handler
        .handle_get_rejected_list(&[])
        .expect("GetRejectedList should succeed");

    assert_eq!(outputs.len(), 1);
    let Variant::Array(certificates) = &outputs[0] else {
        panic!("expected ByteString array output, got {:?}", outputs[0]);
    };
    assert_eq!(certificates.value_type, VariantScalarTypeId::ByteString);
    assert_eq!(
        certificates.values,
        vec![Variant::from(ByteString::from(b"rejected-cert"))]
    );
}

#[test]
fn update_certificate_records_certificate_material_and_requires_apply_changes() {
    let registry = GdsPullMethodRegistry::default();
    let handler = GdsPullMethodHandler::new(registry.clone());
    let issuer_certificates = Array::new(
        VariantScalarTypeId::ByteString,
        vec![Variant::from(ByteString::from(b"issuer-cert"))],
    )
    .expect("issuer certificate array should be valid");

    let outputs = handler
        .handle_update_certificate(&[
            Variant::from(NodeId::new(0, 5001)),
            Variant::from(NodeId::new(0, 5002)),
            Variant::from(ByteString::from(b"new-cert")),
            Variant::Array(Box::new(issuer_certificates)),
            Variant::from("PEM"),
            Variant::from(ByteString::from(b"private-key")),
        ])
        .expect("UpdateCertificate should succeed");

    assert_eq!(outputs, vec![Variant::from(true)]);
    let updates = registry.updated_certificates();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].certificate, ByteString::from(b"new-cert"));
    assert_eq!(
        updates[0].issuer_certificates,
        vec![ByteString::from(b"issuer-cert")]
    );
    assert_eq!(updates[0].private_key_format, "PEM");
}

#[test]
fn update_certificate_rejects_empty_certificate() {
    let handler = GdsPullMethodHandler::new(GdsPullMethodRegistry::default());

    let err = handler
        .handle_update_certificate(&[
            Variant::from(NodeId::new(0, 5001)),
            Variant::from(NodeId::new(0, 5002)),
            Variant::from(ByteString::null()),
            Variant::Array(Box::new(
                Array::new(VariantScalarTypeId::ByteString, Vec::<Variant>::new())
                    .expect("empty issuer array should be valid"),
            )),
            Variant::from(""),
            Variant::from(ByteString::null()),
        ])
        .expect_err("empty certificate should be rejected");

    assert_eq!(err, StatusCode::BadInvalidArgument);
}

#[test]
fn finish_signing_request_returns_completed_certificate_material() {
    let registry = GdsPullMethodRegistry::default();
    let application_id = NodeId::new(0, 7001);
    let request_id = NodeId::new(1, "signing-request-1");
    registry.record_finished_signing_request(
        application_id.clone(),
        request_id.clone(),
        ByteString::from(b"signed-cert"),
        ByteString::from(b"private-key"),
    );
    let handler = GdsPullMethodHandler::new(registry);

    let outputs = handler
        .handle_finish_signing_request(&[Variant::from(application_id), Variant::from(request_id)])
        .expect("FinishSigningRequest should return completed material");

    assert_eq!(
        outputs,
        vec![
            Variant::from(ByteString::from(b"signed-cert")),
            Variant::from(ByteString::from(b"private-key")),
        ]
    );
}
