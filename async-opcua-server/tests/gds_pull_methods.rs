//! Integration tests for GDS pull certificate management callbacks.

use std::sync::Arc;

use opcua_core::sync::RwLock;
use opcua_crypto::SecurityPolicy;
use opcua_server::{
    authenticator::UserToken,
    gds::pull_methods::{
        finish_signing_request_method_id, get_rejected_list_method_id,
        update_certificate_method_id, GdsCertificateUpdate, GdsFinishedSigningRequest,
        GdsPullMethodHandler, GdsPullMethodRegistry,
    },
    node_manager::{RequestContext, RequestContextInner},
    session::instance::Session,
    IdentityToken, ServerBuilder, WellKnownRole,
};
use opcua_types::{
    AnonymousIdentityToken, ApplicationDescription, Array, ByteString, MessageSecurityMode, NodeId,
    StatusCode, UAString, Variant, VariantScalarTypeId,
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct CertificateMaterialSnapshot {
    rejected_certificates: Vec<ByteString>,
    updated_certificates: Vec<GdsCertificateUpdate>,
    finished_signing_requests: Vec<FinishedSigningRequestSnapshot>,
}

#[derive(Clone, PartialEq, Eq)]
struct FinishedSigningRequestSnapshot {
    application_id: NodeId,
    request_id: NodeId,
    certificate: ByteString,
    private_key: ByteString,
}

impl std::fmt::Debug for FinishedSigningRequestSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FinishedSigningRequestSnapshot")
            .field("application_id", &self.application_id)
            .field("request_id", &self.request_id)
            .field("certificate_len", &self.certificate.len())
            .field("private_key", &"<redacted>")
            .finish()
    }
}

#[test]
fn gds_certificate_material_debug_redacts_private_keys() {
    let private_key = ByteString::from(b"secret-private-key-material".to_vec());
    let update = GdsCertificateUpdate {
        certificate_group_id: NodeId::new(0, 1),
        certificate_type_id: NodeId::new(0, 2),
        certificate: ByteString::from(b"certificate-material".to_vec()),
        issuer_certificates: vec![ByteString::from(b"issuer-certificate".to_vec())],
        private_key_format: "PEM".to_string(),
        private_key: private_key.clone(),
    };
    let finished = GdsFinishedSigningRequest {
        application_id: NodeId::new(0, 3),
        request_id: NodeId::new(0, 4),
        certificate: ByteString::from(b"signed-certificate-material".to_vec()),
        private_key: private_key.clone(),
    };
    let snapshot = FinishedSigningRequestSnapshot {
        application_id: NodeId::new(0, 5),
        request_id: NodeId::new(0, 6),
        certificate: ByteString::from(b"snapshot-certificate-material".to_vec()),
        private_key,
    };

    for debug_output in [
        format!("{update:?}"),
        format!("{finished:?}"),
        format!("{snapshot:?}"),
    ] {
        assert!(
            !debug_output.contains("secret-private-key-material"),
            "debug output leaked private-key material: {debug_output}"
        );
        assert!(
            debug_output.contains("redacted"),
            "debug output should state that private-key material is redacted: {debug_output}"
        );
    }
}

impl CertificateMaterialSnapshot {
    fn capture(registry: &GdsPullMethodRegistry) -> Self {
        Self::capture_with_finished_requests(registry, &[])
    }

    fn capture_with_finished_requests(
        registry: &GdsPullMethodRegistry,
        finished_request_ids: &[(NodeId, NodeId)],
    ) -> Self {
        let handler = GdsPullMethodHandler::new(registry.clone());
        let finished_signing_requests = if finished_request_ids.is_empty() {
            Vec::new()
        } else {
            let context = security_admin_request_context(MessageSecurityMode::SignAndEncrypt);
            finished_request_ids
                .iter()
                .filter_map(|(application_id, request_id)| {
                    let outputs = handler
                        .handle_finish_signing_request_for_request(
                            &context,
                            &[
                                Variant::from(application_id.clone()),
                                Variant::from(request_id.clone()),
                            ],
                        )
                        .ok()?;

                    let [Variant::ByteString(certificate), Variant::ByteString(private_key)] =
                        outputs.as_slice()
                    else {
                        panic!("expected signed certificate and private key, got {outputs:?}");
                    };

                    Some(FinishedSigningRequestSnapshot {
                        application_id: application_id.clone(),
                        request_id: request_id.clone(),
                        certificate: certificate.clone(),
                        private_key: private_key.clone(),
                    })
                })
                .collect()
        };

        Self {
            rejected_certificates: registry.rejected_certificates(),
            updated_certificates: registry.updated_certificates(),
            finished_signing_requests,
        }
    }
}

fn assert_certificate_material_unchanged(
    before: &CertificateMaterialSnapshot,
    after: &CertificateMaterialSnapshot,
) {
    assert_eq!(
        after.rejected_certificates, before.rejected_certificates,
        "rejected certificate material changed unexpectedly"
    );
    assert_eq!(
        after.updated_certificates, before.updated_certificates,
        "updated certificate records changed unexpectedly"
    );
    assert_eq!(
        after.finished_signing_requests, before.finished_signing_requests,
        "finished signing request material changed unexpectedly"
    );
}

fn valid_update_certificate_material() -> (ByteString, ByteString) {
    let mut alt_host_names = opcua_crypto::AlternateNames::new();
    alt_host_names.add_dns("localhost");
    let certificate_data = opcua_crypto::X509Data {
        key_size: 2048,
        common_name: "gds-update-certificate-test".to_string(),
        organization: "async-opcua".to_string(),
        organizational_unit: "server-tests".to_string(),
        country: "US".to_string(),
        state: "test".to_string(),
        alt_host_names,
        certificate_duration_days: 365,
    };
    let (certificate, private_key) = opcua_crypto::X509::cert_and_pkey(&certificate_data)
        .expect("valid test certificate should generate");

    let certificate = ByteString::from(
        certificate
            .to_der()
            .expect("valid test certificate should encode as DER"),
    );
    let private_key = ByteString::from(
        private_key
            .to_pem()
            .expect("valid test private key should encode as PEM")
            .into_bytes(),
    );

    (certificate, private_key)
}

fn valid_update_certificate_der() -> ByteString {
    valid_update_certificate_material().0
}

fn request_context(security_mode: MessageSecurityMode, user_roles: Vec<NodeId>) -> RequestContext {
    let (_server, handle) = ServerBuilder::new_anonymous("gds pull method test")
        .without_node_managers()
        .build()
        .expect("test server should build");
    let info = Arc::clone(handle.info());
    let user_roles = Arc::new(user_roles);
    let session = Arc::new(RwLock::new(Session::create(
        &info,
        NodeId::new(0, 1),
        1,
        60_000,
        0,
        0,
        UAString::from("opc.tcp://localhost"),
        SecurityPolicy::Basic256Sha256.to_uri().to_string(),
        IdentityToken::Anonymous(AnonymousIdentityToken {
            policy_id: UAString::from("anonymous"),
        }),
        None,
        ByteString::null(),
        UAString::from("gds-pull-method-test"),
        ApplicationDescription::default(),
        security_mode,
    )));

    RequestContext::new_test(Arc::new(RequestContextInner {
        session,
        session_id: 1,
        authenticator: info.authenticator.clone(),
        token: UserToken("gds-pull-method-test".to_string()),
        user_roles,
        type_tree: info.type_tree.clone(),
        type_tree_getter: info.type_tree_getter.clone(),
        subscriptions: handle.subscriptions().clone(),
        info,
    }))
}

fn security_admin_request_context(security_mode: MessageSecurityMode) -> RequestContext {
    request_context(security_mode, vec![WellKnownRole::SecurityAdmin.node_id()])
}

#[test]
fn pull_method_ids_match_task_contract() {
    assert_eq!(get_rejected_list_method_id(), NodeId::new(0, 22407));
    assert_eq!(update_certificate_method_id(), NodeId::new(0, 22402));
    assert_eq!(finish_signing_request_method_id(), NodeId::new(0, 22402));
}

#[tokio::test]
async fn get_rejected_list_returns_recorded_certificates() {
    let registry = GdsPullMethodRegistry::default();
    registry.record_rejected_certificate(ByteString::from(b"rejected-cert"));
    let handler = GdsPullMethodHandler::new(registry.clone());
    let snapshot = CertificateMaterialSnapshot::capture(&registry);
    let context = security_admin_request_context(MessageSecurityMode::Sign);

    let outputs = handler
        .handle_get_rejected_list_for_request(&context, &[])
        .expect("GetRejectedList should succeed for SecurityAdmin over a signed SecureChannel");

    assert_eq!(outputs.len(), 1);
    let Variant::Array(certificates) = &outputs[0] else {
        panic!("expected ByteString array output, got {:?}", outputs[0]);
    };
    assert_eq!(certificates.value_type, VariantScalarTypeId::ByteString);
    assert_eq!(
        certificates.values,
        vec![Variant::from(ByteString::from(b"rejected-cert"))]
    );
    assert_eq!(
        snapshot.rejected_certificates,
        vec![ByteString::from(b"rejected-cert")]
    );
}

#[test]
fn get_rejected_list_requires_authenticated_secure_channel_and_security_admin_before_registry_read()
{
    let registry = GdsPullMethodRegistry::default();
    registry.record_rejected_certificate(ByteString::from(b"rejected-cert-should-not-leak"));
    let handler = GdsPullMethodHandler::new(registry.clone());
    let before_failure = CertificateMaterialSnapshot::capture(&registry);

    let result = handler.handle_get_rejected_list(&[]);

    assert_eq!(
        result,
        Err(StatusCode::BadSecurityModeInsufficient),
        "GetRejectedList must reject callers without an authenticated SecureChannel and \
         SecurityAdmin authorization before exposing rejected certificates"
    );
    let after_failure = CertificateMaterialSnapshot::capture(&registry);
    assert_certificate_material_unchanged(&before_failure, &after_failure);
}

#[tokio::test]
async fn update_certificate_records_certificate_material_and_requires_apply_changes() {
    let registry = GdsPullMethodRegistry::default();
    let handler = GdsPullMethodHandler::new(registry.clone());
    let context = security_admin_request_context(MessageSecurityMode::SignAndEncrypt);
    let (certificate, private_key) = valid_update_certificate_material();
    let issuer_certificates = Array::new(
        VariantScalarTypeId::ByteString,
        vec![Variant::from(ByteString::from(b"issuer-cert"))],
    )
    .expect("issuer certificate array should be valid");

    let outputs = handler
        .handle_update_certificate_for_request(
            &context,
            &[
                Variant::from(NodeId::new(0, 5001)),
                Variant::from(NodeId::new(0, 5002)),
                Variant::from(certificate.clone()),
                Variant::Array(Box::new(issuer_certificates)),
                Variant::from("PEM"),
                Variant::from(private_key.clone()),
            ],
        )
        .expect("UpdateCertificate should succeed");

    assert_eq!(outputs, vec![Variant::from(true)]);
    let snapshot = CertificateMaterialSnapshot::capture(&registry);
    let updates = snapshot.updated_certificates;
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].certificate, certificate);
    assert_eq!(
        updates[0].issuer_certificates,
        vec![ByteString::from(b"issuer-cert")]
    );
    assert_eq!(updates[0].private_key_format, "PEM");
    assert_eq!(updates[0].private_key, private_key);
}

#[tokio::test]
async fn update_certificate_requires_encrypted_secure_channel_and_security_admin_before_recording_material(
) {
    let registry = GdsPullMethodRegistry::default();
    registry.record_rejected_certificate(ByteString::from(b"rejected-cert-before-failure"));
    let handler = GdsPullMethodHandler::new(registry.clone());
    let before_failure = CertificateMaterialSnapshot::capture(&registry);
    let update_args = || {
        let issuer_certificates = Array::new(
            VariantScalarTypeId::ByteString,
            vec![Variant::from(ByteString::from(b"unauthorized-issuer-cert"))],
        )
        .expect("issuer certificate array should be valid");

        vec![
            Variant::from(NodeId::new(0, 5001)),
            Variant::from(NodeId::new(0, 5002)),
            Variant::from(ByteString::from(b"unauthorized-new-cert")),
            Variant::Array(Box::new(issuer_certificates)),
            Variant::from("PEM"),
            Variant::from(ByteString::from(b"unauthorized-private-key")),
        ]
    };

    let result = handler.handle_update_certificate(&update_args());

    assert_eq!(
        result,
        Err(StatusCode::BadSecurityModeInsufficient),
        "UpdateCertificate must reject callers without an encrypted SecureChannel and \
         SecurityAdmin authorization before recording certificate material"
    );
    let after_failure = CertificateMaterialSnapshot::capture(&registry);
    assert_certificate_material_unchanged(&before_failure, &after_failure);

    let signed_context = security_admin_request_context(MessageSecurityMode::Sign);
    let result = handler.handle_update_certificate_for_request(&signed_context, &update_args());

    assert_eq!(
        result,
        Err(StatusCode::BadSecurityModeInsufficient),
        "UpdateCertificate must reject SecurityAdmin callers without an encrypted SecureChannel \
         before recording certificate material"
    );
    let after_failure = CertificateMaterialSnapshot::capture(&registry);
    assert_certificate_material_unchanged(&before_failure, &after_failure);

    let non_admin_context = request_context(
        MessageSecurityMode::SignAndEncrypt,
        vec![WellKnownRole::AuthenticatedUser.node_id()],
    );
    let result = handler.handle_update_certificate_for_request(&non_admin_context, &update_args());

    assert_eq!(
        result,
        Err(StatusCode::BadUserAccessDenied),
        "UpdateCertificate must reject callers without SecurityAdmin authorization before \
         recording certificate material"
    );
    let after_failure = CertificateMaterialSnapshot::capture(&registry);
    assert_certificate_material_unchanged(&before_failure, &after_failure);
}

#[tokio::test]
async fn update_certificate_rejects_empty_certificate() {
    let registry = GdsPullMethodRegistry::default();
    registry.record_rejected_certificate(ByteString::from(b"rejected-cert-before-failure"));
    let application_id = NodeId::new(0, 7101);
    let request_id = NodeId::new(1, "known-signing-request-before-failure");
    registry.record_finished_signing_request(
        application_id.clone(),
        request_id.clone(),
        ByteString::from(b"signed-cert-before-failure"),
        ByteString::from(b"private-key-before-failure"),
    );
    let handler = GdsPullMethodHandler::new(registry.clone());
    let context = security_admin_request_context(MessageSecurityMode::SignAndEncrypt);
    let certificate = valid_update_certificate_der();
    let issuer_certificates = Array::new(
        VariantScalarTypeId::ByteString,
        vec![Variant::from(ByteString::from(
            b"issuer-cert-before-failure",
        ))],
    )
    .expect("issuer certificate array should be valid");
    handler
        .handle_update_certificate_for_request(
            &context,
            &[
                Variant::from(NodeId::new(0, 5001)),
                Variant::from(NodeId::new(0, 5002)),
                Variant::from(certificate),
                Variant::Array(Box::new(issuer_certificates)),
                Variant::from(""),
                Variant::from(ByteString::null()),
            ],
        )
        .expect("baseline UpdateCertificate should allow no supplied private key");
    let known_finished_requests = [(application_id, request_id)];
    let before_failure = CertificateMaterialSnapshot::capture_with_finished_requests(
        &registry,
        &known_finished_requests,
    );

    let err = handler
        .handle_update_certificate_for_request(
            &context,
            &[
                Variant::from(NodeId::new(0, 5001)),
                Variant::from(NodeId::new(0, 5002)),
                Variant::from(ByteString::null()),
                Variant::Array(Box::new(
                    Array::new(VariantScalarTypeId::ByteString, Vec::<Variant>::new())
                        .expect("empty issuer array should be valid"),
                )),
                Variant::from(""),
                Variant::from(ByteString::null()),
            ],
        )
        .expect_err("empty certificate should be rejected");

    assert_eq!(err, StatusCode::BadInvalidArgument);
    let after_failure = CertificateMaterialSnapshot::capture_with_finished_requests(
        &registry,
        &known_finished_requests,
    );
    assert_certificate_material_unchanged(&before_failure, &after_failure);
}

#[tokio::test]
async fn update_certificate_rejects_malformed_der_certificate_without_mutating_registry() {
    let registry = GdsPullMethodRegistry::default();
    registry.record_rejected_certificate(ByteString::from(b"rejected-cert-before-failure"));
    let handler = GdsPullMethodHandler::new(registry.clone());
    let context = security_admin_request_context(MessageSecurityMode::SignAndEncrypt);
    let before_failure = CertificateMaterialSnapshot::capture(&registry);

    let result = handler.handle_update_certificate_for_request(
        &context,
        &[
            Variant::from(NodeId::new(0, 5001)),
            Variant::from(NodeId::new(0, 5002)),
            Variant::from(ByteString::from(vec![0x30, 0x03, 0x02, 0x01])),
            Variant::Array(Box::new(
                Array::new(VariantScalarTypeId::ByteString, Vec::<Variant>::new())
                    .expect("empty issuer array should be valid"),
            )),
            Variant::from(""),
            Variant::from(ByteString::null()),
        ],
    );

    let after_failure = CertificateMaterialSnapshot::capture(&registry);
    assert_certificate_material_unchanged(&before_failure, &after_failure);
    assert_eq!(
        result,
        Err(StatusCode::BadCertificateInvalid),
        "UpdateCertificate must reject malformed DER certificate bytes before recording \
         certificate material"
    );
}

#[tokio::test]
async fn update_certificate_rejects_malformed_private_key_without_mutating_registry() {
    let registry = GdsPullMethodRegistry::default();
    registry.record_rejected_certificate(ByteString::from(b"rejected-cert-before-failure"));
    let handler = GdsPullMethodHandler::new(registry.clone());
    let context = security_admin_request_context(MessageSecurityMode::SignAndEncrypt);
    let before_failure = CertificateMaterialSnapshot::capture(&registry);

    let result = handler.handle_update_certificate_for_request(
        &context,
        &[
            Variant::from(NodeId::new(0, 5001)),
            Variant::from(NodeId::new(0, 5002)),
            Variant::from(valid_update_certificate_der()),
            Variant::Array(Box::new(
                Array::new(VariantScalarTypeId::ByteString, Vec::<Variant>::new())
                    .expect("empty issuer array should be valid"),
            )),
            Variant::from("PEM"),
            Variant::from(ByteString::from(b"not-a-pkcs8-pem-private-key")),
        ],
    );

    let after_failure = CertificateMaterialSnapshot::capture(&registry);
    assert_certificate_material_unchanged(&before_failure, &after_failure);
    assert_eq!(
        result,
        Err(StatusCode::BadNotSupported),
        "UpdateCertificate must reject malformed private-key bytes before recording \
         certificate material"
    );
}

#[tokio::test]
async fn finish_signing_request_returns_completed_certificate_material() {
    let registry = GdsPullMethodRegistry::default();
    let application_id = NodeId::new(0, 7001);
    let request_id = NodeId::new(1, "signing-request-1");
    registry.record_finished_signing_request(
        application_id.clone(),
        request_id.clone(),
        ByteString::from(b"signed-cert"),
        ByteString::from(b"private-key"),
    );
    let handler = GdsPullMethodHandler::new(registry.clone());
    let context = security_admin_request_context(MessageSecurityMode::SignAndEncrypt);

    let outputs = handler
        .handle_finish_signing_request_for_request(
            &context,
            &[
                Variant::from(application_id.clone()),
                Variant::from(request_id.clone()),
            ],
        )
        .expect("FinishSigningRequest should return completed material");

    let snapshot = CertificateMaterialSnapshot::capture_with_finished_requests(
        &registry,
        &[(application_id.clone(), request_id.clone())],
    );

    assert_eq!(
        outputs,
        vec![
            Variant::from(ByteString::from(b"signed-cert")),
            Variant::from(ByteString::from(b"private-key")),
        ]
    );
    assert_eq!(
        snapshot.finished_signing_requests,
        vec![FinishedSigningRequestSnapshot {
            application_id,
            request_id,
            certificate: ByteString::from(b"signed-cert"),
            private_key: ByteString::from(b"private-key"),
        }]
    );
}

#[tokio::test]
async fn finish_signing_request_helper_requires_encrypted_channel_and_security_admin_before_returning_material(
) {
    let registry = GdsPullMethodRegistry::default();
    registry.record_rejected_certificate(ByteString::from(b"rejected-cert-before-failure"));
    let application_id = NodeId::new(0, 7201);
    let request_id = NodeId::new(1, "unauthorized-signing-request");
    registry.record_finished_signing_request(
        application_id.clone(),
        request_id.clone(),
        ByteString::from(b"unauthorized-signed-cert-should-not-leak"),
        ByteString::from(b"unauthorized-private-key-should-not-leak"),
    );
    let handler = GdsPullMethodHandler::new(registry.clone());
    let known_finished_requests = [(application_id.clone(), request_id.clone())];
    let before_failure = CertificateMaterialSnapshot::capture_with_finished_requests(
        &registry,
        &known_finished_requests,
    );

    let result = handler.handle_finish_signing_request(&[
        Variant::from(application_id.clone()),
        Variant::from(request_id.clone()),
    ]);

    match result {
        Err(status) => assert_eq!(
            status,
            StatusCode::BadSecurityModeInsufficient,
            "FinishSigningRequest helper must reject callers without an encrypted SecureChannel \
             and SecurityAdmin authorization before returning certificate material"
        ),
        Ok(outputs) => panic!(
            "FinishSigningRequest helper leaked {} certificate-material outputs without an \
             encrypted SecureChannel and SecurityAdmin authorization",
            outputs.len()
        ),
    }
    let after_failure = CertificateMaterialSnapshot::capture_with_finished_requests(
        &registry,
        &known_finished_requests,
    );
    assert_certificate_material_unchanged(&before_failure, &after_failure);

    let signed_context = security_admin_request_context(MessageSecurityMode::Sign);
    let result = handler.handle_finish_signing_request_for_request(
        &signed_context,
        &[
            Variant::from(application_id.clone()),
            Variant::from(request_id.clone()),
        ],
    );

    match result {
        Err(status) => assert_eq!(
            status,
            StatusCode::BadSecurityModeInsufficient,
            "FinishSigningRequest helper must reject SecurityAdmin callers without an encrypted \
             SecureChannel before returning certificate material"
        ),
        Ok(outputs) => panic!(
            "FinishSigningRequest helper leaked {} certificate-material outputs without an \
             encrypted SecureChannel",
            outputs.len()
        ),
    }
    let after_failure = CertificateMaterialSnapshot::capture_with_finished_requests(
        &registry,
        &known_finished_requests,
    );
    assert_certificate_material_unchanged(&before_failure, &after_failure);

    let non_admin_context = request_context(
        MessageSecurityMode::SignAndEncrypt,
        vec![WellKnownRole::AuthenticatedUser.node_id()],
    );
    let result = handler.handle_finish_signing_request_for_request(
        &non_admin_context,
        &[Variant::from(application_id), Variant::from(request_id)],
    );

    match result {
        Err(status) => assert_eq!(
            status,
            StatusCode::BadUserAccessDenied,
            "FinishSigningRequest helper must reject callers without SecurityAdmin authorization \
             before returning certificate material"
        ),
        Ok(outputs) => panic!(
            "FinishSigningRequest helper leaked {} certificate-material outputs without \
             SecurityAdmin authorization",
            outputs.len()
        ),
    }
    let after_failure = CertificateMaterialSnapshot::capture_with_finished_requests(
        &registry,
        &known_finished_requests,
    );
    assert_certificate_material_unchanged(&before_failure, &after_failure);
}
