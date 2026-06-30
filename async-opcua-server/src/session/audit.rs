use std::sync::Arc;

use opcua_core::ResponseMessage;
use opcua_nodes::{BaseEventType, Event, EventField};
use opcua_types::{
    ActivateSessionRequest, AttributeId, ByteString, CreateSessionRequest, DateTime,
    ExtensionObject, NodeId, NumericRange, ObjectId, ObjectTypeId, QualifiedName, RequestHeader,
    StatusCode, UAString, Variant,
};
use uuid::Uuid;

use crate::{
    identity_token::IdentityToken, info::ServerInfo, subscriptions::SubscriptionCache,
    ANONYMOUS_USER_TOKEN_ID,
};

const AUDIT_FAILURE_SEVERITY: u16 = 900;
const AUDIT_SUCCESS_SEVERITY: u16 = 100;
const AUDIT_SOURCE_NAME: &str = "Server";
const AUDIT_CERTIFICATE_SOURCE_NAME: &str = "Security/Certificate";

#[derive(Clone)]
pub(crate) struct AuditEventContext {
    request_type: &'static str,
    client_audit_entry_id: UAString,
    client_user_id: UAString,
    session_id: Option<NodeId>,
}

impl AuditEventContext {
    pub(crate) fn new(
        request_type: &'static str,
        request_header: &RequestHeader,
        client_user_id: Option<UAString>,
        session_id: Option<NodeId>,
    ) -> Self {
        Self {
            request_type,
            client_audit_entry_id: request_header.audit_entry_id.clone(),
            client_user_id: client_user_id.unwrap_or_else(UAString::null),
            session_id,
        }
    }
}

#[derive(Clone)]
struct ServerAuditEvent {
    base: BaseEventType,
    action_time_stamp: DateTime,
    status: bool,
    server_id: UAString,
    client_audit_entry_id: UAString,
    client_user_id: UAString,
    status_code_id: StatusCode,
    session_id: Option<NodeId>,
    secure_channel_id: Option<UAString>,
    user_identity_token: Option<ExtensionObject>,
    method_id: Option<NodeId>,
    attribute_id: Option<u32>,
    client_certificate: Option<ByteString>,
    client_certificate_thumbprint: Option<ByteString>,
    revised_session_timeout: Option<f64>,
    request_handle: Option<u32>,
    request_type: Option<i32>,
    security_policy_uri: Option<UAString>,
    security_mode: Option<i32>,
    requested_lifetime: Option<u32>,
}

impl ServerAuditEvent {
    /// Builds an audit event whose `Status`/severity reflect `status_code_id`.
    fn outcome(
        event_type: ObjectTypeId,
        server_id: UAString,
        action: &str,
        client_audit_entry_id: UAString,
        client_user_id: UAString,
        status_code_id: StatusCode,
        session_id: Option<NodeId>,
    ) -> Self {
        let now = DateTime::now();
        let status = status_code_id.is_good();
        let severity = if status {
            AUDIT_SUCCESS_SEVERITY
        } else {
            AUDIT_FAILURE_SEVERITY
        };
        let message = if status {
            format!("{action} succeeded")
        } else {
            format!("{action} failed: {status_code_id}")
        };
        let base = BaseEventType::new(
            event_type,
            ByteString::from(Uuid::new_v4().as_bytes().as_slice()),
            message,
            now,
        )
        .set_source_node(ObjectId::Server.into())
        .set_source_name(UAString::from(AUDIT_SOURCE_NAME))
        .set_severity(severity);

        Self {
            base,
            action_time_stamp: now,
            status,
            server_id,
            client_audit_entry_id,
            client_user_id,
            status_code_id,
            session_id,
            secure_channel_id: None,
            user_identity_token: None,
            method_id: None,
            attribute_id: None,
            client_certificate: None,
            client_certificate_thumbprint: None,
            revised_session_timeout: None,
            request_handle: None,
            request_type: None,
            security_policy_uri: None,
            security_mode: None,
            requested_lifetime: None,
        }
    }

    fn failure(
        event_type: ObjectTypeId,
        server_id: UAString,
        action: &str,
        client_audit_entry_id: UAString,
        client_user_id: UAString,
        status_code_id: StatusCode,
        session_id: Option<NodeId>,
    ) -> Self {
        // Callers only use this for Bad status codes, so the outcome is always a failure.
        Self::outcome(
            event_type,
            server_id,
            action,
            client_audit_entry_id,
            client_user_id,
            status_code_id,
            session_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn method_call(
        server_id: UAString,
        _request_type: &str,
        client_audit_entry_id: UAString,
        client_user_id: UAString,
        status_code_id: StatusCode,
        session_id: Option<NodeId>,
        method_id: NodeId,
    ) -> Self {
        let now = DateTime::now();
        let status = status_code_id.is_good();
        let severity = if status {
            AUDIT_SUCCESS_SEVERITY
        } else {
            AUDIT_FAILURE_SEVERITY
        };
        let message = format!("Method call {method_id}");
        let base = BaseEventType::new(
            ObjectTypeId::AuditUpdateMethodEventType,
            ByteString::from(Uuid::new_v4().as_bytes().as_slice()),
            message,
            now,
        )
        .set_source_node(ObjectId::Server.into())
        .set_source_name(UAString::from(AUDIT_SOURCE_NAME))
        .set_severity(severity);

        Self {
            base,
            action_time_stamp: now,
            status,
            server_id,
            client_audit_entry_id,
            client_user_id,
            status_code_id,
            session_id,
            secure_channel_id: None,
            user_identity_token: None,
            method_id: Some(method_id),
            attribute_id: None,
            client_certificate: None,
            client_certificate_thumbprint: None,
            revised_session_timeout: None,
            request_handle: None,
            request_type: None,
            security_policy_uri: None,
            security_mode: None,
            requested_lifetime: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write_update(
        server_id: UAString,
        _request_type: &str,
        client_audit_entry_id: UAString,
        client_user_id: UAString,
        status_code_id: StatusCode,
        session_id: Option<NodeId>,
        node_id: &NodeId,
        attribute_id: u32,
    ) -> Self {
        let now = DateTime::now();
        let status = status_code_id.is_good();
        let severity = if status {
            AUDIT_SUCCESS_SEVERITY
        } else {
            AUDIT_FAILURE_SEVERITY
        };
        let message = format!("Write to {node_id} attribute {attribute_id}");
        let base = BaseEventType::new(
            ObjectTypeId::AuditWriteUpdateEventType,
            ByteString::from(Uuid::new_v4().as_bytes().as_slice()),
            message,
            now,
        )
        .set_source_node(ObjectId::Server.into())
        .set_source_name(UAString::from(AUDIT_SOURCE_NAME))
        .set_severity(severity);

        Self {
            base,
            action_time_stamp: now,
            status,
            server_id,
            client_audit_entry_id,
            client_user_id,
            status_code_id,
            session_id,
            secure_channel_id: None,
            user_identity_token: None,
            method_id: None,
            attribute_id: Some(attribute_id),
            client_certificate: None,
            client_certificate_thumbprint: None,
            revised_session_timeout: None,
            request_handle: None,
            request_type: None,
            security_policy_uri: None,
            security_mode: None,
            requested_lifetime: None,
        }
    }

    fn with_secure_channel_id(mut self, secure_channel_id: u32) -> Self {
        self.secure_channel_id = Some(UAString::from(secure_channel_id.to_string()));
        self
    }

    fn with_user_identity_token(mut self, user_identity_token: ExtensionObject) -> Self {
        self.user_identity_token = Some(user_identity_token);
        self
    }

    /// Records the client certificate and its SHA-1 thumbprint (AuditCreateSessionEventType).
    fn with_client_certificate(mut self, client_certificate: ByteString) -> Self {
        if !client_certificate.is_null() {
            if let Ok(cert) = opcua_crypto::X509::from_byte_string(&client_certificate) {
                self.client_certificate_thumbprint = Some(ByteString::from(cert.thumbprint()));
            }
        }
        self.client_certificate = Some(client_certificate);
        self
    }

    fn with_revised_session_timeout(mut self, revised_session_timeout: f64) -> Self {
        self.revised_session_timeout = Some(revised_session_timeout);
        self
    }

    /// Records the subject certificate for an AuditCertificateEventType (exposed as `Certificate`).
    fn with_certificate(mut self, certificate: ByteString) -> Self {
        self.client_certificate = Some(certificate);
        self
    }

    /// AuditCertificateEventType subtypes require this source name (OPC UA Part 5 §§6.4.12-6.4.18).
    fn with_certificate_source_name(mut self) -> Self {
        self.base = self
            .base
            .set_source_name(UAString::from(AUDIT_CERTIFICATE_SOURCE_NAME));
        self
    }

    /// Records the cancelled request handle for an AuditCancelEventType.
    fn with_request_handle(mut self, request_handle: u32) -> Self {
        self.request_handle = Some(request_handle);
        self
    }

    /// Records the secure-channel parameters for an AuditOpenSecureChannelEventType.
    fn with_secure_channel_params(
        mut self,
        request_type: i32,
        security_policy_uri: &str,
        security_mode: i32,
        requested_lifetime: u32,
    ) -> Self {
        self.request_type = Some(request_type);
        self.security_policy_uri = Some(UAString::from(security_policy_uri));
        self.security_mode = Some(security_mode);
        self.requested_lifetime = Some(requested_lifetime);
        self
    }
}

impl Event for ServerAuditEvent {
    fn clone_box(&self) -> Box<dyn Event + Send> {
        Box::new(self.clone())
    }

    fn get_field(
        &self,
        _type_definition_id: &NodeId,
        attribute_id: AttributeId,
        index_range: &NumericRange,
        browse_path: &[QualifiedName],
    ) -> Variant {
        self.get_value(attribute_id, index_range, browse_path)
    }

    fn time(&self) -> &DateTime {
        &self.base.time
    }

    fn event_type_id(&self) -> &NodeId {
        &self.base.event_type
    }
}

impl EventField for ServerAuditEvent {
    fn get_value(
        &self,
        attribute_id: AttributeId,
        index_range: &NumericRange,
        remaining_path: &[QualifiedName],
    ) -> Variant {
        if attribute_id != AttributeId::Value || remaining_path.len() != 1 {
            return Variant::Empty;
        }

        let field = &remaining_path[0];
        if field.namespace_index != 0 {
            return Variant::Empty;
        }

        match field.name.as_ref() {
            "ActionTimeStamp" => self
                .action_time_stamp
                .get_value(attribute_id, index_range, &[]),
            "Status" => self.status.get_value(attribute_id, index_range, &[]),
            "ServerId" => self.server_id.get_value(attribute_id, index_range, &[]),
            "ClientAuditEntryId" => {
                self.client_audit_entry_id
                    .get_value(attribute_id, index_range, &[])
            }
            "ClientUserId" => self
                .client_user_id
                .get_value(attribute_id, index_range, &[]),
            "StatusCodeId" => self
                .status_code_id
                .get_value(attribute_id, index_range, &[]),
            "SessionId" => self.session_id.get_value(attribute_id, index_range, &[]),
            "SecureChannelId" => self
                .secure_channel_id
                .get_value(attribute_id, index_range, &[]),
            "UserIdentityToken" => {
                self.user_identity_token
                    .get_value(attribute_id, index_range, &[])
            }
            "MethodId" => self.method_id.get_value(attribute_id, index_range, &[]),
            "AttributeId" => self.attribute_id.get_value(attribute_id, index_range, &[]),
            // AuditCreateSessionEventType exposes the client cert as "ClientCertificate";
            // AuditCertificateEventType exposes the subject cert as "Certificate" — same storage.
            "ClientCertificate" | "Certificate" => {
                self.client_certificate
                    .get_value(attribute_id, index_range, &[])
            }
            "ClientCertificateThumbprint" => {
                self.client_certificate_thumbprint
                    .get_value(attribute_id, index_range, &[])
            }
            "RevisedSessionTimeout" => {
                self.revised_session_timeout
                    .get_value(attribute_id, index_range, &[])
            }
            "RequestHandle" => self
                .request_handle
                .get_value(attribute_id, index_range, &[]),
            "RequestType" => self.request_type.get_value(attribute_id, index_range, &[]),
            "SecurityPolicyUri" => {
                self.security_policy_uri
                    .get_value(attribute_id, index_range, &[])
            }
            "SecurityMode" => self.security_mode.get_value(attribute_id, index_range, &[]),
            "RequestedLifetime" => {
                self.requested_lifetime
                    .get_value(attribute_id, index_range, &[])
            }
            "InputArguments" | "OutputArguments" => {
                // ponytail: flat audit events do not carry generated method argument arrays.
                Variant::Empty
            }
            "NewValue" | "OldValue" => {
                // ponytail: flat audit events do not carry generated write value fields.
                Variant::Empty
            }
            _ => self
                .base
                .get_value(attribute_id, index_range, remaining_path),
        }
    }
}

pub(crate) fn dispatch_activate_session(
    subscriptions: &Arc<SubscriptionCache>,
    info: &ServerInfo,
    request: &ActivateSessionRequest,
    session_id: Option<NodeId>,
    secure_channel_id: u32,
    status: StatusCode,
) {
    let event = ServerAuditEvent::outcome(
        ObjectTypeId::AuditActivateSessionEventType,
        info.application_uri.clone(),
        "ActivateSession",
        request.request_header.audit_entry_id.clone(),
        client_user_id_from_identity_token(&request.user_identity_token),
        status,
        session_id,
    )
    .with_secure_channel_id(secure_channel_id)
    .with_user_identity_token(request.user_identity_token.clone());
    dispatch_audit_event(subscriptions, &event);
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_create_session(
    subscriptions: &Arc<SubscriptionCache>,
    info: &ServerInfo,
    request: &CreateSessionRequest,
    session_id: Option<NodeId>,
    secure_channel_id: u32,
    revised_session_timeout: Option<f64>,
    status: StatusCode,
) {
    let mut event = ServerAuditEvent::outcome(
        ObjectTypeId::AuditCreateSessionEventType,
        info.application_uri.clone(),
        "CreateSession",
        request.request_header.audit_entry_id.clone(),
        UAString::null(),
        status,
        session_id,
    )
    .with_secure_channel_id(secure_channel_id)
    .with_client_certificate(request.client_certificate.clone());
    if let Some(revised_session_timeout) = revised_session_timeout {
        event = event.with_revised_session_timeout(revised_session_timeout);
    }
    dispatch_audit_event(subscriptions, &event);
}

/// Maps a certificate-validation status code to its AuditCertificateEventType subtype (Part 4 §A.2).
///
/// Returns `None` for non-certificate status codes (which get no certificate audit event).
fn certificate_event_type(status: StatusCode) -> Option<ObjectTypeId> {
    Some(match status {
        StatusCode::BadCertificateTimeInvalid | StatusCode::BadCertificateIssuerTimeInvalid => {
            ObjectTypeId::AuditCertificateExpiredEventType
        }
        StatusCode::BadCertificateRevoked
        | StatusCode::BadCertificateIssuerRevoked
        | StatusCode::BadCertificateRevocationUnknown
        | StatusCode::BadCertificateIssuerRevocationUnknown => {
            ObjectTypeId::AuditCertificateRevokedEventType
        }
        StatusCode::BadCertificateUntrusted | StatusCode::BadCertificateChainIncomplete => {
            ObjectTypeId::AuditCertificateUntrustedEventType
        }
        StatusCode::BadCertificateHostNameInvalid | StatusCode::BadCertificateUriInvalid => {
            ObjectTypeId::AuditCertificateDataMismatchEventType
        }
        StatusCode::BadCertificateInvalid
        | StatusCode::BadCertificateUseNotAllowed
        | StatusCode::BadCertificateIssuerUseNotAllowed
        | StatusCode::BadCertificatePolicyCheckFailed => {
            ObjectTypeId::AuditCertificateInvalidEventType
        }
        _ => return None,
    })
}

/// Emits the matching AuditCertificateEventType subtype when a client certificate fails validation.
///
/// A no-op for status codes that are not certificate-validation failures.
pub(crate) fn dispatch_certificate_audit(
    subscriptions: &Arc<SubscriptionCache>,
    info: &ServerInfo,
    request_header: &RequestHeader,
    certificate: ByteString,
    session_id: Option<NodeId>,
    status: StatusCode,
) {
    dispatch_certificate_audit_with_action(
        subscriptions,
        info,
        request_header,
        certificate,
        session_id,
        status,
        "Validate ClientCertificate",
    );
}

/// Emits the matching AuditCertificateEventType subtype for a suppressed finding.
///
/// The certificate validation finding selects the certificate event subtype, while the emitted
/// audit outcome is successful because the enclosing operation was allowed to continue.
pub(crate) fn dispatch_suppressed_certificate_audit_success(
    subscriptions: &Arc<SubscriptionCache>,
    info: &ServerInfo,
    request_header: &RequestHeader,
    certificate: ByteString,
    session_id: Option<NodeId>,
    finding_status: StatusCode,
) {
    let Some(event_type) = certificate_event_type(finding_status) else {
        return;
    };
    dispatch_certificate_audit_event(
        subscriptions,
        info,
        request_header,
        CertificateAuditDetails {
            event_type,
            certificate,
            session_id,
            status: StatusCode::Good,
            action: "Validate ClientCertificate",
        },
    );
}

/// Emits the matching AuditCertificateEventType subtype for an OpenSecureChannel client certificate.
///
/// A no-op for status codes that are not certificate-validation failures.
pub(crate) fn dispatch_open_secure_channel_certificate_audit(
    subscriptions: &Arc<SubscriptionCache>,
    info: &ServerInfo,
    request_header: &RequestHeader,
    certificate: ByteString,
    status: StatusCode,
) {
    let event_type = certificate_event_type(status).or_else(|| {
        // OPC UA Part 4 §6.1.3 reports some application-certificate validation failures to the
        // client as Bad_SecurityChecksFailed while still requiring AuditCertificateInvalidEventType.
        (status == StatusCode::BadSecurityChecksFailed)
            .then_some(ObjectTypeId::AuditCertificateInvalidEventType)
    });
    let Some(event_type) = event_type else {
        return;
    };
    dispatch_certificate_audit_event(
        subscriptions,
        info,
        request_header,
        CertificateAuditDetails {
            event_type,
            certificate,
            session_id: None,
            status,
            action: "Validate OpenSecureChannel ClientCertificate",
        },
    );
}

/// Emits the matching AuditCertificateEventType subtype for an X.509 user identity certificate.
///
/// A no-op for status codes that are not certificate-validation failures.
pub(crate) fn dispatch_user_certificate_audit(
    subscriptions: &Arc<SubscriptionCache>,
    info: &ServerInfo,
    request_header: &RequestHeader,
    certificate: ByteString,
    session_id: Option<NodeId>,
    status: StatusCode,
) {
    dispatch_certificate_audit_with_action(
        subscriptions,
        info,
        request_header,
        certificate,
        session_id,
        status,
        "Validate UserIdentityCertificate",
    );
}

fn dispatch_certificate_audit_with_action(
    subscriptions: &Arc<SubscriptionCache>,
    info: &ServerInfo,
    request_header: &RequestHeader,
    certificate: ByteString,
    session_id: Option<NodeId>,
    status: StatusCode,
    action: &'static str,
) {
    let Some(event_type) = certificate_event_type(status) else {
        return;
    };
    dispatch_certificate_audit_event(
        subscriptions,
        info,
        request_header,
        CertificateAuditDetails {
            event_type,
            certificate,
            session_id,
            status,
            action,
        },
    );
}

struct CertificateAuditDetails {
    event_type: ObjectTypeId,
    certificate: ByteString,
    session_id: Option<NodeId>,
    status: StatusCode,
    action: &'static str,
}

fn dispatch_certificate_audit_event(
    subscriptions: &Arc<SubscriptionCache>,
    info: &ServerInfo,
    request_header: &RequestHeader,
    details: CertificateAuditDetails,
) {
    let event = ServerAuditEvent::outcome(
        details.event_type,
        info.application_uri.clone(),
        details.action,
        request_header.audit_entry_id.clone(),
        UAString::null(),
        details.status,
        details.session_id,
    )
    .with_certificate(details.certificate)
    .with_certificate_source_name();
    dispatch_audit_event(subscriptions, &event);
}

/// Emits an AuditCertificateMismatchEventType when the certificate presented at CreateSession does
/// not match the certificate securing the channel at ActivateSession (Part 4 §A.2 / §5.6.3).
pub(crate) fn dispatch_certificate_mismatch(
    subscriptions: &Arc<SubscriptionCache>,
    info: &ServerInfo,
    request_header: &RequestHeader,
    session_id: Option<NodeId>,
    certificate: ByteString,
) {
    let event = ServerAuditEvent::outcome(
        ObjectTypeId::AuditCertificateMismatchEventType,
        info.application_uri.clone(),
        "Validate ClientCertificate channel binding",
        request_header.audit_entry_id.clone(),
        UAString::null(),
        StatusCode::BadSecurityChecksFailed,
        session_id,
    )
    .with_certificate(certificate);
    dispatch_audit_event(subscriptions, &event);
}

/// Emits an AuditCancelEventType recording a Cancel request against the session (Part 4 §A.5).
pub(crate) fn dispatch_cancel(
    subscriptions: &Arc<SubscriptionCache>,
    info: &ServerInfo,
    request_header: &RequestHeader,
    session_id: Option<NodeId>,
    request_handle: u32,
    status: StatusCode,
) {
    let event = ServerAuditEvent::outcome(
        ObjectTypeId::AuditCancelEventType,
        info.application_uri.clone(),
        "Cancel",
        request_header.audit_entry_id.clone(),
        UAString::null(),
        status,
        session_id,
    )
    .with_request_handle(request_handle);
    dispatch_audit_event(subscriptions, &event);
}

/// Emits an AuditOpenSecureChannelEventType for an OpenSecureChannel request (Part 4 §A.3).
#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_open_secure_channel(
    subscriptions: &Arc<SubscriptionCache>,
    info: &ServerInfo,
    request_header: &RequestHeader,
    secure_channel_id: u32,
    client_certificate: ByteString,
    request_type: i32,
    security_policy_uri: &str,
    security_mode: i32,
    requested_lifetime: u32,
    status: StatusCode,
) {
    let event = ServerAuditEvent::outcome(
        ObjectTypeId::AuditOpenSecureChannelEventType,
        info.application_uri.clone(),
        "OpenSecureChannel",
        request_header.audit_entry_id.clone(),
        UAString::null(),
        status,
        None,
    )
    .with_secure_channel_id(secure_channel_id)
    .with_client_certificate(client_certificate)
    .with_secure_channel_params(
        request_type,
        security_policy_uri,
        security_mode,
        requested_lifetime,
    );
    dispatch_audit_event(subscriptions, &event);
}

pub(crate) fn dispatch_service_failure(
    subscriptions: &Arc<SubscriptionCache>,
    info: &ServerInfo,
    context: &AuditEventContext,
    status: StatusCode,
) {
    if !status.is_bad() {
        return;
    }

    let event = ServerAuditEvent::failure(
        ObjectTypeId::AuditSecurityEventType,
        info.application_uri.clone(),
        context.request_type,
        context.client_audit_entry_id.clone(),
        context.client_user_id.clone(),
        status,
        context.session_id.clone(),
    );
    dispatch_audit_event(subscriptions, &event);
}

pub(crate) fn dispatch_method_audit(
    subscriptions: &Arc<SubscriptionCache>,
    info: &ServerInfo,
    context: &AuditEventContext,
    method_id: &NodeId,
    status: StatusCode,
) {
    let event = ServerAuditEvent::method_call(
        info.application_uri.clone(),
        context.request_type,
        context.client_audit_entry_id.clone(),
        context.client_user_id.clone(),
        status,
        context.session_id.clone(),
        method_id.clone(),
    );
    dispatch_audit_event(subscriptions, &event);
}

pub(crate) fn dispatch_write_audit(
    subscriptions: &Arc<SubscriptionCache>,
    info: &ServerInfo,
    context: &AuditEventContext,
    node_id: &NodeId,
    attribute_id: u32,
    status: StatusCode,
) {
    let event = ServerAuditEvent::write_update(
        info.application_uri.clone(),
        context.request_type,
        context.client_audit_entry_id.clone(),
        context.client_user_id.clone(),
        status,
        context.session_id.clone(),
        node_id,
        attribute_id,
    );
    dispatch_audit_event(subscriptions, &event);
}

pub(crate) fn dispatch_response_failure(
    subscriptions: &Arc<SubscriptionCache>,
    info: &ServerInfo,
    context: &AuditEventContext,
    response: &ResponseMessage,
) {
    dispatch_service_failure(
        subscriptions,
        info,
        context,
        response.response_header().service_result,
    );
}

fn dispatch_audit_event(subscriptions: &SubscriptionCache, event: &ServerAuditEvent) {
    let server_node = NodeId::from(ObjectId::Server);
    let items = std::iter::once((event as &dyn Event, &server_node));
    subscriptions.notify_events(items);
}

fn client_user_id_from_identity_token(user_identity_token: &ExtensionObject) -> UAString {
    match IdentityToken::new(user_identity_token.clone()) {
        IdentityToken::Anonymous(_) => UAString::from(ANONYMOUS_USER_TOKEN_ID),
        IdentityToken::UserName(token) => token.user_name,
        IdentityToken::X509(_) => UAString::from("x509"),
        IdentityToken::IssuedToken(_) => UAString::from("issued-token"),
        IdentityToken::None | IdentityToken::Invalid(_) => UAString::null(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &str) -> Vec<QualifiedName> {
        vec![QualifiedName::new(0, name)]
    }

    #[test]
    fn audit_event_exposes_standard_audit_fields() {
        let event = ServerAuditEvent::failure(
            ObjectTypeId::AuditSecurityEventType,
            UAString::from("urn:test-server"),
            "Read",
            UAString::from("audit-entry"),
            UAString::from("operator"),
            StatusCode::BadUserAccessDenied,
            Some(NodeId::new(1, 42)),
        );

        assert_eq!(
            event.get_value(AttributeId::Value, &NumericRange::None, &field("EventType")),
            Variant::from(NodeId::from(ObjectTypeId::AuditSecurityEventType))
        );
        assert_eq!(
            event.get_value(AttributeId::Value, &NumericRange::None, &field("Status")),
            Variant::Boolean(false)
        );
        assert_eq!(
            event.get_value(
                AttributeId::Value,
                &NumericRange::None,
                &field("ClientAuditEntryId")
            ),
            Variant::from(UAString::from("audit-entry"))
        );
        assert_eq!(
            event.get_value(
                AttributeId::Value,
                &NumericRange::None,
                &field("ClientUserId")
            ),
            Variant::from(UAString::from("operator"))
        );
        assert_eq!(
            event.get_value(
                AttributeId::Value,
                &NumericRange::None,
                &field("StatusCodeId")
            ),
            Variant::StatusCode(StatusCode::BadUserAccessDenied)
        );
    }

    #[test]
    fn create_session_audit_reports_success_and_revised_timeout() {
        let event = ServerAuditEvent::outcome(
            ObjectTypeId::AuditCreateSessionEventType,
            UAString::from("urn:test-server"),
            "CreateSession",
            UAString::null(),
            UAString::null(),
            StatusCode::Good,
            Some(NodeId::new(1, 7)),
        )
        .with_secure_channel_id(5)
        .with_revised_session_timeout(1234.0);

        assert_eq!(
            event.get_value(AttributeId::Value, &NumericRange::None, &field("EventType")),
            Variant::from(NodeId::from(ObjectTypeId::AuditCreateSessionEventType))
        );
        // A Good status code is a successful audit (Status = true).
        assert_eq!(
            event.get_value(AttributeId::Value, &NumericRange::None, &field("Status")),
            Variant::Boolean(true)
        );
        assert_eq!(
            event.get_value(
                AttributeId::Value,
                &NumericRange::None,
                &field("RevisedSessionTimeout")
            ),
            Variant::from(1234.0f64)
        );
        assert_eq!(
            event.get_value(
                AttributeId::Value,
                &NumericRange::None,
                &field("SecureChannelId")
            ),
            Variant::from(UAString::from("5"))
        );
    }

    #[test]
    fn certificate_status_codes_map_to_event_subtypes() {
        let cases = [
            (
                StatusCode::BadCertificateTimeInvalid,
                ObjectTypeId::AuditCertificateExpiredEventType,
            ),
            (
                StatusCode::BadCertificateRevoked,
                ObjectTypeId::AuditCertificateRevokedEventType,
            ),
            (
                StatusCode::BadCertificateUntrusted,
                ObjectTypeId::AuditCertificateUntrustedEventType,
            ),
            (
                StatusCode::BadCertificateUriInvalid,
                ObjectTypeId::AuditCertificateDataMismatchEventType,
            ),
            (
                StatusCode::BadCertificateHostNameInvalid,
                ObjectTypeId::AuditCertificateDataMismatchEventType,
            ),
            (
                StatusCode::BadCertificateInvalid,
                ObjectTypeId::AuditCertificateInvalidEventType,
            ),
            (
                StatusCode::BadCertificateUseNotAllowed,
                ObjectTypeId::AuditCertificateInvalidEventType,
            ),
            (
                StatusCode::BadCertificateChainIncomplete,
                ObjectTypeId::AuditCertificateUntrustedEventType,
            ),
            (
                StatusCode::BadCertificatePolicyCheckFailed,
                ObjectTypeId::AuditCertificateInvalidEventType,
            ),
        ];
        for (status, expected) in cases {
            assert_eq!(certificate_event_type(status), Some(expected), "{status}");
        }
        // Non-certificate failures get no certificate audit event.
        assert_eq!(
            certificate_event_type(StatusCode::BadUserAccessDenied),
            None
        );
        assert_eq!(certificate_event_type(StatusCode::Good), None);
    }

    #[test]
    fn certificate_mismatch_audit_event_is_a_security_failure() {
        let cert = ByteString::from(vec![9u8, 8, 7]);
        let event = ServerAuditEvent::outcome(
            ObjectTypeId::AuditCertificateMismatchEventType,
            UAString::from("urn:test-server"),
            "Validate ClientCertificate channel binding",
            UAString::null(),
            UAString::null(),
            StatusCode::BadSecurityChecksFailed,
            Some(NodeId::new(1, 3)),
        )
        .with_certificate(cert.clone());

        assert_eq!(
            event.get_value(AttributeId::Value, &NumericRange::None, &field("EventType")),
            Variant::from(NodeId::from(
                ObjectTypeId::AuditCertificateMismatchEventType
            ))
        );
        assert_eq!(
            event.get_value(
                AttributeId::Value,
                &NumericRange::None,
                &field("Certificate")
            ),
            Variant::from(cert)
        );
        assert_eq!(
            event.get_value(AttributeId::Value, &NumericRange::None, &field("Status")),
            Variant::Boolean(false)
        );
    }

    #[test]
    fn open_secure_channel_audit_exposes_channel_params() {
        let event = ServerAuditEvent::outcome(
            ObjectTypeId::AuditOpenSecureChannelEventType,
            UAString::from("urn:test-server"),
            "OpenSecureChannel",
            UAString::null(),
            UAString::null(),
            StatusCode::Good,
            None,
        )
        .with_secure_channel_id(9)
        .with_secure_channel_params(
            1,
            "http://opcfoundation.org/UA/SecurityPolicy#None",
            3,
            3600,
        );

        assert_eq!(
            event.get_value(
                AttributeId::Value,
                &NumericRange::None,
                &field("RequestType")
            ),
            Variant::Int32(1)
        );
        assert_eq!(
            event.get_value(
                AttributeId::Value,
                &NumericRange::None,
                &field("SecurityPolicyUri")
            ),
            Variant::from(UAString::from(
                "http://opcfoundation.org/UA/SecurityPolicy#None"
            ))
        );
        assert_eq!(
            event.get_value(
                AttributeId::Value,
                &NumericRange::None,
                &field("SecurityMode")
            ),
            Variant::Int32(3)
        );
        assert_eq!(
            event.get_value(
                AttributeId::Value,
                &NumericRange::None,
                &field("RequestedLifetime")
            ),
            Variant::UInt32(3600)
        );
    }

    #[test]
    fn certificate_audit_event_exposes_certificate_and_failure() {
        let cert = ByteString::from(vec![1u8, 2, 3]);
        let event = ServerAuditEvent::outcome(
            ObjectTypeId::AuditCertificateUntrustedEventType,
            UAString::from("urn:test-server"),
            "Validate ClientCertificate",
            UAString::null(),
            UAString::null(),
            StatusCode::BadCertificateUntrusted,
            None,
        )
        .with_certificate(cert.clone())
        .with_certificate_source_name();

        assert_eq!(
            event.get_value(AttributeId::Value, &NumericRange::None, &field("EventType")),
            Variant::from(NodeId::from(
                ObjectTypeId::AuditCertificateUntrustedEventType
            ))
        );
        // AuditCertificateEventType exposes the subject cert as "Certificate".
        assert_eq!(
            event.get_value(
                AttributeId::Value,
                &NumericRange::None,
                &field("Certificate")
            ),
            Variant::from(cert)
        );
        assert_eq!(
            event.get_value(
                AttributeId::Value,
                &NumericRange::None,
                &field("SourceName")
            ),
            Variant::from(UAString::from(AUDIT_CERTIFICATE_SOURCE_NAME))
        );
        assert_eq!(
            event.get_value(AttributeId::Value, &NumericRange::None, &field("Status")),
            Variant::Boolean(false)
        );
        assert_eq!(
            event.get_value(
                AttributeId::Value,
                &NumericRange::None,
                &field("StatusCodeId")
            ),
            Variant::from(StatusCode::BadCertificateUntrusted)
        );
    }
}
