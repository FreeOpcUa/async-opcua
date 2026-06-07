use std::sync::Arc;

use opcua_core::ResponseMessage;
use opcua_nodes::{BaseEventType, Event, EventField};
use opcua_types::{
    ActivateSessionRequest, AttributeId, ByteString, DateTime, ExtensionObject, NodeId,
    NumericRange, ObjectId, ObjectTypeId, QualifiedName, RequestHeader, StatusCode, UAString,
    Variant,
};
use uuid::Uuid;

use crate::{
    identity_token::IdentityToken, info::ServerInfo, subscriptions::SubscriptionCache,
    ANONYMOUS_USER_TOKEN_ID,
};

const AUDIT_FAILURE_SEVERITY: u16 = 900;
const AUDIT_SOURCE_NAME: &str = "Server";

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
}

impl ServerAuditEvent {
    fn failure(
        event_type: ObjectTypeId,
        server_id: UAString,
        action: &str,
        client_audit_entry_id: UAString,
        client_user_id: UAString,
        status_code_id: StatusCode,
        session_id: Option<NodeId>,
    ) -> Self {
        let now = DateTime::now();
        let message = format!("{action} failed: {status_code_id}");
        let base = BaseEventType::new(
            event_type,
            ByteString::from(Uuid::new_v4().as_bytes().as_slice()),
            message,
            now,
        )
        .set_source_node(ObjectId::Server.into())
        .set_source_name(UAString::from(AUDIT_SOURCE_NAME))
        .set_severity(AUDIT_FAILURE_SEVERITY);

        Self {
            base,
            action_time_stamp: now,
            status: false,
            server_id,
            client_audit_entry_id,
            client_user_id,
            status_code_id,
            session_id,
            secure_channel_id: None,
            user_identity_token: None,
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
}

impl Event for ServerAuditEvent {
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
            _ => self
                .base
                .get_value(attribute_id, index_range, remaining_path),
        }
    }
}

pub(crate) fn dispatch_activate_session_failure(
    subscriptions: &Arc<SubscriptionCache>,
    info: &ServerInfo,
    request: &ActivateSessionRequest,
    session_id: Option<NodeId>,
    secure_channel_id: u32,
    status: StatusCode,
) {
    let event = ServerAuditEvent::failure(
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
}
