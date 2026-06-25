use crate::node_manager::{
    AddNodeItem, AddReferenceItem, DeleteNodeItem, DeleteReferenceItem, RequestContext,
};
use opcua_types::{
    AddNodeAttributes, AddNodesItem, AddReferencesItem, DeleteNodesItem, DeleteReferencesItem,
    ExpandedNodeId, ExtensionObject,
};

#[cfg(feature = "generated-address-space")]
mod generated {
    use super::*;
    use crate::{identity_token::IdentityToken, ANONYMOUS_USER_TOKEN_ID};
    use opcua_core_namespace::events::{
        AuditAddNodesEventType, AuditAddReferencesEventType, AuditDeleteNodesEventType,
        AuditDeleteReferencesEventType, AuditEventType, AuditNodeManagementEventType,
    };
    use opcua_nodes::{BaseEventType, Event};
    use opcua_types::{ByteString, DateTime, NodeId, ObjectId, ObjectTypeId, UAString};
    use uuid::Uuid;

    const AUDIT_SOURCE_NAME: &str = "Server";
    const AUDIT_SUCCESS_SEVERITY: u16 = 100;

    pub(crate) fn notify_add_nodes(context: &RequestContext, nodes_to_add: Vec<AddNodesItem>) {
        for nodes_to_add in nodes_to_add {
            let event = AuditAddNodesEventType {
                base: audit_node_management_base(
                    context,
                    ObjectTypeId::AuditAddNodesEventType,
                    "AddNodes succeeded",
                ),
                nodes_to_add,
            };
            notify_audit_event(context, &event);
        }
    }

    pub(crate) fn notify_delete_nodes(
        context: &RequestContext,
        nodes_to_delete: Vec<DeleteNodesItem>,
    ) {
        for nodes_to_delete in nodes_to_delete {
            let event = AuditDeleteNodesEventType {
                base: audit_node_management_base(
                    context,
                    ObjectTypeId::AuditDeleteNodesEventType,
                    "DeleteNodes succeeded",
                ),
                nodes_to_delete,
            };
            notify_audit_event(context, &event);
        }
    }

    pub(crate) fn notify_add_references(
        context: &RequestContext,
        references_to_add: Vec<AddReferencesItem>,
    ) {
        for references_to_add in references_to_add {
            let event = AuditAddReferencesEventType {
                base: audit_node_management_base(
                    context,
                    ObjectTypeId::AuditAddReferencesEventType,
                    "AddReferences succeeded",
                ),
                references_to_add,
            };
            notify_audit_event(context, &event);
        }
    }

    pub(crate) fn notify_delete_references(
        context: &RequestContext,
        references_to_delete: Vec<DeleteReferencesItem>,
    ) {
        for references_to_delete in references_to_delete {
            let event = AuditDeleteReferencesEventType {
                base: audit_node_management_base(
                    context,
                    ObjectTypeId::AuditDeleteReferencesEventType,
                    "DeleteReferences succeeded",
                ),
                references_to_delete,
            };
            notify_audit_event(context, &event);
        }
    }

    fn audit_node_management_base(
        context: &RequestContext,
        event_type: ObjectTypeId,
        message: &str,
    ) -> AuditNodeManagementEventType {
        AuditNodeManagementEventType {
            base: audit_base(context, event_type, message),
        }
    }

    fn audit_base(
        context: &RequestContext,
        event_type: ObjectTypeId,
        message: &str,
    ) -> AuditEventType {
        let now = DateTime::now();
        let base = BaseEventType::new(
            event_type,
            ByteString::from(Uuid::new_v4().as_bytes().as_slice()),
            message,
            now,
        )
        .set_source_node(ObjectId::Server.into())
        .set_source_name(UAString::from(AUDIT_SOURCE_NAME))
        .set_severity(AUDIT_SUCCESS_SEVERITY);

        AuditEventType {
            base,
            action_time_stamp: now,
            client_audit_entry_id: UAString::null(),
            client_user_id: client_user_id(context),
            server_id: context.info.application_uri.clone(),
            status: true,
        }
    }

    fn client_user_id(context: &RequestContext) -> UAString {
        let session = context.session.read();
        match session.user_identity() {
            IdentityToken::Anonymous(_) => UAString::from(ANONYMOUS_USER_TOKEN_ID),
            IdentityToken::UserName(token) => token.user_name.clone(),
            IdentityToken::X509(_) => UAString::from("x509"),
            IdentityToken::IssuedToken(_) => session
                .user_token()
                .map(|token| UAString::from(token.0.as_str()))
                .unwrap_or_else(|| UAString::from("issued-token")),
            IdentityToken::None | IdentityToken::Invalid(_) => session
                .user_token()
                .map(|token| UAString::from(token.0.as_str()))
                .unwrap_or_else(UAString::null),
        }
    }

    fn notify_audit_event(context: &RequestContext, event: &dyn Event) {
        let server_node_id = NodeId::from(ObjectId::Server);
        context
            .subscriptions
            .notify_events(std::iter::once((event, &server_node_id)));
    }
}

pub(crate) fn add_nodes_item(item: &AddNodeItem) -> AddNodesItem {
    AddNodesItem {
        parent_node_id: item.parent_node_id().clone(),
        reference_type_id: item.reference_type_id().clone(),
        requested_new_node_id: ExpandedNodeId::new(item.added_node_id().clone()),
        browse_name: item.browse_name().clone(),
        node_class: item.node_class(),
        node_attributes: add_node_attributes(item.node_attributes()),
        type_definition: item.type_definition_id().clone(),
    }
}

pub(crate) fn delete_nodes_item(item: &DeleteNodeItem) -> DeleteNodesItem {
    DeleteNodesItem {
        node_id: item.node_id().clone(),
        delete_target_references: item.delete_target_references(),
    }
}

pub(crate) fn add_references_item(item: &AddReferenceItem) -> AddReferencesItem {
    AddReferencesItem {
        source_node_id: item.source_node_id().clone(),
        reference_type_id: item.reference_type_id().clone(),
        is_forward: item.is_forward(),
        target_server_uri: item.target_server_uri().clone(),
        target_node_id: item.target_node_id().clone(),
        target_node_class: item.target_node_class(),
    }
}

pub(crate) fn delete_references_item(item: &DeleteReferenceItem) -> DeleteReferencesItem {
    DeleteReferencesItem {
        source_node_id: item.source_node_id().clone(),
        reference_type_id: item.reference_type_id().clone(),
        is_forward: item.is_forward(),
        target_node_id: item.target_node_id().clone(),
        delete_bidirectional: item.delete_bidirectional(),
    }
}

fn add_node_attributes(attributes: &AddNodeAttributes) -> ExtensionObject {
    match attributes {
        AddNodeAttributes::Object(value) => ExtensionObject::from_message(value.clone()),
        AddNodeAttributes::Variable(value) => ExtensionObject::from_message(value.clone()),
        AddNodeAttributes::Method(value) => ExtensionObject::from_message(value.clone()),
        AddNodeAttributes::ObjectType(value) => ExtensionObject::from_message(value.clone()),
        AddNodeAttributes::VariableType(value) => ExtensionObject::from_message(value.clone()),
        AddNodeAttributes::ReferenceType(value) => ExtensionObject::from_message(value.clone()),
        AddNodeAttributes::DataType(value) => ExtensionObject::from_message(value.clone()),
        AddNodeAttributes::View(value) => ExtensionObject::from_message(value.clone()),
        AddNodeAttributes::Generic(value) => ExtensionObject::from_message(value.clone()),
        AddNodeAttributes::None => ExtensionObject::null(),
    }
}

#[cfg(feature = "generated-address-space")]
pub(crate) use generated::{
    notify_add_nodes, notify_add_references, notify_delete_nodes, notify_delete_references,
};

#[cfg(not(feature = "generated-address-space"))]
pub(crate) fn notify_add_nodes(_context: &RequestContext, _nodes_to_add: Vec<AddNodesItem>) {}

#[cfg(not(feature = "generated-address-space"))]
pub(crate) fn notify_delete_nodes(
    _context: &RequestContext,
    _nodes_to_delete: Vec<DeleteNodesItem>,
) {
}

#[cfg(not(feature = "generated-address-space"))]
pub(crate) fn notify_add_references(
    _context: &RequestContext,
    _references_to_add: Vec<AddReferencesItem>,
) {
}

#[cfg(not(feature = "generated-address-space"))]
pub(crate) fn notify_delete_references(
    _context: &RequestContext,
    _references_to_delete: Vec<DeleteReferencesItem>,
) {
}
