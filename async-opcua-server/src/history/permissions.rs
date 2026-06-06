use crate::address_space::{user_access_level, AccessLevel, EventNotifier, NodeType};
use crate::node_manager::RequestContext;
use opcua_types::StatusCode;

/// Validates whether the request context has permission to read history for the node.
pub fn validate_history_read_permission(
    context: &RequestContext,
    node: &NodeType,
) -> Result<(), StatusCode> {
    match node {
        NodeType::Object(object) => {
            if !object
                .event_notifier()
                .contains(EventNotifier::HISTORY_READ)
            {
                return Err(StatusCode::BadHistoryOperationUnsupported);
            }
        }
        NodeType::Variable(_) => {
            let access = user_access_level(context, node);
            if !access.contains(AccessLevel::HISTORY_READ) {
                return Err(StatusCode::BadUserAccessDenied);
            }
        }
        _ => return Err(StatusCode::BadHistoryOperationUnsupported),
    }
    Ok(())
}

/// Validates whether the request context has permission to write or update history for the node.
pub fn validate_history_write_permission(
    context: &RequestContext,
    node: &NodeType,
) -> Result<(), StatusCode> {
    match node {
        NodeType::Object(object) => {
            if !object
                .event_notifier()
                .contains(EventNotifier::HISTORY_WRITE)
            {
                return Err(StatusCode::BadHistoryOperationUnsupported);
            }
        }
        NodeType::Variable(_) => {
            let access = user_access_level(context, node);
            if !access.contains(AccessLevel::HISTORY_WRITE) {
                return Err(StatusCode::BadUserAccessDenied);
            }
        }
        _ => return Err(StatusCode::BadHistoryOperationUnsupported),
    }
    Ok(())
}
