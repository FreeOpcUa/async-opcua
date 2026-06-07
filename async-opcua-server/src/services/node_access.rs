use opcua_types::StatusCode;

use crate::node_manager::RequestContext;

/// Validate that the current session may read nodes.
pub fn validate_read_access(context: &RequestContext) -> Result<(), StatusCode> {
    let session = context.session.read();
    if let Some(ref auth_profile) = session.auth_profile {
        if !auth_profile.can_read() {
            return Err(StatusCode::BadUserAccessDenied);
        }
    }
    Ok(())
}

/// Validate that the current session may write nodes.
pub fn validate_write_access(context: &RequestContext) -> Result<(), StatusCode> {
    let session = context.session.read();
    if let Some(ref auth_profile) = session.auth_profile {
        if !auth_profile.can_write() {
            return Err(StatusCode::BadUserAccessDenied);
        }
    }
    Ok(())
}
