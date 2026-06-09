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

/// Validate a Safety Protocol Data Unit (SPDU) against the given safety parameters.
pub fn validate_safety_spdu(
    spdu: &async_opcua_safety::Spdu,
    expected_sequence_number: u32,
    max_delay: u64,
    current_time: u64,
) -> Result<(), StatusCode> {
    let mut validator =
        async_opcua_safety::SafetyValidator::new(expected_sequence_number, max_delay);
    match validator.validate(spdu, current_time) {
        Ok(()) => Ok(()),
        Err(async_opcua_safety::SafetyError::InvalidCrc) => {
            Err(StatusCode::BadSecurityChecksFailed)
        }
        Err(async_opcua_safety::SafetyError::SequenceMismatch) => {
            Err(StatusCode::BadSequenceNumberInvalid)
        }
        Err(async_opcua_safety::SafetyError::Timeout) => Err(StatusCode::BadTimeout),
    }
}
