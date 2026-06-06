//! Client-side Program control helper functions (Part 10).

use crate::Session;
use opcua_types::{
    AttributeId, CallMethodRequest, Error, NodeId, NumericRange, QualifiedName, ReadValueId,
    StatusCode, TimestampsToReturn, Variant,
};

/// Helper to call a method on a program node.
async fn call_program_method(
    session: &Session,
    program_id: &NodeId,
    method_suffix: &str,
) -> Result<(), Error> {
    let parent_str = match &program_id.identifier {
        opcua_types::Identifier::String(s) => s.to_string(),
        other => other.to_string(),
    };
    let method_id = NodeId::new(
        program_id.namespace,
        format!("{}_{}", parent_str, method_suffix),
    );
    let request = CallMethodRequest {
        object_id: program_id.clone(),
        method_id,
        input_arguments: None,
    };
    let result = session.call_one(request).await?;
    if result.status_code.is_good() {
        Ok(())
    } else {
        Err(Error::new(
            result.status_code,
            "Program method execution returned bad status code",
        ))
    }
}

/// Calls the Start method on the specified program.
pub async fn start_program(session: &Session, program_id: &NodeId) -> Result<(), Error> {
    call_program_method(session, program_id, "Start").await
}

/// Calls the Suspend method on the specified program.
pub async fn suspend_program(session: &Session, program_id: &NodeId) -> Result<(), Error> {
    call_program_method(session, program_id, "Suspend").await
}

/// Calls the Resume method on the specified program.
pub async fn resume_program(session: &Session, program_id: &NodeId) -> Result<(), Error> {
    call_program_method(session, program_id, "Resume").await
}

/// Calls the Halt method on the specified program.
pub async fn halt_program(session: &Session, program_id: &NodeId) -> Result<(), Error> {
    call_program_method(session, program_id, "Halt").await
}

/// Calls the Reset method on the specified program.
pub async fn reset_program(session: &Session, program_id: &NodeId) -> Result<(), Error> {
    call_program_method(session, program_id, "Reset").await
}

/// Reads the current state of the program.
pub async fn read_program_state(session: &Session, program_id: &NodeId) -> Result<String, Error> {
    let parent_str = match &program_id.identifier {
        opcua_types::Identifier::String(s) => s.to_string(),
        other => other.to_string(),
    };
    let state_id = NodeId::new(program_id.namespace, format!("{}_CurrentState", parent_str));
    let node_to_read = ReadValueId {
        node_id: state_id,
        attribute_id: AttributeId::Value as u32,
        index_range: NumericRange::None,
        data_encoding: QualifiedName::null(),
    };
    let mut data_values = session
        .read(&[node_to_read], TimestampsToReturn::Neither, 0.0)
        .await?;
    if data_values.is_empty() {
        return Err(Error::new(
            StatusCode::BadNoData,
            "No data returned from state read",
        ));
    }
    let data_value = data_values.remove(0);
    if data_value.status.unwrap_or(StatusCode::Good).is_good() {
        if let Some(Variant::String(s)) = data_value.value {
            Ok(s.to_string())
        } else {
            Err(Error::new(
                StatusCode::BadTypeMismatch,
                "CurrentState is not a String",
            ))
        }
    } else {
        Err(Error::new(
            data_value.status.unwrap_or(StatusCode::BadUnexpectedError),
            "Failed to read program state",
        ))
    }
}

/// Reads the current progress of the program.
pub async fn read_program_progress(session: &Session, program_id: &NodeId) -> Result<i32, Error> {
    let parent_str = match &program_id.identifier {
        opcua_types::Identifier::String(s) => s.to_string(),
        other => other.to_string(),
    };
    let progress_id = NodeId::new(program_id.namespace, format!("{}_Progress", parent_str));
    let node_to_read = ReadValueId {
        node_id: progress_id,
        attribute_id: AttributeId::Value as u32,
        index_range: NumericRange::None,
        data_encoding: QualifiedName::null(),
    };
    let mut data_values = session
        .read(&[node_to_read], TimestampsToReturn::Neither, 0.0)
        .await?;
    if data_values.is_empty() {
        return Err(Error::new(
            StatusCode::BadNoData,
            "No data returned from progress read",
        ));
    }
    let data_value = data_values.remove(0);
    if data_value.status.unwrap_or(StatusCode::Good).is_good() {
        if let Some(Variant::Int32(v)) = data_value.value {
            Ok(v)
        } else {
            Err(Error::new(
                StatusCode::BadTypeMismatch,
                "Progress is not an Int32",
            ))
        }
    } else {
        Err(Error::new(
            data_value.status.unwrap_or(StatusCode::BadUnexpectedError),
            "Failed to read program progress",
        ))
    }
}
