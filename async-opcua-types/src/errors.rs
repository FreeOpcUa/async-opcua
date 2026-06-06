// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0

//!  Rust OpcUa specific errors

use thiserror::Error;

use crate::{relative_path::RelativePathError, StatusCode, VariantScalarTypeId};

/// Rust OpcUa specific errors
#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum OpcUaError {
    #[error("Received an unexpected variant type")]
    UnexpectedVariantType {
        variant_id: Option<VariantScalarTypeId>,
        message: String,
    },
    #[error("The requested namespace does not exists")]
    NamespaceDoesNotExist(String),
    #[error("Request returned a StatusCode Error: {0}")]
    StatusCodeError(StatusCode),
    #[error("Generic Error: {0}")]
    Error(crate::Error),
    #[error("Function returned a RelativePathError: {0}")]
    RelativePathError(RelativePathError),
}

impl From<StatusCode> for OpcUaError {
    fn from(value: StatusCode) -> Self {
        OpcUaError::StatusCodeError(value)
    }
}

impl From<crate::Error> for OpcUaError {
    fn from(value: crate::Error) -> Self {
        OpcUaError::Error(value)
    }
}

impl From<RelativePathError> for OpcUaError {
    fn from(value: RelativePathError) -> Self {
        OpcUaError::RelativePathError(value)
    }
}
