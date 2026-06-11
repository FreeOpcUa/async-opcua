// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

// Items are `pub` for tests; outside test builds the parent module is
// `pub(crate)`, which would otherwise trigger unreachable_pub.
#![cfg_attr(not(any(test, feature = "test-utils")), allow(unreachable_pub))]

use std::{error::Error, fmt};

/// Error returned from session actor setup and message-routing paths.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// Session setup failed before the actor could start.
    InitializationFailed(String),
    /// A session state transition was rejected.
    InvalidStateTransition {
        /// State the session was in.
        from: String,
        /// State the transition attempted to reach.
        to: String,
    },
    /// An authentication token was registered twice.
    DuplicateSessionToken,
    /// The actor message queue is full.
    MessageQueueFull,
    /// The actor channel is closed.
    ChannelClosed,
    /// The security policy did not match the session's secure channel.
    SecurityPolicyMismatch,
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InitializationFailed(message) => {
                write!(f, "session initialization failed: {message}")
            }
            Self::InvalidStateTransition { from, to } => {
                write!(f, "invalid session state transition from {from} to {to}")
            }
            Self::DuplicateSessionToken => f.write_str("duplicate session authentication token"),
            Self::MessageQueueFull => f.write_str("session actor message queue is full"),
            Self::ChannelClosed => f.write_str("session actor channel is closed"),
            Self::SecurityPolicyMismatch => f.write_str("session security policy mismatch"),
        }
    }
}

impl Error for SessionError {}

impl From<String> for SessionError {
    fn from(value: String) -> Self {
        Self::InitializationFailed(value)
    }
}

impl From<&str> for SessionError {
    fn from(value: &str) -> Self {
        Self::InitializationFailed(value.to_string())
    }
}

impl<T> From<tokio::sync::mpsc::error::SendError<T>> for SessionError {
    fn from(_: tokio::sync::mpsc::error::SendError<T>) -> Self {
        Self::ChannelClosed
    }
}

impl<T> From<tokio::sync::mpsc::error::TrySendError<T>> for SessionError {
    fn from(value: tokio::sync::mpsc::error::TrySendError<T>) -> Self {
        match value {
            tokio::sync::mpsc::error::TrySendError::Full(_) => Self::MessageQueueFull,
            tokio::sync::mpsc::error::TrySendError::Closed(_) => Self::ChannelClosed,
        }
    }
}

impl From<tokio::sync::oneshot::error::RecvError> for SessionError {
    fn from(_: tokio::sync::oneshot::error::RecvError) -> Self {
        Self::ChannelClosed
    }
}

#[cfg(test)]
mod tests {
    use super::SessionError;

    fn assert_error<E: std::error::Error>() {}

    #[test]
    fn displays_session_actor_failures() {
        assert_error::<SessionError>();

        let init = SessionError::InitializationFailed("missing endpoint".to_string());
        assert_eq!(
            init.to_string(),
            "session initialization failed: missing endpoint"
        );

        let transition = SessionError::InvalidStateTransition {
            from: "Created".to_string(),
            to: "Activated".to_string(),
        };
        assert_eq!(
            transition.to_string(),
            "invalid session state transition from Created to Activated"
        );

        assert_eq!(
            SessionError::DuplicateSessionToken.to_string(),
            "duplicate session authentication token"
        );
        assert_eq!(
            SessionError::MessageQueueFull.to_string(),
            "session actor message queue is full"
        );
        assert_eq!(
            SessionError::ChannelClosed.to_string(),
            "session actor channel is closed"
        );
        assert_eq!(
            SessionError::SecurityPolicyMismatch.to_string(),
            "session security policy mismatch"
        );
    }

    #[test]
    fn maps_mpsc_try_send_failures() {
        let (full_tx, _full_rx) = tokio::sync::mpsc::channel(1);
        full_tx.try_send(1).unwrap();
        let full_error: SessionError = full_tx.try_send(2).unwrap_err().into();
        assert_eq!(full_error, SessionError::MessageQueueFull);

        let (closed_tx, closed_rx) = tokio::sync::mpsc::channel(1);
        drop(closed_rx);
        let closed_error: SessionError = closed_tx.try_send(1).unwrap_err().into();
        assert_eq!(closed_error, SessionError::ChannelClosed);
    }
}
