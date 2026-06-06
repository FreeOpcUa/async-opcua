use std::time::Duration;

use futures::FutureExt;
use opcua_types::{Error, StatusCode};

use crate::retry::ExponentialBackoff;

use super::{session_debug, Session, UARequest};

/// Trait for generic retry policies, used with [`Session::send_with_retry`].
/// For simple use cases you can use [`DefaultRetryPolicy`].
pub trait RequestRetryPolicy {
    /// Return the time until the next retry, or [`None`] if no more retries should be attempted.
    fn get_next_delay(&mut self, status: StatusCode) -> Option<Duration>;
}

impl RequestRetryPolicy for Box<dyn RequestRetryPolicy + Send> {
    fn get_next_delay(&mut self, status: StatusCode) -> Option<Duration> {
        (**self).get_next_delay(status)
    }
}

/// A simple default retry policy. This will retry using the given [`ExponentialBackoff`] if
/// the error matches one of the following status codes:
///
/// - StatusCode::BadUnexpectedError
/// - StatusCode::BadInternalError
/// - StatusCode::BadOutOfMemory
/// - StatusCode::BadResourceUnavailable
/// - StatusCode::BadCommunicationError
/// - StatusCode::BadTimeout
/// - StatusCode::BadShutdown
/// - StatusCode::BadServerNotConnected
/// - StatusCode::BadServerHalted
/// - StatusCode::BadNonceInvalid
/// - StatusCode::BadSessionClosed
/// - StatusCode::BadSessionIdInvalid
/// - StatusCode::BadSessionNotActivated
/// - StatusCode::BadNoCommunication
/// - StatusCode::BadTooManySessions
/// - StatusCode::BadTcpServerTooBusy
/// - StatusCode::BadTcpSecureChannelUnknown
/// - StatusCode::BadTcpNotEnoughResources
/// - StatusCode::BadTcpInternalError
/// - StatusCode::BadSecureChannelClosed
/// - StatusCode::BadSecureChannelIdInvalid
/// - StatusCode::BadNotConnected
/// - StatusCode::BadDeviceFailure
/// - StatusCode::BadSensorFailure
/// - StatusCode::BadDisconnect
/// - StatusCode::BadConnectionClosed
/// - StatusCode::BadEndOfStream
/// - StatusCode::BadInvalidState
/// - StatusCode::BadMaxConnectionsReached
/// - StatusCode::BadConnectionRejected
///
/// or if it's in the configured `extra_status_codes`.
#[derive(Clone)]
pub struct DefaultRetryPolicy<'a> {
    backoff: ExponentialBackoff,
    extra_status_codes: &'a [StatusCode],
}

impl<'a> DefaultRetryPolicy<'a> {
    /// Create a new default retry policy with the given backoff generator.
    pub fn new(backoff: ExponentialBackoff) -> Self {
        Self {
            backoff,
            extra_status_codes: &[],
        }
    }

    /// Create a retry policy with extra status codes to retry.
    pub fn new_with_extras(
        backoff: ExponentialBackoff,
        extra_status_codes: &'a [StatusCode],
    ) -> Self {
        Self {
            backoff,
            extra_status_codes,
        }
    }
}

impl RequestRetryPolicy for DefaultRetryPolicy<'_> {
    fn get_next_delay(&mut self, status: StatusCode) -> Option<Duration> {
        // These status codes should generally be safe to retry, by default.
        // If users disagree they can simply implement `RequestRetryPolicy` themselves.

        let should_retry = matches!(
            status,
            StatusCode::BadUnexpectedError
                | StatusCode::BadInternalError
                | StatusCode::BadOutOfMemory
                | StatusCode::BadResourceUnavailable
                | StatusCode::BadCommunicationError
                | StatusCode::BadTimeout
                | StatusCode::BadShutdown
                | StatusCode::BadServerNotConnected
                | StatusCode::BadServerHalted
                | StatusCode::BadNonceInvalid
                | StatusCode::BadSessionClosed
                | StatusCode::BadSessionIdInvalid
                | StatusCode::BadSessionNotActivated
                | StatusCode::BadNoCommunication
                | StatusCode::BadTooManySessions
                | StatusCode::BadTcpServerTooBusy
                | StatusCode::BadTcpSecureChannelUnknown
                | StatusCode::BadTcpNotEnoughResources
                | StatusCode::BadTcpInternalError
                | StatusCode::BadSecureChannelClosed
                | StatusCode::BadSecureChannelIdInvalid
                | StatusCode::BadNotConnected
                | StatusCode::BadDeviceFailure
                | StatusCode::BadSensorFailure
                | StatusCode::BadDisconnect
                | StatusCode::BadConnectionClosed
                | StatusCode::BadEndOfStream
                | StatusCode::BadInvalidState
                | StatusCode::BadMaxConnectionsReached
                | StatusCode::BadConnectionRejected
        ) || self.extra_status_codes.contains(&status);

        if should_retry {
            self.backoff.next()
        } else {
            None
        }
    }
}

impl Session {
    /// Send a UARequest, retrying if the request fails.
    /// Note that this will always clone the request at least once.
    pub async fn send_with_retry<T: UARequest + Clone>(
        &self,
        request: T,
        mut policy: impl RequestRetryPolicy,
    ) -> Result<T::Out, Error> {
        loop {
            let next_request = request.clone();
            // Removing `boxed` here causes any futures calling this to be non-send,
            // due to a compiler bug. Look into removing this in the future.
            // TODO: Check if tests compile without this in future rustc versions, especially
            // if https://github.com/rust-lang/rust/issues/100013 is closed.
            match next_request.send(&self.channel).boxed().await {
                Ok(r) => break Ok(r),
                Err(e) => {
                    if let Some(delay) = policy.get_next_delay(e.status()) {
                        session_debug!(self, "Request failed, retrying after {delay:?}");
                        tokio::time::sleep(delay).await;
                    } else {
                        break Err(e);
                    }
                }
            }
        }
    }
}
