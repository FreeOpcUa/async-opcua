use std::{sync::Arc, time::Instant};

use futures::Stream;
use opcua_types::StatusCode;

use crate::{
    session::services::subscriptions::event_loop_state::{
        SubscriptionCache, SubscriptionEventLoopState,
    },
    Session,
};

/// An event on the subscription event loop.
#[derive(Debug)]
pub enum SubscriptionActivity {
    /// A publish request received a successful response.
    Publish,
    /// A publish request failed, either due to a timeout or an error.
    /// The publish request will typically be retried.
    PublishFailed(StatusCode),
    /// Fatal failure, a publishing request has failed fatally in a way
    /// that indicates it will not recover on its own.
    /// This typically means the client has lost connection to the server.
    /// When this is received by the session event loop it triggers a session restart.
    FatalFailure(StatusCode),
}

/// An event loop for running periodic subscription tasks.
///
/// This handles publshing on a fixed interval, republishing failed requests,
/// and subscription keep-alive.
pub(crate) struct SubscriptionEventLoop {
    session: Arc<Session>,
    trigger_publish_recv: tokio::sync::watch::Receiver<Instant>,
}

impl SubscriptionEventLoop {
    /// Create a new subscription event loop for `session`
    ///
    /// # Arguments
    ///
    ///  * `session` - A shared reference to an [AsyncSession].
    ///  * `trigger_publish_recv` - A channel used to transmit external publish triggers.
    ///    This is used to trigger publish outside of the normal schedule, for example when
    ///    a new subscription is created.
    pub(crate) fn new(
        session: Arc<Session>,
        trigger_publish_recv: tokio::sync::watch::Receiver<Instant>,
    ) -> Self {
        Self {
            trigger_publish_recv,
            session,
        }
    }

    /// Run the subscription event loop, returning a stream that produces
    /// [SubscriptionActivity] enums, reporting activity to the session event loop.
    pub(crate) fn run(self) -> impl Stream<Item = SubscriptionActivity> {
        let session_ref = self.session.clone();

        futures::stream::unfold(
            SubscriptionEventLoopState::new(
                self.session.session_id(),
                self.trigger_publish_recv,
                self.session.publish_limits_watch_rx.clone(),
                move || {
                    let session = session_ref.clone();
                    async move { session.publish().await }
                },
                SessionSubscriptionCache {
                    inner: self.session.clone(),
                },
            ),
            |mut state| async move {
                let res = state.iter_loop().await;
                Some((res, state))
            },
        )
    }
}

struct SessionSubscriptionCache {
    inner: Arc<Session>,
}

impl SubscriptionCache for SessionSubscriptionCache {
    fn next_publish_time(&mut self, update: bool) -> Option<Instant> {
        self.inner.next_publish_time(update)
    }
}
