use std::{future::Future, time::Instant};

use futures::{stream::FuturesUnordered, StreamExt};
use opcua_types::StatusCode;
use tokio::{select, sync::watch::Receiver};
use tracing::debug;

use crate::{
    session::{services::subscriptions::PublishLimits, session_debug, session_error},
    SubscriptionActivity,
};

/// A trait for managing subscription state in the event loop.
///
/// This is just a handle to something that track subscriptions,
/// letting us query when the next publish should be sent.
pub trait SubscriptionCache {
    /// Get and update the time for the next publish. If `set_last_publish` is true,
    /// the last publish time is updated to now, affecting future calls to this method.
    fn next_publish_time(&mut self, set_last_publish: bool) -> Option<Instant>;
}

/// The state machine for the subscription event loop.
///
/// This is made generic and removed from the subscription event loop to make it
/// possible for users to implement their own event loop that doesn't depend on the
/// `Session`, which can allow for several useful features that we are unlikely to implement
/// in the `Session` itself, such as:
///
///  - Backpressure, letting users replace the `publish` implementation with one that
///    waits for the consumer to be ready before passing the publish response to the
///    event loop.
///  - Custom subscription caches, for example for persisting subscription state.
pub struct SubscriptionEventLoopState<T, R, S> {
    trigger_publish_recv: tokio::sync::watch::Receiver<Instant>,
    futures: FuturesUnordered<T>,
    last_external_trigger: Instant,
    // This is true if the client has received BadTooManyPublishRequests
    // and is waiting for a response before making further requests.
    waiting_for_response: bool,
    // This is true if the client has received a no_subscriptions response,
    // and is waiting for a manual trigger or successful response before resuming publishing.
    no_active_subscription: bool,
    /// Receiver for publish limits updates
    publish_limits_rx: Receiver<PublishLimits>,
    publish_source: R,
    subscription_cache: S,
    session_id: u32,
}

enum ActivityOrNext {
    Activity(SubscriptionActivity),
    Next(Option<Instant>),
}

impl<T: Future<Output = Result<bool, StatusCode>>, R: Fn() -> T, S: SubscriptionCache>
    SubscriptionEventLoopState<T, R, S>
{
    /// Construct a new subscription cache.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session id for logging purposes.
    /// * `trigger_publish_recv` - A channel used to transmit external publish triggers.
    ///   This is used to trigger publish outside of the normal schedule, for example when
    ///   a new subscription is created.
    /// * `publish_limits_rx` - A channel used to receive updates to publish limits.
    /// * `publish_source` - A function that produces a future that performs a publish operation.
    /// * `subscription_cache` - An implementation of the [SubscriptionCache] trait.
    pub fn new(
        session_id: u32,
        trigger_publish_recv: tokio::sync::watch::Receiver<Instant>,
        publish_limits_rx: Receiver<PublishLimits>,
        publish_source: R,
        subscription_cache: S,
    ) -> Self {
        let last_external_trigger = *trigger_publish_recv.borrow();
        Self {
            last_external_trigger,
            trigger_publish_recv,
            futures: FuturesUnordered::new(),
            waiting_for_response: false,
            no_active_subscription: true,
            publish_limits_rx,
            publish_source,
            subscription_cache,
            session_id,
        }
    }

    fn wait_for_next_tick(
        &self,
        next_publish: Option<Instant>,
    ) -> impl Future<Output = ()> + 'static {
        // Deliberately create a future that doesn't capture `self` at all.
        let should_wait_for_response = self.waiting_for_response && !self.futures.is_empty();
        async move {
            if should_wait_for_response {
                futures::future::pending().await
            } else if let Some(next_publish) = next_publish {
                tokio::time::sleep_until(next_publish.into()).await;
            } else {
                futures::future::pending().await
            }
        }
    }

    async fn wait_for_next_publish(&mut self) -> Result<bool, StatusCode> {
        if self.futures.is_empty() {
            futures::future::pending().await
        } else {
            self.futures
                .next()
                .await
                .unwrap_or(Err(StatusCode::BadInvalidState))
        }
    }

    fn session_id(&self) -> u32 {
        self.session_id
    }

    /// Run an iteration of the event loop, returning each time a publish message is received.
    pub async fn iter_loop(&mut self) -> SubscriptionActivity {
        let mut next = self.subscription_cache.next_publish_time(false);
        let mut recv = self.trigger_publish_recv.clone();
        loop {
            match self.tick(next, &mut recv).await {
                ActivityOrNext::Activity(a) => return a,
                ActivityOrNext::Next(n) => next = n,
            }
        }
    }

    async fn tick(
        &mut self,
        mut next_publish: Option<Instant>,
        recv: &mut Receiver<Instant>,
    ) -> ActivityOrNext {
        let last_external_trigger = self.last_external_trigger;
        select! {
            v = recv.wait_for(|i| i > &last_external_trigger) => {
                if let Ok(v) = v {
                    if !self.waiting_for_response {
                        debug!("Sending publish due to external trigger");
                        // On an external trigger, we always publish.
                        self.futures.push((self.publish_source)());
                        next_publish = self.subscription_cache.next_publish_time(true);
                        self.last_external_trigger = *v;
                    } else {
                        debug!("Skipping publish due BadTooManyPublishRequests");
                    }
                }
                self.no_active_subscription = false;
                ActivityOrNext::Next(next_publish)
            }
            _ = self.wait_for_next_tick(next_publish) => {
                if !self.no_active_subscription && self.futures.len()
                    < self
                        .publish_limits_rx
                        .borrow()
                        .max_publish_requests
                {
                    if !self.waiting_for_response {
                        debug!("Sending publish due to internal tick");
                        self.futures.push((self.publish_source)());
                    } else {
                        debug!("Skipping publish due BadTooManyPublishRequests");
                    }
                }
                ActivityOrNext::Next(self.subscription_cache.next_publish_time(true))
            }
            res = self.wait_for_next_publish() => {
                match res {
                    Ok(more_notifications) => {
                        if more_notifications
                            || self.futures.len()
                                < self
                                    .publish_limits_rx
                                    .borrow()
                                    .min_publish_requests
                        {
                            if !self.waiting_for_response {
                                debug!("Sending publish after receiving response");
                                self.futures.push((self.publish_source)());
                                // Set the last publish time to to avoid a buildup
                                // of publish requests if exhausting the queue takes
                                // more time than a single publishing interval.
                                self.subscription_cache.next_publish_time(true);
                            } else {
                                debug!("Skipping publish due BadTooManyPublishRequests");
                            }
                        }
                        self.waiting_for_response = false;
                        self.no_active_subscription = false;
                        ActivityOrNext::Activity(SubscriptionActivity::Publish)
                    }
                    Err(e) => {
                        match e {
                            StatusCode::BadTimeout => {
                                session_debug!(self, "Publish request timed out");
                            }
                            StatusCode::BadTooManyPublishRequests => {
                                session_debug!(
                                    self,
                                    "Server returned BadTooManyPublishRequests, backing off",
                                );
                                self.waiting_for_response = true;
                            }
                            StatusCode::BadSessionClosed
                            | StatusCode::BadSessionIdInvalid => {
                                // If this happens we will probably eventually fail keep-alive, defer to that.
                                session_error!(self, "Publish response indicates session is dead");
                                return ActivityOrNext::Activity(SubscriptionActivity::FatalFailure(e))
                            }
                            StatusCode::BadNoSubscription => {
                                session_debug!(
                                    self,
                                    "Publish response indicates that there are no subscriptions"
                                );
                                self.no_active_subscription = true;
                            },
                            _ => ()
                        }
                        ActivityOrNext::Activity(SubscriptionActivity::PublishFailed(e))
                    }
                }
            },
        }
    }
}
