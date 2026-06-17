use std::{future::Future, time::Instant};

use futures::{stream::FuturesUnordered, StreamExt};
use opcua_types::{Error, StatusCode};
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

impl<T: Future<Output = Result<bool, Error>>, R: Fn() -> T, S: SubscriptionCache>
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

    async fn wait_for_next_publish(&mut self) -> Result<bool, Error> {
        if self.futures.is_empty() {
            futures::future::pending().await
        } else {
            self.futures.next().await.unwrap_or_else(|| {
                Err(Error::new(
                    StatusCode::BadInvalidState,
                    "Invalid state, polling for publish completion returned None",
                ))
            })
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
                        match e.status() {
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
                                return ActivityOrNext::Activity(SubscriptionActivity::FatalFailure(e.status()))
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
                        // `waiting_for_response` is a backoff latch for
                        // BadTooManyPublishRequests; it must never persist once
                        // there are no in-flight publish requests, otherwise if
                        // the in-flight requests all drain to errors rather than
                        // an Ok response, the send sites stay gated forever and
                        // notification delivery freezes while the session stays alive.
                        if self.futures.is_empty() {
                            self.waiting_for_response = false;
                        }
                        ActivityOrNext::Activity(SubscriptionActivity::PublishFailed(e.status()))
                    }
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    };

    use opcua_types::{Error, StatusCode};
    use tokio::{sync::watch, time::timeout};

    use super::{SubscriptionCache, SubscriptionEventLoopState};
    use crate::{session::services::subscriptions::PublishLimits, SubscriptionActivity};

    struct ImmediateCache;
    impl SubscriptionCache for ImmediateCache {
        fn next_publish_time(&mut self, _set_last_publish: bool) -> Option<Instant> {
            // Always due now, so internal ticks fire immediately under tokio time.
            Some(Instant::now())
        }
    }

    fn limits(min: usize, max: usize) -> PublishLimits {
        PublishLimits {
            message_roundtrip: Duration::from_millis(10),
            publish_interval: Duration::ZERO,
            subscriptions: 1,
            min_publish_requests: min,
            max_publish_requests: max,
        }
    }

    /// Regression for the downstream QuackPLC 24h-soak freeze (issue #10): after a
    /// `BadTooManyPublishRequests` sets the `waiting_for_response` backoff latch, if the
    /// in-flight publish requests drain to errors (never an `Ok`), the client must still
    /// resume sending Publish. Before the fix the latch stayed set forever and notification
    /// delivery froze permanently while the session stayed alive — here the second
    /// `iter_loop()` would hang and the timeout would fire.
    #[tokio::test]
    async fn publish_resumes_after_too_many_publish_requests_drains_to_error() {
        let start = Instant::now();
        let (trigger_tx, trigger_rx) = watch::channel(start);
        let (_limits_tx, limits_rx) = watch::channel(limits(0, 1));

        let calls = Arc::new(AtomicUsize::new(0));
        let publish_source = {
            let calls = calls.clone();
            move || {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n == 0 {
                        // First (and only in-flight) publish drains to an error that
                        // sets the backoff latch — the exact stuck state from the report.
                        Err(Error::new(
                            StatusCode::BadTooManyPublishRequests,
                            "too many",
                        ))
                    } else {
                        Ok(false)
                    }
                }
            }
        };

        let mut state = SubscriptionEventLoopState::new(
            0,
            trigger_rx,
            limits_rx,
            publish_source,
            ImmediateCache,
        );

        // Bootstrap publishing with an external trigger (clears `no_active_subscription`).
        trigger_tx.send(start + Duration::from_millis(1)).unwrap();

        let first = timeout(Duration::from_secs(2), state.iter_loop())
            .await
            .expect("first publish attempt should complete");
        assert!(
            matches!(
                first,
                SubscriptionActivity::PublishFailed(StatusCode::BadTooManyPublishRequests)
            ),
            "expected BadTooManyPublishRequests, got {first:?}"
        );

        // The latch must have been re-armed once the in-flight set drained, so publishing
        // resumes. Before the fix this hangs forever (stuck latch) and the timeout fires.
        let second = timeout(Duration::from_secs(2), state.iter_loop())
            .await
            .expect("publishing must resume after BadTooManyPublishRequests drains (issue #10)");
        assert!(
            matches!(second, SubscriptionActivity::Publish),
            "expected a successful Publish after resuming, got {second:?}"
        );
        assert!(
            calls.load(Ordering::SeqCst) >= 2,
            "publish_source must be invoked again after the backoff drains"
        );
    }
}
