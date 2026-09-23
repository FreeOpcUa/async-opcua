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
        let should_wait_for_response = self.backing_off();
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

    /// Back off only while a request is still in flight: its completion is what ends
    /// the back-off. With none left, nothing would end it and publishing would stop.
    fn backing_off(&self) -> bool {
        self.waiting_for_response && !self.futures.is_empty()
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
        // While backing off, leave external triggers pending instead of dropping them.
        // They fire once the back-off ends, after the response that ended it.
        let backing_off = self.backing_off();
        select! {
            v = recv.wait_for(|i| i > &last_external_trigger), if !backing_off => {
                if let Ok(v) = v {
                    debug!("Sending publish due to external trigger");
                    // On an external trigger, we always publish.
                    self.futures.push((self.publish_source)());
                    next_publish = self.subscription_cache.next_publish_time(true);
                    self.last_external_trigger = *v;
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
                    if !self.backing_off() {
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
                            if !self.backing_off() {
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
                        ActivityOrNext::Activity(SubscriptionActivity::PublishFailed(e.status()))
                    }
                }
            },
        }
    }
}

#[cfg(test)]
mod latch_tests {
    use std::{
        pin::Pin,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    use super::*;
    use crate::session::services::subscriptions::PublishLimits;

    struct Every(Duration);

    impl SubscriptionCache for Every {
        fn next_publish_time(&mut self, _set_last_publish: bool) -> Option<Instant> {
            Some(Instant::now() + self.0)
        }
    }

    type PublishFuture = Pin<Box<dyn Future<Output = Result<bool, Error>> + Send>>;

    #[tokio::test]
    async fn a_refused_publish_followed_by_a_subscription_creation() {
        let (trigger_tx, trigger_rx) = tokio::sync::watch::channel(Instant::now());
        let mut limits = PublishLimits::new();
        limits.update_subscriptions(1, Duration::from_millis(100));
        let (_limits_tx, limits_rx) = tokio::sync::watch::channel(limits);

        let publishes_sent = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&publishes_sent);
        let publish_source = move || -> PublishFuture {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if n == 0 {
                    Err(Error::new(StatusCode::BadTooManyPublishRequests, "refused"))
                } else {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Ok(false)
                }
            })
        };

        let mut state = SubscriptionEventLoopState::new(
            1,
            trigger_rx,
            limits_rx,
            publish_source,
            Every(Duration::from_millis(100)),
        );
        let mut recv = state.trigger_publish_recv.clone();

        trigger_tx.send(Instant::now()).unwrap();
        let mut next = None;
        let mut refused = false;
        for _ in 0..10 {
            match state.tick(next, &mut recv).await {
                ActivityOrNext::Activity(SubscriptionActivity::PublishFailed(
                    StatusCode::BadTooManyPublishRequests,
                )) => {
                    refused = true;
                    break;
                }
                ActivityOrNext::Activity(_) => {}
                ActivityOrNext::Next(n) => next = n,
            }
        }
        assert!(refused, "the first publish was not refused");
        assert!(state.futures.is_empty(), "a publish is still in flight");

        tokio::time::sleep(Duration::from_millis(1)).await;
        trigger_tx.send(Instant::now()).unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
        let mut ticks = 0usize;
        let mut accepted = 0usize;
        while let Ok(outcome) = tokio::time::timeout_at(deadline, state.tick(next, &mut recv)).await
        {
            ticks += 1;
            match outcome {
                ActivityOrNext::Activity(SubscriptionActivity::Publish) => accepted += 1,
                ActivityOrNext::Activity(_) => {}
                ActivityOrNext::Next(n) => next = n,
            }
            if ticks > 1_000_000 {
                break;
            }
        }
        assert!(ticks < 1_000, "the loop spun: {ticks} ticks in 500 ms");
        assert!(accepted >= 1, "the session never published again");
    }

    type TestState =
        SubscriptionEventLoopState<PublishFuture, Box<dyn Fn() -> PublishFuture>, Every>;

    /// Records what the fake server receives.
    #[derive(Default)]
    struct FakeServer {
        publishes_sent_at: std::sync::Mutex<Vec<Instant>>,
        last_in_flight_ended_at: std::sync::Mutex<Option<Instant>>,
    }

    impl FakeServer {
        fn publishes_sent(&self) -> usize {
            self.publishes_sent_at.lock().unwrap().len()
        }

        /// When the first publish after the initial two was sent, if any.
        fn third_publish_sent_at(&self) -> Option<Instant> {
            self.publishes_sent_at.lock().unwrap().get(2).copied()
        }

        fn last_in_flight_ended_at(&self) -> Instant {
            self.last_in_flight_ended_at
                .lock()
                .unwrap()
                .expect("the last publish in flight never ended")
        }
    }

    /// Sends two publishes and returns once the server has refused the first one.
    /// The second one is still in flight, and ends with `last_in_flight` 50 ms after it was sent.
    async fn backing_off_with_one_publish_in_flight(
        last_in_flight: Result<bool, StatusCode>,
        publishing_interval: Duration,
    ) -> (
        TestState,
        tokio::sync::watch::Sender<Instant>,
        Arc<FakeServer>,
    ) {
        let (trigger_tx, trigger_rx) = tokio::sync::watch::channel(Instant::now());
        let mut limits = PublishLimits::new();
        limits.update_subscriptions(1, publishing_interval);
        let (_limits_tx, limits_rx) = tokio::sync::watch::channel(limits);

        let server = Arc::new(FakeServer::default());
        let recorder = Arc::clone(&server);
        let publish_source: Box<dyn Fn() -> PublishFuture> = Box::new(move || {
            let mut sent_at = recorder.publishes_sent_at.lock().unwrap();
            let n = sent_at.len();
            sent_at.push(Instant::now());
            let recorder = Arc::clone(&recorder);
            Box::pin(async move {
                match n {
                    0 => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        Err(Error::new(StatusCode::BadTooManyPublishRequests, "refused"))
                    }
                    1 => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        *recorder.last_in_flight_ended_at.lock().unwrap() = Some(Instant::now());
                        last_in_flight.map_err(|status| Error::new(status, "failed"))
                    }
                    _ => {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        Ok(false)
                    }
                }
            })
        });

        let mut state = SubscriptionEventLoopState::new(
            1,
            trigger_rx,
            limits_rx,
            publish_source,
            Every(publishing_interval),
        );
        let mut recv = state.trigger_publish_recv.clone();

        let mut next = None;
        for _ in 0..2 {
            tokio::time::sleep(Duration::from_millis(1)).await;
            trigger_tx.send(Instant::now()).unwrap();
            if let ActivityOrNext::Next(n) = state.tick(next, &mut recv).await {
                next = n;
            }
        }
        assert_eq!(
            server.publishes_sent(),
            2,
            "two publishes are not in flight"
        );

        let mut refused = false;
        for _ in 0..10 {
            match state.tick(next, &mut recv).await {
                ActivityOrNext::Activity(SubscriptionActivity::PublishFailed(
                    StatusCode::BadTooManyPublishRequests,
                )) => {
                    refused = true;
                    break;
                }
                ActivityOrNext::Activity(_) => {}
                ActivityOrNext::Next(n) => next = n,
            }
        }
        assert!(refused, "the first publish was not refused");
        assert!(state.backing_off(), "the session is not backing off");

        (state, trigger_tx, server)
    }

    /// Runs the loop for 500 ms and returns the number of ticks.
    async fn run_for_500_ms(state: &mut TestState, recv: &mut Receiver<Instant>) -> usize {
        let mut next = state.subscription_cache.next_publish_time(false);
        let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
        let mut ticks = 0usize;
        while let Ok(outcome) = tokio::time::timeout_at(deadline, state.tick(next, recv)).await {
            ticks += 1;
            if let ActivityOrNext::Next(n) = outcome {
                next = n;
            }
            if ticks > 1_000_000 {
                break;
            }
        }
        ticks
    }

    #[tokio::test]
    async fn a_refused_publish_followed_by_a_timeout_of_the_last_one_in_flight() {
        let (mut state, _trigger_tx, server) = backing_off_with_one_publish_in_flight(
            Err(StatusCode::BadTimeout),
            Duration::from_millis(100),
        )
        .await;
        let mut recv = state.trigger_publish_recv.clone();

        let ticks = run_for_500_ms(&mut state, &mut recv).await;

        assert!(ticks < 1_000, "the loop spun: {ticks} ticks in 500 ms");
        assert!(
            server.publishes_sent() > 2,
            "the session never published again"
        );
    }

    #[tokio::test]
    async fn a_subscription_creation_while_backing_off_followed_by_no_subscription() {
        let (mut state, trigger_tx, server) = backing_off_with_one_publish_in_flight(
            Err(StatusCode::BadNoSubscription),
            Duration::from_millis(100),
        )
        .await;
        let mut recv = state.trigger_publish_recv.clone();

        // `create_subscription` triggers a publish while the last one is still in flight.
        tokio::time::sleep(Duration::from_millis(1)).await;
        trigger_tx.send(Instant::now()).unwrap();
        let ticks = run_for_500_ms(&mut state, &mut recv).await;

        // `BadNoSubscription` blocks the internal tick, so only the trigger can publish.
        assert!(ticks < 1_000, "the loop spun: {ticks} ticks in 500 ms");
        assert!(
            server.publishes_sent() > 2,
            "the trigger was lost and the session never published again"
        );
    }

    #[tokio::test]
    async fn a_trigger_while_backing_off_publishes_once_the_last_one_in_flight_ends() {
        // A long publishing interval, so that only the trigger can publish within 500 ms.
        let (mut state, trigger_tx, server) = backing_off_with_one_publish_in_flight(
            Err(StatusCode::BadTimeout),
            Duration::from_secs(1),
        )
        .await;
        let mut recv = state.trigger_publish_recv.clone();

        tokio::time::sleep(Duration::from_millis(1)).await;
        trigger_tx.send(Instant::now()).unwrap();
        run_for_500_ms(&mut state, &mut recv).await;

        let sent_at = server
            .third_publish_sent_at()
            .expect("the trigger never published");
        let ended_at = server.last_in_flight_ended_at();
        assert!(
            sent_at >= ended_at,
            "the trigger published while the last one was still in flight"
        );
        let delay = sent_at - ended_at;
        assert!(
            delay < Duration::from_millis(50),
            "the trigger published {delay:?} after the back-off ended"
        );
    }

    #[tokio::test]
    async fn a_success_of_the_last_one_in_flight_publishes_at_once() {
        // A long publishing interval, so that the internal tick cannot publish within 500 ms.
        let (mut state, _trigger_tx, server) =
            backing_off_with_one_publish_in_flight(Ok(false), Duration::from_secs(1)).await;
        let mut recv = state.trigger_publish_recv.clone();

        run_for_500_ms(&mut state, &mut recv).await;

        let sent_at = server
            .third_publish_sent_at()
            .expect("the session did not publish after the success");
        let delay = sent_at - server.last_in_flight_ended_at();
        assert!(
            delay < Duration::from_millis(50),
            "the session published {delay:?} after the back-off ended"
        );
    }

    #[tokio::test]
    async fn a_refused_publish_followed_by_another_error_of_the_last_one_in_flight() {
        // `BadInternalError` has no dedicated handling in the event loop.
        let (mut state, _trigger_tx, server) = backing_off_with_one_publish_in_flight(
            Err(StatusCode::BadInternalError),
            Duration::from_millis(100),
        )
        .await;
        let mut recv = state.trigger_publish_recv.clone();

        run_for_500_ms(&mut state, &mut recv).await;

        assert!(
            server.publishes_sent() > 2,
            "the session never published again"
        );
    }
}
