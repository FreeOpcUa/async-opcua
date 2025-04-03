use std::{
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};

use futures::{future::BoxFuture, stream::BoxStream, FutureExt, Stream, StreamExt, TryStreamExt};
use tracing::warn;

use crate::{
    retry::{ExponentialBackoff, SessionRetryPolicy},
    session::{session_error, session_warn},
    transport::{SecureChannelEventLoop, TransportPollResult},
};
use opcua_types::{
    AttributeId, QualifiedName, ReadValueId, StatusCode, TimestampsToReturn, VariableId,
};

use super::{
    connect::{SessionConnectMode, SessionConnector},
    services::subscriptions::event_loop::{SubscriptionActivity, SubscriptionEventLoop},
    Session, SessionState,
};

/// A list of possible events that happens while polling the session.
/// The client can use this list to monitor events such as disconnects,
/// publish failures, etc.
#[derive(Debug)]
#[non_exhaustive]
pub enum SessionPollResult {
    /// A message was sent to or received from the server.
    Transport(TransportPollResult),
    /// Connection was lost with the inner [`StatusCode`].
    ConnectionLost(StatusCode),
    /// Reconnecting to the server failed with the inner [`StatusCode`].
    ReconnectFailed(StatusCode),
    /// Session was reconnected, the mode is given by the innner [`SessionConnectMode`]
    Reconnected(SessionConnectMode),
    /// The session performed some periodic activity.
    SessionActivity(SessionActivity),
    /// The session performed some subscription-related activity.
    Subscription(SubscriptionActivity),
    /// The session begins (re)connecting to the server.
    BeginConnect,
    /// Disconnect due to a keep alive terminated.
    FinishedDisconnect,
}

struct ConnectedState {
    channel: SecureChannelEventLoop,
    keep_alive: BoxStream<'static, SessionActivity>,
    subscriptions: BoxStream<'static, SubscriptionActivity>,
    current_failed_keep_alive_count: u64,
    currently_closing: bool,
    disconnect_fut: BoxFuture<'static, Result<(), StatusCode>>,
}

enum SessionEventLoopState {
    Connected(ConnectedState),
    Connecting(SessionConnector, ExponentialBackoff, Instant),
    Disconnected,
}

/// The session event loop drives the client. It must be polled for anything to happen at all.
#[must_use = "The session event loop must be started for the session to work"]
pub struct SessionEventLoop {
    inner: Arc<Session>,
    trigger_publish_recv: tokio::sync::watch::Receiver<Instant>,
    retry: SessionRetryPolicy,
    keep_alive_interval: Duration,
    max_failed_keep_alive_count: u64,
}

impl SessionEventLoop {
    pub(crate) fn new(
        inner: Arc<Session>,
        retry: SessionRetryPolicy,
        trigger_publish_recv: tokio::sync::watch::Receiver<Instant>,
        keep_alive_interval: Duration,
        max_failed_keep_alive_count: u64,
    ) -> Self {
        Self {
            inner,
            retry,
            trigger_publish_recv,
            keep_alive_interval,
            max_failed_keep_alive_count,
        }
    }

    /// Convenience method for running the session event loop until completion,
    /// this method will return once the session is closed manually, or
    /// after it fails to reconnect.
    ///
    /// # Returns
    ///
    /// * `StatusCode` - [Status code](StatusCode) indicating how the session terminated.
    pub async fn run(self) -> StatusCode {
        let stream = self.enter();
        tokio::pin!(stream);
        loop {
            let r = stream.try_next().await;

            match r {
                Ok(None) => break StatusCode::Good,
                Err(e) => break e,
                _ => (),
            }
        }
    }

    /// Convenience method for running the session event loop until completion on a tokio task.
    /// This method will return a [`JoinHandle`](tokio::task::JoinHandle) that will terminate
    /// once the session is closed manually, or after it fails to reconnect.
    ///
    /// # Returns
    ///
    /// * `JoinHandle<StatusCode>` - Handle to a tokio task wrapping the event loop.
    pub fn spawn(self) -> tokio::task::JoinHandle<StatusCode> {
        tokio::task::spawn(self.run())
    }

    /// Start the event loop, returning a stream that must be polled until it is closed.
    /// The stream will return `None` when the transport is closed manually, or
    /// `Some(Err(StatusCode))` when the stream fails to reconnect after a loss of connection.
    ///
    /// It yields events from normal session operation, which can be used to take specific actions
    /// based on changes to the session state.
    pub fn enter(self) -> impl Stream<Item = Result<SessionPollResult, StatusCode>> {
        futures::stream::try_unfold(
            (self, SessionEventLoopState::Disconnected),
            |(slf, state)| async move {
                let (res, state) = match state {
                    SessionEventLoopState::Connected(mut state) => {
                        tokio::select! {
                            r = state.channel.poll() => {
                                if let TransportPollResult::Closed(code) = r {
                                    session_warn!(slf.inner, "Transport disconnected: {code}");
                                    let _ = slf.inner.state_watch_tx.send(SessionState::Disconnected);

                                    let should_reconnect = slf.inner.should_reconnect.load(Ordering::Relaxed);
                                    if !should_reconnect {
                                        return Ok(None);
                                    }

                                    Ok((
                                        SessionPollResult::ConnectionLost(code),
                                        SessionEventLoopState::Disconnected,
                                    ))
                                } else {
                                    Ok((
                                        SessionPollResult::Transport(r),
                                        SessionEventLoopState::Connected(state),
                                    ))
                                }
                            }
                            r = state.keep_alive.next() => {
                                // Should never be null, fail out
                                let Some(r) = r else {
                                    session_error!(slf.inner, "Session activity loop ended unexpectedly");
                                    return Err(StatusCode::BadUnexpectedError);
                                };

                                match r {
                                    SessionActivity::KeepAliveSucceeded => state.current_failed_keep_alive_count = 0,
                                    SessionActivity::KeepAliveFailed(status_code) => {
                                        session_warn!(slf.inner, "Keep alive failed: {status_code}");
                                        state.current_failed_keep_alive_count += 1;
                                        if !state.currently_closing
                                            && state.current_failed_keep_alive_count >= slf.max_failed_keep_alive_count
                                            && slf.max_failed_keep_alive_count != 0
                                        {
                                            session_error!(slf.inner, "Maximum number of failed keep-alives exceed limit, session will be closed.");
                                            state.currently_closing = true;
                                            let s = slf.inner.clone();
                                            state.disconnect_fut = async move {
                                                s.disconnect_inner(false, false).await
                                            }.boxed();
                                        }
                                    },
                                }

                                Ok((
                                    SessionPollResult::SessionActivity(r),
                                    SessionEventLoopState::Connected(state),
                                ))
                            }
                            r = state.subscriptions.next() => {
                                // Should never be null, fail out
                                let Some(r) = r else {
                                    session_error!(slf.inner, "Subscription event loop ended unexpectedly");
                                    return Err(StatusCode::BadUnexpectedError);
                                };

                                Ok((
                                    SessionPollResult::Subscription(r),
                                    SessionEventLoopState::Connected(state),
                                ))
                            }
                            _ = &mut state.disconnect_fut => {
                                // Do nothing, if this terminates we will very soon be transitioning
                                // to a disconnected state.
                                Ok((
                                    SessionPollResult::FinishedDisconnect,
                                    SessionEventLoopState::Connected(state)
                                ))
                            }
                        }
                    }
                    SessionEventLoopState::Disconnected => {
                        let connector = SessionConnector::new(slf.inner.clone());

                        let _ = slf.inner.state_watch_tx.send(SessionState::Connecting);

                        Ok((
                            SessionPollResult::BeginConnect,
                            SessionEventLoopState::Connecting(
                                connector,
                                slf.retry.new_backoff(),
                                Instant::now(),
                            ),
                        ))
                    }
                    SessionEventLoopState::Connecting(connector, mut backoff, next_try) => {
                        tokio::time::sleep_until(next_try.into()).await;

                        match connector.try_connect().await {
                            Ok((channel, result)) => {
                                let _ = slf.inner.state_watch_tx.send(SessionState::Connected);
                                Ok((
                                    SessionPollResult::Reconnected(result),
                                    SessionEventLoopState::Connected(ConnectedState {
                                        channel,
                                        keep_alive: SessionActivityLoop::new(
                                            slf.inner.clone(),
                                            slf.keep_alive_interval,
                                        )
                                        .run()
                                        .boxed(),
                                        subscriptions: SubscriptionEventLoop::new(
                                            slf.inner.clone(),
                                            slf.trigger_publish_recv.clone(),
                                        )
                                        .run()
                                        .boxed(),
                                        current_failed_keep_alive_count: 0,
                                        currently_closing: false,
                                        disconnect_fut: futures::future::pending().boxed(),
                                    }),
                                ))
                            }
                            Err(e) => {
                                warn!("Failed to connect to server, status code: {e}");
                                match backoff.next() {
                                    Some(x) => Ok((
                                        SessionPollResult::ReconnectFailed(e),
                                        SessionEventLoopState::Connecting(
                                            connector,
                                            backoff,
                                            Instant::now() + x,
                                        ),
                                    )),
                                    None => Err(e),
                                }
                            }
                        }
                    }
                }?;

                Ok(Some((res, (slf, state))))
            },
        )
    }
}

/// Periodic activity performed by the session.
#[derive(Debug, Clone)]
pub enum SessionActivity {
    /// A keep alive request was sent to the server and a response was received with a successful state.
    KeepAliveSucceeded,
    /// A keep alive request was sent to the server, but it failed or the server was in an invalid state.
    KeepAliveFailed(StatusCode),
}

enum SessionTickEvent {
    KeepAlive,
}

struct SessionIntervals {
    keep_alive: tokio::time::Interval,
}

impl SessionIntervals {
    pub fn new(keep_alive_interval: Duration) -> Self {
        let mut keep_alive = tokio::time::interval(keep_alive_interval);
        keep_alive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        Self { keep_alive }
    }

    pub async fn next(&mut self) -> SessionTickEvent {
        tokio::select! {
            _ = self.keep_alive.tick() => SessionTickEvent::KeepAlive
        }
    }
}

struct SessionActivityLoop {
    inner: Arc<Session>,
    tick_gen: SessionIntervals,
}

impl SessionActivityLoop {
    pub fn new(inner: Arc<Session>, keep_alive_interval: Duration) -> Self {
        Self {
            inner,
            tick_gen: SessionIntervals::new(keep_alive_interval),
        }
    }

    pub fn run(self) -> impl Stream<Item = SessionActivity> {
        futures::stream::unfold(self, |mut slf| async move {
            match slf.tick_gen.next().await {
                SessionTickEvent::KeepAlive => {
                    let now = Instant::now();
                    let res = slf
                        .inner
                        .read(
                            &[ReadValueId {
                                node_id: VariableId::Server_ServerStatus_State.into(),
                                attribute_id: AttributeId::Value as u32,
                                index_range: Default::default(),
                                data_encoding: QualifiedName::null(),
                            }],
                            TimestampsToReturn::Server,
                            1f64,
                        )
                        .await;
                    let elapsed = now.elapsed();

                    let data_value = match res.map(|r| r.into_iter().next()) {
                        Ok(Some(data_value)) => {
                            // Only update if the request was successful to avoid
                            // skewing the roundtrip time by processing timeouts.
                            slf.inner
                                .publish_limits_watch_tx
                                .send_modify(|limits| limits.update_message_roundtrip(elapsed));
                            data_value
                        }
                        // Should not be possible, this would be a bug in
                        // the server, assume everything is terrible.
                        Ok(None) => {
                            return Some((
                                SessionActivity::KeepAliveFailed(StatusCode::BadUnknownResponse),
                                slf,
                            ))
                        }
                        Err(e) => return Some((SessionActivity::KeepAliveFailed(e), slf)),
                    };

                    match data_value.value.and_then(|v| v.try_cast_to().ok()) {
                        Some(0) => Some((SessionActivity::KeepAliveSucceeded, slf)),
                        Some(s) => {
                            warn!("Keep alive failed, non-running status code {s}");
                            Some((
                                SessionActivity::KeepAliveFailed(StatusCode::BadServerHalted),
                                slf,
                            ))
                        }
                        None => Some((
                            SessionActivity::KeepAliveFailed(StatusCode::BadUnknownResponse),
                            slf,
                        )),
                    }
                }
            }
        })
    }
}
