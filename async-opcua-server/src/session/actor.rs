// Items are `pub` for tests; outside test builds the parent module is
// `pub(crate)`, which would otherwise trigger unreachable_pub.
#![cfg_attr(not(any(test, feature = "test-utils")), allow(unreachable_pub))]

use std::panic::AssertUnwindSafe;
use std::sync::{atomic::Ordering, Arc};
use std::time::Instant;

use futures::FutureExt;

use opcua_core::sync::RwLock;
use opcua_types::{
    DataValue, DiagnosticBits, DiagnosticInfo, IntegerId, NodeId, NotificationMessage, ReadValueId,
    StatusCode, TimestampsToReturn, WriteValue,
};
use tokio::sync::oneshot;
use tracing::debug_span;
use tracing_futures::Instrument;

use crate::node_manager::{
    IntoResult, NodeManagers, ReadNode, RequestContext, RequestContextInner, WriteNode,
};

use super::errors::SessionError;
use super::instance::Session;

/// Response channel for a [`SessionMessage::Read`] request. The outer
/// `Err` is a service-level fault for the whole request, e.g. when the
/// owning node manager panicked.
pub type ReadResponseSender =
    oneshot::Sender<Result<(DataValue, Option<DiagnosticInfo>), StatusCode>>;
/// Response channel for a [`SessionMessage::Write`] request. The outer
/// `Err` is a service-level fault for the whole request, e.g. when the
/// owning node manager panicked.
pub type WriteResponseSender =
    oneshot::Sender<Result<(StatusCode, Option<DiagnosticInfo>), StatusCode>>;
/// Response channel for a [`SessionMessage::Publish`] request.
pub type PublishResponseSender = oneshot::Sender<Result<NotificationMessage, StatusCode>>;
/// Acknowledgement channel for a [`SessionMessage::Terminate`] request.
pub type TerminateAckSender = oneshot::Sender<TerminatedSession>;
/// Callback invoked when the actor terminates, used to clean up registry entries.
pub type TerminationCleanup = Arc<dyn Fn(&TerminatedSession) + Send + Sync>;

/// Identity of a session whose actor has terminated.
#[derive(Debug, Clone)]
pub struct TerminatedSession {
    /// Session ID of the terminated session.
    pub session_id: NodeId,
    /// Authentication token of the terminated session.
    pub authentication_token: NodeId,
}

/// Command routed to a [`SessionActor`] through its `mpsc` queue.
#[derive(Debug)]
pub enum SessionMessage {
    /// Read a single attribute through the owning node manager.
    Read {
        /// Node and attribute to read.
        node: ReadValueId,
        /// Maximum age of the value in milliseconds.
        max_age: f64,
        /// Which timestamps to return.
        timestamps_to_return: TimestampsToReturn,
        /// Requested diagnostics.
        return_diagnostics: DiagnosticBits,
        /// Channel the result is sent on.
        response: ReadResponseSender,
    },
    /// Write a single attribute through the owning node manager.
    Write {
        /// Value to write.
        value: WriteValue,
        /// Requested diagnostics.
        return_diagnostics: DiagnosticBits,
        /// Channel the result is sent on.
        response: WriteResponseSender,
    },
    /// Take a pending notification from a subscription on this session.
    Publish {
        /// Subscription to publish for.
        subscription_id: IntegerId,
        /// Channel the result is sent on.
        response: PublishResponseSender,
    },
    /// Terminate the actor, closing the session.
    Terminate {
        /// Reason for termination.
        reason: StatusCode,
        /// Channel acknowledged once the session is closed.
        acknowledge: TerminateAckSender,
    },
}

/// Actor owning the mutable state of a single session, processing
/// [`SessionMessage`]s from an `mpsc` queue one at a time.
pub struct SessionActor {
    session: Arc<RwLock<Session>>,
    context: Arc<RequestContextInner>,
    receiver: tokio::sync::mpsc::Receiver<SessionMessage>,
    termination_cleanup: Option<TerminationCleanup>,
}

impl SessionActor {
    /// Create a session actor processing messages from `receiver`.
    pub fn new(
        context: RequestContext,
        receiver: tokio::sync::mpsc::Receiver<SessionMessage>,
    ) -> Self {
        Self {
            session: context.session.clone(),
            context: context.inner,
            receiver,
            termination_cleanup: None,
        }
    }

    /// Register a callback invoked once when the actor terminates.
    pub fn with_termination_cleanup(
        mut self,
        cleanup: impl Fn(&TerminatedSession) + Send + Sync + 'static,
    ) -> Self {
        self.termination_cleanup = Some(Arc::new(cleanup));
        self
    }

    /// Run the actor until it is terminated or all senders are dropped.
    pub async fn run(&mut self, node_managers: NodeManagers) -> Result<(), SessionError> {
        while let Some(message) = self.receiver.recv().await {
            crate::metrics::METRICS
                .actor_queue_depth
                .store(self.receiver.len(), Ordering::Relaxed);
            let processing_start = Instant::now();
            match message {
                SessionMessage::Read {
                    node,
                    max_age,
                    timestamps_to_return,
                    return_diagnostics,
                    response,
                } => {
                    let result = self
                        .read(
                            node_managers.clone(),
                            node,
                            max_age,
                            timestamps_to_return,
                            return_diagnostics,
                        )
                        .await;
                    let _ = response.send(result);
                    Self::record_message_processed(processing_start);
                }
                SessionMessage::Write {
                    value,
                    return_diagnostics,
                    response,
                } => {
                    let result = self
                        .write(node_managers.clone(), value, return_diagnostics)
                        .await;
                    let _ = response.send(result);
                    Self::record_message_processed(processing_start);
                }
                SessionMessage::Publish {
                    subscription_id,
                    response,
                } => {
                    let result = self.publish(subscription_id);
                    let _ = response.send(result);
                    Self::record_message_processed(processing_start);
                }
                SessionMessage::Terminate {
                    reason,
                    acknowledge,
                } => {
                    self.receiver.close();
                    let cleanup = self.close_session();
                    self.run_termination_cleanup(&cleanup);
                    tracing::debug!(?reason, ?cleanup, "session actor terminating");
                    let _ = acknowledge.send(cleanup);
                    Self::record_message_processed(processing_start);
                    return Ok(());
                }
            }
        }

        let cleanup = self.close_session();
        self.run_termination_cleanup(&cleanup);
        tracing::debug!(?cleanup, "session actor channel closed");
        Err(SessionError::ChannelClosed)
    }

    fn record_message_processed(processing_start: Instant) {
        crate::metrics::METRICS
            .actor_messages_processed
            .fetch_add(1, Ordering::Relaxed);
        crate::metrics::METRICS
            .actor_message_duration_ns
            .fetch_add(processing_start.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }

    /// Close the session and run termination cleanup after the actor
    /// panicked, so the token registries do not leak the dead session.
    pub(crate) fn abort_after_panic(&self) {
        tracing::error!("session actor panicked, aborting session");
        let cleanup = self.close_session();
        self.run_termination_cleanup(&cleanup);
    }

    fn close_session(&self) -> TerminatedSession {
        let mut session = self.session.write();
        session.close();
        TerminatedSession {
            session_id: session.session_id().clone(),
            authentication_token: session.authentication_token.clone(),
        }
    }

    fn run_termination_cleanup(&self, cleanup: &TerminatedSession) {
        if let Some(termination_cleanup) = &self.termination_cleanup {
            termination_cleanup(cleanup);
        }
    }

    fn request_context(&self, current_node_manager_index: usize) -> RequestContext {
        let token = {
            let session = self.session.read();
            session
                .user_token()
                .cloned()
                .unwrap_or_else(|| self.context.token.clone())
        };

        RequestContext {
            current_node_manager_index,
            inner: Arc::new(RequestContextInner {
                session: self.session.clone(),
                session_id: self.context.session_id,
                authenticator: self.context.authenticator.clone(),
                token,
                type_tree: self.context.type_tree.clone(),
                type_tree_getter: self.context.type_tree_getter.clone(),
                subscriptions: self.context.subscriptions.clone(),
                info: self.context.info.clone(),
            }),
        }
    }

    async fn read(
        &self,
        node_managers: NodeManagers,
        node: ReadValueId,
        max_age: f64,
        timestamps_to_return: TimestampsToReturn,
        return_diagnostics: DiagnosticBits,
    ) -> Result<(DataValue, Option<DiagnosticInfo>), StatusCode> {
        let mut node = ReadNode::new(node, return_diagnostics);

        if node.status() == StatusCode::BadNodeIdUnknown {
            for (idx, node_manager) in node_managers.iter().enumerate() {
                if !node_manager.owns_node(&node.node().node_id) {
                    continue;
                }

                let context = self.request_context(idx);
                let mut batch = [&mut node];
                // Catch panics so a faulty node manager faults the request
                // instead of killing the actor and with it the session.
                let result = AssertUnwindSafe(
                    node_manager
                        .read(&context, max_age, timestamps_to_return, &mut batch)
                        .instrument(
                            debug_span!("SessionActorRead", node_manager = %node_manager.name()),
                        ),
                )
                .catch_unwind()
                .await;
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(status)) => batch[0].set_error(status),
                    Err(_) => {
                        tracing::error!(
                            node_manager = %node_manager.name(),
                            "node manager panicked during actor read"
                        );
                        return Err(StatusCode::BadInternalError);
                    }
                }
                break;
            }
        }

        Ok(node.into_result())
    }

    async fn write(
        &self,
        node_managers: NodeManagers,
        value: WriteValue,
        return_diagnostics: DiagnosticBits,
    ) -> Result<(StatusCode, Option<DiagnosticInfo>), StatusCode> {
        let mut node = WriteNode::new(value, return_diagnostics);

        if node.status() == StatusCode::BadNodeIdUnknown {
            for (idx, node_manager) in node_managers.iter().enumerate() {
                if !node_manager.owns_node(&node.value().node_id) {
                    continue;
                }

                let context = self.request_context(idx);
                let mut batch = [&mut node];
                // Catch panics so a faulty node manager faults the request
                // instead of killing the actor and with it the session.
                let result = AssertUnwindSafe(
                    node_manager.write(&context, &mut batch).instrument(
                        debug_span!("SessionActorWrite", node_manager = %node_manager.name()),
                    ),
                )
                .catch_unwind()
                .await;
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(status)) => batch[0].set_status(status),
                    Err(_) => {
                        tracing::error!(
                            node_manager = %node_manager.name(),
                            "node manager panicked during actor write"
                        );
                        return Err(StatusCode::BadInternalError);
                    }
                }
                break;
            }
        }

        Ok(node.into_result())
    }

    fn publish(&self, subscription_id: IntegerId) -> Result<NotificationMessage, StatusCode> {
        let Some(subscriptions) = self
            .context
            .subscriptions
            .get_session_subscriptions(self.context.session_id)
        else {
            return Err(StatusCode::BadNoSubscription);
        };

        let mut subscriptions = subscriptions.lock();
        let Some(subscription) = subscriptions.get_mut(subscription_id) else {
            return Err(StatusCode::BadSubscriptionIdInvalid);
        };

        subscription
            .take_notification()
            .ok_or(StatusCode::BadNothingToDo)
    }
}
