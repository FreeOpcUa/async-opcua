// Items are `pub` for tests; outside test builds the parent module is
// `pub(crate)`, which would otherwise trigger unreachable_pub.
#![cfg_attr(not(any(test, feature = "test-utils")), allow(unreachable_pub))]

use std::panic::AssertUnwindSafe;
use std::sync::{atomic::Ordering, Arc};
use std::time::Instant;

use futures::FutureExt;

use opcua_core::sync::RwLock;
use opcua_types::{
    DataValue, DiagnosticBits, DiagnosticInfo, NodeId, ReadValueId, StatusCode,
    TimestampsToReturn, WriteValue,
};
use tokio::sync::oneshot;
use tracing::debug_span;
use tracing_futures::Instrument;

use crate::node_manager::{
    DynNodeManager, IntoResult, NodeManagers, ReadNode, RequestContext, RequestContextInner,
    WriteNode,
};

use super::errors::SessionError;
use super::instance::Session;
use super::services::{invoke_service_concurrently_mut, ServiceCb};

/// Response channel for a [`SessionMessage::Read`] request. The outer
/// `Err` is a service-level fault for the whole request, e.g. when the
/// owning node manager panicked.
pub type ReadResponseSender =
    oneshot::Sender<Result<Vec<(DataValue, Option<DiagnosticInfo>)>, StatusCode>>;
/// Response channel for a [`SessionMessage::Write`] request. The outer
/// `Err` is a service-level fault for the whole request, e.g. when the
/// owning node manager panicked.
pub type WriteResponseSender =
    oneshot::Sender<Result<Vec<(StatusCode, Option<DiagnosticInfo>)>, StatusCode>>;
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
///
/// Read and Write carry the full request batch so a single service call is
/// one actor round-trip, and node managers are still invoked concurrently
/// within the batch.
#[derive(Debug)]
pub enum SessionMessage {
    /// Read a batch of attributes through the owning node managers.
    Read {
        /// Nodes and attributes to read.
        nodes: Vec<ReadValueId>,
        /// Maximum age of the values in milliseconds.
        max_age: f64,
        /// Which timestamps to return.
        timestamps_to_return: TimestampsToReturn,
        /// Requested diagnostics.
        return_diagnostics: DiagnosticBits,
        /// Channel the results are sent on.
        response: ReadResponseSender,
    },
    /// Write a batch of attributes through the owning node managers.
    Write {
        /// Values to write.
        values: Vec<WriteValue>,
        /// Requested diagnostics.
        return_diagnostics: DiagnosticBits,
        /// Channel the results are sent on.
        response: WriteResponseSender,
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
            self.context
                .info
                .metrics
                .actor_queue_peak_depth
                .fetch_max(self.receiver.len(), Ordering::Relaxed);
            let processing_start = Instant::now();
            match message {
                SessionMessage::Read {
                    nodes,
                    max_age,
                    timestamps_to_return,
                    return_diagnostics,
                    response,
                } => {
                    let result = self
                        .read(
                            node_managers.clone(),
                            nodes,
                            max_age,
                            timestamps_to_return,
                            return_diagnostics,
                        )
                        .await;
                    let _ = response.send(result);
                    self.record_message_processed(processing_start);
                }
                SessionMessage::Write {
                    values,
                    return_diagnostics,
                    response,
                } => {
                    let result = self
                        .write(node_managers.clone(), values, return_diagnostics)
                        .await;
                    let _ = response.send(result);
                    self.record_message_processed(processing_start);
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
                    self.record_message_processed(processing_start);
                    return Ok(());
                }
            }
        }

        let cleanup = self.close_session();
        self.run_termination_cleanup(&cleanup);
        tracing::debug!(?cleanup, "session actor channel closed");
        Err(SessionError::ChannelClosed)
    }

    fn record_message_processed(&self, processing_start: Instant) {
        self.context
            .info
            .metrics
            .actor_messages_processed
            .fetch_add(1, Ordering::Relaxed);
        self.context
            .info
            .metrics
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
        nodes: Vec<ReadValueId>,
        max_age: f64,
        timestamps_to_return: TimestampsToReturn,
        return_diagnostics: DiagnosticBits,
    ) -> Result<Vec<(DataValue, Option<DiagnosticInfo>)>, StatusCode> {
        let mut results: Vec<_> = nodes
            .into_iter()
            .map(|n| ReadNode::new(n, return_diagnostics))
            .collect();

        struct ReadServiceCb {
            max_age: f64,
            timestamps_to_return: TimestampsToReturn,
        }

        impl ServiceCb<ReadNode> for ReadServiceCb {
            async fn call(
                &self,
                batch: &mut [&mut ReadNode],
                node_manager: &Arc<DynNodeManager>,
                context: RequestContext,
            ) {
                if let Err(e) = node_manager
                    .read(&context, self.max_age, self.timestamps_to_return, batch)
                    .instrument(
                        debug_span!("SessionActorRead", node_manager = %node_manager.name()),
                    )
                    .await
                {
                    for node in batch {
                        node.set_error(e);
                    }
                }
            }
        }

        // Node managers run concurrently within the batch; the actor only
        // serializes between requests on the same session. Catch panics so
        // a faulty node manager faults the request instead of killing the
        // actor and with it the session.
        let fan_out = invoke_service_concurrently_mut(
            self.request_context(0),
            &mut results,
            &node_managers,
            ReadServiceCb {
                max_age,
                timestamps_to_return,
            },
            |node, node_manager| {
                node_manager.owns_node(&node.node().node_id)
                    && node.status() == StatusCode::BadNodeIdUnknown
            },
        );
        if AssertUnwindSafe(fan_out).catch_unwind().await.is_err() {
            tracing::error!("node manager panicked during actor read");
            return Err(StatusCode::BadInternalError);
        }

        Ok(results.into_iter().map(|n| n.into_result()).collect())
    }

    async fn write(
        &self,
        node_managers: NodeManagers,
        values: Vec<WriteValue>,
        return_diagnostics: DiagnosticBits,
    ) -> Result<Vec<(StatusCode, Option<DiagnosticInfo>)>, StatusCode> {
        let mut results: Vec<_> = values
            .into_iter()
            .map(|v| WriteNode::new(v, return_diagnostics))
            .collect();

        struct WriteServiceCb;

        impl ServiceCb<WriteNode> for WriteServiceCb {
            async fn call(
                &self,
                batch: &mut [&mut WriteNode],
                node_manager: &Arc<DynNodeManager>,
                context: RequestContext,
            ) {
                if let Err(e) = node_manager
                    .write(&context, batch)
                    .instrument(
                        debug_span!("SessionActorWrite", node_manager = %node_manager.name()),
                    )
                    .await
                {
                    for node in batch {
                        node.set_status(e);
                    }
                }
            }
        }

        // See `read` for concurrency and panic semantics.
        let fan_out = invoke_service_concurrently_mut(
            self.request_context(0),
            &mut results,
            &node_managers,
            WriteServiceCb,
            |node, node_manager| {
                node_manager.owns_node(&node.value().node_id)
                    && node.status() == StatusCode::BadNodeIdUnknown
            },
        );
        if AssertUnwindSafe(fan_out).catch_unwind().await.is_err() {
            tracing::error!("node manager panicked during actor write");
            return Err(StatusCode::BadInternalError);
        }

        Ok(results.into_iter().map(|n| n.into_result()).collect())
    }
}
