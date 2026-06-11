use std::sync::Arc;

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

pub(crate) type ReadResponseSender = oneshot::Sender<(DataValue, Option<DiagnosticInfo>)>;
pub(crate) type WriteResponseSender = oneshot::Sender<(StatusCode, Option<DiagnosticInfo>)>;
pub(crate) type PublishResponseSender = oneshot::Sender<Result<NotificationMessage, StatusCode>>;
pub(crate) type TerminateAckSender = oneshot::Sender<TerminatedSession>;
pub(crate) type TerminationCleanup = Arc<dyn Fn(&TerminatedSession) + Send + Sync>;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct TerminatedSession {
    pub(crate) session_id: NodeId,
    pub(crate) authentication_token: NodeId,
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum SessionMessage {
    Read {
        node: ReadValueId,
        max_age: f64,
        timestamps_to_return: TimestampsToReturn,
        return_diagnostics: DiagnosticBits,
        response: ReadResponseSender,
    },
    Write {
        value: WriteValue,
        return_diagnostics: DiagnosticBits,
        response: WriteResponseSender,
    },
    Publish {
        subscription_id: IntegerId,
        response: PublishResponseSender,
    },
    Terminate {
        reason: StatusCode,
        acknowledge: TerminateAckSender,
    },
}

#[allow(dead_code)]
pub(crate) struct SessionActor {
    session: Arc<RwLock<Session>>,
    context: Arc<RequestContextInner>,
    receiver: tokio::sync::mpsc::Receiver<SessionMessage>,
    termination_cleanup: Option<TerminationCleanup>,
}

#[allow(dead_code)]
impl SessionActor {
    pub(crate) fn new(
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

    pub(crate) fn with_termination_cleanup(
        mut self,
        cleanup: impl Fn(&TerminatedSession) + Send + Sync + 'static,
    ) -> Self {
        self.termination_cleanup = Some(Arc::new(cleanup));
        self
    }

    pub(crate) async fn run(&mut self, node_managers: NodeManagers) -> Result<(), SessionError> {
        while let Some(message) = self.receiver.recv().await {
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
                }
                SessionMessage::Publish {
                    subscription_id,
                    response,
                } => {
                    let result = self.publish(subscription_id);
                    let _ = response.send(result);
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
                    return Ok(());
                }
            }
        }

        let cleanup = self.close_session();
        self.run_termination_cleanup(&cleanup);
        tracing::debug!(?cleanup, "session actor channel closed");
        Err(SessionError::ChannelClosed)
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
    ) -> (DataValue, Option<DiagnosticInfo>) {
        let mut node = ReadNode::new(node, return_diagnostics);

        if node.status() == StatusCode::BadNodeIdUnknown {
            for (idx, node_manager) in node_managers.iter().enumerate() {
                if !node_manager.owns_node(&node.node().node_id) {
                    continue;
                }

                let context = self.request_context(idx);
                let mut batch = [&mut node];
                if let Err(status) = node_manager
                    .read(&context, max_age, timestamps_to_return, &mut batch)
                    .instrument(
                        debug_span!("SessionActorRead", node_manager = %node_manager.name()),
                    )
                    .await
                {
                    batch[0].set_error(status);
                }
                break;
            }
        }

        node.into_result()
    }

    async fn write(
        &self,
        node_managers: NodeManagers,
        value: WriteValue,
        return_diagnostics: DiagnosticBits,
    ) -> (StatusCode, Option<DiagnosticInfo>) {
        let mut node = WriteNode::new(value, return_diagnostics);

        if node.status() == StatusCode::BadNodeIdUnknown {
            for (idx, node_manager) in node_managers.iter().enumerate() {
                if !node_manager.owns_node(&node.value().node_id) {
                    continue;
                }

                let context = self.request_context(idx);
                let mut batch = [&mut node];
                if let Err(status) = node_manager
                    .write(&context, &mut batch)
                    .instrument(
                        debug_span!("SessionActorWrite", node_manager = %node_manager.name()),
                    )
                    .await
                {
                    batch[0].set_status(status);
                }
                break;
            }
        }

        node.into_result()
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
