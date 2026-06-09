use std::sync::Arc;

use opcua_core::sync::RwLock;
use opcua_types::{
    AttributeId, DataValue, DiagnosticBits, IntegerId, NodeId, NotificationMessage, ReadValueId,
    StatusCode, TimestampsToReturn, WriteValue,
};
use tokio::sync::oneshot;
use tracing::debug_span;
use tracing_futures::Instrument;

use crate::node_manager::{NodeManagers, ReadNode, RequestContext, RequestContextInner, WriteNode};

use super::errors::SessionError;
use super::instance::Session;

pub(crate) type ReadResponseSender = oneshot::Sender<Result<DataValue, StatusCode>>;
pub(crate) type WriteResponseSender = oneshot::Sender<StatusCode>;
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
        target: NodeId,
        attribute_id: AttributeId,
        response: ReadResponseSender,
    },
    Write {
        target: NodeId,
        attribute_id: AttributeId,
        value: DataValue,
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
                    target,
                    attribute_id,
                    response,
                } => {
                    let result = self.read(node_managers.clone(), target, attribute_id).await;
                    let _ = response.send(result);
                }
                SessionMessage::Write {
                    target,
                    attribute_id,
                    value,
                    response,
                } => {
                    let status = self
                        .write(node_managers.clone(), target, attribute_id, value)
                        .await;
                    let _ = response.send(status);
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
        RequestContext {
            current_node_manager_index,
            inner: self.context.clone(),
        }
    }

    async fn read(
        &self,
        node_managers: NodeManagers,
        target: NodeId,
        attribute_id: AttributeId,
    ) -> Result<DataValue, StatusCode> {
        let mut node = ReadNode::new(
            ReadValueId {
                node_id: target,
                attribute_id: attribute_id as IntegerId,
                ..Default::default()
            },
            DiagnosticBits::default(),
        );

        for (idx, node_manager) in node_managers.iter().enumerate() {
            if node.status() != StatusCode::BadNodeIdUnknown
                || !node_manager.owns_node(&node.node().node_id)
            {
                continue;
            }

            let context = self.request_context(idx);
            let mut batch = [&mut node];
            if let Err(status) = node_manager
                .read(&context, 0.0, TimestampsToReturn::Neither, &mut batch)
                .instrument(debug_span!("SessionActorRead", node_manager = %node_manager.name()))
                .await
            {
                batch[0].set_error(status);
            }
            break;
        }

        let status = node.status();
        if status.is_good() {
            Ok(node.result)
        } else {
            Err(status)
        }
    }

    async fn write(
        &self,
        node_managers: NodeManagers,
        target: NodeId,
        attribute_id: AttributeId,
        value: DataValue,
    ) -> StatusCode {
        let mut node = WriteNode::new(
            WriteValue {
                node_id: target,
                attribute_id: attribute_id as IntegerId,
                value,
                ..Default::default()
            },
            DiagnosticBits::default(),
        );

        for (idx, node_manager) in node_managers.iter().enumerate() {
            if node.status() != StatusCode::BadNodeIdUnknown
                || !node_manager.owns_node(&node.value().node_id)
            {
                continue;
            }

            let context = self.request_context(idx);
            let mut batch = [&mut node];
            if let Err(status) = node_manager
                .write(&context, &mut batch)
                .instrument(debug_span!("SessionActorWrite", node_manager = %node_manager.name()))
                .await
            {
                batch[0].set_status(status);
            }
            break;
        }

        node.status()
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
