use opcua_types::{AttributeId, DataValue, IntegerId, NodeId, NotificationMessage, StatusCode};
use tokio::sync::oneshot;

use super::instance::Session;

pub(crate) type ReadResponseSender = oneshot::Sender<Result<DataValue, StatusCode>>;
pub(crate) type WriteResponseSender = oneshot::Sender<StatusCode>;
pub(crate) type PublishResponseSender = oneshot::Sender<Result<NotificationMessage, StatusCode>>;
pub(crate) type TerminateAckSender = oneshot::Sender<()>;

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

pub(crate) struct SessionActor {
    session: Session,
    receiver: tokio::sync::mpsc::Receiver<SessionMessage>,
}

impl SessionActor {
    pub(crate) fn new(
        session: Session,
        receiver: tokio::sync::mpsc::Receiver<SessionMessage>,
    ) -> Self {
        Self { session, receiver }
    }
}
