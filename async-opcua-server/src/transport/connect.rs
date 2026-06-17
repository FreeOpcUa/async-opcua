use std::{future::Future, sync::Arc};

use opcua_types::StatusCode;
use tokio_util::sync::CancellationToken;

use crate::info::ServerInfo;

use super::tcp::ConnectionTransport;

pub(crate) trait Connector {
    type Transport: ConnectionTransport;

    fn connect(
        self,
        info: Arc<ServerInfo>,
        token: CancellationToken,
    ) -> impl Future<Output = Result<Self::Transport, StatusCode>> + Send + Sync;
}
