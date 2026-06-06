use std::{future::Future, sync::Arc};

use opcua_types::StatusCode;
use tokio_util::sync::CancellationToken;

use crate::info::ServerInfo;

use super::tcp::TcpTransport;

pub(crate) trait Connector {
    fn connect(
        self,
        info: Arc<ServerInfo>,
        token: CancellationToken,
    ) -> impl Future<Output = Result<TcpTransport, StatusCode>> + Send + Sync;
}
