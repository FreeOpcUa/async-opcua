use std::{future::Future, sync::Arc};

use async_trait::async_trait;
use opcua_core::{comms::secure_channel::SecureChannel, sync::RwLock};
use opcua_types::StatusCode;

use super::{
    tcp::{TcpTransport, TransportConfiguration},
    OutgoingMessage, TransportPollResult,
};

#[async_trait]
/// Trait implemented by simple wrapper types that create a connection to an OPC-UA server.
///
/// Notes for implementors:
///
///  - This deals with connection establishment up to after exchange of HELLO/ACKNOWLEDGE
///    or equivalent.
///  - This should not do any retries, that's handled on a higher level.
pub trait Connector: Send + Sync {
    /// Attempt to establish a connection to the OPC UA endpoint given by `endpoint_url`.
    /// Note that on success, this returns a `TcpTransport`. The caller is responsible for
    /// calling `run` on the returned transport in order to actually send and receive messages.
    async fn connect(
        &self,
        channel: Arc<RwLock<SecureChannel>>,
        outgoing_recv: tokio::sync::mpsc::Receiver<OutgoingMessage>,
        config: TransportConfiguration,
        endpoint_url: &str,
    ) -> Result<TcpTransport, StatusCode>;
}

/// Trait for client transport channels.
///
/// Note for implementors:
///
/// The [`Transport::poll`] method is potentially challenging to implement, notably it _must_
/// be cancellation safe, meaning that it cannot keep an internal state.
///
/// Most futures that needs to cross more than _one_ await-point are not cancel safe. The easiest
/// way to ensure cancel safety is to check the following conditions:
///
///  - Is only a single future awaited in a call to `poll`? Different calls can await different futures,
///    but each call can only await one.
///  - Is that future cancel safe? This is sometimes documented in libraries.
///
/// If making the future cancel safe is impossible, you can create a structure that contains a
/// `Box<dyn Future>`, and await that. The outer future will be cancellation safe, since
/// any internal state is stored within the boxed future.
///
/// Streams are also cancellation safe, a pattern frequently used in this library.
pub trait Transport: Send + Sync + 'static {
    /// Poll the transport, processing any pending incoming or outgoing messages and returning the
    /// action that was taken.
    /// Note that this method _must_ be cancellation safe.
    fn poll(&mut self) -> impl Future<Output = TransportPollResult> + Send + Sync;
}
