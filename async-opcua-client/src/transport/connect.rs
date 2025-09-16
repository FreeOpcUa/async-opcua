use std::{future::Future, sync::Arc};

use async_trait::async_trait;
use opcua_core::{comms::secure_channel::SecureChannel, sync::RwLock};
use opcua_types::{EndpointDescription, Error, StatusCode};

use super::{
    tcp::{TcpTransport, TransportConfiguration},
    OutgoingMessage, TcpConnector, TransportPollResult,
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
    ) -> Result<TcpTransport, StatusCode>;

    /// Get the default endpoint for this connector.
    fn default_endpoint(&self) -> EndpointDescription;
}

/// Trait for types that can be used to create a connector.
/// Implemented for `String`, `&str`, `&String`, and any type that implements the `Connector` trait.
pub trait ConnectorBuilder: Send + Sync {
    /// Create a new connector for the specific endpoint URL.
    fn build(self) -> Result<Box<dyn Connector + Send + Sync>, Error>;
}

impl ConnectorBuilder for String {
    fn build(self) -> Result<Box<dyn Connector + Send + Sync>, Error> {
        ConnectorBuilder::build(self.as_str())
    }
}

impl ConnectorBuilder for &str {
    fn build(self) -> Result<Box<dyn Connector + Send + Sync>, Error> {
        Ok(Box::new(TcpConnector::new(self)?))
    }
}

impl ConnectorBuilder for &String {
    fn build(self) -> Result<Box<dyn Connector + Send + Sync>, Error> {
        ConnectorBuilder::build(self.as_str())
    }
}

impl<T> ConnectorBuilder for T
where
    T: Connector + Send + Sync + 'static,
{
    fn build(self) -> Result<Box<dyn Connector + Send + Sync>, Error> {
        Ok(Box::new(self))
    }
}

impl ConnectorBuilder for Box<dyn Connector + Send + Sync> {
    fn build(self) -> Result<Box<dyn Connector + Send + Sync>, Error> {
        Ok(self)
    }
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
