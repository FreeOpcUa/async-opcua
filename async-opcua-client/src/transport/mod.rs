//! Types for low-level OPC-UA transport implementations.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod channel;
mod connect;
mod core;
mod state;
mod stream;
pub(super) mod tcp;
#[cfg(feature = "wss")]
pub(super) mod websocket;

pub use channel::{AsyncSecureChannel, SecureChannelEventLoop};
pub use connect::{
    Connector, ConnectorBuilder, DefaultConnector, DefaultConnectorBuilder, DefaultTransport,
    Transport,
};
pub use core::{OutgoingMessage, TransportPollResult, TransportState};
pub use state::{RequestRecv, RequestSend, SecureChannelState};
pub use stream::{wait_for_reverse_hello, StreamConnection, StreamConnector, StreamTransport};
pub use tcp::{
    ReverseHelloVerifier, ReverseTcpConnector, TcpConnector, TcpTransport, TransportConfiguration,
};
#[cfg(feature = "wss")]
pub use websocket::{WebSocketConnector, WebSocketTransport};
