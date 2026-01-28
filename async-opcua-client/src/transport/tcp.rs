use std::net::SocketAddr;
use std::sync::Arc;

use crate::transport::state::SecureChannelState;
use crate::transport::stream::{wait_for_reverse_hello, StreamConnection};
use crate::transport::{StreamConnector, StreamTransport};

use super::connect::Connector;
use super::core::OutgoingMessage;
use opcua_core::comms::url::is_opc_ua_binary_url;
use opcua_core::comms::{tcp_codec::TcpCodec, url::hostname_port_from_url};
use opcua_types::{DecodingOptions, EndpointDescription, Error, StatusCode};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::FramedRead;
use tracing::{debug, error, warn};

/// Type alias for a stream transport over TCP streams.
pub type TcpTransport = StreamTransport<ReadHalf<TcpStream>, WriteHalf<TcpStream>>;

#[derive(Debug, Clone)]
/// Internal configuration options for transports.
pub struct TransportConfiguration {
    /// Size of the send buffer in bytes. This is effectively just the
    /// maximum chunk size.
    pub send_buffer_size: usize,
    /// Size of the receive buffer in bytes.
    pub recv_buffer_size: usize,
    /// Maximum message size supported by the transport.
    pub max_message_size: usize,
    /// Maximum number of chunks in a message.
    pub max_chunk_count: usize,
}
/// Connector for `opc.tcp` transport.
pub struct TcpConnector {
    endpoint_url: String,
}

impl TcpConnector {
    /// Create a new `TcpConnector` with the given endpoint URL.
    pub fn new(endpoint_url: &str) -> Result<Self, Error> {
        if is_opc_ua_binary_url(endpoint_url) {
            Ok(Self {
                endpoint_url: endpoint_url.to_string(),
            })
        } else {
            Err(Error::new(
                StatusCode::BadInvalidArgument,
                format!("Invalid OPC-UA URL: {}", endpoint_url),
            ))
        }
    }

    async fn connect_tcp(
        endpoint_url: String,
        decoding_options: DecodingOptions,
    ) -> Result<StreamConnection<ReadHalf<TcpStream>, WriteHalf<TcpStream>>, Error> {
        let (host, port) = hostname_port_from_url(
            &endpoint_url,
            opcua_core::constants::DEFAULT_OPC_UA_SERVER_PORT,
        )
        .map_err(|e| Error::new(e, "Failed to resolve URL to hostname and port"))?;

        let addr = {
            let addr = format!("{host}:{port}");
            match tokio::net::lookup_host(addr).await {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        addr
                    } else {
                        error!(
                            "Invalid address {}, does not resolve to any socket",
                            endpoint_url
                        );
                        return Err(Error::new(
                            StatusCode::BadTcpEndpointUrlInvalid,
                            format!(
                                "Invalid address {}, does not resolve to any socket",
                                endpoint_url
                            ),
                        ));
                    }
                }
                Err(e) => {
                    error!("Invalid address {}, cannot be parsed {:?}", endpoint_url, e);
                    return Err(Error::new(
                        StatusCode::BadTcpEndpointUrlInvalid,
                        format!("Invalid address {}, cannot be parsed {:?}", endpoint_url, e),
                    ));
                }
            }
        };

        debug!("Connecting to {} with url {}", addr, endpoint_url);

        let socket = TcpStream::connect(addr).await.map_err(|err| {
            error!("Could not connect to host {}, {:?}", addr, err);
            Error::new(
                StatusCode::BadCommunicationError,
                format!("Could not connect to host {}, {:?}", addr, err),
            )
        })?;

        let (reader, writer) = tokio::io::split(socket);
        Ok(StreamConnection::new(
            FramedRead::new(reader, TcpCodec::new(decoding_options)),
            writer,
            endpoint_url,
        ))
    }
}

impl Connector for TcpConnector {
    type Transport = TcpTransport;

    async fn connect(
        &self,
        channel: Arc<SecureChannelState>,
        outgoing_recv: tokio::sync::mpsc::Receiver<OutgoingMessage>,
        config: TransportConfiguration,
    ) -> Result<TcpTransport, StatusCode> {
        let inner = StreamConnector::new(Self::connect_tcp, self.endpoint_url.clone());
        inner.connect(channel, outgoing_recv, config).await
    }

    fn default_endpoint(&self) -> opcua_types::EndpointDescription {
        opcua_types::EndpointDescription::from(self.endpoint_url.as_str())
    }
}

#[derive(Clone)]
/// Receiver for a reverse TCP connection.
pub enum TcpConnectorReceiver {
    /// Pre-established TCP listener.
    Listener(Arc<TcpListener>),
    /// Address to bind to and listen for a connection.
    Address(SocketAddr),
}

/// Trait for verifying the server URI in a ReverseHello message.
pub trait ReverseHelloVerifier {
    /// Verify that the server URI and endpoint URL are valid and accepted.
    fn verify(&self, endpoint_url: &str, server_url: &str) -> Result<(), StatusCode>;
}

impl<T> ReverseHelloVerifier for T
where
    T: for<'a> Fn(&'a str, &'a str) -> Result<(), StatusCode>,
{
    fn verify(&self, endpoint_url: &str, server_url: &str) -> Result<(), StatusCode> {
        self(endpoint_url, server_url)
    }
}

/// Connector for reverse connections over opc/tcp.
/// This connector will listen for a connection from the server and then
/// use that to connect, instead of the other way around like the normal
/// direct connector.
pub struct ReverseTcpConnector {
    listener: TcpConnectorReceiver,
    verifier: Arc<dyn ReverseHelloVerifier + Send + Sync>,
    target_endpoint: EndpointDescription,
}

impl ReverseTcpConnector {
    /// Create a new `ReverseTcpConnector` with the given listener and verifier.
    pub fn new(
        listener: TcpConnectorReceiver,
        verifier: Arc<dyn ReverseHelloVerifier + Send + Sync>,
        target_endpoint: EndpointDescription,
    ) -> Self {
        Self {
            listener,
            verifier,
            target_endpoint,
        }
    }

    /// Create a new `ReverseTcpConnector` with the given listener and verifier.
    pub fn new_listener(
        listener: tokio::net::TcpListener,
        verifier: impl ReverseHelloVerifier + Send + Sync + 'static,
        target_endpoint: EndpointDescription,
    ) -> Self {
        Self {
            listener: TcpConnectorReceiver::Listener(Arc::new(listener)),
            verifier: Arc::new(verifier),
            target_endpoint,
        }
    }

    /// Create a new `ReverseTcpConnector` with the given address and verifier.
    /// This will bind to the address and listen for a connection.
    ///
    /// The provided endpoint is the expected endpoint for the
    pub fn new_address(
        address: SocketAddr,
        verifier: impl ReverseHelloVerifier + Send + Sync + 'static,
        target_endpoint: EndpointDescription,
    ) -> Self {
        Self {
            listener: TcpConnectorReceiver::Address(address),
            verifier: Arc::new(verifier),
            target_endpoint,
        }
    }

    /// Create a new `ReverseConnectionBuilder` with a default verifier that just compares the
    /// endpoint URL with the target endpoint.
    pub fn new_default(
        target_endpoint: EndpointDescription,
        listener: TcpConnectorReceiver,
    ) -> Self {
        let ep = target_endpoint.clone();
        Self {
            verifier: Arc::new(move |endpoint_url: &str, _: &str| {
                let expected_url = ep.endpoint_url.as_ref().trim_end_matches("/");
                if expected_url == endpoint_url.trim_end_matches("/") {
                    Ok(())
                } else {
                    warn!(
                        "Rejected reverse connection to endpoint URL: {}, expected {}",
                        endpoint_url, expected_url
                    );
                    Err(StatusCode::BadTcpEndpointUrlInvalid)
                }
            }),
            target_endpoint,
            listener,
        }
    }

    async fn reverse_connect_tcp(
        listener: &TcpListener,
        verifier: &(dyn ReverseHelloVerifier + Send + Sync),
        endpoint_url: String,
        decoding_options: DecodingOptions,
    ) -> Result<StreamConnection<ReadHalf<TcpStream>, WriteHalf<TcpStream>>, Error> {
        let (stream, addr) = listener.accept().await.map_err(|err| {
            error!(
                "Could not accept connection from host {:?}, {:?}",
                endpoint_url, err
            );
            Error::new(
                StatusCode::BadCommunicationError,
                format!(
                    "Could not accept connection from host {:?}, {:?}",
                    endpoint_url, err
                ),
            )
        })?;

        debug!("Accepted connection from {} for url {}", addr, endpoint_url);

        let (reader, writer) = tokio::io::split(stream);
        let mut framed_read = FramedRead::new(reader, TcpCodec::new(decoding_options));
        // Wait for a ReverseHello message from the server
        let reverse_hello = wait_for_reverse_hello(&mut framed_read).await?;

        // Verify the server URI
        verifier
            .verify(
                reverse_hello.endpoint_url.as_ref(),
                reverse_hello.server_uri.as_ref(),
            )
            .map_err(|e| Error::new(e, "Failed to verify URIs in reverse hello message"))?;

        Ok(StreamConnection::new(
            framed_read,
            writer,
            reverse_hello.endpoint_url.to_string(),
        ))
    }
}

impl Connector for ReverseTcpConnector {
    type Transport = TcpTransport;

    async fn connect(
        &self,
        channel: Arc<SecureChannelState>,
        outgoing_recv: tokio::sync::mpsc::Receiver<OutgoingMessage>,
        config: TransportConfiguration,
    ) -> Result<TcpTransport, StatusCode> {
        match &self.listener {
            TcpConnectorReceiver::Listener(listener) => {
                let verifier = self.verifier.as_ref();
                let inner = StreamConnector::new(
                    |endpoint_url: String, decoding_options: DecodingOptions| {
                        Self::reverse_connect_tcp(
                            listener,
                            verifier,
                            endpoint_url,
                            decoding_options,
                        )
                    },
                    self.target_endpoint.endpoint_url.to_string(),
                );
                inner.connect(channel, outgoing_recv, config).await
            }
            TcpConnectorReceiver::Address(addr) => {
                let listener = TcpListener::bind(addr).await.map_err(|err| {
                    error!("Could not bind to address {}, {:?}", addr, err);
                    StatusCode::BadCommunicationError
                })?;
                let verifier = self.verifier.as_ref();
                let inner = StreamConnector::new(
                    |endpoint_url: String, decoding_options: DecodingOptions| {
                        Self::reverse_connect_tcp(
                            &listener,
                            verifier,
                            endpoint_url,
                            decoding_options,
                        )
                    },
                    self.target_endpoint.endpoint_url.to_string(),
                );
                inner.connect(channel, outgoing_recv, config).await
            }
        }
    }

    fn default_endpoint(&self) -> opcua_types::EndpointDescription {
        self.target_endpoint.clone()
    }
}
