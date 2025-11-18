use std::net::SocketAddr;
use std::sync::Arc;

use crate::transport::state::SecureChannelState;

use super::connect::{Connector, Transport};
use super::core::{OutgoingMessage, TransportPollResult, TransportState};
use async_trait::async_trait;
use futures::StreamExt;
use opcua_core::comms::tcp_types::AcknowledgeMessage;
use opcua_core::comms::url::is_opc_ua_binary_url;
use opcua_core::RequestMessage;
use opcua_core::{
    comms::{
        buffer::SendBuffer,
        secure_channel::SecureChannel,
        tcp_codec::{Message, TcpCodec},
        tcp_types::HelloMessage,
        url::hostname_port_from_url,
    },
    trace_read_lock,
};
use opcua_crypto::SecurityPolicy;
use opcua_types::{EndpointDescription, Error, StatusCode};
use parking_lot::RwLock;
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::FramedRead;
use tracing::{debug, error, warn};

#[derive(Debug, Clone, Copy)]
enum TransportCloseState {
    Open,
    Closing(StatusCode),
    Closed(StatusCode),
}

pub struct TcpTransport {
    state: TransportState,
    read: FramedRead<ReadHalf<TcpStream>, TcpCodec>,
    write: WriteHalf<TcpStream>,
    send_buffer: SendBuffer,
    should_close: bool,
    closed: TransportCloseState,
    connected_url: String,
}

#[derive(Debug, Clone)]
pub struct TransportConfiguration {
    pub send_buffer_size: usize,
    pub recv_buffer_size: usize,
    pub max_message_size: usize,
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

    async fn hello_exchange(
        reader: &mut FramedRead<ReadHalf<TcpStream>, TcpCodec>,
        writer: &mut WriteHalf<TcpStream>,
        endpoint_url: &str,
        config: &TransportConfiguration,
    ) -> Result<AcknowledgeMessage, StatusCode> {
        let hello = HelloMessage::new(
            endpoint_url,
            config.send_buffer_size,
            config.recv_buffer_size,
            config.max_message_size,
            config.max_chunk_count,
        );
        tracing::trace!("Send hello message: {hello:?}");

        writer
            .write_all(&opcua_types::SimpleBinaryEncodable::encode_to_vec(&hello))
            .await
            .map_err(|err| {
                error!("Cannot send hello to server, err = {}", err);
                StatusCode::BadCommunicationError
            })?;
        match reader.next().await {
            Some(Ok(Message::Acknowledge(ack))) => {
                if ack.send_buffer_size > hello.receive_buffer_size {
                    tracing::warn!("Acknowledged send buffer size is greater than receive buffer size in hello message!")
                }
                if ack.receive_buffer_size > hello.send_buffer_size {
                    tracing::warn!("Acknowledged receive buffer size is greater than send buffer size in hello message!")
                }
                tracing::trace!("Received acknowledgement: {:?}", ack);
                Ok(ack)
            }
            other => {
                error!(
                    "Unexpected error while waiting for server ACK. Expected ACK, got {:?}",
                    other
                );
                Err(StatusCode::BadConnectionClosed)
            }
        }
    }

    async fn connect_inner(
        secure_channel: &RwLock<SecureChannel>,
        config: &TransportConfiguration,
        endpoint_url: &str,
    ) -> Result<
        (
            FramedRead<ReadHalf<TcpStream>, TcpCodec>,
            WriteHalf<TcpStream>,
            AcknowledgeMessage,
            SecurityPolicy,
        ),
        StatusCode,
    > {
        let (host, port) = hostname_port_from_url(
            endpoint_url,
            opcua_core::constants::DEFAULT_OPC_UA_SERVER_PORT,
        )?;

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
                        return Err(StatusCode::BadTcpEndpointUrlInvalid);
                    }
                }
                Err(e) => {
                    error!("Invalid address {}, cannot be parsed {:?}", endpoint_url, e);
                    return Err(StatusCode::BadTcpEndpointUrlInvalid);
                }
            }
        };

        debug!("Connecting to {} with url {}", addr, endpoint_url);

        let socket = TcpStream::connect(&addr).await.map_err(|err| {
            error!("Could not connect to host {}, {:?}", addr, err);
            StatusCode::BadCommunicationError
        })?;

        let (reader, mut writer) = tokio::io::split(socket);

        let (mut framed_read, policy) = {
            let secure_channel = trace_read_lock!(secure_channel);
            (
                FramedRead::new(reader, TcpCodec::new(secure_channel.decoding_options())),
                secure_channel.security_policy(),
            )
        };

        let ack = Self::hello_exchange(&mut framed_read, &mut writer, endpoint_url, config).await?;

        Ok((framed_read, writer, ack, policy))
    }
}

#[async_trait]
impl Connector for TcpConnector {
    async fn connect(
        &self,
        channel: Arc<SecureChannelState>,
        outgoing_recv: tokio::sync::mpsc::Receiver<OutgoingMessage>,
        config: TransportConfiguration,
    ) -> Result<TcpTransport, StatusCode> {
        let (framed_read, writer, ack, policy) = match Self::connect_inner(
            channel.secure_channel(),
            &config,
            &self.endpoint_url,
        )
        .await
        {
            Ok(k) => k,
            Err(status) => return Err(status),
        };
        let mut buffer = SendBuffer::new(
            config.send_buffer_size,
            config.max_message_size,
            config.max_chunk_count,
            policy.legacy_sequence_numbers(),
        );
        buffer.revise(
            ack.receive_buffer_size as usize,
            ack.max_message_size as usize,
            ack.max_chunk_count as usize,
        );

        Ok(TcpTransport {
            state: TransportState::new(
                channel,
                outgoing_recv,
                config.max_chunk_count,
                ack.send_buffer_size.min(config.recv_buffer_size as u32) as usize,
            ),
            read: framed_read,
            write: writer,
            send_buffer: buffer,
            should_close: false,
            closed: TransportCloseState::Open,
            connected_url: self.endpoint_url.to_string(),
        })
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

    async fn connect_inner(
        &self,
        listener: &TcpListener,
        secure_channel: &RwLock<SecureChannel>,
        config: &TransportConfiguration,
    ) -> Result<
        (
            FramedRead<ReadHalf<TcpStream>, TcpCodec>,
            WriteHalf<TcpStream>,
            AcknowledgeMessage,
            SecurityPolicy,
            String,
        ),
        StatusCode,
    > {
        let stream = listener.accept().await.map_err(|err| {
            error!("Could not accept connection from host {:?}", err);
            StatusCode::BadCommunicationError
        })?;

        debug!("Accepted connection from {}", stream.1);

        let (reader, mut writer) = tokio::io::split(stream.0);

        let (mut framed_read, policy) = {
            let secure_channel = trace_read_lock!(secure_channel);
            (
                FramedRead::new(reader, TcpCodec::new(secure_channel.decoding_options())),
                secure_channel.security_policy(),
            )
        };

        // Wait for a ReverseHello message from the server
        let reverse_hello = match framed_read.next().await {
            Some(Ok(Message::ReverseHello(rev_hello))) => {
                tracing::trace!("Received ReverseHello message: {:?}", rev_hello);
                rev_hello
            }
            Some(Ok(_)) => {
                error!("Unexpected message while waiting for ReverseHello");
                return Err(StatusCode::BadConnectionClosed);
            }
            Some(Err(err)) => {
                error!("Error while waiting for ReverseHello: {}", err);
                return Err(StatusCode::BadConnectionClosed);
            }
            None => {
                error!("Connection closed while waiting for ReverseHello");
                return Err(StatusCode::BadConnectionClosed);
            }
        };

        // Verify the server URI
        self.verifier.verify(
            reverse_hello.endpoint_url.as_ref(),
            reverse_hello.server_uri.as_ref(),
        )?;

        // Perform normal hello exchange
        let ack = TcpConnector::hello_exchange(
            &mut framed_read,
            &mut writer,
            reverse_hello.endpoint_url.as_ref(),
            config,
        )
        .await?;

        Ok((
            framed_read,
            writer,
            ack,
            policy,
            reverse_hello.endpoint_url.to_string(),
        ))
    }
}

#[async_trait]
impl Connector for ReverseTcpConnector {
    async fn connect(
        &self,
        channel: Arc<SecureChannelState>,
        outgoing_recv: tokio::sync::mpsc::Receiver<OutgoingMessage>,
        config: TransportConfiguration,
    ) -> Result<TcpTransport, StatusCode> {
        let (framed_read, writer, ack, policy, endpoint_url) = match &self.listener {
            TcpConnectorReceiver::Listener(listener) => {
                self.connect_inner(listener, channel.secure_channel(), &config)
                    .await?
            }
            TcpConnectorReceiver::Address(addr) => {
                let listener = TcpListener::bind(addr).await.map_err(|err| {
                    error!("Could not bind to address {}, {:?}", addr, err);
                    StatusCode::BadCommunicationError
                })?;
                self.connect_inner(&listener, channel.secure_channel(), &config)
                    .await?
            }
        };

        let mut buffer = SendBuffer::new(
            config.send_buffer_size,
            config.max_message_size,
            config.max_chunk_count,
            policy.legacy_sequence_numbers(),
        );
        buffer.revise(
            ack.receive_buffer_size as usize,
            ack.max_message_size as usize,
            ack.max_chunk_count as usize,
        );

        Ok(TcpTransport {
            state: TransportState::new(
                channel,
                outgoing_recv,
                config.max_chunk_count,
                ack.send_buffer_size.min(config.recv_buffer_size as u32) as usize,
            ),
            read: framed_read,
            write: writer,
            send_buffer: buffer,
            should_close: false,
            closed: TransportCloseState::Open,
            connected_url: endpoint_url,
        })
    }

    fn default_endpoint(&self) -> opcua_types::EndpointDescription {
        self.target_endpoint.clone()
    }
}

impl TcpTransport {
    fn handle_incoming_message(
        &mut self,
        incoming: Option<Result<Message, std::io::Error>>,
    ) -> TransportPollResult {
        let Some(incoming) = incoming else {
            return TransportPollResult::Closed(StatusCode::BadCommunicationError);
        };
        match incoming {
            Ok(message) => {
                if let Err(e) = self.state.handle_incoming_message(message) {
                    TransportPollResult::Closed(e)
                } else {
                    TransportPollResult::IncomingMessage
                }
            }
            Err(err) => {
                error!("Error reading from stream {}", err);
                TransportPollResult::Closed(StatusCode::BadConnectionClosed)
            }
        }
    }

    async fn poll_inner(&mut self) -> TransportPollResult {
        // Either we've got something in the send buffer, which we can send,
        // or we're waiting for more outgoing messages.
        // We won't wait for outgoing messages while sending, since that
        // could cause the send buffer to fill up.

        // If there's nothing in the send buffer, but there are chunks available,
        // write them to the send buffer before proceeding.
        if self.send_buffer.should_encode_chunks() {
            let secure_channel = trace_read_lock!(self.state.channel_state.secure_channel());
            if let Err(e) = self.send_buffer.encode_next_chunk(&secure_channel) {
                return TransportPollResult::Closed(e);
            }
        }

        // If there is something in the send buffer, write to the stream.
        // If not, wait for outgoing messages.
        // Either way, listen to incoming messages while we do this.
        if self.send_buffer.can_read() {
            tokio::select! {
                r = self.send_buffer.read_into_async(&mut self.write) => {
                    if let Err(e) = r {
                        error!("write bytes task failed: {}", e);
                        return TransportPollResult::Closed(StatusCode::BadCommunicationError);
                    }
                    TransportPollResult::OutgoingMessageSent
                }
                incoming = self.read.next() => {
                    self.handle_incoming_message(incoming)
                }
            }
        } else {
            if self.should_close {
                debug!("Writer is setting the connection state to finished(good)");
                return TransportPollResult::Closed(StatusCode::Good);
            }
            tokio::select! {
                outgoing = self.state.wait_for_outgoing_message(&mut self.send_buffer) => {
                    let Some((outgoing, request_id)) = outgoing else {
                        return TransportPollResult::Closed(StatusCode::Good);
                    };
                    let close_connection =
                        matches!(outgoing, RequestMessage::CloseSecureChannel(_));
                    if close_connection {
                        self.should_close = true;
                        debug!("Writer is about to send a CloseSecureChannelRequest which means it should close in a moment");
                    }
                    let secure_channel = trace_read_lock!(self.state.channel_state.secure_channel());
                    if let Err(e) = self.send_buffer.write(request_id, outgoing, &secure_channel) {
                        drop(secure_channel);
                        if let Some((request_id, request_handle)) = e.full_context() {
                            error!("Failed to send message with request handle {}: {}", request_handle, e);
                            self.state.message_send_failed(request_id, e.status());
                            TransportPollResult::RecoverableError(e.status())
                        } else {
                            TransportPollResult::Closed(e.status())
                        }
                    } else {
                        TransportPollResult::OutgoingMessage
                    }
                }
                incoming = self.read.next() => {
                    self.handle_incoming_message(incoming)
                }
            }
        }
    }

    pub fn connected_url(&self) -> &str {
        &self.connected_url
    }
}

impl Transport for TcpTransport {
    async fn poll(&mut self) -> TransportPollResult {
        // We want poll to be cancel safe, this means that if we stop polling
        // a future returned from poll, we do not lose data or get in an
        // inconsistent state.
        // `poll_inner` is cancel safe, because all the async methods it
        // calls are cancel safe, and it only ever finishes one future.
        // The only thing that isn't cancel safe is when we close the channel.
        // `close` can be called multiple times, and will continue where it left off,
        // so all we have to do is keep calling close until we manage to complete it,
        // and _then_ we can set the state to `closed`.
        match self.closed {
            TransportCloseState::Open => {}
            TransportCloseState::Closing(c) => {
                // Close is kind-of cancel safe, in that
                // calling it multiple times is safe.
                let r = self.state.close(c).await;
                self.closed = TransportCloseState::Closed(c);
                return TransportPollResult::Closed(r);
            }
            TransportCloseState::Closed(c) => {
                return TransportPollResult::Closed(c);
            }
        }

        let r = self.poll_inner().await;
        if let TransportPollResult::Closed(status) = &r {
            self.closed = TransportCloseState::Closing(*status);
            let r = self.state.close(*status).await;
            self.closed = TransportCloseState::Closed(r);
        }
        r
    }
}
