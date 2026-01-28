use std::{future::Future, sync::Arc};

use futures::StreamExt;
use opcua_core::{
    comms::{
        buffer::SendBuffer,
        secure_channel::SecureChannel,
        tcp_codec::{Message, TcpCodec},
        tcp_types::{AcknowledgeMessage, HelloMessage, ReverseHelloMessage},
    },
    sync::RwLock,
    trace_read_lock, RequestMessage,
};
use opcua_crypto::SecurityPolicy;
use opcua_types::{DecodingOptions, Error, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_util::codec::FramedRead;
use tracing::{debug, error};

use crate::transport::{
    core::{TransportCloseState, TransportState},
    state::SecureChannelState,
    tcp::TransportConfiguration,
    Connector, OutgoingMessage, Transport, TransportPollResult,
};

/// Result of a stream connection attempt, containing the read and write streams, and the
/// actual endpoint URL used.
pub struct StreamConnection<R, W> {
    reader: FramedRead<R, TcpCodec>,
    writer: W,
    endpoint_url: String,
}

impl<R, W> StreamConnection<R, W> {
    /// Create a new `StreamConnection`.
    pub fn new(reader: FramedRead<R, TcpCodec>, writer: W, endpoint_url: String) -> Self {
        Self {
            reader,
            writer,
            endpoint_url,
        }
    }
}

/// Generic stream connector implementation.
/// This is the core of any TCP-based connector, and can be used to implement
/// custom connectors by providing a custom connection function.
///
/// The Connector function should take an endpoint URL and decoding options,
/// and return a future that resolves to a read stream, a write stream, and
/// the actual endpoint URL used. The endpoint URL may differ from the requested
/// one in some cases, like for reverse connections, or if the connection layer
/// does some manner of translation. It is used in the `Hello` message
/// produced by the connector.
///
/// To use, simply create a new `StreamConnector` with the desired
/// connection function and default endpoint URL, and use it directly as
/// a `Connector`. `C` does _not_ need to be cancellation safe.
///
/// For instance, the built-in TCP connector parses the endpoint URL,
/// creates a TCP stream, then splits it into read and write halves.
///
/// # Cancellation Safety
///
/// We rely on the cancellation safety of `StreamExt::next` on `AsyncRead`,
/// and `AsyncWriteExt::write` on `AsyncWrite`. Any custom implementation
/// must preserve this property, or risk weird behavior as incoming or outgoing
/// data is lost.
pub struct StreamConnector<R, W, C, F> {
    connector: C,
    default_endpoint_url: String,
    // fn() -> T is covariant in T, so this makes the struct
    // covariant in R, W, F.
    _f: std::marker::PhantomData<fn() -> F>,
    _r: std::marker::PhantomData<fn() -> R>,
    _w: std::marker::PhantomData<fn() -> W>,
}

impl<R, W, C, F> StreamConnector<R, W, C, F>
where
    R: AsyncRead + Unpin + Send + Sync + 'static,
    W: AsyncWrite + Unpin + Send + Sync + 'static,
    C: Fn(String, DecodingOptions) -> F + Send + Sync,
    F: Future<Output = Result<StreamConnection<R, W>, Error>> + Send + Sync,
{
    /// Create a new `StreamConnector` with the given connector function and default endpoint URL.
    pub fn new(connector: C, default_endpoint_url: String) -> Self {
        Self {
            connector,
            default_endpoint_url,
            _f: std::marker::PhantomData,
            _r: std::marker::PhantomData,
            _w: std::marker::PhantomData,
        }
    }

    async fn hello_exchange(
        reader: &mut FramedRead<R, TcpCodec>,
        writer: &mut W,
        endpoint_url: &str,
        config: &TransportConfiguration,
    ) -> Result<AcknowledgeMessage, Error> {
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
                Error::new(
                    StatusCode::BadCommunicationError,
                    format!("Cannot send hello to server, err = {}", err),
                )
            })?;
        writer.flush().await.map_err(|err| {
            Error::new(
                StatusCode::BadCommunicationError,
                format!("Cannot send hello to server, err = {}", err),
            )
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
                Err(Error::new(
                    StatusCode::BadConnectionClosed,
                    format!(
                        "Unexpected error while waiting for server ACK. Expected ACK, got {:?}",
                        other
                    ),
                ))
            }
        }
    }

    async fn connect_inner(
        &self,
        secure_channel: &RwLock<SecureChannel>,
        config: &TransportConfiguration,
    ) -> Result<(StreamConnection<R, W>, AcknowledgeMessage, SecurityPolicy), Error> {
        let (decoding_options, policy) = {
            let secure_channel = trace_read_lock!(secure_channel);
            (
                secure_channel.decoding_options(),
                secure_channel.security_policy(),
            )
        };
        let mut connection =
            (self.connector)(self.default_endpoint_url.clone(), decoding_options).await?;

        let ack = Self::hello_exchange(
            &mut connection.reader,
            &mut connection.writer,
            &connection.endpoint_url,
            config,
        )
        .await?;

        Ok((connection, ack, policy))
    }
}

impl<R, W, C, F> Connector for StreamConnector<R, W, C, F>
where
    R: AsyncRead + Unpin + Send + Sync + 'static,
    W: AsyncWrite + Unpin + Send + Sync + 'static,
    C: Fn(String, DecodingOptions) -> F + Send + Sync,
    F: Future<Output = Result<StreamConnection<R, W>, Error>> + Send + Sync,
{
    type Transport = StreamTransport<R, W>;

    async fn connect(
        &self,
        channel: Arc<SecureChannelState>,
        outgoing_recv: tokio::sync::mpsc::Receiver<OutgoingMessage>,
        config: TransportConfiguration,
    ) -> Result<StreamTransport<R, W>, StatusCode> {
        let (connection, ack, policy) = self
            .connect_inner(channel.secure_channel(), &config)
            .await
            .map_err(|e| e.status())?;
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

        Ok(StreamTransport {
            state: TransportState::new(
                channel,
                outgoing_recv,
                config.max_chunk_count,
                ack.send_buffer_size.min(config.recv_buffer_size as u32) as usize,
            ),
            read: connection.reader,
            write: connection.writer,
            send_buffer: buffer,
            should_close: false,
            closed: TransportCloseState::Open,
            connected_url: connection.endpoint_url,
        })
    }

    fn default_endpoint(&self) -> opcua_types::EndpointDescription {
        opcua_types::EndpointDescription::from(self.default_endpoint_url.as_str())
    }
}

/// Stream-based transport implementation.
/// This serves as the transport layer for OPC-UA over TCP, relying on
/// sending and receiving framed messages over a raw binary stream.
pub struct StreamTransport<R, W> {
    state: TransportState,
    read: FramedRead<R, TcpCodec>,
    write: W,
    send_buffer: SendBuffer,
    should_close: bool,
    closed: TransportCloseState,
    connected_url: String,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> StreamTransport<R, W> {
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
}

impl<R, W> Transport for StreamTransport<R, W>
where
    R: AsyncRead + Unpin + Send + Sync + 'static,
    W: AsyncWrite + Unpin + Send + Sync + 'static,
{
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

    fn connected_url(&self) -> &str {
        &self.connected_url
    }
}

/// Wait for a ReverseHello message from the given stream.
pub async fn wait_for_reverse_hello<R: AsyncRead + Unpin>(
    framed_read: &mut FramedRead<R, TcpCodec>,
) -> Result<ReverseHelloMessage, Error> {
    match framed_read.next().await {
        Some(Ok(Message::ReverseHello(rev_hello))) => {
            tracing::trace!("Received ReverseHello message: {:?}", rev_hello);
            Ok(rev_hello)
        }
        Some(Ok(_)) => Err(Error::new(
            StatusCode::BadConnectionClosed,
            "Unexpected message while waiting for ReverseHello",
        )),
        Some(Err(err)) => Err(Error::new(
            StatusCode::BadConnectionClosed,
            format!("Error while waiting for ReverseHello: {}", err),
        )),
        None => Err(Error::new(
            StatusCode::BadConnectionClosed,
            "Connection closed while waiting for ReverseHello",
        )),
    }
}
