use std::{
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};

use opcua_core::{
    comms::{
        buffer::SendBuffer,
        chunker::Chunker,
        message_chunk::{MessageChunk, MessageIsFinalType},
        message_chunk_info::ChunkInfo,
        secure_channel::SecureChannel,
        sequence_number::SequenceNumberHandle,
        tcp_codec::{Message, TcpCodec},
        tcp_types::{AcknowledgeMessage, ErrorMessage, MIN_CHUNK_SIZE},
    },
    RequestMessage, ResponseMessage,
};
use tracing::error;
use tracing_futures::Instrument;

use crate::info::ServerInfo;
use opcua_types::{DecodingOptions, Error, ResponseHeader, ServiceFault, StatusCode};

use futures::StreamExt;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf},
    net::TcpStream,
};
use tokio_util::{codec::FramedRead, sync::CancellationToken};

use super::connect::Connector;
use crate::config::TcpKeepaliveConfig;

pub(crate) trait ConnectionTransport: Send + 'static {
    fn set_closing(&mut self);
    fn is_closing(&self) -> bool;
    fn enqueue_error(&mut self, message: ErrorMessage);
    fn enqueue_message_for_send(
        &mut self,
        channel: &mut SecureChannel,
        message: ResponseMessage,
        request_id: u32,
    ) -> Result<(), StatusCode>;
    fn client_protocol_version(&self) -> u32;
    fn poll<'a>(
        &'a mut self,
        channel: &'a mut SecureChannel,
    ) -> impl Future<Output = TransportPollResult> + Send + 'a;
}

/// Transport implementation for byte streams carrying OPC UA TCP frames.
pub(crate) struct Transport<R, W> {
    read: FramedRead<R, TcpCodec>,
    write: W,
    send_buffer: SendBuffer,
    state: TransportState,
    pending_chunks: Vec<MessageChunk>,
    /// Client protocol version set during HELLO
    pub(crate) client_protocol_version: u32,
    /// Last decoded sequence number
    sequence_numbers: SequenceNumberHandle,
}

/// Transport implementation for opc.tcp.
pub(crate) type TcpTransport = Transport<ReadHalf<TcpStream>, WriteHalf<TcpStream>>;

enum TransportState {
    Running,
    Closing,
}

#[derive(Debug, Clone)]
pub(crate) struct TransportConfig {
    pub send_buffer_size: usize,
    pub receive_buffer_size: usize,
    pub max_message_size: usize,
    pub max_chunk_count: usize,
    pub hello_timeout: Duration,
    pub tcp_keepalive: TcpKeepaliveConfig,
}

#[derive(Debug)]
pub(crate) struct Request {
    pub message: RequestMessage,
    pub chunk_info: ChunkInfo,
    pub request_id: u32,
}

#[derive(Debug)]
/// Result of polling a TCP transport.
pub(crate) enum TransportPollResult {
    OutgoingMessageSent,
    IncomingChunk,
    IncomingMessage(Request),
    Error(StatusCode),
    RecoverableError(StatusCode, u32, u32),
    Closed,
}

fn min_zero_infinite(server: u32, client: u32) -> u32 {
    if client == 0 {
        server
    } else if server == 0 {
        client
    } else {
        client.min(server)
    }
}

fn effective_max_chunk_count(max_chunk_count: usize, max_message_size: usize) -> usize {
    if max_chunk_count > 0 {
        max_chunk_count
    } else if max_message_size > 0 {
        (max_message_size / MIN_CHUNK_SIZE).max(1)
    } else {
        usize::MAX
    }
}

pub(crate) struct TcpConnector<R = ReadHalf<TcpStream>, W = WriteHalf<TcpStream>> {
    read: FramedRead<R, TcpCodec>,
    write: W,
    deadline: Instant,
    config: TransportConfig,
    decoding_options: DecodingOptions,
}

impl TcpConnector<ReadHalf<TcpStream>, WriteHalf<TcpStream>> {
    pub(crate) fn new(
        stream: TcpStream,
        config: TransportConfig,
        decoding_options: DecodingOptions,
    ) -> Self {
        let (read, write) = tokio::io::split(stream);
        let read = FramedRead::new(read, TcpCodec::new(decoding_options.clone()));
        TcpConnector {
            read,
            write,
            deadline: Instant::now() + config.hello_timeout,
            config,
            decoding_options,
        }
    }
}

impl<R, W> TcpConnector<R, W>
where
    R: AsyncRead + Unpin + Send + Sync + 'static,
    W: AsyncWrite + Unpin + Send + Sync + 'static,
{
    pub(crate) fn new_split(
        read: FramedRead<R, TcpCodec>,
        write: W,
        config: TransportConfig,
        decoding_options: DecodingOptions,
    ) -> Self {
        TcpConnector {
            read,
            write,
            deadline: Instant::now() + config.hello_timeout,
            config,
            decoding_options,
        }
    }

    async fn connect_inner(&mut self, info: Arc<ServerInfo>) -> Result<SendBuffer, ErrorMessage> {
        let hello = match self.read.next().await {
            Some(Ok(Message::Hello(hello))) => Ok(hello),
            Some(Ok(bad_msg)) => Err(ErrorMessage::new(
                StatusCode::BadCommunicationError,
                &format!("Expected a hello message, got {bad_msg:?} instead"),
            )),
            Some(Err(communication_err)) => Err(ErrorMessage::new(
                StatusCode::BadCommunicationError,
                &format!(
                    "Communication error while waiting for Hello message: {communication_err}"
                ),
            )),
            None => Err(ErrorMessage::new(
                StatusCode::BadCommunicationError,
                "Stream closed",
            )),
        }?;

        let mut buffer = SendBuffer::new(
            self.config.send_buffer_size,
            self.config.max_message_size,
            self.config.max_chunk_count,
            true,
        );

        let endpoints = info.endpoints(&hello.endpoint_url, &None);

        if !endpoints.is_some_and(|e| hello.is_endpoint_url_valid(&e)) {
            return Err(ErrorMessage::new(
                StatusCode::BadTcpEndpointUrlInvalid,
                "HELLO endpoint url is invalid",
            ));
        }
        if !hello.is_valid_buffer_sizes() {
            return Err(ErrorMessage::new(
                StatusCode::BadCommunicationError,
                "HELLO buffer sizes are invalid",
            ));
        }

        let server_protocol_version = 0;
        // Validate protocol version
        if hello.protocol_version > server_protocol_version {
            return Err(ErrorMessage::new(
                StatusCode::BadProtocolVersionUnsupported,
                "Client protocol version is unsupported.",
            ));
        }

        let decoding_options = &self.decoding_options;

        // Send acknowledge
        let acknowledge = AcknowledgeMessage::new(
            server_protocol_version,
            (self.config.receive_buffer_size as u32).min(hello.send_buffer_size),
            (buffer.send_buffer_size as u32).min(hello.receive_buffer_size),
            min_zero_infinite(
                decoding_options.max_message_size as u32,
                hello.max_message_size,
            ),
            min_zero_infinite(
                decoding_options.max_chunk_count as u32,
                hello.max_chunk_count,
            ),
        );
        buffer.revise(
            acknowledge.send_buffer_size as usize,
            acknowledge.max_message_size as usize,
            acknowledge.max_chunk_count as usize,
        );

        let mut buf =
            Vec::with_capacity(opcua_types::SimpleBinaryEncodable::byte_len(&acknowledge));
        opcua_types::SimpleBinaryEncodable::encode(&acknowledge, &mut buf)
            .map_err(|e| ErrorMessage::new(e.into(), "Failed to encode ack"))?;

        TcpCodec::write_all_frame_vectored(&mut self.write, &buf)
            .await
            .map_err(|e| {
                ErrorMessage::new(
                    StatusCode::BadCommunicationError,
                    &format!("Failed to send ack: {e}"),
                )
            })?;

        Ok(buffer)
    }
}

impl<R, W> Connector for TcpConnector<R, W>
where
    R: AsyncRead + Unpin + Send + Sync + 'static,
    W: AsyncWrite + Unpin + Send + Sync + 'static,
{
    type Transport = Transport<R, W>;

    async fn connect(
        mut self,
        info: Arc<ServerInfo>,
        token: CancellationToken,
    ) -> Result<Self::Transport, StatusCode> {
        let err = tokio::select! {
            _ = tokio::time::sleep_until(self.deadline.into()) => {
                ErrorMessage::new(StatusCode::BadTimeout, "Timeout waiting for HELLO")
            }
            _ = token.cancelled() => {
                ErrorMessage::new(StatusCode::BadServerHalted, "Server closed")
            }
            r = self.connect_inner(info).instrument(tracing::info_span!("OPC-UA TCP handshake")) => {
                match r {
                    Ok(r) => return Ok(Transport::new(self.read, self.write, r)),
                    Err(e) => e,
                }
            }
        };

        // We want to send an error if connection failed for whatever reason, but
        // there's a good chance the channel is closed, so just ignore any errors.
        let mut buf = Vec::with_capacity(opcua_types::SimpleBinaryEncodable::byte_len(&err));
        if opcua_types::SimpleBinaryEncodable::encode(&err, &mut buf).is_ok() {
            let _ = TcpCodec::write_all_frame_vectored(&mut self.write, &buf).await;
        }

        Err(err.error)
    }
}

impl<R, W> Transport<R, W>
where
    R: AsyncRead + Unpin + Send + Sync + 'static,
    W: AsyncWrite + Unpin + Send + Sync + 'static,
{
    fn new(read: FramedRead<R, TcpCodec>, write: W, send_buffer: SendBuffer) -> Self {
        Self {
            read,
            write,
            state: TransportState::Running,
            pending_chunks: Vec::new(),
            sequence_numbers: SequenceNumberHandle::new(true),
            client_protocol_version: 0,
            send_buffer,
        }
    }

    fn set_closing_inner(&mut self) {
        self.state = TransportState::Closing;
    }

    fn is_closing_inner(&self) -> bool {
        matches!(self.state, TransportState::Closing)
    }

    fn enqueue_error_inner(&mut self, message: ErrorMessage) {
        self.send_buffer.write_error(message);
    }

    fn enqueue_message_for_send_inner(
        &mut self,
        channel: &mut SecureChannel,
        message: ResponseMessage,
        request_id: u32,
    ) -> Result<(), StatusCode> {
        match self.send_buffer.write(request_id, message, channel) {
            Ok(_) => Ok(()),
            Err(e) => {
                tracing::warn!("Failed to encode outgoing message: {e:?}");
                if let Some((request_id, request_handle)) = e.full_context() {
                    self.send_buffer.write(
                        request_id,
                        ResponseMessage::ServiceFault(Box::new(ServiceFault {
                            response_header: ResponseHeader::new_service_result(
                                request_handle,
                                e.into(),
                            ),
                        })),
                        channel,
                    )?;
                    Ok(())
                } else {
                    Err(e.into())
                }
            }
        }
    }

    async fn poll_inner(&mut self, channel: &mut SecureChannel) -> TransportPollResult {
        // Either we've got something in the send buffer, which we can send,
        // or we're waiting for more outgoing messages.
        // We won't wait for outgoing messages while sending, since that
        // could cause the send buffer to fill up.

        // If there's nothing in the send buffer, but there are chunks available,
        // write them to the send buffer before proceeding.
        if self.send_buffer.should_encode_chunks() {
            if let Err(e) = self.send_buffer.encode_next_chunk(channel) {
                return TransportPollResult::Error(e);
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
                        return TransportPollResult::Closed;
                    }
                    TransportPollResult::OutgoingMessageSent
                }
                incoming = self.read.next() => {
                    self.handle_incoming_message(incoming, channel)
                }
            }
        } else {
            if self.is_closing_inner() {
                return TransportPollResult::Closed;
            }
            let incoming = self.read.next().await;
            self.handle_incoming_message(incoming, channel)
        }
    }

    fn handle_incoming_message(
        &mut self,
        incoming: Option<Result<Message, std::io::Error>>,
        channel: &mut SecureChannel,
    ) -> TransportPollResult {
        let Some(incoming) = incoming else {
            return TransportPollResult::Closed;
        };
        match incoming {
            Ok(message) => match self.process_message(message, channel) {
                Ok(None) => TransportPollResult::IncomingChunk,
                Ok(Some(message)) => {
                    self.pending_chunks.clear();
                    TransportPollResult::IncomingMessage(message)
                }
                Err(e) => {
                    self.pending_chunks.clear();
                    if let Some((id, handle)) = e.full_context() {
                        TransportPollResult::RecoverableError(e.status(), id, handle)
                    } else {
                        TransportPollResult::Error(e.status())
                    }
                }
            },
            Err(err) => {
                error!("Error reading from stream {:?}", err);
                TransportPollResult::Error(StatusCode::BadConnectionClosed)
            }
        }
    }

    fn process_message(
        &mut self,
        message: Message,
        channel: &mut SecureChannel,
    ) -> Result<Option<Request>, Error> {
        match message {
            Message::Chunk(chunk) => {
                let header = chunk.message_header(&channel.decoding_options())?;

                if header.is_final == MessageIsFinalType::FinalError {
                    self.pending_chunks.clear();
                    Ok(None)
                } else {
                    let chunk = channel.verify_and_remove_security_server(chunk.data)?;

                    let max_chunks = effective_max_chunk_count(
                        self.send_buffer.max_chunk_count,
                        self.send_buffer.max_message_size,
                    );
                    if self.pending_chunks.len() >= max_chunks {
                        return Err(Error::decoding(format!(
                            "Message has more than {max_chunks} chunks, exceeding limits"
                        )));
                    }
                    let chunk_info = chunk.chunk_info(channel)?;
                    self.sequence_numbers
                        .validate_and_increment(chunk_info.sequence_header.sequence_number)?;
                    self.pending_chunks.push(chunk);

                    if header.is_final == MessageIsFinalType::Intermediate {
                        return Ok(None);
                    }

                    let chunk_info = self.pending_chunks[0].chunk_info(channel)?;

                    Chunker::validate_chunks(channel, &self.pending_chunks)?;

                    let request = Chunker::decode(&self.pending_chunks, channel, None)
                        .map_err(|e| e.with_request_id(chunk_info.sequence_header.request_id))?;
                    Ok(Some(Request {
                        request_id: chunk_info.sequence_header.request_id,
                        chunk_info,
                        message: request,
                    }))
                }
            }
            unexpected => Err(Error::new(
                StatusCode::BadUnexpectedError,
                format!("Received unexpected message: {unexpected:?}"),
            )),
        }
    }
}

impl<R, W> ConnectionTransport for Transport<R, W>
where
    R: AsyncRead + Unpin + Send + Sync + 'static,
    W: AsyncWrite + Unpin + Send + Sync + 'static,
{
    fn set_closing(&mut self) {
        self.set_closing_inner();
    }

    fn is_closing(&self) -> bool {
        self.is_closing_inner()
    }

    fn enqueue_error(&mut self, message: ErrorMessage) {
        self.enqueue_error_inner(message);
    }

    fn enqueue_message_for_send(
        &mut self,
        channel: &mut SecureChannel,
        message: ResponseMessage,
        request_id: u32,
    ) -> Result<(), StatusCode> {
        self.enqueue_message_for_send_inner(channel, message, request_id)
    }

    fn client_protocol_version(&self) -> u32 {
        self.client_protocol_version
    }

    fn poll<'a>(
        &'a mut self,
        channel: &'a mut SecureChannel,
    ) -> impl Future<Output = TransportPollResult> + Send + 'a {
        self.poll_inner(channel)
    }
}

#[cfg(test)]
mod tests {
    use super::effective_max_chunk_count;

    /// N6/M11: the inbound chunk-count ceiling must be enforced from `max_message_size`
    /// when only `max_chunk_count` is 0, while preserving documented 0/0 unlimited semantics.
    #[test]
    fn chunk_count_ceiling_is_bounded_even_when_unlimited() {
        // Explicit cap is honored.
        assert_eq!(effective_max_chunk_count(5, 327_675), 5);
        // 0 == unlimited -> derived ceiling = max_message_size / MIN_CHUNK_SIZE (8192).
        assert_eq!(effective_max_chunk_count(0, 327_675), 327_675 / 8192);
        // 0/0 means unlimited; do not collapse it to one chunk (P2 regression).
        assert_eq!(effective_max_chunk_count(0, 0), usize::MAX);
    }
}
