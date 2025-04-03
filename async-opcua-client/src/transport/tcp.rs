use std::sync::Arc;

use super::connect::{Connector, Transport};
use super::core::{OutgoingMessage, TransportPollResult, TransportState};
use async_trait::async_trait;
use futures::StreamExt;
use opcua_core::comms::tcp_types::AcknowledgeMessage;
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
use opcua_types::StatusCode;
use parking_lot::RwLock;
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_util::codec::FramedRead;
use tracing::{debug, error};

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
}

#[derive(Debug, Clone)]
pub struct TransportConfiguration {
    pub max_pending_incoming: usize,
    pub send_buffer_size: usize,
    pub recv_buffer_size: usize,
    pub max_message_size: usize,
    pub max_chunk_count: usize,
}

pub struct TcpConnector;

impl TcpConnector {
    async fn connect_inner(
        secure_channel: &RwLock<SecureChannel>,
        config: &TransportConfiguration,
        endpoint_url: &str,
    ) -> Result<
        (
            FramedRead<ReadHalf<TcpStream>, TcpCodec>,
            WriteHalf<TcpStream>,
            AcknowledgeMessage,
        ),
        StatusCode,
    > {
        let (host, port) = hostname_port_from_url(
            endpoint_url,
            opcua_core::constants::DEFAULT_OPC_UA_SERVER_PORT,
        )?;

        let addr = {
            let addr = format!("{}:{}", host, port);
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

        let hello = HelloMessage::new(
            endpoint_url,
            config.send_buffer_size,
            config.recv_buffer_size,
            config.max_message_size,
            config.max_chunk_count,
        );
        tracing::trace!("Send hello message: {hello:?}");
        let mut framed_read = {
            let secure_channel = trace_read_lock!(secure_channel);
            FramedRead::new(reader, TcpCodec::new(secure_channel.decoding_options()))
        };

        writer
            .write_all(&opcua_types::SimpleBinaryEncodable::encode_to_vec(&hello))
            .await
            .map_err(|err| {
                error!("Cannot send hello to server, err = {}", err);
                StatusCode::BadCommunicationError
            })?;
        let ack = match framed_read.next().await {
            Some(Ok(Message::Acknowledge(ack))) => {
                if ack.send_buffer_size > hello.receive_buffer_size {
                    tracing::warn!("Acknowledged send buffer size is greater than receive buffer size in hello message!")
                }
                if ack.receive_buffer_size > hello.send_buffer_size {
                    tracing::warn!("Acknowledged receive buffer size is greater than send buffer size in hello message!")
                }
                tracing::trace!("Received acknowledgement: {:?}", ack);
                ack
            }
            other => {
                error!(
                    "Unexpected error while waiting for server ACK. Expected ACK, got {:?}",
                    other
                );
                return Err(StatusCode::BadConnectionClosed);
            }
        };

        Ok((framed_read, writer, ack))
    }
}

#[async_trait]
impl Connector for TcpConnector {
    async fn connect(
        &self,
        channel: Arc<RwLock<SecureChannel>>,
        outgoing_recv: tokio::sync::mpsc::Receiver<OutgoingMessage>,
        config: TransportConfiguration,
        endpoint_url: &str,
    ) -> Result<TcpTransport, StatusCode> {
        let (framed_read, writer, ack) =
            match Self::connect_inner(&channel, &config, endpoint_url).await {
                Ok(k) => k,
                Err(status) => return Err(status),
            };
        let mut buffer = SendBuffer::new(
            config.send_buffer_size,
            config.max_message_size,
            config.max_chunk_count,
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
                config.max_pending_incoming,
                ack.send_buffer_size.min(config.recv_buffer_size as u32) as usize,
            ),
            read: framed_read,
            write: writer,
            send_buffer: buffer,
            should_close: false,
            closed: TransportCloseState::Open,
        })
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
            let secure_channel = trace_read_lock!(self.state.secure_channel);
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
                    let secure_channel = trace_read_lock!(self.state.secure_channel);
                    if let Err(e) = self.send_buffer.write(request_id, outgoing, &secure_channel) {
                        drop(secure_channel);
                        if let Some((request_id, request_handle)) = e.full_context() {
                            error!("Failed to send message with request handle {}: {}", request_handle, e.status());
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
