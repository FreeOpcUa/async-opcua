use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use futures::future::Either;
use opcua_core::comms::{
    secure_channel::DecryptedChunkStorage, sequence_number::SequenceNumberHandle,
};
use opcua_core::{trace_read_lock, RequestMessage, ResponseMessage};
use tracing::{debug, error, trace, warn};

use opcua_core::comms::buffer::SendBuffer;
use opcua_core::comms::message_chunk::{MessageFinalError, MessageIsFinalType};
use opcua_core::comms::{
    chunker::Chunker, message_chunk::MessageChunk, message_chunk_info::ChunkInfo,
    tcp_codec::Message, tcp_types::MIN_CHUNK_SIZE,
};
use opcua_types::{Error, StatusCode, UAString};

use crate::transport::state::SecureChannelState;
use crate::transport::RequestRecv;

#[derive(Debug)]
struct MessageChunkWithChunkInfo {
    header: ChunkInfo,
    data_with_header: bytes::Bytes,
}

pub(crate) struct MessageState {
    callback: tokio::sync::oneshot::Sender<Result<ResponseMessage, Error>>,
    chunks: Vec<MessageChunkWithChunkInfo>,
    deadline: Instant,
    span: tracing::Span,
}

/// Internal state of a transport implementation.
pub struct TransportState {
    /// Channel for outgoing requests. Will only be polled if the number of inflight requests is below the limit.
    outgoing_recv: tokio::sync::mpsc::Receiver<OutgoingMessage>,
    /// State of pending requests
    message_states: HashMap<u32, MessageState>,
    /// Secure channel
    pub channel_state: Arc<SecureChannelState>,
    /// Max pending incoming messages
    max_chunk_count: usize,
    /// Max incoming message size used to derive a hard chunk-count ceiling.
    max_message_size: usize,
    /// Last decoded sequence number
    sequence_numbers: SequenceNumberHandle,
    /// Max size of incoming chunks
    #[allow(unused)]
    receive_buffer_size: usize,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum TransportCloseState {
    Open,
    Closing(StatusCode),
    Closed(StatusCode),
}

#[derive(Debug)]
/// Result of polling a transport implementation.
/// This represents a single iteration of the transport event loop.
pub enum TransportPollResult {
    /// An outgoing message was received and enqueued.
    OutgoingMessage,
    /// An outgoing message was sent to the server.
    OutgoingMessageSent,
    /// An incoming message was received from the server.
    IncomingMessage,
    /// An error occured that is recoverable, so the transport can continue and
    /// simply fail the request.
    RecoverableError(StatusCode),
    /// The transport was closed with the given status code.
    Closed(StatusCode),
}

/// An outgoing message to be sent by the transport.
pub struct OutgoingMessage {
    /// The actual request message to send.
    pub request: RequestMessage,
    /// A callback that should be called when a response is received.
    pub callback: Option<tokio::sync::oneshot::Sender<Result<ResponseMessage, Error>>>,
    /// Deadline for the request.
    pub deadline: Instant,
    /// An optional tracing span to attach to the request.
    pub span: tracing::Span,
}

impl TransportState {
    /// Create a new transport state.
    pub fn new(
        channel_state: Arc<SecureChannelState>,
        outgoing_recv: RequestRecv,
        max_chunk_count: usize,
        max_message_size: usize,
        receive_buffer_size: usize,
    ) -> Self {
        let legacy_sequence_numbers = channel_state
            .secure_channel()
            .read()
            .security_policy()
            .legacy_sequence_numbers();
        Self {
            channel_state,
            outgoing_recv,
            message_states: HashMap::new(),
            sequence_numbers: SequenceNumberHandle::new(legacy_sequence_numbers),
            max_chunk_count,
            max_message_size,
            receive_buffer_size,
        }
    }

    fn effective_max_chunk_count(&self) -> usize {
        if self.max_chunk_count > 0 {
            self.max_chunk_count
        } else {
            (self.max_message_size / MIN_CHUNK_SIZE).max(1)
        }
    }

    /// Wait for an outgoing message. Will also check for timed out messages.
    pub async fn wait_for_outgoing_message(
        &mut self,
        send_buffer: &mut SendBuffer,
    ) -> Option<(RequestMessage, u32)> {
        loop {
            // Check for any messages that have timed out, and get the time until the next message
            // times out
            let timeout_fut = match self.next_timeout() {
                Some(t) => Either::Left(tokio::time::sleep_until(t.into())),
                None => Either::Right(futures::future::pending::<()>()),
            };

            tokio::select! {
                _ = timeout_fut => {
                    continue;
                }
                outgoing = self.outgoing_recv.recv() => {
                    let outgoing = outgoing?;
                    let request_id = send_buffer.next_request_id();
                    if let Some(callback) = outgoing.callback {
                        self.message_states.insert(request_id, MessageState {
                            callback,
                            chunks: Vec::new(),
                            deadline: outgoing.deadline,
                            span: outgoing.span,
                        });
                    }
                    break Some((outgoing.request, request_id));
                }
            }
        }
    }

    /// Store incoming messages in the message state.
    pub fn handle_incoming_message(
        &mut self,
        message: Message,
        decrypted_chunk_storage: &mut DecryptedChunkStorage,
    ) -> Result<(), Error> {
        match message {
            Message::Acknowledge(ack) => {
                debug!("Reader got an unexpected ack {:?}", ack);
                Err(Error::new(
                    StatusCode::BadUnexpectedError,
                    "Received an unexpected ACK from the server",
                ))
            }
            Message::Chunk(chunk) => {
                self.process_chunk(chunk, decrypted_chunk_storage)?;
                Ok(())
            }
            Message::Error(error) => {
                error!(
                    "Received error {} from server. Reason: {}",
                    error.error, error.reason
                );
                Err(Error::new(
                    error.error,
                    format!("Received error from server. Reason: {}", error.reason),
                ))
            }
            m => {
                error!("Expected a recognized message, got {:?}", m);
                Err(Error::new(
                    StatusCode::BadUnexpectedError,
                    format!("Expected a chunk or error, got {:?}", m),
                ))
            }
        }
    }

    /// Call this if sending a message fails. This will notify the waiting request
    /// that the message could not be sent.
    pub fn message_send_failed(&mut self, request_id: u32, err: Error) {
        if let Some(message_state) = self.message_states.remove(&request_id) {
            message_state.span.in_scope(|| {
                debug!(
                    "Failed to send message, request_id = {}: {}",
                    request_id, err
                );
            });
            let _ = message_state.callback.send(Err(err));
        }
    }

    fn next_timeout(&mut self) -> Option<Instant> {
        let now = Instant::now();
        let mut next_timeout = None;
        let mut timed_out = Vec::new();
        for (id, state) in &self.message_states {
            if state.deadline <= now {
                timed_out.push(*id);
            } else {
                match &next_timeout {
                    Some(t) if *t > state.deadline => next_timeout = Some(state.deadline),
                    None => next_timeout = Some(state.deadline),
                    _ => {}
                }
            }
        }
        for id in timed_out {
            if let Some(state) = self.message_states.remove(&id) {
                state.span.in_scope(|| {
                    debug!("Message timed out, request_id = {id}");
                });
                let _ = state.callback.send(Err(Error::new(
                    StatusCode::BadTimeout,
                    "Message timed out",
                )
                .with_request_id(id)));
            }
        }
        next_timeout
    }

    fn process_chunk(
        &mut self,
        chunk: MessageChunk,
        decrypted_chunk_storage: &mut DecryptedChunkStorage,
    ) -> Result<(), Error> {
        let (chunk, chunk_info, decoding_options) = {
            let secure_channel = trace_read_lock!(self.channel_state.secure_channel());
            let chunk =
                secure_channel.verify_and_remove_security(chunk.data, decrypted_chunk_storage)?;
            let chunk_info = chunk.chunk_info(&secure_channel)?;
            let decoding_options = secure_channel.decoding_options();
            (chunk, chunk_info, decoding_options)
        };
        let req_id = chunk_info.sequence_header.request_id;

        self.sequence_numbers
            .validate_and_increment(chunk_info.sequence_header.sequence_number)?;

        // We do not care at all about incoming messages without a
        // corresponding request.
        let max_chunks = self.effective_max_chunk_count();
        let Some(message_state) = self.message_states.get_mut(&req_id) else {
            trace!(
                "Received chunk for unknown request id {}:{}. Ignoring.",
                req_id,
                chunk_info.sequence_header.sequence_number
            );

            return Ok(());
        };

        match chunk_info.message_header.is_final {
            MessageIsFinalType::Intermediate => {
                let _h = message_state.span.enter();
                trace!(
                    "receive chunk intermediate {}:{}. Length {}",
                    chunk_info.sequence_header.request_id,
                    chunk_info.sequence_header.sequence_number,
                    chunk_info.body_length
                );
                if message_state.chunks.len() >= max_chunks {
                    error!("Message has more than {max_chunks} chunks, exceeding limits");
                    drop(_h);
                    // Removing the message state means that we ignore any further chunks.
                    let message_state = self.message_states.remove(&req_id).unwrap();
                    message_state.span.in_scope(|| {
                        error!("Message {} exceeded max chunk count", req_id);
                        let _ = message_state.callback.send(Err(Error::new(
                            StatusCode::BadEncodingLimitsExceeded,
                            "Message exceeded max chunk count",
                        )
                        .with_request_id(req_id)));
                    });
                    return Ok(());
                }
                message_state.chunks.push(MessageChunkWithChunkInfo {
                    header: chunk_info,
                    data_with_header: chunk.data,
                });
            }
            MessageIsFinalType::FinalError => {
                let err = match chunk.final_error_body(&chunk_info, &decoding_options) {
                    Ok(err) => err,
                    Err(_) => MessageFinalError {
                        status: StatusCode::BadCommunicationError,
                        reason: UAString::null(),
                    },
                };
                let message_state = self.message_states.remove(&req_id).unwrap();
                message_state.span.in_scope(|| {
                    warn!(
                        "Message marked as final error, request_id = {req_id}, status = {}, reason = {}", err.status, err.reason
                    );
                    let _ = message_state.callback.send(Err(Error::new(err.status, format!("Message marked final error: {}", err.reason)).with_request_id(req_id)));
                });
            }
            MessageIsFinalType::Final => {
                let _h = message_state.span.enter();
                trace!(
                    "receive chunk final {}:{}. Length {}",
                    chunk_info.sequence_header.request_id,
                    chunk_info.sequence_header.sequence_number,
                    chunk_info.body_length
                );
                if message_state.chunks.len() >= max_chunks {
                    error!("Message has more than {max_chunks} chunks, exceeding limits");
                    drop(_h);
                    let message_state = self.message_states.remove(&req_id).unwrap();
                    message_state.span.in_scope(|| {
                        error!("Message {} exceeded max chunk count", req_id);
                        let _ = message_state.callback.send(Err(Error::new(
                            StatusCode::BadEncodingLimitsExceeded,
                            "Message exceeded max chunk count",
                        )
                        .with_request_id(req_id)));
                    });
                    return Ok(());
                }
                message_state.chunks.push(MessageChunkWithChunkInfo {
                    header: chunk_info,
                    data_with_header: chunk.data,
                });
                drop(_h);
                let message_state = self.message_states.remove(&req_id).unwrap();
                let _h = message_state.span.enter();
                let in_chunks = Self::merge_chunks(message_state.chunks).inspect_err(|e| {
                    error!("Failed to merge chunks for message, request_id = {req_id}: {e}");
                })?;
                let message = self
                    .turn_received_chunks_into_message(&in_chunks)
                    .inspect_err(|e| {
                        error!("Failed to decode incoming message, request_id = {req_id}: {e}")
                    })?;

                // If the message is a response to opening a secure channel, we need to update encryption keys
                // right now. If we wait, we risk new messages using the new encryption keys arriving before
                // we've updated the secure channel.
                if let ResponseMessage::OpenSecureChannel(msg) = &message {
                    let service_result = msg.response_header.service_result;
                    if !service_result.is_good() {
                        error!(
                            "OpenSecureChannel response failed, request_id = {req_id}: {service_result}"
                        );
                        return Err(Error::new(
                            service_result,
                            "OpenSecureChannel received service fault from server",
                        ));
                    }
                    self.channel_state.end_issue_or_renew_secure_channel(msg).inspect_err(|e| {
                        error!("Failed to process OpenSecureChannel response, request_id = {req_id}: {e}");
                    })?;
                }

                let _ = message_state.callback.send(Ok(message));
            }
        }
        Ok(())
    }

    fn turn_received_chunks_into_message(
        &mut self,
        chunks: &[MessageChunk],
    ) -> Result<ResponseMessage, Error> {
        // Validate that all chunks have incrementing sequence numbers and valid chunk types
        let secure_channel = trace_read_lock!(self.channel_state.secure_channel());
        Chunker::validate_chunks(&secure_channel, chunks)?;
        // Now decode
        Chunker::decode(chunks, &secure_channel, None)
    }

    fn merge_chunks(
        mut chunks: Vec<MessageChunkWithChunkInfo>,
    ) -> Result<Vec<MessageChunk>, Error> {
        if chunks.len() == 1 {
            return Ok(vec![MessageChunk {
                data: chunks.pop().unwrap().data_with_header,
            }]);
        }
        chunks.sort_by(|a, b| {
            a.header
                .sequence_header
                .sequence_number
                .cmp(&b.header.sequence_header.sequence_number)
        });
        let mut ret = Vec::with_capacity(chunks.len());
        let mut expect_sequence_number = chunks
            .first()
            .unwrap()
            .header
            .sequence_header
            .sequence_number;
        for c in chunks {
            if c.header.sequence_header.sequence_number != expect_sequence_number {
                warn!(
                    "receive wrong chunk expect seq={} got={}",
                    expect_sequence_number, c.header.sequence_header.sequence_number
                );
                continue; //may be duplicate chunk
            }
            expect_sequence_number = expect_sequence_number.wrapping_add(1);
            ret.push(MessageChunk {
                data: c.data_with_header,
            });
        }
        Ok(ret)
    }

    /// Close the transport, aborting any pending requests.
    /// If `status` is good, the pending requests will be terminated with
    /// `BadConnectionClosed`.
    pub async fn close(&mut self, status: StatusCode) -> StatusCode {
        // If the status is good, we still want to send a bad status code
        // to the pending requests. They didn't succeed, after all.
        let request_status = if status.is_good() {
            StatusCode::BadConnectionClosed
        } else {
            status
        };

        for (_, pending) in self.message_states.drain() {
            pending.span.in_scope(|| {
                debug!("Transport is closing, failing pending request");
            });
            let _ = pending
                .callback
                .send(Err(Error::new(request_status, "Transport is closing")));
        }

        // Make sure we also send a bad status for any remaining messages in the queue
        // Close the channel first.
        self.outgoing_recv.close();

        // recv is no longer blocking.
        while let Some(msg) = self.outgoing_recv.recv().await {
            if let Some(cb) = msg.callback {
                let _ = cb.send(Err(Error::new(request_status, "Transport is closing")));
            }
        }

        status
    }
}

#[cfg(test)]
mod tests {
    use std::{path::Path, sync::Arc};

    use arc_swap::ArcSwap;
    use opcua_core::{
        comms::secure_channel::{Role, SecureChannel},
        sync::RwLock,
    };
    use opcua_crypto::CertificateStore;
    use opcua_types::{ContextOwned, NodeId};

    use super::TransportState;
    use crate::transport::state::SecureChannelState;

    fn test_transport_state(max_chunk_count: usize, max_message_size: usize) -> TransportState {
        // CertificateStore::new is pure (just records the path); None-policy channels
        // never touch the PKI dir, so an unused path is fine for this unit test.
        let cert_store = Arc::new(RwLock::new(CertificateStore::new(Path::new(
            "./target/_unused_test_pki",
        ))));
        let encoding_context = Arc::new(RwLock::new(ContextOwned::default()));
        let secure_channel = Arc::new(RwLock::new(SecureChannel::new(
            cert_store,
            Role::Client,
            encoding_context,
        )));
        let auth_token = Arc::new(ArcSwap::new(Arc::new(NodeId::null())));
        let channel_state = Arc::new(SecureChannelState::new(false, secure_channel, auth_token));
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        TransportState::new(
            channel_state,
            rx,
            max_chunk_count,
            max_message_size,
            max_message_size,
        )
    }

    /// T044 / M11: a configured "unlimited" incoming chunk count (`max_chunk_count == 0`)
    /// must NOT mean unbounded accumulation. The client derives a hard, finite ceiling
    /// from `max_message_size / MIN_CHUNK_SIZE` (MIN_CHUNK_SIZE = 8192), floored at 1.
    #[test]
    fn unlimited_chunk_count_derives_a_finite_ceiling() {
        assert_eq!(
            test_transport_state(0, 8192 * 10).effective_max_chunk_count(),
            10
        );
        // Never 0/unbounded: a tiny or zero max message size still floors at 1.
        assert_eq!(test_transport_state(0, 0).effective_max_chunk_count(), 1);
        assert_eq!(test_transport_state(0, 100).effective_max_chunk_count(), 1);
    }

    /// An explicit positive `max_chunk_count` is honored verbatim.
    #[test]
    fn explicit_chunk_count_is_honored() {
        assert_eq!(
            test_transport_state(5, 8192 * 100).effective_max_chunk_count(),
            5
        );
    }
}
