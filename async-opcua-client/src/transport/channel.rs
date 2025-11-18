use std::{str::FromStr, sync::Arc, time::Duration};

use crate::{
    session::{process_unexpected_response, EndpointInfo},
    transport::core::TransportPollResult,
};
use arc_swap::{ArcSwap, ArcSwapOption};
use opcua_core::{
    comms::secure_channel::{Role, SecureChannel},
    sync::RwLock,
    trace_read_lock, trace_write_lock, RequestMessage, ResponseMessage,
};
use opcua_crypto::{CertificateStore, PrivateKey, SecurityPolicy, X509};
use opcua_types::{
    ByteString, CloseSecureChannelRequest, ContextOwned, IntegerId, NodeId, RequestHeader,
    SecurityTokenRequestType, StatusCode,
};
use tracing::{debug, error};

use super::{
    connect::{Connector, Transport},
    state::{Request, RequestSend, SecureChannelState},
    tcp::TcpTransport,
};

use crate::{
    retry::SessionRetryPolicy,
    transport::{tcp::TransportConfiguration, OutgoingMessage},
};

// This is an arbitrary limit which should never be reached in practice,
// it's just a safety net to prevent the client from consuming too much
// memory if it gets into an unexpected (bad) state.
const MAX_INFLIGHT_MESSAGES: usize = 1_000_000;

/// Wrapper around an open secure channel
pub struct AsyncSecureChannel {
    endpoint_info: EndpointInfo,
    session_retry_policy: SessionRetryPolicy,
    pub(crate) secure_channel: Arc<RwLock<SecureChannel>>,
    certificate_store: Arc<RwLock<CertificateStore>>,
    transport_config: TransportConfiguration,
    state: Arc<SecureChannelState>,
    issue_channel_lock: tokio::sync::Mutex<()>,
    connector: Box<dyn Connector>,
    channel_lifetime: u32,

    request_send: ArcSwapOption<RequestSend>,
    encoding_context: Arc<RwLock<ContextOwned>>,
}

/// Event loop for a secure channel. This must be polled to make progress.
pub struct SecureChannelEventLoop {
    transport: TcpTransport,
}

impl SecureChannelEventLoop {
    /// Poll the channel, processing any pending incoming or outgoing messages and returning the
    /// action that was taken.
    pub async fn poll(&mut self) -> TransportPollResult {
        self.transport.poll().await
    }

    /// Get the URL of the connected server.
    /// This was either the URL used to establish the connection, or the URL
    /// reported by the server in ReverseHello.
    pub fn connected_url(&self) -> &str {
        self.transport.connected_url()
    }
}

impl AsyncSecureChannel {
    pub(crate) fn make_request_header(&self, timeout: Duration) -> RequestHeader {
        self.state.make_request_header(timeout)
    }

    /// Get the next request handle on the channel.
    pub fn request_handle(&self) -> IntegerId {
        self.state.request_handle()
    }

    pub(crate) fn update_from_created_session(
        &self,
        nonce: &ByteString,
        certificate: &ByteString,
        auth_token: &NodeId,
    ) -> Result<(), StatusCode> {
        let mut secure_channel = trace_write_lock!(self.secure_channel);
        secure_channel.set_remote_nonce_from_byte_string(nonce)?;
        secure_channel.set_remote_cert_from_byte_string(certificate)?;
        self.set_auth_token(auth_token.clone());
        Ok(())
    }

    pub(crate) fn security_policy(&self) -> SecurityPolicy {
        let secure_channel = trace_read_lock!(self.secure_channel);
        secure_channel.security_policy()
    }

    /// Get the target endpoint of the secure channel.
    pub fn endpoint_info(&self) -> &EndpointInfo {
        &self.endpoint_info
    }

    /// Get the current global encoding context in use by this channel.
    pub fn encoding_context(&self) -> &RwLock<ContextOwned> {
        &self.encoding_context
    }

    /// Set the active authentication token for this channel.
    pub fn set_auth_token(&self, token: NodeId) {
        self.state.set_auth_token(token);
    }

    pub(crate) fn read_own_private_key(&self) -> Option<PrivateKey> {
        let cert_store = trace_read_lock!(self.certificate_store);
        cert_store.read_own_pkey().ok()
    }

    pub(crate) fn read_own_certificate(&self) -> Option<X509> {
        let cert_store = trace_read_lock!(self.certificate_store);
        cert_store.read_own_cert().ok()
    }

    pub(crate) fn certificate_store(&self) -> &RwLock<CertificateStore> {
        &self.certificate_store
    }
}

impl AsyncSecureChannel {
    /// Create a new client secure channel.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        certificate_store: Arc<RwLock<CertificateStore>>,
        endpoint_info: EndpointInfo,
        session_retry_policy: SessionRetryPolicy,
        ignore_clock_skew: bool,
        auth_token: Arc<ArcSwap<NodeId>>,
        transport_config: TransportConfiguration,
        connector: Box<dyn Connector>,
        channel_lifetime: u32,
        encoding_context: Arc<RwLock<ContextOwned>>,
    ) -> Self {
        let secure_channel = Arc::new(RwLock::new(SecureChannel::new(
            certificate_store.clone(),
            Role::Client,
            encoding_context.clone(),
        )));

        Self {
            transport_config,
            issue_channel_lock: tokio::sync::Mutex::new(()),
            state: Arc::new(SecureChannelState::new(
                ignore_clock_skew,
                secure_channel.clone(),
                auth_token,
            )),
            endpoint_info,
            secure_channel,
            certificate_store,
            session_retry_policy,
            request_send: Default::default(),
            connector,
            channel_lifetime,
            encoding_context,
        }
    }

    /// Send a message on the secure channel, and wait for a response.
    pub async fn send(
        &self,
        request: impl Into<RequestMessage>,
        timeout: Duration,
    ) -> Result<ResponseMessage, StatusCode> {
        let sender = self.request_send.load().as_deref().cloned();
        let Some(send) = sender else {
            return Err(StatusCode::BadNotConnected);
        };

        let should_renew_security_token = {
            let secure_channel = trace_read_lock!(self.secure_channel);
            secure_channel.should_renew_security_token()
        };

        if should_renew_security_token {
            // Grab the lock, then check again whether we should renew the secure channel,
            // this avoids renewing it multiple times if the client sends many requests in quick
            // succession.
            // Also, if the channel is currently being renewed, we need to wait for the new security token.
            let guard = self.issue_channel_lock.lock().await;
            let should_renew_security_token = {
                let secure_channel = trace_read_lock!(self.secure_channel);
                secure_channel.should_renew_security_token()
            };

            if should_renew_security_token {
                let request = self.state.begin_issue_or_renew_secure_channel(
                    SecurityTokenRequestType::Renew,
                    self.channel_lifetime,
                    Duration::from_secs(30),
                    send.clone(),
                );

                let resp = request.send().await?;

                if !matches!(resp, ResponseMessage::OpenSecureChannel(_)) {
                    return Err(process_unexpected_response(resp));
                }
            }

            drop(guard);
        }

        Request::new(request, send, timeout).send().await
    }

    /// Attempt to establish a connection using this channel, returning an event loop
    /// for polling the connection.
    pub async fn connect(&self) -> Result<SecureChannelEventLoop, StatusCode> {
        self.request_send.store(None);
        let mut backoff = self.session_retry_policy.new_backoff();
        loop {
            match self.connect_no_retry().await {
                Ok(event_loop) => {
                    break Ok(event_loop);
                }
                Err(s) => {
                    let Some(delay) = backoff.next() else {
                        break Err(s);
                    };

                    tokio::time::sleep(delay).await
                }
            }
        }
    }

    /// Connect to the server without attempting to retry if it fails.
    pub async fn connect_no_retry(&self) -> Result<SecureChannelEventLoop, StatusCode> {
        {
            let mut secure_channel = trace_write_lock!(self.secure_channel);
            secure_channel.clear_security_token();
        }

        let (mut transport, send) = self.create_transport().await?;

        let request = self.state.begin_issue_or_renew_secure_channel(
            SecurityTokenRequestType::Issue,
            self.channel_lifetime,
            Duration::from_secs(30),
            send.clone(),
        );

        let request_fut = request.send();
        tokio::pin!(request_fut);

        // Temporarily poll the transport task while we're waiting for a response.
        let resp = loop {
            tokio::select! {
                r = &mut request_fut => break r?,
                r = transport.poll() => {
                    if let TransportPollResult::Closed(e) = r {
                        return Err(e);
                    }
                }
            }
        };

        self.request_send.store(Some(Arc::new(send)));
        if !matches!(resp, ResponseMessage::OpenSecureChannel(_)) {
            return Err(process_unexpected_response(resp));
        }

        Ok(SecureChannelEventLoop { transport })
    }

    async fn create_transport(
        &self,
    ) -> Result<(TcpTransport, tokio::sync::mpsc::Sender<OutgoingMessage>), StatusCode> {
        debug!("Connect");
        let security_policy =
            SecurityPolicy::from_str(self.endpoint_info.endpoint.security_policy_uri.as_ref())
                .unwrap();

        if security_policy == SecurityPolicy::Unknown {
            error!(
                "connect, security policy \"{}\" is unknown",
                self.endpoint_info.endpoint.security_policy_uri.as_ref()
            );
            Err(StatusCode::BadSecurityPolicyRejected)
        } else {
            let (cert, key) = {
                let certificate_store = trace_write_lock!(self.certificate_store);
                (
                    certificate_store.read_own_cert().ok(),
                    certificate_store.read_own_pkey().ok(),
                )
            };

            {
                let mut secure_channel = trace_write_lock!(self.secure_channel);
                secure_channel.set_private_key(key);
                secure_channel.set_cert(cert);
                secure_channel.set_security_policy(security_policy);
                secure_channel.set_security_mode(self.endpoint_info.endpoint.security_mode);
                secure_channel.set_remote_cert_from_byte_string(
                    &self.endpoint_info.endpoint.server_certificate,
                )?;
                debug!("Security policy = {:?}", security_policy);
                debug!(
                    "Security mode = {:?}",
                    self.endpoint_info.endpoint.security_mode
                );
            }

            let (send, recv) = tokio::sync::mpsc::channel(MAX_INFLIGHT_MESSAGES);
            let transport = self
                .connector
                .connect(self.state.clone(), recv, self.transport_config.clone())
                .await?;

            Ok((transport, send))
        }
    }

    /// Close the secure channel, optionally wait for the channel to close.
    pub async fn close_channel(&self) {
        let msg = CloseSecureChannelRequest {
            request_header: self.state.make_request_header(Duration::from_secs(60)),
        };

        let sender = self.request_send.load().as_deref().cloned();
        let request = sender.map(|s| Request::new(msg, s, Duration::from_secs(60)));

        // Instruct the channel to not attempt to reopen.
        if let Some(request) = request {
            if let Err(e) = request.send_no_response().await {
                error!("Failed to send disconnect message, queue full: {e}");
            }
        }
    }
}
