use std::{
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

use futures::{future::Either, stream::FuturesUnordered, Future, StreamExt};
use opcua_core::{trace_read_lock, trace_write_lock, Message, RequestMessage, ResponseMessage};
use tracing::{debug, debug_span, error, trace, warn};

use opcua_core::{
    comms::{
        secure_channel::SecureChannel, security_header::SecurityHeader, tcp_types::ErrorMessage,
    },
    config::Config,
    handle::AtomicHandle,
    sync::RwLock,
};
use opcua_crypto::{CertificateStore, SecurityPolicy};
use opcua_types::{
    ChannelSecurityToken, DateTime, FindServersResponse, GetEndpointsResponse, MessageSecurityMode,
    OpenSecureChannelRequest, OpenSecureChannelResponse, ResponseHeader, SecurityTokenRequestType,
    ServiceFault, StatusCode,
};
use tokio_util::sync::CancellationToken;
use tracing_futures::Instrument;

use crate::{
    authenticator::UserToken,
    info::ServerInfo,
    node_manager::NodeManagers,
    subscriptions::SubscriptionCache,
    transport::tcp::{Request, TcpTransport, TransportPollResult},
    transport::Connector,
};

use super::{
    instance::Session,
    manager::{activate_session, close_session, SessionManager},
    message_handler::MessageHandler,
};

pub(crate) struct Response {
    pub message: ResponseMessage,
    pub request_id: u32,
}

impl Response {
    pub fn from_result(
        result: Result<impl Into<ResponseMessage>, StatusCode>,
        request_handle: u32,
        request_id: u32,
    ) -> Self {
        match result {
            Ok(r) => Self {
                message: r.into(),
                request_id,
            },
            Err(e) => Self {
                message: ServiceFault::new(request_handle, e).into(),
                request_id,
            },
        }
    }
}

pub(crate) enum ControllerCommand {
    Close,
}

type PendingMessageResponse = dyn Future<Output = Result<Response, String>> + Send + Sync + 'static;

/// Master type managing a single connection.
pub(crate) struct SessionController {
    channel: SecureChannel,
    transport: TcpTransport,
    secure_channel_state: SecureChannelState,
    session_manager: Arc<RwLock<SessionManager>>,
    certificate_store: Arc<RwLock<CertificateStore>>,
    message_handler: MessageHandler,
    pending_messages: FuturesUnordered<Pin<Box<PendingMessageResponse>>>,
    info: Arc<ServerInfo>,
    deadline: Instant,
}

enum RequestProcessResult {
    Ok,
    Close,
}

pub struct SessionStarter<T> {
    connector: T,
    info: Arc<ServerInfo>,
    session_manager: Arc<RwLock<SessionManager>>,
    certificate_store: Arc<RwLock<CertificateStore>>,
    node_managers: NodeManagers,
    subscriptions: Arc<SubscriptionCache>,
}

impl<T: Connector> SessionStarter<T> {
    pub fn new(
        connector: T,
        info: Arc<ServerInfo>,
        session_manager: Arc<RwLock<SessionManager>>,
        certificate_store: Arc<RwLock<CertificateStore>>,
        node_managers: NodeManagers,
        subscriptions: Arc<SubscriptionCache>,
    ) -> Self {
        Self {
            connector,
            info,
            session_manager,
            certificate_store,
            node_managers,
            subscriptions,
        }
    }

    pub async fn run(self, mut command: tokio::sync::mpsc::Receiver<ControllerCommand>) {
        let token = CancellationToken::new();
        let span = tracing::info_span!("Establish TCP channel");
        let fut = self
            .connector
            .connect(self.info.clone(), token.clone())
            .instrument(span.clone());
        tokio::pin!(fut);
        let transport = tokio::select! {
            cmd = command.recv() => {
                match cmd {
                    Some(ControllerCommand::Close) | None => {
                        token.cancel();
                        let _ = fut.await;
                        return;
                    }
                }
            }
            r = &mut fut => {
                match r {
                    Ok(t) => t,
                    Err(e) => {
                        span.in_scope(|| {
                            tracing::error!("Connection failed while waiting for channel to be established: {e}");
                        });
                        return;
                    }
                }
            }
        };

        let controller = SessionController::new(
            transport,
            self.session_manager,
            self.certificate_store,
            self.info,
            self.node_managers,
            self.subscriptions,
        );
        controller.run(command).await
    }
}

impl SessionController {
    pub fn new(
        transport: TcpTransport,
        session_manager: Arc<RwLock<SessionManager>>,
        certificate_store: Arc<RwLock<CertificateStore>>,
        info: Arc<ServerInfo>,
        node_managers: NodeManagers,
        subscriptions: Arc<SubscriptionCache>,
    ) -> Self {
        let channel = SecureChannel::new(
            certificate_store.clone(),
            opcua_core::comms::secure_channel::Role::Server,
            Arc::new(RwLock::new(info.initial_encoding_context())),
        );

        Self {
            channel,
            transport,
            secure_channel_state: SecureChannelState::new(info.secure_channel_id_handle.clone()),
            session_manager,
            certificate_store,
            message_handler: MessageHandler::new(info.clone(), node_managers, subscriptions),
            deadline: Instant::now()
                + Duration::from_secs(info.config.tcp_config.hello_timeout as u64),
            info,
            pending_messages: FuturesUnordered::new(),
        }
    }

    pub async fn run(mut self, mut command: tokio::sync::mpsc::Receiver<ControllerCommand>) {
        loop {
            let resp_fut = if self.pending_messages.is_empty() {
                Either::Left(futures::future::pending::<Option<Result<Response, String>>>())
            } else {
                Either::Right(self.pending_messages.next())
            };

            tokio::select! {
                _ = tokio::time::sleep_until(self.deadline.into()) => {
                    warn!("Connection timed out, closing");
                    self.fatal_error(StatusCode::BadTimeout, "Connection timeout");
                }
                cmd = command.recv() => {
                    match cmd {
                        Some(ControllerCommand::Close) | None => {
                            self.fatal_error(StatusCode::BadServerHalted, "Server stopped");
                        }
                    }
                }
                msg = resp_fut => {
                    let msg = match msg {
                        Some(Ok(x)) => x,
                        Some(Err(e)) => {
                            error!("Unexpected error in message handler: {e}");
                            self.fatal_error(StatusCode::BadInternalError, &e);
                            continue;
                        }
                        // Cannot happen, pending_messages is non-empty or this future never returns.
                        None => unreachable!(),
                    };
                    self.response_metrics(&msg);

                    if let Err(e) = self.transport.enqueue_message_for_send(
                        &mut self.channel,
                        msg.message,
                        msg.request_id
                    ) {
                        error!("Failed to send response: {e}");
                        self.fatal_error(e, "Encoding error");
                    }
                }
                res = self.transport.poll(&mut self.channel) => {
                    match res {
                        TransportPollResult::IncomingMessage(req) => {
                            if matches!(self.process_request(req).await, RequestProcessResult::Close) {
                                self.transport.set_closing();
                            }
                        }
                        TransportPollResult::RecoverableError(s, id, handle) => {
                            warn!("Non-fatal transport error: {s}, with request id {id}, request handle {handle}");
                            let msg = ServiceFault::new(handle, s).into();
                            if let Err(e) = self.transport.enqueue_message_for_send(&mut self.channel, msg, id) {
                                error!("Failed to send response: {e}");
                                self.fatal_error(e, "Encoding error");
                            }
                        }
                        TransportPollResult::Error(s) => {
                            error!("Fatal transport error: {s}");
                            self.fatal_error(s, "Transport error");
                        }
                        TransportPollResult::Closed => break,
                        _ => (),
                    }
                }
            }
        }
    }

    fn response_metrics(&self, msg: &Response) {
        if self.info.diagnostics.enabled {
            let status = msg.message.response_header().service_result;
            if status.is_bad() {
                self.info.diagnostics.inc_rejected_requests();
                if matches!(
                    status,
                    StatusCode::BadSessionIdInvalid
                        | StatusCode::BadSecurityChecksFailed
                        | StatusCode::BadUserAccessDenied
                ) {
                    self.info.diagnostics.inc_security_rejected_requests();
                }
            }
        }
    }

    fn fatal_error(&mut self, err: StatusCode, msg: &str) {
        if !self.transport.is_closing() {
            self.transport.enqueue_error(ErrorMessage::new(err, msg));
        }
        self.transport.set_closing();
    }

    async fn process_request(&mut self, req: Request) -> RequestProcessResult {
        let span = debug_span!(
            "Incoming request",
            request_id = req.request_id,
            request_type = %req.message.type_name(),
            request_handle = req.message.request_handle(),
        );

        let id = req.request_id;
        match req.message {
            RequestMessage::OpenSecureChannel(r) => {
                let _h = span.enter();
                let res = self.open_secure_channel(
                    &req.chunk_info.security_header,
                    self.transport.client_protocol_version,
                    &r,
                );
                if res.is_ok() {
                    self.deadline = self.channel.token_renewal_deadline();
                } else {
                    self.info.diagnostics.inc_rejected_requests();
                    self.info.diagnostics.inc_security_rejected_requests();
                }
                match res {
                    Ok(r) => match self
                        .transport
                        .enqueue_message_for_send(&mut self.channel, r, id)
                    {
                        Ok(_) => RequestProcessResult::Ok,
                        Err(e) => {
                            error!("Failed to send open secure channel response: {e}");
                            RequestProcessResult::Close
                        }
                    },
                    Err(e) => {
                        let _ = self.transport.enqueue_message_for_send(
                            &mut self.channel,
                            ServiceFault::new(&r.request_header, e).into(),
                            id,
                        );
                        RequestProcessResult::Close
                    }
                }
            }

            RequestMessage::CloseSecureChannel(_r) => RequestProcessResult::Close,

            RequestMessage::CreateSession(request) => {
                let _h = span.enter();
                let mut mgr = trace_write_lock!(self.session_manager);
                let res = mgr.create_session(&mut self.channel, &self.certificate_store, &request);
                drop(mgr);
                self.process_service_result(res, request.request_header.request_handle, id)
            }

            RequestMessage::ActivateSession(request) => {
                let res = activate_session(
                    &self.session_manager,
                    &mut self.channel,
                    &request,
                    &mut self.message_handler,
                )
                .instrument(span.clone())
                .await;
                let _h = span.enter();
                self.process_service_result(res, request.request_header.request_handle, id)
            }

            RequestMessage::CloseSession(request) => {
                let res = close_session(
                    &self.session_manager,
                    &mut self.channel,
                    &mut self.message_handler,
                    &request,
                )
                .instrument(span.clone())
                .await;
                let _h = span.enter();
                self.process_service_result(res, request.request_header.request_handle, id)
            }
            RequestMessage::GetEndpoints(request) => {
                // TODO some of the arguments in the request are ignored
                //  localeIds - list of locales to use for human readable strings (in the endpoint descriptions)

                // TODO audit - generate event for failed service invocation

                let _h = span.enter();
                let endpoints = self
                    .info
                    .endpoints(&request.endpoint_url, &request.profile_uris);
                self.process_service_result(
                    Ok(GetEndpointsResponse {
                        response_header: ResponseHeader::new_good(&request.request_header),
                        endpoints,
                    }),
                    request.request_header.request_handle,
                    id,
                )
            }
            RequestMessage::FindServers(request) => {
                let _h = span.enter();
                let desc = self.info.config.application_description();
                let mut servers = vec![desc];

                // TODO endpoint URL

                // TODO localeids, filter out servers that do not support locale ids

                // Filter servers that do not have a matching application uri
                if let Some(ref server_uris) = request.server_uris {
                    if !server_uris.is_empty() {
                        // Filter the servers down
                        servers.retain(|server| {
                            server_uris.iter().any(|uri| *uri == server.application_uri)
                        });
                    }
                }

                let servers = Some(servers);

                self.process_service_result(
                    Ok(FindServersResponse {
                        response_header: ResponseHeader::new_good(&request.request_header),
                        servers,
                    }),
                    request.request_header.request_handle,
                    id,
                )
            }
            RequestMessage::FindServersOnNetwork(request) => {
                let _h = span.enter();
                if let Err(e) = self.transport.enqueue_message_for_send(
                    &mut self.channel,
                    ServiceFault::new(&request.request_header, StatusCode::BadServiceUnsupported)
                        .into(),
                    id,
                ) {
                    error!("Failed to send request response: {e}");
                    RequestProcessResult::Close
                } else {
                    RequestProcessResult::Ok
                }
            }
            RequestMessage::RegisterServer(request) => {
                let _h = span.enter();
                if let Err(e) = self.transport.enqueue_message_for_send(
                    &mut self.channel,
                    ServiceFault::new(&request.request_header, StatusCode::BadServiceUnsupported)
                        .into(),
                    id,
                ) {
                    error!("Failed to send request response: {e}");
                    RequestProcessResult::Close
                } else {
                    RequestProcessResult::Ok
                }
            }
            RequestMessage::RegisterServer2(request) => {
                let _h = span.enter();
                if let Err(e) = self.transport.enqueue_message_for_send(
                    &mut self.channel,
                    ServiceFault::new(&request.request_header, StatusCode::BadServiceUnsupported)
                        .into(),
                    id,
                ) {
                    error!("Failed to send request response: {e}");
                    RequestProcessResult::Close
                } else {
                    RequestProcessResult::Ok
                }
            }

            message => {
                let _h = span.enter();
                let now = Instant::now();
                let mgr = trace_read_lock!(self.session_manager);
                let session = mgr.find_by_token(&message.request_header().authentication_token);

                let (session_id, session, user_token) =
                    match Self::validate_request(&message, session, &self.channel) {
                        Ok(s) => s,
                        Err(e) => {
                            self.info.diagnostics.inc_rejected_requests();
                            self.info.diagnostics.inc_security_rejected_requests();
                            match self
                                .transport
                                .enqueue_message_for_send(&mut self.channel, e, id)
                            {
                                Ok(_) => return RequestProcessResult::Ok,
                                Err(e) => {
                                    error!("Failed to send request response: {e}");
                                    return RequestProcessResult::Close;
                                }
                            }
                        }
                    };

                debug!("Received request on session {session_id}");

                let deadline = {
                    let timeout = message.request_header().timeout_hint;
                    let max_timeout = self.info.config.max_timeout_ms;
                    let timeout = if max_timeout == 0 {
                        timeout
                    } else {
                        max_timeout.max(timeout)
                    };
                    if timeout == 0 {
                        // Just set some huge value. A request taking a day can probably
                        // be safely canceled...
                        now + Duration::from_secs(60 * 60 * 24)
                    } else {
                        now + Duration::from_millis(timeout.into())
                    }
                };
                let request_handle = message.request_handle();

                match self
                    .message_handler
                    .handle_message(message, session_id, session, user_token, id)
                {
                    super::message_handler::HandleMessageResult::AsyncMessage(mut handle) => {
                        self.pending_messages
                            .push(Box::pin(async move {
                                // Select biased because if for some reason there's a long time between polls,
                                // we want to return the response even if the timeout expired. We only want to send a timeout
                                // if the call has not been finished yet.
                                tokio::select! {
                                    biased;
                                    r = &mut handle => {
                                        match r {
                                            Ok(r) => {
                                                debug!(
                                                    status_code = %r.message.response_header().service_result,
                                                    "Sending response of type {}", r.message.type_name()
                                                );
                                                Ok(r)
                                            }
                                            Err(e) => {
                                                error!("Request panic! {e}");
                                                Err(e.to_string())
                                            }
                                        }
                                    }
                                    _ = tokio::time::sleep_until(deadline.into()) => {
                                        handle.abort();
                                        Ok(Response { message: ServiceFault::new(request_handle, StatusCode::BadTimeout).into(), request_id: id })
                                    }
                                }
                            }.instrument(span.clone())));
                        RequestProcessResult::Ok
                    }
                    super::message_handler::HandleMessageResult::SyncMessage(s) => {
                        debug!(
                            status_code = %s.message.response_header().service_result,
                            "Sending response of type {}", s.message.type_name()
                        );
                        self.response_metrics(&s);

                        if let Err(e) = self.transport.enqueue_message_for_send(
                            &mut self.channel,
                            s.message,
                            s.request_id,
                        ) {
                            error!("Failed to send response: {e}");
                            return RequestProcessResult::Close;
                        }
                        RequestProcessResult::Ok
                    }
                    super::message_handler::HandleMessageResult::PublishResponse(resp) => {
                        self.pending_messages.push(Box::pin(resp.recv()));
                        RequestProcessResult::Ok
                    }
                }
            }
        }
    }

    fn process_service_result(
        &mut self,
        res: Result<impl Into<ResponseMessage>, StatusCode>,
        request_handle: u32,
        request_id: u32,
    ) -> RequestProcessResult {
        let message = match res {
            Ok(m) => m.into(),
            Err(e) => {
                self.info.diagnostics.inc_rejected_requests();
                if matches!(
                    e,
                    StatusCode::BadSessionIdInvalid
                        | StatusCode::BadSecurityChecksFailed
                        | StatusCode::BadUserAccessDenied
                ) {
                    self.info.diagnostics.inc_security_rejected_requests();
                }

                ServiceFault::new(request_handle, e).into()
            }
        };
        if let Err(e) =
            self.transport
                .enqueue_message_for_send(&mut self.channel, message, request_id)
        {
            error!("Failed to send request response: {e}");
            RequestProcessResult::Close
        } else {
            RequestProcessResult::Ok
        }
    }

    fn validate_request(
        message: &RequestMessage,
        session: Option<Arc<RwLock<Session>>>,
        channel: &SecureChannel,
    ) -> Result<(u32, Arc<RwLock<Session>>, UserToken), ResponseMessage> {
        let header = message.request_header();

        let Some(session) = session else {
            return Err(ServiceFault::new(header, StatusCode::BadSessionIdInvalid).into());
        };

        let session_lock = trace_read_lock!(session);
        let id = session_lock.session_id_numeric();

        let user_token = (move || {
            let token = session_lock.validate_activated()?;
            session_lock.validate_secure_channel_id(channel.secure_channel_id())?;
            session_lock.validate_timed_out()?;
            Ok(token.clone())
        })()
        .map_err(|e| ServiceFault::new(header, e))?;
        Ok((id, session, user_token))
    }

    fn open_secure_channel(
        &mut self,
        security_header: &SecurityHeader,
        client_protocol_version: u32,
        request: &OpenSecureChannelRequest,
    ) -> Result<ResponseMessage, StatusCode> {
        let security_header = match security_header {
            SecurityHeader::Asymmetric(security_header) => security_header,
            _ => {
                error!("Secure channel request message does not have asymmetric security header");
                return Err(StatusCode::BadUnexpectedError);
            }
        };

        // Must compare protocol version to the one from HELLO
        if request.client_protocol_version != client_protocol_version {
            error!(
                "Client sent a different protocol version than it did in the HELLO - {} vs {}",
                request.client_protocol_version, client_protocol_version
            );
            return Ok(ServiceFault::new(
                &request.request_header,
                StatusCode::BadProtocolVersionUnsupported,
            )
            .into());
        }

        // Test the request type
        let secure_channel_id = match request.request_type {
            SecurityTokenRequestType::Issue => {
                trace!("Request type == Issue");
                // check to see if renew has been called before or not
                if self.secure_channel_state.renew_count > 0 {
                    error!("Asked to issue token on session that has called renew before");
                }
                self.secure_channel_state.create_secure_channel_id()
            }
            SecurityTokenRequestType::Renew => {
                trace!("Request type == Renew");

                // Check for a duplicate nonce. It is invalid for the renew to use the same nonce
                // as was used for last issue/renew. It doesn't matter when policy is none.
                if self.channel.security_policy() != SecurityPolicy::None
                    && request.client_nonce.as_ref() == self.channel.remote_nonce()
                {
                    error!("Client reused a nonce for a renew");
                    return Ok(ServiceFault::new(
                        &request.request_header,
                        StatusCode::BadNonceInvalid,
                    )
                    .into());
                }

                // check to see if the secure channel has been issued before or not
                if !self.secure_channel_state.issued {
                    error!("Asked to renew token on session that has never issued token");
                    return Err(StatusCode::BadUnexpectedError);
                }
                self.secure_channel_state.renew_count += 1;
                self.channel.secure_channel_id()
            }
        };

        // Check the requested security mode
        debug!("Message security mode == {:?}", request.security_mode);
        match request.security_mode {
            MessageSecurityMode::None
            | MessageSecurityMode::Sign
            | MessageSecurityMode::SignAndEncrypt => {
                // TODO validate NONCE
            }
            _ => {
                error!("Security mode is invalid");
                return Ok(ServiceFault::new(
                    &request.request_header,
                    StatusCode::BadSecurityModeRejected,
                )
                .into());
            }
        }

        // Process the request
        self.secure_channel_state.issued = true;

        // Create a new secure channel info
        let security_mode = request.security_mode;
        self.channel.set_security_mode(security_mode);
        self.channel
            .set_token_id(self.secure_channel_state.create_token_id());
        self.channel.set_secure_channel_id(secure_channel_id);
        self.channel
            .set_remote_cert_from_byte_string(&security_header.sender_certificate)?;

        let revised_lifetime = self
            .info
            .config
            .max_secure_channel_token_lifetime_ms
            .min(request.requested_lifetime);
        self.channel.set_token_lifetime(revised_lifetime);

        match self
            .channel
            .set_remote_nonce_from_byte_string(&request.client_nonce)
        {
            Ok(_) => self.channel.create_random_nonce(),
            Err(err) => {
                error!("Was unable to set their nonce, check logic");
                return Ok(ServiceFault::new(&request.request_header, err).into());
            }
        }

        let security_policy = self.channel.security_policy();
        if security_policy != SecurityPolicy::None
            && (security_mode == MessageSecurityMode::Sign
                || security_mode == MessageSecurityMode::SignAndEncrypt)
        {
            self.channel.derive_keys();
        }

        let response = OpenSecureChannelResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            server_protocol_version: 0,
            security_token: ChannelSecurityToken {
                channel_id: self.channel.secure_channel_id(),
                token_id: self.channel.token_id(),
                created_at: DateTime::now(),
                revised_lifetime,
            },
            server_nonce: self.channel.local_nonce_as_byte_string(),
        };
        Ok(response.into())
    }
}

struct SecureChannelState {
    // Issued flag
    issued: bool,
    // Renew count, debugging
    renew_count: usize,
    // Last secure channel id
    secure_channel_id: Arc<AtomicHandle>,
    /// Last token id number
    last_token_id: u32,
}

impl SecureChannelState {
    pub fn new(handle: Arc<AtomicHandle>) -> SecureChannelState {
        SecureChannelState {
            secure_channel_id: handle,
            issued: false,
            renew_count: 0,
            last_token_id: 0,
        }
    }

    pub fn create_secure_channel_id(&mut self) -> u32 {
        self.secure_channel_id.next()
    }

    pub fn create_token_id(&mut self) -> u32 {
        self.last_token_id += 1;
        self.last_token_id
    }
}
