#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::{
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

use chrono::Utc;
use futures::{future::Either, stream::FuturesUnordered, Future, StreamExt};
use opcua_core::{trace_read_lock, trace_write_lock, Message, RequestMessage, ResponseMessage};
use tracing::{debug, debug_span, error, trace, warn};

use opcua_core::{
    comms::{
        message_chunk::MessageChunkType,
        secure_channel::{Role, SecureChannel},
        security_header::SecurityHeader,
        tcp_types::ErrorMessage,
    },
    handle::AtomicHandle,
    sync::RwLock,
};
use opcua_crypto::{CertificateStore, SecurityPolicy};
#[cfg(feature = "discovery-mdns")]
use opcua_types::MdnsDiscoveryConfiguration;
use opcua_types::{
    ChannelSecurityToken, DateTime, ExtensionObject, FindServersOnNetworkResponse,
    FindServersResponse, GetEndpointsResponse, MessageSecurityMode, NodeId,
    OpenSecureChannelRequest, OpenSecureChannelResponse, RegisterServer2Response,
    RegisterServerResponse, ResponseHeader, SecurityTokenRequestType, ServiceFault, StatusCode,
    UAString,
};
use tokio_util::sync::CancellationToken;
use tracing_futures::Instrument;

use crate::{
    authenticator::UserToken,
    info::ServerInfo,
    node_manager::NodeManagers,
    subscriptions::SubscriptionCache,
    transport::tcp::{ConnectionTransport, Request, TransportPollResult},
    transport::Connector,
};

use super::{
    audit::{
        dispatch_activate_session, dispatch_certificate_audit, dispatch_create_session,
        dispatch_open_secure_channel, dispatch_open_secure_channel_certificate_audit,
        dispatch_response_failure, dispatch_service_failure,
        dispatch_suppressed_certificate_audit_success, AuditEventContext,
    },
    instance::Session,
    manager::{activate_session, close_session, SessionManager},
    message_handler::MessageHandler,
};

pub(crate) struct Response {
    pub message: ResponseMessage,
    pub request_id: u32,
}

impl Response {
    pub(super) fn from_result(
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

fn register_server2_configuration_result(
    info: &ServerInfo,
    server: &opcua_types::RegisteredServer,
    registration_status: StatusCode,
    configuration: &ExtensionObject,
) -> StatusCode {
    #[cfg(feature = "discovery-mdns")]
    {
        if registration_status == StatusCode::Good {
            if let Some(mdns) = configuration.inner_as::<MdnsDiscoveryConfiguration>() {
                return info.apply_register_server2_mdns_configuration(server, mdns);
            }
        }
    }

    let _ = (info, server, registration_status, configuration);
    StatusCode::BadNotSupported
}

/// Master type managing a single connection.
pub(crate) struct SessionController<T: ConnectionTransport> {
    channel: SecureChannel,
    transport: T,
    secure_channel_state: SecureChannelState,
    session_manager: Arc<RwLock<SessionManager>>,
    certificate_store: Arc<RwLock<CertificateStore>>,
    node_managers: NodeManagers,
    message_handler: MessageHandler,
    subscriptions: Arc<SubscriptionCache>,
    pending_messages: FuturesUnordered<Pin<Box<PendingMessageResponse>>>,
    max_inflight: usize,
    info: Arc<ServerInfo>,
    deadline: Instant,
}

enum RequestProcessResult {
    Ok,
    Close,
}

/// Backstop deadline for a request that specifies no timeout and where the
/// server sets no `max_timeout_ms` ceiling. Bounds how long a non-returning
/// handler can hold an in-flight slot. Publish requests use a separate path and
/// are unaffected; clients needing longer should set `request_header.timeout_hint`.
pub(crate) const DEFAULT_REQUEST_TIMEOUT_BACKSTOP_MS: u32 = 600_000;

fn effective_request_timeout(timeout_hint: u32, max_timeout_ms: u32) -> u32 {
    let timeout = if max_timeout_ms == 0 {
        timeout_hint
    } else if timeout_hint == 0 {
        max_timeout_ms
    } else {
        timeout_hint.min(max_timeout_ms)
    };

    if timeout == 0 {
        DEFAULT_REQUEST_TIMEOUT_BACKSTOP_MS
    } else {
        timeout
    }
}

/// Backstop SecureChannel token lifetime used when neither the client nor the server
/// supplies a usable value (5 minutes).
pub(crate) const DEFAULT_SECURE_CHANNEL_LIFETIME_BACKSTOP_MS: u32 = 300_000;

/// Revise the requested SecureChannel token lifetime within the configured maximum.
/// OPC UA Part 4 §5.6.2.2: "The Server shall provide a lifetime greater than 0." A client
/// that requests 0 (no preference) gets the configured maximum rather than a zero-length
/// token that would expire immediately; the result is always greater than 0.
fn revise_secure_channel_lifetime(requested_lifetime: u32, max_lifetime_ms: u32) -> u32 {
    let revised = if max_lifetime_ms == 0 {
        requested_lifetime
    } else if requested_lifetime == 0 {
        max_lifetime_ms
    } else {
        requested_lifetime.min(max_lifetime_ms)
    };

    if revised == 0 {
        DEFAULT_SECURE_CHANNEL_LIFETIME_BACKSTOP_MS
    } else {
        revised
    }
}

pub(crate) struct SessionStarter<T> {
    connector: T,
    info: Arc<ServerInfo>,
    session_manager: Arc<RwLock<SessionManager>>,
    certificate_store: Arc<RwLock<CertificateStore>>,
    node_managers: NodeManagers,
    subscriptions: Arc<SubscriptionCache>,
}

impl<T> SessionStarter<T>
where
    T: Connector,
    T::Transport: ConnectionTransport,
{
    pub(crate) fn new(
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

    pub(crate) async fn run(
        self,
        mut command: tokio::sync::mpsc::Receiver<ControllerCommand>,
        on_connect: impl FnOnce(StatusCode) + Send,
    ) {
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
                        on_connect(e);
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

impl<T: ConnectionTransport> SessionController<T> {
    fn new(
        transport: T,
        session_manager: Arc<RwLock<SessionManager>>,
        certificate_store: Arc<RwLock<CertificateStore>>,
        info: Arc<ServerInfo>,
        node_managers: NodeManagers,
        subscriptions: Arc<SubscriptionCache>,
    ) -> Self {
        let mut channel = SecureChannel::new(
            certificate_store.clone(),
            opcua_core::comms::secure_channel::Role::Server,
            Arc::new(RwLock::new(info.initial_encoding_context())),
        );
        channel.set_allow_deprecated(info.config.allow_legacy_crypto);

        Self {
            channel,
            transport,
            secure_channel_state: SecureChannelState::new(info.secure_channel_id_handle.clone()),
            session_manager,
            certificate_store,
            node_managers: node_managers.clone(),
            message_handler: MessageHandler::new(
                info.clone(),
                node_managers,
                subscriptions.clone(),
            ),
            subscriptions,
            deadline: Instant::now()
                + Duration::from_secs(info.config.tcp_config.hello_timeout as u64),
            max_inflight: info.config.limits.max_inflight_requests_per_connection,
            info,
            pending_messages: FuturesUnordered::new(),
        }
    }

    async fn run(mut self, mut command: tokio::sync::mpsc::Receiver<ControllerCommand>) {
        loop {
            let can_poll_transport =
                self.max_inflight == 0 || self.pending_messages.len() < self.max_inflight;
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
                res = self.transport.poll(&mut self.channel), if can_poll_transport => {
                    match res {
                        TransportPollResult::IncomingMessage(req) => {
                            if matches!(self.process_request(req).await, RequestProcessResult::Close) {
                                self.transport.set_closing();
                            }
                        }
                        TransportPollResult::RecoverableError(status, request_id, request_handle) => {
                            self.send_recoverable_service_fault(status, request_id, request_handle);
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
        trace_read_lock!(self.session_manager)
            .cleanup_fota_for_secure_channel(self.channel.secure_channel_id());
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

    fn session_id_for_token(&self, authentication_token: &NodeId) -> Option<NodeId> {
        let mgr = trace_read_lock!(self.session_manager);
        let session = mgr.find_by_token(authentication_token)?;
        let session = trace_read_lock!(session);
        Some(session.session_id().clone())
    }

    fn dispatch_suppressed_create_session_certificate_audits(
        &self,
        request: &opcua_types::CreateSessionRequest,
        session_id: Option<NodeId>,
    ) {
        if self.channel.security_policy() == SecurityPolicy::None
            || self.info.config.certificate_validation.check_time
        {
            return;
        }

        let Ok(cert) = opcua_crypto::X509::from_byte_string(&request.client_certificate) else {
            return;
        };
        let now = Utc::now();
        let validity_finding = match (cert.not_before(), cert.not_after()) {
            (Ok(not_before), Ok(not_after)) => now < not_before || now > not_after,
            _ => true,
        };
        if !validity_finding {
            return;
        }

        dispatch_suppressed_certificate_audit_success(
            &self.subscriptions,
            &self.info,
            &request.request_header,
            request.client_certificate.clone(),
            session_id,
            StatusCode::BadCertificateTimeInvalid,
        );
    }

    fn fatal_error(&mut self, err: StatusCode, msg: &str) {
        if !self.transport.is_closing() {
            self.transport.enqueue_error(ErrorMessage::new(err, msg));
        }
        self.transport.set_closing();
    }

    fn send_recoverable_service_fault(
        &mut self,
        status: StatusCode,
        request_id: u32,
        request_handle: u32,
    ) {
        warn!(
            "Non-fatal transport error: {status}, with request id {request_id}, request handle {request_handle}"
        );
        let msg = ServiceFault::new(request_handle, status).into();
        if let Err(e) = self
            .transport
            .enqueue_message_for_send(&mut self.channel, msg, request_id)
        {
            error!("Failed to send response: {e}");
            self.fatal_error(e, "Encoding error");
        }
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
                    self.transport.client_protocol_version(),
                    &r,
                );
                let osc_status = match &res {
                    Err(status) => *status,
                    Ok(ResponseMessage::ServiceFault(fault)) => {
                        fault.response_header.service_result
                    }
                    Ok(_) => StatusCode::Good,
                };
                let client_certificate = match &req.chunk_info.security_header {
                    SecurityHeader::Asymmetric(header) => header.sender_certificate.clone(),
                    _ => opcua_types::ByteString::null(),
                };
                dispatch_open_secure_channel(
                    &self.subscriptions,
                    &self.info,
                    &r.request_header,
                    self.channel.secure_channel_id(),
                    client_certificate,
                    r.request_type as i32,
                    self.channel.security_policy().to_uri(),
                    r.security_mode as i32,
                    r.requested_lifetime,
                    osc_status,
                );
                if res.is_ok() {
                    self.deadline = self.channel.token_renewal_deadline();
                } else {
                    self.info.diagnostics.inc_rejected_requests();
                    self.info.diagnostics.inc_security_rejected_requests();
                }
                match res {
                    Ok(mut response) => {
                        response.apply_return_diagnostics(r.request_header.return_diagnostics);
                        match self.transport.enqueue_message_for_send_with_message_type(
                            &mut self.channel,
                            response,
                            id,
                            MessageChunkType::OpenSecureChannel,
                        ) {
                            Ok(_) => RequestProcessResult::Ok,
                            Err(e) => {
                                error!("Failed to send open secure channel response: {e}");
                                RequestProcessResult::Close
                            }
                        }
                    }
                    Err(e) => {
                        let mut fault: ResponseMessage =
                            ServiceFault::new(&r.request_header, e).into();
                        fault.apply_return_diagnostics(r.request_header.return_diagnostics);
                        let _ =
                            self.transport
                                .enqueue_message_for_send(&mut self.channel, fault, id);
                        RequestProcessResult::Close
                    }
                }
            }

            RequestMessage::CloseSecureChannel(_r) => RequestProcessResult::Close,

            RequestMessage::CreateSession(request) => {
                let _h = span.enter();
                let mut mgr = trace_write_lock!(self.session_manager);
                let res = mgr.create_session(
                    &mut self.channel,
                    &self.certificate_store,
                    self.node_managers.clone(),
                    self.subscriptions.clone(),
                    &request,
                );
                drop(mgr);
                let (session_id, revised_timeout, status) = match &res {
                    Ok(response) => (
                        Some(response.session_id.clone()),
                        Some(response.revised_session_timeout),
                        StatusCode::Good,
                    ),
                    Err(status) => (None, None, *status),
                };
                dispatch_create_session(
                    &self.subscriptions,
                    &self.info,
                    &request,
                    session_id.clone(),
                    self.channel.secure_channel_id(),
                    revised_timeout,
                    status,
                );
                // A client-certificate validation failure also emits the matching
                // AuditCertificateEventType subtype (no-op for non-certificate failures).
                if status.is_bad() {
                    dispatch_certificate_audit(
                        &self.subscriptions,
                        &self.info,
                        &request.request_header,
                        request.client_certificate.clone(),
                        None,
                        status,
                    );
                } else {
                    self.dispatch_suppressed_create_session_certificate_audits(
                        &request, session_id,
                    );
                }
                self.process_service_result(
                    res,
                    request.request_header.request_handle,
                    request.request_header.return_diagnostics,
                    id,
                )
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
                let status = match &res {
                    Ok(_) => StatusCode::Good,
                    Err(status) => *status,
                };
                let session_id =
                    self.session_id_for_token(&request.request_header.authentication_token);
                dispatch_activate_session(
                    &self.subscriptions,
                    &self.info,
                    &request,
                    session_id,
                    self.channel.secure_channel_id(),
                    status,
                );
                let _h = span.enter();
                self.process_service_result(
                    res,
                    request.request_header.request_handle,
                    request.request_header.return_diagnostics,
                    id,
                )
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
                self.process_service_result(
                    res,
                    request.request_header.request_handle,
                    request.request_header.return_diagnostics,
                    id,
                )
            }
            RequestMessage::GetEndpoints(request) => {
                // GetEndpoints is a pre-session discovery service that cannot fail here (it always
                // returns the filtered endpoint list), so there is no failure to audit.
                let _h = span.enter();
                let endpoints = self.info.get_endpoints_with_filters(
                    &request.endpoint_url,
                    &request.profile_uris,
                    &request.locale_ids,
                );
                self.process_service_result(
                    Ok(GetEndpointsResponse {
                        response_header: ResponseHeader::new_good(&request.request_header),
                        endpoints,
                    }),
                    request.request_header.request_handle,
                    request.request_header.return_diagnostics,
                    id,
                )
            }
            RequestMessage::FindServers(request) => {
                let _h = span.enter();
                let mut servers = if self
                    .info
                    .matches_find_servers_filters(&request.endpoint_url, &request.locale_ids)
                {
                    vec![self
                        .info
                        .find_servers_application_description(&request.endpoint_url)]
                } else {
                    Vec::new()
                };
                servers.extend(self.info.registered_application_descriptions(
                    &request.endpoint_url,
                    &request.locale_ids,
                ));

                // Filter servers that do not have a matching application uri
                if let Some(ref server_uris) = request.server_uris {
                    if !server_uris.is_empty() {
                        // Filter the servers down
                        servers.retain(|server| server_uris.contains(&server.application_uri));
                    }
                }

                let servers = Some(servers);

                self.process_service_result(
                    Ok(FindServersResponse {
                        response_header: ResponseHeader::new_good(&request.request_header),
                        servers,
                    }),
                    request.request_header.request_handle,
                    request.request_header.return_diagnostics,
                    id,
                )
            }
            RequestMessage::FindServersOnNetwork(request) => {
                let _h = span.enter();
                // Pull-based (no-mDNS) FindServersOnNetwork (Part 4 §5.5.3): report servers registered
                // via RegisterServer(2). Full LDS-ME multicast discovery is deferred.
                let servers = self.info.find_servers_on_network(
                    request.starting_record_id,
                    request.max_records_to_return,
                    &request.server_capability_filter,
                );
                self.process_service_result(
                    Ok(FindServersOnNetworkResponse {
                        response_header: ResponseHeader::new_good(&request.request_header),
                        last_counter_reset_time: DateTime::null(),
                        servers: Some(servers),
                    }),
                    request.request_header.request_handle,
                    request.request_header.return_diagnostics,
                    id,
                )
            }
            RequestMessage::RegisterServer(request) => {
                let _h = span.enter();
                let status = match self.register_server_caller_status(&request.server.server_uri) {
                    StatusCode::Good => self.info.apply_register_server(request.server.clone()),
                    e => e,
                };
                #[cfg(feature = "discovery-mdns")]
                if status == StatusCode::Good && !request.server.is_online {
                    self.info.remove_registered_mdns(&request.server.server_uri);
                }
                let mut message: ResponseMessage = RegisterServerResponse {
                    response_header: ResponseHeader::new_service_result(
                        &request.request_header,
                        status,
                    ),
                }
                .into();
                message.apply_return_diagnostics(request.request_header.return_diagnostics);
                if let Err(e) =
                    self.transport
                        .enqueue_message_for_send(&mut self.channel, message, id)
                {
                    error!("Failed to send request response: {e}");
                    RequestProcessResult::Close
                } else {
                    RequestProcessResult::Ok
                }
            }
            RequestMessage::RegisterServer2(request) => {
                let _h = span.enter();
                let status = match self.register_server_caller_status(&request.server.server_uri) {
                    StatusCode::Good => self.info.apply_register_server(request.server.clone()),
                    e => e,
                };
                let configuration_results =
                    request
                        .discovery_configuration
                        .as_ref()
                        .map(|configurations| {
                            configurations
                                .iter()
                                .map(|configuration| {
                                    register_server2_configuration_result(
                                        &self.info,
                                        &request.server,
                                        status,
                                        configuration,
                                    )
                                })
                                .collect()
                        });
                #[cfg(feature = "discovery-mdns")]
                if status == StatusCode::Good && !request.server.is_online {
                    self.info.remove_registered_mdns(&request.server.server_uri);
                }
                let mut message: ResponseMessage = RegisterServer2Response {
                    response_header: ResponseHeader::new_service_result(
                        &request.request_header,
                        status,
                    ),
                    configuration_results,
                    diagnostic_infos: None,
                }
                .into();
                message.apply_return_diagnostics(request.request_header.return_diagnostics);
                if let Err(e) =
                    self.transport
                        .enqueue_message_for_send(&mut self.channel, message, id)
                {
                    error!("Failed to send request response: {e}");
                    RequestProcessResult::Close
                } else {
                    RequestProcessResult::Ok
                }
            }

            message => {
                let _h = span.enter();
                let now = Instant::now();
                let unauthenticated_audit_context = AuditEventContext::new(
                    message.type_name(),
                    message.request_header(),
                    None,
                    None,
                );
                let return_diagnostics = message.request_header().return_diagnostics;
                let mgr = trace_read_lock!(self.session_manager);
                let session = mgr.find_by_token(&message.request_header().authentication_token);
                let actor_sender = mgr.actor_sender(&message.request_header().authentication_token);
                let session_was_closed =
                    mgr.is_closed_token(&message.request_header().authentication_token);

                let (session_id, session, user_token) = match Self::validate_request(
                    &message,
                    session,
                    session_was_closed,
                    &self.channel,
                ) {
                    Ok(s) => s,
                    Err(mut e) => {
                        e.apply_return_diagnostics(return_diagnostics);
                        self.info.diagnostics.inc_rejected_requests();
                        self.info.diagnostics.inc_security_rejected_requests();
                        dispatch_service_failure(
                            &self.subscriptions,
                            &self.info,
                            &unauthenticated_audit_context,
                            e.response_header().service_result,
                        );
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
                let audit_context = AuditEventContext::new(
                    message.type_name(),
                    message.request_header(),
                    Some(UAString::from(user_token.0.clone())),
                    Some(trace_read_lock!(session).session_id().clone()),
                );

                let deadline = {
                    let timeout = message.request_header().timeout_hint;
                    let max_timeout = self.info.config.max_timeout_ms;
                    let timeout = effective_request_timeout(timeout, max_timeout);
                    now + Duration::from_millis(timeout.into())
                };
                let request_handle = message.request_handle();

                match self.message_handler.handle_message(
                    message,
                    session_id,
                    session,
                    user_token,
                    id,
                    actor_sender,
                ) {
                    super::message_handler::HandleMessageResult::AsyncMessage(mut handle) => {
                        let audit_context = audit_context.clone();
                        let info = self.info.clone();
                        let subscriptions = self.subscriptions.clone();
                        self.pending_messages
                            .push(Box::pin(async move {
                                // Select biased because if for some reason there's a long time between polls,
                                // we want to return the response even if the timeout expired. We only want to send a timeout
                                // if the call has not been finished yet.
                                let mut response = tokio::select! {
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
                                };
                                if let Ok(response) = &mut response {
                                    response.message.apply_return_diagnostics(return_diagnostics);
                                    dispatch_response_failure(
                                        &subscriptions,
                                        &info,
                                        &audit_context,
                                        &response.message,
                                    );
                                }
                                response
                            }.instrument(span.clone())));
                        RequestProcessResult::Ok
                    }
                    super::message_handler::HandleMessageResult::SyncMessage(mut s) => {
                        s.message.apply_return_diagnostics(return_diagnostics);
                        debug!(
                            status_code = %s.message.response_header().service_result,
                            "Sending response of type {}", s.message.type_name()
                        );
                        self.response_metrics(&s);
                        dispatch_response_failure(
                            &self.subscriptions,
                            &self.info,
                            &audit_context,
                            &s.message,
                        );

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
                }
            }
        }
    }

    /// OPC UA Part 12 §7.5 / Part 4 §5.5.5: a RegisterServer(2) call must be authenticated.
    /// The SecureChannel must be secured and its client ApplicationInstanceCertificate must
    /// belong to the server being registered (its applicationUri must match the serverUri),
    /// otherwise any client could register or unregister arbitrary servers (spoofing or a
    /// discovery denial-of-service by unregistering a victim). Returns `Good` when the caller
    /// is allowed to (un)register `server_uri`.
    fn register_server_caller_status(&self, server_uri: &UAString) -> StatusCode {
        if self.channel.security_policy() == SecurityPolicy::None {
            return StatusCode::BadSecurityChecksFailed;
        }
        let Some(cert) = self.channel.remote_cert() else {
            return StatusCode::BadSecurityChecksFailed;
        };
        if cert.is_application_uri_valid(server_uri.as_ref()).is_err() {
            return StatusCode::BadServerUriInvalid;
        }
        StatusCode::Good
    }

    fn process_service_result(
        &mut self,
        res: Result<impl Into<ResponseMessage>, StatusCode>,
        request_handle: u32,
        return_diagnostics: opcua_types::DiagnosticBits,
        request_id: u32,
    ) -> RequestProcessResult {
        let mut message = match res {
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
        message.apply_return_diagnostics(return_diagnostics);
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
        session_was_closed: bool,
        channel: &SecureChannel,
    ) -> Result<(u32, Arc<RwLock<Session>>, UserToken), ResponseMessage> {
        let header = message.request_header();

        let Some(session) = session else {
            if session_was_closed {
                return Err(ServiceFault::new(header, StatusCode::BadSessionClosed).into());
            }
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
                let issued_policy = self.channel.security_policy();
                if issued_policy.is_deprecated() {
                    tracing::warn!(
                        "Connection established with deprecated security policy {issued_policy}. \
                         This policy is allowed by allow_legacy_crypto but should be migrated."
                    );
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
                    // Part 4 §5.6.2 Table 12: a Renew with no valid SecureChannel returns
                    // Bad_SecureChannelIdInvalid, not the generic Bad_UnexpectedError.
                    return Err(StatusCode::BadSecureChannelIdInvalid);
                }
                self.secure_channel_state.renew_count += 1;
                self.channel.secure_channel_id()
            }
        };

        // Check the requested security mode
        debug!("Message security mode == {:?}", request.security_mode);
        if matches!(request.security_mode, MessageSecurityMode::Invalid) {
            error!("Security mode is invalid");
            return Ok(ServiceFault::new(
                &request.request_header,
                StatusCode::BadSecurityModeRejected,
            )
            .into());
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

        // Validate the client's ApplicationInstanceCertificate trust (Part 4 §6.1.3) when the
        // SecureChannel is created/renewed, not only at CreateSession (§6.1.4/§6.1.7). An
        // untrusted/expired/revoked certificate must be rejected here. The applicationUri match is a
        // CreateSession-level check (the clientDescription is not available yet), so pass None for it;
        // CreateSession still performs the URI check. Failures map to Bad_SecurityChecksFailed for the
        // client (per §6.1.3).
        if self.channel.security_policy() != SecurityPolicy::None {
            if let Some(cert) = self.channel.remote_cert() {
                let security_policy = self.channel.security_policy();
                let validation_result = {
                    let store = trace_read_lock!(self.certificate_store);
                    store.validate_or_reject_application_instance_cert(
                        &cert,
                        security_policy,
                        None,
                        None,
                    )
                };
                if let Err(e) = validation_result {
                    let validation_status = e.status();
                    error!("OpenSecureChannel rejected: client certificate failed validation: {e}");
                    dispatch_open_secure_channel_certificate_audit(
                        &self.subscriptions,
                        &self.info,
                        &request.request_header,
                        security_header.sender_certificate.clone(),
                        validation_status,
                    );
                    return Ok(ServiceFault::new(
                        &request.request_header,
                        StatusCode::BadSecurityChecksFailed,
                    )
                    .into());
                }
            }
        }

        let revised_lifetime = revise_secure_channel_lifetime(
            request.requested_lifetime,
            self.info.config.max_secure_channel_token_lifetime_ms,
        );
        self.channel.set_token_lifetime(revised_lifetime);

        self.channel
            .validate_secure_channel_nonce_length(&request.client_nonce)?;
        self.channel
            .set_remote_nonce_from_byte_string(&request.client_nonce)?;
        self.channel.set_role(Role::Server);
        #[cfg(feature = "ecc")]
        if self.channel.security_policy().is_ecc() {
            self.channel.set_apply_channel_thumbprint(
                request.request_type == SecurityTokenRequestType::Issue,
            );
        }
        self.channel.create_local_nonce()?;

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
        match request.request_type {
            SecurityTokenRequestType::Issue => self.info.metrics.record_secure_channel_opened(),
            SecurityTokenRequestType::Renew => self.info.metrics.record_secure_channel_renewed(),
        }
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
    fn new(handle: Arc<AtomicHandle>) -> SecureChannelState {
        SecureChannelState {
            secure_channel_id: handle,
            issued: false,
            renew_count: 0,
            last_token_id: 0,
        }
    }

    fn create_secure_channel_id(&mut self) -> u32 {
        self.secure_channel_id.next()
    }

    fn create_token_id(&mut self) -> u32 {
        self.last_token_id += 1;
        self.last_token_id
    }
}

#[cfg(test)]
mod tests {
    use super::{
        effective_request_timeout, revise_secure_channel_lifetime,
        DEFAULT_REQUEST_TIMEOUT_BACKSTOP_MS, DEFAULT_SECURE_CHANNEL_LIFETIME_BACKSTOP_MS,
    };

    /// OPC UA Part 4 §5.6.2.2: "The Server shall provide a lifetime greater than 0."
    /// The revised SecureChannel token lifetime must never be 0, even when the client
    /// requests 0 (no preference).
    #[test]
    fn revised_secure_channel_lifetime_is_never_zero() {
        // Client requests 0 -> use the configured maximum (the bug being fixed: min(max, 0) = 0).
        assert_eq!(revise_secure_channel_lifetime(0, 300_000), 300_000);
        // Client below the cap -> honored.
        assert_eq!(revise_secure_channel_lifetime(60_000, 300_000), 60_000);
        // Client exceeds the cap -> capped.
        assert_eq!(revise_secure_channel_lifetime(600_000, 300_000), 300_000);
        // No configured cap -> honor the client's value.
        assert_eq!(revise_secure_channel_lifetime(60_000, 0), 60_000);
        // Neither side supplies a usable value -> bounded backstop, still > 0.
        assert_eq!(
            revise_secure_channel_lifetime(0, 0),
            DEFAULT_SECURE_CHANNEL_LIFETIME_BACKSTOP_MS
        );
        assert!(revise_secure_channel_lifetime(0, 300_000) > 0);
    }

    /// H2: `max_timeout_ms` must act as a CEILING on the client's `timeout_hint`,
    /// never a floor.
    #[test]
    fn request_timeout_is_capped_not_floored() {
        // In-flight hold hardening: no client hint and no server cap still gets
        // a bounded async request backstop.
        assert_eq!(
            effective_request_timeout(0, 0),
            DEFAULT_REQUEST_TIMEOUT_BACKSTOP_MS
        );
        // No configured cap -> honor the client's hint.
        assert_eq!(effective_request_timeout(5_000, 0), 5_000);
        // Client sends 0 -> use the cap as the default.
        assert_eq!(effective_request_timeout(0, 3_000), 3_000);
        // Client exceeds the cap -> capped at the maximum (the bug being fixed).
        assert_eq!(effective_request_timeout(60_000, 3_000), 3_000);
        // Client below the cap -> honored.
        assert_eq!(effective_request_timeout(1_000, 3_000), 1_000);
    }
}
