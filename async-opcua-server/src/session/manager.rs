use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use dashmap::DashMap;
use futures::FutureExt;
use opcua_core::{comms::secure_channel::SecureChannel, trace_read_lock, trace_write_lock};
use opcua_crypto::{random, CertificateStore, SecurityPolicy};
use parking_lot::RwLock;
use tokio::sync::{mpsc, Notify};
use tracing::{error, info};

use crate::{
    authenticator::UserToken,
    config::ANONYMOUS_USER_TOKEN_ID,
    fota::cleanup::cleanup_session,
    identity_token::IdentityToken,
    info::ServerInfo,
    node_manager::{NodeManagers, RequestContext, RequestContextInner},
    subscriptions::SubscriptionCache,
};
use opcua_types::{
    ActivateSessionRequest, ActivateSessionResponse, CloseSessionRequest, CloseSessionResponse,
    CreateSessionRequest, CreateSessionResponse, Error, NodeId, ResponseHeader, SignatureData,
    StatusCode,
};

use super::{
    actor::{SessionActor, SessionMessage},
    instance::Session,
    message_handler::MessageHandler,
};

static NEXT_SESSION_ID: AtomicU32 = AtomicU32::new(1);
const SESSION_ACTOR_QUEUE_CAPACITY: usize = 256;

pub(super) fn next_session_id() -> (NodeId, u32) {
    // Session id will be a string identifier
    let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    (NodeId::new(1, session_id), session_id)
}

/// Manages all sessions on the server.
pub struct SessionManager {
    sessions: HashMap<NodeId, Arc<RwLock<Session>>>,
    /// O(1) lock-free lookup from authentication token to session,
    /// avoiding a linear scan of `sessions` on every request.
    auth_tokens: Arc<DashMap<NodeId, Arc<RwLock<Session>>>>,
    /// Lock-free lookup from authentication token to the session actor's
    /// message queue.
    actor_senders: Arc<DashMap<NodeId, mpsc::Sender<SessionMessage>>>,
    info: Arc<ServerInfo>,
    notify: Arc<Notify>,
}

impl SessionManager {
    /// Create a session manager for the supplied server information and expiry notifier.
    pub fn new(info: Arc<ServerInfo>, notify: Arc<Notify>) -> Self {
        Self {
            sessions: Default::default(),
            auth_tokens: Default::default(),
            actor_senders: Default::default(),
            info,
            notify,
        }
    }

    /// Get a session by its authentication token.
    pub fn find_by_token(&self, authentication_token: &NodeId) -> Option<Arc<RwLock<Session>>> {
        let lookup_start = Instant::now();
        let session = self
            .auth_tokens
            .get(authentication_token)
            .map(|session| Arc::clone(session.value()));
        let lookup_duration_ns = lookup_start.elapsed().as_nanos() as u64;

        crate::metrics::METRICS
            .session_lookup_count
            .fetch_add(1, Ordering::Relaxed);
        crate::metrics::METRICS
            .session_lookup_duration_ns
            .fetch_add(lookup_duration_ns, Ordering::Relaxed);

        session
    }

    /// Register an authentication token for direct session lookup.
    pub fn register_token(&self, token: NodeId, session: Arc<RwLock<Session>>) {
        self.auth_tokens.insert(token, session);
    }

    /// Remove an authentication token from the direct session lookup registry.
    pub fn deregister_token(&self, token: &NodeId) {
        self.actor_senders.remove(token);
        self.auth_tokens.remove(token);
    }

    #[allow(dead_code)]
    pub(crate) fn actor_sender(
        &self,
        authentication_token: &NodeId,
    ) -> Option<mpsc::Sender<SessionMessage>> {
        self.actor_senders
            .get(authentication_token)
            .map(|sender| sender.value().clone())
    }

    fn register_actor_sender(
        &self,
        authentication_token: NodeId,
        sender: mpsc::Sender<SessionMessage>,
    ) {
        self.actor_senders.insert(authentication_token, sender);
    }

    fn spawn_session_actor(
        &self,
        authentication_token: NodeId,
        session: Arc<RwLock<Session>>,
        session_id_numeric: u32,
        node_managers: NodeManagers,
        subscriptions: Arc<SubscriptionCache>,
    ) {
        let (sender, receiver) = mpsc::channel(SESSION_ACTOR_QUEUE_CAPACITY);
        self.register_actor_sender(authentication_token.clone(), sender);

        let context = RequestContext {
            current_node_manager_index: 0,
            inner: Arc::new(RequestContextInner {
                session,
                session_id: session_id_numeric,
                authenticator: self.info.authenticator.clone(),
                token: UserToken(ANONYMOUS_USER_TOKEN_ID.to_string()),
                type_tree: self.info.type_tree.clone(),
                type_tree_getter: self.info.type_tree_getter.clone(),
                subscriptions,
                info: self.info.clone(),
            }),
        };

        let auth_tokens = Arc::clone(&self.auth_tokens);
        let actor_senders = Arc::clone(&self.actor_senders);
        let mut actor =
            SessionActor::new(context, receiver).with_termination_cleanup(move |terminated| {
                auth_tokens.remove(&terminated.authentication_token);
                actor_senders.remove(&terminated.authentication_token);
                cleanup_session(&terminated.session_id);
            });

        tokio::spawn(async move {
            // Catch panics so a dying actor always cleans its tokens out of
            // the lookup registries.
            match std::panic::AssertUnwindSafe(actor.run(node_managers))
                .catch_unwind()
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(err)) => tracing::debug!(%err, "session actor stopped"),
                Err(_) => actor.abort_after_panic(),
            }
        });
    }

    pub(crate) fn create_session(
        &mut self,
        channel: &mut SecureChannel,
        certificate_store: &RwLock<CertificateStore>,
        node_managers: NodeManagers,
        subscriptions: Arc<SubscriptionCache>,
        request: &CreateSessionRequest,
    ) -> Result<CreateSessionResponse, StatusCode> {
        if self.sessions.len() >= self.info.config.limits.max_sessions {
            return Err(StatusCode::BadTooManySessions);
        }

        // TODO: Auditing and diagnostics.
        let endpoints = self
            .info
            .new_endpoint_descriptions(request.endpoint_url.as_ref());
        // TODO request.endpoint_url should match hostname of server application certificate
        // Find matching end points for this url
        if request.endpoint_url.is_empty() {
            error!("Create session was passed an null endpoint url");
            return Err(StatusCode::BadTcpEndpointUrlInvalid);
        }

        let Some(endpoints) = endpoints else {
            return Err(StatusCode::BadTcpEndpointUrlInvalid);
        };

        self.info
            .validate_endpoint_hostname(request.endpoint_url.as_ref())?;

        let security_policy = channel.security_policy();

        if !matches!(security_policy, SecurityPolicy::None)
            && request.client_nonce.len() < self.info.config.session_nonce_length
        {
            error!("Create session was passed a client nonce that is too short, expected at least {} bytes, got {}", 
                self.info.config.session_nonce_length, request.client_nonce.len()
            );
            return Err(StatusCode::BadNonceInvalid);
        }

        let client_certificate = if security_policy != SecurityPolicy::None {
            let cert = opcua_crypto::X509::from_byte_string(&request.client_certificate)?;
            let store = trace_read_lock!(certificate_store);
            store.validate_or_reject_application_instance_cert(
                &cert,
                security_policy,
                None,
                None,
            )?;
            Some(cert)
        } else {
            None
        };

        let session_timeout = self
            .info
            .config
            .max_session_timeout_ms
            .min(request.requested_session_timeout.floor() as u64);
        let max_request_message_size = self.info.config.limits.max_message_size as u32;

        let server_pkey = self.info.server_pkey.read();
        let server_signature = if let Some(ref pkey) = *server_pkey {
            opcua_crypto::create_signature_data(
                pkey,
                security_policy,
                &request.client_certificate,
                &request.client_nonce,
            )
            .unwrap_or_else(|err| {
                error!(
                    "Cannot create signature data from private key, check log and error {:?}",
                    err
                );
                SignatureData::null()
            })
        } else {
            SignatureData::null()
        };

        let authentication_token = NodeId::new(0, random::byte_string(32));
        let server_nonce = random::byte_string(self.info.config.session_nonce_length);
        let server_certificate = self.info.server_certificate_as_byte_string();
        let server_endpoints = Some(endpoints);

        let session = Session::create(
            &self.info,
            authentication_token.clone(),
            channel.secure_channel_id(),
            session_timeout,
            max_request_message_size,
            request.max_response_message_size,
            request.endpoint_url.clone(),
            security_policy.to_uri().to_string(),
            IdentityToken::None,
            client_certificate,
            server_nonce.clone(),
            request.session_name.clone(),
            request.client_description.clone(),
            channel.security_mode(),
        );
        info!("Created new session with ID {}", session.session_id());

        let session_id = session.session_id().clone();
        let session_id_numeric = session.session_id_numeric();
        let session_arc = Arc::new(RwLock::new(session));
        self.sessions
            .insert(session_id.clone(), session_arc.clone());
        self.register_token(authentication_token.clone(), session_arc.clone());
        self.spawn_session_actor(
            authentication_token.clone(),
            session_arc,
            session_id_numeric,
            node_managers,
            subscriptions,
        );

        // Increment metrics.
        self.info
            .diagnostics
            .set_current_session_count(self.sessions.len() as u32);
        self.info.diagnostics.inc_session_count();

        self.notify.notify_waiters();

        Ok(CreateSessionResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            session_id,
            authentication_token,
            revised_session_timeout: session_timeout as f64,
            server_nonce,
            server_certificate,
            server_endpoints,
            server_software_certificates: None,
            server_signature,
            max_request_message_size,
        })
    }

    fn verify_client_signature(
        security_policy: SecurityPolicy,
        info: &ServerInfo,
        session: &Session,
        client_signature: &SignatureData,
    ) -> Result<(), Error> {
        if let Some(client_certificate) = session.client_certificate() {
            let server_cert = info.server_certificate.read();
            if let Some(ref server_certificate) = *server_cert {
                opcua_crypto::verify_signature_data(
                    client_signature,
                    security_policy,
                    client_certificate,
                    server_certificate,
                    session.session_nonce().as_ref(),
                )?;
                Ok(())
            } else {
                Err(Error::new(
                    StatusCode::BadUnexpectedError,
                    "Client signature verification failed, server has no server certificate",
                ))
            }
        } else {
            Err(Error::new(
                StatusCode::BadUnexpectedError,
                "Client signature verification failed, session has no client certificate",
            ))
        }
    }

    pub(crate) fn expire_session(&mut self, id: &NodeId) {
        let Some(session) = self.sessions.remove(id) else {
            return;
        };
        self.info
            .diagnostics
            .set_current_session_count(self.sessions.len() as u32);
        self.info.diagnostics.inc_session_timeout_count();

        info!("Session {id} has expired, removing it from the session map. Subscriptions will remain until they individually expire");

        let token = {
            let session = trace_read_lock!(session);
            session.authentication_token.clone()
        };
        self.deregister_token(&token);

        let mut session = trace_write_lock!(session);
        session.close();
        drop(session);
        cleanup_session(id);
    }

    pub(crate) fn cleanup_fota_for_secure_channel(&self, secure_channel_id: u32) {
        let session_ids = self
            .sessions
            .iter()
            .filter_map(|(id, session)| {
                let session = trace_read_lock!(session);
                (session.secure_channel_id() == secure_channel_id).then(|| id.clone())
            })
            .collect::<Vec<_>>();

        for session_id in session_ids {
            cleanup_session(&session_id);
        }
    }

    pub(crate) fn check_session_expiry(&self) -> (Instant, Vec<NodeId>) {
        let now = Instant::now();
        let mut expired = Vec::new();
        let mut expiry = now + Duration::from_millis(self.info.config.max_session_timeout_ms);
        for (id, session) in &self.sessions {
            let deadline = session.read().deadline();
            if deadline < now {
                expired.push(id.clone());
            } else if deadline < expiry {
                expiry = deadline;
            }
        }

        (expiry, expired)
    }
}

// This is a non-self method to avoid holding the manager
// across an await point.
pub(crate) async fn close_session(
    mgr_lck: &RwLock<SessionManager>,
    channel: &mut SecureChannel,
    handler: &mut MessageHandler,
    request: &CloseSessionRequest,
) -> Result<CloseSessionResponse, StatusCode> {
    let (session, id, token, actor_sender) = {
        let mgr = trace_read_lock!(mgr_lck);
        let Some(session) = mgr.find_by_token(&request.request_header.authentication_token) else {
            return Err(StatusCode::BadSessionIdInvalid);
        };
        let (id, token, authentication_token) = {
            let session = trace_read_lock!(session);
            let id = session.session_id_numeric();
            let token = session.user_token().cloned();
            let authentication_token = session.authentication_token.clone();

            let secure_channel_id = channel.secure_channel_id();
            if !session.is_activated() && session.secure_channel_id() != secure_channel_id {
                error!("close_session rejected, secure channel id {} for inactive session does not match one used to create session, {}", secure_channel_id, session.secure_channel_id());
                return Err(StatusCode::BadSecureChannelIdInvalid);
            }
            (id, token, authentication_token)
        };

        let Some(actor_sender) = mgr.actor_sender(&authentication_token) else {
            return Err(StatusCode::BadSessionClosed);
        };

        (session, id, token, actor_sender)
    };

    let (acknowledge, acknowledged) = tokio::sync::oneshot::channel();
    actor_sender
        .send(SessionMessage::Terminate {
            reason: StatusCode::Good,
            acknowledge,
        })
        .await
        .map_err(|_| StatusCode::BadSessionClosed)?;

    let terminated = acknowledged
        .await
        .map_err(|_| StatusCode::BadSessionClosed)?;
    {
        let mut mgr = trace_write_lock!(mgr_lck);
        mgr.sessions.remove(&terminated.session_id);
        mgr.info
            .diagnostics
            .set_current_session_count(mgr.sessions.len() as u32);
    }
    info!("Closed session with ID {}", terminated.session_id);

    if request.delete_subscriptions {
        if let Some(token) = token {
            handler
                .delete_session_subscriptions(id, session, token)
                .await;
        }
        // The token might be None if the session was never activated. No need to delete subscriptions in that case.
    }

    Ok(CloseSessionResponse {
        response_header: ResponseHeader::new_good(&request.request_header),
    })
}

pub(crate) async fn activate_session(
    mgr_lck: &RwLock<SessionManager>,
    channel: &mut SecureChannel,
    request: &ActivateSessionRequest,
    handler: &mut MessageHandler,
) -> Result<ActivateSessionResponse, StatusCode> {
    let security_policy = channel.security_policy();
    let security_mode = channel.security_mode();
    let secure_channel_id = channel.secure_channel_id();
    let server_nonce = security_policy.random_nonce();
    let (endpoint_url, session_nonce, session_lck, info) = {
        let mgr = trace_read_lock!(mgr_lck);
        let Some(session_lck) = mgr.find_by_token(&request.request_header.authentication_token)
        else {
            return Err(StatusCode::BadSessionIdInvalid);
        };

        let (endpoint_url, session_nonce) = {
            let session = trace_read_lock!(session_lck);
            session.validate_timed_out()?;

            let endpoint_url = session.endpoint_url().to_string();

            if !mgr
                .info
                .endpoint_exists(&endpoint_url, security_policy, security_mode)
            {
                error!("activate_session, Endpoint dues not exist for requested url & mode {}, {:?} / {:?}",
                endpoint_url, security_policy, security_mode);
                return Err(StatusCode::BadTcpEndpointUrlInvalid);
            }

            if security_policy != SecurityPolicy::None {
                SessionManager::verify_client_signature(
                    security_policy,
                    &mgr.info,
                    &session,
                    &request.client_signature,
                )?;
            }
            (endpoint_url, session.session_nonce().clone())
        };
        (endpoint_url, session_nonce, session_lck, mgr.info.clone())
    };

    let (user_token, claims) = info
        .authenticate_endpoint(
            request,
            &endpoint_url,
            security_policy,
            security_mode,
            request.user_identity_token.clone(),
            &session_nonce,
        )
        .await?;

    let (server_nonce, session_id, user_changed) = {
        let mut session = trace_write_lock!(session_lck);

        if !session.is_activated() && session.secure_channel_id() != secure_channel_id {
            error!("activate session, rejected secure channel id {} for inactive session does not match one used to create session, {}", secure_channel_id, session.secure_channel_id());
            return Err(StatusCode::BadSecureChannelIdInvalid);
        } else {
            // TODO additional secure channel validation here for client certificate and user identity
            //  token
        }

        let user_changed = session
            .user_token()
            .is_some_and(|previous| previous != &user_token);
        session.activate(
            secure_channel_id,
            server_nonce,
            IdentityToken::new(request.user_identity_token.clone()),
            request.locale_ids.clone(),
            user_token.clone(),
            claims,
        );
        (
            session.session_nonce().clone(),
            session.session_id_numeric(),
            user_changed,
        )
    };

    let namespaces =
        handler.get_namespaces_for_user(session_lck.clone(), session_id, user_token.clone());
    {
        channel.set_namespaces(namespaces);
    }

    if user_changed {
        handler
            .revalidate_monitored_items_for_user(session_lck, session_id, user_token)
            .await;
    }

    // TODO: Audit

    Ok(ActivateSessionResponse {
        response_header: ResponseHeader::new_good(&request.request_header),
        server_nonce,
        results: None,
        diagnostic_infos: None,
    })
}
