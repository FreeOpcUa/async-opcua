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

/// Returns true if activating a session on `request_channel_id` must be refused
/// because it differs from the channel the session belongs to and the session
/// either is not yet activated or uses SecurityPolicy::None (which has no
/// cryptographic channel binding, so cross-channel transfer would be a hijack).
pub(crate) fn is_cross_channel_transfer_forbidden(
    session_channel_id: u32,
    request_channel_id: u32,
    session_activated: bool,
    security_policy: SecurityPolicy,
) -> bool {
    session_channel_id != request_channel_id
        && (!session_activated || security_policy == SecurityPolicy::None)
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

        self.info
            .metrics
            .session_lookup_count
            .fetch_add(1, Ordering::Relaxed);
        self.info
            .metrics
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
        let secure_channel_id = channel.secure_channel_id();
        let unactivated_count = self
            .sessions
            .values()
            .filter(|session| {
                let session = trace_read_lock!(session);
                session.secure_channel_id() == secure_channel_id && !session.is_activated()
            })
            .count();
        if unactivated_count >= self.info.config.limits.max_unactivated_sessions_per_channel {
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
            error!(
                "Create session was passed a client nonce that is too short, expected at least {} bytes, got {}",
                self.info.config.session_nonce_length,
                request.client_nonce.len()
            );
            return Err(StatusCode::BadNonceInvalid);
        }

        let client_certificate = if security_policy != SecurityPolicy::None {
            let cert = opcua_crypto::X509::from_byte_string(&request.client_certificate)?;
            let application_uri = if request.client_description.application_uri.is_empty() {
                None
            } else {
                Some(request.client_description.application_uri.as_ref())
            };
            let store = trace_read_lock!(certificate_store);
            store.validate_or_reject_application_instance_cert(
                &cert,
                security_policy,
                None,
                application_uri,
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
            match opcua_crypto::create_signature_data(
                pkey,
                security_policy,
                &request.client_certificate,
                &request.client_nonce,
            ) {
                Ok(signature) => signature,
                Err(err) => {
                    error!(
                        "Cannot create signature data from private key, check log and error {:?}",
                        err
                    );
                    if security_policy != SecurityPolicy::None {
                        return Err(StatusCode::BadSecurityChecksFailed);
                    }
                    SignatureData::null()
                }
            }
        } else {
            SignatureData::null()
        };

        #[cfg(feature = "ecc")]
        let mut issued_ecdh_key: Option<(
            opcua_crypto::ecc::EphemeralKeyPair,
            SecurityPolicy,
        )> = None;
        #[cfg(feature = "ecc")]
        let ecdh_response_header = {
            match opcua_crypto::ecc::read_ecdh_policy_uri(&request.request_header.additional_header)
            {
                Some(uri) => match server_pkey.as_ref() {
                    Some(pkey) => match opcua_crypto::ecc::issue_server_ephemeral_key(&uri, pkey) {
                        Ok((keypair, ephemeral_key)) => {
                            issued_ecdh_key = Some((keypair, SecurityPolicy::from_uri(&uri)));
                            Some(opcua_crypto::ecc::build_ecdh_key_response(ephemeral_key))
                        }
                        Err(e) => Some(opcua_crypto::ecc::build_ecdh_key_error(e.status())),
                    },
                    None => Some(opcua_crypto::ecc::build_ecdh_key_error(
                        StatusCode::BadSecurityPolicyRejected,
                    )),
                },
                None => None,
            }
        };

        let authentication_token = NodeId::new(0, random::byte_string(32));
        let server_nonce = random::byte_string(self.info.config.session_nonce_length);
        let server_certificate = self.info.server_certificate_as_byte_string();
        let server_endpoints = Some(endpoints);

        let session = Session::create(
            &self.info,
            authentication_token.clone(),
            secure_channel_id,
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
        #[cfg(feature = "ecc")]
        let mut session = session;
        #[cfg(feature = "ecc")]
        if let Some((keypair, policy)) = issued_ecdh_key {
            session.set_ecdh_ephemeral_key(keypair, policy);
        }
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

        #[cfg_attr(not(feature = "ecc"), allow(unused_mut))]
        let mut response = CreateSessionResponse {
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
        };
        #[cfg(feature = "ecc")]
        if let Some(header) = ecdh_response_header {
            response.response_header.additional_header = header;
        }

        Ok(response)
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

        info!(
            "Session {id} has expired, removing it from the session map. Subscriptions will remain until they individually expire"
        );

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
            let session = session.read();
            let mut deadline = session.deadline();
            if !session.is_activated() {
                deadline = deadline.min(
                    session.created_at()
                        + Duration::from_millis(
                            self.info.config.limits.unactivated_session_timeout_ms,
                        ),
                );
            }
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
                error!(
                    "close_session rejected, secure channel id {} for inactive session does not match one used to create session, {}",
                    secure_channel_id,
                    session.secure_channel_id()
                );
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
                error!(
                    "activate_session, Endpoint dues not exist for requested url & mode {}, {:?} / {:?}",
                    endpoint_url, security_policy, security_mode
                );
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

        if is_cross_channel_transfer_forbidden(
            session.secure_channel_id(),
            secure_channel_id,
            session.is_activated(),
            security_policy,
        ) {
            error!(
                "activate session, rejected secure channel id {} does not match session channel {} (transfer not permitted for SecurityPolicy::None)",
                secure_channel_id,
                session.secure_channel_id()
            );
            return Err(StatusCode::BadSecureChannelIdInvalid);
        } else {
            // TODO additional secure channel validation here for client certificate and user identity
            //  token
        }

        if session.session_nonce() != &session_nonce {
            return Err(StatusCode::BadNonceInvalid);
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

    #[cfg(feature = "ecc")]
    let ecdh_response_header = {
        use opcua_crypto::ecc::EcdhKeyAction;
        let mut session = trace_write_lock!(session_lck);
        let requested_uri =
            opcua_crypto::ecc::read_ecdh_policy_uri(&request.request_header.additional_header);
        let previous_policy = session.ecdh_ephemeral_key().map(|(_, policy)| *policy);
        // 015a: no EphemeralKey is consumed yet - secret decryption (which consumes the key) is
        // feature 016 - so the previous key is never "used". The §6.8.2 consumed-key anti-replay
        // (never accept the same EphemeralKey twice) is enforced in 016 where the key is consumed.
        let previous_key_consumed = false;
        match opcua_crypto::ecc::decide_ecdh_key_action(
            requested_uri.as_deref(),
            previous_policy,
            previous_key_consumed,
        ) {
            EcdhKeyAction::Issue(policy) => {
                let server_pkey = info.server_pkey.read();
                match server_pkey.as_ref() {
                    Some(pkey) => {
                        match opcua_crypto::ecc::issue_server_ephemeral_key(policy.to_uri(), pkey) {
                            Ok((keypair, ephemeral_key)) => {
                                session.set_ecdh_ephemeral_key(keypair, policy);
                                Some(opcua_crypto::ecc::build_ecdh_key_response(ephemeral_key))
                            }
                            Err(e) => Some(opcua_crypto::ecc::build_ecdh_key_error(e.status())),
                        }
                    }
                    None => Some(opcua_crypto::ecc::build_ecdh_key_error(
                        StatusCode::BadSecurityPolicyRejected,
                    )),
                }
            }
            EcdhKeyAction::Reject => Some(opcua_crypto::ecc::build_ecdh_key_error(
                StatusCode::BadSecurityPolicyRejected,
            )),
            EcdhKeyAction::Retain | EcdhKeyAction::None => None,
        }
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

    #[cfg_attr(not(feature = "ecc"), allow(unused_mut))]
    let mut response = ActivateSessionResponse {
        response_header: ResponseHeader::new_good(&request.request_header),
        server_nonce,
        results: None,
        diagnostic_infos: None,
    };
    #[cfg(feature = "ecc")]
    if let Some(header) = ecdh_response_header {
        response.response_header.additional_header = header;
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    use async_trait::async_trait;
    use opcua_core::{comms::secure_channel::SecureChannel, sync::RwLock};
    use opcua_crypto::{random, SecurityPolicy};
    use opcua_types::{
        ActivateSessionRequest, AnonymousIdentityToken, ApplicationDescription, ByteString, Error,
        ExtensionObject, MessageSecurityMode, NodeId, RequestHeader, SignatureData, StatusCode,
        UAString, UserTokenPolicy, UserTokenType,
    };
    use tokio::sync::Notify;

    use crate::{
        authenticator::{AuthManager, UserToken},
        config::ServerEndpoint,
        identity_token::{IdentityToken, POLICY_ID_ANONYMOUS},
        node_manager::NodeManagers,
        session::{instance::Session, manager::SessionManager, message_handler::MessageHandler},
        ServerBuilder,
    };

    use super::{activate_session, is_cross_channel_transfer_forbidden};

    /// T048 / H1: an activated session under SecurityPolicy::None must not be
    /// transferable to a different secure channel (there is no cryptographic
    /// channel binding, so a transfer would be a session hijack). Sessions that
    /// are not yet activated can never move channels; activated sessions on a
    /// *secured* policy may legitimately move (e.g. reconnect).
    #[test]
    fn cross_channel_transfer_rules() {
        // Same channel is always permitted, regardless of state/policy.
        assert!(!is_cross_channel_transfer_forbidden(
            1,
            1,
            true,
            SecurityPolicy::None
        ));
        assert!(!is_cross_channel_transfer_forbidden(
            1,
            1,
            false,
            SecurityPolicy::Basic256Sha256
        ));

        // Different channel + not yet activated → always refused (any policy).
        assert!(is_cross_channel_transfer_forbidden(
            1,
            2,
            false,
            SecurityPolicy::None
        ));
        assert!(is_cross_channel_transfer_forbidden(
            1,
            2,
            false,
            SecurityPolicy::Basic256Sha256
        ));

        // H1 core: activated None-policy session cannot move channels.
        assert!(is_cross_channel_transfer_forbidden(
            1,
            2,
            true,
            SecurityPolicy::None
        ));

        // Activated session on a secured policy MAY transfer channels.
        assert!(!is_cross_channel_transfer_forbidden(
            1,
            2,
            true,
            SecurityPolicy::Basic256Sha256
        ));
    }

    #[tokio::test]
    async fn activate_session_rejects_stale_nonce_after_intervening_activation() {
        let stale_gate = Arc::new(AuthenticationGate::open());
        let fixture = ActivationFixture::new(stale_gate.clone());

        let baseline = fixture.activate_with(SecurityPolicy::None, 7).await;
        assert!(
            baseline.is_ok(),
            "normal uncontended activation should succeed, got {baseline:?}"
        );

        let stale_nonce = fixture.session_nonce();
        stale_gate.pause_next_authentication();
        let stale_activation = {
            let fixture = fixture.clone();
            tokio::spawn(async move { fixture.activate_with(SecurityPolicy::None, 7).await })
        };

        stale_gate.wait_until_entered().await;

        let intervening_nonce = random::byte_string(fixture.info.config.session_nonce_length);
        fixture.mutate_session_activation(
            7,
            intervening_nonce.clone(),
            anonymous_identity_with_policy("intervening-anonymous"),
            UserToken("intervening-user".to_string()),
        );
        let intervening_identity = fixture.user_identity();
        let intervening_channel_id = fixture.secure_channel_id();
        assert_ne!(
            stale_nonce, intervening_nonce,
            "intervening activation must rotate the nonce observed by the stale activation"
        );

        stale_gate.release();
        let stale_result = stale_activation
            .await
            .expect("stale activation task should not panic");

        assert!(
            matches!(
                stale_result,
                Err(StatusCode::BadNonceInvalid | StatusCode::BadSessionIdInvalid)
            ),
            "stale activation should fail closed after nonce rotation, got {stale_result:?}"
        );
        assert_eq!(
            fixture.session_nonce(),
            intervening_nonce,
            "stale activation must not overwrite the nonce from the intervening activation"
        );
        assert_eq!(
            fixture.secure_channel_id(),
            intervening_channel_id,
            "stale activation must not overwrite the secure channel"
        );
        assert_eq!(
            fixture.user_identity(),
            intervening_identity,
            "stale activation must not overwrite session identity"
        );
    }

    /// US4 (FR-002/FR-006): a None-policy ActivateSession that carries no `ECDHPolicyUri` must leave
    /// the response `AdditionalHeader` null — the ECC EphemeralKey wiring is inert on non-ECDH flows,
    /// byte-identical to before the feature (and holds identically whether or not `ecc` is compiled
    /// in). Anchored to §6.8.2: an absent `ECDHPolicyUri` yields no `ECDHKey`.
    #[tokio::test]
    async fn activate_session_without_ecdh_policy_leaves_response_header_null() {
        let fixture = ActivationFixture::new(Arc::new(AuthenticationGate::open()));
        let response = fixture
            .activate_with(SecurityPolicy::None, 7)
            .await
            .expect("anonymous None-policy activation should succeed");
        assert_eq!(
            response.response_header.additional_header,
            ExtensionObject::null(),
            "an ActivateSession with no ECDHPolicyUri must not add an ECDHKey to the response header"
        );
    }

    #[derive(Clone)]
    struct ActivationFixture {
        info: Arc<crate::ServerInfo>,
        manager: Arc<RwLock<SessionManager>>,
        session: Arc<RwLock<Session>>,
        token: NodeId,
        node_managers: NodeManagers,
        subscriptions: Arc<crate::SubscriptionCache>,
        certificate_store: Arc<RwLock<opcua_crypto::CertificateStore>>,
    }

    impl ActivationFixture {
        fn new(authenticator: Arc<dyn AuthManager>) -> Self {
            let (_server, handle) = ServerBuilder::new_anonymous("activation nonce replay test")
                .without_node_managers()
                .with_authenticator(authenticator)
                .build()
                .expect("test server should build");
            let info = Arc::clone(handle.info());
            let token = NodeId::new(1, 42);
            let endpoint_url = UAString::from(handle.info().base_endpoint());
            let session = Arc::new(RwLock::new(Session::create(
                &info,
                token.clone(),
                7,
                60_000,
                0,
                0,
                endpoint_url.clone(),
                SecurityPolicy::None.to_uri().to_string(),
                anonymous_identity(),
                None,
                random::byte_string(info.config.session_nonce_length),
                UAString::from("activation-nonce-replay-test"),
                ApplicationDescription::default(),
                MessageSecurityMode::None,
            )));
            let manager = Arc::new(RwLock::new(SessionManager::new(
                Arc::clone(&info),
                Arc::new(Notify::new()),
            )));
            {
                let mut manager_lck = manager.write();
                manager_lck
                    .sessions
                    .insert(token.clone(), Arc::clone(&session));
                manager_lck.register_token(token.clone(), Arc::clone(&session));
            }

            Self {
                info,
                manager,
                session,
                token,
                node_managers: handle.node_managers().clone(),
                subscriptions: Arc::clone(handle.subscriptions()),
                certificate_store: Arc::clone(handle.certificate_store()),
            }
        }

        async fn activate_with(
            &self,
            security_policy: SecurityPolicy,
            secure_channel_id: u32,
        ) -> Result<super::ActivateSessionResponse, StatusCode> {
            let mut channel = SecureChannel::new(
                Arc::clone(&self.certificate_store),
                opcua_core::comms::secure_channel::Role::Server,
                Arc::new(RwLock::new(Default::default())),
            );
            channel.set_security_policy(security_policy);
            channel.set_security_mode(MessageSecurityMode::None);
            channel.set_secure_channel_id(secure_channel_id);

            let request = activate_request(&self.token);
            let mut handler = MessageHandler::new(
                Arc::clone(&self.info),
                self.node_managers.clone(),
                Arc::clone(&self.subscriptions),
            );
            activate_session(&self.manager, &mut channel, &request, &mut handler).await
        }

        fn session_nonce(&self) -> ByteString {
            self.session.read().session_nonce().clone()
        }

        fn secure_channel_id(&self) -> u32 {
            self.session.read().secure_channel_id()
        }

        fn user_identity(&self) -> IdentityTokenSnapshot {
            IdentityTokenSnapshot::from(self.session.read().user_identity())
        }

        fn mutate_session_activation(
            &self,
            secure_channel_id: u32,
            server_nonce: ByteString,
            identity: IdentityToken,
            user_token: UserToken,
        ) {
            self.session.write().activate(
                secure_channel_id,
                server_nonce,
                identity,
                None,
                user_token,
                None,
            );
        }
    }

    struct AuthenticationGate {
        pause_once: AtomicBool,
        entered: Notify,
        release: Notify,
    }

    impl AuthenticationGate {
        fn open() -> Self {
            Self {
                pause_once: AtomicBool::new(false),
                entered: Notify::new(),
                release: Notify::new(),
            }
        }

        fn pause_next_authentication(&self) {
            self.pause_once.store(true, Ordering::Release);
        }

        async fn maybe_pause(&self) {
            if self.pause_once.swap(false, Ordering::AcqRel) {
                self.entered.notify_waiters();
                self.release.notified().await;
            }
        }

        async fn wait_until_entered(&self) {
            if self.pause_once.load(Ordering::Acquire) {
                self.entered.notified().await;
            }
        }

        fn release(&self) {
            self.release.notify_waiters();
        }
    }

    #[async_trait]
    impl AuthManager for AuthenticationGate {
        async fn authenticate_anonymous_token(
            &self,
            _endpoint: &ServerEndpoint,
        ) -> Result<(), Error> {
            self.maybe_pause().await;
            Ok(())
        }

        fn user_token_policies(&self, _endpoint: &ServerEndpoint) -> Vec<UserTokenPolicy> {
            vec![UserTokenPolicy {
                policy_id: UAString::from(POLICY_ID_ANONYMOUS),
                token_type: UserTokenType::Anonymous,
                issued_token_type: UAString::null(),
                issuer_endpoint_url: UAString::null(),
                security_policy_uri: UAString::null(),
            }]
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum IdentityTokenSnapshot {
        Anonymous(UAString),
        Other,
    }

    impl From<&IdentityToken> for IdentityTokenSnapshot {
        fn from(value: &IdentityToken) -> Self {
            match value {
                IdentityToken::Anonymous(token) => Self::Anonymous(token.policy_id.clone()),
                _ => Self::Other,
            }
        }
    }

    fn activate_request(authentication_token: &NodeId) -> ActivateSessionRequest {
        ActivateSessionRequest {
            request_header: RequestHeader {
                authentication_token: authentication_token.clone(),
                ..Default::default()
            },
            client_signature: SignatureData::null(),
            client_software_certificates: None,
            locale_ids: None,
            user_identity_token: ExtensionObject::from_message(AnonymousIdentityToken {
                policy_id: UAString::from(POLICY_ID_ANONYMOUS),
            }),
            user_token_signature: SignatureData::null(),
        }
    }

    fn anonymous_identity() -> IdentityToken {
        anonymous_identity_with_policy(POLICY_ID_ANONYMOUS)
    }

    fn anonymous_identity_with_policy(policy_id: &str) -> IdentityToken {
        IdentityToken::Anonymous(AnonymousIdentityToken {
            policy_id: UAString::from(policy_id),
        })
    }
}
