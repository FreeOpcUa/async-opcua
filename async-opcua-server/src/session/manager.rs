use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, OnceLock,
    },
    time::{Duration, Instant},
};

use dashmap::DashMap;
use futures::FutureExt;
use opcua_core::{comms::secure_channel::SecureChannel, trace_read_lock, trace_write_lock};
use opcua_crypto::{random, CertificateStore, SecurityPolicy, X509};
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
    rbac::resolver::ResolvedIdentity,
    subscriptions::SubscriptionCache,
};
use opcua_types::{
    ActivateSessionRequest, ActivateSessionResponse, ByteString, CloseSessionRequest,
    CloseSessionResponse, CreateSessionRequest, CreateSessionResponse, EndpointDescription, Error,
    MessageSecurityMode, NodeId, ResponseHeader, SignatureData, StatusCode, UAString,
};

use super::{
    actor::{SessionActor, SessionMessage},
    audit,
    instance::Session,
    message_handler::MessageHandler,
};

static NEXT_SESSION_ID: AtomicU32 = AtomicU32::new(1);
static SESSION_LOCALE_IDS: OnceLock<DashMap<u32, Vec<UAString>>> = OnceLock::new();
const SESSION_ACTOR_QUEUE_CAPACITY: usize = 256;
const CLOSED_SESSION_TOKEN_TOMBSTONE_SECS: u64 = 300;

pub(super) fn next_session_id() -> (NodeId, u32) {
    // Session id will be a string identifier
    let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    (NodeId::new(1, session_id), session_id)
}

fn session_locale_ids() -> &'static DashMap<u32, Vec<UAString>> {
    SESSION_LOCALE_IDS.get_or_init(DashMap::new)
}

pub(crate) fn locale_ids_for_session(session_id: u32) -> Option<Vec<UAString>> {
    session_locale_ids()
        .get(&session_id)
        .map(|entry| entry.value().clone())
}

fn set_session_locale_ids(session_id: u32, locale_ids: &Option<Vec<UAString>>) {
    match locale_ids {
        Some(locale_ids) if !locale_ids.is_empty() => {
            session_locale_ids().insert(session_id, locale_ids.clone());
        }
        _ => {
            clear_session_locale_ids(session_id);
        }
    }
}

fn clear_session_locale_ids(session_id: u32) {
    session_locale_ids().remove(&session_id);
}

fn clear_session_locale_ids_for_node_id(session_id: &NodeId) {
    if let opcua_types::Identifier::Numeric(id) = &session_id.identifier {
        clear_session_locale_ids(*id);
    }
}

pub(crate) fn normalized_locale_id(locale_id: &str) -> String {
    locale_id.trim().replace('_', "-").to_ascii_lowercase()
}

pub(crate) fn locale_id_matches(supported: &str, requested: &str) -> bool {
    let supported = normalized_locale_id(supported);
    let requested = normalized_locale_id(requested);

    if supported.is_empty() || requested.is_empty() {
        return requested.is_empty();
    }
    if supported == requested {
        return true;
    }

    let supported_is_neutral = !supported.contains('-');
    let requested_is_neutral = !requested.contains('-');

    (supported_is_neutral && requested.starts_with(&format!("{supported}-")))
        || (requested_is_neutral && supported.starts_with(&format!("{requested}-")))
}

pub(crate) fn is_special_write_locale_id(locale_id: &str) -> bool {
    matches!(
        normalized_locale_id(locale_id).split('-').next(),
        Some("mul" | "qst")
    )
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

/// Returns true when the client application certificate bound to the session at CreateSession does
/// NOT match the certificate that secured the activating channel -- a Part 4 §5.6 binding violation
/// that must be rejected. For `SecurityPolicy::None` there is no channel certificate, so the binding
/// is not checked (returns false). Under any secured policy, both certificates must be present and
/// equal (by thumbprint); a missing certificate on either side is treated as a violation (fail closed).
pub(crate) fn is_client_certificate_channel_mismatch(
    session_cert: Option<&X509>,
    channel_cert: Option<&X509>,
    security_policy: SecurityPolicy,
) -> bool {
    if security_policy == SecurityPolicy::None {
        return false;
    }
    match (session_cert, channel_cert) {
        (Some(session_cert), Some(channel_cert)) => {
            session_cert.thumbprint() != channel_cert.thumbprint()
        }
        _ => true,
    }
}

fn non_empty_ua_string(value: &opcua_types::UAString) -> Option<String> {
    value
        .value()
        .as_ref()
        .filter(|value| !value.is_empty())
        .cloned()
}

fn resolved_identity_from_activation(
    identity: &IdentityToken,
    claims: Option<&opcua_crypto::identity::ClaimProfile>,
    application_uri: Option<String>,
    endpoint_url: Option<String>,
) -> Result<ResolvedIdentity, StatusCode> {
    match identity {
        IdentityToken::Anonymous(_) => {
            Ok(ResolvedIdentity::anonymous(application_uri, endpoint_url))
        }
        IdentityToken::UserName(token) => Ok(ResolvedIdentity::username(
            token.user_name.as_ref(),
            application_uri,
            endpoint_url,
        )),
        IdentityToken::X509(token) => {
            let signing_cert =
                X509::from_byte_string(&token.certificate_data).map_err(|err| err.status())?;
            Ok(ResolvedIdentity::x509_thumbprint(
                signing_cert.thumbprint().as_hex_string(),
                application_uri,
                endpoint_url,
            ))
        }
        IdentityToken::IssuedToken(_) => {
            let group_ids = claims
                .map(|claims| claims.roles.clone())
                .unwrap_or_default();
            Ok(ResolvedIdentity::issued_token(
                group_ids,
                std::iter::empty::<NodeId>(),
                application_uri,
                endpoint_url,
            ))
        }
        IdentityToken::None | IdentityToken::Invalid(_) => Err(StatusCode::BadIdentityTokenInvalid),
    }
}

struct CreateSessionEndpointSelection {
    server_endpoints: Vec<EndpointDescription>,
}

impl CreateSessionEndpointSelection {
    fn preflight(info: &ServerInfo, request: &CreateSessionRequest) -> Result<Self, StatusCode> {
        // OPC-10000-4 5.7.2: CreateSession endpoint validation is safe to
        // prepare before the short manager commit as long as statuses remain unchanged.
        let endpoints = info.new_endpoint_descriptions(request.endpoint_url.as_ref());
        if request.endpoint_url.is_empty() {
            error!("Create session was passed an null endpoint url");
            return Err(StatusCode::BadTcpEndpointUrlInvalid);
        }

        let Some(server_endpoints) = endpoints else {
            return Err(StatusCode::BadTcpEndpointUrlInvalid);
        };

        info.validate_endpoint_hostname(request.endpoint_url.as_ref())?;

        Ok(Self { server_endpoints })
    }
}

struct CreateSessionCertificateValidation {
    client_certificate: Option<X509>,
}

impl CreateSessionCertificateValidation {
    fn preflight(
        certificate_store: &RwLock<CertificateStore>,
        security_policy: SecurityPolicy,
        request: &CreateSessionRequest,
    ) -> Result<Self, StatusCode> {
        // OPC-10000-4 5.7.2: secured CreateSession requests bind the client
        // application certificate to the requested ApplicationDescription.
        let client_certificate = if security_policy != SecurityPolicy::None {
            let cert = X509::from_byte_string(&request.client_certificate)?;
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

        Ok(Self { client_certificate })
    }
}

struct CreateSessionServerSignature {
    server_signature: SignatureData,
    #[cfg(feature = "ecc")]
    issued_ecdh_key: Option<(opcua_crypto::ecc::EphemeralKeyPair, SecurityPolicy)>,
    #[cfg(feature = "ecc")]
    ecdh_response_header: Option<opcua_types::ExtensionObject>,
}

impl CreateSessionServerSignature {
    fn preflight(
        info: &ServerInfo,
        security_policy: SecurityPolicy,
        request: &CreateSessionRequest,
    ) -> Result<Self, StatusCode> {
        // OPC-10000-4 5.7.2: the server signature proves possession of the
        // server private key for the client certificate and nonce supplied in
        // CreateSession, and can be prepared before the short manager commit.
        let server_pkey = info.server_pkey.read();
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

        Ok(Self {
            server_signature,
            #[cfg(feature = "ecc")]
            issued_ecdh_key,
            #[cfg(feature = "ecc")]
            ecdh_response_header,
        })
    }
}

pub(crate) struct CreateSessionDraft {
    secure_channel_id: u32,
    actor_construction: CreateSessionActorConstruction,
    session_allocation: CreateSessionAllocation,
}

struct CreateSessionActorConstruction {
    authentication_token: NodeId,
    server_nonce: ByteString,
    server_certificate: ByteString,
    session_timeout: u64,
    max_request_message_size: u32,
    server_endpoints: Option<Vec<EndpointDescription>>,
    session_id: NodeId,
    session_id_numeric: u32,
}

struct CreateSessionAllocation {
    session_arc: Arc<RwLock<Session>>,
    response: CreateSessionResponse,
}

impl CreateSessionActorConstruction {
    fn prepare(
        info: &ServerInfo,
        channel: &SecureChannel,
        request: &CreateSessionRequest,
        endpoint_selection: &CreateSessionEndpointSelection,
        certificate_validation: &CreateSessionCertificateValidation,
        server_signature: &mut CreateSessionServerSignature,
    ) -> (Self, Session) {
        // OPC-10000-4 5.7.2: these values are part of the session returned by
        // CreateSession, but preparing them does not publish the Session or
        // spawn its actor.
        let authentication_token = NodeId::new(0, random::byte_string(32));
        let server_nonce = random::byte_string(info.config.session_nonce_length);
        let server_certificate = info.server_certificate_as_byte_string();
        let session_timeout = info
            .config
            .max_session_timeout_ms
            .min(request.requested_session_timeout.floor() as u64);
        let max_request_message_size = info.config.limits.max_message_size as u32;
        let server_endpoints = Some(endpoint_selection.server_endpoints.clone());
        let security_policy = channel.security_policy();

        let session = Session::create(
            info,
            authentication_token.clone(),
            channel.secure_channel_id(),
            session_timeout,
            max_request_message_size,
            request.max_response_message_size,
            request.endpoint_url.clone(),
            security_policy.to_uri().to_string(),
            IdentityToken::None,
            certificate_validation.client_certificate.clone(),
            server_nonce.clone(),
            request.session_name.clone(),
            request.client_description.clone(),
            channel.security_mode(),
        );

        #[cfg(feature = "ecc")]
        let session = {
            let mut session = session;
            if let Some((keypair, policy)) = server_signature.issued_ecdh_key.take() {
                session.set_ecdh_ephemeral_key(keypair, policy);
            }
            session
        };
        #[cfg(not(feature = "ecc"))]
        let _ = server_signature;

        let session_id = session.session_id().clone();
        let session_id_numeric = session.session_id_numeric();

        (
            Self {
                authentication_token,
                server_nonce,
                server_certificate,
                session_timeout,
                max_request_message_size,
                server_endpoints,
                session_id,
                session_id_numeric,
            },
            session,
        )
    }
}

impl CreateSessionAllocation {
    fn prepare(
        session: Session,
        request: &CreateSessionRequest,
        actor_construction: &CreateSessionActorConstruction,
        server_signature: &CreateSessionServerSignature,
    ) -> Self {
        // OPC-10000-4 5.7.2: allocation can prepare the publishable session
        // handle and response body without registering the Session globally.
        let session_arc = Arc::new(RwLock::new(session));
        let response = CreateSessionResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            session_id: actor_construction.session_id.clone(),
            authentication_token: actor_construction.authentication_token.clone(),
            revised_session_timeout: actor_construction.session_timeout as f64,
            server_nonce: actor_construction.server_nonce.clone(),
            server_certificate: actor_construction.server_certificate.clone(),
            server_endpoints: actor_construction.server_endpoints.clone(),
            server_software_certificates: None,
            server_signature: server_signature.server_signature.clone(),
            max_request_message_size: actor_construction.max_request_message_size,
        };
        #[cfg(feature = "ecc")]
        let response = {
            let mut response = response;
            if let Some(header) = server_signature.ecdh_response_header.clone() {
                response.response_header.additional_header = header;
            }
            response
        };

        Self {
            session_arc,
            response,
        }
    }
}

impl CreateSessionDraft {
    pub(crate) fn prepare_endpoint_preflight(
        info: &ServerInfo,
        channel: &SecureChannel,
        certificate_store: &RwLock<CertificateStore>,
        request: &CreateSessionRequest,
    ) -> Result<Self, StatusCode> {
        let endpoint_selection = CreateSessionEndpointSelection::preflight(info, request)?;
        let security_policy = channel.security_policy();
        if !matches!(security_policy, SecurityPolicy::None)
            && request.client_nonce.len() < info.config.session_nonce_length
        {
            error!(
                "Create session was passed a client nonce that is too short, expected at least {} bytes, got {}",
                info.config.session_nonce_length,
                request.client_nonce.len()
            );
            return Err(StatusCode::BadNonceInvalid);
        }
        let certificate_validation = CreateSessionCertificateValidation::preflight(
            certificate_store,
            security_policy,
            request,
        )?;
        let server_signature =
            CreateSessionServerSignature::preflight(info, security_policy, request)?;
        let mut server_signature = server_signature;
        let (actor_construction, session) = CreateSessionActorConstruction::prepare(
            info,
            channel,
            request,
            &endpoint_selection,
            &certificate_validation,
            &mut server_signature,
        );
        let session_allocation = CreateSessionAllocation::prepare(
            session,
            request,
            &actor_construction,
            &server_signature,
        );

        Ok(Self {
            secure_channel_id: channel.secure_channel_id(),
            actor_construction,
            session_allocation,
        })
    }
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
    closed_auth_tokens: Arc<DashMap<NodeId, Instant>>,
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
            closed_auth_tokens: Default::default(),
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
        self.closed_auth_tokens.remove(&token);
        self.auth_tokens.insert(token, session);
    }

    /// Remove an authentication token from the direct session lookup registry.
    pub fn deregister_token(&self, token: &NodeId) {
        self.actor_senders.remove(token);
        self.auth_tokens.remove(token);
        self.remember_closed_token(token.clone());
    }

    /// Return true if the token belonged to a recently closed session.
    pub fn is_closed_token(&self, token: &NodeId) -> bool {
        self.prune_closed_tokens();
        self.closed_auth_tokens.contains_key(token)
    }

    fn remember_closed_token(&self, token: NodeId) {
        self.prune_closed_tokens();
        self.closed_auth_tokens.insert(token, Instant::now());
    }

    fn prune_closed_tokens(&self) {
        let cutoff = Instant::now() - Duration::from_secs(CLOSED_SESSION_TOKEN_TOMBSTONE_SECS);
        self.closed_auth_tokens
            .retain(|_, closed_at| *closed_at >= cutoff);
    }

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

    fn refresh_client_response_body_limit_for_channel(&self, channel: &mut SecureChannel) {
        let secure_channel_id = channel.secure_channel_id();
        if secure_channel_id == 0 {
            return;
        }

        let effective_limit = self
            .sessions
            .values()
            .filter_map(|session| {
                let session = trace_read_lock!(session);
                let is_closed = matches!(
                    session.validate_activated(),
                    Err(StatusCode::BadSessionClosed)
                );
                if session.secure_channel_id() == secure_channel_id && !is_closed {
                    let limit = session.max_response_message_size();
                    (limit > 0).then_some(limit)
                } else {
                    None
                }
            })
            .min();

        channel.set_client_response_body_limit(effective_limit.unwrap_or(0));
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
        let user_roles = session.read().roles();

        let context = RequestContext {
            current_node_manager_index: 0,
            inner: Arc::new(RequestContextInner {
                session,
                session_id: session_id_numeric,
                authenticator: self.info.authenticator.clone(),
                token: UserToken(ANONYMOUS_USER_TOKEN_ID.to_string()),
                user_roles,
                type_tree: self.info.type_tree.clone(),
                type_tree_getter: self.info.type_tree_getter.clone(),
                subscriptions,
                info: self.info.clone(),
            }),
        };

        let auth_tokens = Arc::clone(&self.auth_tokens);
        let actor_senders = Arc::clone(&self.actor_senders);
        let closed_auth_tokens = Arc::clone(&self.closed_auth_tokens);
        let mut actor =
            SessionActor::new(context, receiver).with_termination_cleanup(move |terminated| {
                auth_tokens.remove(&terminated.authentication_token);
                actor_senders.remove(&terminated.authentication_token);
                closed_auth_tokens.insert(terminated.authentication_token.clone(), Instant::now());
                clear_session_locale_ids_for_node_id(&terminated.session_id);
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

    pub(crate) fn commit_create_session_draft(
        &mut self,
        draft: CreateSessionDraft,
        channel: &mut SecureChannel,
        node_managers: NodeManagers,
        subscriptions: Arc<SubscriptionCache>,
    ) -> Result<CreateSessionResponse, StatusCode> {
        // OPC-10000-4 5.7.2: CreateSession publishes a Session and its
        // authentication token, so the global session limit must be checked
        // immediately before those identifiers become visible.
        if self.sessions.len() >= self.info.config.limits.max_sessions {
            return Err(StatusCode::BadTooManySessions);
        }
        let unactivated_count = self
            .sessions
            .values()
            .filter(|session| {
                let session = trace_read_lock!(session);
                session.secure_channel_id() == draft.secure_channel_id && !session.is_activated()
            })
            .count();
        if unactivated_count >= self.info.config.limits.max_unactivated_sessions_per_channel {
            return Err(StatusCode::BadTooManySessions);
        }
        if channel.secure_channel_id() != draft.secure_channel_id {
            // CreateSession binds the new Session to the SecureChannel that
            // carried the request; a stale draft must not publish on another channel.
            return Err(StatusCode::BadSecureChannelIdInvalid);
        }

        let CreateSessionDraft {
            actor_construction,
            session_allocation,
            ..
        } = draft;
        let CreateSessionActorConstruction {
            authentication_token,
            session_id,
            session_id_numeric,
            ..
        } = actor_construction;
        let CreateSessionAllocation {
            session_arc,
            response,
        } = session_allocation;

        info!("Created new session with ID {}", session_id);
        self.sessions.insert(session_id, Arc::clone(&session_arc));
        self.register_token(authentication_token.clone(), Arc::clone(&session_arc));
        self.spawn_session_actor(
            authentication_token,
            session_arc,
            session_id_numeric,
            node_managers,
            subscriptions,
        );
        self.refresh_client_response_body_limit_for_channel(channel);

        self.info
            .diagnostics
            .set_current_session_count(self.sessions.len() as u32);
        self.info.diagnostics.inc_session_count();

        self.notify.notify_waiters();

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

        let (token, session_id_numeric) = {
            let session = trace_read_lock!(session);
            (
                session.authentication_token.clone(),
                session.session_id_numeric(),
            )
        };
        self.deregister_token(&token);
        clear_session_locale_ids(session_id_numeric);

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
        clear_session_locale_ids(id);
        mgr.info
            .diagnostics
            .set_current_session_count(mgr.sessions.len() as u32);
        mgr.refresh_client_response_body_limit_for_channel(channel);
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

            let is_cross_channel_activation = session.secure_channel_id() != secure_channel_id;
            if is_cross_channel_activation && session.message_security_mode() != security_mode {
                error!(
                    "activate_session, rejected secure channel id {} with SecurityMode {:?}; session channel {} was created with SecurityMode {:?}",
                    secure_channel_id,
                    security_mode,
                    session.secure_channel_id(),
                    session.message_security_mode()
                );
                return Err(StatusCode::BadSecureChannelIdInvalid);
            }

            if is_cross_channel_activation
                && SecurityPolicy::from_uri(session.security_policy_uri()) != security_policy
            {
                error!(
                    "activate_session, rejected secure channel id {} with SecurityPolicy {:?}; session channel {} was created with SecurityPolicy {}",
                    secure_channel_id,
                    security_policy,
                    session.secure_channel_id(),
                    session.security_policy_uri()
                );
                return Err(StatusCode::BadSecureChannelIdInvalid);
            }

            if security_policy != SecurityPolicy::None {
                SessionManager::verify_client_signature(
                    security_policy,
                    &mgr.info,
                    &session,
                    &request.client_signature,
                )?;
            }

            let requested_identity = IdentityToken::new(request.user_identity_token.clone());
            let session_identity_is_non_anonymous = !matches!(
                session.user_identity(),
                IdentityToken::Anonymous(_) | IdentityToken::None
            );
            if is_cross_channel_activation
                && security_mode == MessageSecurityMode::Sign
                && matches!(requested_identity, IdentityToken::Anonymous(_))
                && session_identity_is_non_anonymous
            {
                error!(
                    "activate_session, rejected anonymous ActivateSession over new Sign-only secure channel {} for session channel {} with non-anonymous identity",
                    secure_channel_id,
                    session.secure_channel_id()
                );
                return Err(StatusCode::BadIdentityTokenRejected);
            }
            (endpoint_url, session.session_nonce().clone())
        };
        (endpoint_url, session_nonce, session_lck, mgr.info.clone())
    };

    #[cfg(feature = "ecc")]
    let ecc_ctx = {
        let session = trace_read_lock!(session_lck);
        let server_ephemeral = match session.ecdh_ephemeral_key() {
            Some((kp, _policy)) => Some(
                opcua_crypto::ecc::EphemeralPrivateKey::from_scalar_bytes(
                    kp.private_key().curve(),
                    kp.private_key().scalar(),
                )
                .map_err(|_| StatusCode::BadIdentityTokenRejected)?,
            ),
            None => None,
        };
        let client_certificate = session.client_certificate().cloned();
        crate::session::negotiate::EccSecretContext {
            server_ephemeral,
            client_certificate,
        }
    };
    #[cfg(not(feature = "ecc"))]
    let ecc_ctx = crate::session::negotiate::EccSecretContext::default();

    let authentication = match info
        .authenticate_endpoint_with_ecc_ctx(
            request,
            &endpoint_url,
            security_policy,
            security_mode,
            request.user_identity_token.clone(),
            &session_nonce,
            ecc_ctx,
        )
        .await
    {
        Ok(authentication) => authentication,
        Err(error) => {
            if let Some(certificate) = x509_user_certificate_from_request(request) {
                let session_id = {
                    let session = trace_read_lock!(session_lck);
                    Some(session.session_id().clone())
                };
                audit::dispatch_user_certificate_audit(
                    handler.subscriptions(),
                    &info,
                    &request.request_header,
                    certificate,
                    session_id,
                    error.status(),
                );
            }
            return Err(error.status());
        }
    };
    if let Some(validation) = authentication.x509_user_certificate_validation.as_ref() {
        if !validation.suppressed_findings.is_empty() {
            let session_id = {
                let session = trace_read_lock!(session_lck);
                Some(session.session_id().clone())
            };
            for finding in &validation.suppressed_findings {
                audit::dispatch_user_certificate_audit(
                    handler.subscriptions(),
                    &info,
                    &request.request_header,
                    validation.certificate.clone(),
                    session_id.clone(),
                    finding.status,
                );
            }
        }
    }
    #[cfg(feature = "ecc")]
    let ecc_secret_consumed = matches!(
        security_policy,
        SecurityPolicy::EccNistP256 | SecurityPolicy::EccNistP384
    ) && matches!(
        IdentityToken::new(request.user_identity_token.clone()),
        IdentityToken::UserName(_) | IdentityToken::IssuedToken(_)
    );

    let (server_nonce, session_id, user_changed, user_token) = {
        let mut session = trace_write_lock!(session_lck);
        let previous_secure_channel_id = session.secure_channel_id();

        if is_cross_channel_transfer_forbidden(
            previous_secure_channel_id,
            secure_channel_id,
            session.is_activated(),
            security_policy,
        ) {
            error!(
                "activate session, rejected secure channel id {} does not match session channel {} (transfer not permitted for SecurityPolicy::None)",
                secure_channel_id, previous_secure_channel_id
            );
            return Err(StatusCode::BadSecureChannelIdInvalid);
        }

        let channel_cert = channel.remote_cert();
        if is_client_certificate_channel_mismatch(
            session.client_certificate(),
            channel_cert.as_ref(),
            security_policy,
        ) {
            error!(
                "activate session rejected: client certificate presented at CreateSession does not match the certificate securing the channel (secure channel id {})",
                secure_channel_id
            );
            let mismatch_cert = session
                .client_certificate()
                .map(|cert| cert.as_byte_string())
                .unwrap_or_else(ByteString::null);
            audit::dispatch_certificate_mismatch(
                handler.subscriptions(),
                &info,
                &request.request_header,
                Some(session.session_id().clone()),
                mismatch_cert,
            );
            return Err(StatusCode::BadSecurityChecksFailed);
        }

        if session.session_nonce() != &session_nonce {
            return Err(StatusCode::BadNonceInvalid);
        }

        let user_changed = session
            .user_token()
            .is_some_and(|previous| previous != &authentication.user_token);
        let crate::info::EndpointAuthentication {
            user_token, claims, ..
        } = authentication;
        let activated_identity = IdentityToken::new(request.user_identity_token.clone());
        let application_uri =
            non_empty_ua_string(&session.application_description().application_uri);
        let resolved_identity = resolved_identity_from_activation(
            &activated_identity,
            claims.as_ref(),
            application_uri,
            Some(endpoint_url.clone()),
        )?;
        let roles = Arc::new(info.role_resolver.read().resolve(&resolved_identity));
        let locale_ids = request.locale_ids.clone();
        session.activate(
            secure_channel_id,
            server_nonce,
            activated_identity,
            locale_ids.clone(),
            user_token.clone(),
            claims,
            roles,
        );
        set_session_locale_ids(session.session_id_numeric(), &locale_ids);
        (
            session.session_nonce().clone(),
            session.session_id_numeric(),
            user_changed,
            user_token,
        )
    };

    {
        let mgr = trace_read_lock!(mgr_lck);
        mgr.refresh_client_response_body_limit_for_channel(channel);
    }

    #[cfg(feature = "ecc")]
    let ecdh_response_header = {
        use opcua_crypto::ecc::EcdhKeyAction;
        let mut session = trace_write_lock!(session_lck);
        let requested_uri =
            opcua_crypto::ecc::read_ecdh_policy_uri(&request.request_header.additional_header);
        let previous_policy = session.ecdh_ephemeral_key().map(|(_, policy)| *policy);
        if ecc_secret_consumed {
            session.mark_ecdh_key_consumed();
        }
        let previous_key_consumed = session.ecdh_key_consumed();
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

    let response = ActivateSessionResponse {
        response_header: ResponseHeader::new_good(&request.request_header),
        server_nonce,
        results: None,
        diagnostic_infos: None,
    };
    #[cfg(feature = "ecc")]
    let response = {
        let mut response = response;
        if let Some(header) = ecdh_response_header {
            response.response_header.additional_header = header;
        }
        response
    };
    Ok(response)
}

fn x509_user_certificate_from_request(request: &ActivateSessionRequest) -> Option<ByteString> {
    match IdentityToken::new(request.user_identity_token.clone()) {
        IdentityToken::X509(token) => Some(token.certificate_data),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::Path,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };

    use async_trait::async_trait;
    use opcua_core::{comms::secure_channel::SecureChannel, sync::RwLock};
    use opcua_crypto::{random, CertificateStore, PrivateKey, SecurityPolicy, Thumbprint};
    use opcua_types::{
        ActivateSessionRequest, AnonymousIdentityToken, ApplicationDescription, ByteString, Error,
        ExtensionObject, MessageSecurityMode, NodeId, RequestHeader, SignatureData, StatusCode,
        UAString, UserNameIdentityToken, UserTokenPolicy, UserTokenType, X509IdentityToken,
    };
    use tokio::sync::Notify;

    use crate::{
        authenticator::{AuthManager, UserToken},
        config::{ServerEndpoint, ServerUserToken},
        identity_token::{
            IdentityToken, POLICY_ID_ANONYMOUS, POLICY_ID_USER_PASS_NONE, POLICY_ID_X509,
        },
        node_manager::NodeManagers,
        rbac::{rules::IdentityMappingRule, WellKnownRole},
        session::{instance::Session, manager::SessionManager, message_handler::MessageHandler},
        ServerBuilder,
    };

    use super::{
        activate_session, is_client_certificate_channel_mismatch,
        is_cross_channel_transfer_forbidden,
    };

    const X509_STATE_CLEANUP_USER_TOKEN: &str = "x509-state-cleanup-user";

    struct TempPath {
        dir: tempfile::TempDir,
    }

    impl TempPath {
        fn new(name: &str) -> Self {
            let dir = tempfile::Builder::new()
                .prefix(&format!("async-opcua-manager-{name}-"))
                .tempdir()
                .expect("test temp directory should be created");
            Self { dir }
        }

        fn path(&self) -> &Path {
            self.dir.path()
        }
    }

    /// Mint a self-signed application certificate for binding tests.
    fn make_cert_and_key(common_name: &str) -> (opcua_crypto::X509, PrivateKey) {
        let data = opcua_crypto::X509Data {
            key_size: 2048,
            common_name: common_name.to_string(),
            organization: "async-opcua test".to_string(),
            organizational_unit: "test".to_string(),
            country: "IE".to_string(),
            state: "test".to_string(),
            alt_host_names: vec!["urn:async-opcua-test".to_string(), "localhost".to_string()]
                .into(),
            certificate_duration_days: 60,
        };
        opcua_crypto::X509::cert_and_pkey(&data).expect("generate self-signed test certificate")
    }

    fn make_cert(common_name: &str) -> opcua_crypto::X509 {
        make_cert_and_key(common_name).0
    }

    /// US1 (FR-001): the client application certificate bound at CreateSession must match the
    /// certificate that secured the activating channel, under any secured policy. `None` policy has
    /// no channel certificate, so the binding is not checked.
    #[test]
    fn client_certificate_channel_binding_rules() {
        let c1 = make_cert("client-one");
        let c2 = make_cert("client-two");

        // Matching certificate under a secured policy: no violation.
        assert!(!is_client_certificate_channel_mismatch(
            Some(&c1),
            Some(&c1),
            SecurityPolicy::Basic256Sha256
        ));
        // Different certificate: a binding violation (must be rejected).
        assert!(is_client_certificate_channel_mismatch(
            Some(&c1),
            Some(&c2),
            SecurityPolicy::Basic256Sha256
        ));
        // Secured policy but the channel presented no peer certificate: fail closed.
        assert!(is_client_certificate_channel_mismatch(
            Some(&c1),
            None,
            SecurityPolicy::Basic256Sha256
        ));
        // None policy: no channel certificate exists, so the binding is not checked.
        assert!(!is_client_certificate_channel_mismatch(
            Some(&c1),
            Some(&c2),
            SecurityPolicy::None
        ));
        assert!(!is_client_certificate_channel_mismatch(
            None,
            None,
            SecurityPolicy::None
        ));
    }

    /// US2 (FR-005 lock-in / SC-002): a session is bound to its secure channel — a request whose
    /// secure-channel id differs from the session's is rejected with `BadSecureChannelIdInvalid`.
    /// This is the check `SessionController::validate_request` runs on every session-scoped request.
    #[tokio::test]
    async fn session_rejects_request_from_a_different_secure_channel() {
        let fixture = ActivationFixture::new(Arc::new(AuthenticationGate::open()));
        let session = fixture.session.read();
        // The fixture session belongs to secure channel 7.
        assert!(session.validate_secure_channel_id(7).is_ok());
        assert_eq!(
            session.validate_secure_channel_id(8).unwrap_err(),
            StatusCode::BadSecureChannelIdInvalid,
            "a session must reject a request arriving on a different secure channel"
        );
    }

    /// US2 (FR-002 lock-in): under `SecurityPolicy::None` there is no channel certificate, so the
    /// new client-cert↔channel binding must be skipped and activation must still succeed.
    #[tokio::test]
    async fn none_policy_activation_skips_certificate_binding() {
        let fixture = ActivationFixture::new(Arc::new(AuthenticationGate::open()));
        let result = fixture.activate_with(SecurityPolicy::None, 7).await;
        assert!(
            result.is_ok(),
            "None-policy activation must succeed without a channel certificate, got {result:?}"
        );
    }

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

    /// T007a / P4-SESS-07: OPC-10000-4 5.7.3.1 requires a cross-channel
    /// ActivateSession to use the same SecurityMode as the original SecureChannel.
    /// The secure-channel mismatch must be rejected before user authentication.
    #[tokio::test]
    async fn activate_session_rejects_cross_channel_security_mode_mismatch_before_authentication() {
        let gate = Arc::new(AuthenticationGate::open());
        let authenticator: Arc<dyn AuthManager> = gate.clone();
        let (client_cert, client_key) = make_cert_and_key("security-mode-client");
        let fixture = ActivationFixture::with_secured_session(authenticator, client_cert);
        let original_identity = anonymous_identity_with_policy("already-authenticated");
        let original_nonce = random::byte_string(fixture.info.config.session_nonce_length);

        fixture.mutate_session_activation(
            7,
            original_nonce,
            original_identity,
            UserToken("already-authenticated-user".to_string()),
        );
        let previous_identity = fixture.user_identity();

        let result = fixture
            .activate_with_signed_client_proof(
                SecurityPolicy::Basic256Sha256,
                MessageSecurityMode::Sign,
                8,
                &client_key,
            )
            .await;

        let error = result.expect_err(
            "SecurityMode mismatch on a cross-channel ActivateSession must be rejected",
        );
        assert_eq!(
            error,
            StatusCode::BadSecureChannelIdInvalid,
            "SecurityMode mismatch must use the secure-channel mismatch status"
        );
        assert!(
            !gate.was_called(),
            "SecurityMode mismatch must be rejected before user authentication"
        );
        assert_eq!(
            fixture.secure_channel_id(),
            7,
            "failed cross-channel activation must not rebind the session"
        );
        assert_eq!(
            fixture.user_identity(),
            previous_identity,
            "failed cross-channel activation must not change session identity"
        );
    }

    /// T007b / P4-SESS-07: OPC-10000-4 5.7.3.1 requires a cross-channel
    /// ActivateSession to use the same SecurityPolicy as the original SecureChannel.
    /// The secure-channel mismatch must be rejected before user authentication.
    #[tokio::test]
    async fn activate_session_rejects_cross_channel_security_policy_mismatch_before_authentication()
    {
        let gate = Arc::new(AuthenticationGate::open());
        let authenticator: Arc<dyn AuthManager> = gate.clone();
        let (client_cert, client_key) = make_cert_and_key("security-policy-client");
        let fixture = ActivationFixture::with_secured_session(authenticator, client_cert);
        let original_identity = anonymous_identity_with_policy("already-authenticated");
        let original_nonce = random::byte_string(fixture.info.config.session_nonce_length);

        fixture.mutate_session_activation(
            7,
            original_nonce,
            original_identity,
            UserToken("already-authenticated-user".to_string()),
        );
        let previous_identity = fixture.user_identity();

        let result = fixture
            .activate_with_signed_client_proof(
                SecurityPolicy::Aes128Sha256RsaOaep,
                MessageSecurityMode::SignAndEncrypt,
                8,
                &client_key,
            )
            .await;

        let error = result.expect_err(
            "SecurityPolicy mismatch on a cross-channel ActivateSession must be rejected",
        );
        assert_eq!(
            error,
            StatusCode::BadSecureChannelIdInvalid,
            "SecurityPolicy mismatch must use the secure-channel mismatch status"
        );
        assert!(
            !gate.was_called(),
            "SecurityPolicy mismatch must be rejected before user authentication"
        );
        assert_eq!(
            fixture.secure_channel_id(),
            7,
            "failed cross-channel activation must not rebind the session"
        );
        assert_eq!(
            fixture.user_identity(),
            previous_identity,
            "failed cross-channel activation must not change session identity"
        );
    }

    /// T008 / P4-SESS-08: OPC-10000-4 5.7.3.1 requires anonymous
    /// ActivateSession over a new Sign-only SecureChannel to fail because a
    /// non-anonymous user is required. The rejection must happen before user
    /// authentication or session rebinding.
    #[tokio::test]
    async fn activate_session_rejects_anonymous_transfer_to_new_sign_channel_before_authentication()
    {
        let gate = Arc::new(AuthenticationGate::open());
        let authenticator: Arc<dyn AuthManager> = gate.clone();
        let (client_cert, client_key) = make_cert_and_key("sign-only-anonymous-transfer-client");
        let fixture = ActivationFixture::with_secured_session_created_with_mode(
            authenticator,
            client_cert,
            MessageSecurityMode::Sign,
        );
        let original_identity = IdentityToken::UserName(UserNameIdentityToken {
            policy_id: UAString::from("already-authenticated"),
            user_name: UAString::from("already-authenticated-user"),
            password: ByteString::null(),
            encryption_algorithm: UAString::null(),
        });
        let original_nonce = random::byte_string(fixture.info.config.session_nonce_length);

        fixture.mutate_session_activation(
            7,
            original_nonce,
            original_identity,
            UserToken("already-authenticated-user".to_string()),
        );
        let previous_identity = fixture.user_identity();

        let result = fixture
            .activate_with_signed_client_proof(
                SecurityPolicy::Basic256Sha256,
                MessageSecurityMode::Sign,
                8,
                &client_key,
            )
            .await;

        let error = result.expect_err(
            "anonymous ActivateSession over a new Sign-only SecureChannel must be rejected",
        );
        assert_eq!(
            error,
            StatusCode::BadIdentityTokenRejected,
            "anonymous transfer to a new Sign-only channel must reject the identity token"
        );
        assert!(
            !gate.was_called(),
            "anonymous Sign-only transfer must be rejected before user authentication"
        );
        assert_eq!(
            fixture.secure_channel_id(),
            7,
            "failed anonymous Sign-only transfer must not rebind the session"
        );
        assert_eq!(
            fixture.user_identity(),
            previous_identity,
            "failed anonymous Sign-only transfer must not change session identity"
        );
    }

    /// T013 / P4-SESS-09: OPC-10000-4 5.7.3.2 defines the X.509
    /// `userIdentityToken` and `userTokenSignature` carried by ActivateSession,
    /// and 5.7.3.3 defines rejection results for invalid or rejected identity
    /// tokens. A failed X.509 activation must not store the rejected identity on
    /// the session before a later valid X.509 activation succeeds.
    #[tokio::test]
    async fn activate_session_failed_x509_activation_does_not_leave_rejected_identity_state() {
        let (rejected_cert, _) = make_cert_and_key("rejected-x509-state-user");
        let (accepted_cert, accepted_key) = make_cert_and_key("accepted-x509-state-user");
        let accepted_identity =
            IdentityTokenSnapshot::X509(accepted_cert.thumbprint().as_hex_string());
        let authenticator = Arc::new(X509AuthenticationGate::new(accepted_cert.thumbprint()));
        let fixture = ActivationFixture::with_x509_session(authenticator);
        fixture.trust_x509_user_certificate(&rejected_cert);
        fixture.trust_x509_user_certificate(&accepted_cert);
        let original_identity = fixture.user_identity();

        let rejected = fixture
            .activate_x509_with(&rejected_cert, &accepted_key)
            .await;

        assert_eq!(
            rejected.expect_err("bad X.509 user-token signature must be rejected"),
            StatusCode::BadUserSignatureInvalid,
            "failed X.509 activation must surface the user-token signature rejection"
        );
        assert_eq!(
            fixture.user_identity(),
            original_identity,
            "failed X.509 activation must not store the rejected identity"
        );

        fixture
            .activate_x509_with(&accepted_cert, &accepted_key)
            .await
            .expect("accepted X.509 identity should activate the session");

        assert_eq!(
            fixture.user_identity(),
            accepted_identity,
            "later valid activation must store only the accepted X.509 identity"
        );
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

    #[tokio::test]
    async fn anonymous_activation_stores_anonymous_role_on_session() {
        let fixture = ActivationFixture::new(Arc::new(AuthenticationGate::open()));
        fixture
            .activate_with(SecurityPolicy::None, 7)
            .await
            .expect("anonymous activation should succeed");

        assert_eq!(
            fixture.session.read().roles().as_slice(),
            [WellKnownRole::Anonymous.node_id()]
        );
    }

    #[tokio::test]
    async fn activation_reads_runtime_mutable_role_resolver() {
        let dynamic_role = NodeId::new(1, "RuntimeResolvedRole");
        let fixture = ActivationFixture::with_username_user("alice", "correct-password");

        {
            let mut resolver = fixture.info.role_resolver.write();
            resolver.register_role(dynamic_role.clone());
            resolver.add_mapping(
                dynamic_role.clone(),
                IdentityMappingRule::UserName("alice".into()),
            );
        }

        fixture
            .activate_username_with(SecurityPolicy::None, 7, "alice", "correct-password")
            .await
            .expect("username activation should succeed");

        assert!(fixture.session.read().roles().contains(&dynamic_role));
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
        _temp_path: Option<Arc<TempPath>>,
    }

    impl ActivationFixture {
        fn new(authenticator: Arc<dyn AuthManager>) -> Self {
            let (_server, handle) = ServerBuilder::new_anonymous("activation nonce replay test")
                .without_node_managers()
                .with_authenticator(authenticator)
                .build()
                .expect("test server should build");
            Self::from_handle(handle)
        }

        fn with_username_user(username: &str, password: &str) -> Self {
            let token_id = "runtime-role-user";
            let (_server, handle) = ServerBuilder::new()
                .without_node_managers()
                .application_name("activation runtime role resolver test")
                .add_user_token(token_id, ServerUserToken::user_pass(username, password))
                .add_endpoint(
                    "none",
                    (
                        "/",
                        SecurityPolicy::None,
                        MessageSecurityMode::None,
                        &[token_id] as &[&str],
                    ),
                )
                .discovery_urls(vec!["/".to_owned()])
                .build()
                .expect("test server should build");
            Self::from_handle(handle)
        }

        fn from_handle(handle: crate::ServerHandle) -> Self {
            Self::from_handle_with_session_binding(
                handle,
                SecurityPolicy::None,
                MessageSecurityMode::None,
                None,
            )
        }

        fn with_x509_session(authenticator: Arc<dyn AuthManager>) -> Self {
            let pki = Arc::new(TempPath::new("x509-state-cleanup-pki"));
            let no_configured_user_tokens: [&str; 0] = [];
            let (_server, handle) = ServerBuilder::new()
                .without_node_managers()
                .application_name("activation x509 state cleanup test")
                .pki_dir(pki.path())
                .with_authenticator(authenticator)
                .add_endpoint(
                    "x509_state_cleanup",
                    (
                        "/",
                        SecurityPolicy::None,
                        MessageSecurityMode::None,
                        &no_configured_user_tokens as &[&str],
                    ),
                )
                .discovery_urls(vec!["/".to_owned()])
                .build()
                .expect("test server should build");
            let (server_cert, server_key) = make_cert_and_key("x509-state-cleanup-server");
            *handle.info().server_certificate.write() = Some(server_cert);
            *handle.info().server_pkey.write() = Some(server_key);

            let mut fixture = Self::from_handle(handle);
            fixture._temp_path = Some(pki);
            fixture
        }

        fn with_secured_session(
            authenticator: Arc<dyn AuthManager>,
            client_certificate: opcua_crypto::X509,
        ) -> Self {
            Self::with_secured_session_created_with_mode(
                authenticator,
                client_certificate,
                MessageSecurityMode::SignAndEncrypt,
            )
        }

        fn with_secured_session_created_with_mode(
            authenticator: Arc<dyn AuthManager>,
            client_certificate: opcua_crypto::X509,
            original_mode: MessageSecurityMode,
        ) -> Self {
            let anonymous_tokens = [crate::config::ANONYMOUS_USER_TOKEN_ID];
            let (_server, handle) = ServerBuilder::new()
                .without_node_managers()
                .application_name("activation security mode binding test")
                .with_authenticator(authenticator)
                .add_endpoint(
                    "basic256sha256_sign",
                    (
                        "/",
                        SecurityPolicy::Basic256Sha256,
                        MessageSecurityMode::Sign,
                        &anonymous_tokens as &[&str],
                    ),
                )
                .add_endpoint(
                    "basic256sha256_sign_encrypt",
                    (
                        "/",
                        SecurityPolicy::Basic256Sha256,
                        MessageSecurityMode::SignAndEncrypt,
                        &anonymous_tokens as &[&str],
                    ),
                )
                .add_endpoint(
                    "aes128sha256rsa_oaep_sign_encrypt",
                    (
                        "/",
                        SecurityPolicy::Aes128Sha256RsaOaep,
                        MessageSecurityMode::SignAndEncrypt,
                        &anonymous_tokens as &[&str],
                    ),
                )
                .discovery_urls(vec!["/".to_owned()])
                .build()
                .expect("test server should build");
            let (server_cert, server_key) = make_cert_and_key("security-mode-server");
            *handle.info().server_certificate.write() = Some(server_cert);
            *handle.info().server_pkey.write() = Some(server_key);

            Self::from_handle_with_session_binding(
                handle,
                SecurityPolicy::Basic256Sha256,
                original_mode,
                Some(client_certificate),
            )
        }

        fn from_handle_with_session_binding(
            handle: crate::ServerHandle,
            security_policy: SecurityPolicy,
            message_security_mode: MessageSecurityMode,
            client_certificate: Option<opcua_crypto::X509>,
        ) -> Self {
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
                security_policy.to_uri().to_string(),
                anonymous_identity(),
                client_certificate,
                random::byte_string(info.config.session_nonce_length),
                UAString::from("activation-nonce-replay-test"),
                ApplicationDescription::default(),
                message_security_mode,
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
                _temp_path: None,
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

        async fn activate_x509_with(
            &self,
            cert: &opcua_crypto::X509,
            private_key: &PrivateKey,
        ) -> Result<super::ActivateSessionResponse, StatusCode> {
            let mut channel = SecureChannel::new(
                Arc::clone(&self.certificate_store),
                opcua_core::comms::secure_channel::Role::Server,
                Arc::new(RwLock::new(Default::default())),
            );
            channel.set_security_policy(SecurityPolicy::None);
            channel.set_security_mode(MessageSecurityMode::None);
            channel.set_secure_channel_id(7);

            let server_certificate = self
                .info
                .server_certificate
                .read()
                .as_ref()
                .expect("X.509 activation test must configure a server certificate")
                .clone();
            let request = x509_activate_request(
                &self.token,
                cert,
                private_key,
                &server_certificate,
                &self.session_nonce(),
            );
            let mut handler = MessageHandler::new(
                Arc::clone(&self.info),
                self.node_managers.clone(),
                Arc::clone(&self.subscriptions),
            );
            activate_session(&self.manager, &mut channel, &request, &mut handler).await
        }

        fn trust_x509_user_certificate(&self, cert: &opcua_crypto::X509) {
            let store = self.certificate_store.write();
            store
                .ensure_pki_path()
                .expect("X.509 test PKI directories should exist");
            let path = store
                .trusted_certs_dir()
                .join(CertificateStore::cert_file_name(cert));
            fs::write(path, cert.to_der().expect("test certificate should encode"))
                .expect("trusted X.509 user certificate should be written");
        }

        async fn activate_with_signed_client_proof(
            &self,
            security_policy: SecurityPolicy,
            security_mode: MessageSecurityMode,
            secure_channel_id: u32,
            client_key: &PrivateKey,
        ) -> Result<super::ActivateSessionResponse, StatusCode> {
            let mut channel = SecureChannel::new(
                Arc::clone(&self.certificate_store),
                opcua_core::comms::secure_channel::Role::Server,
                Arc::new(RwLock::new(Default::default())),
            );
            channel.set_security_policy(security_policy);
            channel.set_security_mode(security_mode);
            channel.set_secure_channel_id(secure_channel_id);
            channel.set_remote_cert(self.session.read().client_certificate().cloned());

            let mut request = activate_request(&self.token);
            request.client_signature = self.client_signature(client_key, security_policy);
            let mut handler = MessageHandler::new(
                Arc::clone(&self.info),
                self.node_managers.clone(),
                Arc::clone(&self.subscriptions),
            );
            activate_session(&self.manager, &mut channel, &request, &mut handler).await
        }

        fn client_signature(
            &self,
            client_key: &PrivateKey,
            security_policy: SecurityPolicy,
        ) -> SignatureData {
            let server_certificate = self
                .info
                .server_certificate
                .read()
                .as_ref()
                .expect("secured activation test must configure a server certificate")
                .as_byte_string();
            opcua_crypto::create_signature_data(
                client_key,
                security_policy,
                &server_certificate,
                &self.session_nonce(),
            )
            .expect("test client signature should be valid")
        }

        async fn activate_username_with(
            &self,
            security_policy: SecurityPolicy,
            secure_channel_id: u32,
            username: &str,
            password: &str,
        ) -> Result<super::ActivateSessionResponse, StatusCode> {
            let mut channel = SecureChannel::new(
                Arc::clone(&self.certificate_store),
                opcua_core::comms::secure_channel::Role::Server,
                Arc::new(RwLock::new(Default::default())),
            );
            channel.set_security_policy(security_policy);
            channel.set_security_mode(MessageSecurityMode::None);
            channel.set_secure_channel_id(secure_channel_id);

            let request = username_activate_request(&self.token, username, password);
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
                Arc::new(vec![WellKnownRole::Anonymous.node_id()]),
            );
        }
    }

    struct X509AuthenticationGate {
        accepted_thumbprint: Thumbprint,
    }

    impl X509AuthenticationGate {
        fn new(accepted_thumbprint: Thumbprint) -> Self {
            Self {
                accepted_thumbprint,
            }
        }
    }

    #[async_trait]
    impl AuthManager for X509AuthenticationGate {
        async fn authenticate_x509_identity_token(
            &self,
            _endpoint: &ServerEndpoint,
            signing_thumbprint: &Thumbprint,
        ) -> Result<UserToken, Error> {
            if signing_thumbprint == &self.accepted_thumbprint {
                Ok(UserToken(X509_STATE_CLEANUP_USER_TOKEN.to_string()))
            } else {
                Err(Error::new(
                    StatusCode::BadIdentityTokenRejected,
                    "X.509 state-cleanup test rejected certificate thumbprint",
                ))
            }
        }

        fn user_token_policies(&self, _endpoint: &ServerEndpoint) -> Vec<UserTokenPolicy> {
            vec![UserTokenPolicy {
                policy_id: UAString::from(POLICY_ID_X509),
                token_type: UserTokenType::Certificate,
                issued_token_type: UAString::null(),
                issuer_endpoint_url: UAString::null(),
                security_policy_uri: UAString::from(SecurityPolicy::Basic256Sha256.to_uri()),
            }]
        }
    }

    struct AuthenticationGate {
        called: AtomicBool,
        pause_once: AtomicBool,
        entered: Notify,
        release: Notify,
    }

    impl AuthenticationGate {
        fn open() -> Self {
            Self {
                called: AtomicBool::new(false),
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

        fn was_called(&self) -> bool {
            self.called.load(Ordering::Acquire)
        }
    }

    #[async_trait]
    impl AuthManager for AuthenticationGate {
        async fn authenticate_anonymous_token(
            &self,
            _endpoint: &ServerEndpoint,
        ) -> Result<(), Error> {
            self.called.store(true, Ordering::Release);
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
        X509(String),
        Other,
    }

    impl From<&IdentityToken> for IdentityTokenSnapshot {
        fn from(value: &IdentityToken) -> Self {
            match value {
                IdentityToken::Anonymous(token) => Self::Anonymous(token.policy_id.clone()),
                IdentityToken::X509(token) => {
                    opcua_crypto::X509::from_byte_string(&token.certificate_data)
                        .map(|cert| Self::X509(cert.thumbprint().as_hex_string()))
                        .unwrap_or(Self::Other)
                }
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

    fn username_activate_request(
        authentication_token: &NodeId,
        username: &str,
        password: &str,
    ) -> ActivateSessionRequest {
        ActivateSessionRequest {
            request_header: RequestHeader {
                authentication_token: authentication_token.clone(),
                ..Default::default()
            },
            client_signature: SignatureData::null(),
            client_software_certificates: None,
            locale_ids: None,
            user_identity_token: ExtensionObject::from_message(UserNameIdentityToken {
                policy_id: UAString::from(POLICY_ID_USER_PASS_NONE),
                user_name: UAString::from(username),
                password: ByteString::from(password.as_bytes()),
                encryption_algorithm: UAString::null(),
            }),
            user_token_signature: SignatureData::null(),
        }
    }

    fn x509_activate_request(
        authentication_token: &NodeId,
        cert: &opcua_crypto::X509,
        private_key: &PrivateKey,
        server_certificate: &opcua_crypto::X509,
        server_nonce: &ByteString,
    ) -> ActivateSessionRequest {
        let signature = opcua_crypto::create_signature_data(
            private_key,
            SecurityPolicy::Basic256Sha256,
            &server_certificate.as_byte_string(),
            server_nonce,
        )
        .expect("X.509 user-token signature should be created");

        ActivateSessionRequest {
            request_header: RequestHeader {
                authentication_token: authentication_token.clone(),
                ..Default::default()
            },
            client_signature: SignatureData::null(),
            client_software_certificates: None,
            locale_ids: None,
            user_identity_token: ExtensionObject::from_message(X509IdentityToken {
                policy_id: UAString::from(POLICY_ID_X509),
                certificate_data: cert.as_byte_string(),
            }),
            user_token_signature: signature,
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
