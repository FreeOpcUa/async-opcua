use std::{sync::Arc, time::Duration};

use opcua_core::{
    comms::{secure_channel::SecureChannel, url::hostname_from_url},
    sync::RwLock,
    trace_read_lock, trace_write_lock, ResponseMessage,
};
use opcua_crypto::{
    self, certificate_store::CertificateStore, user_identity::make_user_name_identity_token, PKey,
    SecurityPolicy,
};
use opcua_types::{
    ActivateSessionRequest, ActivateSessionResponse, AnonymousIdentityToken,
    ApplicationDescription, ByteString, CancelRequest, CancelResponse, CloseSessionRequest,
    CloseSessionResponse, CreateSessionRequest, CreateSessionResponse, EndpointDescription,
    ExtensionObject, IntegerId, NodeId, SignatureData, SignedSoftwareCertificate, StatusCode,
    UAString, UserTokenType, X509IdentityToken,
};
use rsa::RsaPrivateKey;
use tracing::error;

use crate::{
    session::{
        process_service_result, process_unexpected_response,
        request_builder::{builder_base, builder_error, RequestHeaderBuilder},
    },
    AsyncSecureChannel, IdentityToken, Session, UARequest,
};

#[derive(Clone)]
/// Sends a [`CreateSessionRequest`] to the server, returning the session id of the created
/// session. Internally, the session will store the authentication token which is used for requests
/// subsequent to this call.
///
/// See OPC UA Part 4 - Services 5.6.2 for complete description of the service and error responses.
///
/// Note that in order to use the session you will need to store the auth token and
/// use that in subsequent requests.
///
/// Note: Avoid calling this on sessions managed by the [`Session`] type. Session creation
/// is handled automatically as part of connect/reconnect logic.
pub struct CreateSession<'a> {
    client_description: ApplicationDescription,
    server_uri: UAString,
    endpoint_url: UAString,
    session_name: UAString,
    client_certificate: ByteString,
    session_timeout: f64,
    max_response_message_size: u32,
    certificate_store: &'a RwLock<CertificateStore>,
    endpoint: &'a EndpointDescription,

    header: RequestHeaderBuilder,
}

builder_base!(CreateSession<'a>);

impl<'a> CreateSession<'a> {
    /// Create a new `CreateSession` request on the given session.
    ///
    /// Crate private since there is no way to safely use this.
    pub(crate) fn new(session: &'a Session) -> Self {
        Self {
            endpoint_url: session.session_info.endpoint.endpoint_url.clone(),
            server_uri: UAString::null(),
            client_description: session.application_description.clone(),
            session_name: session.session_name.clone(),
            client_certificate: {
                let cert_store = trace_read_lock!(session.certificate_store);
                cert_store
                    .read_own_cert()
                    .ok()
                    .map(|m| m.as_byte_string())
                    .unwrap_or_default()
            },
            endpoint: &session.session_info.endpoint,
            certificate_store: &session.certificate_store,
            session_timeout: session.session_timeout,
            max_response_message_size: 0,
            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Create a new `CreateSession` request with the given data.
    pub fn new_manual(
        certificate_store: &'a RwLock<CertificateStore>,
        endpoint: &'a EndpointDescription,
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            endpoint_url: UAString::null(),
            server_uri: UAString::null(),
            client_description: ApplicationDescription::default(),
            session_name: UAString::null(),
            client_certificate: ByteString::null(),
            session_timeout: 0.0,
            max_response_message_size: 0,
            certificate_store,
            endpoint,
            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// Set the client description.
    pub fn client_description(mut self, desc: impl Into<ApplicationDescription>) -> Self {
        self.client_description = desc.into();
        self
    }

    /// Set the server URI.
    pub fn server_uri(mut self, server_uri: impl Into<UAString>) -> Self {
        self.server_uri = server_uri.into();
        self
    }

    /// Set the target endpoint URL.
    pub fn endpoint_url(mut self, endpoint_url: impl Into<UAString>) -> Self {
        self.endpoint_url = endpoint_url.into();
        self
    }

    /// Set the session name.
    pub fn session_name(mut self, session_name: impl Into<UAString>) -> Self {
        self.session_name = session_name.into();
        self
    }

    /// Set the client certificate.
    pub fn client_certificate(mut self, client_certificate: ByteString) -> Self {
        self.client_certificate = client_certificate;
        self
    }

    /// Load the client certificate from the certificate store.
    pub fn client_cert_from_store(mut self, certificate_store: &RwLock<CertificateStore>) -> Self {
        let cert_store = trace_read_lock!(certificate_store);
        self.client_certificate = cert_store
            .read_own_cert()
            .ok()
            .map(|m| m.as_byte_string())
            .unwrap_or_default();
        self
    }

    /// Set the timeout for the session.
    pub fn session_timeout(mut self, session_timeout: f64) -> Self {
        self.session_timeout = session_timeout;
        self
    }

    /// Set the requested maximum response message size.
    pub fn max_response_message_size(mut self, max_response_message_size: u32) -> Self {
        self.max_response_message_size = max_response_message_size;
        self
    }
}

impl UARequest for CreateSession<'_> {
    type Out = CreateSessionResponse;

    async fn send<'a>(self, channel: &'a crate::AsyncSecureChannel) -> Result<Self::Out, StatusCode>
    where
        Self: 'a,
    {
        let request = CreateSessionRequest {
            request_header: self.header.header,
            client_description: self.client_description,
            server_uri: self.server_uri,
            endpoint_url: self.endpoint_url,
            session_name: self.session_name,
            client_nonce: channel.client_nonce(),
            client_certificate: self.client_certificate,
            requested_session_timeout: self.session_timeout,
            max_response_message_size: self.max_response_message_size,
        };
        let response = channel.send(request, self.header.timeout).await?;

        if let ResponseMessage::CreateSession(response) = response {
            tracing::debug!("create_session, success");
            process_service_result(&response.response_header)?;

            let security_policy = channel.security_policy();

            if security_policy != SecurityPolicy::None {
                if let Ok(server_certificate) =
                    opcua_crypto::X509::from_byte_string(&response.server_certificate)
                {
                    // Validate server certificate against hostname and application_uri
                    let hostname = hostname_from_url(self.endpoint.endpoint_url.as_ref())
                        .map_err(|_| StatusCode::BadUnexpectedError)?;
                    let application_uri = self.endpoint.server.application_uri.as_ref();

                    let certificate_store = trace_write_lock!(self.certificate_store);
                    certificate_store.validate_or_reject_application_instance_cert(
                        &server_certificate,
                        security_policy,
                        Some(&hostname),
                        Some(application_uri),
                    )?;
                } else {
                    return Err(StatusCode::BadCertificateInvalid);
                }
            }

            channel.update_from_created_session(
                &response.server_nonce,
                &response.server_certificate,
            )?;

            Ok(*response)
        } else {
            tracing::error!("create_session failed");
            Err(process_unexpected_response(response))
        }
    }
}

#[derive(Debug, Clone)]
/// Sends an [`ActivateSessionRequest`] to the server to activate the session tied to
/// the secure channel.
///
/// See OPC UA Part 4 - Services 5.6.3 for complete description of the service and error responses.
///
/// Note: Avoid calling this on sessions managed by the [`Session`] type. Session activation
/// is handled automatically as part of connect/reconnect logic.
pub struct ActivateSession {
    identity_token: IdentityToken,
    private_key: Option<PKey<RsaPrivateKey>>,
    locale_ids: Vec<UAString>,
    client_software_certificates: Vec<SignedSoftwareCertificate>,
    endpoint: EndpointDescription,

    header: RequestHeaderBuilder,
}

builder_base!(ActivateSession);

impl ActivateSession {
    /// Create a new `ActivateSession` request.
    ///
    /// Crate private since there is no way to safely use this.
    pub(crate) fn new(session: &Session) -> Self {
        Self {
            identity_token: session.session_info.user_identity_token.clone(),
            private_key: {
                let cert_store = trace_read_lock!(session.certificate_store);
                cert_store.read_own_pkey().ok()
            },
            locale_ids: session
                .session_info
                .preferred_locales
                .iter()
                .map(UAString::from)
                .collect(),
            client_software_certificates: Vec::new(),
            endpoint: session.session_info.endpoint.clone(),
            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Create a new `ActivateSession` request.
    pub fn new_manual(
        endpoint: EndpointDescription,
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            identity_token: IdentityToken::Anonymous,
            private_key: None,
            locale_ids: Vec::new(),
            client_software_certificates: Vec::new(),
            endpoint,
            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// Set the identity token.
    pub fn identity_token(mut self, identity_token: IdentityToken) -> Self {
        self.identity_token = identity_token;
        self
    }

    /// Set the client private key.
    pub fn private_key(mut self, private_key: PKey<RsaPrivateKey>) -> Self {
        self.private_key = Some(private_key);
        self
    }

    /// Set the requested list of locales.
    pub fn locale_ids(mut self, locale_ids: Vec<UAString>) -> Self {
        self.locale_ids = locale_ids;
        self
    }

    /// Add a requested locale with the given ID.
    pub fn locale_id(mut self, locale_id: impl Into<UAString>) -> Self {
        self.locale_ids.push(locale_id.into());
        self
    }

    /// Set the client software certificates.
    pub fn client_software_certificates(
        mut self,
        certificates: Vec<SignedSoftwareCertificate>,
    ) -> Self {
        self.client_software_certificates = certificates;
        self
    }

    /// Add a client software certificate.
    pub fn client_software_certificate(mut self, certificate: SignedSoftwareCertificate) -> Self {
        self.client_software_certificates.push(certificate);
        self
    }

    fn user_identity_token(
        &self,
        secure_channel: &SecureChannel,
    ) -> Result<(ExtensionObject, SignatureData), StatusCode> {
        let user_token_type = match &self.identity_token {
            IdentityToken::Anonymous => UserTokenType::Anonymous,
            IdentityToken::UserName(_, _) => UserTokenType::UserName,
            IdentityToken::X509(_, _) => UserTokenType::Certificate,
        };
        let Some(policy) = self.endpoint.find_policy(user_token_type) else {
            builder_error!(
                self,
                "Cannot find user token type {:?} for this endpoint, cannot connect",
                user_token_type
            );
            return Err(StatusCode::BadSecurityPolicyRejected);
        };
        let security_policy = if policy.security_policy_uri.is_null() {
            // Assume None
            SecurityPolicy::None
        } else {
            SecurityPolicy::from_uri(policy.security_policy_uri.as_ref())
        };

        if security_policy == SecurityPolicy::Unknown {
            error!("Unknown security policy {}", policy.security_policy_uri);
            return Err(StatusCode::BadSecurityPolicyRejected);
        }

        match &self.identity_token {
            IdentityToken::Anonymous => {
                let identity_token = AnonymousIdentityToken {
                    policy_id: policy.policy_id.clone(),
                };
                let identity_token = ExtensionObject::from_message(identity_token);
                Ok((identity_token, SignatureData::null()))
            }
            IdentityToken::UserName(user, pass) => {
                let channel_sec_policy = secure_channel.security_policy();
                let nonce = secure_channel.remote_nonce();
                let cert = secure_channel.remote_cert();
                let identity_token = make_user_name_identity_token(
                    channel_sec_policy,
                    policy,
                    nonce,
                    &cert,
                    user,
                    pass,
                )?;
                Ok((
                    ExtensionObject::from_message(identity_token),
                    SignatureData::null(),
                ))
            }
            IdentityToken::X509(cert_path, private_key_path) => {
                let nonce = secure_channel.remote_nonce();
                let cert = secure_channel.remote_cert();
                let Some(server_cert) = &cert else {
                    error!("Cannot create an X509IdentityToken because the remote server has no cert with which to create a signature");
                    return Err(StatusCode::BadCertificateInvalid);
                };
                let certificate_data = CertificateStore::read_cert(cert_path).map_err(|e| {
                    error!(
                        "Certificate cannot be loaded from path {}, error = {}",
                        cert_path.to_str().unwrap(),
                        e
                    );
                    StatusCode::BadSecurityPolicyRejected
                })?;
                let private_key = CertificateStore::read_pkey(private_key_path).map_err(|e| {
                    error!(
                        "Private key cannot be loaded from path {}, error = {}",
                        private_key_path.to_str().unwrap(),
                        e
                    );
                    StatusCode::BadSecurityPolicyRejected
                })?;
                let user_token_signature = opcua_crypto::create_signature_data(
                    &private_key,
                    security_policy,
                    &server_cert.as_byte_string(),
                    &ByteString::from(&nonce),
                )?;

                // Create identity token
                let identity_token = X509IdentityToken {
                    policy_id: policy.policy_id.clone(),
                    certificate_data: certificate_data.as_byte_string(),
                };

                Ok((
                    ExtensionObject::from_message(identity_token),
                    user_token_signature,
                ))
            }
        }
    }

    fn build_request(
        self,
        channel: &AsyncSecureChannel,
    ) -> Result<ActivateSessionRequest, StatusCode> {
        let secure_channel = trace_read_lock!(channel.secure_channel);
        let (user_identity_token, user_token_signature) =
            self.user_identity_token(&secure_channel)?;
        let security_policy = secure_channel.security_policy();
        let client_signature = match security_policy {
            SecurityPolicy::None => SignatureData::null(),
            _ => {
                let Some(client_pkey) = self.private_key else {
                    error!("Cannot create client signature - no pkey!");
                    return Err(StatusCode::BadUnexpectedError);
                };

                let Some(server_cert) = secure_channel.remote_cert() else {
                    error!("Cannot sign server certificate because server cert is null");
                    return Err(StatusCode::BadUnexpectedError);
                };

                let server_nonce = secure_channel.remote_nonce_as_byte_string();
                if server_nonce.is_empty() {
                    error!("Cannot sign server certificate because server nonce is empty");
                    return Err(StatusCode::BadUnexpectedError);
                }

                let server_cert = server_cert.as_byte_string();
                opcua_crypto::create_signature_data(
                    &client_pkey,
                    security_policy,
                    &server_cert,
                    &server_nonce,
                )?
            }
        };

        Ok(ActivateSessionRequest {
            request_header: self.header.header,
            client_signature,
            client_software_certificates: if self.client_software_certificates.is_empty() {
                None
            } else {
                Some(self.client_software_certificates)
            },
            locale_ids: if self.locale_ids.is_empty() {
                None
            } else {
                Some(self.locale_ids)
            },
            user_identity_token,
            user_token_signature,
        })
    }
}

impl UARequest for ActivateSession {
    type Out = ActivateSessionResponse;

    async fn send<'a>(self, channel: &'a crate::AsyncSecureChannel) -> Result<Self::Out, StatusCode>
    where
        Self: 'a,
    {
        let timeout = self.header.timeout;
        let request = self.build_request(channel)?;

        let response = channel.send(request, timeout).await?;

        if let ResponseMessage::ActivateSession(response) = response {
            tracing::debug!("activate_session success");
            // trace!("ActivateSessionResponse = {:#?}", response);
            process_service_result(&response.response_header)?;
            Ok(*response)
        } else {
            tracing::error!("activate_session failed");
            Err(process_unexpected_response(response))
        }
    }
}

#[derive(Debug, Clone)]
/// Close the session by sending a [`CloseSessionRequest`] to the server.
///
/// Note: Avoid using this on an session managed by the [`Session`] type,
/// instead call [`Session::disconnect`].
pub struct CloseSession {
    delete_subscriptions: bool,
    header: RequestHeaderBuilder,
}

builder_base!(CloseSession);

impl CloseSession {
    /// Create a new `CloseSession` request.
    ///
    /// Crate private as there is no way to use this safely.
    pub(crate) fn new(session: &Session) -> Self {
        Self {
            delete_subscriptions: true,
            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Create a new `CloseSession` request.
    pub fn new_manual(
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            delete_subscriptions: true,
            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// Set `DeleteSubscriptions`, indicating to the server whether it should
    /// delete subscriptions immediately or wait for them to expire.
    pub fn delete_subscriptions(mut self, delete_subscriptions: bool) -> Self {
        self.delete_subscriptions = delete_subscriptions;
        self
    }
}

impl UARequest for CloseSession {
    type Out = CloseSessionResponse;

    async fn send<'a>(self, channel: &'a AsyncSecureChannel) -> Result<Self::Out, StatusCode>
    where
        Self: 'a,
    {
        let request = CloseSessionRequest {
            delete_subscriptions: self.delete_subscriptions,
            request_header: self.header.header,
        };
        let response = channel.send(request, self.header.timeout).await?;
        if let ResponseMessage::CloseSession(response) = response {
            process_service_result(&response.response_header)?;
            Ok(*response)
        } else {
            error!("close_session failed {:?}", response);
            Err(process_unexpected_response(response))
        }
    }
}

#[derive(Debug, Clone)]
/// Cancels an outstanding service request by sending a [`CancelRequest`] to the server.
///
/// See OPC UA Part 4 - Services 5.6.5 for complete description of the service and error responses.
pub struct Cancel {
    request_handle: IntegerId,
    header: RequestHeaderBuilder,
}

builder_base!(Cancel);

impl Cancel {
    /// Create a new cancel request, to cancel a running service call.
    pub fn new(request_to_cancel: IntegerId, session: &Session) -> Self {
        Self {
            request_handle: request_to_cancel,
            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Create a new cancel request, to cancel a running service call.
    pub fn new_manual(
        request_to_cancel: IntegerId,
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            request_handle: request_to_cancel,
            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }
}

impl UARequest for Cancel {
    type Out = CancelResponse;

    async fn send<'a>(self, channel: &'a AsyncSecureChannel) -> Result<Self::Out, StatusCode>
    where
        Self: 'a,
    {
        let request = CancelRequest {
            request_header: self.header.header,
            request_handle: self.request_handle,
        };

        let response = channel.send(request, self.header.timeout).await?;
        if let ResponseMessage::Cancel(response) = response {
            process_service_result(&response.response_header)?;
            Ok(*response)
        } else {
            Err(process_unexpected_response(response))
        }
    }
}

impl Session {
    /// Sends a [`CreateSessionRequest`] to the server, returning the session id of the created
    /// session. Internally, the session will store the authentication token which is used for requests
    /// subsequent to this call.
    ///
    /// See OPC UA Part 4 - Services 5.6.2 for complete description of the service and error responses.
    ///
    /// # Returns
    ///
    /// * `Ok(NodeId)` - Success, session id
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub(crate) async fn create_session(&self) -> Result<NodeId, StatusCode> {
        let response = CreateSession::new(self).send(&self.channel).await?;

        let session_id = {
            self.session_id.store(Arc::new(response.session_id.clone()));
            response.session_id.clone()
        };
        self.auth_token
            .store(Arc::new(response.authentication_token));

        Ok(session_id)
    }

    /// Sends an [`ActivateSessionRequest`] to the server to activate this session
    ///
    /// See OPC UA Part 4 - Services 5.6.3 for complete description of the service and error responses.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Success
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub(crate) async fn activate_session(&self) -> Result<(), StatusCode> {
        ActivateSession::new(self).send(&self.channel).await?;
        Ok(())
    }

    /// Close the session by sending a [`CloseSessionRequest`] to the server.
    ///
    /// This is not accessible by users, they must instead call `disconnect` to properly close the session.
    pub(crate) async fn close_session(&self, delete_subscriptions: bool) -> Result<(), StatusCode> {
        CloseSession::new(self)
            .delete_subscriptions(delete_subscriptions)
            .send(&self.channel)
            .await?;
        Ok(())
    }

    /// Cancels an outstanding service request by sending a [`CancelRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.6.5 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `request_handle` - Handle to the outstanding request to be cancelled.
    ///
    /// # Returns
    ///
    /// * `Ok(u32)` - Success, number of cancelled requests
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn cancel(&self, request_handle: IntegerId) -> Result<u32, StatusCode> {
        Ok(Cancel::new(request_handle, self)
            .send(&self.channel)
            .await?
            .cancel_count)
    }
}
