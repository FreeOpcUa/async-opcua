//! Security integration tests for PubSub keys, OAuth2 identities, and password identities.

use std::{
    fs,
    future::Future,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use opcua_client::{ClientBuilder, IdentityToken};
use opcua_crypto::{
    AlternateNames, CertificateStore, KeySize, PrivateKey, SecurityPolicy, X509Data, X509,
};
use opcua_server::{
    authenticator::{issued_token_security_policy, user_pass_security_policy_id, AuthManager},
    authorization::SessionAuthorizationProfile,
    diagnostics::NamespaceMetadata,
    node_manager::memory::simple_node_manager,
    services::security::{
        GetSecurityKeysRequest, GetSecurityKeysResponse, SecurityGroupKeys, SecurityKeyService,
        CURRENT_SECURITY_TOKEN_ID,
    },
    ServerBuilder, ServerEndpoint, ServerHandle, ServerUserToken, ANONYMOUS_USER_TOKEN_ID,
};
use opcua_types::{
    issued_token_types, ActivateSessionRequest, ByteString, Error, ExtensionObject,
    IssuedIdentityToken, MessageSecurityMode, SignatureData, StatusCode, UAString,
    UserNameIdentityToken, UserTokenPolicy, UserTokenType,
};
use serde_json::{json, Value};
use tokio::net::TcpListener;

const OAUTH2_PATH: &str = "/oauth2";
const OAUTH2_ISSUER: &str = "https://issuer.example";
const OAUTH2_AUDIENCE: &str = "opcua-server";
const PUBSUB_SECURITY_POLICY_URI: &str =
    "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss";
const AUTH_FAILURE_TARPIT_MIN: Duration = Duration::from_millis(100);
const AUTH_FAILURE_TARPIT_TIMEOUT: Duration = Duration::from_secs(1);

static NEXT_TEST_ID: AtomicUsize = AtomicUsize::new(0);

async fn assert_tarpitted_auth_failure<T>(
    auth: impl Future<Output = Result<T, Error>>,
    failure: &str,
) -> Error {
    let started = Instant::now();
    tokio::pin!(auth);

    tokio::select! {
        result = &mut auth => {
            let status = result.err().map(|err| err.status());
            panic!("{failure} returned before tarpitting; status={status:?}");
        }
        probe = tokio::time::timeout(Duration::from_millis(10), tokio::task::yield_now()) => {
            assert!(probe.is_ok(), "auth tarpit must not block the current-thread runtime");
        }
    }

    let result = tokio::time::timeout(AUTH_FAILURE_TARPIT_TIMEOUT, &mut auth)
        .await
        .expect("auth failure tarpit should complete");
    let err = match result {
        Ok(_) => panic!("{failure} should be rejected"),
        Err(err) => err,
    };

    assert_eq!(err.status(), StatusCode::BadUserAccessDenied);
    assert!(
        started.elapsed() >= AUTH_FAILURE_TARPIT_MIN,
        "{failure} returned before the minimum tarpit delay"
    );
    err
}

#[test]
fn get_security_keys_contract_matches_part14_signature() {
    let request = GetSecurityKeysRequest::new("group-1", CURRENT_SECURITY_TOKEN_ID, 2);

    assert_eq!(request.security_group_id.as_ref(), "group-1");
    assert_eq!(request.starting_token_id, CURRENT_SECURITY_TOKEN_ID);
    assert_eq!(request.requested_key_count, 2);

    let response = GetSecurityKeysResponse::new(
        "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss",
        7,
        vec![
            ByteString::from(b"current-key"),
            ByteString::from(b"next-key"),
        ],
        500.0,
        1_000.0,
    );

    assert_eq!(
        response.security_policy_uri.as_ref(),
        "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"
    );
    assert_eq!(response.first_token_id, 7);
    assert_eq!(response.keys.len(), 2);
    assert_eq!(response.time_to_next_key, 500.0);
    assert_eq!(response.key_lifetime, 1_000.0);
}

#[test]
fn get_security_keys_handler_returns_current_and_future_keys() {
    let service = SecurityKeyService::new();
    service
        .register_security_group("group-1", security_group_keys(7))
        .unwrap();

    let response = service
        .get_security_keys(GetSecurityKeysRequest::new(
            "group-1",
            CURRENT_SECURITY_TOKEN_ID,
            2,
        ))
        .unwrap();

    assert_eq!(
        response.security_policy_uri.as_ref(),
        PUBSUB_SECURITY_POLICY_URI
    );
    assert_eq!(response.first_token_id, 7);
    assert_eq!(response.keys, key_bytes(&["current-key", "next-key"]));
    assert!(response.time_to_next_key <= 60_000.0);
    assert!(response.time_to_next_key > 59_000.0);
    assert_eq!(response.key_lifetime, 60_000.0);
}

#[test]
fn get_security_keys_handler_can_start_at_future_token() {
    let service = SecurityKeyService::new();
    service
        .register_security_group("group-1", security_group_keys(7))
        .unwrap();

    let response = service
        .get_security_keys(GetSecurityKeysRequest::new("group-1", 8, 2))
        .unwrap();

    assert_eq!(response.first_token_id, 8);
    assert_eq!(response.keys, key_bytes(&["next-key"]));
}

#[test]
fn get_security_keys_handler_rejects_unknown_group() {
    let service = SecurityKeyService::new();

    let error = service
        .get_security_keys(GetSecurityKeysRequest::new(
            "missing",
            CURRENT_SECURITY_TOKEN_ID,
            1,
        ))
        .unwrap_err();

    assert_eq!(error, StatusCode::BadNotFound);
}

#[test]
fn get_security_keys_handler_rejects_invalid_requests() {
    let service = SecurityKeyService::new();
    service
        .register_security_group("group-1", security_group_keys(7))
        .unwrap();

    let empty_group = service
        .get_security_keys(GetSecurityKeysRequest::new(
            "",
            CURRENT_SECURITY_TOKEN_ID,
            1,
        ))
        .unwrap_err();
    let zero_count = service
        .get_security_keys(GetSecurityKeysRequest::new(
            "group-1",
            CURRENT_SECURITY_TOKEN_ID,
            0,
        ))
        .unwrap_err();

    assert_eq!(empty_group, StatusCode::BadInvalidArgument);
    assert_eq!(zero_count, StatusCode::BadInvalidArgument);
}

#[tokio::test]
async fn open_secure_channel_untrusted_client_cert_returns_bad_security_checks_failed() {
    let temp = TempPath::new("open-secure-channel-untrusted-client");
    let server_pki = temp.path().join("server-pki");
    let client_pki = temp.path().join("client-pki");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("security test listener should bind");
    let endpoint_url = format!(
        "opc.tcp://127.0.0.1:{}/",
        listener
            .local_addr()
            .expect("security test listener should have address")
            .port()
    );
    let port = listener
        .local_addr()
        .expect("security test listener should have address")
        .port();

    let (server, handle) = ServerBuilder::new()
        .application_name("OpenSecureChannel Security Test Server")
        .application_uri("urn:open-secure-channel-security-test-server")
        .product_uri("urn:open-secure-channel-security-test-server")
        .host("127.0.0.1")
        .port(port)
        .pki_dir(&server_pki)
        .create_sample_keypair(true)
        .trust_client_certs(false)
        .discovery_urls(vec![endpoint_url.clone()])
        .add_endpoint(
            "secured",
            (
                "/",
                SecurityPolicy::Aes128Sha256RsaOaep,
                MessageSecurityMode::SignAndEncrypt,
                &[ANONYMOUS_USER_TOKEN_ID] as &[&str],
            ),
        )
        .with_node_manager(simple_node_manager(
            NamespaceMetadata {
                namespace_uri: "urn:open-secure-channel-security-test".to_string(),
                namespace_index: 2,
                ..Default::default()
            },
            "open-secure-channel-security-test",
        ))
        .build()
        .expect("OpenSecureChannel security test server should build");
    handle.info().port.store(port, Ordering::Relaxed);
    let endpoint = handle
        .info()
        .endpoints(&UAString::from(endpoint_url.as_str()), &None)
        .expect("security test endpoint should be described")
        .into_iter()
        .find(|endpoint| {
            endpoint.security_policy_uri.as_ref() == SecurityPolicy::Aes128Sha256RsaOaep.to_uri()
                && endpoint.security_mode == MessageSecurityMode::SignAndEncrypt
        })
        .expect("secured security test endpoint should be advertised");
    let server_task = tokio::spawn(async move {
        let _ = server.run_with(listener).await;
    });

    let mut client = ClientBuilder::new()
        .application_name("OpenSecureChannel Security Test Client")
        .application_uri("urn:open-secure-channel-security-test-client")
        .product_uri("urn:open-secure-channel-security-test-client")
        .pki_dir(&client_pki)
        .create_sample_keypair(true)
        .trust_server_certs(true)
        .session_retry_limit(0)
        .session_retry_initial(Duration::from_millis(20))
        .client()
        .expect("OpenSecureChannel security test client should build");

    let (_session, event_loop) = client
        .connect_to_endpoint_directly(endpoint, IdentityToken::Anonymous)
        .expect("session event loop should be created before channel polling");

    // OPC UA Part 4 6.1.3: an untrusted application certificate fails the
    // secured OpenSecureChannel trust check.
    let status = tokio::time::timeout(Duration::from_secs(10), event_loop.run())
        .await
        .expect("OpenSecureChannel rejection should complete");

    handle.cancel();
    server_task.abort();

    assert_eq!(status, StatusCode::BadSecurityChecksFailed);
}

fn security_group_keys(first_token_id: u32) -> SecurityGroupKeys {
    SecurityGroupKeys::with_current_key_started_at(
        PUBSUB_SECURITY_POLICY_URI,
        first_token_id,
        key_bytes(&["current-key", "next-key"]),
        Duration::from_secs(60),
        Instant::now(),
    )
    .unwrap()
}

fn key_bytes(keys: &[&str]) -> Vec<ByteString> {
    keys.iter()
        .map(|key| ByteString::from(key.as_bytes()))
        .collect()
}

struct TempPath {
    path: PathBuf,
}

impl TempPath {
    fn new(name: &str) -> Self {
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::current_dir()
            .expect("current dir")
            .join("target")
            .join("security_tests")
            .join(format!("{name}-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("temporary test directory should be created");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct IssuedTokenAuthenticator;

#[async_trait]
impl AuthManager for IssuedTokenAuthenticator {
    fn user_token_policies(&self, endpoint: &ServerEndpoint) -> Vec<UserTokenPolicy> {
        if endpoint.path == OAUTH2_PATH {
            vec![UserTokenPolicy {
                policy_id: issued_token_security_policy(endpoint),
                token_type: UserTokenType::IssuedToken,
                issued_token_type: UAString::from(issued_token_types::JSON_WEB_TOKEN),
                issuer_endpoint_url: UAString::from(OAUTH2_ISSUER),
                security_policy_uri: UAString::null(),
            }]
        } else {
            Vec::new()
        }
    }
}

struct OAuth2Fixture {
    endpoint_url: String,
    handle: ServerHandle,
    private_key: PrivateKey,
    policy_id: UAString,
    _pki: TempPath,
}

impl OAuth2Fixture {
    fn new() -> Self {
        let pki = TempPath::new("oauth2-pki");
        let (private_key, policy_id, issuer_cert_path) =
            setup_trusted_oauth2_certificate(pki.path());
        let endpoint = ServerEndpoint::new_none(OAUTH2_PATH, &[]);
        let policy_id = {
            assert_eq!(issued_token_security_policy(&endpoint), policy_id);
            policy_id
        };

        let (_server, handle) = ServerBuilder::new()
            .without_node_managers()
            .application_name("OAuth2 Security Test Server")
            .application_uri("urn:oauth2-security-test-server")
            .product_uri("urn:oauth2-security-test-server")
            .host("127.0.0.1")
            .pki_dir(pki.path())
            .create_sample_keypair(true)
            .discovery_urls(vec!["opc.tcp://127.0.0.1:4855/oauth2".to_string()])
            .oauth2_issuer(OAUTH2_ISSUER)
            .oauth2_audience(OAUTH2_AUDIENCE)
            .oauth2_issuer_certificate_path(issuer_cert_path)
            .with_authenticator(Arc::new(IssuedTokenAuthenticator))
            .add_endpoint("oauth2", endpoint)
            .build()
            .expect("OAuth2 security test server should build");

        Self {
            endpoint_url: format!("{}{}", handle.info().base_endpoint(), OAUTH2_PATH),
            handle,
            private_key,
            policy_id,
            _pki: pki,
        }
    }

    async fn authenticate(
        &self,
        token: &str,
    ) -> Result<opcua_server::authenticator::UserToken, Error> {
        let request = activate_session_request(token, self.policy_id.clone());
        self.handle
            .info()
            .authenticate_endpoint(
                &request,
                &self.endpoint_url,
                SecurityPolicy::None,
                MessageSecurityMode::None,
                request.user_identity_token.clone(),
                &ByteString::null(),
            )
            .await
            .map(|(user_token, _claims)| user_token)
    }

    async fn authenticate_encrypted_token(
        &self,
        encrypted_token: ByteString,
        encryption_algorithm: UAString,
    ) -> Result<opcua_server::authenticator::UserToken, Error> {
        let request = activate_session_request_with_issued_token(IssuedIdentityToken {
            policy_id: self.policy_id.clone(),
            token_data: encrypted_token,
            encryption_algorithm,
        });
        self.handle
            .info()
            .authenticate_endpoint(
                &request,
                &self.endpoint_url,
                SecurityPolicy::None,
                MessageSecurityMode::None,
                request.user_identity_token.clone(),
                &ByteString::null(),
            )
            .await
            .map(|(user_token, _claims)| user_token)
    }

    fn server_private_key(&self) -> PrivateKey {
        self.handle
            .info()
            .server_pkey
            .read()
            .clone()
            .expect("test server should have a private key")
    }

    async fn authenticate_with_claims(
        &self,
        token: &str,
    ) -> Result<
        (
            opcua_server::authenticator::UserToken,
            opcua_crypto::identity::ClaimProfile,
        ),
        Error,
    > {
        let request = activate_session_request(token, self.policy_id.clone());
        self.handle
            .info()
            .authenticate_endpoint(
                &request,
                &self.endpoint_url,
                SecurityPolicy::None,
                MessageSecurityMode::None,
                request.user_identity_token.clone(),
                &ByteString::null(),
            )
            .await
            .map(|(user_token, claims)| {
                (
                    user_token,
                    claims.expect("OAuth2 authentication should return claims"),
                )
            })
    }
}

struct PasswordFixture {
    endpoint_url: String,
    handle: ServerHandle,
    policy_id: UAString,
    _pki: TempPath,
}

impl PasswordFixture {
    fn new() -> Self {
        const PASSWORD_PATH: &str = "/password";
        const PASSWORD_USER_TOKEN_ID: &str = "password-user";

        let pki = TempPath::new("password-pki");
        let endpoint = ServerEndpoint::new_none(PASSWORD_PATH, &[PASSWORD_USER_TOKEN_ID.into()]);
        let policy_id = user_pass_security_policy_id(&endpoint);
        let (_server, handle) = ServerBuilder::new()
            .without_node_managers()
            .application_name("Password Security Test Server")
            .application_uri("urn:password-security-test-server")
            .product_uri("urn:password-security-test-server")
            .host("127.0.0.1")
            .pki_dir(pki.path())
            .discovery_urls(vec!["opc.tcp://127.0.0.1:4856/password".to_string()])
            .add_user_token(
                PASSWORD_USER_TOKEN_ID,
                ServerUserToken::user_pass("brew-operator", "correct-password"),
            )
            .add_endpoint("password", endpoint)
            .build()
            .expect("password security test server should build");

        Self {
            endpoint_url: format!("{}{}", handle.info().base_endpoint(), PASSWORD_PATH),
            handle,
            policy_id,
            _pki: pki,
        }
    }

    async fn authenticate(&self, username: &str, password: &str) -> Result<(), Error> {
        let request = activate_session_request_with_username_token(
            self.policy_id.clone(),
            username,
            password,
        );
        self.handle
            .info()
            .authenticate_endpoint(
                &request,
                &self.endpoint_url,
                SecurityPolicy::None,
                MessageSecurityMode::None,
                request.user_identity_token.clone(),
                &ByteString::null(),
            )
            .await
            .map(|_| ())
    }
}

// Feature 025 US1: also returns the issuer cert path — the validator now pins to it.
fn setup_trusted_oauth2_certificate(pki_path: &Path) -> (PrivateKey, UAString, std::path::PathBuf) {
    let certificate_store = CertificateStore::new(pki_path);
    certificate_store
        .ensure_pki_path()
        .expect("PKI structure should be created");

    let (cert, private_key) = oauth2_cert_and_key("oauth2-idp");
    let cert_path = certificate_store
        .trusted_certs_dir()
        .join(CertificateStore::cert_file_name(&cert));
    fs::write(
        &cert_path,
        cert.to_der().expect("certificate should encode"),
    )
    .expect("trusted OAuth2 certificate should be written");

    let endpoint = ServerEndpoint::new_none(OAUTH2_PATH, &[]);
    (
        private_key,
        issued_token_security_policy(&endpoint),
        cert_path,
    )
}

fn oauth2_cert_and_key(common_name: &str) -> (X509, PrivateKey) {
    let mut alt_host_names = AlternateNames::new();
    alt_host_names.add_dns("localhost");
    alt_host_names.add_uri("urn:oauth2-idp");
    let x509_data = X509Data {
        key_size: 2048,
        common_name: common_name.to_string(),
        organization: "async-opcua tests".to_string(),
        organizational_unit: "security".to_string(),
        country: "US".to_string(),
        state: "test".to_string(),
        alt_host_names,
        certificate_duration_days: 30,
    };
    X509::cert_and_pkey(&x509_data).expect("OAuth2 test certificate should be generated")
}

fn activate_session_request(token: &str, policy_id: UAString) -> ActivateSessionRequest {
    activate_session_request_with_issued_token(IssuedIdentityToken {
        policy_id,
        token_data: ByteString::from(token.as_bytes()),
        encryption_algorithm: UAString::null(),
    })
}

fn activate_session_request_with_issued_token(
    token: IssuedIdentityToken,
) -> ActivateSessionRequest {
    ActivateSessionRequest {
        request_header: Default::default(),
        client_signature: SignatureData::null(),
        client_software_certificates: None,
        locale_ids: None,
        user_identity_token: ExtensionObject::from_message(token),
        user_token_signature: SignatureData::null(),
    }
}

fn activate_session_request_with_username_token(
    policy_id: UAString,
    username: &str,
    password: &str,
) -> ActivateSessionRequest {
    ActivateSessionRequest {
        request_header: Default::default(),
        client_signature: SignatureData::null(),
        client_software_certificates: None,
        locale_ids: None,
        user_identity_token: ExtensionObject::from_message(UserNameIdentityToken {
            policy_id,
            user_name: UAString::from(username),
            password: ByteString::from(password.as_bytes()),
            encryption_algorithm: UAString::null(),
        }),
        user_token_signature: SignatureData::null(),
    }
}

fn signed_jwt(payload: Value, private_key: &PrivateKey) -> String {
    let header = json!({"alg": "RS256", "typ": "JWT"});
    let encoded_header = URL_SAFE_NO_PAD.encode(header.to_string());
    let encoded_payload = URL_SAFE_NO_PAD.encode(payload.to_string());
    let signing_input = format!("{encoded_header}.{encoded_payload}");
    let mut signature = vec![0u8; private_key.size()];
    let signature_len = private_key
        .sign_sha256(signing_input.as_bytes(), &mut signature)
        .expect("JWT signing should succeed");
    let encoded_signature = URL_SAFE_NO_PAD.encode(&signature[..signature_len]);

    format!("{signing_input}.{encoded_signature}")
}

fn rsa_oaep_encrypt(
    policy: SecurityPolicy,
    private_key: &PrivateKey,
    plaintext: &[u8],
) -> ByteString {
    let public_key = private_key.to_public_key();
    let mut ciphertext = vec![0u8; policy.calculate_cipher_text_size(plaintext.len(), &public_key)];
    let ciphertext_len = policy
        .asymmetric_encrypt(&public_key, plaintext, &mut ciphertext)
        .expect("RSA-OAEP test encryption should succeed");
    ciphertext.truncate(ciphertext_len);
    ByteString::from(ciphertext)
}

fn future_expiration() -> i64 {
    epoch_seconds() + 3600
}

fn past_expiration() -> i64 {
    epoch_seconds() - 3600
}

fn epoch_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after Unix epoch")
        .as_secs() as i64
}

#[tokio::test]
async fn oauth2_valid_jwt_maps_to_session_authorization_profile() {
    let fixture = OAuth2Fixture::new();
    let token = signed_jwt(
        json!({
            "iss": OAUTH2_ISSUER,
            "aud": ["engineering-tools", OAUTH2_AUDIENCE],
            "exp": future_expiration(),
            "sub": "brew-operator",
            "roles": ["operator", "observer"],
            "permissions": ["read", "write"]
        }),
        &fixture.private_key,
    );

    let (user_token, claims) = fixture
        .authenticate_with_claims(&format!("Bearer {token}"))
        .await
        .expect("valid OAuth2 JWT should authenticate");
    let profile = SessionAuthorizationProfile::from_claims(&claims);

    assert_eq!(user_token.0, "brew-operator");
    assert_eq!(profile.username, "brew-operator");
    assert_eq!(profile.roles, vec!["operator", "observer"]);
    assert_eq!(profile.permissions, vec!["read", "write"]);
    assert!(profile.is_operator);
    assert!(profile.is_observer);
    assert!(!profile.is_admin);
    assert!(profile.can_read());
    assert!(profile.can_write());

    let endpoints = fixture
        .handle
        .info()
        .endpoints(&UAString::from(fixture.endpoint_url.as_str()), &None)
        .expect("OAuth2 endpoint should be returned");
    let issued_policy = endpoints[0]
        .find_policy(UserTokenType::IssuedToken)
        .expect("OAuth2 issued token policy should be advertised");
    assert_eq!(issued_policy.issuer_endpoint_url.as_ref(), OAUTH2_ISSUER);
    assert_eq!(
        fixture.handle.info().config.oauth2_issuer.as_deref(),
        Some(OAUTH2_ISSUER)
    );
    assert_eq!(
        fixture.handle.info().config.oauth2_audience.as_deref(),
        Some(OAUTH2_AUDIENCE)
    );
}

#[tokio::test]
async fn oauth2_invalid_jwts_are_rejected() {
    let fixture = OAuth2Fixture::new();
    let (_untrusted_cert, untrusted_key) = oauth2_cert_and_key("untrusted-oauth2-idp");
    let invalid_tokens = [
        signed_jwt(
            json!({
                "iss": OAUTH2_ISSUER,
                "aud": OAUTH2_AUDIENCE,
                "exp": past_expiration(),
                "sub": "brew-operator"
            }),
            &fixture.private_key,
        ),
        signed_jwt(
            json!({
                "iss": "https://wrong-issuer.example",
                "aud": OAUTH2_AUDIENCE,
                "exp": future_expiration(),
                "sub": "brew-operator"
            }),
            &fixture.private_key,
        ),
        signed_jwt(
            json!({
                "iss": OAUTH2_ISSUER,
                "aud": "wrong-audience",
                "exp": future_expiration(),
                "sub": "brew-operator"
            }),
            &fixture.private_key,
        ),
        signed_jwt(
            json!({
                "iss": OAUTH2_ISSUER,
                "aud": OAUTH2_AUDIENCE,
                "exp": future_expiration(),
                "sub": "brew-operator"
            }),
            &untrusted_key,
        ),
    ];

    for token in invalid_tokens {
        let err = fixture
            .authenticate(&token)
            .await
            .expect_err("invalid OAuth2 JWT should be rejected");

        assert_eq!(err.status(), StatusCode::BadUserAccessDenied);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_oauth2_jwt_validation_failure_is_tarpitted() {
    let fixture = OAuth2Fixture::new();
    let token = signed_jwt(
        json!({
            "iss": OAUTH2_ISSUER,
            "aud": OAUTH2_AUDIENCE,
            "exp": past_expiration(),
            "sub": "brew-operator"
        }),
        &fixture.private_key,
    );

    assert_tarpitted_auth_failure(fixture.authenticate(&token), "invalid OAuth2 JWT").await;
}

#[tokio::test(flavor = "current_thread")]
async fn username_password_auth_failure_is_tarpitted() {
    let fixture = PasswordFixture::new();

    assert_tarpitted_auth_failure(
        fixture.authenticate("brew-operator", "wrong-password"),
        "invalid username password",
    )
    .await;
}

#[tokio::test]
async fn oauth2_rsa_oaep_encrypted_secret_authenticates() {
    let fixture = OAuth2Fixture::new();
    let token = format!(
        "Bearer {}",
        signed_jwt(
            json!({
                "iss": OAUTH2_ISSUER,
                "aud": OAUTH2_AUDIENCE,
                "exp": future_expiration(),
                "sub": "brew-operator"
            }),
            &fixture.private_key,
        )
    );
    let policy = SecurityPolicy::Aes128Sha256RsaOaep;
    let encrypted_token = rsa_oaep_encrypt(policy, &fixture.server_private_key(), token.as_bytes());
    let encryption_algorithm = UAString::from(
        policy
            .asymmetric_encryption_algorithm()
            .expect("Aes128Sha256RsaOaep should define RSA-OAEP encryption"),
    );

    let user_token = fixture
        .authenticate_encrypted_token(encrypted_token, encryption_algorithm)
        .await
        .expect("valid encrypted OAuth2 token should authenticate");

    assert_eq!(user_token.0, "brew-operator");
}

#[tokio::test(flavor = "current_thread")]
async fn encrypted_secret_decryption_failure_is_tarpitted() {
    let fixture = OAuth2Fixture::new();
    let invalid_ciphertext = ByteString::from(vec![0xa5; 256]);
    let encryption_algorithm = UAString::from(
        SecurityPolicy::Aes128Sha256RsaOaep
            .asymmetric_encryption_algorithm()
            .expect("Aes128Sha256RsaOaep should define RSA-OAEP encryption"),
    );

    assert_tarpitted_auth_failure(
        fixture.authenticate_encrypted_token(invalid_ciphertext, encryption_algorithm),
        "decryption failure",
    )
    .await;
}
