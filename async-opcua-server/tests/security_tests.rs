//! Security integration tests for deprecated security policies and OAuth2 identities.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use opcua_client::{Client, ClientBuilder, IdentityToken};
use opcua_crypto::{
    AlternateNames, CertificateStore, KeySize, PrivateKey, SecurityPolicy, X509Data, X509,
};
use opcua_server::{
    authenticator::{issued_token_security_policy, AuthManager},
    authorization::SessionAuthorizationProfile,
    security::validate_security_policy,
    ServerBuilder, ServerConfig, ServerEndpoint, ServerHandle, ANONYMOUS_USER_TOKEN_ID,
};
use opcua_types::{
    issued_token_types, ActivateSessionRequest, ApplicationDescription, ApplicationType,
    ByteString, EndpointDescription, Error, ExtensionObject, IssuedIdentityToken, LocalizedText,
    MessageSecurityMode, SignatureData, StatusCode, UAString, UserTokenPolicy, UserTokenType,
};
use serde_json::{json, Value};
use tokio::net::TcpListener;

const OAUTH2_PATH: &str = "/oauth2";
const OAUTH2_ISSUER: &str = "https://issuer.example";
const OAUTH2_AUDIENCE: &str = "opcua-server";

static NEXT_TEST_ID: AtomicUsize = AtomicUsize::new(0);

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

struct RunningServer {
    endpoint_url: String,
    handle: ServerHandle,
    server_task: tokio::task::JoinHandle<()>,
    client_pki: TempPath,
    _server_pki: TempPath,
}

impl RunningServer {
    async fn legacy(allow_legacy_crypto: bool) -> Self {
        let server_pki = TempPath::new("legacy-server-pki");
        let client_pki = TempPath::new("legacy-client-pki");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let addr = listener.local_addr().expect("listener should have address");
        let endpoint_url = format!("opc.tcp://127.0.0.1:{}/", addr.port());
        let user_token_ids = [ANONYMOUS_USER_TOKEN_ID];

        let (server, handle) = ServerBuilder::new()
            .application_name("Security Test Server")
            .application_uri("urn:security-test-server")
            .product_uri("urn:security-test-server")
            .host("127.0.0.1")
            .port(addr.port())
            .pki_dir(server_pki.path())
            .create_sample_keypair(true)
            .trust_client_certs(true)
            .check_cert_time(false)
            .allow_legacy_crypto(allow_legacy_crypto)
            .discovery_urls(vec![endpoint_url.clone()])
            .add_endpoint(
                "basic128rsa15",
                (
                    "/",
                    SecurityPolicy::Basic128Rsa15,
                    MessageSecurityMode::Sign,
                    &user_token_ids as &[&str],
                ),
            )
            .add_endpoint(
                "basic256",
                (
                    "/",
                    SecurityPolicy::Basic256,
                    MessageSecurityMode::Sign,
                    &user_token_ids as &[&str],
                ),
            )
            .build()
            .expect("legacy security test server should build");

        let server_task = tokio::spawn(async move {
            server.run_with(listener).await.expect("server should run");
        });

        Self {
            endpoint_url,
            handle,
            server_task,
            client_pki,
            _server_pki: server_pki,
        }
    }

    fn legacy_endpoint(&self, security_policy: SecurityPolicy) -> EndpointDescription {
        EndpointDescription {
            endpoint_url: UAString::from(self.endpoint_url.as_str()),
            server: ApplicationDescription {
                application_uri: UAString::from("urn:security-test-server"),
                product_uri: UAString::from("urn:security-test-server"),
                application_name: LocalizedText::new("", "Security Test Server"),
                application_type: ApplicationType::Server,
                gateway_server_uri: UAString::null(),
                discovery_profile_uri: UAString::null(),
                discovery_urls: Some(vec![UAString::from(self.endpoint_url.as_str())]),
            },
            server_certificate: self.handle.info().server_certificate_as_byte_string(),
            security_mode: MessageSecurityMode::Sign,
            security_policy_uri: UAString::from(security_policy.to_uri()),
            user_identity_tokens: Some(vec![UserTokenPolicy::anonymous()]),
            transport_profile_uri: UAString::from(
                opcua_types::profiles::TRANSPORT_PROFILE_URI_BINARY,
            ),
            security_level: 0,
        }
    }

    fn client(&self) -> Client {
        ClientBuilder::new()
            .application_name("Security Test Client")
            .application_uri("urn:security-test-client")
            .pki_dir(self.client_pki.path())
            .create_sample_keypair(true)
            .trust_server_certs(true)
            .verify_server_certs(false)
            .session_retry_limit(0)
            .session_retry_initial(Duration::from_millis(10))
            .client()
            .expect("security test client should build")
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        self.handle.cancel();
        self.server_task.abort();
    }
}

#[test]
fn deprecated_security_profiles_are_rejected_by_default() {
    assert!(!ServerConfig::default().allow_legacy_crypto);
    for security_policy in [SecurityPolicy::Basic128Rsa15, SecurityPolicy::Basic256] {
        assert_eq!(
            validate_security_policy(security_policy, false),
            Err(StatusCode::BadSecurityPolicyRejected)
        );
    }
}

#[tokio::test]
async fn deprecated_security_profiles_are_allowed_when_legacy_crypto_is_enabled() {
    let server = RunningServer::legacy(true).await;

    for security_policy in [SecurityPolicy::Basic128Rsa15, SecurityPolicy::Basic256] {
        assert_eq!(validate_security_policy(security_policy, true), Ok(()));

        let mut client = server.client();
        let (session, event_loop) = client
            .connect_to_endpoint_directly(
                server.legacy_endpoint(security_policy),
                IdentityToken::Anonymous,
            )
            .expect("direct legacy endpoint should build a client session");
        let handle = event_loop.spawn();

        tokio::time::timeout(Duration::from_secs(10), session.wait_for_connection())
            .await
            .expect("legacy connection should be allowed");

        session
            .disconnect()
            .await
            .expect("legacy test session should disconnect");
        let status = tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("event loop should stop")
            .expect("event loop task should complete");

        assert_eq!(status, StatusCode::Good);
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
        let (private_key, policy_id) = setup_trusted_oauth2_certificate(pki.path());
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
            .discovery_urls(vec!["opc.tcp://127.0.0.1:4855/oauth2".to_string()])
            .oauth2_issuer(OAUTH2_ISSUER)
            .oauth2_audience(OAUTH2_AUDIENCE)
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

fn setup_trusted_oauth2_certificate(pki_path: &Path) -> (PrivateKey, UAString) {
    let certificate_store = CertificateStore::new(pki_path);
    certificate_store
        .ensure_pki_path()
        .expect("PKI structure should be created");

    let (cert, private_key) = oauth2_cert_and_key("oauth2-idp");
    let cert_path = certificate_store
        .trusted_certs_dir()
        .join(CertificateStore::cert_file_name(&cert));
    fs::write(cert_path, cert.to_der().expect("certificate should encode"))
        .expect("trusted OAuth2 certificate should be written");

    let endpoint = ServerEndpoint::new_none(OAUTH2_PATH, &[]);
    (private_key, issued_token_security_policy(&endpoint))
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
    ActivateSessionRequest {
        request_header: Default::default(),
        client_signature: SignatureData::null(),
        client_software_certificates: None,
        locale_ids: None,
        user_identity_token: ExtensionObject::from_message(IssuedIdentityToken {
            policy_id,
            token_data: ByteString::from(token.as_bytes()),
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

        assert_eq!(err.status(), StatusCode::BadIdentityTokenRejected);
    }
}
