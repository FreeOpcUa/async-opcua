//! Performance tests for SC-003 encrypted ActivateSession authentication latency.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use opcua_crypto::{
    AlternateNames, CertificateStore, KeySize, PrivateKey, SecurityPolicy, X509Data, X509,
};
use opcua_server::{
    authenticator::{issued_token_security_policy, AuthManager},
    ServerBuilder, ServerEndpoint, ServerHandle,
};
use opcua_types::{
    issued_token_types, ActivateSessionRequest, ByteString, Error, ExtensionObject,
    IssuedIdentityToken, MessageSecurityMode, SignatureData, UAString, UserTokenPolicy,
    UserTokenType,
};
use serde_json::{json, Value};

const AUTH_LATENCY_BUDGET: Duration = Duration::from_millis(50);
const AUTH_LOAD_REQUESTS: usize = 16;
const OAUTH2_PATH: &str = "/oauth2-perf";
const OAUTH2_ISSUER: &str = "https://issuer.example";
const OAUTH2_AUDIENCE: &str = "opcua-server";

static NEXT_TEST_ID: AtomicUsize = AtomicUsize::new(0);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn encrypted_secret_authentication_load_p95_stays_under_50ms() {
    let fixture = Arc::new(PerfAuthFixture::new());
    let request = Arc::new(fixture.encrypted_activate_session_request("brew-operator"));

    fixture
        .authenticate_request(&request)
        .await
        .expect("warmup encrypted OAuth2 authentication should succeed");

    let mut tasks = Vec::with_capacity(AUTH_LOAD_REQUESTS);
    for _ in 0..AUTH_LOAD_REQUESTS {
        let fixture = Arc::clone(&fixture);
        let request = Arc::clone(&request);
        tasks.push(tokio::spawn(async move {
            let started = Instant::now();
            fixture
                .authenticate_request(&request)
                .await
                .expect("load encrypted OAuth2 authentication should succeed");
            started.elapsed()
        }));
    }

    let mut samples = Vec::with_capacity(AUTH_LOAD_REQUESTS);
    for task in tasks {
        samples.push(task.await.expect("auth load task should complete"));
    }
    samples.sort_unstable();

    let p95_index = (samples.len() * 95).div_ceil(100).saturating_sub(1);
    let p95 = samples[p95_index];
    let max = samples[samples.len() - 1];

    assert!(
        p95 < AUTH_LATENCY_BUDGET,
        "SC-003 encrypted auth p95 latency exceeded {AUTH_LATENCY_BUDGET:?}; p95={p95:?}, max={max:?}, samples={samples:?}"
    );
}

struct PerfIssuedTokenAuthenticator;

#[async_trait]
impl AuthManager for PerfIssuedTokenAuthenticator {
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

struct PerfAuthFixture {
    endpoint_url: String,
    handle: ServerHandle,
    private_key: PrivateKey,
    policy_id: UAString,
    _pki: TempPath,
}

impl PerfAuthFixture {
    fn new() -> Self {
        let pki = TempPath::new("perf-auth-pki");
        let (private_key, policy_id, issuer_cert_path) =
            setup_trusted_oauth2_certificate(pki.path());
        let endpoint = ServerEndpoint::new_none(OAUTH2_PATH, &[]);
        assert_eq!(issued_token_security_policy(&endpoint), policy_id);

        let (_server, handle) = ServerBuilder::new()
            .without_node_managers()
            .application_name("OAuth2 Perf Test Server")
            .application_uri("urn:oauth2-perf-test-server")
            .product_uri("urn:oauth2-perf-test-server")
            .host("127.0.0.1")
            .pki_dir(pki.path())
            .create_sample_keypair(true)
            .discovery_urls(vec![format!("opc.tcp://127.0.0.1:4855{OAUTH2_PATH}")])
            .oauth2_issuer(OAUTH2_ISSUER)
            .oauth2_audience(OAUTH2_AUDIENCE)
            .oauth2_issuer_certificate_path(issuer_cert_path)
            .with_authenticator(Arc::new(PerfIssuedTokenAuthenticator))
            .add_endpoint("oauth2-perf", endpoint)
            .build()
            .expect("OAuth2 perf test server should build");

        Self {
            endpoint_url: format!("{}{}", handle.info().base_endpoint(), OAUTH2_PATH),
            handle,
            private_key,
            policy_id,
            _pki: pki,
        }
    }

    fn encrypted_activate_session_request(&self, subject: &str) -> ActivateSessionRequest {
        let token = format!(
            "Bearer {}",
            signed_jwt(
                json!({
                    "iss": OAUTH2_ISSUER,
                    "aud": OAUTH2_AUDIENCE,
                    "exp": future_expiration(),
                    "sub": subject
                }),
                &self.private_key,
            )
        );
        let policy = SecurityPolicy::Aes128Sha256RsaOaep;
        let encrypted_token =
            rsa_oaep_encrypt(policy, &self.server_private_key(), token.as_bytes());
        let encryption_algorithm = UAString::from(
            policy
                .asymmetric_encryption_algorithm()
                .expect("Aes128Sha256RsaOaep should define RSA-OAEP encryption"),
        );

        ActivateSessionRequest {
            request_header: Default::default(),
            client_signature: SignatureData::null(),
            client_software_certificates: None,
            locale_ids: None,
            user_identity_token: ExtensionObject::from_message(IssuedIdentityToken {
                policy_id: self.policy_id.clone(),
                token_data: encrypted_token,
                encryption_algorithm,
            }),
            user_token_signature: SignatureData::null(),
        }
    }

    async fn authenticate_request(&self, request: &ActivateSessionRequest) -> Result<(), Error> {
        self.handle
            .info()
            .authenticate_endpoint(
                request,
                &self.endpoint_url,
                SecurityPolicy::None,
                MessageSecurityMode::None,
                request.user_identity_token.clone(),
                &ByteString::null(),
            )
            .await
            .map(|_| ())
    }

    fn server_private_key(&self) -> PrivateKey {
        self.handle
            .info()
            .server_pkey
            .read()
            .clone()
            .expect("test server should have a private key")
    }
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
            .join("perf_auth_tests")
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

fn epoch_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after Unix epoch")
        .as_secs() as i64
}
