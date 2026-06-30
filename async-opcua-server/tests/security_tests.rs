//! Security integration tests for PubSub keys, OAuth2 identities, and password identities.

use std::{
    fs,
    future::Future,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, TimeZone, Utc};
use const_oid::db::rfc5280::{ID_KP_CLIENT_AUTH, ID_KP_SERVER_AUTH};
use const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION;
use opcua_client::{
    services::{ActivateSession, CreateSession, Read},
    transport::TransportPollResult,
    ClientBuilder, EventCallback, IdentityToken, UARequest,
};
use opcua_crypto::{
    create_signature_data, AlternateNames, CertificateStore, KeySize, PrivateKey, SecurityPolicy,
    Thumbprint, X509Data, X509,
};
use opcua_server::{
    address_space::VariableBuilder,
    authenticator::{
        issued_token_security_policy, user_pass_security_policy_id, user_pass_security_policy_uri,
        AuthManager, Password, UserToken,
    },
    authorization::SessionAuthorizationProfile,
    diagnostics::NamespaceMetadata,
    node_manager::memory::{simple_node_manager, SimpleNodeManager},
    services::security::{
        GetSecurityKeysRequest, GetSecurityKeysResponse, SecurityGroupKeys, SecurityKeyService,
        CURRENT_SECURITY_TOKEN_ID,
    },
    ServerBuilder, ServerEndpoint, ServerHandle, ServerUserToken, ANONYMOUS_USER_TOKEN_ID,
};
use opcua_types::{
    issued_token_types, ActivateSessionRequest, ApplicationDescription, ApplicationType,
    AttributeId, ByteString, ContentFilter, DataTypeId, Error, EventFilter, ExtensionObject,
    IssuedIdentityToken, MessageSecurityMode, MonitoredItemCreateRequest, MonitoringMode,
    MonitoringParameters, NodeId, ObjectId, ObjectTypeId, ReadValueId, SignatureData,
    SimpleAttributeOperand, StatusCode, TimestampsToReturn, UAString, UserNameIdentityToken,
    UserTokenPolicy, UserTokenType, Variant, X509IdentityToken,
};
use rsa::{
    pkcs1v15::{Signature as RsaSignature, SigningKey},
    pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
    rand_core::OsRng,
    signature::{SignatureEncoding, Signer},
    RsaPrivateKey,
};
use serde_json::{json, Value};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use tokio::{net::TcpListener, sync::mpsc};
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    crl::{CertificateList, RevokedCert, TbsCertList},
    der::{
        asn1::{Any, BitString, Null, OctetString},
        Encode,
    },
    ext::pkix::{
        AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
        SubjectKeyIdentifier,
    },
    name::Name,
    serial_number::SerialNumber,
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
    time::{Time, Validity},
    Version,
};

const OAUTH2_PATH: &str = "/oauth2";
const OAUTH2_ISSUER: &str = "https://issuer.example";
const OAUTH2_AUDIENCE: &str = "opcua-server";
const PUBSUB_SECURITY_POLICY_URI: &str =
    "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss";
const X509_PATH: &str = "/x509";
const X509_USER_TOKEN_ID: &str = "x509-user";
const AUTH_FAILURE_TARPIT_MIN: Duration = Duration::from_millis(100);
const AUTH_FAILURE_TARPIT_TIMEOUT: Duration = Duration::from_secs(1);

static NEXT_TEST_ID: AtomicUsize = AtomicUsize::new(0);

#[test]
#[should_panic(expected = "mismatched ActivateSession status: expected BadUserAccessDenied")]
fn activate_session_status_assertion_reports_mismatch() {
    let result: Result<(), Error> = Err(Error::new(
        StatusCode::BadCertificateInvalid,
        "fixture mismatch",
    ));

    let _ = assert_activate_session_status(
        result,
        StatusCode::BadUserAccessDenied,
        "mismatched ActivateSession status",
    );
}

#[test]
#[should_panic(expected = "failed ActivateSession changed identity state")]
fn activate_session_identity_unchanged_assertion_reports_mutation() {
    let before = (
        Some("previous-user"),
        vec!["operator"],
        Some("previous-claims"),
    );
    let after = (
        Some("rejected-user"),
        vec!["admin"],
        Some("rejected-claims"),
    );
    let result: Result<(), Error> = Err(Error::new(
        StatusCode::BadUserSignatureInvalid,
        "fixture failure",
    ));

    let _ = assert_activate_session_identity_unchanged(
        result,
        &before,
        &after,
        StatusCode::BadUserSignatureInvalid,
        "failed ActivateSession",
    );
}

#[test]
#[should_panic(expected = "failed ActivateSession emitted certificate audit before authentication")]
fn activate_session_no_certificate_audit_assertion_reports_emission() {
    let result: Result<(), Error> = Err(Error::new(
        StatusCode::BadUserSignatureInvalid,
        "fixture failure",
    ));

    let _ = assert_activate_session_no_certificate_audit_before_authentication(
        result,
        0,
        1,
        StatusCode::BadUserSignatureInvalid,
        "failed ActivateSession",
    );
}

fn assert_activate_session_status<T>(
    result: Result<T, Error>,
    expected: StatusCode,
    failure: &str,
) -> Error {
    let err = match result {
        Ok(_) => panic!("{failure} unexpectedly succeeded; expected {expected:?}"),
        Err(err) => err,
    };
    let actual = err.status();

    assert_eq!(
        actual, expected,
        "{failure}: expected {expected:?} but got {actual:?}"
    );
    err
}

fn assert_activate_session_identity_unchanged<T, S>(
    result: Result<T, Error>,
    before: &S,
    after: &S,
    expected: StatusCode,
    failure: &str,
) -> Error
where
    S: std::fmt::Debug + PartialEq,
{
    let err = assert_activate_session_status(result, expected, failure);

    assert_eq!(
        after, before,
        "{failure}: failed ActivateSession changed identity state"
    );
    err
}

fn assert_activate_session_no_certificate_audit_before_authentication<T>(
    result: Result<T, Error>,
    certificate_audit_records_before: usize,
    certificate_audit_records_after: usize,
    expected: StatusCode,
    failure: &str,
) -> Error {
    let err = assert_activate_session_status(result, expected, failure);

    assert_eq!(
        certificate_audit_records_after, certificate_audit_records_before,
        "{failure}: failed ActivateSession emitted certificate audit before authentication"
    );
    err
}

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

    let err =
        assert_activate_session_status::<T>(Err(err), StatusCode::BadUserAccessDenied, failure);
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
fn get_security_keys_handler_returns_available_historical_range_for_non_current_starting_token() {
    let service = SecurityKeyService::new();
    service
        .register_security_group("group-1", historical_security_group_keys())
        .unwrap();

    let historical_response = service
        .get_security_keys(GetSecurityKeysRequest::new("group-1", 5, 2))
        .unwrap();
    let exact_current_response = service
        .get_security_keys(GetSecurityKeysRequest::new("group-1", 7, 2))
        .unwrap();
    let current_response = service
        .get_security_keys(GetSecurityKeysRequest::new(
            "group-1",
            CURRENT_SECURITY_TOKEN_ID,
            2,
        ))
        .unwrap();

    assert_eq!(historical_response.first_token_id, 5);
    assert_eq!(
        historical_response.keys,
        key_bytes(&["historical-key-5", "historical-key-6"])
    );
    assert_eq!(exact_current_response.first_token_id, 7);
    assert_eq!(
        exact_current_response.keys,
        key_bytes(&["current-key", "next-key"])
    );
    assert_eq!(
        current_response.first_token_id, 7,
        "OPC-10000-14 8.3.2 requires StartingTokenId=0 to return the current key first"
    );
    assert_eq!(
        current_response.keys,
        key_bytes(&["current-key", "next-key"])
    );
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
    let unknown_token = service
        .get_security_keys(GetSecurityKeysRequest::new("group-1", 99, 1))
        .unwrap_err();

    assert_eq!(empty_group, StatusCode::BadInvalidArgument);
    assert_eq!(zero_count, StatusCode::BadInvalidArgument);
    assert_eq!(unknown_token, StatusCode::BadNotFound);
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

#[tokio::test]
async fn application_certificate_rejected_store_preserves_create_session_and_open_secure_channel_statuses(
) {
    const REJECTED_CREATE_SESSION_APP_URI: &str = "urn:rejected-create-session-application";

    let temp = TempPath::new("application-certificate-rejected-store-contract");
    let server_pki = temp.path().join("server-pki");
    let trusted_client_pki = temp.path().join("trusted-client-pki");
    let rejected_channel_client_pki = temp.path().join("rejected-channel-client-pki");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("security test listener should bind");
    let port = listener
        .local_addr()
        .expect("security test listener should have address")
        .port();
    let endpoint_url = format!("opc.tcp://127.0.0.1:{port}/");

    let mut trusted_client = ClientBuilder::new()
        .application_name("Trusted Channel Security Test Client")
        .application_uri("urn:trusted-channel-security-test-client")
        .product_uri("urn:trusted-channel-security-test-client")
        .pki_dir(&trusted_client_pki)
        .create_sample_keypair(true)
        .trust_server_certs(true)
        .session_retry_limit(0)
        .client()
        .expect("trusted channel security test client should build");
    let trusted_client_cert = trusted_client
        .certificate_store()
        .read()
        .read_own_cert()
        .expect("trusted channel client should have a certificate");

    let (rejected_create_session_cert, _rejected_create_session_key) = application_cert_and_key(
        "rejected-create-session-application",
        REJECTED_CREATE_SESSION_APP_URI,
    );

    let mut rejected_channel_client = ClientBuilder::new()
        .application_name("Rejected Channel Security Test Client")
        .application_uri("urn:rejected-channel-security-test-client")
        .product_uri("urn:rejected-channel-security-test-client")
        .pki_dir(&rejected_channel_client_pki)
        .create_sample_keypair(true)
        .trust_server_certs(true)
        .session_retry_limit(0)
        .session_retry_initial(Duration::from_millis(20))
        .client()
        .expect("rejected channel security test client should build");
    let rejected_channel_client_cert = rejected_channel_client
        .certificate_store()
        .read()
        .read_own_cert()
        .expect("rejected channel client should have a certificate");

    let server_store = CertificateStore::new(&server_pki);
    server_store
        .ensure_pki_path()
        .expect("server PKI structure should be created");
    let trusted_client_cert_name = CertificateStore::cert_file_name(&trusted_client_cert);
    write_cert_to(
        &server_store.trusted_certs_dir(),
        &trusted_client_cert_name,
        &trusted_client_cert,
    );
    server_store
        .store_rejected_cert(&rejected_create_session_cert)
        .expect("CreateSession application certificate should be pre-rejected");
    server_store
        .store_rejected_cert(&rejected_channel_client_cert)
        .expect("OpenSecureChannel application certificate should be pre-rejected");

    let (server, handle) = ServerBuilder::new()
        .application_name("Application Certificate Rejected Store Test Server")
        .application_uri("urn:application-certificate-rejected-store-test-server")
        .product_uri("urn:application-certificate-rejected-store-test-server")
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
                namespace_uri: "urn:application-certificate-rejected-store-test".to_string(),
                namespace_index: 2,
                ..Default::default()
            },
            "application-certificate-rejected-store-test",
        ))
        .build()
        .expect("application certificate rejected-store test server should build");
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

    let (channel, mut channel_loop) = trusted_client
        .open_secure_channel_to_endpoint_directly(endpoint.clone(), IdentityToken::Anonymous)
        .await
        .expect("trusted client should open the secure channel");
    let channel_poller = tokio::spawn(async move {
        loop {
            if matches!(channel_loop.poll().await, TransportPollResult::Closed(_)) {
                break;
            }
        }
    });

    let create_session_result = CreateSession::new_manual(
        trusted_client.certificate_store(),
        &endpoint,
        1,
        Duration::from_secs(5),
        NodeId::null(),
        channel.request_handle(),
    )
    .endpoint_url(endpoint_url.as_str())
    .client_description(ApplicationDescription {
        application_uri: UAString::from(REJECTED_CREATE_SESSION_APP_URI),
        product_uri: UAString::from("urn:rejected-create-session-application"),
        application_type: ApplicationType::Client,
        ..Default::default()
    })
    .client_certificate(rejected_create_session_cert)
    .session_timeout(5_000.0)
    .send(&channel)
    .await;
    let create_session_status = create_session_result
        .expect_err("rejected-store application certificate should reject CreateSession")
        .status();

    channel.close_channel().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), channel_poller).await;

    let (_session, rejected_event_loop) = rejected_channel_client
        .connect_to_endpoint_directly(endpoint, IdentityToken::Anonymous)
        .expect("session event loop should be created before channel polling");

    // OPC UA Part 4 6.1.3: rejected-store application certificates remain
    // certificate validation failures, but these two public surfaces expose
    // their existing status contracts differently.
    let open_secure_channel_status =
        tokio::time::timeout(Duration::from_secs(10), rejected_event_loop.run())
            .await
            .expect("OpenSecureChannel rejected-store failure should complete");

    handle.cancel();
    server_task.abort();

    assert_eq!(create_session_status, StatusCode::BadCertificateUntrusted);
    assert_eq!(
        open_secure_channel_status,
        StatusCode::BadSecurityChecksFailed
    );
}

#[tokio::test]
async fn max_response_message_size_rejects_serialized_read_response_body_above_client_limit() {
    const CLIENT_RESPONSE_BODY_LIMIT: u32 = 64 * 1024;
    const OVERSIZED_VALUE_BYTES: usize = CLIENT_RESPONSE_BODY_LIMIT as usize + 1024;
    const OVERSIZED_NODE_NAMESPACE_INDEX: u16 = 2;
    const TRANSPORT_CHUNK_LIMIT: usize = 128 * 1024;
    const TRANSPORT_MESSAGE_LIMIT: usize = 512 * 1024;

    assert!(
        OVERSIZED_VALUE_BYTES > CLIENT_RESPONSE_BODY_LIMIT as usize,
        "fixture value must make the serialized response body exceed the client limit"
    );

    let temp = TempPath::new("max-response-message-size");
    let server_pki = temp.path().join("server-pki");
    let client_pki = temp.path().join("client-pki");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("maxResponseMessageSize test listener should bind");
    let port = listener
        .local_addr()
        .expect("maxResponseMessageSize test listener should have address")
        .port();
    let endpoint_url = format!("opc.tcp://127.0.0.1:{port}/");
    let oversized_node_id = NodeId::new(OVERSIZED_NODE_NAMESPACE_INDEX, "OversizedReadValue");

    let (server, handle) = ServerBuilder::new()
        .application_name("Max Response Message Size Test Server")
        .application_uri("urn:max-response-message-size-test-server")
        .product_uri("urn:max-response-message-size-test-server")
        .host("127.0.0.1")
        .port(port)
        .pki_dir(&server_pki)
        .create_sample_keypair(true)
        .max_string_length(TRANSPORT_MESSAGE_LIMIT)
        .max_message_size(TRANSPORT_MESSAGE_LIMIT)
        .send_buffer_size(TRANSPORT_CHUNK_LIMIT)
        .receive_buffer_size(TRANSPORT_CHUNK_LIMIT)
        .discovery_urls(vec![endpoint_url.clone()])
        .add_endpoint(
            "none",
            (
                "/",
                SecurityPolicy::None,
                MessageSecurityMode::None,
                &[ANONYMOUS_USER_TOKEN_ID] as &[&str],
            ),
        )
        .with_node_manager(simple_node_manager(
            NamespaceMetadata {
                namespace_uri: "urn:max-response-message-size-test".to_string(),
                namespace_index: OVERSIZED_NODE_NAMESPACE_INDEX,
                ..Default::default()
            },
            "max-response-message-size-test",
        ))
        .build()
        .expect("maxResponseMessageSize test server should build");
    handle.info().port.store(port, Ordering::Relaxed);

    let node_manager = handle
        .node_managers()
        .get_of_type::<SimpleNodeManager>()
        .expect("maxResponseMessageSize test should have a SimpleNodeManager");
    {
        let mut address_space = node_manager.address_space().write();
        VariableBuilder::new(
            &oversized_node_id,
            "OversizedReadValue",
            "OversizedReadValue",
        )
        .data_type(DataTypeId::String)
        .value("x".repeat(OVERSIZED_VALUE_BYTES))
        .insert(&mut *address_space);
    }

    let endpoint = handle
        .info()
        .endpoints(&UAString::from(endpoint_url.as_str()), &None)
        .expect("maxResponseMessageSize test endpoint should be described")
        .into_iter()
        .find(|endpoint| {
            endpoint.security_policy_uri.as_ref() == SecurityPolicy::None.to_uri()
                && endpoint.security_mode == MessageSecurityMode::None
        })
        .expect("unsecured maxResponseMessageSize test endpoint should be advertised");
    let server_task = tokio::spawn(async move {
        let _ = server.run_with(listener).await;
    });

    let mut client = ClientBuilder::new()
        .application_name("Max Response Message Size Test Client")
        .application_uri("urn:max-response-message-size-test-client")
        .product_uri("urn:max-response-message-size-test-client")
        .pki_dir(&client_pki)
        .create_sample_keypair(true)
        .trust_server_certs(true)
        .max_string_length(TRANSPORT_MESSAGE_LIMIT)
        .max_message_size(TRANSPORT_MESSAGE_LIMIT)
        .max_chunk_size(TRANSPORT_CHUNK_LIMIT)
        .max_incoming_chunk_size(TRANSPORT_CHUNK_LIMIT)
        .session_retry_limit(0)
        .client()
        .expect("maxResponseMessageSize test client should build");

    let (channel, mut channel_loop) = client
        .open_secure_channel_to_endpoint_directly(endpoint.clone(), IdentityToken::Anonymous)
        .await
        .expect("maxResponseMessageSize test should open a secure channel");
    let channel_poller = tokio::spawn(async move {
        loop {
            if matches!(channel_loop.poll().await, TransportPollResult::Closed(_)) {
                break;
            }
        }
    });

    let create_session_response = CreateSession::new_manual(
        client.certificate_store(),
        &endpoint,
        1,
        Duration::from_secs(5),
        NodeId::null(),
        channel.request_handle(),
    )
    .endpoint_url(endpoint_url.as_str())
    .client_description(ApplicationDescription {
        application_uri: UAString::from("urn:max-response-message-size-test-client"),
        product_uri: UAString::from("urn:max-response-message-size-test-client"),
        application_type: ApplicationType::Client,
        ..Default::default()
    })
    .client_cert_from_store(client.certificate_store())
    .session_name("max-response-message-size-test")
    .session_timeout(5_000.0)
    .max_response_message_size(CLIENT_RESPONSE_BODY_LIMIT)
    .send(&channel)
    .await
    .expect("CreateSession response should fit below the client response limit");

    ActivateSession::new_manual(
        endpoint,
        1,
        Duration::from_secs(5),
        create_session_response.authentication_token.clone(),
        channel.request_handle(),
    )
    .identity_token(IdentityToken::Anonymous)
    .send(&channel)
    .await
    .expect("ActivateSession response should fit below the client response limit");

    // OPC UA Part 4 5.7.2.2 and 5.3 require Bad_ResponseTooLarge when
    // the serialized response body exceeds the client maxResponseMessageSize.
    let read_result = Read::new_manual(
        1,
        Duration::from_secs(5),
        create_session_response.authentication_token,
        channel.request_handle(),
    )
    .timestamps_to_return(TimestampsToReturn::Neither)
    .node(ReadValueId::new(oversized_node_id, AttributeId::Value))
    .send(&channel)
    .await;
    let actual_status = read_result.as_ref().err().map(|err| err.status());
    let read_succeeded = read_result.is_ok();

    channel.close_channel().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), channel_poller).await;
    handle.cancel();
    server_task.abort();

    assert_eq!(
        actual_status,
        Some(StatusCode::BadResponseTooLarge),
        "oversized Read response with maxResponseMessageSize={CLIENT_RESPONSE_BODY_LIMIT} \
         should fail with BadResponseTooLarge; got {actual_status:?}, success={read_succeeded}"
    );
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

fn historical_security_group_keys() -> SecurityGroupKeys {
    SecurityGroupKeys::with_retained_keys_current_key_started_at(
        PUBSUB_SECURITY_POLICY_URI,
        5,
        7,
        key_bytes(&[
            "historical-key-5",
            "historical-key-6",
            "current-key",
            "next-key",
        ]),
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

struct TestKey {
    rsa: RsaPrivateKey,
    private_key: PrivateKey,
}

#[derive(Clone, Copy)]
enum UserCertEku {
    None,
    Client,
    Server,
    Both,
}

#[derive(Clone, Copy)]
enum UserCertTrust {
    Trusted,
    Untrusted,
    Expired,
    WrongUsage,
    IncompleteChain,
    Revoked,
}

struct UserCertMaterial {
    cert: X509,
    private_key: PrivateKey,
}

struct X509UserTokenPolicyAuthenticator {
    signing_thumbprint: Thumbprint,
    token_security_policy: SecurityPolicy,
}

#[async_trait]
impl AuthManager for X509UserTokenPolicyAuthenticator {
    async fn authenticate_anonymous_token(&self, endpoint: &ServerEndpoint) -> Result<(), Error> {
        if endpoint.user_token_ids.contains(ANONYMOUS_USER_TOKEN_ID) {
            Ok(())
        } else {
            Err(Error::new(
                StatusCode::BadIdentityTokenRejected,
                "Anonymous identity token unsupported",
            ))
        }
    }

    async fn authenticate_x509_identity_token(
        &self,
        _endpoint: &ServerEndpoint,
        signing_thumbprint: &Thumbprint,
    ) -> Result<UserToken, Error> {
        if signing_thumbprint == &self.signing_thumbprint {
            Ok(UserToken(X509_USER_TOKEN_ID.to_string()))
        } else {
            Err(Error::new(
                StatusCode::BadIdentityTokenRejected,
                "X.509 policy authenticator rejected certificate thumbprint",
            ))
        }
    }

    fn user_token_policies(&self, endpoint: &ServerEndpoint) -> Vec<UserTokenPolicy> {
        if endpoint.path != X509_PATH {
            return Vec::new();
        }

        let mut policies = Vec::new();
        if endpoint.user_token_ids.contains(ANONYMOUS_USER_TOKEN_ID) {
            policies.push(UserTokenPolicy {
                policy_id: UAString::from("anonymous"),
                token_type: UserTokenType::Anonymous,
                issued_token_type: UAString::null(),
                issuer_endpoint_url: UAString::null(),
                security_policy_uri: UAString::null(),
            });
        }
        if endpoint.user_token_ids.contains(X509_USER_TOKEN_ID) {
            policies.push(UserTokenPolicy {
                policy_id: UAString::from("x509"),
                token_type: UserTokenType::Certificate,
                issued_token_type: UAString::null(),
                issuer_endpoint_url: UAString::null(),
                security_policy_uri: UAString::from(self.token_security_policy.to_uri()),
            });
        }
        policies
    }
}

struct X509UserFixture {
    endpoint_url: String,
    endpoint_security_policy: SecurityPolicy,
    endpoint_security_mode: MessageSecurityMode,
    handle: ServerHandle,
    server_nonce: ByteString,
    user_token_security_policy: SecurityPolicy,
    user: UserCertMaterial,
    _pki: TempPath,
}

impl X509UserFixture {
    fn new(kind: UserCertTrust) -> Self {
        Self::new_with_policies(
            kind,
            SecurityPolicy::None,
            MessageSecurityMode::None,
            SecurityPolicy::Basic256Sha256,
        )
    }

    fn new_enhanced_channel_bound_policy() -> Self {
        Self::new_with_policies(
            UserCertTrust::Trusted,
            SecurityPolicy::Aes256Sha256RsaPss,
            MessageSecurityMode::Sign,
            SecurityPolicy::Aes256Sha256RsaPss,
        )
    }

    fn new_with_policies(
        kind: UserCertTrust,
        endpoint_security_policy: SecurityPolicy,
        endpoint_security_mode: MessageSecurityMode,
        user_token_security_policy: SecurityPolicy,
    ) -> Self {
        let pki = TempPath::new("x509-user-pki");
        let store = CertificateStore::new(pki.path());
        store
            .ensure_pki_path()
            .expect("X.509 user PKI structure should be created");

        let root_key = test_key(&pki, "root");
        let intermediate_key = test_key(&pki, "intermediate");
        let user_key = test_key(&pki, "user");

        let root = issue_test_cert(&TestCertSpec {
            subject_cn: "x509 user root",
            subject_key: &root_key.rsa,
            issuer_cn: "x509 user root",
            issuer_key: &root_key.rsa,
            signer_key: &root_key.rsa,
            is_ca: true,
            not_before: dt(2020, 1, 1),
            not_after: dt(2035, 1, 1),
            eku: UserCertEku::None,
            key_usage: KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign),
            serial: 10,
        });
        let intermediate = issue_test_cert(&TestCertSpec {
            subject_cn: "x509 user intermediate",
            subject_key: &intermediate_key.rsa,
            issuer_cn: "x509 user root",
            issuer_key: &root_key.rsa,
            signer_key: &root_key.rsa,
            is_ca: true,
            not_before: dt(2020, 1, 1),
            not_after: dt(2035, 1, 1),
            eku: UserCertEku::None,
            key_usage: KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign),
            serial: 11,
        });

        let (cert, private_key) = match kind {
            UserCertTrust::Trusted => (
                user_leaf(
                    &user_key.rsa,
                    &root_key.rsa,
                    &root_key.rsa,
                    dt(2035, 1, 1),
                    UserCertEku::Both,
                    100,
                ),
                user_key.private_key,
            ),
            UserCertTrust::Untrusted => (
                user_leaf(
                    &user_key.rsa,
                    &user_key.rsa,
                    &user_key.rsa,
                    dt(2035, 1, 1),
                    UserCertEku::Client,
                    101,
                ),
                user_key.private_key,
            ),
            UserCertTrust::Expired => (
                user_leaf(
                    &user_key.rsa,
                    &root_key.rsa,
                    &root_key.rsa,
                    dt(2021, 1, 1),
                    UserCertEku::Client,
                    102,
                ),
                user_key.private_key,
            ),
            UserCertTrust::WrongUsage => (
                user_leaf(
                    &user_key.rsa,
                    &root_key.rsa,
                    &root_key.rsa,
                    dt(2035, 1, 1),
                    UserCertEku::Server,
                    103,
                ),
                user_key.private_key,
            ),
            UserCertTrust::IncompleteChain => (
                issue_test_cert(&TestCertSpec {
                    subject_cn: "x509 user leaf",
                    subject_key: &user_key.rsa,
                    issuer_cn: "x509 user intermediate",
                    issuer_key: &intermediate_key.rsa,
                    signer_key: &intermediate_key.rsa,
                    is_ca: false,
                    not_before: dt(2020, 1, 1),
                    not_after: dt(2035, 1, 1),
                    eku: UserCertEku::Client,
                    key_usage: KeyUsage(KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment),
                    serial: 104,
                }),
                user_key.private_key,
            ),
            UserCertTrust::Revoked => (
                user_leaf(
                    &user_key.rsa,
                    &root_key.rsa,
                    &root_key.rsa,
                    dt(2035, 1, 1),
                    UserCertEku::Client,
                    105,
                ),
                user_key.private_key,
            ),
        };

        if !matches!(kind, UserCertTrust::Untrusted) {
            write_cert_to(&store.trusted_certs_dir(), "root.der", &root);
        }
        if matches!(kind, UserCertTrust::Trusted) {
            write_cert_to(&store.issuer_certs_dir(), "intermediate.der", &intermediate);
        }
        if matches!(kind, UserCertTrust::Revoked) {
            let crl = make_test_crl("x509 user root", &root_key.rsa, &[105]);
            write_crl_to(&store.trusted_crls_dir(), "root.der", &crl);
        }

        let user_cert_path = pki.path().join("configured-user.der");
        write_cert_to(pki.path(), "configured-user.der", &cert);
        let authenticator = Arc::new(X509UserTokenPolicyAuthenticator {
            signing_thumbprint: cert.thumbprint(),
            token_security_policy: user_token_security_policy,
        });

        let endpoint = ServerEndpoint::new(
            X509_PATH,
            endpoint_security_policy,
            endpoint_security_mode,
            &[X509_USER_TOKEN_ID.into()],
        );
        let (_server, handle) = ServerBuilder::new()
            .without_node_managers()
            .application_name("X509 User Security Test Server")
            .application_uri("urn:x509-user-security-test-server")
            .product_uri("urn:x509-user-security-test-server")
            .host("127.0.0.1")
            .pki_dir(pki.path())
            .create_sample_keypair(true)
            .discovery_urls(vec!["opc.tcp://127.0.0.1:4857/x509".to_string()])
            .add_user_token(
                X509_USER_TOKEN_ID,
                ServerUserToken::x509("certificate-user", &user_cert_path),
            )
            .with_authenticator(authenticator)
            .add_endpoint("x509", endpoint)
            .build()
            .expect("X.509 user security test server should build");

        Self {
            endpoint_url: format!("{}{}", handle.info().base_endpoint(), X509_PATH),
            endpoint_security_policy,
            endpoint_security_mode,
            handle,
            server_nonce: ByteString::from(b"x509-user-nonce".as_slice()),
            user_token_security_policy,
            user: UserCertMaterial { cert, private_key },
            _pki: pki,
        }
    }

    async fn authenticate(&self) -> Result<(), Error> {
        self.authenticate_with_cert(&self.user.cert, &self.user.private_key)
            .await
    }

    async fn authenticate_with_tampered_signature(&self) -> Result<(), Error> {
        let mut request = self.activate_session_request(&self.user.cert, &self.user.private_key);
        let mut signature = request.user_token_signature.signature.as_ref().to_vec();
        let last = signature
            .last_mut()
            .expect("fixture X.509 user-token signature should not be empty");
        *last ^= 0xFF;
        request.user_token_signature.signature = ByteString::from(signature);

        self.handle
            .info()
            .authenticate_endpoint(
                &request,
                &self.endpoint_url,
                self.endpoint_security_policy,
                self.endpoint_security_mode,
                request.user_identity_token.clone(),
                &self.server_nonce,
            )
            .await
            .map(|_| ())
    }

    async fn authenticate_without_user_token_signature(&self) -> Result<(), Error> {
        let mut request = self.activate_session_request(&self.user.cert, &self.user.private_key);
        request.user_token_signature = SignatureData::null();

        self.handle
            .info()
            .authenticate_endpoint(
                &request,
                &self.endpoint_url,
                self.endpoint_security_policy,
                self.endpoint_security_mode,
                request.user_identity_token.clone(),
                &self.server_nonce,
            )
            .await
            .map(|_| ())
    }

    async fn authenticate_with_cert(
        &self,
        cert: &X509,
        private_key: &PrivateKey,
    ) -> Result<(), Error> {
        let request = self.activate_session_request(cert, private_key);
        self.handle
            .info()
            .authenticate_endpoint(
                &request,
                &self.endpoint_url,
                self.endpoint_security_policy,
                self.endpoint_security_mode,
                request.user_identity_token.clone(),
                &self.server_nonce,
            )
            .await
            .map(|_| ())
    }

    async fn authenticate_malformed_certificate(&self) -> Result<(), Error> {
        let request = ActivateSessionRequest {
            request_header: Default::default(),
            client_signature: SignatureData::null(),
            client_software_certificates: None,
            locale_ids: None,
            user_identity_token: ExtensionObject::from_message(X509IdentityToken {
                policy_id: UAString::from("x509"),
                certificate_data: ByteString::from(&[0x30, 0x03, 0x02, 0x01]),
            }),
            user_token_signature: SignatureData::null(),
        };
        self.handle
            .info()
            .authenticate_endpoint(
                &request,
                &self.endpoint_url,
                self.endpoint_security_policy,
                self.endpoint_security_mode,
                request.user_identity_token.clone(),
                &self.server_nonce,
            )
            .await
            .map(|_| ())
    }

    fn activate_session_request(
        &self,
        cert: &X509,
        private_key: &PrivateKey,
    ) -> ActivateSessionRequest {
        let server_cert = self
            .handle
            .info()
            .server_certificate
            .read()
            .clone()
            .expect("test server should have a certificate");
        let signature = create_signature_data(
            private_key,
            self.user_token_security_policy,
            &server_cert.as_byte_string(),
            &self.server_nonce,
        )
        .expect("X.509 user-token signature should be created");

        ActivateSessionRequest {
            request_header: Default::default(),
            client_signature: SignatureData::null(),
            client_software_certificates: None,
            locale_ids: None,
            user_identity_token: ExtensionObject::from_message(X509IdentityToken {
                policy_id: UAString::from("x509"),
                certificate_data: cert.as_byte_string(),
            }),
            user_token_signature: signature,
        }
    }
}

struct TestCertSpec<'a> {
    subject_cn: &'a str,
    subject_key: &'a RsaPrivateKey,
    issuer_cn: &'a str,
    issuer_key: &'a RsaPrivateKey,
    signer_key: &'a RsaPrivateKey,
    is_ca: bool,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    eku: UserCertEku,
    key_usage: KeyUsage,
    serial: u32,
}

fn test_key(temp: &TempPath, name: &str) -> TestKey {
    let rsa = RsaPrivateKey::new(&mut OsRng, 2048).expect("RSA fixture key should generate");
    let pem = rsa
        .to_pkcs8_pem(LineEnding::LF)
        .expect("RSA fixture key should encode as PKCS8 PEM");
    let path = temp.path().join(format!("{name}.pem"));
    fs::write(&path, pem.as_bytes()).expect("RSA fixture key should be written");
    let private_key =
        CertificateStore::read_pkey(&path).expect("RSA fixture key should be read by store");
    TestKey { rsa, private_key }
}

fn dt(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).unwrap()
}

fn x509_time(dt: DateTime<Utc>) -> Time {
    let secs = u64::try_from(dt.timestamp()).expect("non-negative X.509 fixture timestamp");
    Time::try_from(UNIX_EPOCH + Duration::from_secs(secs)).expect("valid X.509 fixture time")
}

fn spki_from_rsa(key: &RsaPrivateKey) -> SubjectPublicKeyInfoOwned {
    let public_key_der = key
        .to_public_key()
        .to_public_key_der()
        .expect("fixture public key should encode");
    SubjectPublicKeyInfoOwned::try_from(public_key_der.as_bytes())
        .expect("fixture SubjectPublicKeyInfo should parse")
}

fn ski_of(spki: &SubjectPublicKeyInfoOwned) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(spki.subject_public_key.raw_bytes());
    hasher.finalize().to_vec()
}

fn issue_test_cert(spec: &TestCertSpec<'_>) -> X509 {
    let subject_spki = spki_from_rsa(spec.subject_key);
    let issuer_spki = spki_from_rsa(spec.issuer_key);
    let signing_key = SigningKey::<Sha256>::new(spec.signer_key.clone());
    let subject = Name::from_str(&format!("CN={}", spec.subject_cn)).expect("fixture subject");
    let issuer = Name::from_str(&format!("CN={}", spec.issuer_cn)).expect("fixture issuer");
    let mut builder = CertificateBuilder::new(
        Profile::Manual {
            issuer: Some(issuer),
        },
        SerialNumber::from(spec.serial),
        Validity {
            not_before: x509_time(spec.not_before),
            not_after: x509_time(spec.not_after),
        },
        subject,
        subject_spki.clone(),
        &signing_key,
    )
    .expect("fixture certificate builder should initialize");

    builder
        .add_extension(&SubjectKeyIdentifier(
            OctetString::new(ski_of(&subject_spki)).expect("fixture SKI"),
        ))
        .expect("fixture certificate should accept SKI");
    builder
        .add_extension(&AuthorityKeyIdentifier {
            authority_cert_issuer: None,
            key_identifier: Some(OctetString::new(ski_of(&issuer_spki)).expect("fixture AKI")),
            authority_cert_serial_number: None,
        })
        .expect("fixture certificate should accept AKI");
    builder
        .add_extension(&BasicConstraints {
            ca: spec.is_ca,
            path_len_constraint: None,
        })
        .expect("fixture certificate should accept basic constraints");
    builder
        .add_extension(&spec.key_usage)
        .expect("fixture certificate should accept key usage");

    match spec.eku {
        UserCertEku::None => {}
        UserCertEku::Client => builder
            .add_extension(&ExtendedKeyUsage(vec![ID_KP_CLIENT_AUTH]))
            .expect("fixture certificate should accept client EKU"),
        UserCertEku::Server => builder
            .add_extension(&ExtendedKeyUsage(vec![ID_KP_SERVER_AUTH]))
            .expect("fixture certificate should accept server EKU"),
        UserCertEku::Both => builder
            .add_extension(&ExtendedKeyUsage(vec![
                ID_KP_CLIENT_AUTH,
                ID_KP_SERVER_AUTH,
            ]))
            .expect("fixture certificate should accept both EKUs"),
    }

    let cert = builder
        .build::<RsaSignature>()
        .expect("fixture certificate should build");
    X509::from_der(&cert.to_der().expect("fixture certificate should encode"))
        .expect("fixture certificate should parse")
}

fn user_leaf(
    subject_key: &RsaPrivateKey,
    issuer_key: &RsaPrivateKey,
    signer_key: &RsaPrivateKey,
    not_after: DateTime<Utc>,
    eku: UserCertEku,
    serial: u32,
) -> X509 {
    let issuer_cn = if std::ptr::eq(subject_key, issuer_key) {
        "x509 user leaf"
    } else {
        "x509 user root"
    };
    issue_test_cert(&TestCertSpec {
        subject_cn: "x509 user leaf",
        subject_key,
        issuer_cn,
        issuer_key,
        signer_key,
        is_ca: false,
        not_before: dt(2020, 1, 1),
        not_after,
        eku,
        key_usage: KeyUsage(KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment),
        serial,
    })
}

fn make_test_crl(
    issuer_cn: &str,
    issuer_key: &RsaPrivateKey,
    revoked_serials: &[u32],
) -> CertificateList {
    let issuer = Name::from_str(&format!("CN={issuer_cn}")).expect("fixture CRL issuer");
    let algorithm = AlgorithmIdentifierOwned {
        oid: SHA_256_WITH_RSA_ENCRYPTION,
        parameters: Some(Any::from(Null)),
    };
    let revoked_certificates = if revoked_serials.is_empty() {
        None
    } else {
        Some(
            revoked_serials
                .iter()
                .map(|serial| RevokedCert {
                    serial_number: SerialNumber::from(*serial),
                    revocation_date: x509_time(dt(2024, 1, 1)),
                    crl_entry_extensions: None,
                })
                .collect(),
        )
    };
    let tbs = TbsCertList {
        version: Version::V2,
        signature: algorithm.clone(),
        issuer,
        this_update: x509_time(dt(2024, 1, 1)),
        next_update: Some(x509_time(dt(2035, 1, 1))),
        revoked_certificates,
        crl_extensions: None,
    };
    let tbs_der = tbs.to_der().expect("fixture CRL TBS should encode");
    let signing_key = SigningKey::<Sha256>::new(issuer_key.clone());
    let signature: RsaSignature = signing_key.sign(&tbs_der);

    CertificateList {
        tbs_cert_list: tbs,
        signature_algorithm: algorithm,
        signature: BitString::from_bytes(&signature.to_vec()).expect("fixture CRL signature"),
    }
}

fn write_cert_to(dir: &Path, name: &str, cert: &X509) {
    fs::write(
        dir.join(name),
        cert.to_der().expect("fixture certificate should encode"),
    )
    .expect("fixture certificate should be written");
}

fn write_crl_to(dir: &Path, name: &str, crl: &CertificateList) {
    fs::write(
        dir.join(name),
        crl.to_der().expect("fixture CRL should encode"),
    )
    .expect("fixture CRL should be written");
}

fn certificate_audit_monitored_item(filter: EventFilter) -> MonitoredItemCreateRequest {
    MonitoredItemCreateRequest::new(
        ReadValueId::new(ObjectId::Server.into(), AttributeId::EventNotifier),
        MonitoringMode::Reporting,
        MonitoringParameters {
            client_handle: 1,
            sampling_interval: 0.0,
            filter: ExtensionObject::from_message(filter),
            queue_size: 10,
            discard_oldest: true,
        },
    )
}

fn certificate_audit_filter() -> EventFilter {
    let event_type = NodeId::from(ObjectTypeId::BaseEventType);
    EventFilter {
        select_clauses: Some(vec![
            SimpleAttributeOperand::new_value(event_type.clone(), "EventType"),
            SimpleAttributeOperand::new_value(event_type.clone(), "SourceName"),
            SimpleAttributeOperand::new_value(event_type.clone(), "Message"),
            SimpleAttributeOperand::new_value(event_type.clone(), "Severity"),
            SimpleAttributeOperand::new_value(event_type.clone(), "StatusCodeId"),
            SimpleAttributeOperand::new_value(event_type, "Certificate"),
        ]),
        where_clause: ContentFilter::default(),
    }
}

fn localized_text(value: &Variant) -> Option<&str> {
    let Variant::LocalizedText(text) = value else {
        return None;
    };
    Some(text.text.as_ref())
}

#[tokio::test]
async fn x509_user_token_untrusted_configured_thumbprint_is_rejected() {
    let fixture = X509UserFixture::new(UserCertTrust::Untrusted);

    assert_activate_session_status(
        fixture.authenticate().await,
        StatusCode::BadCertificateUntrusted,
        "configured but untrusted X.509 user certificate",
    );
}

#[tokio::test]
async fn x509_user_token_rejected_store_certificate_is_untrusted_and_audited() {
    let temp = TempPath::new("x509-user-rejected-store-audit");
    let server_pki = temp.path().join("server-pki");
    let audit_client_pki = temp.path().join("audit-client-pki");
    let rejected_client_pki = temp.path().join("rejected-client-pki");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("X.509 audit test listener should bind");
    let port = listener
        .local_addr()
        .expect("X.509 audit test listener should have address")
        .port();
    let endpoint_url = format!("opc.tcp://127.0.0.1:{port}{X509_PATH}");

    let store = CertificateStore::new(&server_pki);
    store
        .ensure_pki_path()
        .expect("X.509 audit server PKI structure should be created");
    let root_key = test_key(&temp, "audit-root");
    let user_key = test_key(&temp, "audit-user");
    let root = issue_test_cert(&TestCertSpec {
        subject_cn: "x509 audit root",
        subject_key: &root_key.rsa,
        issuer_cn: "x509 audit root",
        issuer_key: &root_key.rsa,
        signer_key: &root_key.rsa,
        is_ca: true,
        not_before: dt(2020, 1, 1),
        not_after: dt(2035, 1, 1),
        eku: UserCertEku::None,
        key_usage: KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign),
        serial: 110,
    });
    let rejected_user_cert = issue_test_cert(&TestCertSpec {
        subject_cn: "x509 rejected user",
        subject_key: &user_key.rsa,
        issuer_cn: "x509 audit root",
        issuer_key: &root_key.rsa,
        signer_key: &root_key.rsa,
        is_ca: false,
        not_before: dt(2020, 1, 1),
        not_after: dt(2035, 1, 1),
        eku: UserCertEku::Both,
        key_usage: KeyUsage(KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment),
        serial: 111,
    });
    write_cert_to(&store.trusted_certs_dir(), "audit-root.der", &root);
    store
        .store_rejected_cert(&rejected_user_cert)
        .expect("X.509 user identity certificate should be pre-rejected");
    write_cert_to(temp.path(), "rejected-user.der", &rejected_user_cert);
    let rejected_user_cert_path = temp.path().join("rejected-user.der");
    let rejected_user_certificate = rejected_user_cert.as_byte_string();
    let user_token_ids = [
        ANONYMOUS_USER_TOKEN_ID.to_string(),
        X509_USER_TOKEN_ID.to_string(),
    ];
    let endpoint = ServerEndpoint::new(
        X509_PATH,
        SecurityPolicy::None,
        MessageSecurityMode::None,
        &user_token_ids,
    );
    let authenticator = Arc::new(X509UserTokenPolicyAuthenticator {
        signing_thumbprint: rejected_user_cert.thumbprint(),
        token_security_policy: SecurityPolicy::Basic256Sha256,
    });

    let (server, handle) = ServerBuilder::new()
        .application_name("X509 User Certificate Audit Test Server")
        .application_uri("urn:x509-user-certificate-audit-test-server")
        .product_uri("urn:x509-user-certificate-audit-test-server")
        .host("127.0.0.1")
        .port(port)
        .pki_dir(&server_pki)
        .create_sample_keypair(true)
        .discovery_urls(vec![endpoint_url.clone()])
        .add_user_token(
            X509_USER_TOKEN_ID,
            ServerUserToken::x509("certificate-user", &rejected_user_cert_path),
        )
        .with_authenticator(authenticator)
        .add_endpoint("x509-audit", endpoint)
        .build()
        .expect("X.509 audit test server should build");
    handle.info().port.store(port, Ordering::Relaxed);
    let server_task = tokio::spawn(async move {
        let _ = server.run_with(listener).await;
    });

    let mut audit_client = ClientBuilder::new()
        .application_name("X509 User Certificate Audit Test Client")
        .application_uri("urn:x509-user-certificate-audit-test-client")
        .product_uri("urn:x509-user-certificate-audit-test-client")
        .pki_dir(&audit_client_pki)
        .create_sample_keypair(true)
        .trust_server_certs(true)
        .session_retry_limit(0)
        .client()
        .expect("X.509 audit observer client should build");
    let (audit_session, audit_event_loop) = audit_client
        .connect_to_matching_endpoint(
            (
                endpoint_url.as_str(),
                SecurityPolicy::None.to_str(),
                MessageSecurityMode::None,
            ),
            IdentityToken::Anonymous,
        )
        .await
        .expect("X.509 audit observer session should be constructed");
    let audit_event_loop_task = audit_event_loop.spawn();
    tokio::time::timeout(Duration::from_secs(5), audit_session.wait_for_connection())
        .await
        .expect("X.509 audit observer should become connected");

    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let subscription_id = audit_session
        .create_subscription(
            Duration::from_millis(100),
            30,
            10,
            0,
            0,
            true,
            EventCallback::new(move |event_fields, _| {
                let _ = event_tx.send(event_fields.unwrap_or_default());
            }),
        )
        .await
        .expect("X.509 certificate audit subscription should be created");
    let create_results = audit_session
        .create_monitored_items(
            subscription_id,
            TimestampsToReturn::Both,
            vec![certificate_audit_monitored_item(certificate_audit_filter())],
        )
        .await
        .expect("X.509 certificate audit monitored item request should complete");
    assert_eq!(create_results[0].result.status_code, StatusCode::Good);

    let mut rejected_client = ClientBuilder::new()
        .application_name("Rejected X509 User Certificate Test Client")
        .application_uri("urn:rejected-x509-user-certificate-test-client")
        .product_uri("urn:rejected-x509-user-certificate-test-client")
        .pki_dir(&rejected_client_pki)
        .create_sample_keypair(true)
        .trust_server_certs(true)
        .session_retry_limit(0)
        .session_retry_initial(Duration::from_millis(10))
        .client()
        .expect("rejected X.509 user certificate client should build");
    let (rejected_session, rejected_event_loop) = rejected_client
        .connect_to_matching_endpoint(
            (
                endpoint_url.as_str(),
                SecurityPolicy::None.to_str(),
                MessageSecurityMode::None,
            ),
            IdentityToken::new_x509(rejected_user_cert, user_key.private_key),
        )
        .await
        .expect("rejected X.509 user certificate session should be constructed");
    rejected_session.disable_reconnects();
    let rejected_status = tokio::time::timeout(Duration::from_secs(5), rejected_event_loop.spawn())
        .await
        .expect("rejected X.509 user certificate event loop should finish")
        .expect("rejected X.509 user certificate event loop task should complete");

    audit_session.trigger_publish_now();
    let expected_event_type = Variant::from(NodeId::from(
        ObjectTypeId::AuditCertificateUntrustedEventType,
    ));
    let mut audit_fields = None;
    for _ in 0..8 {
        let Ok(Some(fields)) = tokio::time::timeout(Duration::from_secs(5), event_rx.recv()).await
        else {
            break;
        };
        if fields.first() == Some(&expected_event_type) {
            audit_fields = Some(fields);
            break;
        }
        audit_session.trigger_publish_now();
    }
    let audit_fields =
        audit_fields.expect("rejected X.509 user certificate should emit certificate audit event");

    handle.cancel();
    audit_event_loop_task.abort();
    server_task.abort();

    assert_eq!(rejected_status, StatusCode::BadCertificateUntrusted);
    assert_eq!(audit_fields[0], expected_event_type);
    assert_eq!(
        audit_fields[1],
        Variant::from(UAString::from("Security/Certificate"))
    );
    assert_eq!(
        localized_text(&audit_fields[2]),
        Some("Validate UserIdentityCertificate failed: BadCertificateUntrusted")
    );
    assert_eq!(audit_fields[3], Variant::UInt16(900));
    assert_eq!(
        audit_fields[4],
        Variant::from(StatusCode::BadCertificateUntrusted)
    );
    assert_eq!(audit_fields[5], Variant::from(rejected_user_certificate));
}

#[tokio::test]
async fn x509_user_token_expired_configured_thumbprint_is_rejected() {
    let fixture = X509UserFixture::new(UserCertTrust::Expired);

    assert_activate_session_status(
        fixture.authenticate().await,
        StatusCode::BadCertificateTimeInvalid,
        "configured but expired X.509 user certificate",
    );
}

#[tokio::test]
async fn x509_user_token_wrong_usage_configured_thumbprint_is_rejected() {
    let fixture = X509UserFixture::new(UserCertTrust::WrongUsage);

    assert_activate_session_status(
        fixture.authenticate().await,
        StatusCode::BadCertificateUseNotAllowed,
        "configured but wrong-usage X.509 user certificate",
    );
}

#[tokio::test]
async fn x509_user_token_incomplete_or_revoked_chain_is_rejected() {
    let incomplete = X509UserFixture::new(UserCertTrust::IncompleteChain);
    assert_activate_session_status(
        incomplete.authenticate().await,
        StatusCode::BadCertificateChainIncomplete,
        "configured but incomplete-chain X.509 user certificate",
    );

    let revoked = X509UserFixture::new(UserCertTrust::Revoked);
    assert_activate_session_status(
        revoked.authenticate().await,
        StatusCode::BadCertificateRevoked,
        "configured but revoked X.509 user certificate",
    );
}

#[tokio::test]
async fn x509_user_token_malformed_certificate_is_rejected() {
    let fixture = X509UserFixture::new(UserCertTrust::Trusted);

    assert_activate_session_status(
        fixture.authenticate_malformed_certificate().await,
        StatusCode::BadCertificateInvalid,
        "malformed X.509 user certificate bytes",
    );
}

#[tokio::test]
async fn x509_user_token_bad_signature_is_distinguishable() {
    let fixture = X509UserFixture::new(UserCertTrust::Trusted);

    assert_activate_session_no_certificate_audit_before_authentication(
        fixture.authenticate_with_tampered_signature().await,
        0,
        0,
        StatusCode::BadUserSignatureInvalid,
        "trusted X.509 user certificate with bad signature",
    );
}

#[tokio::test]
async fn x509_user_token_missing_signature_is_user_signature_invalid() {
    let fixture = X509UserFixture::new(UserCertTrust::Trusted);

    assert_activate_session_no_certificate_audit_before_authentication(
        fixture.authenticate_without_user_token_signature().await,
        0,
        0,
        StatusCode::BadUserSignatureInvalid,
        "trusted X.509 user certificate without userTokenSignature",
    );
}

#[tokio::test]
async fn x509_user_token_legacy_signature_is_rejected_when_enhanced_proof_required() {
    let fixture = X509UserFixture::new_enhanced_channel_bound_policy();

    assert_activate_session_no_certificate_audit_before_authentication(
        fixture.authenticate().await,
        0,
        0,
        StatusCode::BadUserSignatureInvalid,
        "legacy X.509 user-token signature on enhanced channel-bound policy",
    );
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

    fn new_protected_policy_on_unprotected_endpoint() -> Self {
        let pki = TempPath::new("oauth2-protected-pki");
        let (private_key, _, issuer_cert_path) = setup_trusted_oauth2_certificate(pki.path());
        let mut endpoint = ServerEndpoint::new_none(OAUTH2_PATH, &[]);
        endpoint.password_security_policy = Some(SecurityPolicy::Basic256Sha256.to_string());
        let policy_id = issued_token_security_policy(&endpoint);

        let (_server, handle) = ServerBuilder::new()
            .without_node_managers()
            .application_name("Protected OAuth2 Security Test Server")
            .application_uri("urn:protected-oauth2-security-test-server")
            .product_uri("urn:protected-oauth2-security-test-server")
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
            .expect("protected OAuth2 security test server should build");

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

const PASSWORD_PATH: &str = "/password";
const PASSWORD_USER_TOKEN_ID: &str = "password-user";

struct PasswordFixture {
    endpoint_url: String,
    handle: ServerHandle,
    policy_id: UAString,
    authentication_attempts: Option<Arc<AtomicUsize>>,
    _pki: TempPath,
}

impl PasswordFixture {
    fn new() -> Self {
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
            authentication_attempts: None,
            _pki: pki,
        }
    }

    fn new_protected_policy_on_unprotected_endpoint() -> Self {
        let pki = TempPath::new("password-protected-pki");
        let mut endpoint =
            ServerEndpoint::new_none(PASSWORD_PATH, &[PASSWORD_USER_TOKEN_ID.into()]);
        endpoint.password_security_policy = Some(SecurityPolicy::Basic256Sha256.to_string());
        let policy_id = user_pass_security_policy_id(&endpoint);
        let authentication_attempts = Arc::new(AtomicUsize::new(0));
        let authenticator = Arc::new(PasswordAuthenticatorProbe {
            authentication_attempts: authentication_attempts.clone(),
        });

        let (_server, handle) = ServerBuilder::new()
            .without_node_managers()
            .application_name("Protected Password Security Test Server")
            .application_uri("urn:protected-password-security-test-server")
            .product_uri("urn:protected-password-security-test-server")
            .host("127.0.0.1")
            .pki_dir(pki.path())
            .discovery_urls(vec!["opc.tcp://127.0.0.1:4856/password".to_string()])
            .add_user_token(
                PASSWORD_USER_TOKEN_ID,
                ServerUserToken::user_pass("brew-operator", "correct-password"),
            )
            .with_authenticator(authenticator)
            .add_endpoint("password", endpoint)
            .build()
            .expect("protected password security test server should build");

        Self {
            endpoint_url: format!("{}{}", handle.info().base_endpoint(), PASSWORD_PATH),
            handle,
            policy_id,
            authentication_attempts: Some(authentication_attempts),
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

    fn authentication_attempt_count(&self) -> usize {
        self.authentication_attempts
            .as_ref()
            .map(|attempts| attempts.load(Ordering::Relaxed))
            .unwrap_or_default()
    }
}

struct PasswordAuthenticatorProbe {
    authentication_attempts: Arc<AtomicUsize>,
}

#[async_trait]
impl AuthManager for PasswordAuthenticatorProbe {
    async fn authenticate_username_identity_token(
        &self,
        _endpoint: &ServerEndpoint,
        username: &str,
        password: &Password,
    ) -> Result<UserToken, Error> {
        self.authentication_attempts.fetch_add(1, Ordering::Relaxed);

        if username == "brew-operator" && password.get() == "correct-password" {
            Ok(UserToken(PASSWORD_USER_TOKEN_ID.to_string()))
        } else {
            Err(Error::new(
                StatusCode::BadIdentityTokenRejected,
                "password probe rejected credentials",
            ))
        }
    }

    fn user_token_policies(&self, endpoint: &ServerEndpoint) -> Vec<UserTokenPolicy> {
        vec![UserTokenPolicy {
            policy_id: user_pass_security_policy_id(endpoint),
            token_type: UserTokenType::UserName,
            issued_token_type: UAString::null(),
            issuer_endpoint_url: UAString::null(),
            security_policy_uri: user_pass_security_policy_uri(endpoint),
        }]
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
    application_cert_and_key(common_name, "urn:oauth2-idp")
}

fn application_cert_and_key(common_name: &str, application_uri: &str) -> (X509, PrivateKey) {
    let mut alt_host_names = AlternateNames::new();
    alt_host_names.add_dns("localhost");
    alt_host_names.add_uri(application_uri);
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
        assert_activate_session_status(
            fixture.authenticate(&token).await,
            StatusCode::BadUserAccessDenied,
            "invalid OAuth2 JWT",
        );
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
async fn username_password_token_requiring_protection_rejects_cleartext_before_authentication() {
    let fixture = PasswordFixture::new_protected_policy_on_unprotected_endpoint();

    let result = fixture
        .authenticate("brew-operator", "correct-password")
        .await;

    assert_eq!(
        fixture.authentication_attempt_count(),
        0,
        "unprotected username/password token reached user authentication"
    );
    assert_activate_session_status(
        result,
        StatusCode::BadIdentityTokenInvalid,
        "unprotected username/password token requiring protection",
    );
}

#[tokio::test]
async fn issued_token_requiring_protection_rejects_cleartext_before_claim_validation() {
    let fixture = OAuth2Fixture::new_protected_policy_on_unprotected_endpoint();
    let token = signed_jwt(
        json!({
            "iss": OAUTH2_ISSUER,
            "aud": OAUTH2_AUDIENCE,
            "exp": past_expiration(),
            "sub": "brew-operator"
        }),
        &fixture.private_key,
    );

    assert_activate_session_status(
        fixture.authenticate(&format!("Bearer {token}")).await,
        StatusCode::BadIdentityTokenInvalid,
        "unprotected issued token requiring protection",
    );
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
