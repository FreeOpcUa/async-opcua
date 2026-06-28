use std::{
    fs,
    path::PathBuf,
    sync::{atomic::Ordering, Arc},
    time::Duration,
};

use super::utils::hostname;
use async_trait::async_trait;
use bytes::BytesMut;
use log::debug;
use opcua::{
    client::IdentityToken,
    core::comms::tcp_codec::{Message, TcpCodec},
    core::config::Config,
    crypto::{KeySize, PrivateKey, SecurityPolicy},
    types::{
        ApplicationType, AttributeId, BrowseDescription, BrowseDirection, DecodingOptions,
        MessageSecurityMode, NodeClass, NodeId, ObjectId, ReadValueId, ReferenceTypeId, StatusCode,
        TimestampsToReturn, VariableId, Variant,
    },
};
use opcua_client::IssuedTokenWrapper;
use opcua_server::{
    authenticator::{issued_token_security_policy, AuthManager, UserToken},
    ServerEndpoint,
};
use opcua_types::{ByteString, Error, UAString, UserTokenPolicy, UserTokenType};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};
use tokio_util::codec::Decoder;

use crate::utils::{
    client_user_token, client_x509_token, copy_shared_certs, default_server, test_server, Tester,
    CLIENT_USERPASS_ID, TEST_COUNTER,
};

#[tokio::test]
async fn hello_timeout() {
    let _ = env_logger::try_init();

    let test_id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = default_server()
        .discovery_urls(vec![format!("opc.tcp://{}:{}", hostname(), port)])
        .pki_dir(format!("./pki-server/{test_id}"))
        .hello_timeout(1);
    copy_shared_certs(test_id, &server.config().application_description());

    let (server, handle) = server.build().unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::task::spawn(server.run_with(listener));

    let _guard = handle.token().clone().drop_guard();

    let mut stream = TcpStream::connect(addr).await.unwrap();
    debug!("Connected to {addr}");

    // Wait a bit more than the hello timeout (1 second)
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let mut bytes = BytesMut::with_capacity(1024);
    let result = stream.read_buf(&mut bytes).await;
    // Should first read the error message from the server.
    let read = result.unwrap();
    assert!(read > 0);
    let mut codec = TcpCodec::new(DecodingOptions::default());
    let msg = codec.decode(&mut bytes).unwrap();
    let Some(Message::Error(msg)) = msg else {
        panic!("Expected error got {msg:?}");
    };
    assert_eq!(msg.error, StatusCode::BadTimeout);

    let result = stream.read_buf(&mut bytes).await;

    match result {
        Ok(v) => {
            if v > 0 {
                panic!("Hello timeout exceeded and socket is still open, result = {v}")
            } else {
                // From
                debug!("Client got a read of 0 bytes on the socket, so treating by terminating with success");
            }
        }
        Err(err) => {
            debug!("Client got an error {err:?} on the socket terminating successfully");
        }
    }
    debug!("Test passed, closing server");
}

#[tokio::test]
async fn get_endpoints() {
    let tester = Tester::new_default_server(false).await;
    let endpoints = tester
        .client
        .get_server_endpoints_from_url(tester.endpoint())
        .await
        .unwrap();
    assert_eq!(endpoints.len(), tester.handle.info().config.endpoints.len());
}

async fn conn_test(policy: SecurityPolicy, mode: MessageSecurityMode, token: IdentityToken) {
    let mut tester = Tester::new_default_server(false).await;
    let (session, handle) = tester.connect(policy, mode, token).await.unwrap();
    let _h = handle.spawn();

    tokio::time::timeout(Duration::from_secs(20), session.wait_for_connection())
        .await
        .unwrap();

    session
        .read(
            &[ReadValueId::from(<VariableId as Into<NodeId>>::into(
                VariableId::Server_ServiceLevel,
            ))],
            TimestampsToReturn::Both,
            0.0,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn connect_none() {
    conn_test(
        SecurityPolicy::None,
        MessageSecurityMode::None,
        IdentityToken::Anonymous,
    )
    .await;
}

#[tokio::test]
async fn connect_basic128rsa15_sign() {
    conn_test(
        SecurityPolicy::Basic128Rsa15,
        MessageSecurityMode::Sign,
        IdentityToken::Anonymous,
    )
    .await;
}

#[tokio::test]
async fn connect_basic128rsa15_sign_and_encrypt() {
    conn_test(
        SecurityPolicy::Basic128Rsa15,
        MessageSecurityMode::SignAndEncrypt,
        IdentityToken::Anonymous,
    )
    .await;
}

#[tokio::test]
async fn connect_basic256_sign() {
    conn_test(
        SecurityPolicy::Basic256,
        MessageSecurityMode::Sign,
        IdentityToken::Anonymous,
    )
    .await;
}

#[tokio::test]
async fn connect_basic256_sign_and_encrypt() {
    conn_test(
        SecurityPolicy::Basic256,
        MessageSecurityMode::SignAndEncrypt,
        IdentityToken::Anonymous,
    )
    .await;
}

#[tokio::test]
async fn connect_aes256sha256rsaoaep_sign() {
    conn_test(
        SecurityPolicy::Aes128Sha256RsaOaep,
        MessageSecurityMode::Sign,
        IdentityToken::Anonymous,
    )
    .await;
}

#[tokio::test]
async fn connect_aes256sha256rsaoaep_sign_and_encrypt() {
    conn_test(
        SecurityPolicy::Aes128Sha256RsaOaep,
        MessageSecurityMode::SignAndEncrypt,
        IdentityToken::Anonymous,
    )
    .await;
}

#[tokio::test]
async fn connect_aes256sha256rsapss_sign() {
    conn_test(
        SecurityPolicy::Aes256Sha256RsaPss,
        MessageSecurityMode::Sign,
        IdentityToken::Anonymous,
    )
    .await;
}

#[tokio::test]
async fn connect_aes256sha256rsapss_sign_and_encrypt() {
    conn_test(
        SecurityPolicy::Aes256Sha256RsaPss,
        MessageSecurityMode::SignAndEncrypt,
        IdentityToken::Anonymous,
    )
    .await;
}

#[tokio::test]
async fn connect_basic128rsa15_with_username_password() {
    conn_test(
        SecurityPolicy::Basic128Rsa15,
        MessageSecurityMode::SignAndEncrypt,
        client_user_token(),
    )
    .await;
}

#[tokio::test]
async fn connect_basic128rsa15_with_x509_token() {
    conn_test(
        SecurityPolicy::Basic128Rsa15,
        MessageSecurityMode::SignAndEncrypt,
        client_x509_token().unwrap(),
    )
    .await;
}

#[tokio::test]
async fn connect_basic128rsa_15_with_invalid_token() {
    let mut tester = Tester::new_default_server(true).await;
    let (_, handle) = tester
        .connect(
            SecurityPolicy::Basic128Rsa15,
            MessageSecurityMode::SignAndEncrypt,
            IdentityToken::UserName(CLIENT_USERPASS_ID.to_owned(), "invalid".into()),
        )
        .await
        .unwrap();
    let res = handle.spawn().await.unwrap();
    assert_eq!(res, StatusCode::BadUserAccessDenied);
}

#[tokio::test]
async fn find_servers() {
    let tester = Tester::new_default_server(true).await;
    let servers = tester
        .client
        .find_servers(tester.endpoint(), None, None)
        .await
        .unwrap();
    assert_eq!(servers.len(), 1);

    let s = &servers[0];
    let discovery_urls = s.discovery_urls.as_ref().unwrap();
    assert!(!discovery_urls.is_empty());
    assert_eq!(s.application_type, ApplicationType::Server);
    assert_eq!(s.application_name.text.as_ref(), "integration_server");
    assert_eq!(s.application_uri.as_ref(), "urn:integration_server");
    assert_eq!(s.product_uri.as_ref(), "urn:integration_server Testkit");

    let servers = tester
        .client
        .find_servers(tester.endpoint(), Some(vec!["fr-FR".into()]), None)
        .await
        .unwrap();
    assert!(servers.is_empty());
}

#[tokio::test]
async fn discovery_test() {
    let tester = Tester::new_default_server(true).await;
    // Get all
    let endpoints = tester
        .client
        .get_endpoints(tester.endpoint(), &[], &[])
        .await
        .unwrap();
    assert_eq!(endpoints.len(), 11);

    let endpoints = tester
        .client
        .get_endpoints(tester.endpoint(), &["fr-FR"], &[])
        .await
        .unwrap();
    assert!(endpoints.is_empty());

    // Get with wrong profile URIs
    let endpoints = tester
        .client
        .get_endpoints(tester.endpoint(), &[], &["wrongwrong"])
        .await
        .unwrap();
    assert!(endpoints.is_empty());

    // Get all binary endpoints (all of them)
    let endpoints = tester
        .client
        .get_endpoints(
            tester.endpoint(),
            &[],
            &["http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary"],
        )
        .await
        .unwrap();
    assert_eq!(endpoints.len(), 11);
}

#[tokio::test]
async fn multi_client_test() {
    // Simple multi-client test, checking that we can send and receive requests with multiple clients
    // to the same server, and also that the client SDK can handle multiple sessions in the same client.
    let mut tester = Tester::new_default_server(true).await;

    let c1 = tester
        .connect_and_wait(
            SecurityPolicy::Basic128Rsa15,
            MessageSecurityMode::SignAndEncrypt,
            IdentityToken::UserName(
                CLIENT_USERPASS_ID.to_owned(),
                format!("{CLIENT_USERPASS_ID}_password").into(),
            ),
        )
        .await
        .unwrap();
    // Same user token, should still be fine
    let c2 = tester
        .connect_and_wait(
            SecurityPolicy::Basic256,
            MessageSecurityMode::SignAndEncrypt,
            IdentityToken::UserName(
                CLIENT_USERPASS_ID.to_owned(),
                format!("{CLIENT_USERPASS_ID}_password").into(),
            ),
        )
        .await
        .unwrap();

    // Different user, anonymous
    let c3 = tester
        .connect_and_wait(
            SecurityPolicy::None,
            MessageSecurityMode::None,
            IdentityToken::Anonymous,
        )
        .await
        .unwrap();

    // Read the service level a few times
    let mut val = 100;
    for _ in 0..5 {
        val += 10;
        tester.handle.set_service_level(val);
        for session in &[c1.clone(), c2.clone(), c3.clone()] {
            let value = session
                .read(
                    &[ReadValueId::from(<VariableId as Into<NodeId>>::into(
                        VariableId::Server_ServiceLevel,
                    ))],
                    TimestampsToReturn::Both,
                    0.0,
                )
                .await
                .unwrap();
            let Some(Variant::Byte(v)) = value[0].value else {
                panic!("Wrong result type");
            };
            assert_eq!(val, v);
        }
    }
}

#[tokio::test]
async fn recoverable_error_test_server() {
    // Test that if we send a too large message to the server, we don't lose the connection
    // entirely.
    let mut server = test_server();
    server = server.max_array_length(50);
    let mut tester = Tester::new(server, false).await;
    let (session, lp) = tester.connect_default().await.unwrap();
    lp.spawn();
    tokio::time::timeout(Duration::from_secs(2), session.wait_for_connection())
        .await
        .unwrap();

    let ids = (0..100)
        .map(|_| {
            ReadValueId::from(<VariableId as Into<NodeId>>::into(
                VariableId::Server_ServiceLevel,
            ))
        })
        .collect::<Vec<_>>();

    let res = session
        .read(&ids, TimestampsToReturn::Both, 0.0)
        .await
        .unwrap_err();
    assert_eq!(res.status(), StatusCode::BadDecodingError);

    session
        .read(
            &[ReadValueId::from(<VariableId as Into<NodeId>>::into(
                VariableId::Server_ServiceLevel,
            ))],
            TimestampsToReturn::Both,
            0.0,
        )
        .await
        .unwrap();
}

struct IssuedTokenAuthenticator;

fn valid_issued_jwt() -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = URL_SAFE_NO_PAD.encode(r#"{"sub":"valid","exp":4102444800}"#);
    format!("{header}.{claims}.signature")
}

fn sign_issued_jwt(claims: &str, private_key: &PrivateKey) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = URL_SAFE_NO_PAD.encode(claims);
    let signing_input = format!("{header}.{claims}");
    let mut signature = vec![0u8; private_key.size()];
    let signature_len = private_key
        .sign_sha256(signing_input.as_bytes(), &mut signature)
        .unwrap();
    let signature = URL_SAFE_NO_PAD.encode(&signature[..signature_len]);

    format!("{signing_input}.{signature}")
}

// Feature 025 US1: a DEDICATED OAuth2 issuer cert (separate from the server's app cert — the point of
// the pinning fix). Returns the cert path (to configure on the server) + its signing key.
fn make_oauth_issuer() -> (PathBuf, tempfile::TempDir, PrivateKey) {
    use opcua::crypto::{X509Data, X509};
    let data = X509Data {
        key_size: 2048,
        common_name: "oauth-issuer".to_string(),
        organization: "test".to_string(),
        organizational_unit: "test".to_string(),
        country: "EN".to_string(),
        state: "London".to_string(),
        alt_host_names: vec!["urn:oauth-issuer".to_string()].into(),
        certificate_duration_days: 60,
    };
    let (cert, key) = X509::cert_and_pkey(&data).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("issuer.der");
    fs::write(&path, cert.to_der().unwrap()).unwrap();
    (path, dir, key)
}

#[async_trait]
impl AuthManager for IssuedTokenAuthenticator {
    fn user_token_policies(&self, endpoint: &ServerEndpoint) -> Vec<UserTokenPolicy> {
        if endpoint.path == "/issued_token" {
            vec![UserTokenPolicy {
                policy_id: issued_token_security_policy(endpoint),
                token_type: UserTokenType::IssuedToken,
                issued_token_type: opcua::types::issued_token_types::JSON_WEB_TOKEN.into(),
                // Yes this is JSON in a string. The real thing would have a lot more fields.
                issuer_endpoint_url: "{\"ua:tokenEndpoint\": \"example.com/token\"}".into(),
                security_policy_uri: UAString::null(),
            }]
        } else {
            vec![]
        }
    }

    async fn authenticate_issued_identity_token(
        &self,
        _endpoint: &ServerEndpoint,
        token: &ByteString,
    ) -> Result<UserToken, Error> {
        let token_str = String::from_utf8(token.value.clone().unwrap_or_default().to_vec())
            .map_err(Error::decoding)?;
        if token_str == valid_issued_jwt() {
            Ok(UserToken("valid".into()))
        } else {
            Err(Error::new(
                StatusCode::BadIdentityTokenRejected,
                "Invalid token",
            ))
        }
    }
}

#[tokio::test]
async fn issued_token_test() {
    let (issuer_cert_path, _issuer_dir, issuer_key) = make_oauth_issuer();
    let server = test_server()
        .add_endpoint(
            "issued_token",
            (
                "/issued_token",
                SecurityPolicy::Aes128Sha256RsaOaep,
                MessageSecurityMode::SignAndEncrypt,
                &[] as &[&str],
            ),
        )
        .with_authenticator(Arc::new(IssuedTokenAuthenticator))
        // Feature 025 US1: issued-token auth now requires explicit issuer/audience + a pinned issuer cert.
        .oauth2_issuer("opcua-issuer")
        .oauth2_audience("opcua-server")
        .oauth2_issuer_certificate_path(issuer_cert_path);
    let mut tester = Tester::new(server, false).await;
    let issued_jwt = sign_issued_jwt(
        r#"{"sub":"valid","iss":"opcua-issuer","aud":"opcua-server","exp":4102444800,"roles":["operator"],"permissions":["read","write"]}"#,
        &issuer_key,
    );
    let (session, lp) = tester
        .connect_path(
            SecurityPolicy::Aes128Sha256RsaOaep,
            MessageSecurityMode::SignAndEncrypt,
            IdentityToken::IssuedToken(IssuedTokenWrapper::new_source(ByteString::from(
                issued_jwt.as_bytes(),
            ))),
            "issued_token",
        )
        .await
        .unwrap();
    lp.spawn();
    tokio::time::timeout(Duration::from_secs(5), session.wait_for_connection())
        .await
        .unwrap();

    session
        .read(
            &[ReadValueId::from(<VariableId as Into<NodeId>>::into(
                VariableId::Server_ServiceLevel,
            ))],
            TimestampsToReturn::Both,
            0.0,
        )
        .await
        .unwrap();
}

/// Cancel service (OPC UA Part 4 v1.05 §5.7.5, Session Service Set). This server processes requests
/// without a cancellable queue, so Cancel of any handle is a clean no-op: cancelCount 0, and the
/// session stays fully usable afterwards.
#[tokio::test]
async fn cancel_is_a_clean_noop() {
    let mut tester = Tester::new_default_server(false).await;
    let (session, handle) = tester
        .connect(
            SecurityPolicy::None,
            MessageSecurityMode::None,
            IdentityToken::Anonymous,
        )
        .await
        .unwrap();
    let _h = handle.spawn();
    tokio::time::timeout(Duration::from_secs(20), session.wait_for_connection())
        .await
        .unwrap();

    let cancelled = session.cancel(42).await.unwrap();
    assert_eq!(cancelled, 0, "no outstanding requests to cancel");

    // The session is still usable after Cancel.
    session
        .read(
            &[ReadValueId::from(<VariableId as Into<NodeId>>::into(
                VariableId::Server_ServiceLevel,
            ))],
            TimestampsToReturn::Both,
            0.0,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn namespace_metadata_properties_read_node_class_variable() {
    let mut tester = Tester::new(test_server(), false).await;
    let (session, lp) = tester.connect_default().await.unwrap();
    lp.spawn();
    tokio::time::timeout(Duration::from_secs(20), session.wait_for_connection())
        .await
        .unwrap();

    let metadata_refs = session
        .browse(
            &[BrowseDescription {
                node_id: ObjectId::Server_Namespaces.into(),
                browse_direction: BrowseDirection::Forward,
                reference_type_id: ReferenceTypeId::HasComponent.into(),
                include_subtypes: false,
                node_class_mask: NodeClass::Object as u32,
                result_mask: 0x3f,
            }],
            1000,
            None,
        )
        .await
        .unwrap();
    let metadata_node = metadata_refs[0]
        .references
        .as_ref()
        .and_then(|refs| refs.first())
        .expect("test namespace metadata should be browsable")
        .node_id
        .node_id
        .clone();

    let property_refs = session
        .browse(
            &[BrowseDescription {
                node_id: metadata_node,
                browse_direction: BrowseDirection::Forward,
                reference_type_id: ReferenceTypeId::HasProperty.into(),
                include_subtypes: false,
                node_class_mask: NodeClass::Variable as u32,
                result_mask: 0x3f,
            }],
            1000,
            None,
        )
        .await
        .unwrap();
    let namespace_uri_property = property_refs[0]
        .references
        .as_ref()
        .and_then(|refs| {
            refs.iter()
                .find(|reference| reference.browse_name.name.as_ref() == "NamespaceUri")
        })
        .expect("NamespaceUri metadata property should be browsable")
        .node_id
        .node_id
        .clone();

    // OPC UA Part 5 6.3.14: NamespaceMetadata properties are Variable nodes.
    let values = session
        .read(
            &[ReadValueId {
                node_id: namespace_uri_property,
                attribute_id: AttributeId::NodeClass as u32,
                ..Default::default()
            }],
            TimestampsToReturn::Neither,
            0.0,
        )
        .await
        .unwrap();

    assert_eq!(values[0].status(), StatusCode::Good);
    assert_eq!(
        values[0].value,
        Some(Variant::Int32(NodeClass::Variable as i32))
    );
}
