use std::{
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
    crypto::SecurityPolicy,
    types::{
        ApplicationType, DecodingOptions, MessageSecurityMode, NodeId, ReadValueId, StatusCode,
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
    assert_eq!(res, StatusCode::BadIdentityTokenRejected);
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
    assert_eq!(res, StatusCode::BadDecodingError);

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
        let token_str =
            String::from_utf8(token.value.clone().unwrap_or_default()).map_err(Error::decoding)?;
        if token_str == "valid" {
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
        .with_authenticator(Arc::new(IssuedTokenAuthenticator));
    let mut tester = Tester::new(server, false).await;
    let (session, lp) = tester
        .connect_path(
            SecurityPolicy::Aes128Sha256RsaOaep,
            MessageSecurityMode::SignAndEncrypt,
            IdentityToken::IssuedToken(IssuedTokenWrapper::new_source(ByteString::from(
                "valid".as_bytes(),
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
