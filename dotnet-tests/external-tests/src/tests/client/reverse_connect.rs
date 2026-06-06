use std::{panic::AssertUnwindSafe, sync::Arc};

use futures::FutureExt;
use opcua::{
    client::{reverse_connect::ReverseConnectionSource, ConnectionSource, IdentityToken},
    crypto::{hostname, SecurityPolicy},
    types::{
        AttributeId, EndpointDescription, MessageSecurityMode, ReadValueId, ServerState,
        TimestampsToReturn, VariableId,
    },
};
use tokio::{net::TcpListener, select};

use crate::{
    client::{make_client, ClientTestState},
    common::{InMessage, JoinHandleAbortGuard, ReverseConnectMessage},
    tests::client::WithSessionMethod,
};

pub async fn with_reverse_connect_session<Fun: for<'a> WithSessionMethod<'a>>(
    f: Fun,
    policy: SecurityPolicy,
    mode: MessageSecurityMode,
    identity_token: IdentityToken,
    ctx: &mut ClientTestState,
) {
    let client = make_client(false).client().unwrap();

    let listener = TcpListener::bind("localhost:0").await.unwrap();
    println!(
        "Bound listener for reverse connect on {}",
        listener.local_addr().unwrap()
    );
    let addr = listener.local_addr().unwrap();
    let listener = Arc::new(listener);

    ctx.server
        .send_message(InMessage::ReverseConnect(ReverseConnectMessage {
            url: Some(format!("opc.tcp://localhost:{}", addr.port())),
        }))
        .await;

    let endpoints = client
        .get_endpoints(
            // Using reverse connect for discovery as well.
            // This requires us to actually make the connector.
            ReverseConnectionSource::new_listener(listener.clone())
                .get_connector(&format!("opc.tcp://{}:62546", hostname().unwrap()).into())
                .unwrap(),
            &[],
            &[],
        )
        .await
        .unwrap();

    let (session, event_loop) = client
        .session_builder()
        .with_connector(ReverseConnectionSource::new_listener(listener))
        .user_identity_token(identity_token)
        .with_endpoints(endpoints)
        .connect_to_matching_endpoint(EndpointDescription {
            endpoint_url: format!("opc.tcp://{}:62546", hostname().unwrap()).into(),
            security_mode: mode,
            security_policy_uri: policy.to_uri().into(),
            ..Default::default()
        })
        .unwrap()
        .build(client.certificate_store().clone())
        .unwrap();

    let mut h = event_loop.spawn();
    let _guard = JoinHandleAbortGuard::new(h.abort_handle());
    select! {
        r = session.wait_for_connection() => assert!(r, "Expected connection"),
        r = &mut h => {
            panic!("Failed to connect, loop terminated: {r:?}");
        }
    }

    let r = select! {
        r = AssertUnwindSafe(f(session.clone(), ctx)).catch_unwind() => r,
        r = &mut h => {
            panic!("Event loop terminated unexpectedly while test was running: {r:?}");
        }
    };

    if let Err(e) = session.disconnect().await {
        println!("Failed to shut down session: {e}");
    } else {
        let _ = h.await;
    }

    if let Err(e) = r {
        std::panic::resume_unwind(e)
    }
}

async fn test_reverse_connect_inner(
    session: Arc<opcua::client::Session>,
    _ctx: &mut ClientTestState,
) {
    let read = session
        .read(
            &[ReadValueId {
                node_id: VariableId::Server_ServerStatus_State.into(),
                attribute_id: AttributeId::Value as u32,
                ..Default::default()
            }],
            TimestampsToReturn::Both,
            0.0,
        )
        .await
        .unwrap();
    assert_eq!(
        read[0].value.clone().unwrap().try_cast_to::<i32>().unwrap(),
        ServerState::Running as i32
    );
}

pub async fn test_reverse_connect(ctx: &mut ClientTestState) {
    with_reverse_connect_session(
        test_reverse_connect_inner,
        SecurityPolicy::Aes128Sha256RsaOaep,
        MessageSecurityMode::SignAndEncrypt,
        IdentityToken::UserName("test".to_owned(), "pass".into()),
        ctx,
    )
    .await;
}
