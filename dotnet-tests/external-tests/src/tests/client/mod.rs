mod connect;
pub mod reverse_connect;
pub mod services;

use std::{future::Future, panic::AssertUnwindSafe, sync::Arc};

pub use connect::run_connect_tests;
use futures::FutureExt;
use opcua::{
    client::{IdentityToken, Session},
    crypto::{hostname, SecurityPolicy},
    types::MessageSecurityMode,
};
pub use reverse_connect::test_reverse_connect;
use tokio::select;

use crate::{
    client::{make_client, ClientTestState},
    common::JoinHandleAbortGuard,
};

/// Workaround for AsyncFn, but it only really barely works, and breaks closures.
pub trait WithSessionMethod<'a>:
    FnOnce(Arc<Session>, &'a mut ClientTestState) -> Self::Fut
{
    type Fut: Future<Output = ()> + 'a;
}

impl<'a, T, F> WithSessionMethod<'a> for T
where
    T: FnOnce(Arc<Session>, &'a mut ClientTestState) -> F,
    F: Future<Output = ()> + 'a,
{
    type Fut = F;
}

pub async fn with_session<Fun: for<'a> WithSessionMethod<'a>>(
    f: Fun,
    policy: SecurityPolicy,
    mode: MessageSecurityMode,
    identity_token: IdentityToken,
    ctx: &mut ClientTestState,
) {
    let mut client = make_client(true).client().unwrap();
    let (session, event_loop) = client
        .connect_to_matching_endpoint(
            (
                format!("opc.tcp://{}:62546", hostname().unwrap()).as_str(),
                policy.to_str(),
                mode,
            ),
            identity_token,
        )
        .await
        .unwrap();
    let mut h = event_loop.spawn();
    let _guard = JoinHandleAbortGuard::new(h.abort_handle());
    select! {
        r = session.wait_for_connection() => assert!(r, "Expected connection"),
        r = &mut h => {
            panic!("Failed to connect, loop terminated: {r:?}");
        }
    };
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

pub async fn with_basic_session<Fun: for<'a> WithSessionMethod<'a>>(
    f: Fun,
    ctx: &mut ClientTestState,
) {
    with_session(
        f,
        SecurityPolicy::None,
        MessageSecurityMode::None,
        IdentityToken::Anonymous,
        ctx,
    )
    .await
}
