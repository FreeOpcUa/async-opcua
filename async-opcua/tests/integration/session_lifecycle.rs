//! What a caller sees from a session when the event loop stops running.

use std::{sync::atomic::Ordering, time::Duration};

use opcua::{
    client::IdentityToken,
    crypto::SecurityPolicy,
    types::{MessageSecurityMode, UserTokenPolicy},
};
use tokio::net::TcpListener;

use crate::utils::{default_client, hostname, test_server, Tester, TEST_COUNTER};

/// Bind to get a free port, then let go of it, so nothing is listening there.
async fn closed_port() -> u16 {
    let listener = TcpListener::bind(format!("{}:0", hostname()))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// With `session_retry_limit(0)` the event loop gives up after the first failed attempt and the
/// task finishes. `wait_for_connection` used to keep waiting anyway, since nothing updated the
/// session state anymore. It should say `false`.
#[tokio::test]
async fn wait_for_connection_returns_false_when_the_event_loop_has_ended() {
    let _ = env_logger::try_init();
    let test_id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let port = closed_port().await;

    let mut client = default_client(test_id, false)
        .session_retry_limit(0)
        .client()
        .unwrap();
    let (session, event_loop) = client
        .connect_to_endpoint_directly(
            (
                format!("opc.tcp://{}:{port}/", hostname()).as_str(),
                SecurityPolicy::None.to_str(),
                MessageSecurityMode::None,
                UserTokenPolicy::anonymous(),
            ),
            IdentityToken::Anonymous,
        )
        .unwrap();
    let status = event_loop.spawn();

    let connected = tokio::time::timeout(Duration::from_secs(10), session.wait_for_connection())
        .await
        .expect("wait_for_connection never returned, even though the event loop has ended");
    assert!(
        !connected,
        "there is no server, so the session can't be connected"
    );

    let status = status.await.unwrap();
    assert!(
        status.is_bad(),
        "the event loop should say why it ended, got {status}"
    );
}

/// If the task running the event loop goes away after the session connected (aborted here), the
/// session is dead. `wait_for_connection` shouldn't claim it's still connected, and `disconnect`
/// shouldn't hang waiting for a loop that isn't there.
#[tokio::test]
async fn dead_event_loop_does_not_leave_the_session_looking_connected_or_hanging() {
    let _ = env_logger::try_init();
    let mut tester = Tester::new(test_server(), false).await;
    let (session, event_loop) = tester.connect_default().await.unwrap();
    let task = event_loop.spawn();
    assert!(session.wait_for_connection().await);

    task.abort();
    let _ = task.await;

    let connected = tokio::time::timeout(Duration::from_secs(5), session.wait_for_connection())
        .await
        .expect("wait_for_connection hung after the event loop was gone");
    assert!(
        !connected,
        "the event loop is gone, the session can't still be connected"
    );

    // It's fine for this to be an error, it just has to come back.
    let _ = tokio::time::timeout(Duration::from_secs(5), session.disconnect())
        .await
        .expect("disconnect hung after the event loop was gone");
}
