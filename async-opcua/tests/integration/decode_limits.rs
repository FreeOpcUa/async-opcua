//! What a caller sees when a response doesn't fit the client's decoding limits.

use std::time::Duration;

use opcua::types::{AttributeId, NodeId, ReadValueId, StatusCode, TimestampsToReturn, VariableId};
use opcua_client::{services::Read, DefaultRetryPolicy, ExponentialBackoff, UARequest};

use crate::utils::{default_client, test_server, Tester};

fn read_ids(count: usize) -> Vec<ReadValueId> {
    let node: NodeId = VariableId::Server_ServerStatus_CurrentTime.into();
    vec![
        ReadValueId {
            node_id: node,
            attribute_id: AttributeId::Value as u32,
            ..Default::default()
        };
        count
    ]
}

/// A response with more elements than the client's `max_array_length` fails to decode, and the
/// transport gets closed, which is the right call. But the request waiting for that response only
/// heard "BadConnectionClosed: Fatal error", and the real reason was only in the log. It should
/// get the actual error, so a limit that's too low shows up as something you can fix.
#[tokio::test]
async fn response_larger_than_the_client_array_limit_reports_the_decoding_error() {
    let _ = env_logger::try_init();
    let client = default_client(0, false).max_array_length(1_000);
    let mut tester = Tester::new_custom_client(test_server(), client).await;
    let (session, event_loop) = tester.connect_default().await.unwrap();
    event_loop.spawn();
    assert!(session.wait_for_connection().await);

    let err = session
        .read(&read_ids(1_500), TimestampsToReturn::Neither, 0.0)
        .await
        .expect_err("1500 values can't be decoded with a limit of 1000");
    assert_eq!(
        err.status(),
        StatusCode::BadDecodingError,
        "the caller should be told why the request failed, got: {err}"
    );
    assert!(
        err.to_string().contains("1000"),
        "the error should name the limit that was exceeded, got: {err}"
    );
}

/// After a failure like that the session should come back and serve requests that fit.
#[tokio::test]
async fn session_recovers_after_a_response_exceeded_the_decoding_limit() {
    let _ = env_logger::try_init();
    let client = default_client(0, false).max_array_length(1_000);
    let mut tester = Tester::new_custom_client(test_server(), client).await;
    let (session, event_loop) = tester.connect_default().await.unwrap();
    event_loop.spawn();
    assert!(session.wait_for_connection().await);

    let _ = session
        .read(&read_ids(1_500), TimestampsToReturn::Neither, 0.0)
        .await;

    // The event loop reconnects on its own, so give it a moment.
    let mut recovered = false;
    for _ in 0..50 {
        if session
            .read(&read_ids(10), TimestampsToReturn::Neither, 0.0)
            .await
            .is_ok_and(|values| values.len() == 10)
        {
            recovered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        recovered,
        "the session didn't recover after the decoding failure"
    );
}

/// The default retry policy retries `BadConnectionClosed`, which is what these requests used to
/// fail with, and every retry sent the same request, got the same too-big response and dropped the
/// session again. Now the request fails right away with the real error. (Anyone who wants to retry
/// decoding errors anyway can add `BadDecodingError` with `DefaultRetryPolicy::new_with_extras`.)
#[tokio::test]
async fn decoding_error_is_not_retried_by_the_default_policy() {
    let _ = env_logger::try_init();
    let client = default_client(0, false).max_array_length(1_000);
    let mut tester = Tester::new_custom_client(test_server(), client).await;
    let (session, event_loop) = tester.connect_default().await.unwrap();
    event_loop.spawn();
    assert!(session.wait_for_connection().await);

    let err = session
        .send_with_retry(
            Read::new(&session).nodes_to_read(read_ids(1_500)),
            DefaultRetryPolicy::new(ExponentialBackoff::new(
                Duration::from_millis(1000),
                Some(3),
                Duration::from_millis(50),
            )),
        )
        .await
        .expect_err("1500 values can't be decoded with a limit of 1000");
    assert_eq!(err.status(), StatusCode::BadDecodingError);
}
