//! Behavioral regression tests that drive the real async-opcua client against a
//! *misbehaving* server, via the transparent "evil proxy" harness in
//! `common::hostile_server` (all under SecurityPolicy::None / MessageSecurityMode::None).
//!
//! These cover feature-009 client-hardening findings that were otherwise verified
//! only by compile/inspection because no hostile-server harness existed (T009):
//!
//! - T035 / H7: empty `results` in a DeleteSubscriptions response must not panic or mis-index the client.
//! - T042 / M10: a stalled secure-channel *renewal* must not wedge the client; it must tear the channel down and reconnect.

#![allow(missing_docs)]

mod common;

use std::time::{Duration, Instant};

use common::hostile_server::{current_time_read, HostileBehavior, HostileServer};
use opcua_client::{DataChangeCallback, MonitoredItem};
use opcua_types::TimestampsToReturn;

/// Sanity: the proxy faithfully forwards a normal None-policy connect + read.
/// If this regresses, failures in the hostile-behavior tests below are harness
/// bugs rather than client bugs.
#[tokio::test]
async fn proxy_passes_through_normal_none_policy_session() {
    let hostile = HostileServer::start(HostileBehavior::PassThrough).await;
    let (session, event_loop) = hostile.connect().await;
    let event_loop_task = event_loop.spawn();

    tokio::time::timeout(Duration::from_secs(5), session.wait_for_connection())
        .await
        .expect("session should connect through hostile proxy");

    let values = session
        .read(&[current_time_read()], TimestampsToReturn::Both, 0.0)
        .await
        .expect("read through hostile proxy should succeed");
    assert_eq!(values.len(), 1);

    event_loop_task.abort();
}

/// T035 / H7: a *successful* DeleteSubscriptions response carrying an empty
/// `results` array (server misbehavior) must not panic or mis-index the client.
/// The hardened handler rejects the length mismatch with an error instead.
#[tokio::test]
async fn empty_delete_subscriptions_results_do_not_panic_client() {
    let hostile = HostileServer::start(HostileBehavior::EmptyDeleteSubscriptionsResults).await;
    let (session, event_loop) = hostile.connect().await;
    let event_loop_task = event_loop.spawn();

    tokio::time::timeout(Duration::from_secs(5), session.wait_for_connection())
        .await
        .expect("session should connect through hostile proxy");

    let subscription_id = session
        .create_subscription(
            Duration::from_millis(100),
            100,
            20,
            1000,
            0,
            true,
            DataChangeCallback::new(|_, _: &MonitoredItem| {}),
        )
        .await
        .expect("subscription should be created before the hostile delete");

    // The proxy rewrites the DeleteSubscriptionsResponse `results` to empty, so the
    // returned count (0) no longer matches the one requested subscription id (1).
    let result = session.delete_subscription(subscription_id).await;
    assert!(
        result.is_err(),
        "client must reject an empty-results DeleteSubscriptions response, not accept it or panic"
    );
    assert_eq!(
        hostile.hook_hits(),
        1,
        "the empty-results hook should have fired exactly once"
    );

    event_loop_task.abort();
}

/// T042 / M10: when secure-channel renewal stalls (server never answers the renewal
/// OpenSecureChannel), the client must detect it, tear the channel down, and
/// reconnect — *not* wedge with operations hanging forever on the dead channel.
///
/// We force renewal quickly with a short `channel_lifetime` (renewal fires at 75%
/// of the granted token lifetime). The proxy withholds the renewal OPN response.
/// We then require both:
///   (a) the stall hook fired at least once (a renewal was attempted + withheld), and
///   (b) a read succeeds *after* the stall (the client recovered).
/// A true wedge never recovers, so the bounded loop below would expire and fail.
#[tokio::test]
async fn stalled_channel_renewal_does_not_wedge_client() {
    let hostile = HostileServer::start(HostileBehavior::StallChannelRenewal).await;
    let (session, event_loop) = hostile
        .connect_with(|b| {
            b.channel_lifetime(2_000) // 2s channel → renewal attempted ~1.5s in
                .keep_alive_interval(Duration::from_millis(400))
                .session_retry_limit(-1) // reconnect indefinitely
                .session_retry_initial(Duration::from_millis(200))
                .session_retry_max(Duration::from_millis(500))
        })
        .await;
    let event_loop_task = event_loop.spawn();

    tokio::time::timeout(Duration::from_secs(5), session.wait_for_connection())
        .await
        .expect("session should connect through hostile proxy");

    // Initial read works on the freshly opened channel.
    let initial = tokio::time::timeout(
        Duration::from_secs(3),
        session.read(&[current_time_read()], TimestampsToReturn::Both, 0.0),
    )
    .await
    .expect("initial read should not hang")
    .expect("initial read should succeed");
    assert_eq!(initial.len(), 1);

    // Drive reads until the renewal has been stalled AND a read subsequently
    // succeeds (proving recovery rather than a wedge).
    let mut recovered_after_stall = false;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        let stalled_already = hostile.hook_hits() >= 1;
        let read = tokio::time::timeout(
            Duration::from_secs(3),
            session.read(&[current_time_read()], TimestampsToReturn::Both, 0.0),
        )
        .await;
        if stalled_already {
            if let Ok(Ok(values)) = read {
                assert_eq!(values.len(), 1);
                recovered_after_stall = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    assert!(
        hostile.hook_hits() >= 1,
        "expected the proxy to withhold at least one renewal OpenSecureChannel response"
    );
    assert!(
        recovered_after_stall,
        "client did not recover after a stalled renewal (a post-stall read never succeeded) — possible wedge"
    );

    event_loop_task.abort();
}
