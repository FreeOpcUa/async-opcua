//! Feature 026 / US4 (T015): subscriber anti-replay / freshness tests (SC-002).

use std::sync::Arc;
use std::time::Duration;

use opcua_core::sync::RwLock;
use opcua_crypto::SecurityPolicy;
use opcua_pubsub::{
    engine::PubSubEngine,
    security::ReplayWindow,
    PublisherId, SecurityGroup, UadpDataSetMessage, UadpNetworkMessage,
};
use opcua_server::address_space::AddressSpace;
use opcua_types::{ContextOwned, MessageSecurityMode, StatusCode};

fn address_space() -> Arc<RwLock<AddressSpace>> {
    Arc::new(RwLock::new(AddressSpace::new()))
}

const TOKEN: u32 = 1;

fn accepts(w: &mut ReplayWindow, seq: u16) -> bool {
    w.check(TOKEN, seq).is_ok()
}

#[test]
fn first_message_is_accepted_and_seeds_the_window() {
    let mut w = ReplayWindow::new();
    assert!(accepts(&mut w, 5000), "first message of an epoch must be accepted");
}

#[test]
fn strictly_increasing_sequence_is_accepted() {
    let mut w = ReplayWindow::new();
    for seq in 1..=200u16 {
        assert!(accepts(&mut w, seq), "increasing seq {seq} must be accepted");
    }
}

#[test]
fn exact_replay_is_rejected() {
    let mut w = ReplayWindow::new();
    assert!(accepts(&mut w, 10));
    assert!(accepts(&mut w, 11));
    assert!(!accepts(&mut w, 11), "replay of 11 must be rejected");
    assert!(!accepts(&mut w, 10), "replay of an in-window seq must be rejected");
}

#[test]
fn benign_reordering_within_window_is_accepted_once() {
    let mut w = ReplayWindow::new();
    assert!(accepts(&mut w, 100));
    // Out-of-order but within the 64-wide window and unseen: accepted.
    assert!(accepts(&mut w, 95));
    assert!(accepts(&mut w, 98));
    assert!(accepts(&mut w, 60)); // 100-60 = 40 < 64
                                  // ...but a second copy of any of them is a replay.
    assert!(!accepts(&mut w, 95));
    assert!(!accepts(&mut w, 98));
}

#[test]
fn stale_sequence_outside_window_is_rejected() {
    let mut w = ReplayWindow::new();
    assert!(accepts(&mut w, 100));
    assert!(!accepts(&mut w, 36), "100-36 = 64 == WINDOW -> stale, rejected");
    assert!(accepts(&mut w, 37), "100-37 = 63 < WINDOW -> still inside, accepted");
}

#[test]
fn token_change_resets_the_window() {
    let mut w = ReplayWindow::new();
    assert!(accepts(&mut w, 5000));
    // New SecurityTokenId => key/epoch rotation => sequence restarts at 1, window resets.
    assert!(w.check(2, 1).is_ok(), "after token change seq 1 must be accepted");
    // And the old high value under the new token is now just a normal fresh start point.
    assert!(w.check(2, 2).is_ok());
}

#[test]
fn sequence_wraparound_is_handled() {
    let mut w = ReplayWindow::new();
    for seq in [65530u16, 65531, 65532, 65533, 65534, 65535, 0, 1, 2] {
        assert!(accepts(&mut w, seq), "wrap seq {seq} must be accepted in order");
    }
    // A value from just before the wrap is now within the window and already seen -> replay.
    assert!(!accepts(&mut w, 65534), "post-wrap replay of 65534 must be rejected");
}

fn sample(seq: u16) -> UadpNetworkMessage {
    UadpNetworkMessage {
        publisher_id: PublisherId::None,
        writer_group_id: 1,
        network_message_number: 0,
        sequence_number: seq,
        dataset_messages: vec![UadpDataSetMessage {
            dataset_writer_id: 10,
            sequence_number: seq,
            timestamp: None,
            status: None,
            fields: vec![opcua_types::Variant::from(1.0f64)],
        }],
    }
}

// End-to-end: the engine rejects a replayed secured NetworkMessage.
#[test]
fn engine_rejects_replayed_network_message() {
    let ctx_owned = ContextOwned::default();
    let ctx = ctx_owned.context();
    let mut engine = PubSubEngine::new(address_space());
    let group = SecurityGroup::new("line-a", Duration::from_secs(3600)).unwrap();
    engine.register_security_group(group);

    let mode = MessageSecurityMode::SignAndEncrypt;
    let policy = SecurityPolicy::PubSubAes256Ctr;

    let m1 = engine.encode_publisher_uadp_message("line-a", mode, policy, &sample(1), &ctx).unwrap();
    let m2 = engine.encode_publisher_uadp_message("line-a", mode, policy, &sample(2), &ctx).unwrap();

    assert!(engine.decode_subscriber_uadp_message("line-a", mode, policy, &m1, &ctx).is_ok());
    assert!(engine.decode_subscriber_uadp_message("line-a", mode, policy, &m2, &ctx).is_ok());

    // Replaying m1 (sequence 1, already accepted) must be rejected.
    let err = engine
        .decode_subscriber_uadp_message("line-a", mode, policy, &m1, &ctx)
        .unwrap_err();
    assert_eq!(err, StatusCode::BadSecurityChecksFailed);
}
