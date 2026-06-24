//! Tier A lock-in tests from the multi-AI test-coverage cross-check
//! (`specs/multi-ai-test-suites/UNIFIED-PROTOCOL.md`).
//!
//! Each of the four Tier-A items was a *potential* real bug proposed by an independent reviewer
//! (Antigravity / Codex). We probed the server code first; these tests lock in the behaviour found:
//!
//! * A2 — MonitoredItem on a node that is then DeleteNodes'd: the server stays up and keeps serving
//!   (the sampler paths return graceful status, they do not `unwrap()` a missing node).
//! * A3 — circular hierarchical references + a long TranslateBrowsePaths path: the translate loop is
//!   *iterative* (bounded by the requested path length), not recursive, so a cycle cannot overflow
//!   the stack. This pins that — a regression to recursive traversal would hang/panic here.
//! * A4 — UserName identity token with an EMPTY password must be rejected (fail-closed), distinct
//!   from the wrong-but-non-empty password already covered by `conformance_smoke_rejects_bad_password`.
//!
//! A1 (PercentDeadband caches EURange at create-time and never refreshes it) was CONFIRMED real but
//! is a deliberate caching choice, not a crash/security issue — documented at the `eu_range` field in
//! `subscriptions/monitored_item.rs` rather than locked in here (live re-read would be a redesign).

use std::time::Duration;

use super::utils::{setup, test_server, ChannelNotifications, Tester, CLIENT_USERPASS_ID};
use opcua::{
    server::address_space::{AccessLevel, ReferenceDirection, VariableBuilder},
    types::{
        AttributeId, DeleteNodesItem, MessageSecurityMode, MonitoredItemCreateRequest,
        MonitoringMode, MonitoringParameters, ObjectId, ReadValueId, ReferenceTypeId, RelativePath,
        RelativePathElement, StatusCode, TimestampsToReturn, VariableTypeId,
    },
};
use opcua_client::IdentityToken;
use opcua_crypto::SecurityPolicy;
use opcua_types::{BrowsePath, DataTypeId};
use tokio::time::timeout;

/// A2: a node under a live MonitoredItem is deleted via DeleteNodes — the server must survive and keep
/// serving (no panic from sampling/reading a now-missing node).
#[tokio::test]
async fn delete_node_under_live_monitored_item_keeps_server_alive() {
    let (tester, nm, session) = setup().await;

    // A monitored variable.
    let id = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        VariableBuilder::new(&id, "DoomedVar", "DoomedVar")
            .value(1i32)
            .data_type(DataTypeId::Int32)
            .access_level(AccessLevel::CURRENT_READ)
            .user_access_level(AccessLevel::CURRENT_READ)
            .build()
            .into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        Some(&VariableTypeId::BaseDataVariableType.into()),
        Vec::new(),
    );

    let (notifs, mut data, _) = ChannelNotifications::new();
    let sub_id = session
        .create_subscription(Duration::from_millis(50), 100, 20, 1000, 0, true, notifs)
        .await
        .unwrap();
    let res = session
        .create_monitored_items(
            sub_id,
            TimestampsToReturn::Both,
            vec![MonitoredItemCreateRequest {
                item_to_monitor: ReadValueId {
                    node_id: id.clone(),
                    attribute_id: AttributeId::Value as u32,
                    ..Default::default()
                },
                monitoring_mode: MonitoringMode::Reporting,
                requested_parameters: MonitoringParameters {
                    sampling_interval: 0.0,
                    queue_size: 10,
                    discard_oldest: true,
                    ..Default::default()
                },
            }],
        )
        .await
        .unwrap();
    assert_eq!(res[0].result.status_code, StatusCode::Good);

    // Drain the initial publish so we know the item is live.
    let _ = timeout(Duration::from_secs(2), data.recv()).await;

    // Delete the monitored node out from under the subscription.
    let dr = session
        .delete_nodes(&[DeleteNodesItem {
            node_id: id.clone(),
            delete_target_references: true,
        }])
        .await
        .unwrap();
    assert_eq!(dr, vec![StatusCode::Good]);

    // Give the subscription a few cycles to sample the now-missing node.
    tokio::time::sleep(Duration::from_millis(250)).await;

    // The server must still be serving: a read on a live node returns Good, and the deleted node is
    // gone (not a panic, not a hang).
    let vals = session
        .read(
            &[ReadValueId {
                node_id: ObjectId::Server.into(),
                attribute_id: AttributeId::NodeId as u32,
                ..Default::default()
            }],
            TimestampsToReturn::Neither,
            0.0,
        )
        .await
        .expect("server must still answer reads after deleting a monitored node");
    assert_eq!(vals[0].status(), StatusCode::Good);

    let gone = session
        .read(
            &[ReadValueId {
                node_id: id.clone(),
                attribute_id: AttributeId::Value as u32,
                ..Default::default()
            }],
            TimestampsToReturn::Neither,
            0.0,
        )
        .await
        .unwrap();
    assert_ne!(
        gone[0].status(),
        StatusCode::Good,
        "deleted node must no longer read Good"
    );
}

/// A3: a circular hierarchical reference (A -> B -> A) plus a long repeated TranslateBrowsePaths path
/// must NOT overflow the stack or hang — the traversal is iterative and bounded by the path length.
#[tokio::test]
async fn translate_browse_paths_over_a_reference_cycle_terminates() {
    let (tester, nm, session) = setup().await;

    let a = nm.inner().next_node_id();
    let b = nm.inner().next_node_id();
    // A organized under ObjectsFolder, B under A.
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        opcua::server::address_space::ObjectBuilder::new(&a, "CycleA", "CycleA")
            .build()
            .into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        Some(&opcua::types::ObjectTypeId::BaseObjectType.into()),
        Vec::new(),
    );
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        opcua::server::address_space::ObjectBuilder::new(&b, "CycleB", "CycleB")
            .build()
            .into(),
        &a,
        &ReferenceTypeId::Organizes.into(),
        Some(&opcua::types::ObjectTypeId::BaseObjectType.into()),
        Vec::new(),
    );
    // Close the cycle: B -> Organizes -> A.
    nm.inner().add_references(
        nm.address_space(),
        &b,
        vec![(
            &a,
            ReferenceTypeId::Organizes.into(),
            ReferenceDirection::Forward,
        )],
    );

    // Walk CycleA/CycleB/CycleA/CycleB/... many times. A recursive traversal without cycle detection
    // would blow the stack here; the iterative one terminates with a (non-)match.
    let elements: Vec<RelativePathElement> = (0..256)
        .map(|i| RelativePathElement {
            reference_type_id: ReferenceTypeId::HierarchicalReferences.into(),
            is_inverse: false,
            include_subtypes: true,
            target_name: if i % 2 == 0 { "CycleB" } else { "CycleA" }.into(),
        })
        .collect();

    let r = timeout(
        Duration::from_secs(10),
        session.translate_browse_paths_to_node_ids(&[BrowsePath {
            starting_node: a.clone(),
            relative_path: RelativePath {
                elements: Some(elements),
            },
        }]),
    )
    .await
    .expect("translate over a reference cycle must terminate, not hang")
    .expect("translate call itself must return");
    assert_eq!(r.len(), 1);
    // We don't assert a particular status — only that the server answered and is still alive below.

    let vals = session
        .read(
            &[ReadValueId {
                node_id: ObjectId::Server.into(),
                attribute_id: AttributeId::NodeId as u32,
                ..Default::default()
            }],
            TimestampsToReturn::Neither,
            0.0,
        )
        .await
        .expect("server must still serve after a cyclic translate");
    assert_eq!(vals[0].status(), StatusCode::Good);
}

/// A4: a UserName identity token with an EMPTY password must be rejected — the user has a password set,
/// so an empty one must fail closed (distinct edge from the wrong-non-empty-password case).
#[tokio::test]
async fn empty_password_username_token_is_rejected() {
    let mut tester = Tester::new(test_server(), false).await;
    let token = IdentityToken::UserName(CLIENT_USERPASS_ID.to_owned(), "".into());

    let result = tester
        .connect(
            SecurityPolicy::Basic256Sha256,
            MessageSecurityMode::SignAndEncrypt,
            token,
        )
        .await;

    match result {
        Err(_) => {} // rejected at connect — fine
        Ok((session, handle)) => {
            let _h = handle.spawn();
            assert!(
                timeout(Duration::from_secs(3), session.wait_for_connection())
                    .await
                    .is_err(),
                "an empty password must not yield a connected session"
            );
        }
    }
    // keep `tester` alive until the assertion
    let _ = &tester;
}
