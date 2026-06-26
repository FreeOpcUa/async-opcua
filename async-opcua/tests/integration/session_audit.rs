use std::time::Duration;

use crate::utils::{setup, ChannelNotifications};
use opcua::{
    crypto::SecurityPolicy,
    types::{
        AttributeId, EventFilter, ExtensionObject, MessageSecurityMode, MonitoredItemCreateRequest,
        MonitoringMode, MonitoringParameters, NodeId, NumericRange, ObjectId, QualifiedName,
        ReadValueId, SimpleAttributeOperand, StatusCode, TimestampsToReturn, Variant,
    },
};
use opcua_client::IdentityToken;

/// Part 4/3 auditing: opening a session emits an AuditCreateSessionEventType (i=2071) and an
/// AuditActivateSessionEventType (i=2075) from the Server node.
#[tokio::test]
async fn session_lifecycle_emits_audit_events() {
    let (mut tester, _nm, session) = setup().await;

    // Subscribe the existing session to Server events before opening the audited session.
    let (notifs, _, mut events) = ChannelNotifications::new();
    let sub_id = session
        .create_subscription(Duration::from_millis(100), 100, 20, 1000, 0, true, notifs)
        .await
        .unwrap();
    let select = vec![SimpleAttributeOperand {
        type_definition_id: NodeId::new(0, 2041), // BaseEventType
        browse_path: Some(vec![QualifiedName::new(0, "EventType")]),
        attribute_id: AttributeId::Value as u32,
        index_range: NumericRange::None,
    }];
    let res = session
        .create_monitored_items(
            sub_id,
            TimestampsToReturn::Both,
            vec![MonitoredItemCreateRequest {
                item_to_monitor: ReadValueId {
                    node_id: ObjectId::Server.into(),
                    attribute_id: AttributeId::EventNotifier as u32,
                    ..Default::default()
                },
                monitoring_mode: MonitoringMode::Reporting,
                requested_parameters: MonitoringParameters {
                    sampling_interval: 0.0,
                    queue_size: 10,
                    discard_oldest: true,
                    filter: ExtensionObject::new(EventFilter {
                        select_clauses: Some(select),
                        where_clause: Default::default(),
                    }),
                    ..Default::default()
                },
            }],
        )
        .await
        .unwrap();
    assert_eq!(res[0].result.status_code, StatusCode::Good);

    // A second session: its CreateSession + ActivateSession should be audited.
    let _audited = tester
        .connect_and_wait(
            SecurityPolicy::None,
            MessageSecurityMode::None,
            IdentityToken::Anonymous,
        )
        .await
        .unwrap();

    let create_type = Variant::from(NodeId::new(0, 2071)); // AuditCreateSessionEventType
    let activate_type = Variant::from(NodeId::new(0, 2075)); // AuditActivateSessionEventType
    let mut saw_create = false;
    let mut saw_activate = false;
    for _ in 0..10 {
        if saw_create && saw_activate {
            break;
        }
        let Ok(Some((_h, v))) = tokio::time::timeout(Duration::from_secs(3), events.recv()).await
        else {
            break;
        };
        let fields = v.unwrap();
        if fields[0] == create_type {
            saw_create = true;
        } else if fields[0] == activate_type {
            saw_activate = true;
        }
    }
    assert!(
        saw_create,
        "an AuditCreateSessionEventType must be delivered when a session is created"
    );
    assert!(
        saw_activate,
        "an AuditActivateSessionEventType must be delivered when a session is activated"
    );
}

/// Part 4 §A.5: a Cancel request emits an AuditCancelEventType (i=2078) carrying the RequestHandle.
#[tokio::test]
async fn cancel_emits_audit_event() {
    let (_tester, _nm, session) = setup().await;

    let (notifs, _, mut events) = ChannelNotifications::new();
    let sub_id = session
        .create_subscription(Duration::from_millis(100), 100, 20, 1000, 0, true, notifs)
        .await
        .unwrap();
    let select = vec![
        SimpleAttributeOperand {
            type_definition_id: NodeId::new(0, 2041), // BaseEventType
            browse_path: Some(vec![QualifiedName::new(0, "EventType")]),
            attribute_id: AttributeId::Value as u32,
            index_range: NumericRange::None,
        },
        SimpleAttributeOperand {
            type_definition_id: NodeId::new(0, 2078), // AuditCancelEventType
            browse_path: Some(vec![QualifiedName::new(0, "RequestHandle")]),
            attribute_id: AttributeId::Value as u32,
            index_range: NumericRange::None,
        },
    ];
    let res = session
        .create_monitored_items(
            sub_id,
            TimestampsToReturn::Both,
            vec![MonitoredItemCreateRequest {
                item_to_monitor: ReadValueId {
                    node_id: ObjectId::Server.into(),
                    attribute_id: AttributeId::EventNotifier as u32,
                    ..Default::default()
                },
                monitoring_mode: MonitoringMode::Reporting,
                requested_parameters: MonitoringParameters {
                    sampling_interval: 0.0,
                    queue_size: 10,
                    discard_oldest: true,
                    filter: ExtensionObject::new(EventFilter {
                        select_clauses: Some(select),
                        where_clause: Default::default(),
                    }),
                    ..Default::default()
                },
            }],
        )
        .await
        .unwrap();
    assert_eq!(res[0].result.status_code, StatusCode::Good);

    // Cancel is a no-op here (no cancellable queue) but is still audited.
    let cancel_count = session.cancel(4242).await.unwrap();
    assert_eq!(cancel_count, 0);

    let cancel_type = Variant::from(NodeId::new(0, 2078));
    let mut found = false;
    for _ in 0..5 {
        let Ok(Some((_h, v))) = tokio::time::timeout(Duration::from_secs(3), events.recv()).await
        else {
            break;
        };
        let fields = v.unwrap();
        if fields[0] == cancel_type {
            assert_eq!(
                fields[1],
                Variant::UInt32(4242),
                "AuditCancelEventType must carry the cancelled RequestHandle"
            );
            found = true;
            break;
        }
    }
    assert!(
        found,
        "an AuditCancelEventType must be delivered after a Cancel request"
    );
}
