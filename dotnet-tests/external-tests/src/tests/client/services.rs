use std::{collections::HashMap, sync::Arc, time::Duration};

use opcua::{
    client::{OnSubscriptionNotification, Session},
    types::{
        AttributeId, BrowseDescription, BrowseResultMask, CallMethodRequest, DataValue,
        EUInformation, MonitoredItemCreateRequest, MonitoringParameters, NodeClass, NodeId,
        QualifiedName, ReadValueId, ReferenceTypeId, StatusCode, TimestampsToReturn,
        VariableTypeId, Variant,
    },
};
use tokio::{sync::mpsc::UnboundedReceiver, time::timeout};

use crate::client::ClientTestState;

pub async fn test_read(session: Arc<Session>, _ctx: &mut ClientTestState) {
    let r = session
        .read(
            &[
                ReadValueId::new_value(NodeId::new(2, "VarDouble")),
                ReadValueId::new_value(NodeId::new(2, "VarString")),
                ReadValueId::new_value(NodeId::new(2, "VarEuInfo")),
            ],
            opcua::types::TimestampsToReturn::Both,
            0.0,
        )
        .await
        .unwrap();
    assert_eq!(3, r.len());
    assert_eq!(
        r[0].value.clone().unwrap().try_cast_to::<f64>().unwrap(),
        0.0f64
    );
    assert_eq!(
        r[1].value.clone().unwrap().try_cast_to::<String>().unwrap(),
        "test 0"
    );
    assert_eq!(
        r[2].value
            .clone()
            .unwrap()
            .try_cast_to::<EUInformation>()
            .unwrap(),
        EUInformation {
            namespace_uri: "opc.tcp://test.localhost".into(),
            unit_id: 0,
            display_name: "Degrees C".into(),
            description: "Temperature degrees Celsius".into()
        }
    );
}

pub async fn test_browse(session: Arc<Session>, _ctx: &mut ClientTestState) {
    let r = session
        .browse(
            &[BrowseDescription {
                node_id: NodeId::new(2, "CoreBase"),
                browse_direction: opcua::types::BrowseDirection::Forward,
                reference_type_id: ReferenceTypeId::HierarchicalReferences.into(),
                include_subtypes: true,
                node_class_mask: 0,
                result_mask: BrowseResultMask::All as u32,
            }],
            100,
            None,
        )
        .await
        .unwrap();

    assert_eq!(1, r.len());
    let refs = r.into_iter().next().unwrap().references.unwrap();
    assert_eq!(4, refs.len());
    let mut by_id: HashMap<_, _> = refs
        .into_iter()
        .map(|r| (r.node_id.node_id.clone(), r))
        .collect();

    let n = by_id.remove(&NodeId::new(2, "VarDouble")).unwrap();
    assert_eq!(n.browse_name, QualifiedName::new(2, "VarDouble"));
    assert_eq!(n.display_name, "VarDouble".into());
    assert_eq!(n.reference_type_id, ReferenceTypeId::HasComponent);
    assert!(n.is_forward);
    assert_eq!(
        n.type_definition.node_id,
        VariableTypeId::BaseDataVariableType
    );
    assert_eq!(n.node_class, NodeClass::Variable);

    let n = by_id.remove(&NodeId::new(2, "VarString")).unwrap();
    assert_eq!(n.browse_name, QualifiedName::new(2, "VarString"));
    assert_eq!(n.display_name, "VarString".into());
    assert_eq!(n.reference_type_id, ReferenceTypeId::HasComponent);
    assert!(n.is_forward);
    assert_eq!(
        n.type_definition.node_id,
        VariableTypeId::BaseDataVariableType
    );
    assert_eq!(n.node_class, NodeClass::Variable);

    let n = by_id.remove(&NodeId::new(2, "VarEuInfo")).unwrap();
    assert_eq!(n.browse_name, QualifiedName::new(2, "VarEuInfo"));
    assert_eq!(n.display_name, "VarEuInfo".into());
    assert_eq!(n.reference_type_id, ReferenceTypeId::HasComponent);
    assert!(n.is_forward);
    assert_eq!(n.type_definition.node_id, VariableTypeId::PropertyType);
    assert_eq!(n.node_class, NodeClass::Variable);

    let n = by_id.remove(&NodeId::new(2, "EchoMethod")).unwrap();
    assert_eq!(n.browse_name, QualifiedName::new(2, "EchoMethod"));
    assert_eq!(n.display_name, "EchoMethod".into());
    assert_eq!(n.reference_type_id, ReferenceTypeId::HasComponent);
    assert!(n.is_forward);
    assert_eq!(n.node_class, NodeClass::Method);
}

pub async fn test_call(session: Arc<Session>, _ctx: &mut ClientTestState) {
    let r = session
        .call_one(CallMethodRequest {
            object_id: NodeId::new(2, "CoreBase"),
            method_id: NodeId::new(2, "EchoMethod"),
            input_arguments: Some(vec!["Hello there".into()]),
        })
        .await
        .unwrap();

    assert!(r.status_code.is_good());
    let out = r.output_arguments.unwrap();
    assert_eq!(1, out.len());
    assert_eq!(
        out[0].clone().try_cast_to::<String>().unwrap(),
        "Echo: Hello there"
    );
}

pub async fn test_big_request(session: Arc<Session>, _ctx: &mut ClientTestState) {
    let items: Vec<_> = (0..1000)
        .map(|n| ReadValueId::new_value(NodeId::new(2, format!("{n}{}", "c".repeat(100)))))
        .collect();

    let r = session
        .read(&items, opcua::types::TimestampsToReturn::Both, 0.0)
        .await
        .unwrap();

    for n in r {
        assert_eq!(n.status, Some(StatusCode::BadNodeIdUnknown));
    }
}

#[derive(Clone)]
pub struct ChannelNotifications {
    data_values: tokio::sync::mpsc::UnboundedSender<(ReadValueId, DataValue)>,
    events: tokio::sync::mpsc::UnboundedSender<(ReadValueId, Option<Vec<Variant>>)>,
}

impl ChannelNotifications {
    #[allow(clippy::type_complexity)]
    pub fn new() -> (
        Self,
        UnboundedReceiver<(ReadValueId, DataValue)>,
        UnboundedReceiver<(ReadValueId, Option<Vec<Variant>>)>,
    ) {
        let (data_values, data_recv) = tokio::sync::mpsc::unbounded_channel();
        let (events, events_recv) = tokio::sync::mpsc::unbounded_channel();
        (
            Self {
                data_values,
                events,
            },
            data_recv,
            events_recv,
        )
    }
}

impl OnSubscriptionNotification for ChannelNotifications {
    fn on_data_value(&mut self, notification: DataValue, item: &opcua::client::MonitoredItem) {
        let _ = self
            .data_values
            .send((item.item_to_monitor().clone(), notification));
    }

    fn on_event(
        &mut self,
        event_fields: Option<Vec<Variant>>,
        item: &opcua::client::MonitoredItem,
    ) {
        let _ = self
            .events
            .send((item.item_to_monitor().clone(), event_fields));
    }
}

pub async fn test_subscriptions(session: Arc<Session>, ctx: &mut ClientTestState) {
    let (notifs, mut data, _) = ChannelNotifications::new();

    let sub_id = session
        .create_subscription(Duration::from_millis(100), 100, 100, 1000, 0, true, notifs)
        .await
        .unwrap();

    // Create a monitored item on that subscription
    let res = session
        .create_monitored_items(
            sub_id,
            TimestampsToReturn::Both,
            vec![MonitoredItemCreateRequest {
                item_to_monitor: ReadValueId {
                    node_id: NodeId::new(2, "VarDouble"),
                    attribute_id: AttributeId::Value as u32,
                    ..Default::default()
                },
                monitoring_mode: opcua::types::MonitoringMode::Reporting,
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

    assert_eq!(res.len(), 1);
    let it = &res[0];
    assert_eq!(it.result.status_code, StatusCode::Good);

    // We should quickly get a data value, this is due to the initial queued publish request.
    let (_, v) = timeout(Duration::from_millis(2000), data.recv())
        .await
        .unwrap()
        .unwrap();
    let val = match v.value {
        Some(Variant::Double(v)) => v,
        _ => panic!("Expected double value"),
    };
    assert_eq!(0.0, val);

    ctx.send_change_message(&session, NodeId::new(2, "VarDouble"), 1.0.into())
        .await;

    // We should get a new update
    let (_, v) = timeout(Duration::from_millis(2000), data.recv())
        .await
        .unwrap()
        .unwrap();
    let val = match v.value {
        Some(Variant::Double(v)) => v,
        _ => panic!("Expected double value"),
    };
    assert_eq!(1.0, val);

    // Reset the value on the server before stopping
    ctx.send_change_message(&session, NodeId::new(2, "VarDouble"), 0.0.into())
        .await;
}
