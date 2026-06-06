mod node_manager;
mod tester;

pub const CLIENT_USERPASS_ID: &str = "sample1";
pub const CLIENT_X509_ID: &str = "x509";

pub use node_manager::*;
use opcua::types::{AttributeId, DataValue, NodeId, ReadValueId, Variant};
use opcua_client::OnSubscriptionNotification;
pub use tester::*;
use tokio::sync::mpsc::UnboundedReceiver;

#[allow(unused)]
pub fn read_value_id(attribute: AttributeId, id: impl Into<NodeId>) -> ReadValueId {
    let node_id = id.into();
    ReadValueId {
        node_id,
        attribute_id: attribute as u32,
        ..Default::default()
    }
}

#[allow(unused)]
pub fn read_value_ids(attributes: &[AttributeId], id: impl Into<NodeId>) -> Vec<ReadValueId> {
    let node_id = id.into();
    attributes
        .iter()
        .map(|a| read_value_id(*a, &node_id))
        .collect()
}

#[allow(unused)]
pub fn array_value(v: &DataValue) -> &Vec<Variant> {
    let v = match v.value.as_ref().unwrap() {
        Variant::Array(a) => a,
        _ => panic!("Expected array"),
    };
    &v.values
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
