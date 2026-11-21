use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use opcua::{
    server::{
        node_manager::{MonitoredItemRef, NodeManager, RequestContext, ServerContext},
        CreateMonitoredItem, SubscriptionCache,
    },
    sync::Mutex,
    types::{
        AttributeId, DataValue, MonitoredItemCreateRequest, MonitoringMode, MonitoringParameters,
        NodeId, ReadValueId, StatusCode, TimestampsToReturn, Variant,
    },
};
use opcua_nodes::DefaultTypeTree;
use opcua_server::diagnostics::NamespaceMetadata;
use tokio::time::timeout;

use crate::utils::{default_server, ChannelNotifications, Tester};

const NAMESPACE: &str = "urn:monitoreditemsregistered";
const EARLY_VALUE: i32 = 7;
const REPLAYED_VALUE: i32 = 42;

/// A node manager that notifies a value from `create_monitored_items`, before the
/// server has registered the item, and a newer one from `monitored_items_registered`.
struct ReplayingNodeManager {
    namespace_index: u16,
    subscriptions: Arc<SubscriptionCache>,
    registered: Mutex<Vec<NodeId>>,
}

impl ReplayingNodeManager {
    fn accepted_node(&self) -> NodeId {
        NodeId::new(self.namespace_index, "accepted")
    }

    fn rejected_node(&self) -> NodeId {
        NodeId::new(self.namespace_index, "rejected")
    }

    fn notify(&self, node: &NodeId, value: i32) {
        self.subscriptions.notify_data_change(
            [(
                DataValue::new_now(Variant::Int32(value)),
                node,
                AttributeId::Value,
            )]
            .into_iter(),
        );
    }
}

#[async_trait]
impl NodeManager for ReplayingNodeManager {
    fn owns_node(&self, id: &NodeId) -> bool {
        id.namespace == self.namespace_index
    }

    fn name(&self) -> &str {
        "replaying"
    }

    fn namespaces_for_user(&self, _context: &RequestContext) -> Vec<NamespaceMetadata> {
        vec![NamespaceMetadata {
            namespace_uri: NAMESPACE.to_owned(),
            namespace_index: self.namespace_index,
            ..Default::default()
        }]
    }

    async fn init(&self, _type_tree: &mut DefaultTypeTree, _context: ServerContext) {}

    async fn create_monitored_items(
        &self,
        _context: &RequestContext,
        items: &mut [&mut CreateMonitoredItem],
    ) -> Result<(), StatusCode> {
        for item in items.iter_mut() {
            let node = item.item_to_monitor().node_id.clone();
            if node == self.accepted_node() {
                item.set_status(StatusCode::Good);
                self.notify(&node, EARLY_VALUE);
            } else {
                item.set_status(StatusCode::BadNodeIdUnknown);
            }
        }
        Ok(())
    }

    async fn monitored_items_registered(
        &self,
        _context: &RequestContext,
        items: &[&MonitoredItemRef],
    ) {
        let mut registered = self.registered.lock();
        for item in items {
            registered.push(item.node_id().clone());
            self.notify(item.node_id(), REPLAYED_VALUE);
        }
    }
}

fn value_item(node_id: NodeId, client_handle: u32) -> MonitoredItemCreateRequest {
    MonitoredItemCreateRequest {
        item_to_monitor: ReadValueId {
            node_id,
            attribute_id: AttributeId::Value as u32,
            ..Default::default()
        },
        monitoring_mode: MonitoringMode::Reporting,
        requested_parameters: MonitoringParameters {
            client_handle,
            sampling_interval: 0.0,
            queue_size: 10,
            discard_oldest: true,
            ..Default::default()
        },
    }
}

#[tokio::test]
async fn value_notified_from_registered_hook_reaches_new_item() {
    let server = default_server().with_node_manager(|context: ServerContext| {
        let namespace_index = context
            .type_tree
            .write()
            .namespaces_mut()
            .add_namespace(NAMESPACE);
        ReplayingNodeManager {
            namespace_index,
            subscriptions: context.subscriptions.clone(),
            registered: Mutex::new(Vec::new()),
        }
    });
    let mut tester = Tester::new(server, false).await;
    let nm = tester
        .handle
        .node_managers()
        .get_of_type::<ReplayingNodeManager>()
        .unwrap();
    let (session, lp) = tester.connect_default().await.unwrap();
    lp.spawn();
    timeout(Duration::from_secs(2), session.wait_for_connection())
        .await
        .unwrap();

    let (notifs, mut data, _) = ChannelNotifications::new();
    let sub_id = session
        .create_subscription(Duration::from_millis(100), 100, 20, 1000, 0, true, notifs)
        .await
        .unwrap();

    let res = session
        .create_monitored_items(
            sub_id,
            TimestampsToReturn::Both,
            vec![
                value_item(nm.accepted_node(), 1),
                value_item(nm.rejected_node(), 2),
            ],
        )
        .await
        .unwrap();
    assert_eq!(res[0].result.status_code, StatusCode::Good);
    assert_eq!(res[1].result.status_code, StatusCode::BadNodeIdUnknown);

    // The hook ran before the response, with the registered item only.
    assert_eq!(*nm.registered.lock(), vec![nm.accepted_node()]);

    let mut received = Vec::new();
    let replayed = timeout(Duration::from_secs(2), async {
        while let Some((read_id, dv)) = data.recv().await {
            received.push(dv.value.clone());
            if read_id.node_id == nm.accepted_node()
                && dv.value == Some(Variant::Int32(REPLAYED_VALUE))
            {
                return;
            }
        }
    })
    .await;
    assert!(
        replayed.is_ok(),
        "the value notified from monitored_items_registered never reached the item; received {received:?}"
    );
    assert!(
        !received.contains(&Some(Variant::Int32(EARLY_VALUE))),
        "a value notified before registration reached the item; received {received:?}"
    );
}
