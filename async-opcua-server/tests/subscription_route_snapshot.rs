//! OPC-10000-4 5.13.2.1 requires CreateMonitoredItems to create monitored
//! items for an existing subscription. Any route snapshot/index follow-up must
//! preserve creation of the subscription route used by later notifications.

#![allow(missing_docs)]

use std::{path::PathBuf, sync::mpsc, sync::Arc, time::Duration};

use opcua_client::{ClientBuilder, DataChangeCallback, IdentityToken, MonitoredItem, Session};
use opcua_crypto::SecurityPolicy;
use opcua_server::{ServerBuilder, ServerHandle, ANONYMOUS_USER_TOKEN_ID};
use opcua_types::{
    ExtensionObject, MessageSecurityMode, MonitoredItemCreateRequest, MonitoredItemModifyRequest,
    MonitoringMode, MonitoringParameters, NodeId, ReadValueId, StatusCode, TimestampsToReturn,
    VariableId,
};
use tokio::{net::TcpListener, task::JoinHandle};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subscription_route_snapshot_create_monitored_item_preserves_part4_5_13_2_1() {
    tokio::time::timeout(TEST_TIMEOUT, run_create_monitored_item_route_probe())
        .await
        .expect("subscription route create monitored item probe should not hang");
}

async fn run_create_monitored_item_route_probe() {
    let server = RouteSnapshotServer::start("subscription-route-snapshot-create").await;
    let subscription_id = server
        .session
        .create_subscription(
            Duration::from_millis(100),
            30,
            10,
            0,
            0,
            true,
            DataChangeCallback::new(|_, _: &MonitoredItem| {}),
        )
        .await
        .expect("subscription should be created");

    let create_results = server
        .session
        .create_monitored_items(
            subscription_id,
            TimestampsToReturn::Both,
            vec![current_time_monitored_item()],
        )
        .await
        .expect("CreateMonitoredItems should complete");

    assert_eq!(create_results.len(), 1);
    assert_eq!(create_results[0].result.status_code, StatusCode::Good);
    assert_ne!(create_results[0].result.monitored_item_id, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subscription_route_snapshot_delete_monitored_item_preserves_part4_5_13_2_1() {
    tokio::time::timeout(TEST_TIMEOUT, run_delete_monitored_item_route_probe())
        .await
        .expect("subscription route delete monitored item probe should not hang");
}

async fn run_delete_monitored_item_route_probe() {
    let server = RouteSnapshotServer::start("subscription-route-snapshot-delete").await;
    let subscription_id = server
        .session
        .create_subscription(
            Duration::from_millis(100),
            30,
            10,
            0,
            0,
            true,
            DataChangeCallback::new(|_, _: &MonitoredItem| {}),
        )
        .await
        .expect("subscription should be created");

    let create_results = server
        .session
        .create_monitored_items(
            subscription_id,
            TimestampsToReturn::Both,
            vec![current_time_monitored_item()],
        )
        .await
        .expect("CreateMonitoredItems should complete");

    assert_eq!(create_results.len(), 1);
    assert_eq!(create_results[0].result.status_code, StatusCode::Good);
    let monitored_item_id = create_results[0].result.monitored_item_id;
    assert_ne!(monitored_item_id, 0);

    let delete_statuses = server
        .session
        .delete_monitored_items(subscription_id, &[monitored_item_id])
        .await
        .expect("DeleteMonitoredItems should complete");

    // OPC-10000-4 5.13.2.1 delete routing must remove the monitored-item route
    // cleanly without breaking the subscription route table.
    assert_eq!(delete_statuses.len(), 1);
    assert_eq!(delete_statuses[0], StatusCode::Good);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subscription_route_snapshot_modify_monitored_item_preserves_part4_5_13_3_1() {
    tokio::time::timeout(TEST_TIMEOUT, run_modify_monitored_item_route_probe())
        .await
        .expect("subscription route modify monitored item probe should not hang");
}

async fn run_modify_monitored_item_route_probe() {
    let server = RouteSnapshotServer::start("subscription-route-snapshot-modify").await;
    let subscription_id = server
        .session
        .create_subscription(
            Duration::from_millis(100),
            30,
            10,
            0,
            0,
            true,
            DataChangeCallback::new(|_, _: &MonitoredItem| {}),
        )
        .await
        .expect("subscription should be created");

    let create_results = server
        .session
        .create_monitored_items(
            subscription_id,
            TimestampsToReturn::Both,
            vec![current_time_monitored_item()],
        )
        .await
        .expect("CreateMonitoredItems should complete");

    assert_eq!(create_results.len(), 1);
    assert_eq!(create_results[0].result.status_code, StatusCode::Good);
    let monitored_item_id = create_results[0].result.monitored_item_id;
    assert_ne!(monitored_item_id, 0);

    let modify_results = server
        .session
        .modify_monitored_items(
            subscription_id,
            TimestampsToReturn::Both,
            &[MonitoredItemModifyRequest {
                monitored_item_id,
                requested_parameters: MonitoringParameters {
                    client_handle: 2,
                    sampling_interval: 75.0,
                    filter: ExtensionObject::null(),
                    queue_size: 2,
                    discard_oldest: false,
                },
            }],
        )
        .await
        .expect("ModifyMonitoredItems should complete");

    // OPC-10000-4 5.13.3.1 modify routing must refresh parameters while
    // preserving the same monitored item route for the subscription.
    assert_eq!(modify_results.len(), 1);
    assert_eq!(modify_results[0].status_code, StatusCode::Good);
    assert!(
        modify_results[0].revised_sampling_interval.is_finite()
            && modify_results[0].revised_sampling_interval >= 0.0,
        "OPC-10000-4 5.13.3.1 modify should return a sensible revised sampling interval"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subscription_route_snapshot_transfer_subscription_preserves_part4_6_7_route() {
    tokio::time::timeout(TEST_TIMEOUT, run_transfer_subscription_route_probe())
        .await
        .expect("subscription route transfer probe should not hang");
}

async fn run_transfer_subscription_route_probe() {
    let server = RouteSnapshotServer::start("subscription-route-snapshot-transfer").await;
    let subscription_id = server
        .session
        .create_subscription(
            Duration::from_millis(100),
            30,
            10,
            0,
            0,
            true,
            DataChangeCallback::new(|_, _: &MonitoredItem| {}),
        )
        .await
        .expect("subscription should be created");

    let create_results = server
        .session
        .create_monitored_items(
            subscription_id,
            TimestampsToReturn::Both,
            vec![current_time_monitored_item()],
        )
        .await
        .expect("CreateMonitoredItems should complete");

    assert_eq!(create_results.len(), 1);
    assert_eq!(create_results[0].result.status_code, StatusCode::Good);
    assert_ne!(create_results[0].result.monitored_item_id, 0);

    let (second_session, second_event_loop_task) = server
        .connect_session(
            "subscription_route_snapshot_transfer_client",
            "urn:async-opcua:subscription-route-snapshot-client",
            "transfer-client-pki",
            SecurityPolicy::Aes128Sha256RsaOaep,
            MessageSecurityMode::SignAndEncrypt,
        )
        .await;

    let transfer_results = second_session
        .transfer_subscriptions(&[subscription_id], false)
        .await
        .expect("TransferSubscriptions should complete");

    // OPC-10000-4 6.7 requires transfer to update ownership/routing without
    // losing the monitored-item route belonging to the transferred subscription.
    assert_eq!(transfer_results.len(), 1);
    assert_eq!(transfer_results[0].status_code, StatusCode::Good);

    second_event_loop_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subscription_route_snapshot_publish_notification_preserves_part4_5_14_1_2_route() {
    tokio::time::timeout(TEST_TIMEOUT, run_publish_notification_route_probe())
        .await
        .expect("subscription route publish notification probe should not hang");
}

async fn run_publish_notification_route_probe() {
    let server = RouteSnapshotServer::start("subscription-route-snapshot-publish").await;
    let (notification_tx, notification_rx) = mpsc::channel();
    let subscription_id = server
        .session
        .create_subscription(
            Duration::from_millis(100),
            30,
            10,
            0,
            0,
            true,
            DataChangeCallback::new(move |value, item: &MonitoredItem| {
                if item.item_to_monitor().node_id == current_time_node_id() {
                    let _ = notification_tx.send((item.id(), value.value.is_some()));
                }
            }),
        )
        .await
        .expect("subscription should be created");

    let create_results = server
        .session
        .create_monitored_items(
            subscription_id,
            TimestampsToReturn::Both,
            vec![current_time_monitored_item()],
        )
        .await
        .expect("CreateMonitoredItems should complete");

    assert_eq!(create_results.len(), 1);
    assert_eq!(create_results[0].result.status_code, StatusCode::Good);
    let monitored_item_id = create_results[0].result.monitored_item_id;
    assert_ne!(monitored_item_id, 0);

    server.session.trigger_publish_now();
    let (delivered_monitored_item_id, delivered_value) = notification_rx
        .recv_timeout(TEST_TIMEOUT)
        .expect("Publish should deliver a data-change notification for ServerStatus CurrentTime");

    // OPC-10000-4 5.14.1.2 requires Publish to route NotificationMessages for
    // the owning subscription without losing the monitored-item route created
    // before the Publish response is delivered.
    assert_eq!(delivered_monitored_item_id, monitored_item_id);
    assert!(
        delivered_value,
        "CurrentTime notification should include a value"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subscription_route_snapshot_republish_preserves_part4_5_14_1_2_route() {
    tokio::time::timeout(TEST_TIMEOUT, run_republish_route_probe())
        .await
        .expect("subscription route republish probe should not hang");
}

async fn run_republish_route_probe() {
    let server = RouteSnapshotServer::start("subscription-route-snapshot-republish").await;
    let subscription_id = server
        .session
        .create_subscription(
            Duration::from_millis(100),
            30,
            10,
            0,
            0,
            true,
            DataChangeCallback::new(|_, _: &MonitoredItem| {}),
        )
        .await
        .expect("subscription should be created");

    let create_results = server
        .session
        .create_monitored_items(
            subscription_id,
            TimestampsToReturn::Both,
            vec![current_time_monitored_item()],
        )
        .await
        .expect("CreateMonitoredItems should complete");

    assert_eq!(create_results.len(), 1);
    assert_eq!(create_results[0].result.status_code, StatusCode::Good);
    assert_ne!(create_results[0].result.monitored_item_id, 0);

    let unavailable_sequence_number = u32::MAX;
    let republish_error = server
        .session
        .republish(subscription_id, unavailable_sequence_number)
        .await
        .expect_err(
            "Republish of a deliberately unavailable sequence number should return a service error",
        );

    // OPC-10000-4 5.14.1.2 routes Republish by SubscriptionId. For a valid
    // subscription with no retained notification at the requested sequence,
    // the routed service result is Bad_MessageNotAvailable, not a lost-route
    // Bad_NoSubscription/Bad_SubscriptionIdInvalid failure.
    assert_eq!(republish_error.status(), StatusCode::BadMessageNotAvailable);
}

fn current_time_monitored_item() -> MonitoredItemCreateRequest {
    MonitoredItemCreateRequest::new(
        ReadValueId::from(current_time_node_id()),
        MonitoringMode::Reporting,
        MonitoringParameters {
            client_handle: 1,
            sampling_interval: 50.0,
            filter: ExtensionObject::null(),
            queue_size: 1,
            discard_oldest: true,
        },
    )
}

fn current_time_node_id() -> NodeId {
    <VariableId as Into<NodeId>>::into(VariableId::Server_ServerStatus_CurrentTime)
}

struct RouteSnapshotServer {
    handle: ServerHandle,
    session: Arc<Session>,
    endpoint: String,
    event_loop_task: JoinHandle<StatusCode>,
    server_task: JoinHandle<()>,
    _temp_dir: tempfile::TempDir,
}

impl RouteSnapshotServer {
    async fn start(test_name: &str) -> Self {
        let temp_dir = tempfile::Builder::new()
            .prefix(test_name)
            .tempdir()
            .expect("temporary route snapshot test dir should be created");
        let server_pki = temp_dir.path().join("server-pki");
        let client_pki = temp_dir.path().join("client-pki");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("route snapshot test listener should bind");
        let addr = listener
            .local_addr()
            .expect("route snapshot test listener should have an address");
        let endpoint = format!("opc.tcp://127.0.0.1:{}/", addr.port());

        let (server, handle) = ServerBuilder::new()
            .application_name("subscription_route_snapshot")
            .application_uri("urn:async-opcua:subscription-route-snapshot")
            .product_uri("urn:async-opcua:subscription-route-snapshot")
            .host("127.0.0.1")
            .pki_dir(PathBuf::from(&server_pki))
            .create_sample_keypair(true)
            .trust_client_certs(true)
            .discovery_urls(vec![endpoint.clone()])
            .add_endpoint(
                "none",
                (
                    "/",
                    SecurityPolicy::None,
                    MessageSecurityMode::None,
                    &[ANONYMOUS_USER_TOKEN_ID] as &[&str],
                ),
            )
            .add_endpoint(
                "secured",
                (
                    "/",
                    SecurityPolicy::Aes128Sha256RsaOaep,
                    MessageSecurityMode::SignAndEncrypt,
                    &[ANONYMOUS_USER_TOKEN_ID] as &[&str],
                ),
            )
            .build()
            .expect("route snapshot test server should build");
        let server_task = tokio::spawn(async move {
            server
                .run_with(listener)
                .await
                .expect("route snapshot test server should run");
        });

        let (session, event_loop_task) = Self::connect_session_to_endpoint(
            &endpoint,
            client_pki,
            "subscription_route_snapshot_client",
            "urn:async-opcua:subscription-route-snapshot-client",
            SecurityPolicy::None,
            MessageSecurityMode::None,
        )
        .await;

        Self {
            handle,
            session,
            endpoint,
            event_loop_task,
            server_task,
            _temp_dir: temp_dir,
        }
    }

    async fn connect_session(
        &self,
        application_name: &str,
        application_uri: &str,
        pki_dir_name: &str,
        security_policy: SecurityPolicy,
        security_mode: MessageSecurityMode,
    ) -> (Arc<Session>, JoinHandle<StatusCode>) {
        Self::connect_session_to_endpoint(
            &self.endpoint,
            self._temp_dir.path().join(pki_dir_name),
            application_name,
            application_uri,
            security_policy,
            security_mode,
        )
        .await
    }

    async fn connect_session_to_endpoint(
        endpoint: &str,
        pki_dir: PathBuf,
        application_name: &str,
        application_uri: &str,
        security_policy: SecurityPolicy,
        security_mode: MessageSecurityMode,
    ) -> (Arc<Session>, JoinHandle<StatusCode>) {
        let mut client = ClientBuilder::new()
            .application_name(application_name)
            .application_uri(application_uri)
            .product_uri(application_uri)
            .pki_dir(pki_dir)
            .create_sample_keypair(true)
            .trust_server_certs(true)
            .session_retry_initial(Duration::from_millis(100))
            .client()
            .expect("route snapshot test client should build");

        let (session, event_loop) = client
            .connect_to_matching_endpoint(
                (endpoint, security_policy.to_str(), security_mode),
                IdentityToken::Anonymous,
            )
            .await
            .expect("route snapshot test client should connect");
        let event_loop_task = event_loop.spawn();

        tokio::time::timeout(Duration::from_secs(5), session.wait_for_connection())
            .await
            .expect("route snapshot test client should become connected");

        (session, event_loop_task)
    }
}

impl Drop for RouteSnapshotServer {
    fn drop(&mut self) {
        self.handle.cancel();
        self.event_loop_task.abort();
        self.server_task.abort();
    }
}
