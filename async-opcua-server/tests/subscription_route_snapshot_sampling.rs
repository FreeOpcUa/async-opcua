#![allow(missing_docs)]

//! Expected-red route snapshot proof for server subscription sampling.

use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc,
    },
    time::Duration,
};

use opcua_client::{ClientBuilder, DataChangeCallback, IdentityToken, MonitoredItem, Session};
use opcua_crypto::SecurityPolicy;
use opcua_server::{ServerBuilder, ServerHandle, ANONYMOUS_USER_TOKEN_ID};
use opcua_types::{
    AttributeId, DataEncoding, DataValue, ExtensionObject, MessageSecurityMode,
    MonitoredItemCreateRequest, MonitoringMode, MonitoringParameters, NodeId, NumericRange,
    ReadValueId, StatusCode, TimestampsToReturn, VariableId, Variant,
};
use tokio::{net::TcpListener, task::JoinHandle};

static NEXT_TEST_ID: AtomicUsize = AtomicUsize::new(0);

const DELETE_PROGRESS_TIMEOUT: Duration = Duration::from_millis(300);
const OBSERVATION_TIMEOUT: Duration = Duration::from_secs(2);
const TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// HPL-006 expected-red proof grounded in OPC-10000-4 5.13.2 through 5.13.6
/// and 5.14.1: monitored item route lookup must be captured under the route
/// cache guard, but sampling closures must run after that guard is released so
/// monitored-item create/modify/delete races can make progress while preserving
/// in-flight notification routing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subscription_route_lookup_releases_cache_guard_before_sampling() {
    tokio::time::timeout(TEST_TIMEOUT, run_route_snapshot_sampling_probe())
        .await
        .expect("route snapshot sampling probe should not hang");
}

async fn run_route_snapshot_sampling_probe() {
    let server = RouteSnapshotServer::start().await;
    let (session, event_loop_task) = server.connect().await;
    let _event_loop_guard = AbortOnDrop(event_loop_task);

    let subscription_id = session
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

    let created = session
        .create_monitored_items(
            subscription_id,
            TimestampsToReturn::Both,
            vec![current_time_monitored_item()],
        )
        .await
        .expect("monitored item should be created");
    assert_eq!(created.len(), 1);
    assert!(
        created[0].result.status_code.is_good(),
        "monitored item create should succeed, got {}",
        created[0].result.status_code
    );

    let monitored_item_id = created[0].result.monitored_item_id;
    assert_ne!(monitored_item_id, 0);

    let node_id = current_time_node_id();
    let (observation_tx, observation_rx) = mpsc::channel();
    let sampling_session = Arc::clone(&session);

    server.handle.subscriptions().maybe_notify(
        [(&node_id, AttributeId::Value)].into_iter(),
        move |_node_id: &NodeId,
              _attribute_id: AttributeId,
              _index_range: &NumericRange,
              _data_encoding: &DataEncoding| {
            let delete_completed = delete_monitored_item_during_sampling(
                &sampling_session,
                subscription_id,
                monitored_item_id,
            );
            let _ = observation_tx.send(delete_completed);
            Some(DataValue::new_now(Variant::from(42i32)))
        },
    );

    let delete_completed = observation_rx
        .recv_timeout(OBSERVATION_TIMEOUT)
        .expect("sampling closure should run for the monitored route");

    assert!(
        delete_completed,
        "OPC-10000-4 5.13.2-5.13.6 and 5.14.1 allow delete races with in-flight notifications; \
         DeleteMonitoredItems timed out inside sampling, which means route lookup still holds the \
         subscription cache guard while sampling closures execute"
    );
}

fn delete_monitored_item_during_sampling(
    session: &Arc<Session>,
    subscription_id: u32,
    monitored_item_id: u32,
) -> bool {
    let session = Arc::clone(session);
    let (delete_tx, delete_rx) = mpsc::channel();

    tokio::spawn(async move {
        let ok = session
            .delete_monitored_items(subscription_id, &[monitored_item_id])
            .await
            .is_ok_and(|statuses| statuses.len() == 1 && statuses[0] == StatusCode::Good);
        let _ = delete_tx.send(ok);
    });

    delete_rx
        .recv_timeout(DELETE_PROGRESS_TIMEOUT)
        .unwrap_or(false)
}

struct RouteSnapshotServer {
    handle: ServerHandle,
    endpoint: String,
    server_task: JoinHandle<()>,
    _temp_dir: TempDir,
}

impl RouteSnapshotServer {
    async fn start() -> Self {
        let temp_dir = TempDir::new("subscription-route-snapshot-sampling");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("route snapshot test listener should bind");
        let addr = listener
            .local_addr()
            .expect("route snapshot test listener should have addr");
        let endpoint = format!("opc.tcp://127.0.0.1:{}/", addr.port());

        let (server, handle) = ServerBuilder::new()
            .application_name("subscription_route_snapshot_sampling")
            .application_uri("urn:async-opcua:subscription-route-snapshot-sampling")
            .product_uri("urn:async-opcua:subscription-route-snapshot-sampling")
            .host("127.0.0.1")
            .pki_dir(temp_dir.path.join("server-pki"))
            .create_sample_keypair(true)
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
            .build()
            .expect("route snapshot test server should build");

        let server_task = tokio::spawn(async move {
            server
                .run_with(listener)
                .await
                .expect("route snapshot test server should run");
        });

        Self {
            handle,
            endpoint,
            server_task,
            _temp_dir: temp_dir,
        }
    }

    async fn connect(&self) -> (Arc<Session>, JoinHandle<StatusCode>) {
        let mut client = ClientBuilder::new()
            .application_name("subscription_route_snapshot_sampling_client")
            .application_uri("urn:async-opcua:subscription-route-snapshot-sampling-client")
            .product_uri("urn:async-opcua:subscription-route-snapshot-sampling-client")
            .pki_dir(self._temp_dir.path.join("client-pki"))
            .create_sample_keypair(true)
            .trust_server_certs(true)
            .session_retry_initial(Duration::from_millis(50))
            .client()
            .expect("route snapshot test client should build");

        let (session, event_loop) = client
            .connect_to_matching_endpoint(
                (
                    self.endpoint.as_str(),
                    SecurityPolicy::None.to_str(),
                    MessageSecurityMode::None,
                ),
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
        self.server_task.abort();
    }
}

struct AbortOnDrop<T>(JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
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

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(test_name: &str) -> Self {
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::current_dir()
            .expect("current directory")
            .join("target")
            .join("subscription_route_snapshot_sampling")
            .join(format!("{test_name}-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path)
            .expect("temporary route snapshot test dir should be created");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
