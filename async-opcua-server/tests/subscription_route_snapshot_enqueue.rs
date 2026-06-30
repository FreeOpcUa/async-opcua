//! Expected-red guard-release proof for subscription route actor enqueue.
//!
//! OPC-10000-4 5.13.2 through 5.13.6 require monitored-item route changes to
//! take effect without weakening create/modify/delete race behavior. OPC-10000-4
//! 5.14.1 requires Subscriptions to package queued notifications without holding
//! unrelated cache guards through actor enqueue.

use std::{
    path::PathBuf,
    sync::{mpsc, Arc, Mutex},
    thread,
    time::Duration,
};

use opcua_client::{ClientBuilder, EventCallback, IdentityToken, Session};
use opcua_crypto::SecurityPolicy;
use opcua_nodes::{BaseEventType, Event};
use opcua_server::{ServerBuilder, ServerEndpoint, ServerHandle, ANONYMOUS_USER_TOKEN_ID};
use opcua_types::{
    event_field::EventField, AttributeId, ByteString, ContentFilter, DateTime, EventFilter,
    ExtensionObject, MessageSecurityMode, MonitoredItemCreateRequest, MonitoringMode,
    MonitoringParameters, NodeId, NumericRange, ObjectId, ObjectTypeId, QualifiedName, ReadValueId,
    SimpleAttributeOperand, StatusCode, TimestampsToReturn, Variant,
};
use tokio::net::TcpListener;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const CLONE_START_TIMEOUT: Duration = Duration::from_secs(2);
const CACHE_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const CLONE_RELEASE_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subscription_route_snapshot_releases_cache_guard_before_actor_enqueue() {
    tokio::time::timeout(TEST_TIMEOUT, run_actor_enqueue_guard_probe())
        .await
        .expect("subscription route actor enqueue guard probe should not hang");
}

async fn run_actor_enqueue_guard_probe() {
    let server = RouteSnapshotServer::start("subscription-route-snapshot-enqueue").await;
    let subscription_id = server
        .session
        .create_subscription(
            Duration::from_millis(100),
            30,
            10,
            0,
            0,
            true,
            EventCallback::new(|_, _| {}),
        )
        .await
        .expect("event subscription should be created");

    let create_results = server
        .session
        .create_monitored_items(
            subscription_id,
            TimestampsToReturn::Both,
            vec![event_monitored_item()],
        )
        .await
        .expect("event monitored item request should complete");
    assert_eq!(create_results.len(), 1);
    assert_eq!(create_results[0].result.status_code, StatusCode::Good);

    let (clone_started_tx, clone_started_rx) = mpsc::channel();
    let (release_clone_tx, release_clone_rx) = mpsc::channel();
    let subscriptions = Arc::clone(server.handle.subscriptions());
    let notify_thread = thread::spawn(move || {
        let server_node = NodeId::from(ObjectId::Server);
        let event = BlockingCloneEvent::new(clone_started_tx, release_clone_rx);
        subscriptions.notify_events([(&event as &dyn Event, &server_node)].into_iter());
    });

    clone_started_rx
        .recv_timeout(CLONE_START_TIMEOUT)
        .expect("event work item clone did not start; the test cannot prove enqueue guard scope");

    let mut cache_write_task = tokio::spawn(create_probe_subscription(Arc::clone(&server.session)));
    let cache_write_result = tokio::time::timeout(CACHE_WRITE_TIMEOUT, &mut cache_write_task).await;
    let cache_write_finished_before_enqueue_release = cache_write_result.is_ok();

    let _ = release_clone_tx.send(());
    notify_thread
        .join()
        .expect("notification thread should finish after releasing event clone");

    let probe_result = match cache_write_result {
        Ok(joined) => joined.expect("probe subscription task should not panic"),
        Err(_) => cache_write_task
            .await
            .expect("probe subscription task should not panic after releasing event clone"),
    };
    let probe_subscription_id =
        probe_result.expect("probe subscription should be created after releasing event clone");
    assert_ne!(probe_subscription_id, 0);

    assert!(
        cache_write_finished_before_enqueue_release,
        "OPC-10000-4 5.13.2-5.13.6 and 5.14.1 require subscription route lookup to finish under the cache guard, then actor queue work to proceed after unlock; creating a second subscription could not acquire the cache write guard while event enqueue preparation was blocked, so the notifier is still carrying the cache read guard into the actor enqueue path"
    );
}

async fn create_probe_subscription(session: Arc<Session>) -> Result<u32, opcua_types::Error> {
    session
        .create_subscription(
            Duration::from_millis(100),
            30,
            10,
            0,
            0,
            true,
            EventCallback::new(|_, _| {}),
        )
        .await
}

fn event_monitored_item() -> MonitoredItemCreateRequest {
    MonitoredItemCreateRequest::new(
        ReadValueId::new(ObjectId::Server.into(), AttributeId::EventNotifier),
        MonitoringMode::Reporting,
        MonitoringParameters {
            client_handle: 1,
            sampling_interval: 0.0,
            filter: ExtensionObject::from_message(EventFilter {
                select_clauses: Some(vec![SimpleAttributeOperand::new_value(
                    ObjectTypeId::BaseEventType,
                    "Message",
                )]),
                where_clause: ContentFilter::default(),
            }),
            queue_size: 10,
            discard_oldest: true,
        },
    )
}

struct BlockingCloneEvent {
    base: BaseEventType,
    clone_started: mpsc::Sender<()>,
    release_clone: Mutex<Option<mpsc::Receiver<()>>>,
}

impl BlockingCloneEvent {
    fn new(clone_started: mpsc::Sender<()>, release_clone: mpsc::Receiver<()>) -> Self {
        Self {
            base: BaseEventType::new_now(
                ObjectTypeId::BaseEventType,
                ByteString::from(b"route-snapshot-enqueue".to_vec()),
                "route snapshot enqueue",
            )
            .set_severity(500),
            clone_started,
            release_clone: Mutex::new(Some(release_clone)),
        }
    }
}

impl Event for BlockingCloneEvent {
    fn clone_box(&self) -> Box<dyn Event + Send> {
        let _ = self.clone_started.send(());
        if let Some(release_clone) = self
            .release_clone
            .lock()
            .expect("event clone release mutex should not be poisoned")
            .take()
        {
            let _ = release_clone.recv_timeout(CLONE_RELEASE_TIMEOUT);
        }
        Box::new(self.base.clone())
    }

    fn get_field(
        &self,
        type_definition_id: &NodeId,
        attribute_id: AttributeId,
        index_range: &NumericRange,
        browse_path: &[QualifiedName],
    ) -> Variant {
        self.base
            .get_field(type_definition_id, attribute_id, index_range, browse_path)
    }

    fn time(&self) -> &DateTime {
        &self.base.time
    }

    fn event_type_id(&self) -> &NodeId {
        &self.base.event_type
    }
}

impl EventField for BlockingCloneEvent {
    fn get_value(
        &self,
        attribute_id: AttributeId,
        index_range: &NumericRange,
        remaining_path: &[QualifiedName],
    ) -> Variant {
        self.base
            .get_value(attribute_id, index_range, remaining_path)
    }
}

struct RouteSnapshotServer {
    handle: ServerHandle,
    session: Arc<Session>,
    event_loop_task: tokio::task::JoinHandle<StatusCode>,
    server_task: tokio::task::JoinHandle<()>,
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
        let user_token_ids = [ANONYMOUS_USER_TOKEN_ID.to_string()];

        let (server, handle) = ServerBuilder::new()
            .application_name("subscription_route_snapshot_enqueue")
            .application_uri("urn:async-opcua:subscription-route-snapshot-enqueue")
            .product_uri("urn:async-opcua:subscription-route-snapshot-enqueue")
            .host("127.0.0.1")
            .pki_dir(PathBuf::from(&server_pki))
            .create_sample_keypair(true)
            .discovery_urls(vec![endpoint.clone()])
            .add_endpoint("none", ServerEndpoint::new_none("/", &user_token_ids))
            .build()
            .expect("route snapshot test server should build");
        let server_task = tokio::spawn(async move {
            server
                .run_with(listener)
                .await
                .expect("route snapshot test server should run");
        });

        let mut client = ClientBuilder::new()
            .application_name("subscription_route_snapshot_enqueue_client")
            .application_uri("urn:async-opcua:subscription-route-snapshot-enqueue-client")
            .product_uri("urn:async-opcua:subscription-route-snapshot-enqueue-client")
            .pki_dir(client_pki)
            .create_sample_keypair(true)
            .trust_server_certs(true)
            .session_retry_initial(Duration::from_millis(100))
            .client()
            .expect("route snapshot test client should build");

        let (session, event_loop) = client
            .connect_to_matching_endpoint(
                (
                    endpoint.as_str(),
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

        Self {
            handle,
            session,
            event_loop_task,
            server_task,
            _temp_dir: temp_dir,
        }
    }
}

impl Drop for RouteSnapshotServer {
    fn drop(&mut self) {
        self.handle.cancel();
        self.event_loop_task.abort();
        self.server_task.abort();
    }
}
