//! Expected-red proof for the no-match subscription data-change route path.
//!
//! OPC-10000-4 5.13.2 through 5.13.6 require monitored-item route changes to
//! take effect promptly across create/modify/delete races. OPC-10000-4 5.14.1
//! requires Subscriptions to package only routed notifications. A data-change
//! source with no matching monitored items should therefore produce an empty
//! route batch without running sampling closures or enqueueing actor work.

#![allow(missing_docs)]

use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc,
    },
    thread,
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
use tokio::net::TcpListener;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const CACHE_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_FINISH_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subscription_route_snapshot_no_match_path_is_allocation_light() {
    tokio::time::timeout(TEST_TIMEOUT, run_no_match_route_probe())
        .await
        .expect("subscription route no-match probe should not hang");
}

async fn run_no_match_route_probe() {
    let server = RouteSnapshotServer::start("subscription-route-snapshot-no-match").await;
    let (data_tx, data_rx) = mpsc::channel();
    let subscription_id = server
        .session
        .create_subscription(
            Duration::from_millis(100),
            30,
            10,
            0,
            0,
            true,
            DataChangeCallback::new(move |value, _: &MonitoredItem| {
                if let Some(Variant::Int32(value)) = value.value {
                    let _ = data_tx.send(value);
                }
            }),
        )
        .await
        .expect("data-change subscription should be created");

    let create_results = server
        .session
        .create_monitored_items(
            subscription_id,
            TimestampsToReturn::Both,
            vec![current_time_monitored_item()],
        )
        .await
        .expect("data-change monitored item request should complete");
    assert_eq!(create_results.len(), 1);
    assert_eq!(create_results[0].result.status_code, StatusCode::Good);

    let unmatched_node = NodeId::new(2, "subscription-route-no-match-source");
    let sample_calls = Arc::new(AtomicUsize::new(0));
    server.handle.subscriptions().maybe_notify(
        [(&unmatched_node, AttributeId::Value)].into_iter(),
        {
            let sample_calls = Arc::clone(&sample_calls);
            move |_node_id: &NodeId,
                  _attribute_id: AttributeId,
                  _index_range: &NumericRange,
                  _data_encoding: &DataEncoding| {
                sample_calls.fetch_add(1, Ordering::SeqCst);
                Some(DataValue::new_now(Variant::Int32(111)))
            }
        },
    );
    assert_eq!(
        sample_calls.load(Ordering::SeqCst),
        0,
        "a no-match data-change route must not run sampling closures"
    );

    let mut notifier = server.handle.subscriptions().data_notifier();
    let no_match_batch = notifier.notify_for(&unmatched_node, AttributeId::Value);
    drop(no_match_batch);

    let (probe_tx, probe_rx) = mpsc::channel();
    let probe_session = Arc::clone(&server.session);
    let probe_thread = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("probe runtime should build");
        let result = runtime.block_on(create_probe_subscription(probe_session));
        let _ = probe_tx.send(result);
    });
    let early_probe_result = probe_rx.recv_timeout(CACHE_WRITE_TIMEOUT);
    let cache_write_finished_before_empty_batch_drop = early_probe_result.is_ok();

    drop(notifier);

    let probe_result = match early_probe_result {
        Ok(result) => result,
        Err(_) => probe_rx
            .recv_timeout(PROBE_FINISH_TIMEOUT)
            .expect("probe subscription should finish after no-match notifier drop"),
    };
    probe_thread
        .join()
        .expect("probe subscription thread should not panic");
    let probe_subscription_id =
        probe_result.expect("probe subscription should be created after no-match notifier drop");
    assert_ne!(probe_subscription_id, 0);

    server.handle.subscriptions().notify_data_change(
        [
            (
                DataValue::new_now(Variant::Int32(111)),
                &unmatched_node,
                AttributeId::Value,
            ),
            (
                DataValue::new_now(Variant::Int32(222)),
                &current_time_node_id(),
                AttributeId::Value,
            ),
        ]
        .into_iter(),
    );

    let first_routed_value = data_rx
        .recv_timeout(CALLBACK_TIMEOUT)
        .expect("matched data-change notification should be delivered");
    assert_eq!(
        first_routed_value, 222,
        "a no-match data-change route must not enqueue actor work before the matched control notification"
    );

    assert!(
        cache_write_finished_before_empty_batch_drop,
        "OPC-10000-4 5.13.2-5.13.6 and 5.14.1 require no-match data-change routing to produce only an empty route batch; creating another subscription could not acquire the cache write guard while the no-match notifier was alive, so the current path is still carrying the cache guard instead of an allocation-light empty batch"
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
            DataChangeCallback::new(|_, _: &MonitoredItem| {}),
        )
        .await
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
        let (server, handle) = ServerBuilder::new()
            .application_name("subscription_route_snapshot_no_match")
            .application_uri("urn:async-opcua:subscription-route-snapshot-no-match")
            .product_uri("urn:async-opcua:subscription-route-snapshot-no-match")
            .host("127.0.0.1")
            .pki_dir(PathBuf::from(&server_pki))
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

        let mut client = ClientBuilder::new()
            .application_name("subscription_route_snapshot_no_match_client")
            .application_uri("urn:async-opcua:subscription-route-snapshot-no-match-client")
            .product_uri("urn:async-opcua:subscription-route-snapshot-no-match-client")
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
