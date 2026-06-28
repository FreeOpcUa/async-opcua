//! Event filter integration tests.

use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use opcua_client::{services::Read, ClientBuilder, EventCallback, IdentityToken, Session};
use opcua_core::ResponseMessage;
use opcua_crypto::SecurityPolicy;
use opcua_nodes::{BaseEventType, DefaultTypeTree, Event};
use opcua_server::{
    services::subscription::filter::ParsedEventFilter, ServerBuilder, ServerEndpoint, ServerHandle,
    ServerUserToken, ANONYMOUS_USER_TOKEN_ID,
};
use opcua_types::{
    AttributeId, ByteString, ContentFilter, ContentFilterBuilder, ContentFilterElement,
    EventFilter, ExtensionObject, FilterOperator, MessageSecurityMode, MonitoredItemCreateRequest,
    MonitoringMode, MonitoringParameters, NodeId, NumericRange, ObjectId, ObjectTypeId, Operand,
    ReadRequest, ReadValueId, SimpleAttributeOperand, StatusCode, TimestampsToReturn, Variant,
};
use tokio::{net::TcpListener, sync::mpsc};

static NEXT_TEST_ID: AtomicUsize = AtomicUsize::new(0);

struct EventFilterServer {
    handle: ServerHandle,
    session: Arc<Session>,
    endpoint: String,
    event_loop_task: tokio::task::JoinHandle<StatusCode>,
    server_task: tokio::task::JoinHandle<()>,
    _temp_dir: TempDir,
}

impl EventFilterServer {
    async fn start(test_name: &str) -> Self {
        let temp_dir = TempDir::new(test_name);
        let server_pki = temp_dir.path.join("server-pki");
        let client_pki = temp_dir.path.join("client-pki");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("event filter test listener should bind");
        let addr = listener
            .local_addr()
            .expect("test listener should have addr");
        let endpoint = format!("opc.tcp://127.0.0.1:{}/", addr.port());
        let user_token_ids = [ANONYMOUS_USER_TOKEN_ID, "password-user"];

        let (server, handle) = ServerBuilder::new()
            .application_name("event_filter_tests")
            .application_uri("urn:async-opcua:event-filter-tests")
            .product_uri("urn:async-opcua:event-filter-tests")
            .host("127.0.0.1")
            .pki_dir(&server_pki)
            .create_sample_keypair(true)
            .discovery_urls(vec![endpoint.clone()])
            .add_user_token(
                "password-user",
                ServerUserToken::user_pass("brew-operator", "correct-password"),
            )
            .add_endpoint(
                "none",
                ServerEndpoint::new_none("/", &user_token_ids.map(str::to_string)),
            )
            .build()
            .expect("event filter test server should build");
        let server_task = tokio::spawn(async move {
            server
                .run_with(listener)
                .await
                .expect("event filter test server should run");
        });

        let mut client = ClientBuilder::new()
            .application_name("event_filter_tests_client")
            .application_uri("urn:async-opcua:event-filter-tests-client")
            .product_uri("urn:async-opcua:event-filter-tests-client")
            .pki_dir(client_pki)
            .create_sample_keypair(true)
            .trust_server_certs(true)
            .session_retry_initial(Duration::from_millis(100))
            .client()
            .expect("event filter test client should build");

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
            .expect("event filter test client should connect");
        let event_loop_task = event_loop.spawn();

        tokio::time::timeout(Duration::from_secs(5), session.wait_for_connection())
            .await
            .expect("event filter test client should become connected");

        Self {
            handle,
            session,
            endpoint,
            event_loop_task,
            server_task,
            _temp_dir: temp_dir,
        }
    }

    fn client(&self, pki_name: &str) -> opcua_client::Client {
        ClientBuilder::new()
            .application_name("event_filter_tests_client")
            .application_uri(format!(
                "urn:async-opcua:event-filter-tests-client:{pki_name}"
            ))
            .product_uri("urn:async-opcua:event-filter-tests-client")
            .pki_dir(self._temp_dir.path.join(pki_name))
            .create_sample_keypair(true)
            .trust_server_certs(true)
            .session_retry_limit(0)
            .session_retry_initial(Duration::from_millis(10))
            .client()
            .expect("event filter test client should build")
    }
}

impl Drop for EventFilterServer {
    fn drop(&mut self) {
        self.handle.cancel();
        self.event_loop_task.abort();
        self.server_task.abort();
    }
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
            .join("event_filter_tests")
            .join(format!("{test_name}-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temporary event filter dir should be created");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[tokio::test]
async fn event_filter_delivers_only_matching_events_with_selected_fields() {
    let server = EventFilterServer::start("matching-events").await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let subscription_id = server
        .session
        .create_subscription(
            Duration::from_millis(100),
            30,
            10,
            0,
            0,
            true,
            EventCallback::new(move |event_fields, _| {
                let _ = event_tx.send(event_fields.unwrap_or_default());
            }),
        )
        .await
        .expect("event filter subscription should be created");

    let create_results = server
        .session
        .create_monitored_items(
            subscription_id,
            TimestampsToReturn::Both,
            vec![event_monitored_item(severity_filter(500))],
        )
        .await
        .expect("event monitored item request should complete");
    assert_eq!(create_results.len(), 1);
    assert_eq!(create_results[0].result.status_code, StatusCode::Good);

    let server_node = NodeId::from(ObjectId::Server);
    let low = base_event("low-severity", 100);
    let high = base_event("high-severity", 700);
    server.handle.subscriptions().notify_events(
        [
            (&low as &dyn Event, &server_node),
            (&high as &dyn Event, &server_node),
        ]
        .into_iter(),
    );
    server.session.trigger_publish_now();

    let fields = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
        .await
        .expect("matching event should be published")
        .expect("matching event fields should be received");

    assert_eq!(fields.len(), 2);
    assert_eq!(localized_text(&fields[0]), Some("high-severity"));
    assert_eq!(fields[1], Variant::UInt16(700));
    assert!(event_rx.try_recv().is_err());
}

#[tokio::test]
async fn event_filter_rejects_unsupported_where_clause_operator() {
    let server = EventFilterServer::start("unsupported-operator").await;
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
        .expect("event filter subscription should be created");

    let create_results = server
        .session
        .create_monitored_items(
            subscription_id,
            TimestampsToReturn::Both,
            vec![event_monitored_item(unsupported_where_clause_filter())],
        )
        .await
        .expect("event monitored item request should complete");

    assert_eq!(create_results.len(), 1);
    assert_eq!(
        create_results[0].result.status_code,
        StatusCode::BadMonitoredItemFilterUnsupported
    );
}

#[test]
fn unsupported_event_filter_operator_returns_bad_filter_operator_unsupported() {
    let status = first_where_element_status(EventFilter {
        select_clauses: Some(vec![SimpleAttributeOperand::new_value(
            ObjectTypeId::BaseEventType,
            "Severity",
        )]),
        where_clause: ContentFilter {
            elements: Some(vec![(
                FilterOperator::RelatedTo,
                vec![
                    Operand::literal(NodeId::from(ObjectId::Server)),
                    Operand::literal(NodeId::null()),
                    Operand::literal(NodeId::null()),
                    Operand::literal(NodeId::null()),
                    Operand::literal(0u32),
                    Operand::literal(false),
                ],
            )
                .into()]),
        },
    });

    // OPC-10000-4 7.7: unsupported ContentFilter operators report BadFilterOperatorUnsupported.
    assert_eq!(status, StatusCode::BadFilterOperatorUnsupported);
}

#[test]
fn event_filter_wrong_operand_count_returns_bad_filter_operand_count_mismatch() {
    let status = first_where_element_status(EventFilter {
        select_clauses: Some(vec![SimpleAttributeOperand::new_value(
            ObjectTypeId::BaseEventType,
            "Severity",
        )]),
        where_clause: ContentFilter {
            elements: Some(vec![ContentFilterElement::from((
                FilterOperator::GreaterThanOrEqual,
                vec![Operand::literal(500u16)],
            ))]),
        },
    });

    // OPC-10000-4 7.7: wrong operand counts report BadFilterOperandCountMismatch.
    assert_eq!(status, StatusCode::BadFilterOperandCountMismatch);
}

#[test]
fn event_filter_invalid_operand_returns_bad_filter_operand_invalid() {
    let status = first_where_element_status(EventFilter {
        select_clauses: Some(vec![SimpleAttributeOperand::new_value(
            ObjectTypeId::BaseEventType,
            "Severity",
        )]),
        where_clause: ContentFilter {
            elements: Some(vec![ContentFilterElement::from((
                FilterOperator::Not,
                vec![Operand::element(1)],
            ))]),
        },
    });

    // OPC-10000-4 7.7: invalid operands report BadFilterOperandInvalid.
    assert_eq!(status, StatusCode::BadFilterOperandInvalid);
}

#[tokio::test]
async fn failed_username_activation_dispatches_audit_event() {
    let server = EventFilterServer::start("failed-auth-audit").await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let subscription_id = server
        .session
        .create_subscription(
            Duration::from_millis(100),
            30,
            10,
            0,
            0,
            true,
            EventCallback::new(move |event_fields, _| {
                let _ = event_tx.send(event_fields.unwrap_or_default());
            }),
        )
        .await
        .expect("audit subscription should be created");

    let create_results = server
        .session
        .create_monitored_items(
            subscription_id,
            TimestampsToReturn::Both,
            vec![event_monitored_item(audit_failure_filter())],
        )
        .await
        .expect("audit monitored item request should complete");
    assert_eq!(create_results[0].result.status_code, StatusCode::Good);

    let mut client = server.client("failed-auth-client");
    let (bad_session, event_loop) = client
        .connect_to_matching_endpoint(
            (
                server.endpoint.as_str(),
                SecurityPolicy::None.to_str(),
                MessageSecurityMode::None,
            ),
            IdentityToken::new_user_name("brew-operator", "wrong-password"),
        )
        .await
        .expect("bad auth client session should be constructed");
    bad_session.disable_reconnects();

    let status = tokio::time::timeout(Duration::from_secs(5), event_loop.spawn())
        .await
        .expect("bad auth event loop should finish")
        .expect("bad auth event loop task should complete");
    assert_eq!(status, StatusCode::BadUserAccessDenied);

    server.session.trigger_publish_now();
    // The bad client's CreateSession succeeds and now emits an AuditCreateSessionEventType ahead of
    // the ActivateSession failure; skip non-activate audit events and assert on the activation one.
    let activate_type = Variant::from(NodeId::from(ObjectTypeId::AuditActivateSessionEventType));
    let mut fields = None;
    for _ in 0..4 {
        let Ok(Some(received)) =
            tokio::time::timeout(Duration::from_secs(5), event_rx.recv()).await
        else {
            break;
        };
        if received.first() == Some(&activate_type) {
            fields = Some(received);
            break;
        }
        server.session.trigger_publish_now();
    }
    let fields = fields.expect("an AuditActivateSessionEventType failure should be published");

    assert_eq!(
        localized_text(&fields[1]),
        Some("ActivateSession failed: BadUserAccessDenied")
    );
    assert_eq!(fields[2], Variant::UInt16(900));
}

#[tokio::test]
async fn failed_service_invocation_dispatches_audit_event() {
    let server = EventFilterServer::start("failed-service-audit").await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let subscription_id = server
        .session
        .create_subscription(
            Duration::from_millis(100),
            30,
            10,
            0,
            0,
            true,
            EventCallback::new(move |event_fields, _| {
                let _ = event_tx.send(event_fields.unwrap_or_default());
            }),
        )
        .await
        .expect("audit subscription should be created");

    let create_results = server
        .session
        .create_monitored_items(
            subscription_id,
            TimestampsToReturn::Both,
            vec![event_monitored_item(audit_failure_filter())],
        )
        .await
        .expect("audit monitored item request should complete");
    assert_eq!(create_results[0].result.status_code, StatusCode::Good);

    let request = ReadRequest {
        request_header: Read::new(&server.session).header().clone(),
        max_age: -1.0,
        timestamps_to_return: TimestampsToReturn::Both,
        nodes_to_read: Some(vec![ReadValueId::new(
            ObjectId::Server.into(),
            AttributeId::NodeId,
        )]),
    };
    let response = server
        .session
        .channel()
        .send(request, Duration::from_secs(5))
        .await
        .expect("invalid read request should receive a service fault");
    let ResponseMessage::ServiceFault(response) = response else {
        panic!("invalid read request should return ServiceFault");
    };
    assert_eq!(
        response.response_header.service_result,
        StatusCode::BadMaxAgeInvalid
    );

    server.session.trigger_publish_now();
    let fields = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
        .await
        .expect("failed service audit event should be published")
        .expect("failed service audit event fields should be received");

    assert_eq!(
        fields[0],
        Variant::from(NodeId::from(ObjectTypeId::AuditSecurityEventType))
    );
    assert_eq!(
        localized_text(&fields[1]),
        Some("Read failed: BadMaxAgeInvalid")
    );
    assert_eq!(fields[2], Variant::UInt16(900));
}

fn event_monitored_item(filter: EventFilter) -> MonitoredItemCreateRequest {
    MonitoredItemCreateRequest::new(
        ReadValueId::new(ObjectId::Server.into(), AttributeId::EventNotifier),
        MonitoringMode::Reporting,
        MonitoringParameters {
            client_handle: 1,
            sampling_interval: 0.0,
            filter: ExtensionObject::from_message(filter),
            queue_size: 10,
            discard_oldest: true,
        },
    )
}

fn first_where_element_status(filter: EventFilter) -> StatusCode {
    let type_tree = DefaultTypeTree::new();
    let (result, parsed) = ParsedEventFilter::parse(filter, &type_tree);
    assert!(parsed.is_err());

    result
        .where_clause_result
        .element_results
        .expect("where clause element result should be present")[0]
        .status_code
}

fn severity_filter(min_severity: u16) -> EventFilter {
    let base_event_type = NodeId::from(ObjectTypeId::BaseEventType);
    EventFilter {
        select_clauses: Some(vec![
            SimpleAttributeOperand::new_value(base_event_type.clone(), "Message"),
            SimpleAttributeOperand::new_value(base_event_type.clone(), "Severity"),
        ]),
        where_clause: ContentFilterBuilder::new()
            .gte(
                Operand::simple_attribute(
                    base_event_type,
                    "Severity",
                    AttributeId::Value,
                    NumericRange::None,
                ),
                Operand::literal(min_severity),
            )
            .build(),
    }
}

fn unsupported_where_clause_filter() -> EventFilter {
    EventFilter {
        select_clauses: Some(vec![SimpleAttributeOperand::new_value(
            ObjectTypeId::BaseEventType,
            "Severity",
        )]),
        where_clause: ContentFilter {
            elements: Some(vec![(
                FilterOperator::RelatedTo,
                vec![
                    Operand::literal(NodeId::from(ObjectId::Server)),
                    Operand::literal(NodeId::null()),
                    Operand::literal(NodeId::null()),
                    Operand::literal(NodeId::null()),
                    Operand::literal(0u32),
                    Operand::literal(false),
                ],
            )
                .into()]),
        },
    }
}

fn audit_failure_filter() -> EventFilter {
    let event_type = NodeId::from(ObjectTypeId::BaseEventType);
    EventFilter {
        select_clauses: Some(vec![
            SimpleAttributeOperand::new_value(event_type.clone(), "EventType"),
            SimpleAttributeOperand::new_value(event_type.clone(), "Message"),
            SimpleAttributeOperand::new_value(event_type, "Severity"),
        ]),
        where_clause: ContentFilter::default(),
    }
}

fn base_event(message: &str, severity: u16) -> BaseEventType {
    BaseEventType::new(
        ObjectTypeId::BaseEventType,
        ByteString::from(message.as_bytes()),
        message,
        opcua_types::DateTime::now(),
    )
    .set_severity(severity)
}

fn localized_text(value: &Variant) -> Option<&str> {
    let Variant::LocalizedText(text) = value else {
        return None;
    };
    Some(text.text.as_ref())
}
