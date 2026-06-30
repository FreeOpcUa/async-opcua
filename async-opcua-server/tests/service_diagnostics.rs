//! Service diagnostic integration tests.

use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use opcua_client::{services::Read, ClientBuilder, IdentityToken, Session};
use opcua_core::ResponseMessage;
use opcua_crypto::SecurityPolicy;
use opcua_server::{ServerBuilder, ServerEndpoint, ServerHandle, ANONYMOUS_USER_TOKEN_ID};
use opcua_types::{
    AttributeId, DiagnosticBits, DiagnosticInfo, MessageSecurityMode, ObjectId, ReadRequest,
    ReadValueId, ResponseHeader, StatusCode, TimestampsToReturn, UAString,
};
use tokio::net::TcpListener;

static NEXT_TEST_ID: AtomicUsize = AtomicUsize::new(0);

struct DiagnosticsServer {
    handle: ServerHandle,
    session: Arc<Session>,
    event_loop_task: tokio::task::JoinHandle<StatusCode>,
    server_task: tokio::task::JoinHandle<()>,
    _temp_dir: TempDir,
}

impl DiagnosticsServer {
    async fn start(test_name: &str) -> Self {
        let temp_dir = TempDir::new(test_name);
        let server_pki = temp_dir.path.join("server-pki");
        let client_pki = temp_dir.path.join("client-pki");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("diagnostics test listener should bind");
        let addr = listener
            .local_addr()
            .expect("diagnostics test listener should have an address");
        let endpoint = format!("opc.tcp://127.0.0.1:{}/", addr.port());
        let user_token_ids = [ANONYMOUS_USER_TOKEN_ID];

        let (server, handle) = ServerBuilder::new()
            .application_name("service_diagnostics_tests")
            .application_uri("urn:async-opcua:service-diagnostics-tests")
            .product_uri("urn:async-opcua:service-diagnostics-tests")
            .host("127.0.0.1")
            .pki_dir(&server_pki)
            .create_sample_keypair(true)
            .discovery_urls(vec![endpoint.clone()])
            .add_endpoint(
                "none",
                ServerEndpoint::new_none("/", &user_token_ids.map(str::to_string)),
            )
            .build()
            .expect("diagnostics test server should build");
        let server_task = tokio::spawn(async move {
            server
                .run_with(listener)
                .await
                .expect("diagnostics test server should run");
        });

        let mut client = ClientBuilder::new()
            .application_name("service_diagnostics_tests_client")
            .application_uri("urn:async-opcua:service-diagnostics-tests-client")
            .product_uri("urn:async-opcua:service-diagnostics-tests-client")
            .pki_dir(client_pki)
            .create_sample_keypair(true)
            .trust_server_certs(true)
            .session_retry_initial(Duration::from_millis(100))
            .client()
            .expect("diagnostics test client should build");

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
            .expect("diagnostics test client should connect");
        let event_loop_task = event_loop.spawn();

        tokio::time::timeout(Duration::from_secs(5), session.wait_for_connection())
            .await
            .expect("diagnostics test client should become connected");

        Self {
            handle,
            session,
            event_loop_task,
            server_task,
            _temp_dir: temp_dir,
        }
    }
}

impl Drop for DiagnosticsServer {
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
            .join("service_diagnostics_tests")
            .join(format!("{test_name}-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temporary diagnostics dir should be created");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[tokio::test]
async fn return_diagnostics_populates_service_fault_header_only_when_requested() {
    let server = DiagnosticsServer::start("return-diagnostics").await;

    let without_diagnostics = invalid_read_fault(
        &server.session,
        DiagnosticBits::empty(),
        "without diagnostics",
    )
    .await;
    assert_eq!(
        without_diagnostics.service_result,
        StatusCode::BadMaxAgeInvalid
    );
    assert_diagnostics_absent(&without_diagnostics);

    let requested_diagnostics = DiagnosticBits::SERVICE_LEVEL_SYMBOLIC_ID
        | DiagnosticBits::SERVICE_LEVEL_LOCALIZED_TEXT
        | DiagnosticBits::SERVICE_LEVEL_ADDITIONAL_INFO;
    let with_diagnostics =
        invalid_read_fault(&server.session, requested_diagnostics, "with diagnostics").await;
    assert_eq!(
        with_diagnostics.service_result,
        StatusCode::BadMaxAgeInvalid
    );
    assert_diagnostics_populated(&with_diagnostics);
}

async fn invalid_read_fault(
    session: &Session,
    diagnostics: DiagnosticBits,
    label: &str,
) -> ResponseHeader {
    let mut request_header = Read::new(session).diagnostics(diagnostics).header().clone();
    request_header.return_diagnostics = diagnostics;
    let request = ReadRequest {
        request_header,
        max_age: -1.0,
        timestamps_to_return: TimestampsToReturn::Both,
        nodes_to_read: Some(vec![ReadValueId::new(
            ObjectId::Server.into(),
            AttributeId::NodeId,
        )]),
    };

    let response = session
        .channel()
        .send(request, Duration::from_secs(5))
        .await
        .unwrap_or_else(|err| panic!("{label}: invalid Read should receive ServiceFault: {err}"));
    let ResponseMessage::ServiceFault(fault) = response else {
        panic!("{label}: invalid Read should return ServiceFault");
    };
    fault.response_header
}

fn assert_diagnostics_absent(header: &ResponseHeader) {
    assert!(
        header.service_diagnostics.encoding_mask().is_empty(),
        "serviceDiagnostics must be empty when returnDiagnostics is not requested: {:?}",
        header.service_diagnostics
    );
    assert!(
        string_table_is_empty(&header.string_table),
        "stringTable must be empty when returnDiagnostics is not requested: {:?}",
        header.string_table
    );
}

fn assert_diagnostics_populated(header: &ResponseHeader) {
    assert!(
        !header.service_diagnostics.encoding_mask().is_empty(),
        "serviceDiagnostics must be populated when service-level returnDiagnostics are requested"
    );

    let string_table = header
        .string_table
        .as_ref()
        .filter(|table| !table.is_empty())
        .expect("stringTable must be populated when diagnostics reference strings");
    assert!(
        diagnostic_references_string_table(&header.service_diagnostics, string_table),
        "serviceDiagnostics must reference populated stringTable entries: diagnostics={:?}, stringTable={:?}",
        header.service_diagnostics,
        string_table
    );
}

fn string_table_is_empty(string_table: &Option<Vec<UAString>>) -> bool {
    string_table.as_ref().is_none_or(Vec::is_empty)
}

fn diagnostic_references_string_table(
    diagnostic: &DiagnosticInfo,
    string_table: &[UAString],
) -> bool {
    [
        diagnostic.symbolic_id,
        diagnostic.namespace_uri,
        diagnostic.locale,
        diagnostic.localized_text,
    ]
    .into_iter()
    .flatten()
    .any(|index| {
        usize::try_from(index)
            .ok()
            .is_some_and(|index| index < string_table.len())
    })
}
