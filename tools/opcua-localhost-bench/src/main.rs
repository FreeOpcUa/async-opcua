//! Controlled localhost throughput harness for async-opcua Read/Write hot paths.

use std::{fmt, process::ExitCode, sync::Arc, time::Duration};

use async_trait::async_trait;
use opcua::{
    client::{ClientBuilder, IdentityToken, Session},
    crypto::SecurityPolicy,
    server::{
        address_space::{write_node_value, AddressSpace, VariableBuilder},
        diagnostics::NamespaceMetadata,
        node_manager::memory::{InMemoryNodeManagerBuilder, InMemoryNodeManagerImpl},
        node_manager::{NodeManagerBuilder, RequestContext, ServerContext, WriteNode},
        ServerBuilder, ServerHandle,
    },
    sync::RwLock,
    types::{
        AttributeId, DataTypeId, MessageSecurityMode, NodeClass, NodeId, ObjectId, ReadValueId,
        StatusCode, TimestampsToReturn, UserTokenPolicy, Variant, WriteValue,
    },
};
use serde::Serialize;
use tokio::{net::TcpListener, task::JoinHandle, time::Instant};

const DEFAULT_ENDPOINT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 4840;
const DEFAULT_NAMESPACE: u16 = 2;
const DEFAULT_NODE: u32 = 1000;
const DEFAULT_WARMUP_SECONDS: f64 = 1.0;
const DEFAULT_MEASURE_SECONDS: f64 = 5.0;
const APP_URI: &str = "urn:localhost:async-opcua-localhost-bench";
const BENCH_NAMESPACE_URI: &str = "urn:localhost:async-opcua-localhost-bench:bench";
const READINESS_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> ExitCode {
    match run_cli(std::env::args().skip(1).collect()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

async fn run_cli(args: Vec<String>) -> Result<(), String> {
    if args.is_empty() || args.iter().any(|arg| arg == "-h" || arg == "--help") {
        print_usage();
        return Ok(());
    }

    match Command::parse(args)? {
        Command::Run(config) => run_one_shot(config).await,
        Command::Server(config) => run_standalone_server(config).await,
        Command::Client(config) => run_standalone_client(config).await,
    }
}

fn print_usage() {
    println!("{}", usage());
}

fn usage() -> String {
    format!(
        "\
async-opcua localhost benchmark

Usage:
  async-opcua-localhost-bench run --op <read|write> [--port {DEFAULT_PORT}] [--warmup {DEFAULT_WARMUP_SECONDS}] [--measure {DEFAULT_MEASURE_SECONDS}]
  async-opcua-localhost-bench server [--port {DEFAULT_PORT}]
  async-opcua-localhost-bench client --op <read|write> --endpoint <url> [--namespace {DEFAULT_NAMESPACE}] [--node {DEFAULT_NODE}] [--warmup {DEFAULT_WARMUP_SECONDS}] [--measure {DEFAULT_MEASURE_SECONDS}]
  async-opcua-localhost-bench --help

Defaults:
  endpoint host: {DEFAULT_ENDPOINT_HOST}
  namespace: {DEFAULT_NAMESPACE}
  node: {DEFAULT_NODE}
"
    )
}

#[derive(Clone, Debug)]
enum Command {
    Run(RunConfig),
    Server(ServerConfig),
    Client(ClientConfig),
}

impl Command {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut parser = ArgParser::new(args);
        let mode = parser.next_required("mode")?;
        match mode.as_str() {
            "run" => {
                let mut options = SharedOptions::default();
                let mut port = DEFAULT_PORT;
                while let Some(arg) = parser.next() {
                    match arg.as_str() {
                        "--op" => options.operation = Some(parser.parse_value("--op")?),
                        "--port" => port = parser.parse_value("--port")?,
                        "--namespace" => {
                            options.namespace_index = parser.parse_value("--namespace")?
                        }
                        "--node" => options.node_id = parser.parse_value("--node")?,
                        "--warmup" => options.warmup_seconds = parser.parse_value("--warmup")?,
                        "--measure" => options.measure_seconds = parser.parse_value("--measure")?,
                        _ => return Err(format!("unknown run option `{arg}`\n\n{}", usage())),
                    }
                }
                let target = options.target_with_endpoint(endpoint_for_port(port))?;
                Ok(Self::Run(RunConfig {
                    port,
                    operation: options.operation()?,
                    target,
                    timing: options.timing()?,
                }))
            }
            "server" => {
                let mut port = DEFAULT_PORT;
                while let Some(arg) = parser.next() {
                    match arg.as_str() {
                        "--port" => port = parser.parse_value("--port")?,
                        _ => return Err(format!("unknown server option `{arg}`\n\n{}", usage())),
                    }
                }
                Ok(Self::Server(ServerConfig { port }))
            }
            "client" => {
                let mut options = SharedOptions::default();
                while let Some(arg) = parser.next() {
                    match arg.as_str() {
                        "--op" => options.operation = Some(parser.parse_value("--op")?),
                        "--endpoint" => {
                            options.endpoint = Some(parser.next_required("--endpoint")?)
                        }
                        "--namespace" => {
                            options.namespace_index = parser.parse_value("--namespace")?
                        }
                        "--node" => options.node_id = parser.parse_value("--node")?,
                        "--warmup" => options.warmup_seconds = parser.parse_value("--warmup")?,
                        "--measure" => options.measure_seconds = parser.parse_value("--measure")?,
                        _ => return Err(format!("unknown client option `{arg}`\n\n{}", usage())),
                    }
                }
                Ok(Self::Client(ClientConfig {
                    operation: options.operation()?,
                    target: options.target()?,
                    timing: options.timing()?,
                }))
            }
            _ => Err(format!("unknown mode `{mode}`\n\n{}", usage())),
        }
    }
}

#[derive(Clone, Debug)]
struct RunConfig {
    port: u16,
    operation: BenchmarkOperation,
    target: BenchmarkTarget,
    timing: BenchmarkTiming,
}

#[derive(Clone, Debug)]
struct ServerConfig {
    port: u16,
}

#[derive(Clone, Debug)]
struct ClientConfig {
    operation: BenchmarkOperation,
    target: BenchmarkTarget,
    timing: BenchmarkTiming,
}

#[derive(Clone, Debug)]
struct SharedOptions {
    operation: Option<BenchmarkOperation>,
    endpoint: Option<String>,
    namespace_index: u16,
    node_id: u32,
    warmup_seconds: f64,
    measure_seconds: f64,
}

impl Default for SharedOptions {
    fn default() -> Self {
        Self {
            operation: None,
            endpoint: None,
            namespace_index: DEFAULT_NAMESPACE,
            node_id: DEFAULT_NODE,
            warmup_seconds: DEFAULT_WARMUP_SECONDS,
            measure_seconds: DEFAULT_MEASURE_SECONDS,
        }
    }
}

impl SharedOptions {
    fn operation(&self) -> Result<BenchmarkOperation, String> {
        self.operation
            .ok_or_else(|| "missing required --op <read|write>".to_owned())
    }

    fn target(&self) -> Result<BenchmarkTarget, String> {
        let endpoint = self
            .endpoint
            .clone()
            .ok_or_else(|| "missing required --endpoint <url>".to_owned())?;
        self.target_with_endpoint(endpoint)
    }

    fn target_with_endpoint(&self, endpoint: String) -> Result<BenchmarkTarget, String> {
        if endpoint.trim().is_empty() {
            return Err("endpoint must not be empty".to_owned());
        }

        Ok(BenchmarkTarget {
            endpoint,
            namespace_index: self.namespace_index,
            node_id: self.node_id,
        })
    }

    fn timing(&self) -> Result<BenchmarkTiming, String> {
        BenchmarkTiming::new(self.warmup_seconds, self.measure_seconds)
    }
}

#[derive(Clone, Copy, Debug)]
enum BenchmarkOperation {
    Read,
    Write,
}

impl BenchmarkOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

impl fmt::Display for BenchmarkOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for BenchmarkOperation {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            _ => Err(format!(
                "invalid operation `{value}`; expected `read` or `write`"
            )),
        }
    }
}

#[derive(Clone, Debug)]
struct BenchmarkTarget {
    endpoint: String,
    namespace_index: u16,
    node_id: u32,
}

impl BenchmarkTarget {
    fn node_label(&self) -> String {
        format!("ns={};i={}", self.namespace_index, self.node_id)
    }
}

#[derive(Clone, Debug)]
struct BenchmarkTiming {
    warmup: Duration,
    measure: Duration,
}

impl BenchmarkTiming {
    fn new(warmup_seconds: f64, measure_seconds: f64) -> Result<Self, String> {
        if !warmup_seconds.is_finite() || warmup_seconds < 0.0 {
            return Err("warmup duration must be finite and non-negative".to_owned());
        }
        if !measure_seconds.is_finite() || measure_seconds <= 0.0 {
            return Err("measurement duration must be finite and positive".to_owned());
        }

        Ok(Self {
            warmup: Duration::from_secs_f64(warmup_seconds),
            measure: Duration::from_secs_f64(measure_seconds),
        })
    }
}

#[derive(Debug, Serialize)]
struct BenchmarkSample {
    endpoint: String,
    op: &'static str,
    node: String,
    warmup_ok: u64,
    warmup_bad: u64,
    ok: u64,
    bad: u64,
    seconds: f64,
    ops_per_sec: f64,
    first_bad: String,
}

impl BenchmarkSample {
    fn new(
        operation: BenchmarkOperation,
        target: &BenchmarkTarget,
        warmup: OperationCounts,
        measured: OperationCounts,
        elapsed: Duration,
    ) -> Self {
        let seconds = elapsed.as_secs_f64();
        let ops_per_sec = if seconds > 0.0 {
            measured.ok as f64 / seconds
        } else {
            0.0
        };

        Self {
            endpoint: target.endpoint.clone(),
            op: operation.as_str(),
            node: target.node_label(),
            warmup_ok: warmup.ok,
            warmup_bad: warmup.bad,
            ok: measured.ok,
            bad: measured.bad,
            seconds,
            ops_per_sec,
            first_bad: measured
                .first_bad
                .or(warmup.first_bad)
                .unwrap_or_else(good_status),
        }
    }

    fn has_no_failures(&self) -> bool {
        self.warmup_bad == 0 && self.bad == 0
    }

    fn failure_message(&self, operation: BenchmarkOperation) -> String {
        format!(
            "{} sample had {} warmup failures and {} measured failures; first_bad={}",
            operation, self.warmup_bad, self.bad, self.first_bad
        )
    }
}

#[derive(Clone, Debug, Default)]
struct OperationCounts {
    ok: u64,
    bad: u64,
    first_bad: Option<String>,
}

impl OperationCounts {
    fn record_ok(&mut self) {
        self.ok += 1;
    }

    fn record_bad(&mut self, status: String) {
        self.bad += 1;
        if self.first_bad.is_none() {
            self.first_bad = Some(status);
        }
    }
}

fn print_sample(sample: &BenchmarkSample) -> Result<(), String> {
    let json = serde_json::to_string(sample).map_err(|err| err.to_string())?;
    println!("{json}");
    Ok(())
}

fn endpoint_for_port(port: u16) -> String {
    format!("opc.tcp://{DEFAULT_ENDPOINT_HOST}:{port}")
}

fn good_status() -> String {
    "0x00000000".to_owned()
}

async fn run_one_shot(config: RunConfig) -> Result<(), String> {
    let listener = TcpListener::bind((DEFAULT_ENDPOINT_HOST, config.port))
        .await
        .map_err(|err| format!("failed to bind 127.0.0.1:{}: {err}", config.port))?;
    let (server, handle) = build_benchmark_server(config.port)?;
    let server_task = tokio::spawn(async move { server.run_with(listener).await });

    let result = async {
        wait_for_port(config.port).await?;
        let sample = run_client_sample(config.operation, &config.target, &config.timing).await?;
        print_sample(&sample)?;
        if sample.has_no_failures() {
            Ok(())
        } else {
            Err(sample.failure_message(config.operation))
        }
    }
    .await;

    stop_server(handle, server_task).await;
    result
}

async fn run_standalone_server(config: ServerConfig) -> Result<(), String> {
    let listener = TcpListener::bind((DEFAULT_ENDPOINT_HOST, config.port))
        .await
        .map_err(|err| format!("failed to bind 127.0.0.1:{}: {err}", config.port))?;
    let (server, handle) = build_benchmark_server(config.port)?;
    let shutdown = handle.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            shutdown.cancel();
        }
    });
    server.run_with(listener).await
}

async fn run_standalone_client(config: ClientConfig) -> Result<(), String> {
    let sample = run_client_sample(config.operation, &config.target, &config.timing).await?;
    print_sample(&sample)?;
    if sample.has_no_failures() {
        Ok(())
    } else {
        Err(sample.failure_message(config.operation))
    }
}

fn build_benchmark_server(port: u16) -> Result<(opcua::server::Server, ServerHandle), String> {
    let endpoint = endpoint_for_port(port);
    let (server, handle) = ServerBuilder::new_anonymous("async-opcua localhost bench")
        .application_uri(APP_URI)
        .product_uri("urn:async-opcua:bench")
        .host(DEFAULT_ENDPOINT_HOST)
        .port(port)
        .discovery_urls(vec![endpoint])
        .with_node_manager(bench_node_manager())
        .build()?;

    let ns = handle
        .get_namespace_index(BENCH_NAMESPACE_URI)
        .ok_or_else(|| "bench namespace was not registered".to_owned())?;
    if ns != DEFAULT_NAMESPACE {
        return Err(format!(
            "bench namespace index is {ns}, expected {DEFAULT_NAMESPACE}"
        ));
    }

    Ok((server, handle))
}

async fn wait_for_port(port: u16) -> Result<(), String> {
    let started = Instant::now();
    loop {
        match tokio::net::TcpStream::connect((DEFAULT_ENDPOINT_HOST, port)).await {
            Ok(_) => return Ok(()),
            Err(err) if started.elapsed() < READINESS_TIMEOUT => {
                let _ = err;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(err) => {
                return Err(format!(
                    "server did not become reachable on 127.0.0.1:{port}: {err}"
                ));
            }
        }
    }
}

async fn stop_server(handle: ServerHandle, task: JoinHandle<Result<(), String>>) {
    handle.cancel();
    match tokio::time::timeout(Duration::from_secs(5), task).await {
        Ok(Ok(_)) | Ok(Err(_)) | Err(_) => {}
    }
}

async fn run_client_sample(
    operation: BenchmarkOperation,
    target: &BenchmarkTarget,
    timing: &BenchmarkTiming,
) -> Result<BenchmarkSample, String> {
    let (session, event_loop_task) = connect_client(&target.endpoint).await?;
    let warmup = run_phase(&session, operation, target, timing.warmup).await;
    let started = Instant::now();
    let measured = run_phase(&session, operation, target, timing.measure).await;
    let elapsed = started.elapsed();

    let _ = session.disconnect().await;
    event_loop_task.abort();

    Ok(BenchmarkSample::new(
        operation, target, warmup, measured, elapsed,
    ))
}

async fn connect_client(endpoint: &str) -> Result<(Arc<Session>, JoinHandle<StatusCode>), String> {
    let mut client = ClientBuilder::new()
        .application_name("async-opcua localhost bench client")
        .application_uri("urn:async-opcua:localhost-bench-client")
        .product_uri("urn:async-opcua:localhost-bench-client")
        .trust_server_certs(true)
        .session_retry_limit(3)
        .session_retry_initial(Duration::from_millis(100))
        .client()
        .map_err(|errors| errors.join("; "))?;

    let (session, event_loop) = client
        .connect_to_matching_endpoint(
            (
                endpoint,
                SecurityPolicy::None.to_str(),
                MessageSecurityMode::None,
                UserTokenPolicy::anonymous(),
            ),
            IdentityToken::Anonymous,
        )
        .await
        .map_err(|err| err.to_string())?;
    let event_loop_task = event_loop.spawn();

    let connected = tokio::time::timeout(READINESS_TIMEOUT, session.wait_for_connection())
        .await
        .map_err(|_| format!("timed out waiting for client connection to {endpoint}"))?;
    if !connected {
        event_loop_task.abort();
        return Err(format!("client did not connect to {endpoint}"));
    }

    Ok((session, event_loop_task))
}

async fn run_phase(
    session: &Session,
    operation: BenchmarkOperation,
    target: &BenchmarkTarget,
    duration: Duration,
) -> OperationCounts {
    let mut counts = OperationCounts::default();
    let deadline = Instant::now() + duration;
    let mut seed = 0i32;
    while Instant::now() < deadline {
        match perform_operation(session, operation, target, seed).await {
            Ok(()) => counts.record_ok(),
            Err(status) => counts.record_bad(status),
        }
        seed = seed.wrapping_add(1);
    }
    counts
}

async fn perform_operation(
    session: &Session,
    operation: BenchmarkOperation,
    target: &BenchmarkTarget,
    value_seed: i32,
) -> Result<(), String> {
    let node_id = NodeId::new(target.namespace_index, target.node_id);
    match operation {
        BenchmarkOperation::Read => {
            let values = session
                .read(
                    &[ReadValueId::new_value(node_id)],
                    TimestampsToReturn::Neither,
                    0.0,
                )
                .await
                .map_err(|err| status_hex(err.status()))?;
            let value = values
                .first()
                .ok_or_else(|| status_hex(StatusCode::BadNoData))?;
            status_result(value.status())
        }
        BenchmarkOperation::Write => {
            let statuses = session
                .write(&[WriteValue::value_attr(node_id, Variant::from(value_seed))])
                .await
                .map_err(|err| status_hex(err.status()))?;
            let status = statuses
                .first()
                .copied()
                .ok_or_else(|| status_hex(StatusCode::BadNoData))?;
            status_result(status)
        }
    }
}

fn status_result(status: StatusCode) -> Result<(), String> {
    if status.is_good() {
        Ok(())
    } else {
        Err(status_hex(status))
    }
}

fn status_hex(status: StatusCode) -> String {
    format!("0x{:08x}", status.bits())
}

struct BenchNodeManager {
    namespace: NamespaceMetadata,
}

#[async_trait]
impl InMemoryNodeManagerImpl for BenchNodeManager {
    async fn init(&self, _address_space: &mut AddressSpace, _context: ServerContext) {}

    fn name(&self) -> &str {
        "bench"
    }

    fn namespaces(&self) -> Vec<NamespaceMetadata> {
        vec![self.namespace.clone()]
    }

    async fn write(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        nodes_to_write: &mut [&mut WriteNode],
    ) -> Result<(), StatusCode> {
        let address_space = address_space.read();
        let type_tree = context.type_tree.read();

        for write in nodes_to_write {
            let mut node =
                match address_space.validate_node_write(context, write.value(), &*type_tree) {
                    Ok(node) => node,
                    Err(status) => {
                        write.set_status(status);
                        continue;
                    }
                };

            if node.node_class() != NodeClass::Variable
                || write.value().attribute_id != AttributeId::Value
            {
                write.set_status(StatusCode::BadNotWritable);
                continue;
            }

            if write.value().value.value.is_none() {
                write.set_status(StatusCode::BadNothingToDo);
                continue;
            }

            match write_node_value(&context.info, &mut node, write.value()) {
                Ok(()) => write.set_status(StatusCode::Good),
                Err(status) => write.set_status(status),
            }
        }

        Ok(())
    }
}

fn bench_node_manager() -> impl NodeManagerBuilder {
    InMemoryNodeManagerBuilder::new(|context: ServerContext, address_space: &mut AddressSpace| {
        let mut namespace = NamespaceMetadata {
            namespace_uri: BENCH_NAMESPACE_URI.to_owned(),
            ..Default::default()
        };
        {
            let mut type_tree = context.type_tree.write();
            namespace.namespace_index = type_tree
                .namespaces_mut()
                .add_namespace(&namespace.namespace_uri);
        }
        address_space.add_namespace(&namespace.namespace_uri, namespace.namespace_index);

        let bench_node = NodeId::new(namespace.namespace_index, DEFAULT_NODE);
        VariableBuilder::new(&bench_node, "BenchValue", "BenchValue")
            .data_type(DataTypeId::Int32)
            .value(42i32)
            .writable()
            .organized_by(ObjectId::ObjectsFolder)
            .insert(address_space);

        BenchNodeManager { namespace }
    })
}

struct ArgParser {
    args: Vec<String>,
    index: usize,
}

impl ArgParser {
    fn new(args: Vec<String>) -> Self {
        Self { args, index: 0 }
    }

    fn next(&mut self) -> Option<String> {
        let value = self.args.get(self.index).cloned();
        self.index += usize::from(value.is_some());
        value
    }

    fn next_required(&mut self, name: &str) -> Result<String, String> {
        self.next()
            .ok_or_else(|| format!("missing required value for {name}"))
    }

    fn parse_value<T>(&mut self, name: &str) -> Result<T, String>
    where
        T: std::str::FromStr,
        T::Err: fmt::Display,
    {
        let value = self.next_required(name)?;
        value
            .parse()
            .map_err(|err| format!("invalid value `{value}` for {name}: {err}"))
    }
}
