//! Stateful resource lifecycle integration tests.

use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc,
    },
    time::Duration,
};

use opcua_core::sync::RwLock;
use opcua_crypto::SecurityPolicy;
use opcua_server::{
    address_space::{AddressSpace, NodeType},
    alarms::{
        transitions::{acknowledge_alarm, confirm_alarm, trigger_alarm_transition},
        ConditionStateMachine,
    },
    diagnostics::NamespaceMetadata,
    fota::{
        cleanup::{cleanup_session, register_session_file},
        file_node::{TemporaryFileNode, TemporaryFileNodeConfig},
    },
    node_manager::memory::{simple_node_manager, SimpleNodeManager},
    programs::{register_program, ProgramState},
    ServerBuilder, ANONYMOUS_USER_TOKEN_ID,
};
use opcua_types::{
    DataEncoding, LocalizedText, MessageSecurityMode, NodeId, NumericRange, StatusCode,
    TimestampsToReturn, Variant,
};

static TEST_COUNTER: AtomicU16 = AtomicU16::new(0);
const STATEFUL_NAMESPACE_URI: &str = "urn:async-opcua:stateful-tests:nodes";

#[test]
fn alarm_transition_acknowledge_and_confirm_update_address_space_state() {
    let mut address_space = AddressSpace::new();
    address_space.add_namespace(STATEFUL_NAMESPACE_URI, 2);
    let source_node_id = NodeId::new(2, "Boiler1");
    let condition = ConditionStateMachine::create_in_address_space(
        &mut address_space,
        "Boiler1",
        "HighPressure",
        source_node_id,
        "High pressure",
    );

    condition.set_acked(&mut address_space, true);
    condition.set_confirmed(&mut address_space, true);

    let event = trigger_alarm_transition(
        &mut address_space,
        &condition,
        true,
        700,
        LocalizedText::new("en", "Pressure high"),
    )
    .expect("active transition should succeed")
    .expect("active transition should emit an alarm event");

    assert!(event.active_state);
    assert!(!event.acked_state);
    assert!(!event.confirmed_state);
    assert!(condition.get_active(&address_space));
    assert!(!condition.get_acked(&address_space));
    assert!(!condition.get_confirmed(&address_space));
    assert!(condition.get_retain(&address_space));

    acknowledge_alarm(
        &mut address_space,
        &condition,
        LocalizedText::new("en", "operator acknowledged"),
    )
    .expect("acknowledge should succeed");

    assert!(condition.get_acked(&address_space));
    assert!(!condition.get_confirmed(&address_space));
    assert!(bool_variable(&address_space, &condition.acked_state_id));
    assert!(!bool_variable(
        &address_space,
        &condition.confirmed_state_id
    ));
    assert!(condition.get_retain(&address_space));

    trigger_alarm_transition(
        &mut address_space,
        &condition,
        false,
        100,
        LocalizedText::new("en", "Pressure normal"),
    )
    .expect("inactive transition should succeed")
    .expect("inactive transition should emit an alarm event");

    assert!(!condition.get_active(&address_space));
    assert!(condition.get_retain(&address_space));

    confirm_alarm(
        &mut address_space,
        &condition,
        LocalizedText::new("en", "operator confirmed"),
    )
    .expect("confirm should succeed");

    assert!(condition.get_confirmed(&address_space));
    assert!(bool_variable(&address_space, &condition.confirmed_state_id));
    assert!(!condition.get_retain(&address_space));
    assert!(!bool_variable(&address_space, &condition.retain_id));
}

#[tokio::test]
async fn program_control_methods_update_state_and_progress_variables() {
    let fixture = ProgramFixture::new("program_control_methods");
    let engine = register_program(
        fixture.node_manager.address_space(),
        &fixture.node_manager,
        "Cell1",
        "Batch",
    );

    assert_eq!(engine.state(), ProgramState::Halted);
    assert_eq!(string_variable(&fixture, "CurrentState"), "Halted");

    engine.reset().expect("reset should transition to Ready");
    assert_eq!(engine.state(), ProgramState::Ready);
    assert_eq!(string_variable(&fixture, "CurrentState"), "Ready");

    engine.start().expect("start should transition to Running");
    assert_eq!(engine.state(), ProgramState::Running);
    assert_eq!(string_variable(&fixture, "CurrentState"), "Running");
    assert_eq!(
        engine
            .start()
            .expect_err("starting while running should fail"),
        StatusCode::BadStateNotActive
    );

    tokio::time::sleep(Duration::from_millis(35)).await;
    assert!(engine.progress() > 0);
    assert!(int32_variable(&fixture, "Progress") > 0);

    engine
        .suspend()
        .expect("suspend should transition to Suspended");
    assert_eq!(engine.state(), ProgramState::Suspended);
    assert_eq!(string_variable(&fixture, "CurrentState"), "Suspended");

    engine
        .resume()
        .expect("resume should transition to Running");
    assert_eq!(engine.state(), ProgramState::Running);
    assert_eq!(string_variable(&fixture, "CurrentState"), "Running");

    engine.halt().expect("halt should transition to Halted");
    assert_eq!(engine.state(), ProgramState::Halted);
    assert_eq!(string_variable(&fixture, "CurrentState"), "Halted");
}

#[test]
fn cleanup_session_deletes_temporary_file_nodes_and_backing_file() {
    let address_space = Arc::new(RwLock::new(AddressSpace::new()));
    let session_id = NodeId::new(0, format!("stateful-cleanup-{}", std::process::id()));
    let backing_file = unique_temp_path("stateful-cleanup", "bin");
    std::fs::write(&backing_file, b"temporary firmware")
        .expect("temporary backing file should be written");

    let file_node: TemporaryFileNode = {
        let mut address_space = address_space.write();
        TemporaryFileNode::create(
            &mut address_space,
            TemporaryFileNodeConfig::new(2, session_id.clone(), "firmware.bin"),
        )
        .expect("temporary FileType nodes should be created")
    };
    let node_ids = file_node.node_ids();

    register_session_file(
        session_id.clone(),
        &address_space,
        &file_node,
        Some(backing_file.clone()),
    );
    let report = cleanup_session(&session_id);

    assert_eq!(report.resources, 1);
    assert_eq!(report.files, 1);
    assert_eq!(report.nodes, node_ids.len());
    assert_eq!(report.errors, 0);
    assert!(!backing_file.exists());

    let address_space = address_space.read();
    for node_id in node_ids {
        assert!(
            address_space.find(&node_id).is_none(),
            "expected cleanup to delete FileType node {node_id}"
        );
    }
}

struct ProgramFixture {
    node_manager: Arc<SimpleNodeManager>,
    temp_dir: PathBuf,
}

impl ProgramFixture {
    fn new(test_name: &str) -> Self {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp_dir = std::env::temp_dir().join(format!(
            "async-opcua-stateful-{test_name}-{}-{id}",
            std::process::id()
        ));
        let namespace = NamespaceMetadata {
            namespace_uri: STATEFUL_NAMESPACE_URI.to_string(),
            namespace_index: 2,
            ..Default::default()
        };

        let server = ServerBuilder::new()
            .application_name("stateful_tests")
            .application_uri("urn:async-opcua:stateful-tests")
            .product_uri("urn:async-opcua:stateful-tests")
            .host("127.0.0.1")
            .pki_dir(temp_dir.join("server-pki"))
            .create_sample_keypair(true)
            .discovery_urls(vec!["opc.tcp://127.0.0.1:0/".to_string()])
            .add_endpoint(
                "none",
                (
                    "/",
                    SecurityPolicy::None,
                    MessageSecurityMode::None,
                    &[ANONYMOUS_USER_TOKEN_ID] as &[&str],
                ),
            )
            .with_node_manager(simple_node_manager(namespace, "stateful-test"));

        let (_server, handle) = server.build().expect("build stateful test server");
        let node_manager = handle
            .node_managers()
            .get_of_type::<SimpleNodeManager>()
            .expect("SimpleNodeManager");

        Self {
            node_manager,
            temp_dir,
        }
    }

    fn program_node_id(&self, suffix: &str) -> NodeId {
        NodeId::new(2, format!("Program_Cell1_Batch_{suffix}"))
    }
}

impl Drop for ProgramFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.temp_dir);
    }
}

fn unique_temp_path(prefix: &str, extension: &str) -> PathBuf {
    let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "async-opcua-{prefix}-{}-{id}.{extension}",
        std::process::id()
    ))
}

fn bool_variable(address_space: &AddressSpace, node_id: &NodeId) -> bool {
    match variable_value(address_space, node_id) {
        Variant::Boolean(value) => value,
        other => panic!("expected Boolean value for {node_id}, got {other:?}"),
    }
}

fn int32_variable(fixture: &ProgramFixture, suffix: &str) -> i32 {
    let node_id = fixture.program_node_id(suffix);
    let address_space = fixture.node_manager.address_space().read();
    match variable_value(&address_space, &node_id) {
        Variant::Int32(value) => value,
        other => panic!("expected Int32 value for {node_id}, got {other:?}"),
    }
}

fn string_variable(fixture: &ProgramFixture, suffix: &str) -> String {
    let node_id = fixture.program_node_id(suffix);
    let address_space = fixture.node_manager.address_space().read();
    match variable_value(&address_space, &node_id) {
        Variant::String(value) if !value.is_null() => value.as_ref().to_owned(),
        other => panic!("expected String value for {node_id}, got {other:?}"),
    }
}

fn variable_value(address_space: &AddressSpace, node_id: &NodeId) -> Variant {
    let node_guard = address_space.find(node_id);
    let Some(NodeType::Variable(var)) = node_guard.as_deref() else {
        panic!("expected variable node {node_id}");
    };

    var.value(
        TimestampsToReturn::Neither,
        &NumericRange::None,
        &DataEncoding::Binary,
        0.0,
    )
    .value
    .expect("variable should have a value")
}
