use std::{sync::Arc, time::Duration};

use crate::utils::{default_server, Tester};
use opcua::{
    server::node_manager::memory::{simple_node_manager, SimpleNodeManager},
    types::{NodeId, StatusCode},
};
use opcua_client::program_client::*;
use opcua_server::programs::{register_program, ProgramEngine};
use tokio::time::timeout;

pub async fn setup_programs() -> (
    Tester,
    Arc<SimpleNodeManager>,
    Arc<opcua_client::Session>,
    Arc<ProgramEngine>,
) {
    let namespace = opcua::server::diagnostics::NamespaceMetadata {
        namespace_uri: "urn:rustopcuatestserver".to_owned(),
        namespace_index: 2,
        ..Default::default()
    };
    let simple_mgr = simple_node_manager(namespace, "test");
    let server = default_server().with_node_manager(simple_mgr);
    let mut tester = Tester::new(server, false).await;
    let nm = tester
        .handle
        .node_managers()
        .get_of_type::<SimpleNodeManager>()
        .expect("SimpleNodeManager not found");
    let (session, lp) = tester.connect_default().await.unwrap();
    lp.spawn();
    timeout(Duration::from_secs(2), session.wait_for_connection())
        .await
        .unwrap();

    // Register Program
    let engine = register_program(nm.address_space(), &nm, "Device1", "TestProgram");

    (tester, nm, session, engine)
}

#[tokio::test]
async fn test_program_lifecycle() {
    let (_tester, _nm, session, _engine) = setup_programs().await;
    let program_id = NodeId::new(2, "Program_Device1_TestProgram");

    // 1. Check initial state is Halted
    let state = read_program_state(&session, &program_id).await.unwrap();
    assert_eq!(state, "Halted");

    // 2. Reset the program to Ready
    reset_program(&session, &program_id).await.unwrap();
    let state = read_program_state(&session, &program_id).await.unwrap();
    assert_eq!(state, "Ready");

    // 3. Start the program
    start_program(&session, &program_id).await.unwrap();
    let state = read_program_state(&session, &program_id).await.unwrap();
    assert_eq!(state, "Running");

    // 4. Wait a little and check progress is > 0
    let mut progress = 0;
    for _ in 0..50 {
        progress = read_program_progress(&session, &program_id).await.unwrap();
        if progress > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(progress > 0 && progress <= 100);

    // 5. Suspend the program
    suspend_program(&session, &program_id).await.unwrap();
    let state = read_program_state(&session, &program_id).await.unwrap();
    assert_eq!(state, "Suspended");

    // Record progress at suspension (after allowing the current iteration to finish/block)
    tokio::time::sleep(Duration::from_millis(15)).await;
    let progress_at_suspend = read_program_progress(&session, &program_id).await.unwrap();

    // Wait and verify progress has not changed while suspended
    tokio::time::sleep(Duration::from_millis(50)).await;
    let progress_now = read_program_progress(&session, &program_id).await.unwrap();
    assert_eq!(progress_now, progress_at_suspend);

    // 6. Resume the program
    resume_program(&session, &program_id).await.unwrap();
    let state = read_program_state(&session, &program_id).await.unwrap();
    assert_eq!(state, "Running");

    // Wait for it to finish (it goes from 1 to 100, sleeping 10ms per loop, so ~1 sec total)
    // We check periodically for state to transition back to Halted
    let mut finished = false;
    for _ in 0..150 {
        let state = read_program_state(&session, &program_id).await.unwrap();
        if state == "Halted" {
            finished = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        finished,
        "Program did not transition to Halted on completion"
    );

    let progress = read_program_progress(&session, &program_id).await.unwrap();
    assert_eq!(progress, 100);
}

#[tokio::test]
async fn test_program_halt() {
    let (_tester, _nm, session, _engine) = setup_programs().await;
    let program_id = NodeId::new(2, "Program_Device1_TestProgram");

    // Initial state is Halted, Reset to Ready
    reset_program(&session, &program_id).await.unwrap();
    let state = read_program_state(&session, &program_id).await.unwrap();
    assert_eq!(state, "Ready");

    // Start program
    start_program(&session, &program_id).await.unwrap();
    let state = read_program_state(&session, &program_id).await.unwrap();
    assert_eq!(state, "Running");

    // Halt program
    halt_program(&session, &program_id).await.unwrap();
    let state = read_program_state(&session, &program_id).await.unwrap();
    assert_eq!(state, "Halted");
}

/// Part 10 ProgramStateMachineType: a control method invoked from a state that does not permit it
/// returns Bad_StateNotActive. The lifecycle tests cover the valid transitions; this locks in the
/// guards (the error paths the happy-path tests skip).
#[tokio::test]
async fn program_invalid_transitions_return_bad_state() {
    let (_tester, _nm, session, _engine) = setup_programs().await;
    let id = NodeId::new(2, "Program_Device1_TestProgram");

    // Initial state is Halted: only Reset is valid — Start/Suspend/Resume/Halt are all rejected.
    for r in [
        start_program(&session, &id).await,
        suspend_program(&session, &id).await,
        resume_program(&session, &id).await,
        halt_program(&session, &id).await,
    ] {
        assert_eq!(r.unwrap_err().status(), StatusCode::BadStateNotActive);
    }

    // Reset -> Ready. From Ready only Start/Halt are valid — Reset/Suspend/Resume are rejected.
    reset_program(&session, &id).await.unwrap();
    assert_eq!(read_program_state(&session, &id).await.unwrap(), "Ready");
    for r in [
        reset_program(&session, &id).await,
        suspend_program(&session, &id).await,
        resume_program(&session, &id).await,
    ] {
        assert_eq!(r.unwrap_err().status(), StatusCode::BadStateNotActive);
    }
}
