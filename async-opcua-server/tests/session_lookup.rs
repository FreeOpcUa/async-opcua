//! Session lookup registry regression tests.

use std::{
    hint::black_box,
    sync::Arc,
    time::{Duration, Instant},
};

use opcua_core::sync::RwLock;
use opcua_crypto::SecurityPolicy;
use opcua_server::{
    session::{instance::Session, manager::SessionManager},
    IdentityToken, ServerBuilder,
};
use opcua_types::{
    AnonymousIdentityToken, ApplicationDescription, ByteString, MessageSecurityMode, NodeId,
    UAString,
};
use tokio::sync::Notify;

const SMALL_SESSION_COUNT: usize = 1_000;
const LARGE_SESSION_COUNT: usize = 10_000;
const LOOKUP_ROUNDS: usize = 200_000;
const CONCURRENT_TASKS: usize = 8;
const PER_TASK_LOOKUPS: usize = 5_000;
// The spec target (SC-001) is 10µs; the generous absolute bound keeps the
// test meaningful without flaking on a loaded machine.
const MAX_LOOKUP_NS: u128 = Duration::from_micros(10).as_nanos();

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_token_lookup_stays_constant_and_deregister_removes_token() {
    let small = lookup_fixture(SMALL_SESSION_COUNT);
    let small_average_ns = average_lookup_ns(&small.manager, &small.tokens, LOOKUP_ROUNDS);

    let large = lookup_fixture(LARGE_SESSION_COUNT);
    let large_average_ns = average_lookup_ns(&large.manager, &large.tokens, LOOKUP_ROUNDS);

    let found = large
        .manager
        .find_by_token(&large.probe_token)
        .expect("registered probe token should resolve");
    assert!(Arc::ptr_eq(&found, &large.probe_session));

    assert!(
        large_average_ns < MAX_LOOKUP_NS,
        "average lookup latency must stay below 10µs; small={small_average_ns}ns, large={large_average_ns}ns"
    );
    assert!(
        large_average_ns <= small_average_ns.saturating_mul(4).saturating_add(1_000),
        "lookup latency should remain effectively constant; small={small_average_ns}ns, large={large_average_ns}ns"
    );

    concurrent_lookups(Arc::clone(&large.manager), Arc::clone(&large.tokens)).await;

    large.manager.deregister_token(&large.probe_token);
    assert!(
        large.manager.find_by_token(&large.probe_token).is_none(),
        "deregistered token should be removed from the lookup registry"
    );
}

struct LookupFixture {
    manager: Arc<SessionManager>,
    tokens: Arc<Vec<NodeId>>,
    probe_token: NodeId,
    probe_session: Arc<RwLock<Session>>,
}

fn lookup_fixture(session_count: usize) -> LookupFixture {
    let (_server, handle) = ServerBuilder::new_anonymous("session lookup test")
        .without_node_managers()
        .build()
        .expect("test server should build");
    let info = Arc::clone(handle.info());
    let manager = Arc::new(SessionManager::new(info.clone(), Arc::new(Notify::new())));
    let probe_index = session_count / 2;
    let mut tokens = Vec::with_capacity(session_count);
    let mut probe_token = None;
    let mut probe_session = None;

    for index in 0..session_count {
        let token = NodeId::new(1, index as u32);
        let session = Arc::new(RwLock::new(Session::create(
            &info,
            token.clone(),
            1,
            60_000,
            0,
            0,
            UAString::from("opc.tcp://localhost"),
            SecurityPolicy::None.to_str().to_string(),
            IdentityToken::Anonymous(AnonymousIdentityToken {
                policy_id: UAString::from("anonymous"),
            }),
            None,
            ByteString::null(),
            UAString::from(format!("session-{index}")),
            ApplicationDescription::default(),
            MessageSecurityMode::None,
        )));

        manager.register_token(token.clone(), Arc::clone(&session));

        if index == probe_index {
            probe_token = Some(token.clone());
            probe_session = Some(session);
        }
        tokens.push(token);
    }

    LookupFixture {
        manager,
        tokens: Arc::new(tokens),
        probe_token: probe_token.expect("probe token should be registered"),
        probe_session: probe_session.expect("probe session should be registered"),
    }
}

fn average_lookup_ns(manager: &SessionManager, tokens: &[NodeId], rounds: usize) -> u128 {
    for token in tokens.iter().take(1_024) {
        assert!(manager.find_by_token(token).is_some());
    }

    let started = Instant::now();
    let mut hits = 0;
    for index in 0..rounds {
        let token = black_box(&tokens[index % tokens.len()]);
        if black_box(manager.find_by_token(token)).is_some() {
            hits += 1;
        }
    }

    assert_eq!(hits, rounds);
    started.elapsed().as_nanos() / rounds as u128
}

async fn concurrent_lookups(manager: Arc<SessionManager>, tokens: Arc<Vec<NodeId>>) {
    let mut tasks = Vec::with_capacity(CONCURRENT_TASKS);
    for task_index in 0..CONCURRENT_TASKS {
        let manager = Arc::clone(&manager);
        let tokens = Arc::clone(&tokens);
        tasks.push(tokio::spawn(async move {
            for index in 0..PER_TASK_LOOKUPS {
                let token_index = (index * 31 + task_index) % tokens.len();
                assert!(manager.find_by_token(&tokens[token_index]).is_some());
            }
        }));
    }

    for task in tasks {
        task.await.expect("lookup task should complete");
    }
}
