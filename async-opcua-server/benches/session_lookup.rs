//! Benchmarks for the O(1) session token lookup registry (spec 006 SC-001).
// criterion_group!/criterion_main! generate undocumented public items that
// trip the workspace-wide `missing_docs` lint under `clippy --all-targets`.
#![allow(missing_docs)]

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
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

fn lookup_fixture(session_count: usize) -> (SessionManager, Vec<NodeId>) {
    let (_server, handle) = ServerBuilder::new_anonymous("session lookup bench")
        .without_node_managers()
        .build()
        .expect("bench server should build");
    let info = Arc::clone(handle.info());
    let manager = SessionManager::new(info.clone(), Arc::new(Notify::new()));
    let mut tokens = Vec::with_capacity(session_count);

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
        manager.register_token(token.clone(), session);
        tokens.push(token);
    }

    (manager, tokens)
}

fn bench_session_lookup(c: &mut Criterion) {
    // Building the server fixture requires a tokio runtime context.
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let _guard = runtime.enter();

    let mut group = c.benchmark_group("session_token_lookup");
    for session_count in [1_000usize, 10_000] {
        let (manager, tokens) = lookup_fixture(session_count);
        let mut index = 0usize;
        group.bench_with_input(
            BenchmarkId::from_parameter(session_count),
            &session_count,
            |b, _| {
                b.iter(|| {
                    index = (index + 31) % tokens.len();
                    std::hint::black_box(manager.find_by_token(&tokens[index]))
                        .expect("registered token should resolve")
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_session_lookup);
criterion_main!(benches);
