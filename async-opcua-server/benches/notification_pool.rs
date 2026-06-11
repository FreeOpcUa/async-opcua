//! Benchmarks for the subscription notification buffer pool (spec 006 SC-004).

use criterion::{criterion_group, criterion_main, Criterion};
use opcua_server::pool::NotificationPool;

fn bench_notification_pool(c: &mut Criterion) {
    let mut group = c.benchmark_group("notification_pool");

    let pool = NotificationPool::new(1024);
    group.bench_function("acquire_release", |b| {
        b.iter(|| {
            let buffer = pool.acquire();
            std::hint::black_box(buffer.is_empty());
        })
    });

    // Hold several buffers at once, mimicking many subscriptions ticking in
    // parallel without releasing immediately.
    group.bench_function("acquire_release_batch_8", |b| {
        b.iter(|| {
            let buffers: Vec<_> = (0..8).map(|_| pool.acquire()).collect();
            std::hint::black_box(buffers.len());
        })
    });

    group.finish();
}

criterion_group!(benches, bench_notification_pool);
criterion_main!(benches);
