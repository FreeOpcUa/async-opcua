//! Notification pool load tests verifying bounded memory under
//! high-frequency subscription update patterns.

use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use opcua_server::{metrics::METRICS, pool::NotificationPool};

const POOL_CAPACITY: usize = 8;
const THREADS: usize = 16;
const CYCLES_PER_THREAD: usize = 10_000;

#[test]
fn high_frequency_acquire_release_keeps_memory_bounded() {
    let pool = Arc::new(NotificationPool::new(POOL_CAPACITY));
    let completed = Arc::new(AtomicUsize::new(0));

    // Warm the pool up; the object pool allocates its backing storage in
    // pages, so the stability invariant is that no further allocation
    // happens once the pool is in use.
    drop(pool.acquire());
    let created_after_warmup = pool.created();

    // Twice as many threads as buffers, hammering the pool. Every acquire
    // beyond capacity must block rather than allocate.
    let mut handles = Vec::with_capacity(THREADS);
    for _ in 0..THREADS {
        let pool = Arc::clone(&pool);
        let completed = Arc::clone(&completed);
        handles.push(thread::spawn(move || {
            for _ in 0..CYCLES_PER_THREAD {
                let buffer = pool.acquire();
                assert!(
                    buffer.is_empty(),
                    "pooled buffers must be handed out clean"
                );
                assert!(
                    pool.active() <= POOL_CAPACITY,
                    "checked-out buffers must never exceed pool capacity"
                );
                drop(buffer);
                completed.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    for handle in handles {
        handle.join().expect("load thread should complete");
    }

    assert_eq!(completed.load(Ordering::Relaxed), THREADS * CYCLES_PER_THREAD);
    assert_eq!(pool.active(), 0, "all buffers must be returned");
    // Memory stability: 160k acquire/release cycles across 16 threads must
    // not allocate any buffers beyond the warmed-up pool.
    assert_eq!(
        pool.created(),
        created_after_warmup,
        "pool must reuse buffers instead of allocating under load"
    );
}

#[test]
fn exhausted_pool_blocks_until_release_and_counts_waits() {
    let pool = Arc::new(NotificationPool::new(1));
    let waits_before = METRICS.pooled_notifications_wait_count.load(Ordering::Relaxed);

    let held = pool.acquire();
    let created_while_held = pool.created();

    let (tx, rx) = std::sync::mpsc::channel();
    let blocked_pool = Arc::clone(&pool);
    let blocked = thread::spawn(move || {
        let buffer = blocked_pool.acquire();
        tx.send(()).expect("main thread should be listening");
        drop(buffer);
    });

    // The second acquire must block while the only buffer is checked out.
    assert!(
        rx.recv_timeout(Duration::from_millis(200)).is_err(),
        "acquire must block while the pool is exhausted"
    );

    drop(held);
    rx.recv_timeout(Duration::from_secs(5))
        .expect("blocked acquire must resume after a buffer is released");
    blocked.join().expect("blocked thread should complete");

    let waits_after = METRICS.pooled_notifications_wait_count.load(Ordering::Relaxed);
    assert!(
        waits_after > waits_before,
        "pool exhaustion must be recorded in the wait-count metric"
    );
    assert_eq!(pool.active(), 0);
    assert_eq!(
        pool.created(),
        created_while_held,
        "blocking must not create extra buffers"
    );
}
