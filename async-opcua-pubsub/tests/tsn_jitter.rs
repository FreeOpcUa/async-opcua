#![cfg(feature = "tsn")]
// async-opcua-pubsub/tests/tsn_jitter.rs
// This test intentionally fails by asserting jitter > 1ms.
// It uses a stub AF_XDP socket via the `xsk-rs` crate.

use std::time::{Duration, Instant};

#[tokio::test]
#[ignore = "placeholder awaiting real TSN hardware (spec 004 T046): the stub loopback has near-zero jitter so the >1ms assertion always fails"]
async fn tsn_jitter_loopback() {
    // Stub creation of an AF_XDP socket.
    #[allow(unused_imports)]
    use xsk_rs::socket::Socket;
    let _xsk: Option<Socket> = None;

    // Number of packets to send in the burst
    const BURST_SIZE: usize = 1000;

    // Record latencies in seconds
    let mut latencies = Vec::with_capacity(BURST_SIZE);

    for _ in 0..BURST_SIZE {
        // In a real test we would send a packet over the socket here.
        let send_ts = Instant::now();
        // Simulate immediate loopback receive.
        let recv_ts = Instant::now();
        let latency = recv_ts.duration_since(send_ts);
        latencies.push(latency);
    }

    // Compute mean latency
    let total: Duration = latencies.iter().cloned().sum();
    let mean = total / (latencies.len() as u32);

    // Compute jitter as the maximum absolute deviation from the mean
    let jitter = latencies
        .iter()
        .map(|d| if *d > mean { *d - mean } else { mean - *d })
        .max()
        .unwrap_or_else(|| Duration::from_secs(0));

    // The test is expected to fail: we assert that jitter exceeds 1 ms.
    assert!(
        jitter > Duration::from_millis(1),
        "jitter {:?} <= 1 ms",
        jitter
    );
}
