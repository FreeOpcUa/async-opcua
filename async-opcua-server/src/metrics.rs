//! Server-side performance metrics.

use std::sync::atomic::{AtomicU64, AtomicUsize};

/// Thread-safe counters and gauges for server performance hot paths.
#[derive(Debug)]
pub struct ServerMetrics {
    /// Number of session authentication token lookups performed.
    pub session_lookup_count: AtomicU64,
    /// Total nanoseconds spent in session authentication token lookups.
    pub session_lookup_duration_ns: AtomicU64,
    /// Number of pooled subscription notifications currently checked out.
    pub pooled_notifications_active: AtomicUsize,
    /// Total number of pooled subscription notifications managed by the server.
    pub pooled_notifications_total: AtomicUsize,
    /// Number of times notification acquisition had to wait for pool capacity.
    pub pooled_notifications_wait_count: AtomicU64,
    /// Number of serialization errors observed on outbound responses.
    pub serialization_errors: AtomicU64,
}

impl ServerMetrics {
    /// Creates a zero-initialized metrics registry.
    pub const fn new() -> Self {
        Self {
            session_lookup_count: AtomicU64::new(0),
            session_lookup_duration_ns: AtomicU64::new(0),
            pooled_notifications_active: AtomicUsize::new(0),
            pooled_notifications_total: AtomicUsize::new(0),
            pooled_notifications_wait_count: AtomicU64::new(0),
            serialization_errors: AtomicU64::new(0),
        }
    }
}

impl Default for ServerMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Global server metrics registry.
pub static METRICS: ServerMetrics = ServerMetrics::new();
