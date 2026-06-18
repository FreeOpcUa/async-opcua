//! Server-side performance metrics.
//!
//! Each server owns its own [`ServerMetrics`] instance, available via
//! `ServerInfo::metrics`, so multiple servers in one process do not share
//! or clobber each other's counters.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Point-in-time copy of server metrics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ServerMetricsSnapshot {
    /// Total number of accepted connections.
    pub connections_total_accepted: u64,
    /// Number of currently active accepted connections.
    pub connections_currently_active: u64,
    /// Total bytes received from transports.
    pub bytes_total_received: u64,
    /// Total bytes sent on transports.
    pub bytes_total_sent: u64,
    /// Total secure channels opened with `SecurityTokenRequestType::Issue`.
    pub secure_channels_opened: u64,
    /// Total secure channels renewed with `SecurityTokenRequestType::Renew`.
    pub secure_channels_renewed: u64,
    /// Number of session authentication token lookups performed.
    pub session_lookup_count: u64,
    /// Total nanoseconds spent in session authentication token lookups.
    pub session_lookup_duration_ns: u64,
    /// Number of serialization errors observed on outbound responses.
    pub serialization_errors: u64,
    /// Number of messages processed by session actors.
    pub actor_messages_processed: u64,
    /// Total nanoseconds spent processing session actor messages.
    pub actor_message_duration_ns: u64,
    /// Peak number of messages observed queued on a single session actor channel.
    pub actor_queue_peak_depth: u64,
}

/// Thread-safe counters and gauges for server performance hot paths.
#[derive(Debug)]
pub struct ServerMetrics {
    /// Total number of accepted connections.
    pub connections_total_accepted: AtomicU64,
    /// Number of currently active accepted connections.
    pub connections_currently_active: AtomicU64,
    /// Total bytes received from transports.
    pub bytes_total_received: AtomicU64,
    /// Total bytes sent on transports.
    pub bytes_total_sent: AtomicU64,
    /// Total secure channels opened with `SecurityTokenRequestType::Issue`.
    pub secure_channels_opened: AtomicU64,
    /// Total secure channels renewed with `SecurityTokenRequestType::Renew`.
    pub secure_channels_renewed: AtomicU64,
    /// Number of session authentication token lookups performed.
    pub session_lookup_count: AtomicU64,
    /// Total nanoseconds spent in session authentication token lookups.
    pub session_lookup_duration_ns: AtomicU64,
    /// Number of serialization errors observed on outbound responses.
    pub serialization_errors: AtomicU64,
    /// Number of messages processed by session actors.
    pub actor_messages_processed: AtomicU64,
    /// Total nanoseconds spent processing session actor messages.
    pub actor_message_duration_ns: AtomicU64,
    /// Peak number of messages observed queued on a single session actor
    /// channel.
    pub actor_queue_peak_depth: AtomicUsize,
}

impl ServerMetrics {
    /// Creates a zero-initialized metrics registry.
    pub const fn new() -> Self {
        Self {
            connections_total_accepted: AtomicU64::new(0),
            connections_currently_active: AtomicU64::new(0),
            bytes_total_received: AtomicU64::new(0),
            bytes_total_sent: AtomicU64::new(0),
            secure_channels_opened: AtomicU64::new(0),
            secure_channels_renewed: AtomicU64::new(0),
            session_lookup_count: AtomicU64::new(0),
            session_lookup_duration_ns: AtomicU64::new(0),
            serialization_errors: AtomicU64::new(0),
            actor_messages_processed: AtomicU64::new(0),
            actor_message_duration_ns: AtomicU64::new(0),
            actor_queue_peak_depth: AtomicUsize::new(0),
        }
    }

    /// Records one accepted connection and marks it active.
    pub fn record_connection_accepted(&self) {
        self.connections_total_accepted
            .fetch_add(1, Ordering::Relaxed);
        self.connections_currently_active
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records one accepted connection closing.
    pub fn record_connection_closed(&self) {
        self.connections_currently_active
            .fetch_sub(1, Ordering::Relaxed);
    }

    /// Records received transport bytes.
    pub fn record_bytes_received(&self, bytes: u64) {
        self.bytes_total_received
            .fetch_add(bytes, Ordering::Relaxed);
    }

    /// Records sent transport bytes.
    pub fn record_bytes_sent(&self, bytes: u64) {
        self.bytes_total_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Records a successfully opened secure channel.
    pub fn record_secure_channel_opened(&self) {
        self.secure_channels_opened.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a successfully renewed secure channel.
    pub fn record_secure_channel_renewed(&self) {
        self.secure_channels_renewed.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the total number of accepted connections.
    pub fn connections_total_accepted(&self) -> u64 {
        self.connections_total_accepted.load(Ordering::Relaxed)
    }

    /// Returns the number of currently active accepted connections.
    pub fn connections_currently_active(&self) -> u64 {
        self.connections_currently_active.load(Ordering::Relaxed)
    }

    /// Returns the total bytes received from transports.
    pub fn bytes_total_received(&self) -> u64 {
        self.bytes_total_received.load(Ordering::Relaxed)
    }

    /// Returns the total bytes sent on transports.
    pub fn bytes_total_sent(&self) -> u64 {
        self.bytes_total_sent.load(Ordering::Relaxed)
    }

    /// Returns the total number of opened secure channels.
    pub fn secure_channels_opened(&self) -> u64 {
        self.secure_channels_opened.load(Ordering::Relaxed)
    }

    /// Returns the total number of renewed secure channels.
    pub fn secure_channels_renewed(&self) -> u64 {
        self.secure_channels_renewed.load(Ordering::Relaxed)
    }

    /// Returns a point-in-time copy of all metrics.
    pub fn snapshot(&self) -> ServerMetricsSnapshot {
        ServerMetricsSnapshot {
            connections_total_accepted: self.connections_total_accepted(),
            connections_currently_active: self.connections_currently_active(),
            bytes_total_received: self.bytes_total_received(),
            bytes_total_sent: self.bytes_total_sent(),
            secure_channels_opened: self.secure_channels_opened(),
            secure_channels_renewed: self.secure_channels_renewed(),
            session_lookup_count: self.session_lookup_count.load(Ordering::Relaxed),
            session_lookup_duration_ns: self.session_lookup_duration_ns.load(Ordering::Relaxed),
            serialization_errors: self.serialization_errors.load(Ordering::Relaxed),
            actor_messages_processed: self.actor_messages_processed.load(Ordering::Relaxed),
            actor_message_duration_ns: self.actor_message_duration_ns.load(Ordering::Relaxed),
            actor_queue_peak_depth: self.actor_queue_peak_depth.load(Ordering::Relaxed) as u64,
        }
    }

    /// Exports a snapshot through a caller-supplied hook when the
    /// `metrics-exporter` feature is enabled.
    #[cfg(feature = "metrics-exporter")]
    pub fn export_with<E>(&self, exporter: &mut E)
    where
        E: ServerMetricsExporter,
    {
        exporter.export(self.snapshot());
    }
}

impl Default for ServerMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Feature-gated hook for exporting server metrics snapshots.
#[cfg(feature = "metrics-exporter")]
pub trait ServerMetricsExporter {
    /// Export a point-in-time metrics snapshot.
    fn export(&mut self, snapshot: ServerMetricsSnapshot);
}

#[cfg(test)]
mod tests {
    use super::ServerMetrics;

    #[test]
    fn snapshot_reads_network_and_secure_channel_counters() {
        let metrics = ServerMetrics::new();

        metrics.record_connection_accepted();
        metrics.record_bytes_received(11);
        metrics.record_bytes_sent(17);
        metrics.record_secure_channel_opened();
        metrics.record_secure_channel_renewed();
        metrics.record_connection_closed();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.connections_total_accepted, 1);
        assert_eq!(snapshot.connections_currently_active, 0);
        assert_eq!(snapshot.bytes_total_received, 11);
        assert_eq!(snapshot.bytes_total_sent, 17);
        assert_eq!(snapshot.secure_channels_opened, 1);
        assert_eq!(snapshot.secure_channels_renewed, 1);
    }
}
