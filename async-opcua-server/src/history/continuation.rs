use crate::session::continuation_points::ContinuationPoint;
use opcua_types::{ByteString, DateTime, NodeId};
use std::time::{Duration, Instant};

/// Historical read continuation point payload structure.
#[derive(Debug, Clone)]
pub struct HistoryContinuationPoint {
    /// The NodeId of the node being read.
    pub node_id: NodeId,
    /// Start time of the read interval.
    pub start_time: DateTime,
    /// End time of the read interval.
    pub end_time: DateTime,
    /// Maximum number of values requested per node.
    pub num_values_per_node: u32,
    /// Whether to return boundary values.
    pub return_bounds: bool,
    /// Optional timestamp cursor tracking the last returned data point.
    pub last_read_time: Option<DateTime>,
    /// Optional continuation point token from the database backend itself.
    pub backend_token: Option<Vec<u8>>,
    /// Monotonic time when this continuation point was created.
    pub created_at: Instant,
    /// Monotonic time when this continuation point was last accessed.
    pub last_accessed_at: Instant,
}

impl HistoryContinuationPoint {
    /// Creates a new historical continuation point.
    pub fn new(
        node_id: NodeId,
        start_time: DateTime,
        end_time: DateTime,
        num_values_per_node: u32,
        return_bounds: bool,
        backend_token: Option<Vec<u8>>,
    ) -> Self {
        let now = Instant::now();
        Self {
            node_id,
            start_time,
            end_time,
            num_values_per_node,
            return_bounds,
            last_read_time: None,
            backend_token,
            created_at: now,
            last_accessed_at: now,
        }
    }

    /// Touch the continuation point to update its last accessed time.
    pub fn touch(&mut self) {
        self.last_accessed_at = Instant::now();
    }
}

/// Helper cache to manage continuation point lifecycles, pruning, and eviction.
#[derive(Clone)]
pub struct HistoryContinuationPointCache {
    cache: moka::sync::Cache<ByteString, std::sync::Arc<parking_lot::Mutex<Option<ContinuationPoint>>>>,
}

impl HistoryContinuationPointCache {
    /// Creates a new HistoryContinuationPointCache.
    pub fn new(max_limit: usize, max_age: Duration) -> Self {
        let builder = moka::sync::Cache::builder();
        let builder = if max_limit > 0 {
            builder.max_capacity(max_limit as u64)
        } else {
            builder
        };
        Self {
            cache: builder
                .time_to_live(max_age)
                .build(),
        }
    }

    /// Insert a continuation point.
    pub fn insert(&self, id: ByteString, cp: ContinuationPoint) {
        self.cache.insert(id, std::sync::Arc::new(parking_lot::Mutex::new(Some(cp))));
    }

    /// Remove a continuation point.
    pub fn remove(&self, id: &ByteString) -> Option<ContinuationPoint> {
        let cp_arc = self.cache.get(id);
        self.cache.invalidate(id);
        cp_arc.and_then(|arc| arc.lock().take())
    }

    /// Check if key exists.
    pub fn contains_key(&self, id: &ByteString) -> bool {
        self.cache.contains_key(id)
    }

    /// Get count of entries in the cache.
    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }

    /// Force cache maintenance tasks to run.
    pub fn run_pending_tasks(&self) {
        self.cache.run_pending_tasks();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::continuation_points::ContinuationPoint;
    use opcua_types::{ByteString, DateTime, NodeId};

    fn history_point() -> ContinuationPoint {
        let point = HistoryContinuationPoint::new(
            NodeId::new(1, "history-node"),
            DateTime::null(),
            DateTime::null(),
            100,
            false,
            None,
        );
        ContinuationPoint::new(Box::new(point))
    }

    #[test]
    fn cache_limits_size_via_eviction() {
        let cache = HistoryContinuationPointCache::new(10, Duration::from_secs(300));
        for i in 0..100 {
            let key = ByteString::from(format!("key-{}", i).into_bytes());
            cache.insert(key, history_point());
        }
        
        // Force moka to process evictions
        cache.run_pending_tasks();
        
        assert!(cache.entry_count() <= 10, "Cache size {} exceeded max capacity 10", cache.entry_count());
    }

    #[test]
    fn cache_removes_expired_history_points() {
        // Use a short TTL of 50ms
        let cache = HistoryContinuationPointCache::new(10, Duration::from_millis(50));
        let active = ByteString::from(b"active");

        cache.insert(active.clone(), history_point());
        assert!(cache.contains_key(&active));

        // Wait for it to expire
        std::thread::sleep(Duration::from_millis(150));

        // Force expiration check
        cache.run_pending_tasks();

        assert!(!cache.contains_key(&active), "Active continuation point was not expired");
    }
}
