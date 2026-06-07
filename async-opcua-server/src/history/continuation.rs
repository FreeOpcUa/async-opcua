use crate::session::continuation_points::ContinuationPoint;
use opcua_types::{ByteString, DateTime, NodeId};
use std::collections::HashMap;
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
pub struct HistoryContinuationPointCache;

impl HistoryContinuationPointCache {
    /// Prunes expired continuation points and evicts the oldest (LRU) history continuation points
    /// if the number of points exceeds the specified maximum limit.
    pub fn prune_and_evict(
        points: &mut HashMap<ByteString, ContinuationPoint>,
        max_limit: usize,
        max_age: Duration,
    ) {
        // 1. Evict expired history continuation points
        points.retain(|_, cp| {
            if let Some(hcp) = cp.get::<HistoryContinuationPoint>() {
                hcp.created_at.elapsed() < max_age
            } else {
                true // keep non-history continuation points or empty ones
            }
        });

        let mut history_keys: Vec<(ByteString, Instant)> = points
            .iter()
            .filter_map(|(k, cp)| {
                cp.get::<HistoryContinuationPoint>()
                    .map(|hcp| (k.clone(), hcp.last_accessed_at))
            })
            .collect();

        // 2. If the history size exceeds max_limit, evict the least recently used points.
        if max_limit > 0 && history_keys.len() > max_limit {
            // Sort by last accessed time (oldest first)
            history_keys.sort_by_key(|&(_, last_accessed)| last_accessed);

            let to_remove = history_keys.len() - max_limit;
            for i in 0..to_remove.min(history_keys.len()) {
                points.remove(&history_keys[i].0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::continuation_points::ContinuationPoint;
    use opcua_types::{ByteString, DateTime, NodeId};

    fn history_point(created_ago: Duration, accessed_ago: Duration) -> ContinuationPoint {
        let now = Instant::now();
        let mut point = HistoryContinuationPoint::new(
            NodeId::new(1, "history-node"),
            DateTime::null(),
            DateTime::null(),
            100,
            false,
            None,
        );
        point.created_at = now - created_ago;
        point.last_accessed_at = now - accessed_ago;
        ContinuationPoint::new(Box::new(point))
    }

    fn non_history_point() -> ContinuationPoint {
        ContinuationPoint::new(Box::new("browse-continuation".to_string()))
    }

    #[test]
    fn prune_and_evict_removes_expired_history_points() {
        let expired = ByteString::from(b"expired");
        let active = ByteString::from(b"active");
        let non_history = ByteString::from(b"non-history");
        let mut points = HashMap::new();
        points.insert(
            expired.clone(),
            history_point(Duration::from_secs(301), Duration::from_secs(1)),
        );
        points.insert(
            active.clone(),
            history_point(Duration::from_secs(60), Duration::from_secs(1)),
        );
        points.insert(non_history.clone(), non_history_point());

        HistoryContinuationPointCache::prune_and_evict(&mut points, 10, Duration::from_secs(300));

        assert!(!points.contains_key(&expired));
        assert!(points.contains_key(&active));
        assert!(points.contains_key(&non_history));
    }

    #[test]
    fn prune_and_evict_removes_least_recently_used_history_points() {
        let oldest = ByteString::from(b"oldest");
        let middle = ByteString::from(b"middle");
        let newest = ByteString::from(b"newest");
        let non_history = ByteString::from(b"non-history");
        let mut points = HashMap::new();
        points.insert(
            oldest.clone(),
            history_point(Duration::from_secs(1), Duration::from_secs(30)),
        );
        points.insert(
            middle.clone(),
            history_point(Duration::from_secs(1), Duration::from_secs(20)),
        );
        points.insert(
            newest.clone(),
            history_point(Duration::from_secs(1), Duration::from_secs(10)),
        );
        points.insert(non_history.clone(), non_history_point());

        HistoryContinuationPointCache::prune_and_evict(&mut points, 2, Duration::from_secs(300));

        assert!(!points.contains_key(&oldest));
        assert!(points.contains_key(&middle));
        assert!(points.contains_key(&newest));
        assert!(points.contains_key(&non_history));
    }
}
