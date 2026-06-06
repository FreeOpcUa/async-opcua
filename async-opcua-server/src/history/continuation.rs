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

        // 2. If the size exceeds max_limit, evict the oldest history continuation point
        if max_limit > 0 && points.len() > max_limit {
            let mut history_keys: Vec<(ByteString, Instant)> = points
                .iter()
                .filter_map(|(k, cp)| {
                    cp.get::<HistoryContinuationPoint>()
                        .map(|hcp| (k.clone(), hcp.last_accessed_at))
                })
                .collect();

            // Sort by last accessed time (oldest first)
            history_keys.sort_by_key(|&(_, last_accessed)| last_accessed);

            let to_remove = points.len() - max_limit;
            for i in 0..to_remove.min(history_keys.len()) {
                points.remove(&history_keys[i].0);
            }
        }
    }
}
