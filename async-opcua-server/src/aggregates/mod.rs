//! Aggregates (Part 13) module.
//! Implements aggregate engines, quality calculation, and middleware.

/// Calculations for various mathematical aggregates.
pub mod engine;
/// Middleware processing history read processed details requests.
pub mod middleware;
/// Quality code evaluation for aggregated data points.
pub mod quality;

pub use engine::{
    compute_processed_intervals, dispatch_aggregate, partition_intervals, supported_aggregates,
    AggregateInput,
};
pub use middleware::{read_processed_aggregates, resolve_stepped};
pub use quality::compute_aggregate_quality;
