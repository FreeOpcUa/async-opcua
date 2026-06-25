//! OPC-UA Historical Data Access (HDA) support.
//!
//! Provides traits, continuation point management, permission validation,
//! and pagination helper functions.

/// Storage backend trait definition.
pub mod backend;
/// In-memory continuation point cache and eviction policy.
pub mod continuation;
/// In-memory event history backend.
pub mod event_history;
/// User permission and access level validation.
pub mod permissions;
/// Read raw/modified response formatting and chronological sorting middleware.
pub mod read;

pub use backend::{HistoryCache, HistoryStorageBackend};
pub use continuation::{HistoryContinuationPoint, HistoryContinuationPointCache};
pub use event_history::InMemoryEventHistory;
pub use permissions::{validate_history_read_permission, validate_history_write_permission};
pub use read::{format_history_result, sort_historical_values};
