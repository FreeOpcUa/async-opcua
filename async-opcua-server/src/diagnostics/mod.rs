//! This module contains the diagnostics node manager, and related types.

mod node_manager;
mod server;
pub use node_manager::{DiagnosticsNodeManager, DiagnosticsNodeManagerBuilder, NamespaceMetadata};
use opcua_core::sync::Mutex;
use opcua_types::{DataValue, DateTime, IntoVariant};
pub use server::{ServerDiagnostics, ServerDiagnosticsSummary};

#[derive(Default)]
/// Wrapper around a value in memory, used for metrics.
/// We need to use a mutex to keep track of when the value was last
/// updated.
pub struct LocalValue<T> {
    inner: Mutex<LocalValueInner<T>>,
}

#[derive(Default)]
struct LocalValueInner<T> {
    pub value: T,
    pub timestamp: DateTime,
}

impl<T: Clone + IntoVariant> LocalValue<T> {
    /// Create a new LocalValue with the given value.
    pub fn new(value: T) -> Self {
        Self {
            inner: Mutex::new(LocalValueInner {
                value,
                timestamp: DateTime::now(),
            }),
        }
    }

    /// Update the value and set the timestamp.
    pub fn modify(&self, fun: impl FnOnce(&mut T)) {
        let mut inner = self.inner.lock();
        fun(&mut inner.value);
        inner.timestamp = DateTime::now();
    }

    /// Set the value and update the timestamp.
    pub fn set(&self, value: T) {
        let mut inner = self.inner.lock();
        inner.value = value;
        inner.timestamp = DateTime::now();
    }

    /// Get the current value as a datavalue.
    pub fn sample(&self) -> DataValue {
        let inner = self.inner.lock();
        DataValue::new_at(inner.value.clone().into_variant(), inner.timestamp)
    }

    /// Get the current value.
    pub fn get(&self) -> T {
        let inner = self.inner.lock();
        inner.value.clone()
    }

    /// Get the current value and timestamp.
    pub fn get_with_time(&self) -> (T, DateTime) {
        let inner = self.inner.lock();
        (inner.value.clone(), inner.timestamp)
    }
}

impl LocalValue<u32> {
    /// Convenience function to increment the value.
    pub fn increment(&self) {
        self.modify(|v| *v += 1);
    }

    /// Convenience function to decrement the value.
    pub fn decrement(&self) {
        self.modify(|v| {
            *v = v.saturating_sub(1);
        });
    }
}
