//! Reusable allocation pool for subscription notification scratch buffers.
//!
//! Subscription ticks repeatedly allocate scratch storage while scanning
//! monitored items for notifications. The [`NotificationPool`] bounds and
//! reuses that storage so steady-state publishing does not allocate.

use std::{
    ops::{Deref, DerefMut},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
};

use lockfree_object_pool::{LinearObjectPool, LinearReusable};
use parking_lot::{Condvar, Mutex};

use crate::metrics::ServerMetrics;

use super::monitored_item::Notification;

/// Scratch buffers used while scanning monitored items for notifications.
///
/// The buffers retain their capacity when returned to the pool, so a
/// subscription that repeatedly produces notifications reuses the same
/// allocations on every tick.
#[derive(Debug, Default)]
pub struct NotificationBuffer {
    pub(crate) notifications: Vec<Notification>,
    pub(crate) triggers: Vec<(u32, u32)>,
}

impl NotificationBuffer {
    fn new() -> Self {
        Self::default()
    }

    /// Clear the buffer contents for reuse, retaining allocated capacity.
    pub(crate) fn reset(&mut self) {
        self.notifications.clear();
        self.triggers.clear();
    }

    /// Number of notifications currently held in the buffer.
    pub fn len(&self) -> usize {
        self.notifications.len()
    }

    /// Whether the buffer holds no notifications.
    pub fn is_empty(&self) -> bool {
        self.notifications.is_empty()
    }

    /// Allocated capacity of the notification storage.
    pub fn notification_capacity(&self) -> usize {
        self.notifications.capacity()
    }
}

/// Lock-free reuse pool for notification scratch buffers.
///
/// Holds at most `capacity` buffers checked out at any one time, enforcing
/// a strict bound on notification scratch memory.
pub struct NotificationPool {
    pool: LinearObjectPool<NotificationBuffer>,
    capacity: usize,
    active: AtomicUsize,
    created: Arc<AtomicUsize>,
    waits: AtomicU64,
    metrics: Option<Arc<ServerMetrics>>,
    wait_lock: Mutex<()>,
    wait_cvar: Condvar,
}

impl NotificationPool {
    /// Create a pool allowing at most `capacity` concurrently checked-out buffers.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero, since acquiring from an empty pool
    /// would block forever.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "notification pool capacity must be non-zero");
        let created = Arc::new(AtomicUsize::new(0));
        let created_in_init = Arc::clone(&created);
        Self {
            pool: LinearObjectPool::new(
                move || {
                    created_in_init.fetch_add(1, Ordering::Relaxed);
                    NotificationBuffer::new()
                },
                NotificationBuffer::reset,
            ),
            capacity,
            active: AtomicUsize::new(0),
            created,
            waits: AtomicU64::new(0),
            metrics: None,
            wait_lock: Mutex::new(()),
            wait_cvar: Condvar::new(),
        }
    }

    /// Publish pool statistics to the given server metrics registry.
    pub fn with_metrics(mut self, metrics: Arc<ServerMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Acquire a buffer from the pool.
    ///
    /// If all `capacity` buffers are checked out this blocks until one is
    /// released, enforcing a strict bound on notification scratch memory.
    pub fn acquire(&self) -> PooledNotificationBuffer<'_> {
        if !self.try_claim_slot() {
            self.waits.fetch_add(1, Ordering::Relaxed);
            if let Some(metrics) = &self.metrics {
                metrics
                    .pooled_notifications_wait_count
                    .fetch_add(1, Ordering::Relaxed);
            }
            let mut guard = self.wait_lock.lock();
            while !self.try_claim_slot() {
                self.wait_cvar.wait(&mut guard);
            }
        }

        let buffer = PooledNotificationBuffer {
            inner: Some(self.pool.pull()),
            pool: self,
        };
        self.publish_stats();
        buffer
    }

    /// Attempt to claim one of the pool's capacity slots.
    fn try_claim_slot(&self) -> bool {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.capacity).then_some(active + 1)
            })
            .is_ok()
    }

    /// Maximum number of concurrently checked-out buffers.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of buffers currently checked out.
    pub fn active(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    /// Total number of buffers ever created by this pool.
    pub fn created(&self) -> usize {
        self.created.load(Ordering::Relaxed)
    }

    /// Number of times acquisition had to wait for pool capacity.
    pub fn waits(&self) -> u64 {
        self.waits.load(Ordering::Relaxed)
    }

    /// Publish active/total gauges to the attached metrics registry, if any.
    fn publish_stats(&self) {
        if let Some(metrics) = &self.metrics {
            metrics
                .pooled_notifications_active
                .store(self.active(), Ordering::Relaxed);
            metrics
                .pooled_notifications_total
                .store(self.created(), Ordering::Relaxed);
        }
    }
}

impl std::fmt::Debug for NotificationPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotificationPool")
            .field("capacity", &self.capacity)
            .field("active", &self.active)
            .field("created", &self.created)
            .finish()
    }
}

/// RAII guard for a pooled [`NotificationBuffer`].
///
/// Returns the buffer to the pool when dropped.
pub struct PooledNotificationBuffer<'a> {
    inner: Option<LinearReusable<'a, NotificationBuffer>>,
    pool: &'a NotificationPool,
}

impl Deref for PooledNotificationBuffer<'_> {
    type Target = NotificationBuffer;

    fn deref(&self) -> &NotificationBuffer {
        self.inner.as_ref().expect("buffer present until drop")
    }
}

impl DerefMut for PooledNotificationBuffer<'_> {
    fn deref_mut(&mut self) -> &mut NotificationBuffer {
        self.inner.as_mut().expect("buffer present until drop")
    }
}

impl Drop for PooledNotificationBuffer<'_> {
    fn drop(&mut self) {
        // Return the buffer to the pool before releasing the capacity slot.
        drop(self.inner.take());
        self.pool.active.fetch_sub(1, Ordering::AcqRel);
        self.pool.publish_stats();
        // Take the wait lock so the notification cannot race with a waiter
        // that failed to claim a slot but has not yet started waiting.
        let _guard = self.pool.wait_lock.lock();
        self.pool.wait_cvar.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use opcua_types::{DataValue, MonitoredItemNotification};

    use super::{Notification, NotificationPool};

    fn notification() -> Notification {
        Notification::MonitoredItemNotification(MonitoredItemNotification {
            client_handle: 1,
            value: DataValue::new_now(1),
        })
    }

    #[test]
    fn reset_clears_contents_and_buffers_are_reused() {
        let pool = NotificationPool::new(2);

        let grown_capacity = {
            let mut buffer = pool.acquire();
            for _ in 0..64 {
                buffer.notifications.push(notification());
            }
            buffer.triggers.push((1, 2));
            assert_eq!(buffer.len(), 64);
            buffer.notification_capacity()
        };
        assert!(grown_capacity >= 64);

        // The underlying object pool allocates in pages; what matters is
        // that buffers come back clean and no further allocation happens
        // on reuse.
        let created_after_growth = pool.created();
        for _ in 0..100 {
            let buffer = pool.acquire();
            assert!(buffer.is_empty());
            assert!(buffer.triggers.is_empty());
        }
        assert_eq!(pool.created(), created_after_growth);
    }

    #[test]
    fn capacity_bounds_concurrent_checkouts() {
        let pool = NotificationPool::new(2);
        let first = pool.acquire();
        let second = pool.acquire();
        assert_eq!(pool.active(), 2);
        let created_at_capacity = pool.created();
        drop(first);
        let third = pool.acquire();
        assert_eq!(pool.active(), 2);
        drop(second);
        drop(third);
        assert_eq!(pool.active(), 0);
        assert_eq!(pool.created(), created_at_capacity);
    }
}
