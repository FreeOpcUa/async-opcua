//! Reusable subscription notification scratch buffers.
//!
//! Subscription ticks repeatedly allocate scratch storage while scanning
//! monitored items for notifications. The [`NotificationBuffer`] retains
//! allocations between ticks so steady-state publishing does not allocate.

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
    pub(crate) fn new() -> Self {
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

#[cfg(test)]
mod tests {
    use opcua_types::{DataValue, MonitoredItemNotification};

    use super::{Notification, NotificationBuffer};

    fn notification() -> Notification {
        Notification::MonitoredItemNotification(MonitoredItemNotification {
            client_handle: 1,
            value: DataValue::new_now(1),
        })
    }

    #[test]
    fn reset_clears_contents_and_buffers_are_reused() {
        let mut buffer = NotificationBuffer::new();
        for _ in 0..64 {
            buffer.notifications.push(notification());
        }
        buffer.triggers.push((1, 2));
        assert_eq!(buffer.len(), 64);
        let grown_capacity = buffer.notification_capacity();
        assert!(grown_capacity >= 64);

        for _ in 0..100 {
            buffer.reset();
            assert!(buffer.is_empty());
            assert!(buffer.triggers.is_empty());
            assert_eq!(buffer.notification_capacity(), grown_capacity);
        }
    }
}
