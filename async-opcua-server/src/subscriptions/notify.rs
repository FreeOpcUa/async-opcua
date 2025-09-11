use hashbrown::HashMap;
use opcua_nodes::Event;
use opcua_types::{node_id::IntoNodeIdRef, AttributeId, DataValue, DateTime, ObjectId, Variant};
use parking_lot::RwLockReadGuard;

use crate::{
    subscriptions::{MonitoredItemEntry, MonitoredItemKeyRef, SubscriptionCacheInner},
    MonitoredItemHandle,
};

/// Handle for notifying the subscription cache of a batch of changes,
/// without allocating NodeIds unnecessarily.
/// Notifications are actually submitted once the notifier is dropped.
pub struct SubscriptionDataNotifier<'a> {
    lock: RwLockReadGuard<'a, SubscriptionCacheInner>,
    by_subscription: HashMap<u32, Vec<(MonitoredItemHandle, DataValue)>>,
}

/// Notifier for a specific node.
pub struct SubscriptionDataNotifierBatch<'a> {
    items: &'a HashMap<MonitoredItemHandle, MonitoredItemEntry>,
    by_subscription: &'a mut HashMap<u32, Vec<(MonitoredItemHandle, DataValue)>>,
}

impl<'a> SubscriptionDataNotifierBatch<'a> {
    /// Notify the referenced node of a change in value by providing a DataValue.
    pub fn data_value(&mut self, value: impl Into<DataValue>) {
        let dv = value.into();
        for (handle, entry) in self.items {
            if !entry.enabled {
                continue;
            }
            self.by_subscription
                .entry(handle.subscription_id)
                .or_default()
                .push((*handle, dv.clone()));
        }
    }

    /// Submit a data value to a specific monitored item.
    pub fn data_value_to_item(
        &mut self,
        value: impl Into<DataValue>,
        handle: &MonitoredItemHandle,
    ) {
        self.by_subscription
            .entry(handle.subscription_id)
            .or_default()
            .push((*handle, value.into()));
    }

    /// Notify the referenced node of a change in value by providing a Variant and source timestamp.
    pub fn value(&mut self, value: impl Into<Variant>, source_timestamp: DateTime) {
        let dv = DataValue::new_at(value, source_timestamp);
        self.data_value(dv);
    }

    /// Get an iterator over the matched monitored item entries. This can be used to
    /// conditionally sample using parameters for each monitored item.
    ///
    /// This only returns monitored item entries that are enabled.
    pub fn entries<'b>(
        &'b self,
    ) -> impl Iterator<Item = (&'a MonitoredItemHandle, &'a MonitoredItemEntry)> + 'a {
        self.items.iter().filter(|e| e.1.enabled)
    }
}

impl<'a> SubscriptionDataNotifier<'a> {
    pub(super) fn new(lock: RwLockReadGuard<'a, SubscriptionCacheInner>) -> Self {
        Self {
            lock,
            by_subscription: Default::default(),
        }
    }

    /// Maybe sample for the given node ID and attribute ID.
    ///
    /// This allows you to only sample when a user is listening.
    ///
    /// # Example
    ///
    /// ```ignore
    /// if let Some(mut notif) = notifier.notify_for((1, 123), AttributeId::Value) {
    ///     notif.value(Variant::Int32(42), DateTime::now());
    ///     notif.value(Variant::Int32(45), DateTime::now());
    /// }
    /// ```
    pub fn notify_for<'b, 'c>(
        &'b mut self,
        node_id: impl IntoNodeIdRef<'c>,
        attribute_id: AttributeId,
    ) -> Option<SubscriptionDataNotifierBatch<'b>> {
        if attribute_id == AttributeId::EventNotifier {
            return None;
        }

        let items = self.lock.monitored_items.get(&MonitoredItemKeyRef {
            id: node_id.into_node_id_ref(),
            attribute_id,
        })?;
        Some(SubscriptionDataNotifierBatch {
            items,
            by_subscription: &mut self.by_subscription,
        })
    }

    /// Notify the subscription cache of a change in value for the given node ID and attribute ID.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node ID or reference to node ID for the changed node.
    /// * `attribute_id` - The attribute ID of the changed value. Note that this may not be EventNotifier.
    /// * `value` - The new value as a DataValue or something convertible to a DataValue.
    pub fn notify(
        &mut self,
        node_id: impl IntoNodeIdRef<'a>,
        attribute_id: AttributeId,
        value: impl Into<DataValue>,
    ) {
        if let Some(mut batch) = self.notify_for(node_id, attribute_id) {
            batch.data_value(value);
        }
    }
}

impl<'a> Drop for SubscriptionDataNotifier<'a> {
    fn drop(&mut self) {
        for (sub_id, items) in std::mem::take(&mut self.by_subscription) {
            let Some(session_id) = self.lock.subscription_to_session.get(&sub_id) else {
                continue;
            };
            let Some(cache) = self.lock.session_subscriptions.get(session_id) else {
                continue;
            };
            let mut cache_lck = cache.lock();
            cache_lck.notify_data_changes(items);
        }
    }
}

/// Handle for notifying the subscription cache of a batch of events,
/// without allocating NodeIds unnecessarily.
/// Notifications are actually submitted once the notifier is dropped.
pub struct SubscriptionEventNotifier<'a, 'b> {
    lock: RwLockReadGuard<'a, SubscriptionCacheInner>,
    by_subscription: HashMap<u32, Vec<(MonitoredItemHandle, &'b dyn Event)>>,
}

/// Notifier for a specific node emitting events.
pub struct SubscriptionEventNotifierBatch<'a, 'b> {
    // An event may notify on both the server, and an emitting node.
    // So we may in some cases need two maps of monitored item entries.
    items: &'a HashMap<MonitoredItemHandle, MonitoredItemEntry>,
    items_2: Option<&'a HashMap<MonitoredItemHandle, MonitoredItemEntry>>,
    by_subscription: &'a mut HashMap<u32, Vec<(MonitoredItemHandle, &'b dyn Event)>>,
}

impl<'a, 'b> SubscriptionEventNotifierBatch<'a, 'b> {
    /// Notify the referenced node of a new event.
    pub fn event(&mut self, event: &'b dyn Event) {
        for (handle, entry) in self
            .items
            .iter()
            .chain(self.items_2.iter().flat_map(|v| v.iter()))
        {
            if !entry.enabled {
                continue;
            }
            self.by_subscription
                .entry(handle.subscription_id)
                .or_default()
                .push((*handle, event));
        }
    }
}

impl<'a, 'b> SubscriptionEventNotifier<'a, 'b> {
    pub(super) fn new(lock: RwLockReadGuard<'a, SubscriptionCacheInner>) -> Self {
        Self {
            lock,
            by_subscription: Default::default(),
        }
    }

    /// Maybe get a notifier for the given node ID and attribute ID.
    ///
    /// This allows you to only sample when a user is listening.
    ///
    /// # Example
    ///
    /// ```ignore
    /// if let Some(mut notif) = notifier.notify_for((1, 123)) {
    ///     notif.event(&my_event);
    ///     notif.event(&my_other_event);
    /// }
    /// ```
    pub fn notify_for<'c>(
        &'c mut self,
        node_id: impl IntoNodeIdRef<'a>,
    ) -> Option<SubscriptionEventNotifierBatch<'c, 'b>> {
        let id_ref = node_id.into_node_id_ref();
        let is_server = id_ref == ObjectId::Server;
        let items = self.lock.monitored_items.get(&MonitoredItemKeyRef {
            id: id_ref,
            attribute_id: AttributeId::EventNotifier,
        });
        let server_items = if !is_server {
            self.lock.monitored_items.get(&MonitoredItemKeyRef {
                id: ObjectId::Server.into_node_id_ref(),
                attribute_id: AttributeId::EventNotifier,
            })
        } else {
            None
        };

        let (items, items_2) = match (items, server_items) {
            (None, Some(v)) | (Some(v), None) => (v, None),
            (Some(v), Some(v2)) => (v, Some(v2)),
            (None, None) => return None,
        };

        Some(SubscriptionEventNotifierBatch {
            items,
            items_2,
            by_subscription: &mut self.by_subscription,
        })
    }

    /// Notify the subscription cache of a new event for the given node ID and attribute ID.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node ID or reference to node ID for the node emitting the event.
    /// * `event` - The event to notify the server of.
    pub fn notify(&mut self, node_id: impl IntoNodeIdRef<'a>, event: &'b dyn Event) {
        if let Some(mut batch) = self.notify_for(node_id) {
            batch.event(event);
        }
    }
}

impl<'a, 'b> Drop for SubscriptionEventNotifier<'a, 'b> {
    fn drop(&mut self) {
        for (sub_id, items) in std::mem::take(&mut self.by_subscription) {
            let Some(session_id) = self.lock.subscription_to_session.get(&sub_id) else {
                continue;
            };
            let Some(cache) = self.lock.session_subscriptions.get(session_id) else {
                continue;
            };
            let mut cache_lck = cache.lock();
            cache_lck.notify_events(items);
        }
    }
}
