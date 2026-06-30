use hashbrown::HashMap;
use opcua_nodes::Event;
use opcua_types::{
    node_id::IntoNodeIdRef, AttributeId, DataEncoding, DataValue, DateTime, NumericRange, ObjectId,
    Variant,
};
use parking_lot::RwLockReadGuard;

use crate::{
    subscriptions::{
        actor::SubscriptionActorHandle, ring::NotificationWorkItem, MonitoredItemEntry,
        MonitoredItemKeyRef, SubscriptionCacheInner,
    },
    MonitoredItemHandle,
};

/// Owned metadata for one monitored item route captured from the cache.
#[allow(dead_code)]
#[derive(Clone)]
pub(crate) struct NotificationRouteTarget {
    pub(crate) session_id: u32,
    pub(crate) subscription_id: u32,
    pub(crate) monitored_item_id: u32,
    pub(crate) handle: MonitoredItemHandle,
    pub(crate) attribute_id: AttributeId,
    pub(crate) index_range: NumericRange,
    pub(crate) data_encoding: DataEncoding,
}

/// Owned routes for a single subscription actor.
#[allow(dead_code)]
#[derive(Clone)]
pub(crate) struct NotificationRouteBatch {
    pub(crate) session_id: u32,
    pub(crate) subscription_id: u32,
    pub(crate) subscription_handle: SubscriptionActorHandle,
    pub(crate) targets: Vec<NotificationRouteTarget>,
}

impl NotificationRouteBatch {
    fn new(
        session_id: u32,
        subscription_id: u32,
        subscription_handle: SubscriptionActorHandle,
    ) -> Self {
        Self {
            session_id,
            subscription_id,
            subscription_handle,
            targets: Vec::new(),
        }
    }
}

/// Owned route lookup result for one notification source.
///
/// This snapshot owns the session, subscription, monitored-item, and sampling
/// metadata needed after the global subscription cache guard has been released.
#[allow(dead_code)]
#[derive(Clone, Default)]
pub(crate) struct NotificationRouteSnapshot {
    batches: Vec<NotificationRouteBatch>,
}

#[allow(dead_code)]
impl NotificationRouteSnapshot {
    #[must_use]
    pub(crate) fn empty() -> Self {
        Self::default()
    }

    #[must_use]
    pub(crate) fn for_data<'a>(
        inner: &SubscriptionCacheInner,
        node_id: impl IntoNodeIdRef<'a>,
        attribute_id: AttributeId,
    ) -> Self {
        if attribute_id == AttributeId::EventNotifier {
            return Self::empty();
        }

        let Some(items) = inner.monitored_items.get(&MonitoredItemKeyRef {
            id: node_id.into_node_id_ref(),
            attribute_id,
        }) else {
            return Self::empty();
        };

        let mut snapshot = Self::empty();
        snapshot.extend_from_items(inner, attribute_id, items);
        snapshot
    }

    #[must_use]
    pub(crate) fn for_events<'a>(
        inner: &SubscriptionCacheInner,
        node_id: impl IntoNodeIdRef<'a>,
    ) -> Self {
        let id_ref = node_id.into_node_id_ref();
        let is_server = id_ref == ObjectId::Server;
        let mut snapshot = Self::empty();

        if let Some(items) = inner.monitored_items.get(&MonitoredItemKeyRef {
            id: id_ref,
            attribute_id: AttributeId::EventNotifier,
        }) {
            snapshot.extend_from_items(inner, AttributeId::EventNotifier, items);
        }

        if !is_server {
            if let Some(items) = inner.monitored_items.get(&MonitoredItemKeyRef {
                id: ObjectId::Server.into_node_id_ref(),
                attribute_id: AttributeId::EventNotifier,
            }) {
                snapshot.extend_from_items(inner, AttributeId::EventNotifier, items);
            }
        }

        snapshot
    }

    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.batches.is_empty()
    }

    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.batches.iter().map(|batch| batch.targets.len()).sum()
    }

    #[must_use]
    pub(crate) fn batches(&self) -> &[NotificationRouteBatch] {
        &self.batches
    }

    #[must_use]
    pub(crate) fn into_batches(self) -> Vec<NotificationRouteBatch> {
        self.batches
    }

    fn extend_from_items(
        &mut self,
        inner: &SubscriptionCacheInner,
        attribute_id: AttributeId,
        items: &HashMap<MonitoredItemHandle, MonitoredItemEntry>,
    ) {
        for (handle, entry) in items {
            if !entry.enabled {
                continue;
            }

            let subscription_id = handle.subscription_id;
            let Some(session_id) = inner.subscription_to_session.get(&subscription_id).copied()
            else {
                continue;
            };
            let Some(session_entry) = inner.session_subscriptions.get(&session_id) else {
                continue;
            };

            let batch_index = match self
                .batches
                .iter()
                .position(|batch| batch.subscription_id == subscription_id)
            {
                Some(index) => index,
                None => {
                    self.batches.push(NotificationRouteBatch::new(
                        session_id,
                        subscription_id,
                        session_entry.handle(),
                    ));
                    self.batches.len() - 1
                }
            };

            self.batches[batch_index]
                .targets
                .push(NotificationRouteTarget {
                    session_id,
                    subscription_id,
                    monitored_item_id: handle.monitored_item_id,
                    handle: *handle,
                    attribute_id,
                    index_range: entry.index_range.clone(),
                    data_encoding: entry.data_encoding.clone(),
                });
        }
    }
}

/// Handle for notifying the subscription cache of a batch of changes,
/// without allocating NodeIds unnecessarily.
/// Notifications are actually submitted once the notifier is dropped.
pub struct SubscriptionDataNotifier<'a> {
    lock: Option<RwLockReadGuard<'a, SubscriptionCacheInner>>,
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
            lock: Some(lock),
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

        let lock = self.lock.as_deref()?;
        let items = lock.monitored_items.get(&MonitoredItemKeyRef {
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

impl Drop for SubscriptionDataNotifier<'_> {
    fn drop(&mut self) {
        let Some(lock) = self.lock.as_deref() else {
            return;
        };

        let mut pending = Vec::with_capacity(self.by_subscription.len());
        for (sub_id, items) in std::mem::take(&mut self.by_subscription) {
            let Some(session_id) = lock.subscription_to_session.get(&sub_id) else {
                continue;
            };
            let Some(entry) = lock.session_subscriptions.get(session_id) else {
                continue;
            };
            pending.push((entry.handle(), items));
        }

        drop(self.lock.take());

        for (subscription_handle, items) in pending {
            for (handle, value) in items {
                let item = NotificationWorkItem::Data { handle, value };
                subscription_handle.push_notification(item);
            }
        }
    }
}

struct PendingEventNotifications<'b> {
    subscription_handle: SubscriptionActorHandle,
    items: Vec<(MonitoredItemHandle, &'b dyn Event)>,
}

/// Handle for notifying the subscription cache of a batch of events,
/// without allocating NodeIds unnecessarily.
/// Notifications are actually submitted once the notifier is dropped.
pub struct SubscriptionEventNotifier<'a, 'b> {
    lock: Option<RwLockReadGuard<'a, SubscriptionCacheInner>>,
    by_subscription: HashMap<(u32, u32), PendingEventNotifications<'b>>,
}

/// Notifier for a specific node emitting events.
pub struct SubscriptionEventNotifierBatch<'a, 'b> {
    route_batches: Vec<NotificationRouteBatch>,
    by_subscription: &'a mut HashMap<(u32, u32), PendingEventNotifications<'b>>,
}

impl<'b> SubscriptionEventNotifierBatch<'_, 'b> {
    /// Notify the referenced node of a new event.
    pub fn event(&mut self, event: &'b dyn Event) {
        for batch in &self.route_batches {
            let pending = self
                .by_subscription
                .entry((batch.session_id, batch.subscription_id))
                .or_insert_with(|| PendingEventNotifications {
                    subscription_handle: batch.subscription_handle.clone(),
                    items: Vec::new(),
                });
            for target in &batch.targets {
                pending.items.push((target.handle, event));
            }
        }
    }
}

impl<'a, 'b> SubscriptionEventNotifier<'a, 'b> {
    pub(super) fn new(lock: RwLockReadGuard<'a, SubscriptionCacheInner>) -> Self {
        Self {
            lock: Some(lock),
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
        let lock = self.lock.as_deref()?;
        let snapshot = NotificationRouteSnapshot::for_events(lock, node_id);
        if snapshot.is_empty() {
            return None;
        }

        Some(SubscriptionEventNotifierBatch {
            route_batches: snapshot.into_batches(),
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

impl Drop for SubscriptionEventNotifier<'_, '_> {
    fn drop(&mut self) {
        drop(self.lock.take());

        for (_, pending) in std::mem::take(&mut self.by_subscription) {
            let PendingEventNotifications {
                subscription_handle,
                items,
            } = pending;
            for (handle, event) in items {
                let item = NotificationWorkItem::Event {
                    handle,
                    event: event.clone_box(),
                };
                subscription_handle.push_notification(item);
            }
        }
    }
}
