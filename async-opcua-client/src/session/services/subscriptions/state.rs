use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use opcua_core::handle::Handle;
use opcua_types::{MonitoringMode, NotificationMessage, SubscriptionAcknowledgement};

use crate::session::services::subscriptions::{MonitoredItemTempResult, TempMonitoredItem};

use super::{CreateMonitoredItem, ModifyMonitoredItem, PublishLimits, Subscription};

/// State containing all known subscriptions in the session.
pub struct SubscriptionState {
    acknowledgements: Vec<SubscriptionAcknowledgement>,
    keep_alive_timeout: Option<Duration>,
    last_publish: Instant,
    min_publish_interval: Duration,
    publish_limits_watch_tx: tokio::sync::watch::Sender<PublishLimits>,
    subscriptions: HashMap<u32, Subscription>,
    temp_id_handle: Handle,
}

impl SubscriptionState {
    /// Create a new subscription state.
    ///
    /// # Arguments
    ///
    /// * `min_publishing_interval` - The minimum accepted publishing interval, any lower values
    ///   will be set to this.
    pub(crate) fn new(
        min_publish_interval: Duration,
        publish_limits_watch_tx: tokio::sync::watch::Sender<PublishLimits>,
    ) -> Self {
        Self {
            acknowledgements: Vec::new(),
            keep_alive_timeout: None,
            last_publish: Instant::now() - min_publish_interval,
            min_publish_interval,
            publish_limits_watch_tx,
            subscriptions: HashMap::new(),
            temp_id_handle: Handle::new(0),
        }
    }

    pub(crate) fn next_publish_time(&self) -> Option<Instant> {
        if self.subscriptions.is_empty() {
            return None;
        }

        let next = self
            .subscriptions
            .values()
            .filter(|s| s.publishing_enabled())
            .map(|s| s.publishing_interval().max(self.min_publish_interval))
            .min()
            .or(self.keep_alive_timeout)
            .map(|e| self.last_publish + e);

        next
    }

    pub(crate) fn set_last_publish(&mut self) {
        self.last_publish = Instant::now();
    }

    pub(crate) fn take_acknowledgements(&mut self) -> Vec<SubscriptionAcknowledgement> {
        std::mem::take(&mut self.acknowledgements)
    }

    pub(crate) fn add_acknowledgement(&mut self, subscription_id: u32, sequence_number: u32) {
        self.acknowledgements.push(SubscriptionAcknowledgement {
            subscription_id,
            sequence_number,
        })
    }

    pub(crate) fn re_queue_acknowledgements(&mut self, acks: Vec<SubscriptionAcknowledgement>) {
        self.acknowledgements.extend(acks);
    }

    /// List of subscription IDs.
    pub fn subscription_ids(&self) -> Option<Vec<u32>> {
        if self.subscriptions.is_empty() {
            None
        } else {
            Some(self.subscriptions.keys().cloned().collect())
        }
    }

    /// Check if the subscription ID is known.
    pub fn subscription_exists(&self, subscription_id: u32) -> bool {
        self.subscriptions.contains_key(&subscription_id)
    }

    /// Get a reference to a subscription by ID.
    pub fn get(&self, subscription_id: u32) -> Option<&Subscription> {
        self.subscriptions.get(&subscription_id)
    }

    /// Get the number of subscriptions.
    pub fn len(&self) -> usize {
        self.subscriptions.len()
    }

    /// Get the number of subscriptions that have publishing enabled.
    pub fn len_active(&self) -> usize {
        self.subscriptions
            .iter()
            .filter(|s| s.1.publishing_enabled)
            .count()
    }

    /// Add a subscription to the state. Note that this
    /// does not create the subscription, you need to do that yourself.
    ///
    /// Most users should simply call [`crate::Session::create_subscription`]
    pub fn add_subscription(&mut self, subscription: Subscription) {
        self.subscriptions
            .insert(subscription.subscription_id(), subscription);
        self.set_keep_alive_timeout();
        self.update_publish_limits();
    }

    pub(crate) fn modify_subscription(
        &mut self,
        subscription_id: u32,
        publishing_interval: Duration,
        lifetime_count: u32,
        max_keep_alive_count: u32,
        max_notifications_per_publish: u32,
        priority: u8,
    ) {
        if let Some(ref mut subscription) = self.subscriptions.get_mut(&subscription_id) {
            subscription.set_publishing_interval(publishing_interval);
            subscription.set_lifetime_count(lifetime_count);
            subscription.set_max_keep_alive_count(max_keep_alive_count);
            subscription.set_max_notifications_per_publish(max_notifications_per_publish);
            subscription.set_priority(priority);
            self.set_keep_alive_timeout();
        }
    }

    pub(crate) fn delete_subscription(&mut self, subscription_id: u32) -> Option<Subscription> {
        let subscription = self.subscriptions.remove(&subscription_id);
        self.set_keep_alive_timeout();
        self.update_publish_limits();
        subscription
    }

    pub(crate) fn set_publishing_mode(
        &mut self,
        subscription_ids: &[u32],
        publishing_enabled: bool,
    ) {
        subscription_ids.iter().for_each(|subscription_id| {
            if let Some(ref mut subscription) = self.subscriptions.get_mut(subscription_id) {
                subscription.set_publishing_enabled(publishing_enabled);
            }
        });
    }

    pub(crate) fn insert_monitored_items(
        &mut self,
        subscription_id: u32,
        items_to_create: Vec<CreateMonitoredItem>,
    ) {
        if let Some(ref mut subscription) = self.subscriptions.get_mut(&subscription_id) {
            subscription.insert_monitored_items(items_to_create);
        }
    }

    pub(crate) fn modify_monitored_items(
        &mut self,
        subscription_id: u32,
        items_to_modify: &[ModifyMonitoredItem],
    ) {
        if let Some(ref mut subscription) = self.subscriptions.get_mut(&subscription_id) {
            subscription.modify_monitored_items(items_to_modify);
        }
    }

    pub(crate) fn delete_monitored_items(&mut self, subscription_id: u32, items_to_delete: &[u32]) {
        if let Some(ref mut subscription) = self.subscriptions.get_mut(&subscription_id) {
            subscription.delete_monitored_items(items_to_delete);
        }
    }

    pub(crate) fn set_triggering(
        &mut self,
        subscription_id: u32,
        triggering_item_id: u32,
        links_to_add: &[u32],
        links_to_remove: &[u32],
    ) {
        if let Some(ref mut subscription) = self.subscriptions.get_mut(&subscription_id) {
            subscription.set_triggering(triggering_item_id, links_to_add, links_to_remove);
        }
    }

    pub(crate) fn set_monitoring_mode(
        &mut self,
        subscription_id: u32,
        montiored_item_ids: &[u32],
        monitoring_mode: MonitoringMode,
    ) {
        if let Some(ref mut subscription) = self.subscriptions.get_mut(&subscription_id) {
            for id in montiored_item_ids {
                if let Some(item) = subscription
                    .monitored_items
                    .get_mut(&super::MonitoredItemId::Server(*id))
                {
                    item.set_monitoring_mode(monitoring_mode);
                }
            }
        }
    }

    pub(crate) fn handle_notification(
        &mut self,
        subscription_id: u32,
        notification: NotificationMessage,
    ) {
        self.add_acknowledgement(subscription_id, notification.sequence_number);
        if let Some(sub) = self.subscriptions.get_mut(&subscription_id) {
            sub.on_notification(notification);
        } else {
            tracing::warn!(
                "Received notification for unknown subscription {}",
                subscription_id
            );
        }
    }

    fn set_keep_alive_timeout(&mut self) {
        self.keep_alive_timeout = self
            .subscriptions
            .values()
            .map(|v| v.publishing_interval() * v.lifetime_count())
            .min()
    }

    fn update_publish_limits(&mut self) {
        let publish_interval = self
            .subscriptions
            .values()
            .filter(|s| s.publishing_enabled())
            .map(|s| s.publishing_interval().max(self.min_publish_interval))
            .min()
            .unwrap_or(Duration::ZERO);

        self.publish_limits_watch_tx.send_modify(|limits| {
            limits.update_subscriptions(self.subscriptions.len(), publish_interval);
        });
    }

    pub(super) fn clear_temporary_ids(
        &mut self,
        ids: &[MonitoredItemTempResult],
        subscription_id: u32,
    ) {
        if let Some(subscription) = self.subscriptions.get_mut(&subscription_id) {
            for id in ids {
                subscription.clear_temporary_id(id.temp_id, !id.created);
            }
        }
    }

    pub(super) fn insert_temporary_monitored_items(
        &mut self,
        items: &[TempMonitoredItem],
        subscription_id: u32,
    ) {
        if let Some(subscription) = self.subscriptions.get_mut(&subscription_id) {
            for item in items {
                subscription.insert_temporary_monitored_item(item);
            }
        }
    }

    pub(super) fn next_temp_id(&mut self) -> u32 {
        self.temp_id_handle.next()
    }
}
