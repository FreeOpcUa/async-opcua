use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use opcua_core::handle::Handle;
use opcua_types::{MonitoringMode, NotificationMessage, SubscriptionAcknowledgement};

use crate::session::services::subscriptions::{MonitoredItemTempResult, TempMonitoredItem};

use super::{CreateMonitoredItem, ModifyMonitoredItem, PublishLimits, Subscription};

/// How many sequence numbers of delivered notification messages are kept per subscription to recognise one
/// delivered twice.
const DELIVERED_SEQUENCE_NUMBERS_KEPT: usize = 64;

/// State containing all known subscriptions in the session.
pub struct SubscriptionState {
    acknowledgements: Vec<SubscriptionAcknowledgement>,
    /// Per subscription, the highest sequence number this client has heard the server account for: the number of
    /// the last notification message with data, or one below the number a keep-alive names as the next.
    heard_sequence_numbers: HashMap<u32, u32>,
    /// Per subscription, the sequence numbers of the latest notification messages with data handed to the
    /// subscription. Publish responses are handled as they complete, so a later one can be handled first and the
    /// earlier one republished as missed; when the earlier one is then handled itself, it is not handed over again.
    delivered_sequence_numbers: HashMap<u32, VecDeque<u32>>,
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
            heard_sequence_numbers: HashMap::new(),
            delivered_sequence_numbers: HashMap::new(),
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
        self.heard_sequence_numbers.remove(&subscription_id);
        self.delivered_sequence_numbers.remove(&subscription_id);
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
        monitored_item_ids: &[u32],
        monitoring_mode: MonitoringMode,
    ) {
        if let Some(ref mut subscription) = self.subscriptions.get_mut(&subscription_id) {
            for id in monitored_item_ids {
                if let Some(item) = subscription
                    .monitored_items
                    .get_mut(&super::MonitoredItemId::Server(*id))
                {
                    item.set_monitoring_mode(monitoring_mode);
                }
            }
        }
    }

    /// The messages the server sent before `notification` that never reached this client, oldest first, among the
    /// `available` sequence numbers the server still holds for retransmission; records `notification` as heard.
    ///
    /// OPC UA Part 4, 5.13.1.1 and 5.13.6: a message with data carries its own sequence number, a keep-alive the
    /// number the next message will carry, and the client recovers the messages in between with Republish. A
    /// Publish response lost with its transport (the request was answered on a connection that died) is the case:
    /// the session reactivates, the server keeps the message in its retransmission queue, and without Republish its
    /// value never arrives. The first message of a subscription only sets the mark.
    pub(crate) fn missed_before(
        &mut self,
        subscription_id: u32,
        notification: &NotificationMessage,
        available: &[u32],
    ) -> Vec<u32> {
        let has_data = notification
            .notification_data
            .as_ref()
            .is_some_and(|v| !v.is_empty());
        let next = notification.sequence_number;
        let heard = if has_data {
            next
        } else {
            next.saturating_sub(1)
        };
        let previous = self.heard_sequence_numbers.get(&subscription_id).copied();
        if previous.is_none_or(|previous| heard > previous) {
            self.heard_sequence_numbers.insert(subscription_id, heard);
        }
        let Some(previous) = previous else {
            return Vec::new();
        };
        let delivered = self.delivered_sequence_numbers.get(&subscription_id);
        let mut missed: Vec<u32> = available
            .iter()
            .copied()
            .filter(|&number| number > previous && number < next)
            .filter(|number| delivered.is_none_or(|delivered| !delivered.contains(number)))
            .collect();
        missed.sort_unstable();
        missed.dedup();
        missed
    }

    pub(crate) fn handle_notification(
        &mut self,
        subscription_id: u32,
        notification: NotificationMessage,
    ) {
        let has_data = notification
            .notification_data
            .as_ref()
            .is_some_and(|v| !v.is_empty());
        if has_data {
            let delivered = self
                .delivered_sequence_numbers
                .entry(subscription_id)
                .or_default();
            if delivered.contains(&notification.sequence_number) {
                tracing::debug!(
                    "Notification {} of subscription {} was already delivered",
                    notification.sequence_number,
                    subscription_id
                );
                return;
            }
            if delivered.len() == DELIVERED_SEQUENCE_NUMBERS_KEPT {
                delivered.pop_front();
            }
            delivered.push_back(notification.sequence_number);
            self.add_acknowledgement(subscription_id, notification.sequence_number);
        }
        if let Some(sub) = self.subscriptions.get_mut(&subscription_id) {
            sub.on_notification(notification);
        } else if has_data {
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
            .map(|v| {
                v.publishing_interval()
                    .checked_mul(v.max_keep_alive_count())
                    .unwrap_or(Duration::MAX)
            })
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

#[cfg(test)]
mod sequence_tests {
    use std::time::Duration;

    use opcua_types::{
        DataChangeNotification, ExtensionObject, NotificationMessage, SubscriptionAcknowledgement,
    };

    use super::SubscriptionState;
    use crate::session::services::subscriptions::PublishLimits;

    const SUBSCRIPTION: u32 = 1;

    fn state() -> SubscriptionState {
        let (limits_tx, _) = tokio::sync::watch::channel(PublishLimits::new());
        SubscriptionState::new(Duration::from_millis(100), limits_tx)
    }

    fn data(sequence_number: u32) -> NotificationMessage {
        NotificationMessage {
            sequence_number,
            notification_data: Some(vec![ExtensionObject::from_message(
                DataChangeNotification::default(),
            )]),
            ..Default::default()
        }
    }

    fn keep_alive(next_sequence_number: u32) -> NotificationMessage {
        NotificationMessage {
            sequence_number: next_sequence_number,
            notification_data: None,
            ..Default::default()
        }
    }

    fn acknowledged(state: &mut SubscriptionState) -> Vec<u32> {
        state
            .take_acknowledgements()
            .into_iter()
            .map(
                |SubscriptionAcknowledgement {
                     sequence_number, ..
                 }| sequence_number,
            )
            .collect()
    }

    #[test]
    fn the_first_message_of_a_subscription_only_sets_the_mark() {
        let mut state = state();
        assert!(state
            .missed_before(SUBSCRIPTION, &data(5), &[3, 4, 5])
            .is_empty());
    }

    #[test]
    fn messages_between_two_data_messages_are_missed_oldest_first() {
        let mut state = state();
        state.missed_before(SUBSCRIPTION, &data(1), &[1]);
        assert_eq!(
            state.missed_before(SUBSCRIPTION, &data(4), &[3, 2, 4]),
            vec![2, 3]
        );
    }

    #[test]
    fn a_keep_alive_names_the_messages_before_the_next_one_as_missed() {
        let mut state = state();
        state.missed_before(SUBSCRIPTION, &data(1), &[1]);
        assert_eq!(
            state.missed_before(SUBSCRIPTION, &keep_alive(3), &[2]),
            vec![2]
        );
        assert!(state
            .missed_before(SUBSCRIPTION, &keep_alive(3), &[2])
            .is_empty());
    }

    #[test]
    fn a_message_the_server_no_longer_holds_is_not_requested() {
        let mut state = state();
        state.missed_before(SUBSCRIPTION, &data(1), &[1]);
        assert_eq!(
            state.missed_before(SUBSCRIPTION, &data(4), &[3, 4]),
            vec![3]
        );
    }

    #[test]
    fn a_message_handled_after_the_one_that_overtook_it_is_delivered_once() {
        let mut state = state();
        state.missed_before(SUBSCRIPTION, &data(1), &[1]);
        state.handle_notification(SUBSCRIPTION, data(1));

        assert_eq!(
            state.missed_before(SUBSCRIPTION, &data(3), &[2, 3]),
            vec![2]
        );
        state.handle_notification(SUBSCRIPTION, data(2));
        state.handle_notification(SUBSCRIPTION, data(3));

        assert!(state.missed_before(SUBSCRIPTION, &data(2), &[]).is_empty());
        state.handle_notification(SUBSCRIPTION, data(2));

        assert_eq!(acknowledged(&mut state), vec![1, 2, 3]);
    }
}
