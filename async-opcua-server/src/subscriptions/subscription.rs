use std::{
    collections::{BTreeSet, HashMap, HashSet},
    time::{Duration, Instant},
};

use opcua_core::handle::Handle;
use opcua_nodes::{Event, TypeTree};
use opcua_types::{DataValue, DateTime, DateTimeUtc, StatusCode};
use tracing::{debug, trace};

use crate::subscriptions::queue::PublishRequestSlots;

use super::monitored_item::MonitoredItem;

#[derive(Debug, Copy, Clone, PartialEq)]
/// Current internal state of the subscription.
pub enum SubscriptionState {
    /// The subscription has been closed and will be removed soon.
    Closed,
    /// The subscription is being created.
    Creating,
    /// The subscription is operating normally.
    Normal,
    /// The subscription is waiting for publish requests that are
    /// not arriving as expected.
    Late,
    /// The subscription is sending keep alives because no
    /// data is being produced.
    KeepAlive,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
/// Unique identifier for a monitored item on the server.
pub struct MonitoredItemHandle {
    /// Subscription this monitored item belongs to.
    pub subscription_id: u32,
    /// ID of this monitored item.
    pub monitored_item_id: u32,
}

#[derive(Debug)]
pub(crate) struct SubscriptionStateParams {
    pub notifications_available: bool,
    pub more_notifications: bool,
    pub publishing_req_queued: bool,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum UpdateStateAction {
    None,
    // Return a keep alive
    ReturnKeepAlive,
    // Return notifications
    ReturnNotifications,
    // The subscription was created normally
    SubscriptionCreated,
    // The subscription has expired and must be closed
    SubscriptionExpired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TickResult {
    Expired,
    Triggered,
    None,
}

/// This is for debugging purposes. It allows the caller to validate the output state if required.
///
/// Values correspond to state table in OPC UA Part 4 5.13.1.2
///
#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) enum HandledState {
    None0 = 0,
    Create3 = 3,
    Normal4 = 4,
    Normal5 = 5,
    IntervalElapsed6 = 6,
    IntervalElapsed7 = 7,
    IntervalElapsed8 = 8,
    IntervalElapsed9 = 9,
    Late10 = 10,
    Late11 = 11,
    Late12 = 12,
    KeepAlive13 = 13,
    KeepAlive14 = 14,
    KeepAlive15 = 15,
    KeepAlive16 = 16,
    KeepAlive17 = 17,
    Closed27 = 27,
}

#[derive(Debug)]
/// A single subscription maintained by the server.
pub struct Subscription {
    id: u32,
    publishing_interval: Duration,
    max_lifetime_counter: u32,
    max_keep_alive_counter: u32,
    priority: u8,
    monitored_items: HashMap<u32, MonitoredItem>,
    /// Monitored items that have seen notifications.
    notified_monitored_items: BTreeSet<u32>,
    /// Monitored items holding a value delayed by the sampling interval that is not due yet.
    /// They are moved to `notified_monitored_items` once the value is due.
    skipped_value_monitored_items: HashSet<u32>,
    /// State of the subscription
    state: SubscriptionState,
    /// A value that contains the number of consecutive publishing timer expirations without Client
    /// activity before the Subscription is terminated.
    lifetime_counter: u32,
    /// Keep alive counter decrements when there are no notifications to publish and when it expires
    /// requests to send an empty notification as a keep alive event
    keep_alive_counter: u32,
    /// boolean value that is set to true to mean that either a NotificationMessage or a keep-alive
    /// Message has been sent on the Subscription. It is a flag that is used to ensure that either
    /// a NotificationMessage or a keep-alive Message is sent out the first time the publishing timer
    /// expires.
    first_message_sent: bool,
    /// The parameter that requests publishing to be enabled or disabled.
    publishing_enabled: bool,
    /// A flag that tells the subscription to send the latest value of every monitored item on the
    /// next publish request.
    resend_data: bool,
    /// The next sequence number to be sent
    sequence_number: Handle,
    // The time that the subscription interval last fired
    last_time_publishing_interval_elapsed: Instant,
    /// Maximum number of notifications per publish.
    max_notifications_per_publish: usize,
    /// Flag set to indicate whether there are more notifications available.
    more_notifications: bool,
    /// Flag set to indicate a pending keep-alive message, meaning that
    /// a future publish request may trigger a keep-alive notification
    /// once there's space.
    pending_keep_alive: bool,
    /// Monitored items that were triggered, but whose notifications did not all fit
    /// in the available publish requests. These are sent on a later tick, ahead of
    /// any new triggers.
    pending_triggered_items: BTreeSet<u32>,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) enum TickReason {
    ReceivePublishRequest,
    TickTimerFired,
}

impl Subscription {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        id: u32,
        publishing_enabled: bool,
        publishing_interval: Duration,
        lifetime_counter: u32,
        keep_alive_counter: u32,
        priority: u8,
        max_notifications_per_publish: u64,
    ) -> Self {
        Self {
            id,
            publishing_interval,
            max_lifetime_counter: lifetime_counter,
            max_keep_alive_counter: keep_alive_counter,
            priority,
            monitored_items: HashMap::new(),
            notified_monitored_items: BTreeSet::new(),
            skipped_value_monitored_items: HashSet::new(),
            // State variables
            state: SubscriptionState::Creating,
            lifetime_counter,
            keep_alive_counter,
            first_message_sent: false,
            resend_data: false,
            publishing_enabled,
            // Counters for new items
            sequence_number: Handle::new(1),
            last_time_publishing_interval_elapsed: Instant::now(),
            max_notifications_per_publish: max_notifications_per_publish as usize,
            more_notifications: false,
            pending_keep_alive: false,
            pending_triggered_items: BTreeSet::new(),
        }
    }

    /// Get the number of monitored items in this subscription.
    pub fn len(&self) -> usize {
        self.monitored_items.len()
    }

    /// Return whether the subscription has no monitored items.
    pub fn is_empty(&self) -> bool {
        self.monitored_items.is_empty()
    }

    pub(super) fn get_mut(&mut self, id: &u32) -> Option<&mut MonitoredItem> {
        self.monitored_items.get_mut(id)
    }

    /// Get a reference to a monitored item managed by this subscription.
    pub fn get(&self, id: &u32) -> Option<&MonitoredItem> {
        self.monitored_items.get(id)
    }

    /// Return whether the subscription contains the given monitored item ID.
    pub fn contains_key(&self, id: &u32) -> bool {
        self.monitored_items.contains_key(id)
    }

    /// Iterate over the monitored items in the subscription.
    pub fn items(&self) -> impl Iterator<Item = &MonitoredItem> {
        self.monitored_items.values()
    }

    pub(super) fn drain(&mut self) -> impl Iterator<Item = (u32, MonitoredItem)> + '_ {
        self.monitored_items.drain()
    }

    /// Set `resend_data`. The next publish request will send values for all
    /// monitored items, whether or not they have produced any new data.
    pub fn set_resend_data(&mut self) {
        self.resend_data = true;
    }

    pub(super) fn remove(&mut self, id: &u32) -> Option<MonitoredItem> {
        self.monitored_items.remove(id)
    }

    pub(super) fn insert(&mut self, id: u32, item: MonitoredItem) {
        self.monitored_items.insert(id, item);
        self.notified_monitored_items.insert(id);
    }

    /// Notify the given monitored item of a new data value.
    pub fn notify_data_value(&mut self, id: &u32, value: DataValue, now: &DateTime) {
        if let Some(item) = self.monitored_items.get_mut(id) {
            if item.notify_data_value(value, now, false) {
                self.notified_monitored_items.insert(*id);
            }
        }
    }

    /// Notify the given monitored item of a new event.
    pub fn notify_event(&mut self, id: &u32, event: &dyn Event, type_tree: &dyn TypeTree) {
        if let Some(item) = self.monitored_items.get_mut(id) {
            if item.notify_event(event, type_tree) {
                self.notified_monitored_items.insert(*id);
            }
        }
    }

    /// Tests if the publishing interval has elapsed since the last time this function in which case
    /// it returns `true` and updates its internal state.
    fn test_and_set_publishing_interval_elapsed(&mut self, now: Instant) -> bool {
        // Look at the last expiration time compared to now and see if it matches
        // or exceeds the publishing interval
        let elapsed = now - self.last_time_publishing_interval_elapsed;
        if elapsed >= self.publishing_interval {
            self.last_time_publishing_interval_elapsed = now;
            true
        } else {
            false
        }
    }

    fn get_state_transition(
        &self,
        tick_reason: TickReason,
        p: SubscriptionStateParams,
    ) -> HandledState {
        // The full state transition table from Part 4 5.13.1.
        // Note that the exact layout here is written to be as close as possible to the state transition
        // table. Avoid changing it to clean it up or remove redundant checks. To make it easier to debug,
        // it should be as one-to-one with the original document as possible.
        #[allow(clippy::nonminimal_bool)]
        match (self.state, tick_reason) {
            (SubscriptionState::Creating, _) => HandledState::Create3,
            (SubscriptionState::Normal, TickReason::ReceivePublishRequest)
                if !self.publishing_enabled
                    || (self.publishing_enabled && !p.more_notifications) =>
            {
                HandledState::Normal4
            }
            (SubscriptionState::Normal, TickReason::ReceivePublishRequest)
                if self.publishing_enabled && p.more_notifications =>
            {
                HandledState::Normal5
            }
            (SubscriptionState::Normal, TickReason::TickTimerFired)
                if p.publishing_req_queued
                    && self.publishing_enabled
                    && p.notifications_available =>
            {
                HandledState::IntervalElapsed6
            }
            (SubscriptionState::Normal, TickReason::TickTimerFired)
                if p.publishing_req_queued
                    && !self.first_message_sent
                    && (!self.publishing_enabled
                        || self.publishing_enabled && !p.more_notifications) =>
            {
                HandledState::IntervalElapsed7
            }
            (SubscriptionState::Normal, TickReason::TickTimerFired)
                if !p.publishing_req_queued
                    && (!self.first_message_sent
                        || self.publishing_enabled && p.notifications_available) =>
            {
                HandledState::IntervalElapsed8
            }
            (SubscriptionState::Normal, TickReason::TickTimerFired)
                if self.first_message_sent
                    && (!self.publishing_enabled
                        || self.publishing_enabled && !p.more_notifications) =>
            {
                HandledState::IntervalElapsed9
            }
            (SubscriptionState::Late, TickReason::ReceivePublishRequest)
                if self.publishing_enabled
                    && (p.notifications_available || p.more_notifications) =>
            {
                HandledState::Late10
            }
            (SubscriptionState::Late, TickReason::ReceivePublishRequest)
                if !self.publishing_enabled
                    || self.publishing_enabled
                        && !p.notifications_available
                        && !p.more_notifications =>
            {
                HandledState::Late11
            }
            // This check is not in the spec, but without it the lifetime counter won't behave properly.
            // This is probably an error in the standard.
            (SubscriptionState::Late, TickReason::TickTimerFired) if self.lifetime_counter > 1 => {
                HandledState::Late12
            }
            (SubscriptionState::KeepAlive, TickReason::ReceivePublishRequest) => {
                HandledState::KeepAlive13
            }
            (SubscriptionState::KeepAlive, TickReason::TickTimerFired)
                if self.publishing_enabled
                    && p.notifications_available
                    && p.publishing_req_queued =>
            {
                HandledState::KeepAlive14
            }
            (SubscriptionState::KeepAlive, TickReason::TickTimerFired)
                if p.publishing_req_queued
                    && self.keep_alive_counter == 1
                    && (!self.publishing_enabled
                        || self.publishing_enabled && !p.notifications_available) =>
            {
                HandledState::KeepAlive15
            }
            (SubscriptionState::KeepAlive, TickReason::TickTimerFired)
                if self.keep_alive_counter > 1
                    && (!self.publishing_enabled
                        || self.publishing_enabled && !p.notifications_available) =>
            {
                HandledState::KeepAlive16
            }
            (SubscriptionState::KeepAlive, TickReason::TickTimerFired)
                if !p.publishing_req_queued
                    && (self.keep_alive_counter == 1
                        || self.keep_alive_counter > 1
                            && self.publishing_enabled
                            && p.notifications_available) =>
            {
                HandledState::KeepAlive17
            }
            // Late is unreachable in the next state.
            (
                SubscriptionState::Normal | SubscriptionState::Late | SubscriptionState::KeepAlive,
                TickReason::TickTimerFired,
            ) if self.lifetime_counter <= 1 => HandledState::Closed27,
            _ => HandledState::None0,
        }
    }

    fn handle_state_transition(&mut self, transition: HandledState) -> UpdateStateAction {
        match transition {
            HandledState::None0 => UpdateStateAction::None,
            HandledState::Create3 => {
                self.state = SubscriptionState::Normal;
                self.first_message_sent = false;
                UpdateStateAction::SubscriptionCreated
            }
            HandledState::Normal4 => {
                // Publish req queued at session level.
                UpdateStateAction::None
            }
            HandledState::Normal5 => {
                self.reset_lifetime_counter();
                UpdateStateAction::ReturnNotifications
            }
            HandledState::IntervalElapsed6 => {
                self.reset_lifetime_counter();
                self.start_publishing_timer();
                self.first_message_sent = true;
                UpdateStateAction::ReturnNotifications
            }
            HandledState::IntervalElapsed7 => {
                self.reset_lifetime_counter();
                self.start_publishing_timer();
                self.first_message_sent = true;
                UpdateStateAction::ReturnKeepAlive
            }
            HandledState::IntervalElapsed8 => {
                self.start_publishing_timer();
                self.state = SubscriptionState::Late;
                UpdateStateAction::None
            }
            HandledState::IntervalElapsed9 => {
                self.start_publishing_timer();
                self.reset_keep_alive_counter();
                self.state = SubscriptionState::KeepAlive;
                UpdateStateAction::None
            }
            HandledState::Late10 => {
                self.reset_lifetime_counter();
                self.first_message_sent = true;
                self.state = SubscriptionState::Normal;
                UpdateStateAction::ReturnNotifications
            }
            HandledState::Late11 => {
                self.reset_lifetime_counter();
                self.first_message_sent = true;
                self.state = SubscriptionState::KeepAlive;
                UpdateStateAction::ReturnKeepAlive
            }
            HandledState::Late12 => {
                self.start_publishing_timer();
                self.state = SubscriptionState::Late;
                UpdateStateAction::None
            }
            HandledState::KeepAlive13 => {
                // No-op, publish req enqueued at session level.
                UpdateStateAction::None
            }
            HandledState::KeepAlive14 => {
                self.reset_lifetime_counter();
                self.start_publishing_timer();
                self.first_message_sent = true;
                self.state = SubscriptionState::Normal;
                UpdateStateAction::ReturnNotifications
            }
            HandledState::KeepAlive15 => {
                self.start_publishing_timer();
                self.reset_keep_alive_counter();
                UpdateStateAction::ReturnKeepAlive
            }
            HandledState::KeepAlive16 => {
                self.start_publishing_timer();
                self.keep_alive_counter -= 1;
                UpdateStateAction::None
            }
            HandledState::KeepAlive17 => {
                self.start_publishing_timer();
                self.state = SubscriptionState::Late;
                UpdateStateAction::None
            }
            HandledState::Closed27 => {
                self.state = SubscriptionState::Closed;
                UpdateStateAction::SubscriptionExpired
            }
        }
    }

    /// Move monitored items whose skipped value is due to the set of notified items.
    /// Items are only moved once due, so that a value that is not due yet does not
    /// count as an available notification, which would suppress keep-alive messages.
    fn notify_due_skipped_values(&mut self, now: &DateTimeUtc) {
        if self.skipped_value_monitored_items.is_empty() {
            return;
        }
        let now = DateTime::from(*now);
        let monitored_items = &self.monitored_items;
        let notified = &mut self.notified_monitored_items;
        self.skipped_value_monitored_items.retain(|id| {
            let Some(item) = monitored_items.get(id) else {
                return false;
            };
            if item.skipped_value_is_due(&now) {
                notified.insert(*id);
                return false;
            }
            item.has_skipped_value()
        });
    }

    fn notifications_available(&self, resend_data: bool) -> bool {
        if !self.notified_monitored_items.is_empty() || !self.pending_triggered_items.is_empty() {
            true
        } else if resend_data {
            self.monitored_items.iter().any(|it| it.1.has_last_value())
        } else {
            false
        }
    }

    pub(super) fn tick(
        &mut self,
        now: &DateTimeUtc,
        now_instant: Instant,
        tick_reason: TickReason,
        slots: &mut PublishRequestSlots,
    ) -> TickResult {
        let publishing_interval_elapsed = match tick_reason {
            TickReason::ReceivePublishRequest => false,
            TickReason::TickTimerFired => {
                if self.state == SubscriptionState::Creating {
                    true
                } else {
                    self.test_and_set_publishing_interval_elapsed(now_instant)
                }
            }
        };

        // We're not actually doing anything in this case.
        if matches!(tick_reason, TickReason::TickTimerFired) && !publishing_interval_elapsed {
            return TickResult::None;
        }
        self.notify_due_skipped_values(now);

        if self.pending_keep_alive {
            self.pending_keep_alive =
                !slots.try_enqueue_keep_alive(self.sequence_number.peek_next(), now);
        }

        // First, get the actual state transition we're in.
        let params = SubscriptionStateParams {
            notifications_available: self.notifications_available(self.resend_data),
            more_notifications: self.more_notifications,
            publishing_req_queued: slots.any_available_publish_requests(),
        };
        let transition = self.get_state_transition(tick_reason, params);
        let action = self.handle_state_transition(transition);

        let result = match action {
            UpdateStateAction::None => TickResult::None,
            UpdateStateAction::ReturnKeepAlive => {
                self.pending_keep_alive =
                    !slots.try_enqueue_keep_alive(self.sequence_number.peek_next(), now);

                TickResult::Triggered
            }
            UpdateStateAction::ReturnNotifications => {
                let resend_data = std::mem::take(&mut self.resend_data);
                // Reset more-notifications before we keep going, it'll be set again
                // if the tick turns out to not get all available notifications.
                self.more_notifications = false;
                self.tick_monitored_items(now, resend_data, slots);
                TickResult::Triggered
            }
            UpdateStateAction::SubscriptionCreated => TickResult::None,
            UpdateStateAction::SubscriptionExpired => {
                debug!("Subscription status change to closed / timeout");
                self.monitored_items.clear();
                self.pending_triggered_items.clear();
                // The standard states to send a status change notification here,
                // but it seems mostly meaningless, because this only happens if there
                // are no publish requests.
                slots.try_enqueue_status_change(
                    StatusCode::BadTimeout,
                    &mut self.sequence_number,
                    now,
                );
                TickResult::Expired
            }
        };

        slots.finalize(&mut self.sequence_number, now);

        result
    }

    pub(super) fn ready_to_remove(&self) -> bool {
        self.state == SubscriptionState::Closed
    }

    fn handle_triggers(
        &mut self,
        now: &DateTimeUtc,
        triggers: Vec<(u32, u32)>,
        slots: &mut PublishRequestSlots,
    ) {
        // Triggers that did not fit in an earlier tick go first. Note that these will
        // also send any notifications the triggered item has received since it was triggered.
        let pending = std::mem::take(&mut self.pending_triggered_items)
            .into_iter()
            .map(|item_id| (None, item_id));
        let new = triggers
            .into_iter()
            .map(|(triggering_item, item_id)| (Some(triggering_item), item_id));

        for (triggering_item, item_id) in pending.chain(new) {
            let Some(item) = self.monitored_items.get_mut(&item_id) else {
                if let Some(item) = triggering_item.and_then(|t| self.monitored_items.get_mut(&t)) {
                    item.remove_dead_trigger(item_id);
                }
                continue;
            };

            while item.has_notifications() {
                let Some(slot) = slots.item_notif_slot() else {
                    // No more space in the available publish requests, the trigger
                    // is delayed until the next tick.
                    self.pending_triggered_items.insert(item_id);
                    self.more_notifications = true;
                    break;
                };
                // Guaranteed non-empty here, by item.has_notifications()
                slot.enqueue(
                    item.pop_notification().unwrap(),
                    &mut self.sequence_number,
                    now,
                );
            }
        }
    }

    fn tick_monitored_items(
        &mut self,
        now: &DateTimeUtc,
        resend_data: bool,
        slots: &mut PublishRequestSlots<'_>,
    ) {
        let mut triggers = Vec::new();

        let item_ids: Vec<u32> = if resend_data {
            // If resend data is true, we must visit every monitored item. This covers
            // every notified item as well.
            self.notified_monitored_items.clear();
            self.monitored_items.keys().copied().collect()
        } else {
            std::mem::take(&mut self.notified_monitored_items)
                .into_iter()
                .collect()
        };

        for item_id in item_ids {
            let Some(monitored_item) = self.monitored_items.get_mut(&item_id) else {
                continue;
            };
            let more = slots.tick_monitored_item(
                monitored_item,
                now,
                resend_data,
                &mut triggers,
                &mut self.sequence_number,
            );
            self.more_notifications |= more;
            // A skipped value that is not due yet must be enqueued by a later tick,
            // even if no new value is notified for the item before then.
            if monitored_item.has_skipped_value() {
                self.skipped_value_monitored_items.insert(item_id);
            }

            // If the notifications did not all fit, consider the item still notified,
            // so that it is visited again in the next tick. This is fine, because
            // triggers check if there are _new_ notifications, so ticking an item
            // again is idempotent.
            if more {
                self.notified_monitored_items.insert(item_id);
            }
        }

        self.handle_triggers(now, triggers, slots);
    }

    /// Reset the keep-alive counter to the maximum keep-alive count of the Subscription.
    /// The maximum keep-alive count is set by the Client when the Subscription is created
    /// and may be modified using the ModifySubscription Service
    pub(super) fn reset_keep_alive_counter(&mut self) {
        self.keep_alive_counter = self.max_keep_alive_counter;
    }

    /// Reset the lifetime counter to the value specified for the life time of the subscription
    /// in the create subscription service
    pub(super) fn reset_lifetime_counter(&mut self) {
        self.lifetime_counter = self.max_lifetime_counter;
    }

    /// Start or restart the publishing timer and decrement the LifetimeCounter Variable.
    pub(super) fn start_publishing_timer(&mut self) {
        self.lifetime_counter = self.lifetime_counter.saturating_sub(1);
        trace!("Decrementing life time counter {}", self.lifetime_counter);
    }

    /// The ID of this subscription.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// The priority of this subscription.
    pub fn priority(&self) -> u8 {
        self.priority
    }

    pub(super) fn set_publishing_interval(&mut self, publishing_interval: Duration) {
        self.publishing_interval = publishing_interval;
        self.reset_lifetime_counter();
    }

    pub(super) fn set_max_lifetime_counter(&mut self, max_lifetime_counter: u32) {
        self.max_lifetime_counter = max_lifetime_counter;
    }

    pub(super) fn set_max_keep_alive_counter(&mut self, max_keep_alive_counter: u32) {
        self.max_keep_alive_counter = max_keep_alive_counter;
    }

    pub(super) fn set_priority(&mut self, priority: u8) {
        self.priority = priority;
    }

    pub(super) fn set_max_notifications_per_publish(&mut self, max_notifications_per_publish: u64) {
        self.max_notifications_per_publish = max_notifications_per_publish as usize;
    }

    pub(super) fn set_publishing_enabled(&mut self, publishing_enabled: bool) {
        self.publishing_enabled = publishing_enabled;
    }

    /// The publishing interval of this subscription.
    pub fn publishing_interval(&self) -> Duration {
        self.publishing_interval
    }

    /// Whether publishing is enabled on this subscription.
    pub fn publishing_enabled(&self) -> bool {
        self.publishing_enabled
    }

    /// The maximum number of notifications per notification message for this
    /// subscription.
    pub fn max_notifications_per_publish(&self) -> usize {
        self.max_notifications_per_publish
    }

    /// Get whether there are more notifications available on the subscription.
    pub fn more_notifications(&self) -> bool {
        self.more_notifications
    }

    /// The current state of the subscription.
    pub fn state(&self) -> SubscriptionState {
        self.state
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        time::{Duration, Instant},
    };

    use chrono::{TimeDelta, Utc};

    use crate::{
        subscriptions::{
            monitored_item::{
                tests::new_monitored_item, FilterType, Notification, SamplingInterval,
            },
            queue::PublishRequestSlots,
            PendingPublish,
        },
        SubscriptionState,
    };
    use opcua_types::{
        match_extension_object_owned, AttributeId, DataChangeNotification, DataValue, DateTime,
        DateTimeUtc, EventNotificationList, MonitoringMode, NodeId, NotificationMessage,
        PublishRequest, ReadValueId, Variant,
    };

    use super::{Subscription, TickReason, TickResult};

    fn pending_publish() -> PendingPublish {
        let (response, _) = tokio::sync::oneshot::channel();
        PendingPublish {
            response,
            request: Box::new(PublishRequest::default()),
            ack_results: None,
            deadline: Instant::now() + Duration::from_secs(3600),
        }
    }

    /// Tick the subscription with `num_requests` publish requests available,
    /// returning the tick result and the notification messages written to
    /// publish requests, in order.
    fn tick_with_result(
        sub: &mut Subscription,
        now: &DateTimeUtc,
        now_instant: Instant,
        tick_reason: TickReason,
        num_requests: usize,
    ) -> (TickResult, Vec<NotificationMessage>) {
        let mut requests: VecDeque<_> = (0..num_requests).map(|_| pending_publish()).collect();
        let mut responses = Vec::new();
        let mut slots = PublishRequestSlots::new(
            sub.max_notifications_per_publish(),
            &mut requests,
            &mut responses,
            sub.id(),
        );
        let res = sub.tick(now, now_instant, tick_reason, &mut slots);
        assert_eq!(requests.len() + responses.len(), num_requests);
        (
            res,
            responses
                .into_iter()
                .map(|(_, msg, sub_id)| {
                    assert_eq!(sub_id, sub.id());
                    msg
                })
                .collect(),
        )
    }

    fn do_tick(
        sub: &mut Subscription,
        now: &DateTimeUtc,
        now_instant: Instant,
        tick_reason: TickReason,
        num_requests: usize,
    ) -> Vec<NotificationMessage> {
        tick_with_result(sub, now, now_instant, tick_reason, num_requests).1
    }

    fn new_value_item(id: u32, mode: MonitoringMode, value: DataValue) -> super::MonitoredItem {
        new_monitored_item(
            id,
            ReadValueId {
                node_id: NodeId::null(),
                attribute_id: AttributeId::Value as u32,
                ..Default::default()
            },
            mode,
            FilterType::None,
            SamplingInterval::NonZero(TimeDelta::milliseconds(100)),
            false,
            Some(value),
        )
    }

    fn get_notifications(message: &NotificationMessage) -> Vec<Notification> {
        let mut res = Vec::new();
        for it in message.notification_data.iter().flatten() {
            let it = it.clone();
            match_extension_object_owned!(it,
                notif: DataChangeNotification => {
                    for n in notif.monitored_items.into_iter().flatten() {
                        res.push(Notification::MonitoredItemNotification(n));
                    }
                },
                notif: EventNotificationList => {
                    for n in notif.events.into_iter().flatten() {
                        res.push(Notification::Event(n));
                    }
                },
                _ => panic!("Wrong message type"),
            )
        }
        res
    }

    fn offset(time: DateTimeUtc, time_inst: Instant, ms: u64) -> (DateTimeUtc, Instant) {
        (
            time + chrono::Duration::try_milliseconds(ms as i64).unwrap(),
            time_inst + Duration::from_millis(ms),
        )
    }

    #[test]
    fn tick() {
        let mut sub = Subscription::new(1, true, Duration::from_millis(100), 100, 20, 1, 1000);
        let start = Instant::now();
        let start_dt = Utc::now();

        sub.last_time_publishing_interval_elapsed = start;

        // Subscription is creating, handle the first tick.
        assert_eq!(sub.state, SubscriptionState::Creating);
        assert!(do_tick(&mut sub, &start_dt, start, TickReason::TickTimerFired, 1).is_empty());
        assert_eq!(sub.state, SubscriptionState::Normal);
        assert!(!sub.first_message_sent);

        // Tick again before the publishing interval has elapsed, should change nothing.
        assert!(do_tick(&mut sub, &start_dt, start, TickReason::TickTimerFired, 1).is_empty());
        assert_eq!(sub.state, SubscriptionState::Normal);
        assert!(!sub.first_message_sent);

        // Add a monitored item
        sub.insert(
            1,
            new_value_item(1, MonitoringMode::Reporting, DataValue::new_now(123)),
        );
        // New tick at next publishing interval should produce something
        let (time, time_inst) = offset(start_dt, start, 100);
        let msgs = do_tick(&mut sub, &time, time_inst, TickReason::TickTimerFired, 1);
        assert_eq!(sub.state, SubscriptionState::Normal);
        assert!(sub.first_message_sent);
        assert_eq!(msgs.len(), 1);
        let its = get_notifications(&msgs[0]);
        assert_eq!(its.len(), 1);
        assert_eq!(msgs[0].sequence_number, 1);
        let Notification::MonitoredItemNotification(m) = &its[0] else {
            panic!("Wrong notification type");
        };
        assert_eq!(m.value.value, Some(Variant::Int32(123)));

        // Next tick produces nothing
        let (time, time_inst) = offset(start_dt, start, 200);
        let msgs = do_tick(&mut sub, &time, time_inst, TickReason::TickTimerFired, 1);
        // State transitions to keep alive due to empty publish.
        assert_eq!(sub.state, SubscriptionState::KeepAlive);
        assert_eq!(sub.lifetime_counter, 98);
        assert!(sub.first_message_sent);
        assert!(msgs.is_empty());

        // Enqueue a new notification
        sub.notify_data_value(
            &1,
            DataValue::new_at(
                321,
                DateTime::from(start_dt + chrono::Duration::try_milliseconds(300).unwrap()),
            ),
            &DateTime::now(),
        );
        let (time, time_inst) = offset(start_dt, start, 300);
        let msgs = do_tick(&mut sub, &time, time_inst, TickReason::TickTimerFired, 1);
        // State transitions back to normal.
        assert_eq!(sub.state, SubscriptionState::Normal);
        assert!(sub.first_message_sent);
        assert_eq!(sub.lifetime_counter, 99);
        assert_eq!(msgs.len(), 1);
        let its = get_notifications(&msgs[0]);
        assert_eq!(msgs[0].sequence_number, 2);
        assert_eq!(its.len(), 1);
        let Notification::MonitoredItemNotification(m) = &its[0] else {
            panic!("Wrong notification type");
        };
        assert_eq!(m.value.value, Some(Variant::Int32(321)));

        for i in 0..20 {
            let (time, time_inst) = offset(start_dt, start, 1000 + i * 100);
            let msgs = do_tick(&mut sub, &time, time_inst, TickReason::TickTimerFired, 1);
            assert_eq!(sub.state, SubscriptionState::KeepAlive);
            assert_eq!(sub.lifetime_counter, (99 - i - 1) as u32);
            assert_eq!(sub.keep_alive_counter, (20 - i) as u32);
            assert!(msgs.is_empty());
        }
        assert_eq!(sub.lifetime_counter, 79);
        assert_eq!(sub.keep_alive_counter, 1);

        // Tick one more time to get a keep alive
        let (time, time_inst) = offset(start_dt, start, 3000);
        let msgs = do_tick(&mut sub, &time, time_inst, TickReason::TickTimerFired, 1);
        assert_eq!(sub.state, SubscriptionState::KeepAlive);
        assert_eq!(sub.lifetime_counter, 78);
        assert_eq!(sub.keep_alive_counter, 20);
        assert_eq!(msgs.len(), 1);
        assert!(get_notifications(&msgs[0]).is_empty());
        // The next sequence number...
        assert_eq!(msgs[0].sequence_number, 3);

        // Tick another 20 times to become late
        for i in 0..19 {
            let (time, time_inst) = offset(start_dt, start, 3100 + i * 100);
            assert!(do_tick(&mut sub, &time, time_inst, TickReason::TickTimerFired, 0).is_empty());
            assert_eq!(sub.state, SubscriptionState::KeepAlive);
            assert_eq!(sub.lifetime_counter, (78 - i - 1) as u32);
        }

        // Tick another 58 times to expire
        for i in 0..58 {
            let (time, time_inst) = offset(start_dt, start, 5100 + i * 100);
            assert!(do_tick(&mut sub, &time, time_inst, TickReason::TickTimerFired, 0).is_empty());
            assert_eq!(sub.state, SubscriptionState::Late);
            assert_eq!(sub.lifetime_counter, (58 - i) as u32);
        }
        assert_eq!(sub.lifetime_counter, 1);

        // The subscription expires. Nothing is sent, since there are no publish requests,
        // and the subscription can be removed immediately.
        let (time, time_inst) = offset(start_dt, start, 20000);
        let (res, msgs) =
            tick_with_result(&mut sub, &time, time_inst, TickReason::TickTimerFired, 0);
        assert_eq!(res, TickResult::Expired);
        assert_eq!(sub.state, SubscriptionState::Closed);
        assert!(msgs.is_empty());
        assert!(sub.is_empty());
        assert!(sub.ready_to_remove());
    }

    #[test]
    fn monitored_item_triggers() {
        let mut sub = Subscription::new(1, true, Duration::from_millis(100), 100, 20, 1, 1000);
        let start = Instant::now();
        let start_dt = Utc::now();

        sub.last_time_publishing_interval_elapsed = start;
        for i in 0..4 {
            sub.insert(
                i + 1,
                new_monitored_item(
                    i + 1,
                    ReadValueId {
                        node_id: NodeId::null(),
                        attribute_id: AttributeId::Value as u32,
                        ..Default::default()
                    },
                    if i == 0 {
                        MonitoringMode::Reporting
                    } else if i == 3 {
                        MonitoringMode::Disabled
                    } else {
                        MonitoringMode::Sampling
                    },
                    FilterType::None,
                    SamplingInterval::NonZero(TimeDelta::milliseconds(100)),
                    false,
                    Some(DataValue::new_at(0, start_dt.into())),
                ),
            );
        }
        sub.get_mut(&1).unwrap().set_triggering(&[1, 2, 3, 4], &[]);
        // Notify the two sampling items and the disabled item
        let (otime, time_inst) = offset(start_dt, start, 100);
        let time = otime.into();
        sub.notify_data_value(&2, DataValue::new_at(1, time), &time);
        sub.notify_data_value(&3, DataValue::new_at(1, time), &time);
        sub.notify_data_value(&4, DataValue::new_at(1, time), &time);

        // Should not cause a notification
        assert!(do_tick(&mut sub, &otime, time_inst, TickReason::TickTimerFired, 1).is_empty());

        // Notify the first item
        sub.notify_data_value(&1, DataValue::new_at(1, time), &time);
        let (time, time_inst) = offset(start_dt, start, 200);
        let msgs = do_tick(&mut sub, &time, time_inst, TickReason::TickTimerFired, 1);
        assert_eq!(msgs.len(), 1);
        let its = get_notifications(&msgs[0]);
        assert_eq!(its.len(), 6);
        for it in its {
            let Notification::MonitoredItemNotification(_m) = it else {
                panic!("Wrong notification type");
            };
        }
    }

    #[test]
    fn skipped_value_sent_without_further_notification() {
        let mut sub = Subscription::new(1, true, Duration::from_millis(100), 100, 20, 1, 1000);
        let start = Instant::now();
        let start_dt = Utc::now();

        sub.last_time_publishing_interval_elapsed = start;
        do_tick(&mut sub, &start_dt, start, TickReason::TickTimerFired, 1);
        assert_eq!(sub.state, SubscriptionState::Normal);

        // The item is created 50ms after the subscription, so its first value is
        // stamped later than the subscription's publishing ticks.
        let (created, _) = offset(start_dt, start, 50);
        sub.insert(
            1,
            new_monitored_item(
                1,
                ReadValueId {
                    node_id: NodeId::null(),
                    attribute_id: AttributeId::Value as u32,
                    ..Default::default()
                },
                MonitoringMode::Reporting,
                FilterType::None,
                SamplingInterval::NonZero(TimeDelta::milliseconds(100)),
                false,
                Some(DataValue::new_at(1, created.into())),
            ),
        );

        // A value with an older source timestamp is held back by the sampling interval,
        // until 100ms after the first value.
        let observed = (start_dt - TimeDelta::days(1)).into();
        sub.notify_data_value(&1, DataValue::new_at(2, observed), &created.into());

        // This tick is before the held value is due, so only the first value is sent.
        let (time, time_inst) = offset(start_dt, start, 100);
        let msgs = do_tick(&mut sub, &time, time_inst, TickReason::TickTimerFired, 1);
        assert_eq!(msgs.len(), 1);
        let its = get_notifications(&msgs[0]);
        assert_eq!(its.len(), 1);
        let Notification::MonitoredItemNotification(m) = &its[0] else {
            panic!("Wrong notification type");
        };
        assert_eq!(m.value.value, Some(Variant::Int32(1)));

        // No new value is notified, but the next tick is after the held value is due.
        let (time, time_inst) = offset(start_dt, start, 200);
        let msgs = do_tick(&mut sub, &time, time_inst, TickReason::TickTimerFired, 1);
        assert_eq!(msgs.len(), 1);
        let its = get_notifications(&msgs[0]);
        assert_eq!(its.len(), 1);
        let Notification::MonitoredItemNotification(m) = &its[0] else {
            panic!("Wrong notification type");
        };
        assert_eq!(m.value.value, Some(Variant::Int32(2)));
        assert_eq!(m.value.source_timestamp, Some(observed));
    }

    #[test]
    fn skipped_value_not_due_does_not_suppress_keep_alive() {
        let mut sub = Subscription::new(1, true, Duration::from_millis(100), 100, 5, 1, 1000);
        let start = Instant::now();
        let start_dt = Utc::now();

        sub.last_time_publishing_interval_elapsed = start;
        do_tick(&mut sub, &start_dt, start, TickReason::TickTimerFired, 1);
        assert_eq!(sub.state, SubscriptionState::Normal);

        // The first value has a source timestamp an hour ahead, so the next value
        // is held back until an hour from now.
        sub.insert(
            1,
            new_monitored_item(
                1,
                ReadValueId {
                    node_id: NodeId::null(),
                    attribute_id: AttributeId::Value as u32,
                    ..Default::default()
                },
                MonitoringMode::Reporting,
                FilterType::None,
                SamplingInterval::NonZero(TimeDelta::milliseconds(100)),
                false,
                Some(DataValue::new_at(
                    1,
                    (start_dt + TimeDelta::hours(1)).into(),
                )),
            ),
        );
        sub.notify_data_value(&1, DataValue::new_at(2, start_dt.into()), &start_dt.into());

        let mut data_messages = 0;
        let mut keep_alives = 0;
        for i in 1..=30 {
            let (time, time_inst) = offset(start_dt, start, 100 * i);
            for notif in do_tick(&mut sub, &time, time_inst, TickReason::TickTimerFired, 1) {
                if get_notifications(&notif).is_empty() {
                    keep_alives += 1;
                } else {
                    data_messages += 1;
                }
            }
        }
        // The first value is sent, then the subscription sends a keep-alive
        // every 5 publishing intervals while the held value is not due.
        assert_eq!(data_messages, 1);
        assert_eq!(keep_alives, 5);
    }

    #[test]
    fn notifications_split_across_publish_requests() {
        // At most one notification per publish.
        let mut sub = Subscription::new(1, true, Duration::from_millis(100), 100, 20, 1, 1);
        let start = Instant::now();
        let start_dt = Utc::now();

        sub.last_time_publishing_interval_elapsed = start;
        do_tick(&mut sub, &start_dt, start, TickReason::TickTimerFired, 1);
        assert_eq!(sub.state, SubscriptionState::Normal);

        for i in 1..=3 {
            sub.insert(
                i,
                new_value_item(i, MonitoringMode::Reporting, DataValue::new_now(i as i32)),
            );
        }

        // Three notifications, but only two publish requests. Each request gets a
        // message, and the subscription notes that there are more notifications.
        let (time, time_inst) = offset(start_dt, start, 100);
        let msgs = do_tick(&mut sub, &time, time_inst, TickReason::TickTimerFired, 2);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].sequence_number, 1);
        assert_eq!(msgs[1].sequence_number, 2);
        for msg in &msgs {
            assert_eq!(get_notifications(msg).len(), 1);
        }
        assert!(sub.more_notifications());
        assert_eq!(sub.state, SubscriptionState::Normal);

        // A new publish request picks up the remaining notification immediately (Normal5),
        // without waiting for the publishing interval.
        let msgs = do_tick(
            &mut sub,
            &time,
            time_inst,
            TickReason::ReceivePublishRequest,
            1,
        );
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].sequence_number, 3);
        assert_eq!(get_notifications(&msgs[0]).len(), 1);
        assert!(!sub.more_notifications());

        // Nothing left, so another publish request is just held.
        assert!(do_tick(
            &mut sub,
            &time,
            time_inst,
            TickReason::ReceivePublishRequest,
            1
        )
        .is_empty());
    }

    #[test]
    fn keep_alive_deferred_until_publish_request_available() {
        let mut sub = Subscription::new(1, true, Duration::from_millis(100), 100, 20, 1, 1000);
        let start = Instant::now();
        let start_dt = Utc::now();

        sub.last_time_publishing_interval_elapsed = start;
        do_tick(&mut sub, &start_dt, start, TickReason::TickTimerFired, 0);
        assert_eq!(sub.state, SubscriptionState::Normal);

        // No publish request when the first interval elapses, so the subscription is late.
        let (time, time_inst) = offset(start_dt, start, 100);
        assert!(do_tick(&mut sub, &time, time_inst, TickReason::TickTimerFired, 0).is_empty());
        assert_eq!(sub.state, SubscriptionState::Late);

        // A publish request arrives at the session, but is consumed before this
        // subscription is ticked, e.g. by another subscription. The keep-alive is deferred.
        assert!(do_tick(
            &mut sub,
            &time,
            time_inst,
            TickReason::ReceivePublishRequest,
            0
        )
        .is_empty());
        assert_eq!(sub.state, SubscriptionState::KeepAlive);
        assert!(sub.pending_keep_alive);

        // The next available publish request gets the keep-alive.
        let msgs = do_tick(
            &mut sub,
            &time,
            time_inst,
            TickReason::ReceivePublishRequest,
            1,
        );
        assert_eq!(msgs.len(), 1);
        assert!(get_notifications(&msgs[0]).is_empty());
        assert_eq!(msgs[0].sequence_number, 1);
        assert!(!sub.pending_keep_alive);
    }

    #[test]
    fn resend_data_split_across_publish_requests() {
        // At most one notification per publish.
        let mut sub = Subscription::new(1, true, Duration::from_millis(100), 100, 20, 1, 1);
        let start = Instant::now();
        let start_dt = Utc::now();

        sub.last_time_publishing_interval_elapsed = start;
        do_tick(&mut sub, &start_dt, start, TickReason::TickTimerFired, 1);
        for i in 1..=3 {
            sub.insert(
                i,
                new_value_item(i, MonitoringMode::Reporting, DataValue::new_now(i as i32)),
            );
        }
        // Send the initial values.
        let (time, time_inst) = offset(start_dt, start, 100);
        let msgs = do_tick(&mut sub, &time, time_inst, TickReason::TickTimerFired, 3);
        assert_eq!(msgs.len(), 3);
        assert!(!sub.more_notifications());

        // Resend data with only a single publish request available.
        sub.set_resend_data();
        let (time, time_inst) = offset(start_dt, start, 200);
        let msgs = do_tick(&mut sub, &time, time_inst, TickReason::TickTimerFired, 1);
        assert_eq!(msgs.len(), 1);
        assert!(sub.more_notifications());

        // The remaining resent values are picked up by the next publish requests.
        let mut values = get_notifications(&msgs[0]);
        for _ in 0..2 {
            let msgs = do_tick(
                &mut sub,
                &time,
                time_inst,
                TickReason::ReceivePublishRequest,
                1,
            );
            assert_eq!(msgs.len(), 1);
            values.extend(get_notifications(&msgs[0]));
        }
        assert!(!sub.more_notifications());
        let mut values: Vec<_> = values
            .into_iter()
            .map(|n| {
                let Notification::MonitoredItemNotification(m) = n else {
                    panic!("Wrong notification type");
                };
                m.value.value
            })
            .collect();
        values.sort_by_key(|v| match v {
            Some(Variant::Int32(i)) => *i,
            _ => panic!("Unexpected value {v:?}"),
        });
        assert_eq!(
            values,
            vec![
                Some(Variant::Int32(1)),
                Some(Variant::Int32(2)),
                Some(Variant::Int32(3))
            ]
        );

        // Nothing left after that.
        assert!(do_tick(
            &mut sub,
            &time,
            time_inst,
            TickReason::ReceivePublishRequest,
            1
        )
        .is_empty());
    }

    #[test]
    fn triggered_notifications_delayed_until_publish_request_available() {
        // At most one notification per publish.
        let mut sub = Subscription::new(1, true, Duration::from_millis(100), 100, 20, 1, 1);
        let start = Instant::now();
        let start_dt = Utc::now();

        sub.last_time_publishing_interval_elapsed = start;
        do_tick(&mut sub, &start_dt, start, TickReason::TickTimerFired, 1);
        sub.insert(
            1,
            new_value_item(
                1,
                MonitoringMode::Reporting,
                DataValue::new_at(0, start_dt.into()),
            ),
        );
        for i in 2..=3 {
            sub.insert(
                i,
                new_value_item(
                    i,
                    MonitoringMode::Sampling,
                    DataValue::new_at(0, start_dt.into()),
                ),
            );
        }
        sub.get_mut(&1).unwrap().set_triggering(&[2, 3], &[]);

        // Flush the initial values.
        let (time, time_inst) = offset(start_dt, start, 100);
        do_tick(&mut sub, &time, time_inst, TickReason::TickTimerFired, 10);
        assert!(sub.pending_triggered_items.is_empty());
        assert!(!sub.more_notifications());

        // Notify the sampling items, then the triggering item.
        let (otime, time_inst) = offset(start_dt, start, 200);
        let time = otime.into();
        sub.notify_data_value(&2, DataValue::new_at(20, time), &time);
        sub.notify_data_value(&3, DataValue::new_at(30, time), &time);
        sub.notify_data_value(&1, DataValue::new_at(10, time), &time);

        // Only two publish requests, so the notification for the last triggered item
        // does not fit.
        let msgs = do_tick(&mut sub, &otime, time_inst, TickReason::TickTimerFired, 2);
        assert_eq!(msgs.len(), 2);
        assert!(sub.more_notifications());
        assert_eq!(sub.pending_triggered_items.len(), 1);

        // The next publish request gets the delayed triggered notification.
        let msgs = do_tick(
            &mut sub,
            &otime,
            time_inst,
            TickReason::ReceivePublishRequest,
            1,
        );
        assert_eq!(msgs.len(), 1);
        let its = get_notifications(&msgs[0]);
        assert_eq!(its.len(), 1);
        let Notification::MonitoredItemNotification(m) = &its[0] else {
            panic!("Wrong notification type");
        };
        assert_eq!(m.value.value, Some(Variant::Int32(30)));
        assert!(sub.pending_triggered_items.is_empty());
        assert!(!sub.more_notifications());

        // Nothing is available any more, so the subscription goes back to keep-alive.
        let (time, time_inst) = offset(start_dt, start, 300);
        assert!(do_tick(&mut sub, &time, time_inst, TickReason::TickTimerFired, 1).is_empty());
        assert_eq!(sub.state, SubscriptionState::KeepAlive);
    }
}
