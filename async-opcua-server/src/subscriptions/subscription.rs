use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::{Duration, Instant},
};

use opcua_core::handle::Handle;
use opcua_nodes::{Event, TypeTree};
use opcua_types::{DataValue, DateTime, DateTimeUtc, NotificationMessage, StatusCode};
use tracing::{debug, trace, warn};

use crate::node_manager::MonitoredItemRef;

use super::monitored_item::{MonitoredItem, Notification};
use super::pool::NotificationBuffer;

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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(super) enum TickResult {
    Expired,
    Enqueued,
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
    notified_monitored_items: HashSet<u32>,
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
    // Currently outstanding notifications to send
    notifications: VecDeque<NotificationMessage>,
    /// Maximum number of queued notifications.
    max_queued_notifications: usize,
    /// Maximum number of notifications per publish.
    max_notifications_per_publish: usize,
    /// Number of notification messages discarded because the queue limit was reached.
    discarded_message_count: u32,
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
        max_queued_notifications: usize,
        max_notifications_per_publish: u64,
    ) -> Self {
        Self {
            id,
            publishing_interval,
            max_lifetime_counter: lifetime_counter,
            max_keep_alive_counter: keep_alive_counter,
            priority,
            monitored_items: HashMap::new(),
            notified_monitored_items: HashSet::new(),
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
            notifications: VecDeque::new(),
            max_queued_notifications,
            max_notifications_per_publish: max_notifications_per_publish as usize,
            discarded_message_count: 0,
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

    pub(super) fn monitored_item_refs(&self) -> Vec<MonitoredItemRef> {
        self.monitored_items
            .values()
            .map(|item| {
                MonitoredItemRef::new(
                    MonitoredItemHandle {
                        subscription_id: self.id,
                        monitored_item_id: item.id(),
                    },
                    item.item_to_monitor().node_id.clone(),
                    item.item_to_monitor().attribute_id,
                )
            })
            .collect()
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

    pub(super) fn update_monitored_item_value(
        &mut self,
        handle: MonitoredItemHandle,
        value: DataValue,
        now: &DateTime,
    ) {
        if handle.subscription_id != self.id {
            return;
        }

        let id = handle.monitored_item_id;
        if let Some(item) = self.monitored_items.get_mut(&id) {
            if item.notify_data_value(value, now, false) {
                self.notified_monitored_items.insert(id);
            }
        }
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
                if self.publishing_enabled || !self.publishing_enabled && !p.more_notifications =>
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

    fn notifications_available(&self, resend_data: bool) -> bool {
        if !self.notified_monitored_items.is_empty() {
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
        publishing_req_queued: bool,
        buffer: &mut NotificationBuffer,
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
        // First, get the actual state transition we're in.
        let transition = self.get_state_transition(
            tick_reason,
            SubscriptionStateParams {
                notifications_available: self.notifications_available(self.resend_data),
                more_notifications: !self.notifications.is_empty(),
                publishing_req_queued,
            },
        );
        let action = self.handle_state_transition(transition);

        match action {
            UpdateStateAction::None => TickResult::None,
            UpdateStateAction::ReturnKeepAlive => {
                let notification = NotificationMessage::keep_alive(
                    // OPC-UA part 4 5.13.1.1
                    // "Each keep-alive Message is a response to a Publish request in which the notificationMessage parameter does not
                    // contain any Notifications and that contains the sequence number of the next NotificationMessage that is to be sent."
                    // Very vague, but the correct interpretation appears to be to not increment the sequence number.
                    self.sequence_number.peek_next(),
                    DateTime::from(*now),
                );
                self.enqueue_notification(notification);
                self.enforce_queued_notification_limit();
                TickResult::Enqueued
            }
            UpdateStateAction::ReturnNotifications => {
                let resend_data = std::mem::take(&mut self.resend_data);
                buffer.reset();
                let messages = self.tick_monitored_items(now, resend_data, buffer);
                for msg in messages {
                    self.enqueue_notification(msg);
                }
                self.enforce_queued_notification_limit();
                // Every notification has been moved into an enqueued message
                // at this point, so the scratch buffer can safely be reused
                // by the next subscription tick.
                debug_assert!(buffer.is_empty());
                TickResult::Enqueued
            }
            UpdateStateAction::SubscriptionCreated => TickResult::None,
            UpdateStateAction::SubscriptionExpired => {
                debug!("Subscription status change to closed / timeout");
                self.monitored_items.clear();
                let notification = NotificationMessage::status_change(
                    self.sequence_number.next(),
                    DateTime::from(*now),
                    StatusCode::BadTimeout,
                );
                self.enqueue_notification(notification);
                self.enforce_queued_notification_limit();
                TickResult::Expired
            }
        }
    }

    fn enqueue_notification(&mut self, notification: NotificationMessage) {
        // debug!("Enqueuing notification {:?}", notification);
        self.notifications.push_back(notification);
    }

    fn enforce_queued_notification_limit(&mut self) {
        if self.max_queued_notifications == 0
            || self.notifications.len() <= self.max_queued_notifications
        {
            return;
        }

        let dropped = self.notifications.len() - self.max_queued_notifications;
        warn!(
            "Maximum number of queued notifications exceeded, dropping {} oldest. Subscription ID: {}",
            dropped, self.id
        );
        for _ in 0..dropped {
            self.notifications.pop_front();
        }
        self.discarded_message_count = self.discarded_message_count.saturating_add(dropped as u32);
    }

    pub(crate) fn take_notification(&mut self) -> Option<NotificationMessage> {
        self.notifications.pop_front()
    }

    pub(super) fn more_notifications(&self) -> bool {
        !self.notifications.is_empty()
    }

    pub(super) fn ready_to_remove(&self) -> bool {
        self.state == SubscriptionState::Closed && self.notifications.is_empty()
    }

    fn handle_triggers(
        &mut self,
        now: &DateTimeUtc,
        triggers: &mut Vec<(u32, u32)>,
        notifications: &mut Vec<Notification>,
        messages: &mut Vec<NotificationMessage>,
    ) {
        for (triggering_item, item_id) in triggers.drain(..) {
            let Some(item) = self.monitored_items.get_mut(&item_id) else {
                if let Some(item) = self.monitored_items.get_mut(&triggering_item) {
                    item.remove_dead_trigger(item_id);
                }
                continue;
            };

            while let Some(notif) = item.pop_notification() {
                notifications.push(notif);
                if notifications.len() >= self.max_notifications_per_publish
                    && self.max_notifications_per_publish > 0
                {
                    messages.push(Self::make_notification_message(
                        self.sequence_number.next(),
                        notifications,
                        now,
                    ));
                }
            }
        }
    }

    /// Build a notification message by draining the pooled scratch buffer,
    /// retaining its allocated capacity for reuse.
    fn make_notification_message(
        next_sequence_number: u32,
        notifications: &mut Vec<Notification>,
        now: &DateTimeUtc,
    ) -> NotificationMessage {
        let mut data_change_notifications = Vec::new();
        let mut event_notifications = Vec::new();

        for notif in notifications.drain(..) {
            match notif {
                Notification::MonitoredItemNotification(n) => data_change_notifications.push(n),
                Notification::Event(n) => event_notifications.push(n),
            }
        }

        NotificationMessage::data_change(
            next_sequence_number,
            DateTime::from(*now),
            data_change_notifications,
            event_notifications,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn tick_monitored_item(
        monitored_item: &mut MonitoredItem,
        now: &DateTimeUtc,
        resend_data: bool,
        max_notifications: usize,
        triggers: &mut Vec<(u32, u32)>,
        notifications: &mut Vec<Notification>,
        messages: &mut Vec<NotificationMessage>,
        sequence_numbers: &mut Handle,
    ) {
        monitored_item.maybe_enqueue_skipped_value(&(*now).into());

        if monitored_item.is_sampling() && monitored_item.has_new_notifications() {
            triggers.extend(
                monitored_item
                    .triggered_items()
                    .iter()
                    .copied()
                    .map(|id| (monitored_item.id(), id)),
            );
        }

        if monitored_item.is_reporting() {
            if resend_data {
                monitored_item.add_current_value_to_queue();
            }
            if monitored_item.has_notifications() {
                while let Some(notif) = monitored_item.pop_notification() {
                    notifications.push(notif);
                    if notifications.len() >= max_notifications && max_notifications > 0 {
                        messages.push(Self::make_notification_message(
                            sequence_numbers.next(),
                            notifications,
                            now,
                        ));
                    }
                }
            }
        }
    }

    /// Scan monitored items for notifications, accumulating them in the
    /// pooled scratch `buffer` rather than freshly allocated storage.
    fn tick_monitored_items(
        &mut self,
        now: &DateTimeUtc,
        resend_data: bool,
        buffer: &mut NotificationBuffer,
    ) -> Vec<NotificationMessage> {
        let mut messages = Vec::new();
        let NotificationBuffer {
            notifications,
            triggers,
        } = buffer;

        // If resend data is true, we must visit ever monitored item
        if resend_data {
            for monitored_item in self.monitored_items.values_mut() {
                Self::tick_monitored_item(
                    monitored_item,
                    now,
                    resend_data,
                    self.max_notifications_per_publish,
                    triggers,
                    notifications,
                    &mut messages,
                    &mut self.sequence_number,
                );
            }
        } else {
            for item_id in self.notified_monitored_items.drain() {
                let Some(monitored_item) = self.monitored_items.get_mut(&item_id) else {
                    continue;
                };
                Self::tick_monitored_item(
                    monitored_item,
                    now,
                    resend_data,
                    self.max_notifications_per_publish,
                    triggers,
                    notifications,
                    &mut messages,
                    &mut self.sequence_number,
                );
            }
        }

        self.handle_triggers(now, triggers, notifications, &mut messages);

        if !notifications.is_empty() {
            messages.push(Self::make_notification_message(
                self.sequence_number.next(),
                notifications,
                now,
            ));
        }

        messages
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

    /// The maximum number of notification messages queued for this subscription.
    pub fn max_queued_notifications(&self) -> usize {
        self.max_queued_notifications
    }

    /// The maximum number of notifications per notification message for this
    /// subscription.
    pub fn max_notifications_per_publish(&self) -> usize {
        self.max_notifications_per_publish
    }

    /// The number of notification messages discarded because the queue limit was reached.
    pub fn discarded_message_count(&self) -> u32 {
        self.discarded_message_count
    }

    /// The current state of the subscription.
    pub fn state(&self) -> SubscriptionState {
        self.state
    }
}

#[cfg(test)]
mod tests {
    use std::{
        alloc::{GlobalAlloc, Layout, System},
        hint::black_box,
        sync::{
            atomic::{AtomicU64, AtomicUsize, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    };

    use chrono::{TimeDelta, Utc};

    use crate::{
        subscriptions::monitored_item::{
            tests::new_monitored_item, FilterType, Notification, SamplingInterval,
        },
        SubscriptionState,
    };
    use opcua_types::{
        match_extension_object_owned, AttributeId, DataChangeNotification, DataValue, DateTime,
        DateTimeUtc, EventNotificationList, MonitoredItemNotification, MonitoringMode, NodeId,
        NotificationMessage, PublishResponse, ReadValueId, StatusChangeNotification, StatusCode,
        Variant,
    };

    use super::{Subscription, TickReason};

    #[global_allocator]
    static COUNTING_ALLOCATOR: CountingAllocator = CountingAllocator::new();

    struct CountingAllocator {
        allocation_count: AtomicUsize,
        allocated_bytes: AtomicU64,
    }

    #[derive(Debug, Copy, Clone, Default)]
    struct AllocationSnapshot {
        count: usize,
        bytes: u64,
    }

    impl CountingAllocator {
        const fn new() -> Self {
            Self {
                allocation_count: AtomicUsize::new(0),
                allocated_bytes: AtomicU64::new(0),
            }
        }

        fn reset(&self) {
            self.allocation_count.store(0, Ordering::Relaxed);
            self.allocated_bytes.store(0, Ordering::Relaxed);
        }

        fn snapshot(&self) -> AllocationSnapshot {
            AllocationSnapshot {
                count: self.allocation_count.load(Ordering::Relaxed),
                bytes: self.allocated_bytes.load(Ordering::Relaxed),
            }
        }

        fn record_allocation(&self, bytes: usize) {
            self.allocation_count.fetch_add(1, Ordering::Relaxed);
            self.allocated_bytes
                .fetch_add(bytes as u64, Ordering::Relaxed);
        }
    }

    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            self.record_allocation(layout.size());
            // SAFETY: This allocator only observes allocation metadata, then delegates the
            // allocation request unchanged to the standard system allocator.
            unsafe { System.alloc(layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            self.record_allocation(layout.size());
            // SAFETY: This allocator only observes allocation metadata, then delegates the
            // zeroed allocation request unchanged to the standard system allocator.
            unsafe { System.alloc_zeroed(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // SAFETY: Pointers returned by the delegated system allocator are deallocated
            // through the same allocator with the original layout.
            unsafe { System.dealloc(ptr, layout) };
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            self.record_allocation(new_size);
            // SAFETY: This allocator only observes reallocation metadata, then delegates the
            // reallocation request unchanged to the standard system allocator.
            unsafe { System.realloc(ptr, layout, new_size) }
        }
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

    fn make_publish_baseline_notifications(count: usize) -> Vec<Notification> {
        (0..count)
            .map(|idx| {
                Notification::MonitoredItemNotification(MonitoredItemNotification {
                    client_handle: idx as u32,
                    value: DataValue::new_now(idx as i32),
                })
            })
            .collect()
    }

    fn measure_publish_baseline_once(
        notification_count: usize,
        sequence_number: u32,
        now: &DateTimeUtc,
    ) -> (AllocationSnapshot, AllocationSnapshot) {
        let mut notifications = make_publish_baseline_notifications(notification_count);

        COUNTING_ALLOCATOR.reset();
        let message =
            Subscription::make_notification_message(sequence_number, &mut notifications, now);
        let construction = COUNTING_ALLOCATOR.snapshot();
        black_box(&message);

        let notification = Arc::new(message);
        COUNTING_ALLOCATOR.reset();
        let response = PublishResponse {
            notification_message: (*notification).clone(),
            ..PublishResponse::default()
        };
        let publish_clone = COUNTING_ALLOCATOR.snapshot();
        black_box(response);

        (construction, publish_clone)
    }

    #[test]
    #[ignore = "allocation baseline harness; run explicitly with --ignored --nocapture"]
    fn publish_allocation_baseline_reports_construction_and_clone() {
        const WARMUP_RUNS: u32 = 3;
        const MEASURED_RUNS: u32 = 5;
        const NOTIFICATION_COUNTS: [usize; 2] = [1000, 5000];

        let now = Utc::now();

        for notification_count in NOTIFICATION_COUNTS {
            for sequence_number in 0..WARMUP_RUNS {
                let (construction, publish_clone) =
                    measure_publish_baseline_once(notification_count, sequence_number + 1, &now);
                black_box((construction, publish_clone));
            }

            let mut construction_total = AllocationSnapshot::default();
            let mut clone_total = AllocationSnapshot::default();

            for run in 0..MEASURED_RUNS {
                let (construction, publish_clone) =
                    measure_publish_baseline_once(notification_count, WARMUP_RUNS + run + 1, &now);
                construction_total.count += construction.count;
                construction_total.bytes += construction.bytes;
                clone_total.count += publish_clone.count;
                clone_total.bytes += publish_clone.bytes;
            }

            println!(
                "publish_alloc_baseline monitored_items={} runs={} construction_allocs_avg={} construction_bytes_avg={} publish_clone_allocs_avg={} publish_clone_bytes_avg={}",
                notification_count,
                MEASURED_RUNS,
                construction_total.count / MEASURED_RUNS as usize,
                construction_total.bytes / u64::from(MEASURED_RUNS),
                clone_total.count / MEASURED_RUNS as usize,
                clone_total.bytes / u64::from(MEASURED_RUNS),
            );
        }
    }

    #[test]
    fn monitored_item_refs_include_node_attribute_and_handles_for_revalidation() {
        let mut sub =
            Subscription::new(42, true, Duration::from_millis(100), 100, 20, 1, 100, 1000);

        sub.insert(
            11,
            new_monitored_item(
                11,
                ReadValueId {
                    node_id: NodeId::new(2, "Temperature"),
                    attribute_id: AttributeId::Value as u32,
                    ..Default::default()
                },
                MonitoringMode::Reporting,
                FilterType::None,
                SamplingInterval::Subscription,
                true,
                None,
            ),
        );
        sub.insert(
            12,
            new_monitored_item(
                12,
                ReadValueId {
                    node_id: NodeId::new(2, "Valve"),
                    attribute_id: AttributeId::UserAccessLevel as u32,
                    ..Default::default()
                },
                MonitoringMode::Reporting,
                FilterType::None,
                SamplingInterval::Subscription,
                true,
                None,
            ),
        );

        let mut refs = sub.monitored_item_refs();
        refs.sort_by_key(|item| item.handle().monitored_item_id);

        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].handle().subscription_id, 42);
        assert_eq!(refs[0].handle().monitored_item_id, 11);
        assert_eq!(refs[0].node_id(), &NodeId::new(2, "Temperature"));
        assert_eq!(refs[0].attribute(), AttributeId::Value);
        assert_eq!(refs[1].handle().subscription_id, 42);
        assert_eq!(refs[1].handle().monitored_item_id, 12);
        assert_eq!(refs[1].node_id(), &NodeId::new(2, "Valve"));
        assert_eq!(refs[1].attribute(), AttributeId::UserAccessLevel);
    }

    #[test]
    fn tick() {
        let mut buffer = super::NotificationBuffer::new();
        let mut sub = Subscription::new(1, true, Duration::from_millis(100), 100, 20, 1, 100, 1000);
        let start = Instant::now();
        let start_dt = Utc::now();

        sub.last_time_publishing_interval_elapsed = start;

        // Subscription is creating, handle the first tick.
        assert_eq!(sub.state, SubscriptionState::Creating);
        sub.tick(
            &start_dt,
            start,
            TickReason::TickTimerFired,
            true,
            &mut buffer,
        );
        assert_eq!(sub.state, SubscriptionState::Normal);
        assert!(!sub.first_message_sent);

        // Tick again before the publishing interval has elapsed, should change nothing.
        sub.tick(
            &start_dt,
            start,
            TickReason::TickTimerFired,
            true,
            &mut buffer,
        );
        assert_eq!(sub.state, SubscriptionState::Normal);
        assert!(!sub.first_message_sent);

        // Add a monitored item
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
                Some(DataValue::new_now(123)),
            ),
        );
        // New tick at next publishing interval should produce something
        let (time, time_inst) = offset(start_dt, start, 100);
        sub.tick(
            &time,
            time_inst,
            TickReason::TickTimerFired,
            true,
            &mut buffer,
        );
        assert_eq!(sub.state, SubscriptionState::Normal);
        assert!(sub.first_message_sent);
        let notif = sub.take_notification().unwrap();
        let its = get_notifications(&notif);
        assert_eq!(its.len(), 1);
        assert_eq!(notif.sequence_number, 1);
        let Notification::MonitoredItemNotification(m) = &its[0] else {
            panic!("Wrong notification type");
        };
        assert_eq!(m.value.value, Some(Variant::Int32(123)));

        // Next tick produces nothing
        let (time, time_inst) = offset(start_dt, start, 200);

        sub.tick(
            &time,
            time_inst,
            TickReason::TickTimerFired,
            true,
            &mut buffer,
        );
        // State transitions to keep alive due to empty publish.
        assert_eq!(sub.state, SubscriptionState::KeepAlive);
        assert_eq!(sub.lifetime_counter, 98);
        assert!(sub.first_message_sent);
        assert!(sub.take_notification().is_none());

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
        sub.tick(
            &time,
            time_inst,
            TickReason::TickTimerFired,
            true,
            &mut buffer,
        );
        // State transitions back to normal.
        assert_eq!(sub.state, SubscriptionState::Normal);
        assert!(sub.first_message_sent);
        assert_eq!(sub.lifetime_counter, 99);
        let notif = sub.take_notification().unwrap();
        let its = get_notifications(&notif);
        assert_eq!(notif.sequence_number, 2);
        assert_eq!(its.len(), 1);
        let Notification::MonitoredItemNotification(m) = &its[0] else {
            panic!("Wrong notification type");
        };
        assert_eq!(m.value.value, Some(Variant::Int32(321)));

        for i in 0..20 {
            let (time, time_inst) = offset(start_dt, start, 1000 + i * 100);
            sub.tick(
                &time,
                time_inst,
                TickReason::TickTimerFired,
                true,
                &mut buffer,
            );
            assert_eq!(sub.state, SubscriptionState::KeepAlive);
            assert_eq!(sub.lifetime_counter, (99 - i - 1) as u32);
            assert_eq!(sub.keep_alive_counter, (20 - i) as u32);
            assert!(sub.take_notification().is_none());
        }
        assert_eq!(sub.lifetime_counter, 79);
        assert_eq!(sub.keep_alive_counter, 1);

        // Tick one more time to get a keep alive
        let (time, time_inst) = offset(start_dt, start, 3000);
        sub.tick(
            &time,
            time_inst,
            TickReason::TickTimerFired,
            true,
            &mut buffer,
        );
        assert_eq!(sub.state, SubscriptionState::KeepAlive);
        assert_eq!(sub.lifetime_counter, 78);
        assert_eq!(sub.keep_alive_counter, 20);
        let notif = sub.take_notification().unwrap();
        let its = get_notifications(&notif);
        assert!(its.is_empty());
        // The next sequence number...
        assert_eq!(notif.sequence_number, 3);

        // Tick another 20 times to become late
        for i in 0..19 {
            let (time, time_inst) = offset(start_dt, start, 3100 + i * 100);
            sub.tick(
                &time,
                time_inst,
                TickReason::TickTimerFired,
                false,
                &mut buffer,
            );
            assert_eq!(sub.state, SubscriptionState::KeepAlive);
            assert_eq!(sub.lifetime_counter, (78 - i - 1) as u32);
        }

        // Tick another 58 times to expire
        for i in 0..58 {
            let (time, time_inst) = offset(start_dt, start, 5100 + i * 100);
            sub.tick(
                &time,
                time_inst,
                TickReason::TickTimerFired,
                false,
                &mut buffer,
            );
            assert_eq!(sub.state, SubscriptionState::Late);
            assert_eq!(sub.lifetime_counter, (58 - i) as u32);
        }
        assert_eq!(sub.lifetime_counter, 1);

        let (time, time_inst) = offset(start_dt, start, 20000);
        sub.tick(
            &time,
            time_inst,
            TickReason::TickTimerFired,
            false,
            &mut buffer,
        );
        assert_eq!(sub.state, SubscriptionState::Closed);
        let notif = sub.take_notification().unwrap();
        assert_eq!(notif.sequence_number, 3);
        assert_eq!(1, notif.notification_data.as_ref().unwrap().len());
        let status_change = notif.notification_data.as_ref().unwrap()[0]
            .inner_as::<StatusChangeNotification>()
            .unwrap();
        assert_eq!(status_change.status, StatusCode::BadTimeout);
    }

    #[test]
    fn monitored_item_triggers() {
        let mut buffer = super::NotificationBuffer::new();
        let mut sub = Subscription::new(1, true, Duration::from_millis(100), 100, 20, 1, 100, 1000);
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
        sub.tick(
            &otime,
            time_inst,
            TickReason::TickTimerFired,
            true,
            &mut buffer,
        );
        assert!(sub.take_notification().is_none());

        // Notify the first item
        sub.notify_data_value(&1, DataValue::new_at(1, time), &time);
        let (time, time_inst) = offset(start_dt, start, 200);
        sub.tick(
            &time,
            time_inst,
            TickReason::TickTimerFired,
            true,
            &mut buffer,
        );
        let notif = sub.take_notification().unwrap();
        let its = get_notifications(&notif);
        assert_eq!(its.len(), 6);
        for it in its {
            let Notification::MonitoredItemNotification(_m) = it else {
                panic!("Wrong notification type");
            };
        }
    }
}
