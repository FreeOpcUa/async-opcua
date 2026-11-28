//! Logic to _avoid_ having an explicit queue,
//! these are used for a reasonably type-safe way to
//! request one or more notifications from a subscription.

use std::collections::VecDeque;

use opcua_core::handle::Handle;
use opcua_types::{DateTime, DateTimeUtc, NotificationMessage, StatusCode};

use crate::{
    subscriptions::{monitored_item::Notification, PendingPublish},
    MonitoredItem,
};

/// A request to a subscription for one or more publish
/// notifications. This may contain space for publish
/// requests, which the subscription may write to.
pub(super) struct PublishRequestSlots<'a> {
    responses: &'a mut Vec<(PendingPublish, NotificationMessage, u32)>,
    publish_requests: &'a mut VecDeque<PendingPublish>,
    notifications: Vec<Notification>,
    max_notifications_per_publish: usize,
    subscription_id: u32,
}

impl<'a> PublishRequestSlots<'a> {
    pub(super) fn new(
        max_notifications_per_publish: usize,
        publish_requests: &'a mut VecDeque<PendingPublish>,
        responses: &'a mut Vec<(PendingPublish, NotificationMessage, u32)>,
        subscription_id: u32,
    ) -> Self {
        Self {
            responses,
            notifications: Vec::new(),
            max_notifications_per_publish,
            publish_requests,
            subscription_id,
        }
    }

    pub(super) fn any_available_publish_requests(&self) -> bool {
        !self.publish_requests.is_empty()
    }

    pub(super) fn item_notif_slot<'b>(&'b mut self) -> Option<ItemNotificationSlot<'b, 'a>> {
        if !self.publish_requests.is_empty() {
            Some(ItemNotificationSlot { slots: self })
        } else {
            None
        }
    }

    pub(super) fn try_enqueue_keep_alive(
        &mut self,
        next_sequence_number: u32,
        now: &DateTimeUtc,
    ) -> bool {
        if let Some(request) = self.publish_requests.pop_front() {
            self.responses.push((
                request,
                NotificationMessage::keep_alive(
                    // OPC-UA part 4 5.13.1.1
                    // "Each keep-alive Message is a response to a Publish request in which the notificationMessage parameter does not
                    // contain any Notifications and that contains the sequence number of the next NotificationMessage that is to be sent."
                    // Very vague, but the correct interpretation appears to be to not increment the sequence number.
                    next_sequence_number,
                    DateTime::from(*now),
                ),
                self.subscription_id,
            ));
            true
        } else {
            false
        }
    }

    pub(super) fn try_enqueue_status_change(
        &mut self,
        status_code: StatusCode,
        sequence_numbers: &mut Handle,
        now: &DateTimeUtc,
    ) -> bool {
        if let Some(request) = self.publish_requests.pop_front() {
            self.responses.push((
                request,
                NotificationMessage::status_change(
                    sequence_numbers.next(),
                    DateTime::from(*now),
                    status_code,
                ),
                self.subscription_id,
            ));
            true
        } else {
            false
        }
    }

    fn make_notification_message(&mut self, sequence_numbers: &mut Handle, now: &DateTimeUtc) {
        // Should not panic, because we should never enqueue any notifications if
        // there are no available publish requests, and never call this if there are
        // no enqueued notifications.
        let request = self
            .publish_requests
            .pop_front()
            .expect("no publish request available");

        let mut data_change_notifications = Vec::new();
        let mut event_notifications = Vec::new();

        for notif in std::mem::take(&mut self.notifications) {
            match notif {
                Notification::MonitoredItemNotification(n) => data_change_notifications.push(n),
                Notification::Event(n) => event_notifications.push(n),
            }
        }
        self.responses.push((
            request,
            NotificationMessage::data_change(
                sequence_numbers.next(),
                DateTime::from(*now),
                data_change_notifications,
                event_notifications,
            ),
            self.subscription_id,
        ));
    }

    pub(super) fn finalize(&mut self, sequence_numbers: &mut Handle, now: &DateTimeUtc) {
        if !self.notifications.is_empty() {
            self.make_notification_message(sequence_numbers, now);
        }
    }

    pub(super) fn tick_monitored_item(
        &mut self,
        item: &mut MonitoredItem,
        now: &DateTimeUtc,
        resend_data: bool,
        triggers: &mut Vec<(u32, u32)>,
        sequence_numbers: &mut Handle,
    ) -> bool {
        item.maybe_enqueue_skipped_value(&(*now).into());

        if item.is_sampling() && item.has_new_notifications() {
            triggers.extend(
                item.triggered_items()
                    .iter()
                    .copied()
                    .map(|id| (item.id(), id)),
            );
        }

        let mut more = false;

        if item.is_reporting() {
            if resend_data {
                item.add_current_value_to_queue();
            }

            while let Some(slot) = self.item_notif_slot() {
                let Some(notif) = item.pop_notification() else {
                    break;
                };
                slot.enqueue(notif, sequence_numbers, now);
            }

            more = item.has_notifications();
        }

        more
    }
}

/// A granted slot. When this is given, it guarantees
/// that a single notification may be pushed, and provides
/// `enqueue` to do so.
pub(super) struct ItemNotificationSlot<'a, 'b> {
    slots: &'a mut PublishRequestSlots<'b>,
}

impl<'a, 'b> ItemNotificationSlot<'a, 'b> {
    pub(super) fn enqueue(
        self,
        notif: Notification,
        sequence_numbers: &mut Handle,
        now: &DateTimeUtc,
    ) {
        self.slots.notifications.push(notif);
        if self.slots.notifications.len() >= self.slots.max_notifications_per_publish
            && self.slots.max_notifications_per_publish > 0
        {
            self.slots.make_notification_message(sequence_numbers, now);
        }
    }
}
