// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock
//! Helpers for NotificationMessage types
use tracing::{debug, trace};

use crate::{
    date_time::DateTime, diagnostic_info::DiagnosticInfo, extension_object::ExtensionObject,
    match_extension_object_owned, status_code::StatusCode, DataChangeNotification, EventFieldList,
    EventNotificationList, MonitoredItemNotification, NotificationMessage,
    StatusChangeNotification,
};

impl NotificationMessage {
    /// Create a notification message which contains data change AND / OR events. Calling this with
    /// neither will panic. Notification data can have up to 2 elements to covers the case in
    /// table 158 where a subscription contains monitored items for events and data.
    pub fn data_change(
        sequence_number: u32,
        publish_time: DateTime,
        data_change_notifications: Vec<MonitoredItemNotification>,
        event_notifications: Vec<EventFieldList>,
    ) -> NotificationMessage {
        if data_change_notifications.is_empty() && event_notifications.is_empty() {
            panic!("No notifications supplied to data_change()");
        }

        let mut notification_data = Vec::with_capacity(2);
        if !data_change_notifications.is_empty() {
            let data_change_notification = DataChangeNotification {
                monitored_items: Some(data_change_notifications),
                diagnostic_infos: None,
            };
            trace!("data change notification = {:?}", data_change_notification);
            notification_data.push(ExtensionObject::from_message(data_change_notification));
        }
        if !event_notifications.is_empty() {
            let event_notification_list = EventNotificationList {
                events: Some(event_notifications),
            };
            trace!("event notification = {:?}", event_notification_list);
            notification_data.push(ExtensionObject::from_message(event_notification_list));
        }

        // Both data and events are serialized
        NotificationMessage {
            sequence_number,
            publish_time,
            notification_data: Some(notification_data),
        }
    }
    /// Create a status change notification message
    pub fn status_change(
        sequence_number: u32,
        publish_time: DateTime,
        status: StatusCode,
    ) -> NotificationMessage {
        let status_change_notification = StatusChangeNotification {
            status,
            diagnostic_info: DiagnosticInfo::null(),
        };
        let notification_data = ExtensionObject::from_message(status_change_notification);
        NotificationMessage {
            sequence_number,
            publish_time,
            notification_data: Some(vec![notification_data]),
        }
    }

    /// Create a keep-alive notification message
    pub fn keep_alive(sequence_number: u32, publish_time: DateTime) -> NotificationMessage {
        NotificationMessage {
            sequence_number,
            publish_time,
            notification_data: None,
        }
    }

    fn process_notification(
        n: ExtensionObject,
        data_changes: &mut Vec<DataChangeNotification>,
        events: &mut Vec<EventNotificationList>,
    ) {
        match_extension_object_owned!(n,
            n: DataChangeNotification => data_changes.push(n),
            n: EventNotificationList => events.push(n),
            _ => {
                if n.inner_is::<StatusChangeNotification>() {
                    debug!("Ignoring a StatusChangeNotification");
                } else {
                    debug!("Ignoring a notification of type {:?}", n.binary_type_id());
                }
            }
        )
    }

    /// Extract notifications from the message. Unrecognized / unparseable notifications will be
    /// ignored. If there are no notifications, the function will return `None`.
    pub fn into_notifications(
        self,
    ) -> Option<(Vec<DataChangeNotification>, Vec<EventNotificationList>)> {
        if let Some(notification_data) = self.notification_data {
            let mut data_changes = Vec::with_capacity(notification_data.len());
            let mut events = Vec::with_capacity(notification_data.len());

            // Build up the notifications
            notification_data.into_iter().for_each(|n| {
                Self::process_notification(n, &mut data_changes, &mut events);
            });
            if data_changes.is_empty() && events.is_empty() {
                None
            } else {
                Some((data_changes, events))
            }
        } else {
            None
        }
    }
}
