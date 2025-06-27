use opcua_types::{
    match_extension_object_owned, DataChangeNotification, DataValue, EventNotificationList,
    NotificationMessage, StatusChangeNotification, Variant,
};

use crate::{session::services::subscriptions::MonitoredItemMap, MonitoredItem};

/// A trait for handling subscription notifications.
/// Typically, you will want to use OnSubscriptionNotification instead,
/// which has a blanket implementation for this trait.
pub trait OnSubscriptionNotificationCore: Send + Sync {
    /// Called when a notification is received on a subscription.
    fn on_subscription_notification(
        &mut self,
        notification: NotificationMessage,
        monitored_items: MonitoredItemMap<'_>,
    );
}

impl<T> OnSubscriptionNotificationCore for T
where
    T: OnSubscriptionNotification + Send + Sync,
{
    fn on_subscription_notification(
        &mut self,
        notification: NotificationMessage,
        monitored_items: MonitoredItemMap<'_>,
    ) {
        let Some(notifications) = notification.notification_data else {
            return;
        };

        for obj in notifications {
            match_extension_object_owned!(obj,
                v: DataChangeNotification => {
                    for notif in v.monitored_items.into_iter().flatten() {
                        let item = monitored_items.get(notif.client_handle);

                        if let Some(item) = item {
                            self.on_data_value(notif.value, item);
                        } else {
                            tracing::warn!("Received notification for unknown monitored item {}", notif.client_handle);
                        }
                    }
                },
                v: EventNotificationList => {
                    for notif in v.events.into_iter().flatten() {
                        let item = monitored_items.get(notif.client_handle);

                        if let Some(item) = item {
                            self.on_event(notif.event_fields, item);
                        }
                    }
                },
                v: StatusChangeNotification => {
                    self.on_subscription_status_change(v);
                }
            )
        }
    }
}

/// A set of callbacks for notifications on a subscription.
/// You may implement this on your own struct, or simply use [SubscriptionCallbacks]
/// for a simple collection of closures.
pub trait OnSubscriptionNotification: Send + Sync {
    /// Called when a subscription changes state on the server.
    #[allow(unused)]
    fn on_subscription_status_change(&mut self, notification: StatusChangeNotification) {}

    /// Called for each data value change.
    #[allow(unused)]
    fn on_data_value(&mut self, notification: DataValue, item: &MonitoredItem) {}

    /// Called for each received event.
    #[allow(unused)]
    fn on_event(&mut self, event_fields: Option<Vec<Variant>>, item: &MonitoredItem) {}
}

type StatusChangeCallbackFun = dyn FnMut(StatusChangeNotification) + Send + Sync;
type DataChangeCallbackFun = dyn FnMut(DataValue, &MonitoredItem) + Send + Sync;
type EventCallbackFun = dyn FnMut(Option<Vec<Variant>>, &MonitoredItem) + Send + Sync;

/// A convenient wrapper around a set of callback functions that implements [OnSubscriptionNotification]
pub struct SubscriptionCallbacks {
    status_change: Box<StatusChangeCallbackFun>,
    data_value: Box<DataChangeCallbackFun>,
    event: Box<EventCallbackFun>,
}

impl SubscriptionCallbacks {
    /// Create a new subscription callback wrapper.
    ///
    /// # Arguments
    ///
    /// * `status_change` - Called when a subscription changes state on the server.
    /// * `data_value` - Called for each received data value.
    /// * `event` - Called for each received event.
    pub fn new(
        status_change: impl FnMut(StatusChangeNotification) + Send + Sync + 'static,
        data_value: impl FnMut(DataValue, &MonitoredItem) + Send + Sync + 'static,
        event: impl FnMut(Option<Vec<Variant>>, &MonitoredItem) + Send + Sync + 'static,
    ) -> Self {
        Self {
            status_change: Box::new(status_change) as Box<StatusChangeCallbackFun>,
            data_value: Box::new(data_value) as Box<DataChangeCallbackFun>,
            event: Box::new(event) as Box<EventCallbackFun>,
        }
    }
}

impl OnSubscriptionNotification for SubscriptionCallbacks {
    fn on_subscription_status_change(&mut self, notification: StatusChangeNotification) {
        (self.status_change)(notification);
    }

    fn on_data_value(&mut self, notification: DataValue, item: &MonitoredItem) {
        (self.data_value)(notification, item);
    }

    fn on_event(&mut self, event_fields: Option<Vec<Variant>>, item: &MonitoredItem) {
        (self.event)(event_fields, item);
    }
}

/// A wrapper around a data change callback that implements [OnSubscriptionNotification]
pub struct DataChangeCallback {
    data_value: Box<DataChangeCallbackFun>,
}

impl DataChangeCallback {
    /// Create a new data change callback wrapper.
    ///
    /// # Arguments
    ///
    /// * `data_value` - Called for each received data value.
    pub fn new(data_value: impl FnMut(DataValue, &MonitoredItem) + Send + Sync + 'static) -> Self {
        Self {
            data_value: Box::new(data_value)
                as Box<dyn FnMut(DataValue, &MonitoredItem) + Send + Sync>,
        }
    }
}

impl OnSubscriptionNotification for DataChangeCallback {
    fn on_data_value(&mut self, notification: DataValue, item: &MonitoredItem) {
        (self.data_value)(notification, item);
    }
}

/// A wrapper around an event callback that implements [OnSubscriptionNotification]
pub struct EventCallback {
    event: Box<EventCallbackFun>,
}

impl EventCallback {
    /// Create a new event callback wrapper.
    ///
    /// # Arguments
    ///
    /// * `data_value` - Called for each received data value.
    pub fn new(
        event: impl FnMut(Option<Vec<Variant>>, &MonitoredItem) + Send + Sync + 'static,
    ) -> Self {
        Self {
            event: Box::new(event)
                as Box<dyn FnMut(Option<Vec<Variant>>, &MonitoredItem) + Send + Sync>,
        }
    }
}

impl OnSubscriptionNotification for EventCallback {
    fn on_event(&mut self, event_fields: Option<Vec<Variant>>, item: &MonitoredItem) {
        (self.event)(event_fields, item);
    }
}
