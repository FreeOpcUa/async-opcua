pub(crate) mod event_loop;
pub use event_loop::SubscriptionActivity;

mod service;
pub(crate) mod state;

use std::{
    collections::{BTreeSet, HashMap},
    time::Duration,
};

use opcua_types::{
    match_extension_object_owned, DataChangeNotification, DataValue, EventNotificationList,
    ExtensionObject, MonitoringMode, NotificationMessage, ReadValueId, StatusChangeNotification,
    Variant,
};

pub use service::{
    CreateMonitoredItems, CreateSubscription, DeleteMonitoredItems, DeleteSubscriptions,
    ModifyMonitoredItems, ModifySubscription, SetMonitoringMode, SetPublishingMode, SetTriggering,
    TransferSubscriptions,
};

pub(crate) struct CreateMonitoredItem {
    pub id: u32,
    pub client_handle: u32,
    pub item_to_monitor: ReadValueId,
    pub monitoring_mode: MonitoringMode,
    pub queue_size: u32,
    pub discard_oldest: bool,
    pub sampling_interval: f64,
    pub filter: ExtensionObject,
}

pub(crate) struct ModifyMonitoredItem {
    pub id: u32,
    pub sampling_interval: f64,
    pub queue_size: u32,
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

#[derive(Debug, Clone)]
/// Client-side representation of a monitored item.
pub struct MonitoredItem {
    /// This is the monitored item's id within the subscription
    id: u32,
    /// Monitored item's handle. Used internally - not modifiable
    client_handle: u32,
    // The thing that is actually being monitored - the node id, attribute, index, encoding.
    item_to_monitor: ReadValueId,
    /// Queue size
    queue_size: usize,
    /// Monitoring mode
    monitoring_mode: MonitoringMode,
    /// Sampling interval
    sampling_interval: f64,
    /// Triggered items
    triggered_items: BTreeSet<u32>,
    /// Whether to discard oldest values on queue overflow
    discard_oldest: bool,
    /// Active filter
    filter: ExtensionObject,
}

impl MonitoredItem {
    /// Create a new monitored item.
    pub fn new(client_handle: u32) -> MonitoredItem {
        MonitoredItem {
            id: 0,
            client_handle,
            item_to_monitor: ReadValueId::default(),
            queue_size: 1,
            monitoring_mode: MonitoringMode::Reporting,
            sampling_interval: 0.0,
            triggered_items: BTreeSet::new(),
            discard_oldest: true,
            filter: ExtensionObject::null(),
        }
    }

    /// Server assigned ID of the monitored item.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Client assigned handle for the monitored item.
    pub fn client_handle(&self) -> u32 {
        self.client_handle
    }

    /// Attribute and node ID for the item the monitored item receives notifications for.
    pub fn item_to_monitor(&self) -> &ReadValueId {
        &self.item_to_monitor
    }

    /// Sampling interval.
    pub fn sampling_interval(&self) -> f64 {
        self.sampling_interval
    }

    /// Queue size on the server.
    pub fn queue_size(&self) -> usize {
        self.queue_size
    }

    /// Whether the oldest values are discarded on queue overflow on the server.
    pub fn discard_oldest(&self) -> bool {
        self.discard_oldest
    }

    pub(crate) fn set_sampling_interval(&mut self, value: f64) {
        self.sampling_interval = value;
    }

    pub(crate) fn set_queue_size(&mut self, value: usize) {
        self.queue_size = value;
    }

    pub(crate) fn set_monitoring_mode(&mut self, monitoring_mode: MonitoringMode) {
        self.monitoring_mode = monitoring_mode;
    }

    pub(crate) fn set_triggering(&mut self, links_to_add: &[u32], links_to_remove: &[u32]) {
        links_to_remove.iter().for_each(|i| {
            self.triggered_items.remove(i);
        });
        links_to_add.iter().for_each(|i| {
            self.triggered_items.insert(*i);
        });
    }

    pub(crate) fn triggered_items(&self) -> &BTreeSet<u32> {
        &self.triggered_items
    }
}

/// Client-side representation of a subscription.
pub struct Subscription {
    /// Subscription id, supplied by server
    subscription_id: u32,
    /// Publishing interval in seconds
    publishing_interval: Duration,
    /// Lifetime count, revised by server
    lifetime_count: u32,
    /// Max keep alive count, revised by server
    max_keep_alive_count: u32,
    /// Max notifications per publish, revised by server
    max_notifications_per_publish: u32,
    /// Publishing enabled
    publishing_enabled: bool,
    /// Subscription priority
    priority: u8,

    /// A map of monitored items associated with the subscription (key = monitored_item_id)
    monitored_items: HashMap<u32, MonitoredItem>,
    /// A map of client handle to monitored item id
    client_handles: HashMap<u32, u32>,

    callback: Box<dyn OnSubscriptionNotification>,
}

impl Subscription {
    /// Creates a new subscription using the supplied parameters and the supplied data change callback.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subscription_id: u32,
        publishing_interval: Duration,
        lifetime_count: u32,
        max_keep_alive_count: u32,
        max_notifications_per_publish: u32,
        priority: u8,
        publishing_enabled: bool,
        status_change_callback: Box<dyn OnSubscriptionNotification>,
    ) -> Subscription {
        Subscription {
            subscription_id,
            publishing_interval,
            lifetime_count,
            max_keep_alive_count,
            max_notifications_per_publish,
            publishing_enabled,
            priority,
            monitored_items: HashMap::new(),
            client_handles: HashMap::new(),
            callback: status_change_callback,
        }
    }

    /// Get the monitored items in this subscription.
    pub fn monitored_items(&self) -> &HashMap<u32, MonitoredItem> {
        &self.monitored_items
    }

    /// Get the subscription ID.
    pub fn subscription_id(&self) -> u32 {
        self.subscription_id
    }

    /// Get the configured publishing interval.
    pub fn publishing_interval(&self) -> Duration {
        self.publishing_interval
    }

    /// Get the `LifetimeCount` parameter for this subscription.
    pub fn lifetime_count(&self) -> u32 {
        self.lifetime_count
    }

    /// Get the configured priority.
    pub fn priority(&self) -> u8 {
        self.priority
    }

    /// Get the configured maximum keep alive count.
    pub fn max_keep_alive_count(&self) -> u32 {
        self.max_keep_alive_count
    }

    /// Get the configured maximum number of notifications per publish request.
    pub fn max_notifications_per_publish(&self) -> u32 {
        self.max_notifications_per_publish
    }

    /// Get whether publishing is enabled.
    pub fn publishing_enabled(&self) -> bool {
        self.publishing_enabled
    }

    /// Insert a monitored item that has been created on the server.
    ///
    /// If you call this yourself you are responsible for knowing that the
    /// monitored item already exists.
    pub fn insert_existing_monitored_item(&mut self, item: MonitoredItem) {
        let client_handle = item.client_handle();
        let monitored_item_id = item.id();
        self.monitored_items.insert(monitored_item_id, item);
        self.client_handles.insert(client_handle, monitored_item_id);
    }

    pub(crate) fn set_publishing_interval(&mut self, publishing_interval: Duration) {
        self.publishing_interval = publishing_interval;
    }

    pub(crate) fn set_lifetime_count(&mut self, lifetime_count: u32) {
        self.lifetime_count = lifetime_count;
    }

    pub(crate) fn set_max_keep_alive_count(&mut self, max_keep_alive_count: u32) {
        self.max_keep_alive_count = max_keep_alive_count;
    }

    pub(crate) fn set_max_notifications_per_publish(&mut self, max_notifications_per_publish: u32) {
        self.max_notifications_per_publish = max_notifications_per_publish;
    }

    pub(crate) fn set_publishing_enabled(&mut self, publishing_enabled: bool) {
        self.publishing_enabled = publishing_enabled;
    }

    pub(crate) fn set_priority(&mut self, priority: u8) {
        self.priority = priority;
    }

    pub(crate) fn insert_monitored_items(&mut self, items_to_create: Vec<CreateMonitoredItem>) {
        items_to_create.into_iter().for_each(|i| {
            let monitored_item = MonitoredItem {
                id: i.id,
                client_handle: i.client_handle,
                item_to_monitor: i.item_to_monitor,
                queue_size: i.queue_size as usize,
                monitoring_mode: i.monitoring_mode,
                sampling_interval: i.sampling_interval,
                triggered_items: BTreeSet::new(),
                discard_oldest: i.discard_oldest,
                filter: i.filter,
            };

            self.insert_existing_monitored_item(monitored_item);
        });
    }

    pub(crate) fn modify_monitored_items(&mut self, items_to_modify: &[ModifyMonitoredItem]) {
        items_to_modify.iter().for_each(|i| {
            if let Some(ref mut monitored_item) = self.monitored_items.get_mut(&i.id) {
                monitored_item.set_sampling_interval(i.sampling_interval);
                monitored_item.set_queue_size(i.queue_size as usize);
            }
        });
    }

    pub(crate) fn delete_monitored_items(&mut self, items_to_delete: &[u32]) {
        items_to_delete.iter().for_each(|id| {
            // Remove the monitored item and the client handle / id entry
            if let Some(monitored_item) = self.monitored_items.remove(id) {
                let _ = self.client_handles.remove(&monitored_item.client_handle());
            }
        })
    }

    pub(crate) fn set_triggering(
        &mut self,
        triggering_item_id: u32,
        links_to_add: &[u32],
        links_to_remove: &[u32],
    ) {
        if let Some(ref mut monitored_item) = self.monitored_items.get_mut(&triggering_item_id) {
            monitored_item.set_triggering(links_to_add, links_to_remove);
        }
    }

    pub(crate) fn on_notification(&mut self, notification: NotificationMessage) {
        let Some(notifications) = notification.notification_data else {
            return;
        };

        for obj in notifications {
            match_extension_object_owned!(obj,
                v: DataChangeNotification => {
                    for notif in v.monitored_items.into_iter().flatten() {
                        let item = self
                            .client_handles
                            .get(&notif.client_handle)
                            .and_then(|handle| self.monitored_items.get(handle));

                        if let Some(item) = item {
                            self.callback.on_data_value(notif.value, item);
                        }
                    }
                },
                v: EventNotificationList => {
                    for notif in v.events.into_iter().flatten() {
                        let item = self
                            .client_handles
                            .get(&notif.client_handle)
                            .and_then(|handle| self.monitored_items.get(handle));

                        if let Some(item) = item {
                            self.callback.on_event(notif.event_fields, item);
                        }
                    }
                },
                v: StatusChangeNotification => {
                    self.callback.on_subscription_status_change(v);
                }
            )
        }
    }
}

#[derive(Debug)]
pub(crate) struct PublishLimits {
    message_roundtrip: Duration,
    publish_interval: Duration,
    subscriptions: usize,
    min_publish_requests: usize,
    max_publish_requests: usize,
}

impl PublishLimits {
    const MIN_MESSAGE_ROUNDTRIP: Duration = Duration::from_millis(10);
    const REQUESTS_PER_SUBSCRIPTION: usize = 2;

    pub(crate) fn new() -> Self {
        Self {
            message_roundtrip: Self::MIN_MESSAGE_ROUNDTRIP,
            publish_interval: Duration::ZERO,
            subscriptions: 0,
            min_publish_requests: 0,
            max_publish_requests: 0,
        }
    }

    pub(crate) fn update_message_roundtrip(&mut self, message_roundtrip: Duration) {
        self.message_roundtrip = message_roundtrip.max(Self::MIN_MESSAGE_ROUNDTRIP);
        self.calculate_publish_limits();
    }

    pub(crate) fn update_subscriptions(
        &mut self,
        subscriptions: usize,
        publish_interval: Duration,
    ) {
        self.subscriptions = subscriptions;
        self.publish_interval = publish_interval;
        self.calculate_publish_limits();
    }

    fn calculate_publish_limits(&mut self) {
        self.min_publish_requests = self.subscriptions * Self::REQUESTS_PER_SUBSCRIPTION;
        self.max_publish_requests = (self.message_roundtrip.as_millis() as f32
            / self.publish_interval.as_millis() as f32)
            .ceil() as usize
            * (self.min_publish_requests);
    }
}
