use std::collections::{BTreeSet, VecDeque};

use chrono::TimeDelta;
use opcua_nodes::{Event, ParsedEventFilter, TypeTree};
use tracing::error;

use super::MonitoredItemHandle;
use crate::{info::ServerInfo, node_manager::ParsedReadValueId};
use opcua_types::{
    match_extension_object_owned, DataChangeFilter, DataValue, DateTime, EventFieldList,
    EventFilter, EventFilterResult, ExtensionObject, MonitoredItemCreateRequest,
    MonitoredItemModifyRequest, MonitoredItemNotification, MonitoringMode, NumericRange,
    ParsedDataChangeFilter, StatusCode, TimestampsToReturn, Variant,
};

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Notification {
    MonitoredItemNotification(MonitoredItemNotification),
    Event(EventFieldList),
}

impl From<MonitoredItemNotification> for Notification {
    fn from(v: MonitoredItemNotification) -> Self {
        Notification::MonitoredItemNotification(v)
    }
}

impl From<EventFieldList> for Notification {
    fn from(v: EventFieldList) -> Self {
        Notification::Event(v)
    }
}

#[derive(Debug, Clone)]
/// Parsed filter type for a monitored item.
pub enum FilterType {
    None,
    DataChangeFilter(ParsedDataChangeFilter),
    EventFilter(ParsedEventFilter),
}

impl FilterType {
    /// Try to create a filter from an extension object, returning
    /// an `EventFilterResult` if the filter is for events.
    pub fn from_filter(
        filter: ExtensionObject,
        eu_range: Option<(f64, f64)>,
        type_tree: &dyn TypeTree,
    ) -> (Option<EventFilterResult>, Result<FilterType, StatusCode>) {
        // Check if the filter is a supported filter type
        if filter.is_null() {
            return (None, Ok(FilterType::None));
        }

        match_extension_object_owned!(filter,
            v: DataChangeFilter => {
                let res = ParsedDataChangeFilter::parse(v, eu_range);
                (None, res.map(FilterType::DataChangeFilter))
            },
            v: EventFilter => {
                let (res, filter_res) = ParsedEventFilter::new(v, type_tree);
                (Some(res), filter_res.map(FilterType::EventFilter))
            },
            _ => {
                error!(
                    "Requested data filter type is not supported: {}",
                    filter
                        .body
                        .as_ref()
                        .map(|b| b.type_name())
                        .unwrap_or("Unknown")
                );
                (None, Err(StatusCode::BadFilterNotAllowed))
            }
        )
    }
}

#[derive(Debug)]
/// Container for a request to create a single monitored item.
pub struct CreateMonitoredItem {
    id: u32,
    subscription_id: u32,
    item_to_monitor: ParsedReadValueId,
    monitoring_mode: MonitoringMode,
    client_handle: u32,
    discard_oldest: bool,
    queue_size: usize,
    sampling_interval: f64,
    initial_value: Option<DataValue>,
    status_code: StatusCode,
    filter: FilterType,
    filter_res: Option<EventFilterResult>,
    timestamps_to_return: TimestampsToReturn,
    eu_range: Option<(f64, f64)>,
}

/// Takes the requested sampling interval value supplied by client and ensures it is within
/// the range supported by the server
fn sanitize_sampling_interval(info: &ServerInfo, requested_sampling_interval: f64) -> f64 {
    if requested_sampling_interval < 0.0 {
        // From spec "any negative number is interpreted as -1"
        // -1 means monitored item's sampling interval defaults to the subscription's publishing interval
        -1.0
    } else if requested_sampling_interval == 0.0
        || requested_sampling_interval < info.config.limits.subscriptions.min_sampling_interval_ms
    {
        info.config.limits.subscriptions.min_sampling_interval_ms
    } else {
        requested_sampling_interval
    }
}

/// Takes the requested queue size and ensures it is within the range supported by the server
fn sanitize_queue_size(info: &ServerInfo, requested_queue_size: usize) -> usize {
    if requested_queue_size == 0 || requested_queue_size == 1 {
        // For data monitored items 0 -> 1
        // Future - for event monitored items, queue size should be the default queue size for event notifications
        1
    // Future - for event monitored items, the minimum queue size the server requires for event notifications
    } else if requested_queue_size
        > info
            .config
            .limits
            .subscriptions
            .max_monitored_item_queue_size
    {
        info.config
            .limits
            .subscriptions
            .max_monitored_item_queue_size
    // Future - for event monitored items MaxUInt32 returns the maximum queue size the server support
    // for event notifications
    } else {
        requested_queue_size
    }
}

impl CreateMonitoredItem {
    pub(crate) fn new(
        req: MonitoredItemCreateRequest,
        id: u32,
        sub_id: u32,
        info: &ServerInfo,
        timestamps_to_return: TimestampsToReturn,
        type_tree: &dyn TypeTree,
        eu_range: Option<(f64, f64)>,
    ) -> Self {
        let (filter_res, filter) =
            FilterType::from_filter(req.requested_parameters.filter, eu_range, type_tree);
        let sampling_interval =
            sanitize_sampling_interval(info, req.requested_parameters.sampling_interval);
        let queue_size = sanitize_queue_size(info, req.requested_parameters.queue_size as usize);

        let (filter, mut status) = match filter {
            Ok(s) => (s, StatusCode::BadNodeIdUnknown),
            Err(e) => (FilterType::None, e),
        };

        let item_to_monitor = match ParsedReadValueId::parse(req.item_to_monitor) {
            Ok(r) => r,
            Err(e) => {
                status = e;
                ParsedReadValueId::null()
            }
        };

        Self {
            id,
            subscription_id: sub_id,
            item_to_monitor,
            monitoring_mode: req.monitoring_mode,
            client_handle: req.requested_parameters.client_handle,
            discard_oldest: req.requested_parameters.discard_oldest,
            queue_size,
            sampling_interval,
            initial_value: None,
            status_code: status,
            filter,
            timestamps_to_return,
            filter_res,
            eu_range,
        }
    }

    /// Get the monitored item handle of this create request.
    pub fn handle(&self) -> MonitoredItemHandle {
        MonitoredItemHandle {
            monitored_item_id: self.id,
            subscription_id: self.subscription_id,
        }
    }

    /// Set the initial value of the monitored item.
    pub fn set_initial_value(&mut self, value: DataValue) {
        self.initial_value = Some(value);
    }

    /// Set the status of the monitored item create request.
    /// If this is an error after all node managers have been evulated, the
    /// monitored item will not be created on the server.
    ///
    /// Note: Only consider a monitored item to be created if this is set to a
    /// `Good` status code.
    pub fn set_status(&mut self, status: StatusCode) {
        self.status_code = status;
    }

    /// Attribute to monitor.
    pub fn item_to_monitor(&self) -> &ParsedReadValueId {
        &self.item_to_monitor
    }

    /// Requested monitoring mode.
    pub fn monitoring_mode(&self) -> MonitoringMode {
        self.monitoring_mode
    }

    /// Requested sampling interval in milliseconds.
    pub fn sampling_interval(&self) -> f64 {
        self.sampling_interval
    }

    /// Requested queue size.
    pub fn queue_size(&self) -> usize {
        self.queue_size
    }

    /// Requested filter type.
    pub fn filter(&self) -> &FilterType {
        &self.filter
    }

    /// Revise the queue size, setting it equal to the given `queue_size` if it is smaller
    /// or if the requested queue size is 0.
    pub fn revise_queue_size(&mut self, queue_size: usize) {
        if queue_size < self.queue_size && queue_size > 0 || self.queue_size == 0 {
            self.queue_size = queue_size;
        }
    }

    /// Revise the sampling interval, settign it equal to the given `sampling_interval` if
    /// it is larger.
    pub fn revise_sampling_interval(&mut self, sampling_interval: f64) {
        if sampling_interval < self.sampling_interval && sampling_interval > 0.0
            || self.sampling_interval == 0.0
        {
            self.sampling_interval = sampling_interval;
        }
    }

    /// Requested timestamps to return.
    pub fn timestamps_to_return(&self) -> TimestampsToReturn {
        self.timestamps_to_return
    }

    /// Get the current result status code.
    pub fn status_code(&self) -> StatusCode {
        self.status_code
    }

    pub(crate) fn filter_res(&self) -> Option<&EventFilterResult> {
        self.filter_res.as_ref()
    }
}

#[derive(Debug)]
/// State of an active monitored item on the server.
pub struct MonitoredItem {
    id: u32,
    item_to_monitor: ParsedReadValueId,
    monitoring_mode: MonitoringMode,
    // Triggered items are other monitored items in the same subscription which are reported if this
    // monitored item changes.
    triggered_items: BTreeSet<u32>,
    client_handle: u32,
    sampling_interval: f64,
    filter: FilterType,
    discard_oldest: bool,
    queue_size: usize,
    notification_queue: VecDeque<Notification>,
    queue_overflow: bool,
    timestamps_to_return: TimestampsToReturn,
    last_data_value: Option<DataValue>,
    /// Value skipped due to sampling interval, we keep these
    /// so that we can generate a new notification later.
    sample_skipped_data_value: Option<DataValue>,
    any_new_notification: bool,
    eu_range: Option<(f64, f64)>,
}

impl MonitoredItem {
    pub(super) fn new(request: &CreateMonitoredItem) -> Self {
        let mut v = Self {
            id: request.id,
            item_to_monitor: request.item_to_monitor.clone(),
            monitoring_mode: request.monitoring_mode,
            triggered_items: BTreeSet::new(),
            client_handle: request.client_handle,
            sampling_interval: request.sampling_interval,
            filter: request.filter.clone(),
            discard_oldest: request.discard_oldest,
            timestamps_to_return: request.timestamps_to_return,
            last_data_value: None,
            sample_skipped_data_value: None,
            queue_size: request.queue_size,
            notification_queue: VecDeque::new(),
            queue_overflow: false,
            any_new_notification: false,
            eu_range: request.eu_range,
        };
        let now = DateTime::now();
        if let Some(val) = request.initial_value.as_ref() {
            v.notify_data_value(val.clone(), &now);
        } else {
            v.notify_data_value(
                DataValue {
                    value: Some(Variant::Empty),
                    status: Some(StatusCode::BadWaitingForInitialData),
                    source_timestamp: Some(now),
                    source_picoseconds: None,
                    server_timestamp: Some(now),
                    server_picoseconds: None,
                },
                &now,
            );
        }
        v
    }

    /// Modifies the existing item with the values of the modify request. On success, the result
    /// holds the filter result.
    pub(super) fn modify(
        &mut self,
        info: &ServerInfo,
        timestamps_to_return: TimestampsToReturn,
        request: &MonitoredItemModifyRequest,
        type_tree: &dyn TypeTree,
    ) -> (Option<EventFilterResult>, StatusCode) {
        self.timestamps_to_return = timestamps_to_return;
        let (filter_res, filter) = FilterType::from_filter(
            request.requested_parameters.filter.clone(),
            self.eu_range,
            type_tree,
        );
        self.filter = match filter {
            Ok(f) => f,
            Err(e) => return (filter_res, e),
        };
        self.sampling_interval =
            sanitize_sampling_interval(info, request.requested_parameters.sampling_interval);
        self.queue_size =
            sanitize_queue_size(info, request.requested_parameters.queue_size as usize);
        self.client_handle = request.requested_parameters.client_handle;
        self.discard_oldest = request.requested_parameters.discard_oldest;

        // Shrink / grow the notification queue to the new threshold
        if self.notification_queue.len() > self.queue_size {
            // Discard old notifications
            let discard = self.notification_queue.len() - self.queue_size;
            for _ in 0..discard {
                if self.discard_oldest {
                    let _ = self.notification_queue.pop_back();
                } else {
                    let _ = self.notification_queue.pop_front();
                }
            }
            // Shrink the queue
            self.notification_queue.shrink_to_fit();
        }
        (filter_res, StatusCode::Good)
    }

    fn filter_by_sampling_interval(&self, old: &DataValue, new: &DataValue) -> bool {
        let (Some(old), Some(new)) = (&old.source_timestamp, &new.source_timestamp) else {
            // Always include measurements without source timestamp, we don't know enough about these,
            // assume the server implementation did filtering elsewhere.
            return true;
        };

        let elapsed = new.as_chrono().signed_duration_since(old.as_chrono());

        elapsed >= TimeDelta::milliseconds(self.sampling_interval as i64)
    }

    /// Enqueue a value skipped due to sampling interval,
    /// if its new timestamp is in the past.
    ///
    /// Effectively what this mechanism does is to delay a notification
    /// if it arrives too early. I.e. with a sampling interval of 100ms, we get
    /// a notification at 0ms, and at 50ms. The second one is skipped, but if we don't
    /// get any new notifications until after 100ms, we will send the 50ms notification with
    /// timestamp equal to 100ms.
    ///
    /// This specifically avoids situations where two value changes arrive quickly,
    /// and then we get no new value changes for a long time. In this case,
    /// for the client it would appear as if the value changed at 0ms, and then
    /// was held constant for a long time.
    ///
    /// Instead, we want it to appear as if we actually sampled the value at 0ms and
    /// at 100ms, even if we actually don't sample at all.
    ///
    /// A corner case occurs if a new value arrives at exactly 100ms, in which case
    /// we discard the previous value after all. If a new value arrives at 101ms, it
    /// would be delayed to 200ms, giving the appearance of regular samples at 100ms intervals,
    /// even at the cost of delaying the actual update by a little bit.
    ///
    /// Users that want to avoid this should just set the sampling interval to 0.
    pub(super) fn maybe_enqueue_skipped_value(&mut self, now: &DateTime) -> bool {
        if let Some(value) = self.sample_skipped_data_value.take() {
            if value.source_timestamp.is_some_and(|v| v <= *now) {
                self.notify_data_value(value, now);
                true
            } else {
                // If there is no new sample, we can keep the last skipped value.
                self.sample_skipped_data_value = Some(value);
                false
            }
        } else {
            false
        }
    }

    pub(super) fn notify_data_value(&mut self, mut value: DataValue, now: &DateTime) -> bool {
        if self.monitoring_mode == MonitoringMode::Disabled {
            return false;
        }

        let mut extra_enqueued = false;
        if let Some(skipped_value) = self.sample_skipped_data_value.take() {
            // We use the skipped value if it is in the past, and if it is earlier than
            // the value we are currently reporting.
            if skipped_value
                .source_timestamp
                .is_some_and(|v| v <= *now && value.source_timestamp.is_none_or(|v2| v2 >= v))
            {
                extra_enqueued = self.notify_data_value(skipped_value, now);
            }
        }

        if !matches!(self.item_to_monitor.index_range, NumericRange::None) {
            if let Some(v) = value.value {
                match v.range_of(&self.item_to_monitor.index_range) {
                    Ok(r) => value.value = Some(r),
                    Err(e) => {
                        value.status = Some(e);
                        value.value = Some(Variant::Empty);
                    }
                }
            }
        }

        let (matches_filter, matches_sampling_interval) =
            match (&self.last_data_value, &self.filter) {
                (Some(last_dv), FilterType::DataChangeFilter(filter)) => (
                    filter.is_changed(&value, last_dv),
                    self.filter_by_sampling_interval(last_dv, &value),
                ),
                (Some(last_dv), FilterType::None) => (
                    value.value != last_dv.value,
                    self.filter_by_sampling_interval(last_dv, &value),
                ),
                (None, _) => (true, true),
                _ => (false, false),
            };

        if !matches_filter {
            return extra_enqueued;
        }

        // If we're outside the sampling interval, keep the value for now,
        // but shift it to the next sample.
        if !matches_sampling_interval {
            value.source_timestamp = Some(
                (self
                    .last_data_value
                    .as_ref()
                    .and_then(|dv| dv.source_timestamp)
                    .unwrap_or(*now)
                    .as_chrono()
                    + TimeDelta::milliseconds(self.sampling_interval as i64))
                .into(),
            );
            self.sample_skipped_data_value = Some(value);
            // We need to return true here, so that the subscription knows it needs to tick this
            // monitored item later.
            return true;
        }

        self.last_data_value = Some(value.clone());

        match self.timestamps_to_return {
            TimestampsToReturn::Neither | TimestampsToReturn::Invalid => {
                value.source_timestamp = None;
                value.source_picoseconds = None;
                value.server_timestamp = None;
                value.server_picoseconds = None
            }
            TimestampsToReturn::Server => {
                value.source_timestamp = None;
                value.source_picoseconds = None;
            }
            TimestampsToReturn::Source => {
                value.server_timestamp = None;
                value.server_picoseconds = None
            }
            TimestampsToReturn::Both => {
                // DO NOTHING
            }
        }

        let client_handle = self.client_handle;
        self.enqueue_notification(MonitoredItemNotification {
            client_handle,
            value,
        });

        true
    }

    pub(super) fn notify_event(&mut self, event: &dyn Event, type_tree: &dyn TypeTree) -> bool {
        if self.monitoring_mode == MonitoringMode::Disabled {
            return false;
        }

        let FilterType::EventFilter(filter) = &self.filter else {
            return false;
        };

        let Some(notif) = filter.evaluate(event, self.client_handle, type_tree) else {
            return false;
        };

        self.enqueue_notification(notif);

        true
    }

    fn enqueue_notification(&mut self, notification: impl Into<Notification>) {
        self.any_new_notification = true;
        let overflow = self.notification_queue.len() == self.queue_size;
        if overflow {
            if self.discard_oldest {
                self.notification_queue.pop_front();
            } else {
                self.notification_queue.pop_back();
            }
        }

        let mut notification = notification.into();
        if overflow {
            if let Notification::MonitoredItemNotification(n) = &mut notification {
                n.value.status = Some(n.value.status().set_overflow(true));
            }
            self.queue_overflow = true;
        }

        self.notification_queue.push_back(notification);
    }

    pub(super) fn add_current_value_to_queue(&mut self) {
        // Check if the last value is already enqueued
        let last_value = self.notification_queue.front();
        if let Some(Notification::MonitoredItemNotification(it)) = last_value {
            if Some(&it.value) == self.last_data_value.as_ref() {
                return;
            }
        }

        let Some(value) = self.last_data_value.as_ref() else {
            return;
        };

        self.enqueue_notification(Notification::MonitoredItemNotification(
            MonitoredItemNotification {
                client_handle: self.client_handle,
                value: value.clone(),
            },
        ));
    }

    /// Return `true` if this item has a stored last value.
    pub fn has_last_value(&self) -> bool {
        self.last_data_value.is_some()
    }

    /// Return `true` if this item has any new notifications.
    /// Note that this clears the `any_new_notification` flag and should
    /// be used with care.
    pub(super) fn has_new_notifications(&mut self) -> bool {
        let any_new = self.any_new_notification;
        self.any_new_notification = false;
        any_new
    }

    pub(super) fn pop_notification(&mut self) -> Option<Notification> {
        self.notification_queue.pop_front()
    }

    /// Adds or removes other monitored items which will be triggered when this monitored item changes
    pub(super) fn set_triggering(&mut self, items_to_add: &[u32], items_to_remove: &[u32]) {
        // Spec says to process remove items before adding new ones.
        items_to_remove.iter().for_each(|i| {
            self.triggered_items.remove(i);
        });
        items_to_add.iter().for_each(|i| {
            self.triggered_items.insert(*i);
        });
    }

    pub(super) fn remove_dead_trigger(&mut self, id: u32) {
        self.triggered_items.remove(&id);
    }

    /// Whether this monitored item is currently reporting new values.
    pub fn is_reporting(&self) -> bool {
        matches!(self.monitoring_mode, MonitoringMode::Reporting)
    }

    /// Whether this monitored item is currently storing new values.
    pub fn is_sampling(&self) -> bool {
        matches!(
            self.monitoring_mode,
            MonitoringMode::Reporting | MonitoringMode::Sampling
        )
    }

    /// Items that are triggered by updates to this monitored item.
    pub fn triggered_items(&self) -> &BTreeSet<u32> {
        &self.triggered_items
    }

    /// Whether this monitored item has enqueued notifications.
    pub fn has_notifications(&self) -> bool {
        !self.notification_queue.is_empty()
    }

    /// Monitored item ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Sampling interval.
    pub fn sampling_interval(&self) -> f64 {
        self.sampling_interval
    }

    /// Current maximum queue size.
    pub fn queue_size(&self) -> usize {
        self.queue_size
    }

    /// Item being monitored.
    pub fn item_to_monitor(&self) -> &ParsedReadValueId {
        &self.item_to_monitor
    }

    pub(super) fn set_monitoring_mode(&mut self, monitoring_mode: MonitoringMode) {
        self.monitoring_mode = monitoring_mode;
    }

    /// Current monitoring mode.
    pub fn monitoring_mode(&self) -> MonitoringMode {
        self.monitoring_mode
    }

    /// Whether oldest or newest values are discarded when the queue
    /// overflows.
    pub fn discard_oldest(&self) -> bool {
        self.discard_oldest
    }

    /// Get the client defined handle for this monitored item.
    pub fn client_handle(&self) -> u32 {
        self.client_handle
    }
}

#[cfg(test)]
pub(super) mod tests {
    use chrono::{Duration, TimeDelta, Utc};

    use crate::{node_manager::ParsedReadValueId, subscriptions::monitored_item::Notification};
    use opcua_types::{
        AttributeId, DataChangeFilter, DataChangeTrigger, DataValue, DateTime, Deadband,
        DeadbandType, MonitoringMode, NodeId, ParsedDataChangeFilter, ReadValueId, StatusCode,
        Variant,
    };

    use super::{FilterType, MonitoredItem};

    pub(crate) fn new_monitored_item(
        id: u32,
        item_to_monitor: ReadValueId,
        monitoring_mode: MonitoringMode,
        filter: FilterType,
        sampling_interval: f64,
        discard_oldest: bool,
        initial_value: Option<DataValue>,
    ) -> MonitoredItem {
        let mut v = MonitoredItem {
            id,
            item_to_monitor: ParsedReadValueId::parse(item_to_monitor).unwrap(),
            monitoring_mode,
            triggered_items: Default::default(),
            client_handle: Default::default(),
            sampling_interval,
            filter,
            discard_oldest,
            queue_size: 10,
            notification_queue: Default::default(),
            queue_overflow: false,
            timestamps_to_return: opcua_types::TimestampsToReturn::Both,
            last_data_value: None,
            sample_skipped_data_value: None,
            any_new_notification: false,
            eu_range: None,
        };

        let now = DateTime::now();
        if let Some(val) = initial_value {
            v.notify_data_value(val, &now);
        } else {
            let now = DateTime::now();
            v.notify_data_value(
                DataValue {
                    value: Some(Variant::Empty),
                    status: Some(StatusCode::BadWaitingForInitialData),
                    source_timestamp: Some(now),
                    source_picoseconds: None,
                    server_timestamp: Some(now),
                    server_picoseconds: None,
                },
                &now,
            );
        }

        v
    }

    #[test]
    fn data_change_filter() {
        let filter = DataChangeFilter {
            trigger: DataChangeTrigger::Status,
            deadband_type: DeadbandType::None as u32,
            deadband_value: 0f64,
        };
        let mut filter = ParsedDataChangeFilter::parse(filter, None).unwrap();

        let mut v1 = DataValue {
            value: None,
            status: None,
            source_timestamp: None,
            source_picoseconds: None,
            server_timestamp: None,
            server_picoseconds: None,
        };

        let mut v2 = DataValue {
            value: None,
            status: None,
            source_timestamp: None,
            source_picoseconds: None,
            server_timestamp: None,
            server_picoseconds: None,
        };

        assert!(!filter.is_changed(&v1, &v2));

        // Change v1 status
        v1.status = Some(StatusCode::Good);
        assert!(filter.is_changed(&v1, &v2));

        // Change v2 status
        v2.status = Some(StatusCode::Good);
        assert!(!filter.is_changed(&v1, &v2));

        // Change value - but since trigger is status, this should not matter
        v1.value = Some(Variant::Boolean(true));
        assert!(!filter.is_changed(&v1, &v2));

        // Change trigger to status-value and change should matter
        filter.trigger = DataChangeTrigger::StatusValue;
        assert!(filter.is_changed(&v1, &v2));

        // Now values are the same
        v2.value = Some(Variant::Boolean(true));
        assert!(!filter.is_changed(&v1, &v2));

        // And for status-value-timestamp
        filter.trigger = DataChangeTrigger::StatusValueTimestamp;
        assert!(!filter.is_changed(&v1, &v2));

        // Change timestamps to differ
        let now = DateTime::now();
        v1.source_timestamp = Some(now);
        assert!(filter.is_changed(&v1, &v2));
    }

    #[test]
    fn data_change_deadband_abs() {
        let filter = DataChangeFilter {
            trigger: DataChangeTrigger::StatusValue,
            // Abs compare
            deadband_type: DeadbandType::Absolute as u32,
            deadband_value: 1f64,
        };
        let filter = ParsedDataChangeFilter::parse(filter, None).unwrap();

        let v1 = DataValue {
            value: Some(Variant::Double(10f64)),
            status: None,
            source_timestamp: None,
            source_picoseconds: None,
            server_timestamp: None,
            server_picoseconds: None,
        };

        let mut v2 = DataValue {
            value: Some(Variant::Double(10f64)),
            status: None,
            source_timestamp: None,
            source_picoseconds: None,
            server_timestamp: None,
            server_picoseconds: None,
        };

        // Values are the same so deadband should not matter
        assert!(!filter.is_changed(&v1, &v2));

        // Adjust by less than deadband
        v2.value = Some(Variant::Double(10.9f64));
        assert!(!filter.is_changed(&v1, &v2));

        // Adjust by equal deadband
        v2.value = Some(Variant::Double(11f64));
        assert!(!filter.is_changed(&v1, &v2));

        // Adjust by equal deadband plus a little bit
        v2.value = Some(Variant::Double(11.00001f64));
        assert!(filter.is_changed(&v1, &v2));
    }

    #[test]
    fn monitored_item_filter() {
        let start = Utc::now();
        let mut item = new_monitored_item(
            1,
            ReadValueId {
                node_id: NodeId::null(),
                attribute_id: AttributeId::Value as u32,
                ..Default::default()
            },
            MonitoringMode::Reporting,
            FilterType::DataChangeFilter(ParsedDataChangeFilter {
                trigger: DataChangeTrigger::StatusValue,
                // Abs compare
                deadband: Deadband::Absolute(0.9),
            }),
            100.0,
            true,
            Some(DataValue::new_at(1.0, start.into())),
        );

        // Not within sampling interval
        assert!(item.notify_data_value(
            DataValue::new_at(
                2.0,
                (start + Duration::try_milliseconds(50).unwrap()).into()
            ),
            &start.into()
        ));
        assert_eq!(1, item.notification_queue.len());
        assert!(item.sample_skipped_data_value.is_some());
        // In deadband
        assert!(!item.notify_data_value(
            DataValue::new_at(
                1.5,
                (start + Duration::try_milliseconds(100).unwrap()).into()
            ),
            &start.into()
        ));
        // Sampling is disabled, don't notify anything.
        item.set_monitoring_mode(MonitoringMode::Disabled);
        assert!(!item.notify_data_value(
            DataValue::new_at(
                3.0,
                (start + Duration::try_milliseconds(250).unwrap()).into()
            ),
            &start.into()
        ));
        item.set_monitoring_mode(MonitoringMode::Reporting);
        // Ok
        assert!(item.notify_data_value(
            DataValue::new_at(
                2.0,
                (start + Duration::try_milliseconds(100).unwrap()).into()
            ),
            &start.into()
        ));
        // Now in deadband
        assert!(!item.notify_data_value(
            DataValue::new_at(
                2.5,
                (start + Duration::try_milliseconds(200).unwrap()).into()
            ),
            &start.into()
        ));
        // And outside deadband
        assert!(item.notify_data_value(
            DataValue::new_at(
                3.0,
                (start + Duration::try_milliseconds(250).unwrap()).into()
            ),
            &start.into()
        ));
        assert_eq!(item.notification_queue.len(), 3);
    }

    #[test]
    fn monitored_item_overflow() {
        let start = Utc::now();
        let mut item = new_monitored_item(
            1,
            ReadValueId {
                node_id: NodeId::null(),
                attribute_id: AttributeId::Value as u32,
                ..Default::default()
            },
            MonitoringMode::Reporting,
            FilterType::None,
            100.0,
            true,
            Some(DataValue::new_at(0, start.into())),
        );
        let now = start.into();
        item.queue_size = 5;
        for i in 0..4 {
            assert!(item.notify_data_value(
                DataValue::new_at(
                    i as i32 + 1,
                    (start + Duration::try_milliseconds(100 * i + 100).unwrap()).into(),
                ),
                &now
            ));
        }
        assert_eq!(item.notification_queue.len(), 5);

        assert!(item.notify_data_value(
            DataValue::new_at(5, (start + Duration::try_milliseconds(600).unwrap()).into(),),
            &now
        ));

        assert_eq!(item.notification_queue.len(), 5);
        let items: Vec<_> = item.notification_queue.drain(..).collect();
        for (idx, notif) in items.iter().enumerate() {
            let Notification::MonitoredItemNotification(n) = notif else {
                panic!("Wrong notification type");
            };
            let Some(Variant::Int32(v)) = &n.value.value else {
                panic!("Wrong value type");
            };
            // Values should be 1, 2, 3, 4, 5, since the first value 0 was dropped.
            assert_eq!(*v, idx as i32 + 1);
            // Last status code should have the overflow flag set.
            if idx == 4 {
                assert_eq!(n.value.status, Some(StatusCode::Good.set_overflow(true)));
            } else {
                assert_eq!(n.value.status, Some(StatusCode::Good));
            }
        }
    }

    #[test]
    fn monitored_item_delayed_sample() {
        let start = Utc::now();
        let mut item = new_monitored_item(
            1,
            ReadValueId {
                node_id: NodeId::null(),
                attribute_id: AttributeId::Value as u32,
                ..Default::default()
            },
            MonitoringMode::Reporting,
            FilterType::None,
            100.0,
            true,
            Some(DataValue::new_at(0, start.into())),
        );
        let t = start + TimeDelta::milliseconds(50);
        // Skipped due to sampling interval
        assert!(item.notify_data_value(DataValue::new_at(1, t.into()), &t.into()));
        assert_eq!(item.notification_queue.len(), 1);
        assert!(item.sample_skipped_data_value.is_some());

        // Now, trigger a new notification after 100 milliseconds, we should delete the skipped value
        // and send the new value, since its timestamp is not after the next sample.
        // This is to avoid cases where we indefinitely delay notifications.
        let t = start + TimeDelta::milliseconds(100);
        assert!(item.notify_data_value(DataValue::new_at(2, t.into()), &start.into()));
        assert!(item.sample_skipped_data_value.is_none());
        assert_eq!(item.notification_queue.len(), 2);
        item.notification_queue.drain(..);

        // Again, skip a value due to sampling interval
        let t = start + TimeDelta::milliseconds(150);
        assert!(item.notify_data_value(DataValue::new_at(3, t.into()), &t.into()));
        assert_eq!(item.notification_queue.len(), 0);
        assert!(item.sample_skipped_data_value.is_some());

        // This time, enqueue a new value far enough in the future that there is "room" for the skipped value.
        let t = start + TimeDelta::milliseconds(300);
        assert!(item.notify_data_value(DataValue::new_at(4, t.into()), &t.into()));
        assert!(item.sample_skipped_data_value.is_none());
        assert_eq!(item.notification_queue.len(), 2);

        item.notification_queue.drain(..);
        // A skipped value should also be enqueued on tick.
        let t = start + TimeDelta::milliseconds(350);
        assert!(item.notify_data_value(DataValue::new_at(5, t.into()), &t.into()));
        assert!(item.sample_skipped_data_value.is_some());
        assert_eq!(item.notification_queue.len(), 0);

        let t = start + TimeDelta::milliseconds(400);
        // If we tick the item, we should get the skipped value.
        assert!(item.maybe_enqueue_skipped_value(&t.into()));
        assert_eq!(item.notification_queue.len(), 1);
        assert!(item.sample_skipped_data_value.is_none());
    }
}
