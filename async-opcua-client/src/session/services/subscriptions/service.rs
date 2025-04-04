use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

use crate::{
    session::{
        process_service_result, process_unexpected_response,
        request_builder::{builder_base, builder_debug, builder_error, RequestHeaderBuilder},
        services::subscriptions::{CreateMonitoredItem, ModifyMonitoredItem, Subscription},
        session_debug, session_error, session_warn,
    },
    Session, UARequest,
};
use opcua_core::{handle::AtomicHandle, sync::Mutex, trace_lock, ResponseMessage};
use opcua_types::{
    AttributeId, CreateMonitoredItemsRequest, CreateMonitoredItemsResponse,
    CreateSubscriptionRequest, CreateSubscriptionResponse, DeleteMonitoredItemsRequest,
    DeleteMonitoredItemsResponse, DeleteSubscriptionsRequest, DeleteSubscriptionsResponse,
    IntegerId, ModifyMonitoredItemsRequest, ModifyMonitoredItemsResponse,
    ModifySubscriptionRequest, ModifySubscriptionResponse, MonitoredItemCreateRequest,
    MonitoredItemCreateResult, MonitoredItemModifyRequest, MonitoredItemModifyResult,
    MonitoringMode, MonitoringParameters, NodeId, NotificationMessage, PublishRequest, ReadValueId,
    RepublishRequest, SetMonitoringModeRequest, SetMonitoringModeResponse,
    SetPublishingModeRequest, SetPublishingModeResponse, SetTriggeringRequest,
    SetTriggeringResponse, StatusCode, TimestampsToReturn, TransferResult,
    TransferSubscriptionsRequest, TransferSubscriptionsResponse,
};
use tracing::{debug, enabled};

use super::{state::SubscriptionState, OnSubscriptionNotification};

/// Create a subscription by sending a [`CreateSubscriptionRequest`] to the server.
///
/// See OPC UA Part 4 - Services 5.13.2 for complete description of the service and error responses.
pub struct CreateSubscription<'a> {
    subscriptions: &'a Mutex<SubscriptionState>,
    callback: Box<dyn OnSubscriptionNotification>,

    publishing_interval: Duration,
    lifetime_count: u32,
    keep_alive_count: u32,
    max_notifications_per_publish: u32,
    publishing_enabled: bool,
    priority: u8,

    header: RequestHeaderBuilder,
}

builder_base!(CreateSubscription<'a>);

impl<'a> CreateSubscription<'a> {
    /// Construct a new call to the `CreateSubscription` service.
    pub fn new(session: &'a Session, callback: Box<dyn OnSubscriptionNotification>) -> Self {
        Self {
            publishing_interval: Duration::from_millis(500),
            lifetime_count: 60,
            keep_alive_count: 20,
            max_notifications_per_publish: 0,
            publishing_enabled: true,
            priority: 0,
            subscriptions: session.subscription_state(),
            header: RequestHeaderBuilder::new_from_session(session),
            callback,
        }
    }

    /// Construct a new call to the `CreateSubscription` service, setting header parameters manually.
    pub fn new_manual(
        subscriptions: &'a Mutex<SubscriptionState>,
        callback: Box<dyn OnSubscriptionNotification>,
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            subscriptions,
            callback,
            publishing_interval: Duration::from_millis(500),
            lifetime_count: 60,
            keep_alive_count: 20,
            max_notifications_per_publish: 0,
            publishing_enabled: true,
            priority: 0,
            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// The requested publishing interval defines the cyclic rate that
    /// the Subscription is being requested to return Notifications to the Client. This interval
    /// is expressed in milliseconds. This interval is represented by the publishing timer in the
    /// Subscription state table. The negotiated value for this parameter returned in the
    /// response is used as the default sampling interval for MonitoredItems assigned to this
    /// Subscription. If the requested value is 0 or negative, the server shall revise with the
    /// fastest supported publishing interval in milliseconds.
    pub fn publishing_interval(mut self, interval: Duration) -> Self {
        self.publishing_interval = interval;
        self
    }

    /// Requested lifetime count. The lifetime count shall be a minimum of
    /// three times the keep keep-alive count. When the publishing timer has expired this
    /// number of times without a Publish request being available to send a NotificationMessage,
    /// then the Subscription shall be deleted by the Server.
    pub fn max_lifetime_count(mut self, lifetime_count: u32) -> Self {
        self.lifetime_count = lifetime_count;
        self
    }

    /// Requested maximum keep-alive count. When the publishing timer has
    /// expired this number of times without requiring any NotificationMessage to be sent, the
    /// Subscription sends a keep-alive Message to the Client. The negotiated value for this
    /// parameter is returned in the response. If the requested value is 0, the server shall
    /// revise with the smallest supported keep-alive count.
    pub fn max_keep_alive_count(mut self, keep_alive_count: u32) -> Self {
        self.keep_alive_count = keep_alive_count;
        self
    }

    /// The maximum number of notifications that the Client
    /// wishes to receive in a single Publish response. A value of zero indicates that there is
    /// no limit. The number of notifications per Publish is the sum of monitoredItems in
    /// the DataChangeNotification and events in the EventNotificationList.
    pub fn max_notifications_per_publish(mut self, max_notifications_per_publish: u32) -> Self {
        self.max_notifications_per_publish = max_notifications_per_publish;
        self
    }

    /// Indicates the relative priority of the Subscription. When more than one
    /// Subscription needs to send Notifications, the Server should de-queue a Publish request
    /// to the Subscription with the highest priority number. For Subscriptions with equal
    /// priority the Server should de-queue Publish requests in a round-robin fashion.
    pub fn priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// A boolean parameter with the following values - `true` publishing
    /// is enabled for the Subscription, `false`, publishing is disabled for the Subscription.
    /// The value of this parameter does not affect the value of the monitoring mode Attribute of
    /// MonitoredItems.
    pub fn publishing_enabled(mut self, publishing_enabled: bool) -> Self {
        self.publishing_enabled = publishing_enabled;
        self
    }
}

impl UARequest for CreateSubscription<'_> {
    type Out = CreateSubscriptionResponse;

    async fn send<'a>(self, channel: &'a crate::AsyncSecureChannel) -> Result<Self::Out, StatusCode>
    where
        Self: 'a,
    {
        let request = CreateSubscriptionRequest {
            request_header: self.header.header,
            requested_publishing_interval: self.publishing_interval.as_millis() as f64,
            requested_lifetime_count: self.lifetime_count,
            requested_max_keep_alive_count: self.keep_alive_count,
            max_notifications_per_publish: self.max_notifications_per_publish,
            publishing_enabled: self.publishing_enabled,
            priority: self.priority,
        };

        let response = channel.send(request, self.header.timeout).await?;

        if let ResponseMessage::CreateSubscription(response) = response {
            process_service_result(&response.response_header)?;
            let subscription = Subscription::new(
                response.subscription_id,
                Duration::from_millis(response.revised_publishing_interval.max(0.0).floor() as u64),
                response.revised_lifetime_count,
                response.revised_max_keep_alive_count,
                self.max_notifications_per_publish,
                self.priority,
                self.publishing_enabled,
                self.callback,
            );
            {
                let mut subscription_state = trace_lock!(self.subscriptions);
                subscription_state.add_subscription(subscription);
            }
            builder_debug!(
                self,
                "create_subscription, created a subscription with id {}",
                response.subscription_id
            );
            Ok(*response)
        } else {
            builder_error!(self, "create_subscription failed {:?}", response);
            Err(process_unexpected_response(response))
        }
    }
}

/// Modifies a subscription by sending a [`ModifySubscriptionRequest`] to the server.
///
/// See OPC UA Part 4 - Services 5.13.3 for complete description of the service and error responses.
#[derive(Clone)]
pub struct ModifySubscription<'a> {
    subscriptions: &'a Mutex<SubscriptionState>,
    subscription_id: u32,
    publishing_interval: Duration,
    lifetime_count: u32,
    keep_alive_count: u32,
    max_notifications_per_publish: u32,
    priority: u8,

    header: RequestHeaderBuilder,
}

builder_base!(ModifySubscription<'a>);

impl<'a> ModifySubscription<'a> {
    /// Construct a new call to the `ModifySubscription` service.
    pub fn new(subscription_id: u32, session: &'a Session) -> Self {
        Self {
            subscription_id,
            publishing_interval: Duration::from_millis(500),
            lifetime_count: 60,
            keep_alive_count: 20,
            max_notifications_per_publish: 0,
            priority: 0,
            subscriptions: session.subscription_state(),
            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Construct a new call to the `ModifySubscription` service, setting header parameters manually.
    pub fn new_manual(
        subscription_id: u32,
        subscriptions: &'a Mutex<SubscriptionState>,
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            subscription_id,
            subscriptions,
            publishing_interval: Duration::from_millis(500),
            lifetime_count: 60,
            keep_alive_count: 20,
            max_notifications_per_publish: 0,
            priority: 0,
            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// The requested publishing interval defines the cyclic rate that
    /// the Subscription is being requested to return Notifications to the Client. This interval
    /// is expressed in milliseconds. This interval is represented by the publishing timer in the
    /// Subscription state table. The negotiated value for this parameter returned in the
    /// response is used as the default sampling interval for MonitoredItems assigned to this
    /// Subscription. If the requested value is 0 or negative, the server shall revise with the
    /// fastest supported publishing interval in milliseconds.
    pub fn publishing_interval(mut self, interval: Duration) -> Self {
        self.publishing_interval = interval;
        self
    }

    /// Requested lifetime count. The lifetime count shall be a minimum of
    /// three times the keep keep-alive count. When the publishing timer has expired this
    /// number of times without a Publish request being available to send a NotificationMessage,
    /// then the Subscription shall be deleted by the Server.
    pub fn max_lifetime_count(mut self, lifetime_count: u32) -> Self {
        self.lifetime_count = lifetime_count;
        self
    }

    /// Requested maximum keep-alive count. When the publishing timer has
    /// expired this number of times without requiring any NotificationMessage to be sent, the
    /// Subscription sends a keep-alive Message to the Client. The negotiated value for this
    /// parameter is returned in the response. If the requested value is 0, the server shall
    /// revise with the smallest supported keep-alive count.
    pub fn max_keep_alive_count(mut self, keep_alive_count: u32) -> Self {
        self.keep_alive_count = keep_alive_count;
        self
    }

    /// The maximum number of notifications that the Client
    /// wishes to receive in a single Publish response. A value of zero indicates that there is
    /// no limit. The number of notifications per Publish is the sum of monitoredItems in
    /// the DataChangeNotification and events in the EventNotificationList.
    pub fn max_notifications_per_publish(mut self, max_notifications_per_publish: u32) -> Self {
        self.max_notifications_per_publish = max_notifications_per_publish;
        self
    }

    /// Indicates the relative priority of the Subscription. When more than one
    /// Subscription needs to send Notifications, the Server should de-queue a Publish request
    /// to the Subscription with the highest priority number. For Subscriptions with equal
    /// priority the Server should de-queue Publish requests in a round-robin fashion.
    pub fn priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }
}

impl UARequest for ModifySubscription<'_> {
    type Out = ModifySubscriptionResponse;

    async fn send<'a>(self, channel: &'a crate::AsyncSecureChannel) -> Result<Self::Out, StatusCode>
    where
        Self: 'a,
    {
        if self.subscription_id == 0 {
            builder_error!(
                self,
                "modify_subscription, subscription id must be non-zero"
            );
            return Err(StatusCode::BadInvalidArgument);
        }

        let request = ModifySubscriptionRequest {
            request_header: self.header.header,
            subscription_id: self.subscription_id,
            requested_publishing_interval: self.publishing_interval.as_millis() as f64,
            requested_lifetime_count: self.lifetime_count,
            requested_max_keep_alive_count: self.keep_alive_count,
            max_notifications_per_publish: self.max_notifications_per_publish,
            priority: self.priority,
        };

        let response = channel.send(request, self.header.timeout).await?;

        if let ResponseMessage::ModifySubscription(response) = response {
            process_service_result(&response.response_header)?;
            let mut subscription_state = trace_lock!(self.subscriptions);
            subscription_state.modify_subscription(
                self.subscription_id,
                Duration::from_millis(response.revised_publishing_interval.max(0.0).floor() as u64),
                response.revised_lifetime_count,
                response.revised_max_keep_alive_count,
                self.max_notifications_per_publish,
                self.priority,
            );
            builder_debug!(
                self,
                "modify_subscription success for {}",
                self.subscription_id
            );
            Ok(*response)
        } else {
            builder_debug!(self, "modify_subscription failed");
            Err(process_unexpected_response(response))
        }
    }
}

/// Changes the publishing mode of subscriptions by sending a [`SetPublishingModeRequest`] to the server.
///
/// See OPC UA Part 4 - Services 5.13.4 for complete description of the service and error responses.
#[derive(Clone)]
pub struct SetPublishingMode<'a> {
    subscriptions: &'a Mutex<SubscriptionState>,
    subscription_ids: Vec<u32>,
    publishing_enabled: bool,

    header: RequestHeaderBuilder,
}

builder_base!(SetPublishingMode<'a>);

impl<'a> SetPublishingMode<'a> {
    /// Construct a new call to the `SetPublishingMode` service.
    pub fn new(publishing_enabled: bool, session: &'a Session) -> Self {
        Self {
            subscription_ids: Vec::new(),
            publishing_enabled,
            subscriptions: session.subscription_state(),
            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Construct a new call to the `SetPublishingMode` service, setting header parameters manually.
    pub fn new_manual(
        publishing_enabled: bool,
        subscriptions: &'a Mutex<SubscriptionState>,
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            subscription_ids: Vec::new(),
            publishing_enabled,
            subscriptions,
            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// Set the subscription IDs to update, overwriting any that were added previously.
    pub fn subscription_ids(mut self, subscription_ids: Vec<u32>) -> Self {
        self.subscription_ids = subscription_ids;
        self
    }

    /// Add a subscription ID to update.
    pub fn subscription(mut self, subscription_id: u32) -> Self {
        self.subscription_ids.push(subscription_id);
        self
    }
}

impl UARequest for SetPublishingMode<'_> {
    type Out = SetPublishingModeResponse;

    async fn send<'a>(self, channel: &'a crate::AsyncSecureChannel) -> Result<Self::Out, StatusCode>
    where
        Self: 'a,
    {
        builder_debug!(
            self,
            "set_publishing_mode, for subscriptions {:?}, publishing enabled {}",
            self.subscription_ids,
            self.publishing_enabled
        );
        if self.subscription_ids.is_empty() {
            builder_error!(
                self,
                "set_publishing_mode, no subscription ids were provided"
            );
            return Err(StatusCode::BadNothingToDo);
        }

        let request = SetPublishingModeRequest {
            request_header: self.header.header,
            publishing_enabled: self.publishing_enabled,
            subscription_ids: Some(self.subscription_ids.clone()),
        };
        let response = channel.send(request, self.header.timeout).await?;
        if let ResponseMessage::SetPublishingMode(response) = response {
            process_service_result(&response.response_header)?;
            let num_results = response
                .results
                .as_ref()
                .map(|l| l.len())
                .unwrap_or_default();

            if num_results != self.subscription_ids.len() {
                builder_error!(
                    self,
                    "set_publishing_mode returned an incorrect number of results. Expected {}, got {}",
                    self.subscription_ids.len(),
                    num_results
                );
                return Err(StatusCode::BadUnexpectedError);
            }

            {
                // Update all subscriptions where the returned status is good.
                let mut subscription_state = trace_lock!(self.subscriptions);
                let ids = self
                    .subscription_ids
                    .iter()
                    .zip(response.results.iter().flat_map(|f| f.iter()))
                    .filter(|(_, s)| s.is_good())
                    .map(|(v, _)| *v)
                    .collect::<Vec<_>>();
                subscription_state.set_publishing_mode(&ids, self.publishing_enabled);
            }

            builder_debug!(self, "set_publishing_mode success");
            Ok(*response)
        } else {
            builder_error!(self, "set_publishing_mode failed {:?}", response);
            Err(process_unexpected_response(response))
        }
    }
}

#[derive(Clone)]
/// Transfers Subscriptions and their MonitoredItems from one Session to another. For example,
/// a Client may need to reopen a Session and then transfer its Subscriptions to that Session.
/// It may also be used by one Client to take over a Subscription from another Client by
/// transferring the Subscription to its Session.
///
/// Note that if you call this manually, you will need to register the
/// subscriptions in the subscription state ([`Session::subscription_state`]) in order to
/// receive notifications.
///
/// See OPC UA Part 4 - Services 5.13.7 for complete description of the service and error responses.
///
pub struct TransferSubscriptions {
    subscription_ids: Vec<u32>,
    send_initial_values: bool,

    header: RequestHeaderBuilder,
}

builder_base!(TransferSubscriptions);

impl TransferSubscriptions {
    /// Construct a new call to the `TransferSubscriptions` service.
    pub fn new(session: &Session) -> Self {
        Self {
            subscription_ids: Vec::new(),
            send_initial_values: false,
            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Construct a new call to the `TransferSubscriptions` service, setting header parameters manually.
    pub fn new_manual(
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            subscription_ids: Vec::new(),
            send_initial_values: false,
            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }
    /// A boolean parameter with the following values - `true` the first
    /// publish response shall contain the current values of all monitored items in the subscription,
    /// `false`, the first publish response shall contain only the value changes since the last
    /// publish response was sent.
    pub fn send_initial_values(mut self, send_initial_values: bool) -> Self {
        self.send_initial_values = send_initial_values;
        self
    }

    /// Set the subscription IDs to transfer, overwriting any that were added previously.
    pub fn subscription_ids(mut self, subscription_ids: Vec<u32>) -> Self {
        self.subscription_ids = subscription_ids;
        self
    }

    /// Add a subscription ID to transfer.
    pub fn subscription(mut self, subscription_id: u32) -> Self {
        self.subscription_ids.push(subscription_id);
        self
    }
}

impl UARequest for TransferSubscriptions {
    type Out = TransferSubscriptionsResponse;

    async fn send<'a>(self, channel: &'a crate::AsyncSecureChannel) -> Result<Self::Out, StatusCode>
    where
        Self: 'a,
    {
        if self.subscription_ids.is_empty() {
            builder_error!(
                self,
                "transfer_subscriptions, no subscription ids were provided"
            );
            return Err(StatusCode::BadNothingToDo);
        }
        let request = TransferSubscriptionsRequest {
            request_header: self.header.header,
            subscription_ids: Some(self.subscription_ids),
            send_initial_values: self.send_initial_values,
        };
        let response = channel.send(request, self.header.timeout).await?;
        if let ResponseMessage::TransferSubscriptions(response) = response {
            process_service_result(&response.response_header)?;
            builder_debug!(self, "transfer_subscriptions success");
            Ok(*response)
        } else {
            builder_error!(self, "transfer_subscriptions failed {:?}", response);
            Err(process_unexpected_response(response))
        }
    }
}

#[derive(Clone)]
/// Deletes subscriptions by sending a [`DeleteSubscriptionsRequest`] to the server with the list
/// of subscriptions to delete.
///
/// See OPC UA Part 4 - Services 5.13.8 for complete description of the service and error responses.
pub struct DeleteSubscriptions<'a> {
    subscription_ids: Vec<u32>,
    subscriptions: &'a Mutex<SubscriptionState>,

    header: RequestHeaderBuilder,
}

builder_base!(DeleteSubscriptions<'a>);

impl<'a> DeleteSubscriptions<'a> {
    /// Construct a new call to the `DeleteSubscriptions` service.
    pub fn new(session: &'a Session) -> Self {
        Self {
            subscription_ids: Vec::new(),
            subscriptions: session.subscription_state(),
            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Construct a new call to the `DeleteSubscriptions` service, setting header parameters manually.
    pub fn new_manual(
        subscriptions: &'a Mutex<SubscriptionState>,
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            subscription_ids: Vec::new(),
            subscriptions,
            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// Set the subscription IDs to delete, overwriting any that were added previously.
    pub fn subscription_ids(mut self, subscription_ids: Vec<u32>) -> Self {
        self.subscription_ids = subscription_ids;
        self
    }

    /// Add a subscription ID to delete.
    pub fn subscription(mut self, subscription_id: u32) -> Self {
        self.subscription_ids.push(subscription_id);
        self
    }
}

impl UARequest for DeleteSubscriptions<'_> {
    type Out = DeleteSubscriptionsResponse;

    async fn send<'a>(self, channel: &'a crate::AsyncSecureChannel) -> Result<Self::Out, StatusCode>
    where
        Self: 'a,
    {
        if self.subscription_ids.is_empty() {
            builder_error!(self, "delete_subscriptions called with no subscription IDs");
            return Err(StatusCode::BadNothingToDo);
        }
        let request = DeleteSubscriptionsRequest {
            request_header: self.header.header,
            subscription_ids: Some(self.subscription_ids.clone()),
        };
        let response = channel.send(request, self.header.timeout).await?;
        if let ResponseMessage::DeleteSubscriptions(response) = response {
            process_service_result(&response.response_header)?;
            {
                // Clear out deleted subscriptions, assuming the delete worked
                let mut subscription_state = trace_lock!(self.subscriptions);
                for id in self.subscription_ids {
                    subscription_state.delete_subscription(id);
                }
            }
            builder_debug!(self, "delete_subscriptions success");
            Ok(*response)
        } else {
            builder_error!(self, "delete_subscriptions failed {:?}", response);
            Err(process_unexpected_response(response))
        }
    }
}

#[derive(Clone)]
/// Creates monitored items on a subscription by sending a [`CreateMonitoredItemsRequest`] to the server.
///
/// See OPC UA Part 4 - Services 5.12.2 for complete description of the service and error responses.
pub struct CreateMonitoredItems<'a> {
    subscription_id: u32,
    timestamps_to_return: TimestampsToReturn,
    items_to_create: Vec<MonitoredItemCreateRequest>,
    subscriptions: &'a Mutex<SubscriptionState>,
    handle: &'a AtomicHandle,

    header: RequestHeaderBuilder,
}

builder_base!(CreateMonitoredItems<'a>);

impl<'a> CreateMonitoredItems<'a> {
    /// Construct a new call to the `CreateMonitoredItems` service.
    pub fn new(subscription_id: u32, session: &'a Session) -> Self {
        Self {
            subscription_id,
            timestamps_to_return: TimestampsToReturn::Neither,
            items_to_create: Vec::new(),
            subscriptions: session.subscription_state(),
            handle: &session.monitored_item_handle,
            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Construct a new call to the `CreateMonitoredItems` service, setting header parameters manually.
    pub fn new_manual(
        subscription_id: u32,
        subscriptions: &'a Mutex<SubscriptionState>,
        monitored_item_handle: &'a AtomicHandle,
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            subscription_id,
            timestamps_to_return: TimestampsToReturn::Neither,
            items_to_create: Vec::new(),
            subscriptions,
            handle: monitored_item_handle,
            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// An enumeration that specifies the timestamp Attributes to be transmitted for each MonitoredItem.
    pub fn timestamps_to_return(mut self, timestamps_to_return: TimestampsToReturn) -> Self {
        self.timestamps_to_return = timestamps_to_return;
        self
    }

    /// Set the monitored items to create, overwriting any that were added previously.
    pub fn items_to_create(mut self, items_to_create: Vec<MonitoredItemCreateRequest>) -> Self {
        self.items_to_create = items_to_create;
        self
    }

    /// Add a monitored item to create.
    pub fn item(mut self, item: MonitoredItemCreateRequest) -> Self {
        self.items_to_create.push(item);
        self
    }

    /// Add a monitored item to create, subscribing to values on `node_id` with the
    /// given `sampling_interval` and `queue_size`.
    pub fn value(mut self, node_id: NodeId, sampling_interval: f64, queue_size: u32) -> Self {
        self.items_to_create.push(MonitoredItemCreateRequest {
            item_to_monitor: ReadValueId {
                node_id,
                attribute_id: AttributeId::Value as u32,
                ..Default::default()
            },
            monitoring_mode: MonitoringMode::Reporting,
            requested_parameters: MonitoringParameters {
                client_handle: self.handle.next(),
                sampling_interval,
                queue_size,
                discard_oldest: true,
                ..Default::default()
            },
        });
        self
    }
}

impl UARequest for CreateMonitoredItems<'_> {
    type Out = CreateMonitoredItemsResponse;

    async fn send<'a>(
        mut self,
        channel: &'a crate::AsyncSecureChannel,
    ) -> Result<Self::Out, StatusCode>
    where
        Self: 'a,
    {
        builder_debug!(
            self,
            "create_monitored_items, for subscription {}, {} items",
            self.subscription_id,
            self.items_to_create.len()
        );
        if self.subscription_id == 0 {
            builder_error!(self, "create_monitored_items, subscription id 0 is invalid");
            return Err(StatusCode::BadSubscriptionIdInvalid);
        }
        {
            let state = trace_lock!(self.subscriptions);
            if !state.subscription_exists(self.subscription_id) {
                builder_error!(
                    self,
                    "create_monitored_items, subscription id {} does not exist",
                    self.subscription_id
                );
                return Err(StatusCode::BadSubscriptionIdInvalid);
            }
        }
        if self.items_to_create.is_empty() {
            builder_error!(
                self,
                "create_monitored_items, called with no items to create"
            );
            return Err(StatusCode::BadNothingToDo);
        }
        for item in &mut self.items_to_create {
            if item.requested_parameters.client_handle == 0 {
                item.requested_parameters.client_handle = self.handle.next();
            }
        }

        let request = CreateMonitoredItemsRequest {
            request_header: self.header.header,
            subscription_id: self.subscription_id,
            timestamps_to_return: self.timestamps_to_return,
            items_to_create: Some(self.items_to_create.clone()),
        };

        let response = channel.send(request, self.header.timeout).await?;

        if let ResponseMessage::CreateMonitoredItems(response) = response {
            process_service_result(&response.response_header)?;
            if let Some(ref results) = response.results {
                if results.len() != self.items_to_create.len() {
                    builder_error!(
                        self,
                        "create_monitored_items, unexpected number of results. Got {}, expected {}",
                        results.len(),
                        self.items_to_create.len()
                    );
                    return Err(StatusCode::BadUnexpectedError);
                }
                builder_debug!(
                    self,
                    "create_monitored_items, {} items created",
                    self.items_to_create.len()
                );
                // Set the items in our internal state
                let items_to_create = self
                    .items_to_create
                    .into_iter()
                    .zip(results)
                    .map(|(i, r)| CreateMonitoredItem {
                        id: r.monitored_item_id,
                        client_handle: i.requested_parameters.client_handle,
                        discard_oldest: i.requested_parameters.discard_oldest,
                        item_to_monitor: i.item_to_monitor.clone(),
                        monitoring_mode: i.monitoring_mode,
                        queue_size: r.revised_queue_size,
                        sampling_interval: r.revised_sampling_interval,
                        filter: i.requested_parameters.filter,
                    })
                    .collect::<Vec<CreateMonitoredItem>>();
                {
                    let mut subscription_state = trace_lock!(self.subscriptions);
                    subscription_state
                        .insert_monitored_items(self.subscription_id, items_to_create);
                }
            } else {
                builder_error!(
                    self,
                    "create_monitored_items, success but no monitored items were created"
                );
                return Err(StatusCode::BadUnexpectedError);
            }
            Ok(*response)
        } else {
            builder_error!(self, "create_monitored_items failed {:?}", response);
            Err(process_unexpected_response(response))
        }
    }
}

#[derive(Clone)]
/// Modifies monitored items on a subscription by sending a [`ModifyMonitoredItemsRequest`] to the server.
///
/// See OPC UA Part 4 - Services 5.12.3 for complete description of the service and error responses.
pub struct ModifyMonitoredItems<'a> {
    subscription_id: u32,
    timestamps_to_return: TimestampsToReturn,
    items_to_modify: Vec<MonitoredItemModifyRequest>,
    subscriptions: &'a Mutex<SubscriptionState>,

    header: RequestHeaderBuilder,
}

builder_base!(ModifyMonitoredItems<'a>);

impl<'a> ModifyMonitoredItems<'a> {
    /// Construct a new call to the `ModifyMonitoredItems` service.
    pub fn new(subscription_id: u32, session: &'a Session) -> Self {
        Self {
            subscription_id,
            timestamps_to_return: TimestampsToReturn::Neither,
            items_to_modify: Vec::new(),
            subscriptions: session.subscription_state(),
            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Construct a new call to the `ModifyMonitoredItems` service, setting header parameters manually.
    pub fn new_manual(
        subscription_id: u32,
        subscriptions: &'a Mutex<SubscriptionState>,
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            subscription_id,
            timestamps_to_return: TimestampsToReturn::Neither,
            items_to_modify: Vec::new(),
            subscriptions,
            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// An enumeration that specifies the timestamp Attributes to be transmitted for each MonitoredItem.
    pub fn timestamps_to_return(mut self, timestamps_to_return: TimestampsToReturn) -> Self {
        self.timestamps_to_return = timestamps_to_return;
        self
    }

    /// Set the monitored items to modify, overwriting any that were added previously.
    pub fn items_to_modify(mut self, items_to_modify: Vec<MonitoredItemModifyRequest>) -> Self {
        self.items_to_modify = items_to_modify;
        self
    }

    /// Add a monitored item to modify.
    pub fn item(mut self, item: MonitoredItemModifyRequest) -> Self {
        self.items_to_modify.push(item);
        self
    }
}

impl UARequest for ModifyMonitoredItems<'_> {
    type Out = ModifyMonitoredItemsResponse;

    async fn send<'a>(self, channel: &'a crate::AsyncSecureChannel) -> Result<Self::Out, StatusCode>
    where
        Self: 'a,
    {
        builder_debug!(
            self,
            "modify_monitored_items, for subscription {}, {} items",
            self.subscription_id,
            self.items_to_modify.len()
        );
        if self.subscription_id == 0 {
            builder_error!(self, "modify_monitored_items, subscription id 0 is invalid");
            return Err(StatusCode::BadInvalidArgument);
        }
        {
            let state = trace_lock!(self.subscriptions);
            if !state.subscription_exists(self.subscription_id) {
                builder_error!(
                    self,
                    "modify_monitored_items, subscription id {} does not exist",
                    self.subscription_id
                );
                return Err(StatusCode::BadSubscriptionIdInvalid);
            }
        }
        if self.items_to_modify.is_empty() {
            builder_error!(
                self,
                "modify_monitored_items, called with no items to modify"
            );
            return Err(StatusCode::BadNothingToDo);
        }
        let ids = self
            .items_to_modify
            .iter()
            .map(|i| i.monitored_item_id)
            .collect::<Vec<_>>();
        let request = ModifyMonitoredItemsRequest {
            request_header: self.header.header,
            subscription_id: self.subscription_id,
            timestamps_to_return: self.timestamps_to_return,
            items_to_modify: Some(self.items_to_modify),
        };
        let response = channel.send(request, self.header.timeout).await?;
        if let ResponseMessage::ModifyMonitoredItems(response) = response {
            process_service_result(&response.response_header)?;
            let Some(results) = &response.results else {
                builder_error!(self, "modify_monitored_items, got empty response");
                return Err(StatusCode::BadUnexpectedError);
            };
            if results.len() != ids.len() {
                builder_error!(
                    self,
                    "modify_monitored_items, unexpected number of results. Expected {}, got {}",
                    ids.len(),
                    results.len()
                );
                return Err(StatusCode::BadUnexpectedError);
            }
            let items_to_modify = ids
                .iter()
                .zip(results.iter())
                .map(|(id, r)| ModifyMonitoredItem {
                    id: *id,
                    queue_size: r.revised_queue_size,
                    sampling_interval: r.revised_sampling_interval,
                })
                .collect::<Vec<ModifyMonitoredItem>>();
            {
                let mut subscription_state = trace_lock!(self.subscriptions);
                subscription_state.modify_monitored_items(self.subscription_id, &items_to_modify);
            }
            builder_debug!(self, "modify_monitored_items, success");
            Ok(*response)
        } else {
            builder_error!(self, "modify_monitored_items failed {:?}", response);
            Err(process_unexpected_response(response))
        }
    }
}

#[derive(Clone)]
/// Sets the monitoring mode on one or more monitored items by sending a [`SetMonitoringModeRequest`]
/// to the server.
///
/// See OPC UA Part 4 - Services 5.12.4 for complete description of the service and error responses.
pub struct SetMonitoringMode<'a> {
    subscription_id: u32,
    monitoring_mode: MonitoringMode,
    monitored_item_ids: Vec<u32>,
    subscriptions: &'a Mutex<SubscriptionState>,

    header: RequestHeaderBuilder,
}

builder_base!(SetMonitoringMode<'a>);

impl<'a> SetMonitoringMode<'a> {
    /// Construct a new call to the `SetMonitoringMode` service.
    pub fn new(
        subscription_id: u32,
        monitoring_mode: MonitoringMode,
        session: &'a Session,
    ) -> Self {
        Self {
            subscription_id,
            monitored_item_ids: Vec::new(),
            monitoring_mode,
            subscriptions: session.subscription_state(),
            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Construct a new call to the `SetMonitoringMode` service, setting header parameters manually.
    pub fn new_manual(
        subscription_id: u32,
        monitoring_mode: MonitoringMode,
        subscriptions: &'a Mutex<SubscriptionState>,
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            subscription_id,
            monitored_item_ids: Vec::new(),
            monitoring_mode,
            subscriptions,
            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// Set the monitored items to modify, overwriting any that were added previously.
    pub fn monitored_item_ids(mut self, monitored_item_ids: Vec<u32>) -> Self {
        self.monitored_item_ids = monitored_item_ids;
        self
    }

    /// Add a monitored item to modify.
    pub fn item(mut self, item: u32) -> Self {
        self.monitored_item_ids.push(item);
        self
    }
}

impl UARequest for SetMonitoringMode<'_> {
    type Out = SetMonitoringModeResponse;

    async fn send<'a>(self, channel: &'a crate::AsyncSecureChannel) -> Result<Self::Out, StatusCode>
    where
        Self: 'a,
    {
        builder_debug!(
            self,
            "set_monitoring_mode, for subscription {}, {} items",
            self.subscription_id,
            self.monitored_item_ids.len()
        );
        if self.subscription_id == 0 {
            builder_error!(self, "set_monitoring_mode, subscription id 0 is invalid");
            return Err(StatusCode::BadInvalidArgument);
        }
        {
            let state = trace_lock!(self.subscriptions);
            if !state.subscription_exists(self.subscription_id) {
                builder_error!(
                    self,
                    "set_monitoring_mode, subscription id {} does not exist",
                    self.subscription_id
                );
                return Err(StatusCode::BadSubscriptionIdInvalid);
            }
        }
        if self.monitored_item_ids.is_empty() {
            builder_error!(self, "set_monitoring_mode, called with no items to modify");
            return Err(StatusCode::BadNothingToDo);
        }

        let request = SetMonitoringModeRequest {
            request_header: self.header.header,
            subscription_id: self.subscription_id,
            monitoring_mode: self.monitoring_mode,
            monitored_item_ids: Some(self.monitored_item_ids.clone()),
        };
        let response = channel.send(request, self.header.timeout).await?;
        if let ResponseMessage::SetMonitoringMode(response) = response {
            let Some(results) = &response.results else {
                builder_error!(self, "set_monitoring_mode, got empty response");
                return Err(StatusCode::BadUnexpectedError);
            };
            if results.len() != self.monitored_item_ids.len() {
                builder_error!(
                    self,
                    "set_monitoring_mode, unexpected number of results. Expected {}, got {}",
                    self.monitored_item_ids.len(),
                    results.len()
                );
                return Err(StatusCode::BadUnexpectedError);
            }
            let ok_ids: Vec<_> = self
                .monitored_item_ids
                .iter()
                .zip(results.iter())
                .filter(|(_, s)| s.is_good())
                .map(|(v, _)| *v)
                .collect();
            {
                let mut subscription_state = trace_lock!(self.subscriptions);
                subscription_state.set_monitoring_mode(
                    self.subscription_id,
                    &ok_ids,
                    self.monitoring_mode,
                );
            }

            Ok(*response)
        } else {
            builder_error!(self, "set_monitoring_mode failed {:?}", response);
            Err(process_unexpected_response(response))
        }
    }
}

#[derive(Clone)]
/// Sets a monitored item so it becomes the trigger that causes other monitored items to send
/// change events in the same update. Sends a [`SetTriggeringRequest`] to the server.
/// Note that `items_to_remove` is applied before `items_to_add`.
///
/// See OPC UA Part 4 - Services 5.12.5 for complete description of the service and error responses.
pub struct SetTriggering<'a> {
    subscription_id: u32,
    triggering_item_id: u32,
    links_to_add: Vec<u32>,
    links_to_remove: Vec<u32>,
    subscriptions: &'a Mutex<SubscriptionState>,

    header: RequestHeaderBuilder,
}

builder_base!(SetTriggering<'a>);

impl<'a> SetTriggering<'a> {
    /// Construct a new call to the `SetTriggering` service.
    pub fn new(subscription_id: u32, triggering_item_id: u32, session: &'a Session) -> Self {
        Self {
            subscription_id,
            triggering_item_id,
            links_to_add: Vec::new(),
            links_to_remove: Vec::new(),
            subscriptions: session.subscription_state(),
            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Construct a new call to the `SetTriggering` service, setting header parameters manually.
    pub fn new_manual(
        subscription_id: u32,
        triggering_item_id: u32,
        subscriptions: &'a Mutex<SubscriptionState>,
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            subscription_id,
            triggering_item_id,
            links_to_add: Vec::new(),
            links_to_remove: Vec::new(),
            subscriptions,
            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// Set the links to add, overwriting any that were added previously.
    pub fn links_to_add(mut self, links_to_add: Vec<u32>) -> Self {
        self.links_to_add = links_to_add;
        self
    }

    /// Add a new trigger target.
    pub fn add_link(mut self, item: u32) -> Self {
        self.links_to_add.push(item);
        self
    }

    /// Set the links to add, overwriting any that were added previously.
    pub fn links_to_remove(mut self, links_to_remove: Vec<u32>) -> Self {
        self.links_to_remove = links_to_remove;
        self
    }

    /// Add a new trigger to remove.
    pub fn remove_link(mut self, item: u32) -> Self {
        self.links_to_remove.push(item);
        self
    }
}

impl UARequest for SetTriggering<'_> {
    type Out = SetTriggeringResponse;

    async fn send<'a>(self, channel: &'a crate::AsyncSecureChannel) -> Result<Self::Out, StatusCode>
    where
        Self: 'a,
    {
        builder_debug!(
            self,
            "set_triggering, for subscription {}, {} links to add, {} links to remove",
            self.subscription_id,
            self.links_to_add.len(),
            self.links_to_remove.len()
        );
        if self.subscription_id == 0 {
            builder_error!(self, "set_triggering, subscription id 0 is invalid");
            return Err(StatusCode::BadInvalidArgument);
        }
        {
            let state = trace_lock!(self.subscriptions);
            if !state.subscription_exists(self.subscription_id) {
                builder_error!(
                    self,
                    "set_triggering, subscription id {} does not exist",
                    self.subscription_id
                );
                return Err(StatusCode::BadSubscriptionIdInvalid);
            }
        }
        if self.links_to_add.is_empty() && self.links_to_remove.is_empty() {
            builder_error!(self, "set_triggering, called with nothing to add or remove");
            return Err(StatusCode::BadNothingToDo);
        }
        let request = SetTriggeringRequest {
            request_header: self.header.header,
            subscription_id: self.subscription_id,
            triggering_item_id: self.triggering_item_id,
            links_to_add: if self.links_to_add.is_empty() {
                None
            } else {
                Some(self.links_to_add.clone())
            },
            links_to_remove: if self.links_to_remove.is_empty() {
                None
            } else {
                Some(self.links_to_remove.clone())
            },
        };

        let response = channel.send(request, self.header.timeout).await?;
        if let ResponseMessage::SetTriggering(response) = response {
            let to_add_res = response.add_results.as_deref().unwrap_or(&[]);
            let to_remove_res = response.remove_results.as_deref().unwrap_or(&[]);
            if to_add_res.len() != self.links_to_add.len() {
                builder_error!(
                    self,
                    "set_triggering, got unexpected number of add results: {}, expected {}",
                    to_add_res.len(),
                    self.links_to_add.len()
                );
                return Err(StatusCode::BadUnexpectedError);
            }
            if to_remove_res.len() != self.links_to_remove.len() {
                builder_error!(
                    self,
                    "set_triggering, got unexpected number of remove results: {}, expected {}",
                    to_remove_res.len(),
                    self.links_to_add.len()
                );
                return Err(StatusCode::BadUnexpectedError);
            }
            let ok_adds = to_add_res
                .iter()
                .zip(self.links_to_add)
                .filter(|(s, _)| s.is_good())
                .map(|(_, v)| v)
                .collect::<Vec<_>>();
            let ok_removes = to_remove_res
                .iter()
                .zip(self.links_to_remove)
                .filter(|(s, _)| s.is_good())
                .map(|(_, v)| v)
                .collect::<Vec<_>>();

            // Update client side state
            let mut subscription_state = trace_lock!(self.subscriptions);
            subscription_state.set_triggering(
                self.subscription_id,
                self.triggering_item_id,
                &ok_adds,
                &ok_removes,
            );
            Ok(*response)
        } else {
            builder_error!(self, "set_triggering failed {:?}", response);
            Err(process_unexpected_response(response))
        }
    }
}

#[derive(Clone)]
/// Deletes monitored items from a subscription by sending a [`DeleteMonitoredItemsRequest`] to the server.
///
/// See OPC UA Part 4 - Services 5.12.6 for complete description of the service and error responses.
pub struct DeleteMonitoredItems<'a> {
    subscription_id: u32,
    items_to_delete: Vec<u32>,
    subscriptions: &'a Mutex<SubscriptionState>,

    header: RequestHeaderBuilder,
}

builder_base!(DeleteMonitoredItems<'a>);

impl<'a> DeleteMonitoredItems<'a> {
    /// Construct a new call to the `DeleteMonitoredItems` service.
    pub fn new(subscription_id: u32, session: &'a Session) -> Self {
        Self {
            subscription_id,
            items_to_delete: Vec::new(),
            subscriptions: session.subscription_state(),
            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Construct a new call to the `DeleteMonitoredItems` service, setting header parameters manually.
    pub fn new_manual(
        subscription_id: u32,
        subscriptions: &'a Mutex<SubscriptionState>,
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            subscription_id,
            items_to_delete: Vec::new(),
            subscriptions,
            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// Set the items to delete, overwriting any that were added previously.
    pub fn items_to_delete(mut self, items_to_delete: Vec<u32>) -> Self {
        self.items_to_delete = items_to_delete;
        self
    }

    /// Add a new item to delete.
    pub fn item(mut self, item: u32) -> Self {
        self.items_to_delete.push(item);
        self
    }
}

impl UARequest for DeleteMonitoredItems<'_> {
    type Out = DeleteMonitoredItemsResponse;

    async fn send<'a>(self, channel: &'a crate::AsyncSecureChannel) -> Result<Self::Out, StatusCode>
    where
        Self: 'a,
    {
        builder_debug!(
            self,
            "delete_monitored_items, subscription {} for {} items",
            self.subscription_id,
            self.items_to_delete.len(),
        );
        if self.subscription_id == 0 {
            builder_error!(self, "delete_monitored_items, subscription id 0 is invalid");
            return Err(StatusCode::BadInvalidArgument);
        }
        {
            let state = trace_lock!(self.subscriptions);
            if !state.subscription_exists(self.subscription_id) {
                builder_error!(
                    self,
                    "delete_monitored_items, subscription id {} does not exist",
                    self.subscription_id
                );
                return Err(StatusCode::BadSubscriptionIdInvalid);
            }
        }
        if self.items_to_delete.is_empty() {
            builder_error!(
                self,
                "delete_monitored_items, called with no items to delete"
            );
            return Err(StatusCode::BadNothingToDo);
        }

        let request = DeleteMonitoredItemsRequest {
            request_header: self.header.header,
            subscription_id: self.subscription_id,
            monitored_item_ids: Some(self.items_to_delete.clone()),
        };
        let response = channel.send(request, self.header.timeout).await?;
        if let ResponseMessage::DeleteMonitoredItems(response) = response {
            process_service_result(&response.response_header)?;
            if response.results.is_some() {
                let mut subscription_state = trace_lock!(self.subscriptions);
                subscription_state
                    .delete_monitored_items(self.subscription_id, &self.items_to_delete);
            }
            builder_debug!(self, "delete_monitored_items, success");
            Ok(*response)
        } else {
            builder_error!(self, "delete_monitored_items failed {:?}", response);
            Err(process_unexpected_response(response))
        }
    }
}

impl Session {
    /// Get the internal state of subscriptions registered on the session.
    pub fn subscription_state(&self) -> &Mutex<SubscriptionState> {
        &self.subscription_state
    }

    /// Trigger a publish to fire immediately.
    pub fn trigger_publish_now(&self) {
        let _ = self.trigger_publish_tx.send(Instant::now());
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_subscription_inner(
        &self,
        publishing_interval: Duration,
        lifetime_count: u32,
        max_keep_alive_count: u32,
        max_notifications_per_publish: u32,
        publishing_enabled: bool,
        priority: u8,
        callback: Box<dyn OnSubscriptionNotification>,
    ) -> Result<u32, StatusCode> {
        let response = CreateSubscription::new(self, callback)
            .publishing_interval(publishing_interval)
            .max_lifetime_count(lifetime_count)
            .max_keep_alive_count(max_keep_alive_count)
            .max_notifications_per_publish(max_notifications_per_publish)
            .publishing_enabled(publishing_enabled)
            .priority(priority)
            .send(&self.channel)
            .await?;

        self.trigger_publish_now();

        Ok(response.subscription_id)
    }

    /// Create a subscription by sending a [`CreateSubscriptionRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.13.2 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `publishing_interval` - The requested publishing interval defines the cyclic rate that
    ///   the Subscription is being requested to return Notifications to the Client. This interval
    ///   is expressed in milliseconds. This interval is represented by the publishing timer in the
    ///   Subscription state table. The negotiated value for this parameter returned in the
    ///   response is used as the default sampling interval for MonitoredItems assigned to this
    ///   Subscription. If the requested value is 0 or negative, the server shall revise with the
    ///   fastest supported publishing interval in milliseconds.
    /// * `lifetime_count` - Requested lifetime count. The lifetime count shall be a minimum of
    ///   three times the keep keep-alive count. When the publishing timer has expired this
    ///   number of times without a Publish request being available to send a NotificationMessage,
    ///   then the Subscription shall be deleted by the Server.
    /// * `max_keep_alive_count` - Requested maximum keep-alive count. When the publishing timer has
    ///   expired this number of times without requiring any NotificationMessage to be sent, the
    ///   Subscription sends a keep-alive Message to the Client. The negotiated value for this
    ///   parameter is returned in the response. If the requested value is 0, the server shall
    ///   revise with the smallest supported keep-alive count.
    /// * `max_notifications_per_publish` - The maximum number of notifications that the Client
    ///   wishes to receive in a single Publish response. A value of zero indicates that there is
    ///   no limit. The number of notifications per Publish is the sum of monitoredItems in
    ///   the DataChangeNotification and events in the EventNotificationList.
    /// * `priority` - Indicates the relative priority of the Subscription. When more than one
    ///   Subscription needs to send Notifications, the Server should de-queue a Publish request
    ///   to the Subscription with the highest priority number. For Subscriptions with equal
    ///   priority the Server should de-queue Publish requests in a round-robin fashion.
    ///   A Client that does not require special priority settings should set this value to zero.
    /// * `publishing_enabled` - A boolean parameter with the following values - `true` publishing
    ///   is enabled for the Subscription, `false`, publishing is disabled for the Subscription.
    ///   The value of this parameter does not affect the value of the monitoring mode Attribute of
    ///   MonitoredItems.
    ///
    /// # Returns
    ///
    /// * `Ok(u32)` - identifier for new subscription
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    #[allow(clippy::too_many_arguments)]
    pub async fn create_subscription(
        &self,
        publishing_interval: Duration,
        lifetime_count: u32,
        max_keep_alive_count: u32,
        max_notifications_per_publish: u32,
        priority: u8,
        publishing_enabled: bool,
        callback: impl OnSubscriptionNotification + 'static,
    ) -> Result<u32, StatusCode> {
        self.create_subscription_inner(
            publishing_interval,
            lifetime_count,
            max_keep_alive_count,
            max_notifications_per_publish,
            publishing_enabled,
            priority,
            Box::new(callback),
        )
        .await
    }

    fn subscription_exists(&self, subscription_id: u32) -> bool {
        let subscription_state = trace_lock!(self.subscription_state);
        subscription_state.subscription_exists(subscription_id)
    }

    /// Modifies a subscription by sending a [`ModifySubscriptionRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.13.3 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - subscription identifier returned from `create_subscription`.
    /// * `publishing_interval` - The requested publishing interval defines the cyclic rate that
    ///   the Subscription is being requested to return Notifications to the Client. This interval
    ///   is expressed in milliseconds. This interval is represented by the publishing timer in the
    ///   Subscription state table. The negotiated value for this parameter returned in the
    ///   response is used as the default sampling interval for MonitoredItems assigned to this
    ///   Subscription. If the requested value is 0 or negative, the server shall revise with the
    ///   fastest supported publishing interval in milliseconds.
    /// * `lifetime_count` - Requested lifetime count. The lifetime count shall be a minimum of
    ///   three times the keep keep-alive count. When the publishing timer has expired this
    ///   number of times without a Publish request being available to send a NotificationMessage,
    ///   then the Subscription shall be deleted by the Server.
    /// * `max_keep_alive_count` - Requested maximum keep-alive count. When the publishing timer has
    ///   expired this number of times without requiring any NotificationMessage to be sent, the
    ///   Subscription sends a keep-alive Message to the Client. The negotiated value for this
    ///   parameter is returned in the response. If the requested value is 0, the server shall
    ///   revise with the smallest supported keep-alive count.
    /// * `max_notifications_per_publish` - The maximum number of notifications that the Client
    ///   wishes to receive in a single Publish response. A value of zero indicates that there is
    ///   no limit. The number of notifications per Publish is the sum of monitoredItems in
    ///   the DataChangeNotification and events in the EventNotificationList.
    /// * `priority` - Indicates the relative priority of the Subscription. When more than one
    ///   Subscription needs to send Notifications, the Server should de-queue a Publish request
    ///   to the Subscription with the highest priority number. For Subscriptions with equal
    ///   priority the Server should de-queue Publish requests in a round-robin fashion.
    ///   A Client that does not require special priority settings should set this value to zero.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Success
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn modify_subscription(
        &self,
        subscription_id: u32,
        publishing_interval: Duration,
        lifetime_count: u32,
        max_keep_alive_count: u32,
        max_notifications_per_publish: u32,
        priority: u8,
    ) -> Result<(), StatusCode> {
        if !self.subscription_exists(subscription_id) {
            session_error!(self, "modify_subscription, subscription id does not exist");
            return Err(StatusCode::BadInvalidArgument);
        }

        ModifySubscription::new(subscription_id, self)
            .publishing_interval(publishing_interval)
            .max_lifetime_count(lifetime_count)
            .max_keep_alive_count(max_keep_alive_count)
            .max_notifications_per_publish(max_notifications_per_publish)
            .priority(priority)
            .send(&self.channel)
            .await?;

        Ok(())
    }

    /// Changes the publishing mode of subscriptions by sending a [`SetPublishingModeRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.13.4 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_ids` - one or more subscription identifiers.
    /// * `publishing_enabled` - A boolean parameter with the following values - `true` publishing
    ///   is enabled for the Subscriptions, `false`, publishing is disabled for the Subscriptions.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - Service return code for the action for each id, `Good` or `BadSubscriptionIdInvalid`
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn set_publishing_mode(
        &self,
        subscription_ids: &[u32],
        publishing_enabled: bool,
    ) -> Result<Vec<StatusCode>, StatusCode> {
        let r = SetPublishingMode::new(publishing_enabled, self)
            .subscription_ids(subscription_ids.to_vec())
            .send(&self.channel)
            .await?
            .results
            .unwrap_or_default();
        if publishing_enabled {
            self.trigger_publish_now();
        }
        Ok(r)
    }

    /// Transfers Subscriptions and their MonitoredItems from one Session to another. For example,
    /// a Client may need to reopen a Session and then transfer its Subscriptions to that Session.
    /// It may also be used by one Client to take over a Subscription from another Client by
    /// transferring the Subscription to its Session.
    ///
    /// Note that if you call this manually, you will need to register the
    /// subscriptions in the subscription state ([`Session::subscription_state`]) in order to
    /// receive notifications.
    ///
    /// See OPC UA Part 4 - Services 5.13.7 for complete description of the service and error responses.
    ///
    /// * `subscription_ids` - one or more subscription identifiers.
    /// * `send_initial_values` - A boolean parameter with the following values - `true` the first
    ///   publish response shall contain the current values of all monitored items in the subscription,
    ///   `false`, the first publish response shall contain only the value changes since the last
    ///   publish response was sent.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<TransferResult>)` - The [`TransferResult`] for each transfer subscription.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn transfer_subscriptions(
        &self,
        subscription_ids: &[u32],
        send_initial_values: bool,
    ) -> Result<Vec<TransferResult>, StatusCode> {
        let r = TransferSubscriptions::new(self)
            .send_initial_values(send_initial_values)
            .subscription_ids(subscription_ids.to_vec())
            .send(&self.channel)
            .await?
            .results
            .unwrap_or_default();

        self.trigger_publish_now();

        Ok(r)
    }

    /// Deletes a subscription by sending a [`DeleteSubscriptionsRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.13.8 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - subscription identifier returned from `create_subscription`.
    ///
    /// # Returns
    ///
    /// * `Ok(StatusCode)` - Service return code for the delete action, `Good` or `BadSubscriptionIdInvalid`
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn delete_subscription(
        &self,
        subscription_id: u32,
    ) -> Result<StatusCode, StatusCode> {
        if subscription_id == 0 {
            session_error!(self, "delete_subscription, subscription id 0 is invalid");
            Err(StatusCode::BadInvalidArgument)
        } else if !self.subscription_exists(subscription_id) {
            session_error!(
                self,
                "delete_subscription, subscription id {} does not exist",
                subscription_id
            );
            Err(StatusCode::BadInvalidArgument)
        } else {
            let result = self.delete_subscriptions(&[subscription_id]).await?;
            Ok(result[0])
        }
    }

    /// Deletes subscriptions by sending a [`DeleteSubscriptionsRequest`] to the server with the list
    /// of subscriptions to delete.
    ///
    /// See OPC UA Part 4 - Services 5.13.8 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_ids` - List of subscription identifiers to delete.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - List of result for delete action on each id, `Good` or `BadSubscriptionIdInvalid`
    ///   The size and order of the list matches the size and order of the input.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn delete_subscriptions(
        &self,
        subscription_ids: &[u32],
    ) -> Result<Vec<StatusCode>, StatusCode> {
        Ok(DeleteSubscriptions::new(self)
            .subscription_ids(subscription_ids.to_vec())
            .send(&self.channel)
            .await?
            .results
            .unwrap_or_default())
    }

    /// Creates monitored items on a subscription by sending a [`CreateMonitoredItemsRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.12.2 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - The Server-assigned identifier for the Subscription that will report Notifications for this MonitoredItem
    /// * `timestamps_to_return` - An enumeration that specifies the timestamp Attributes to be transmitted for each MonitoredItem.
    /// * `items_to_create` - A list of [`MonitoredItemCreateRequest`] to be created and assigned to the specified Subscription.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<MonitoredItemCreateResult>)` - A list of [`MonitoredItemCreateResult`] corresponding to the items to create.
    ///   The size and order of the list matches the size and order of the `items_to_create` request parameter.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn create_monitored_items(
        &self,
        subscription_id: u32,
        timestamps_to_return: TimestampsToReturn,
        items_to_create: Vec<MonitoredItemCreateRequest>,
    ) -> Result<Vec<MonitoredItemCreateResult>, StatusCode> {
        Ok(CreateMonitoredItems::new(subscription_id, self)
            .items_to_create(items_to_create)
            .timestamps_to_return(timestamps_to_return)
            .send(&self.channel)
            .await?
            .results
            .unwrap_or_default())
    }

    /// Modifies monitored items on a subscription by sending a [`ModifyMonitoredItemsRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.12.3 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - The Server-assigned identifier for the Subscription that will report Notifications for this MonitoredItem.
    /// * `timestamps_to_return` - An enumeration that specifies the timestamp Attributes to be transmitted for each MonitoredItem.
    /// * `items_to_modify` - The list of [`MonitoredItemModifyRequest`] to modify.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<MonitoredItemModifyResult>)` - A list of [`MonitoredItemModifyResult`] corresponding to the MonitoredItems to modify.
    ///   The size and order of the list matches the size and order of the `items_to_modify` request parameter.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn modify_monitored_items(
        &self,
        subscription_id: u32,
        timestamps_to_return: TimestampsToReturn,
        items_to_modify: &[MonitoredItemModifyRequest],
    ) -> Result<Vec<MonitoredItemModifyResult>, StatusCode> {
        Ok(ModifyMonitoredItems::new(subscription_id, self)
            .timestamps_to_return(timestamps_to_return)
            .items_to_modify(items_to_modify.to_vec())
            .send(&self.channel)
            .await?
            .results
            .unwrap_or_default())
    }

    /// Sets the monitoring mode on one or more monitored items by sending a [`SetMonitoringModeRequest`]
    /// to the server.
    ///
    /// See OPC UA Part 4 - Services 5.12.4 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - the subscription identifier containing the monitored items to be modified.
    /// * `monitoring_mode` - the monitored mode to apply to the monitored items
    /// * `monitored_item_ids` - the monitored items to be modified
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - Individual result for each monitored item.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn set_monitoring_mode(
        &self,
        subscription_id: u32,
        monitoring_mode: MonitoringMode,
        monitored_item_ids: &[u32],
    ) -> Result<Vec<StatusCode>, StatusCode> {
        Ok(
            SetMonitoringMode::new(subscription_id, monitoring_mode, self)
                .monitored_item_ids(monitored_item_ids.to_vec())
                .send(&self.channel)
                .await?
                .results
                .unwrap_or_default(),
        )
    }

    /// Sets a monitored item so it becomes the trigger that causes other monitored items to send
    /// change events in the same update. Sends a [`SetTriggeringRequest`] to the server.
    /// Note that `items_to_remove` is applied before `items_to_add`.
    ///
    /// See OPC UA Part 4 - Services 5.12.5 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - the subscription identifier containing the monitored item to be used as the trigger.
    /// * `monitored_item_id` - the monitored item that is the trigger.
    /// * `links_to_add` - zero or more items to be added to the monitored item's triggering list.
    /// * `items_to_remove` - zero or more items to be removed from the monitored item's triggering list.
    ///
    /// # Returns
    ///
    /// * `Ok((Option<Vec<StatusCode>>, Option<Vec<StatusCode>>))` - Individual result for each item added / removed for the SetTriggering call.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn set_triggering(
        &self,
        subscription_id: u32,
        triggering_item_id: u32,
        links_to_add: &[u32],
        links_to_remove: &[u32],
    ) -> Result<(Option<Vec<StatusCode>>, Option<Vec<StatusCode>>), StatusCode> {
        let response = SetTriggering::new(subscription_id, triggering_item_id, self)
            .links_to_add(links_to_add.to_vec())
            .links_to_remove(links_to_remove.to_vec())
            .send(&self.channel)
            .await?;
        Ok((response.add_results, response.remove_results))
    }

    /// Deletes monitored items from a subscription by sending a [`DeleteMonitoredItemsRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.12.6 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - The Server-assigned identifier for the Subscription that will report Notifications for this MonitoredItem.
    /// * `items_to_delete` - List of Server-assigned ids for the MonitoredItems to be deleted.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - List of StatusCodes for the MonitoredItems to delete. The size and
    ///   order of the list matches the size and order of the `items_to_delete` request parameter.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn delete_monitored_items(
        &self,
        subscription_id: u32,
        items_to_delete: &[u32],
    ) -> Result<Vec<StatusCode>, StatusCode> {
        Ok(DeleteMonitoredItems::new(subscription_id, self)
            .items_to_delete(items_to_delete.to_vec())
            .send(&self.channel)
            .await?
            .results
            .unwrap_or_default())
    }

    pub(crate) fn next_publish_time(&self, set_last_publish: bool) -> Option<Instant> {
        let mut subscription_state = trace_lock!(self.subscription_state);
        if set_last_publish {
            subscription_state.set_last_publish();
        }
        subscription_state.next_publish_time()
    }

    /// Send a publish request, returning `true` if the session should send a new request
    /// immediately.
    pub(crate) async fn publish(&self) -> Result<bool, StatusCode> {
        let acks = {
            let mut subscription_state = trace_lock!(self.subscription_state);
            let acks = subscription_state.take_acknowledgements();
            if !acks.is_empty() {
                Some(acks)
            } else {
                None
            }
        };

        if enabled!(tracing::Level::DEBUG) {
            let sequence_nrs: Vec<u32> = acks
                .iter()
                .flatten()
                .map(|ack| ack.sequence_number)
                .collect();
            debug!(
                "publish is acknowledging subscription acknowledgements with sequence nrs {:?}",
                sequence_nrs
            );
        }

        let request = PublishRequest {
            request_header: self.channel.make_request_header(self.publish_timeout),
            subscription_acknowledgements: acks.clone(),
        };

        let response = self.channel.send(request, self.publish_timeout).await;

        let err_status = match response {
            Ok(ResponseMessage::Publish(r)) => {
                session_debug!(self, "PublishResponse");

                {
                    let mut subscription_state = trace_lock!(self.subscription_state);
                    subscription_state
                        .handle_notification(r.subscription_id, r.notification_message);
                }

                return Ok(r.more_notifications);
            }
            Err(e) => e,
            Ok(r) => {
                session_error!(self, "publish failed {:?}", r);
                process_unexpected_response(r)
            }
        };

        if let Some(acks) = acks {
            let mut subscription_state = trace_lock!(self.subscription_state);
            subscription_state.re_queue_acknowledgements(acks);
        }

        Err(err_status)
    }

    /// Send a request to re-publish an unacknowledged notification message from the server.
    ///
    /// If this succeeds, the session will automatically acknowledge the notification in the next publish request.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - The Server-assigned identifier for the Subscription to republish from.
    /// * `sequence_number` - Sequence number to re-publish.
    ///
    /// # Returns
    ///
    /// * `Ok(NotificationMessage)` - Re-published notification message.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn republish(
        &self,
        subscription_id: u32,
        sequence_number: u32,
    ) -> Result<NotificationMessage, StatusCode> {
        let request = RepublishRequest {
            request_header: self.channel.make_request_header(self.request_timeout),
            subscription_id,
            retransmit_sequence_number: sequence_number,
        };

        let response = self.channel.send(request, self.request_timeout).await?;

        if let ResponseMessage::Republish(response) = response {
            process_service_result(&response.response_header)?;
            session_debug!(self, "republish, success");
            {
                let mut lck = trace_lock!(self.subscription_state);
                lck.add_acknowledgement(subscription_id, sequence_number);
            }
            Ok(response.notification_message)
        } else {
            session_error!(self, "republish failed {:?}", response);
            Err(process_unexpected_response(response))
        }
    }

    /// This code attempts to take the existing subscriptions created by a previous session and
    /// either transfer them to this session, or construct them from scratch.
    pub(crate) async fn transfer_subscriptions_from_old_session(&self) {
        let subscription_ids = {
            let subscription_state = trace_lock!(self.subscription_state);
            subscription_state.subscription_ids()
        };

        let Some(subscription_ids) = subscription_ids else {
            return;
        };

        // Start by getting the subscription ids
        // Try to use TransferSubscriptions to move subscriptions_ids over. If this
        // works then there is nothing else to do.
        let mut subscription_ids_to_recreate =
            subscription_ids.iter().copied().collect::<HashSet<u32>>();
        if let Ok(transfer_results) = self.transfer_subscriptions(&subscription_ids, true).await {
            session_debug!(self, "transfer_results = {:?}", transfer_results);
            transfer_results.iter().enumerate().for_each(|(i, r)| {
                if r.status_code.is_good() {
                    // Subscription was transferred so it does not need to be recreated
                    subscription_ids_to_recreate.remove(&subscription_ids[i]);
                }
            });
        }

        // But if it didn't work, then some or all subscriptions have to be remade.
        if !subscription_ids_to_recreate.is_empty() {
            session_warn!(self, "Some or all of the existing subscriptions could not be transferred and must be created manually");
        }

        for subscription_id in subscription_ids_to_recreate {
            session_debug!(self, "Recreating subscription {}", subscription_id);

            let deleted_subscription = {
                let mut subscription_state = trace_lock!(self.subscription_state);
                subscription_state.delete_subscription(subscription_id)
            };

            let Some(subscription) = deleted_subscription else {
                session_warn!(
                    self,
                    "Subscription removed from session while transfer in progress"
                );
                continue;
            };

            let Ok(subscription_id) = self
                .create_subscription_inner(
                    subscription.publishing_interval,
                    subscription.lifetime_count,
                    subscription.max_keep_alive_count,
                    subscription.max_notifications_per_publish,
                    subscription.publishing_enabled,
                    subscription.priority,
                    subscription.callback,
                )
                .await
            else {
                session_warn!(
                    self,
                    "Could not create a subscription from the existing subscription {}",
                    subscription_id
                );
                continue;
            };

            let items_to_create = subscription
                .monitored_items
                .values()
                .map(|item| MonitoredItemCreateRequest {
                    item_to_monitor: item.item_to_monitor().clone(),
                    monitoring_mode: item.monitoring_mode,
                    requested_parameters: MonitoringParameters {
                        client_handle: item.client_handle(),
                        sampling_interval: item.sampling_interval(),
                        filter: item.filter.clone(),
                        queue_size: item.queue_size() as u32,
                        discard_oldest: item.discard_oldest(),
                    },
                })
                .collect::<Vec<MonitoredItemCreateRequest>>();

            let mut iter = items_to_create.into_iter();

            loop {
                let chunk = (&mut iter)
                    .take(self.recreate_monitored_items_chunk)
                    .collect::<Vec<_>>();

                if chunk.is_empty() {
                    break;
                }

                let _ = self
                    .create_monitored_items(subscription_id, TimestampsToReturn::Both, chunk)
                    .await;
            }

            for item in subscription.monitored_items.values() {
                let triggered_items = item.triggered_items();
                if !triggered_items.is_empty() {
                    let links_to_add = triggered_items.iter().copied().collect::<Vec<u32>>();
                    let _ = self
                        .set_triggering(subscription_id, item.id(), links_to_add.as_slice(), &[])
                        .await;
                }
            }
        }
    }
}
