use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

use super::{
    monitored_item::MonitoredItem,
    pool::NotificationBuffer,
    retransmission_queue::RetransmissionQueue,
    ring::NotificationWorkItem,
    subscription::{
        reclaim_data_change_notification_vecs, DataChangeNotificationVecPool, MonitoredItemHandle,
        Subscription, TickReason, TickResult,
    },
    CreateMonitoredItem, NonAckedPublish, PendingPublish, PersistentSessionKey,
};
use crossbeam_queue::ArrayQueue;
use hashbrown::HashMap;
use opcua_nodes::{Event, TypeTree};

use crate::{
    info::ServerInfo,
    node_manager::{
        MonitoredItemRef, MonitoredItemUpdateRef, NodeManagersRef, TypeTreeForUserStatic,
    },
    rbac,
    session::instance::Session,
    SubscriptionLimits,
};
use opcua_core::{sync::RwLock, PublishResponseShared, RepublishResponseShared};
use opcua_types::{
    AttributeId, CreateSubscriptionRequest, CreateSubscriptionResponse, DataValue, DateTime,
    DateTimeUtc, ExtensionObject, ModifySubscriptionRequest, ModifySubscriptionResponse,
    MonitoredItemCreateResult, MonitoredItemModifyRequest, MonitoredItemModifyResult,
    MonitoringMode, NodeId, NotificationMessage, ObjectTypeId, PublishRequest, QualifiedName,
    RepublishRequest, ResponseHeader, RolePermissionType, ServiceFault, SetPublishingModeRequest,
    SetPublishingModeResponse, StatusCode, TimestampsToReturn, Variant,
};

pub(super) struct RemovedSubscription {
    pub(super) id: u32,
    pub(super) monitored_items: Vec<MonitoredItemRef>,
}

type PendingPublishResponse = (PendingPublish, Arc<NotificationMessage>, u32);

pub(super) struct PendingRefreshDrain {
    subscription_id: u32,
    monitored_item: Option<MonitoredItemHandle>,
    events: Vec<Box<dyn Event + Send>>,
    next_event: usize,
}

impl PendingRefreshDrain {
    fn new(
        subscription_id: u32,
        monitored_item: Option<MonitoredItemHandle>,
        events: Vec<Box<dyn Event + Send>>,
    ) -> Self {
        Self {
            subscription_id,
            monitored_item,
            events,
            next_event: 0,
        }
    }

    fn remaining(&self) -> usize {
        self.events.len().saturating_sub(self.next_event)
    }

    pub(super) fn is_complete(&self) -> bool {
        self.next_event >= self.events.len()
    }
}

/// Subscriptions belonging to a single session. Note that they are technically _owned_ by
/// a user token, which means that they can be transfered to a different session.
pub struct SessionSubscriptions {
    /// Identity token of the user that created the subscription, used for transfer subscriptions.
    user_token: PersistentSessionKey,
    /// Subscriptions associated with the session.
    subscriptions: HashMap<u32, Subscription>,
    /// Publish request queue (requests by the client on the session)
    publish_request_queue: VecDeque<PendingPublish>,
    /// Status-change notifications owed to this session for subscriptions that have been
    /// transferred away (Part 4 §5.14.7.1: the old session receives Good_SubscriptionTransferred).
    /// Delivered on the next available publish request, even with no remaining subscriptions.
    pending_status_changes: VecDeque<(u32, Arc<NotificationMessage>)>,
    /// Subscriptions staged for transfer out. They remain routable/drainable
    /// until the cache index flips, but this session no longer advances them.
    transferring: HashSet<u32>,
    /// Notifications that have been sent but have yet to be acknowledged (retransmission queue).
    retransmission_queue: RetransmissionQueue,
    /// Reusable storage for data-change notifications reclaimed from acknowledged publishes.
    data_change_notification_pool: DataChangeNotificationVecPool,
    /// Configured limits on subscriptions.
    limits: SubscriptionLimits,

    /// Static reference to the session owning this, required to cleanly handle deletion.
    session: Arc<RwLock<Session>>,
    /// Static reference to the type-tree for the user owning this.
    type_tree_for_user: Arc<dyn TypeTreeForUserStatic>,
    /// Weak reference to server node managers, used for delivery-time event-source metadata lookup.
    node_managers: NodeManagersRef,
    /// Whether unconfigured RolePermissions fail closed for this session's event delivery.
    enforce_role_based_access: bool,
}

impl SessionSubscriptions {
    pub(super) fn new(
        limits: SubscriptionLimits,
        user_token: PersistentSessionKey,
        session: Arc<RwLock<Session>>,
        type_tree_for_user: Arc<dyn TypeTreeForUserStatic>,
        node_managers: NodeManagersRef,
        enforce_role_based_access: bool,
    ) -> Self {
        Self {
            user_token,
            subscriptions: HashMap::new(),
            publish_request_queue: VecDeque::new(),
            pending_status_changes: VecDeque::new(),
            transferring: HashSet::new(),
            retransmission_queue: RetransmissionQueue::new(),
            data_change_notification_pool: DataChangeNotificationVecPool::default(),
            limits,
            session,
            type_tree_for_user,
            node_managers,
            enforce_role_based_access,
        }
    }

    fn max_publish_requests(&self) -> usize {
        self.limits
            .max_pending_publish_requests
            .min(self.subscriptions.len() * self.limits.max_publish_requests_per_subscription)
            .max(1)
    }

    pub(super) fn is_ready_to_delete(&self) -> bool {
        self.subscriptions.is_empty()
            && self.publish_request_queue.is_empty()
            && self.pending_status_changes.is_empty()
    }

    #[allow(clippy::result_large_err)]
    pub(super) fn insert(
        &mut self,
        subscription: Subscription,
        notifs: Vec<NonAckedPublish>,
    ) -> Result<(), (StatusCode, Subscription, Vec<NonAckedPublish>)> {
        if self.subscriptions.len() >= self.limits.max_subscriptions_per_session {
            return Err((StatusCode::BadTooManySubscriptions, subscription, notifs));
        }
        self.transferring.remove(&subscription.id());
        self.subscriptions.insert(subscription.id(), subscription);
        for notif in notifs {
            self.retransmission_queue.push_existing(notif);
        }
        Ok(())
    }

    /// Return `true` if the session has a subscription with ID given by
    /// `sub_id`.
    pub fn contains(&self, sub_id: u32) -> bool {
        self.subscriptions.contains_key(&sub_id)
    }

    /// Return a vector of all the subscription IDs in this session.
    pub fn subscription_ids(&self) -> Vec<u32> {
        self.subscriptions.keys().copied().collect()
    }

    pub(super) fn update_owner(
        &mut self,
        user_token: PersistentSessionKey,
        type_tree_for_user: Arc<dyn TypeTreeForUserStatic>,
    ) {
        self.user_token = user_token;
        self.type_tree_for_user = type_tree_for_user;
        for subscription in self.subscriptions.values_mut() {
            subscription.set_resend_data();
        }
    }

    pub(super) fn monitored_item_refs(&self) -> Vec<MonitoredItemRef> {
        self.subscriptions
            .values()
            .flat_map(Subscription::monitored_item_refs)
            .collect()
    }

    pub(super) fn apply_revalidated_values(&mut self, values: Vec<(MonitoredItemRef, DataValue)>) {
        let now = DateTime::now();
        for (item, value) in values {
            let handle = item.handle();
            if let Some(subscription) = self.subscriptions.get_mut(&handle.subscription_id) {
                subscription.update_monitored_item_value(handle, value, &now);
            }
        }
    }

    pub(super) fn remove(
        &mut self,
        subscription_id: u32,
    ) -> (Option<Subscription>, Vec<NonAckedPublish>) {
        self.transferring.remove(&subscription_id);
        let notifs = self
            .retransmission_queue
            .remove_subscription(subscription_id);
        (self.subscriptions.remove(&subscription_id), notifs)
    }

    pub(super) fn clone_for_transfer(
        &self,
        subscription_id: u32,
    ) -> Option<(Subscription, Vec<NonAckedPublish>)> {
        let subscription = self.subscriptions.get(&subscription_id)?.clone();
        let notifs = self
            .retransmission_queue
            .clone_subscription(subscription_id);
        Some((subscription, notifs))
    }

    pub(super) fn mark_transferring(&mut self, subscription_id: u32) -> Result<(), StatusCode> {
        if !self.subscriptions.contains_key(&subscription_id) {
            return Err(StatusCode::BadSubscriptionIdInvalid);
        }
        self.transferring.insert(subscription_id);
        Ok(())
    }

    /// Get a mutable reference to a subscription by ID.
    pub fn get_mut(&mut self, subscription_id: u32) -> Option<&mut Subscription> {
        self.subscriptions.get_mut(&subscription_id)
    }

    /// Get a reference to a subscription by ID.
    pub fn get(&self, subscription_id: u32) -> Option<&Subscription> {
        self.subscriptions.get(&subscription_id)
    }

    pub(super) fn create_subscription(
        &mut self,
        request: &CreateSubscriptionRequest,
        info: &ServerInfo,
    ) -> Result<CreateSubscriptionResponse, StatusCode> {
        if self.subscriptions.len() >= self.limits.max_subscriptions_per_session {
            return Err(StatusCode::BadTooManySubscriptions);
        }
        let subscription_id = info.subscription_id_handle.next();

        let (revised_publishing_interval, revised_max_keep_alive_count, revised_lifetime_count) =
            Self::revise_subscription_values(
                info,
                request.requested_publishing_interval,
                request.requested_max_keep_alive_count,
                request.requested_lifetime_count,
            );

        let subscription = Subscription::new(
            subscription_id,
            request.publishing_enabled,
            Duration::from_millis(revised_publishing_interval as u64),
            revised_lifetime_count,
            revised_max_keep_alive_count,
            request.priority,
            self.limits.max_queued_notifications,
            self.revise_max_notifications_per_publish(request.max_notifications_per_publish),
        );
        self.subscriptions.insert(subscription.id(), subscription);
        Ok(CreateSubscriptionResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            subscription_id,
            revised_publishing_interval,
            revised_lifetime_count,
            revised_max_keep_alive_count,
        })
    }

    pub(super) fn modify_subscription(
        &mut self,
        request: &ModifySubscriptionRequest,
        info: &ServerInfo,
    ) -> Result<ModifySubscriptionResponse, StatusCode> {
        let max_notifications_per_publish =
            self.revise_max_notifications_per_publish(request.max_notifications_per_publish);
        let Some(subscription) = self.subscriptions.get_mut(&request.subscription_id) else {
            return Err(StatusCode::BadSubscriptionIdInvalid);
        };

        let (revised_publishing_interval, revised_max_keep_alive_count, revised_lifetime_count) =
            Self::revise_subscription_values(
                info,
                request.requested_publishing_interval,
                request.requested_max_keep_alive_count,
                request.requested_lifetime_count,
            );

        subscription.set_publishing_interval(Duration::from_micros(
            (revised_publishing_interval * 1000.0) as u64,
        ));
        subscription.set_max_keep_alive_counter(revised_max_keep_alive_count);
        subscription.set_max_lifetime_counter(revised_lifetime_count);
        subscription.set_priority(request.priority);
        subscription.reset_lifetime_counter();
        subscription.reset_keep_alive_counter();
        subscription.set_max_notifications_per_publish(max_notifications_per_publish);

        Ok(ModifySubscriptionResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            revised_publishing_interval,
            revised_lifetime_count,
            revised_max_keep_alive_count,
        })
    }

    pub(super) fn set_publishing_mode(
        &mut self,
        request: &SetPublishingModeRequest,
    ) -> Result<SetPublishingModeResponse, StatusCode> {
        let Some(ids) = &request.subscription_ids else {
            return Err(StatusCode::BadNothingToDo);
        };
        if ids.is_empty() {
            return Err(StatusCode::BadNothingToDo);
        }

        let mut results = Vec::new();
        for id in ids {
            results.push(match self.subscriptions.get_mut(id) {
                Some(sub) => {
                    sub.set_publishing_enabled(request.publishing_enabled);
                    sub.reset_lifetime_counter();
                    StatusCode::Good
                }
                None => StatusCode::BadSubscriptionIdInvalid,
            })
        }
        Ok(SetPublishingModeResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            results: Some(results),
            diagnostic_infos: None,
        })
    }

    pub(super) fn republish(
        &mut self,
        request: &RepublishRequest,
    ) -> Result<RepublishResponseShared, StatusCode> {
        let Some(subscription) = self.subscriptions.get_mut(&request.subscription_id) else {
            return Err(StatusCode::BadSubscriptionIdInvalid);
        };
        subscription.reset_lifetime_counter();

        let msg = self.find_notification_message(
            request.subscription_id,
            request.retransmit_sequence_number,
        )?;
        Ok(RepublishResponseShared {
            response_header: ResponseHeader::new_good(&request.request_header),
            notification_message: msg,
        })
    }

    pub(super) fn create_monitored_items(
        &mut self,
        subscription_id: u32,
        requests: &[CreateMonitoredItem],
    ) -> Result<Vec<MonitoredItemCreateResult>, StatusCode> {
        let cap = self.limits.max_monitored_items_per_sub;
        let Some(sub) = self.subscriptions.get_mut(&subscription_id) else {
            return Err(StatusCode::BadSubscriptionIdInvalid);
        };

        let mut results = Vec::with_capacity(requests.len());
        for item in requests {
            let filter_result = item
                .filter_res()
                .cloned()
                .unwrap_or_else(ExtensionObject::null);
            if item.status_code().is_good() {
                if cap > 0 && sub.len() >= cap {
                    results.push(MonitoredItemCreateResult {
                        status_code: StatusCode::BadTooManyMonitoredItems,
                        monitored_item_id: 0,
                        revised_sampling_interval: item.sampling_interval(),
                        revised_queue_size: item.queue_size() as u32,
                        filter_result,
                    });
                    continue;
                }
                let new_item = MonitoredItem::new(item);
                results.push(MonitoredItemCreateResult {
                    status_code: StatusCode::Good,
                    monitored_item_id: new_item.id(),
                    revised_sampling_interval: new_item.sampling_interval(),
                    revised_queue_size: new_item.queue_size() as u32,
                    filter_result,
                });
                sub.insert(new_item.id(), new_item);
            } else {
                results.push(MonitoredItemCreateResult {
                    status_code: item.status_code(),
                    monitored_item_id: 0,
                    revised_sampling_interval: item.sampling_interval(),
                    revised_queue_size: item.queue_size() as u32,
                    filter_result,
                });
            }
        }

        Ok(results)
    }

    pub(super) fn modify_monitored_items(
        &mut self,
        subscription_id: u32,
        info: &ServerInfo,
        timestamps_to_return: TimestampsToReturn,
        requests: Vec<MonitoredItemModifyRequest>,
        eu_ranges: HashMap<u32, (f64, f64)>,
        type_tree: &dyn TypeTree,
    ) -> Result<Vec<MonitoredItemUpdateRef>, StatusCode> {
        let Some(sub) = self.subscriptions.get_mut(&subscription_id) else {
            return Err(StatusCode::BadSubscriptionIdInvalid);
        };
        let mut results = Vec::with_capacity(requests.len());
        for request in requests {
            if let Some(item) = sub.get_mut(&request.monitored_item_id) {
                let eu_range = eu_ranges.get(&request.monitored_item_id).copied();
                let (filter_result, status) =
                    item.modify(info, timestamps_to_return, &request, eu_range, type_tree);
                let filter_result = filter_result.unwrap_or_else(ExtensionObject::null);

                results.push(MonitoredItemUpdateRef::new(
                    MonitoredItemHandle {
                        subscription_id,
                        monitored_item_id: item.id(),
                    },
                    item.item_to_monitor().node_id.clone(),
                    item.item_to_monitor().attribute_id,
                    MonitoredItemModifyResult {
                        status_code: status,
                        revised_sampling_interval: item.sampling_interval(),
                        revised_queue_size: item.queue_size() as u32,
                        filter_result,
                    },
                ));
            } else {
                results.push(MonitoredItemUpdateRef::new(
                    MonitoredItemHandle {
                        subscription_id,
                        monitored_item_id: request.monitored_item_id,
                    },
                    NodeId::null(),
                    AttributeId::NodeId,
                    MonitoredItemModifyResult {
                        status_code: StatusCode::BadMonitoredItemIdInvalid,
                        revised_sampling_interval: 0.0,
                        revised_queue_size: 0,
                        filter_result: ExtensionObject::null(),
                    },
                ));
            }
        }

        Ok(results)
    }

    pub(super) fn monitored_item_node_ids(
        &self,
        subscription_id: u32,
        monitored_item_ids: &[u32],
    ) -> Result<HashMap<u32, NodeId>, StatusCode> {
        let Some(sub) = self.subscriptions.get(&subscription_id) else {
            return Err(StatusCode::BadSubscriptionIdInvalid);
        };
        let mut results = HashMap::with_capacity(monitored_item_ids.len());
        for monitored_item_id in monitored_item_ids {
            if let Some(item) = sub.get(monitored_item_id) {
                results.insert(*monitored_item_id, item.item_to_monitor().node_id.clone());
            }
        }
        Ok(results)
    }

    pub(super) fn set_monitoring_mode(
        &mut self,
        subscription_id: u32,
        monitoring_mode: MonitoringMode,
        items: Vec<u32>,
    ) -> Result<Vec<(StatusCode, MonitoredItemRef)>, StatusCode> {
        let Some(sub) = self.subscriptions.get_mut(&subscription_id) else {
            return Err(StatusCode::BadSubscriptionIdInvalid);
        };
        let mut results = Vec::with_capacity(items.len());
        for id in items {
            let handle = MonitoredItemHandle {
                subscription_id,
                monitored_item_id: id,
            };
            if let Some(item) = sub.get_mut(&id) {
                results.push((
                    StatusCode::Good,
                    MonitoredItemRef::new(
                        handle,
                        item.item_to_monitor().node_id.clone(),
                        item.item_to_monitor().attribute_id,
                    ),
                ));
                item.set_monitoring_mode(monitoring_mode);
            } else {
                results.push((
                    StatusCode::BadMonitoredItemIdInvalid,
                    MonitoredItemRef::new(handle, NodeId::null(), AttributeId::NodeId),
                ));
            }
        }
        Ok(results)
    }

    fn filter_links(links: Vec<u32>, sub: &Subscription) -> (Vec<u32>, Vec<StatusCode>) {
        let mut to_apply = Vec::with_capacity(links.len());
        let mut results = Vec::with_capacity(links.len());

        for link in links {
            if sub.contains_key(&link) {
                to_apply.push(link);
                results.push(StatusCode::Good);
            } else {
                results.push(StatusCode::BadMonitoredItemIdInvalid);
            }
        }
        (to_apply, results)
    }

    pub(super) fn set_triggering(
        &mut self,
        subscription_id: u32,
        triggering_item_id: u32,
        links_to_add: Vec<u32>,
        links_to_remove: Vec<u32>,
    ) -> Result<(Vec<StatusCode>, Vec<StatusCode>), StatusCode> {
        let Some(sub) = self.subscriptions.get_mut(&subscription_id) else {
            return Err(StatusCode::BadSubscriptionIdInvalid);
        };
        if !sub.contains_key(&triggering_item_id) {
            return Err(StatusCode::BadMonitoredItemIdInvalid);
        }

        let (to_add, add_results) = Self::filter_links(links_to_add, sub);
        let (to_remove, remove_results) = Self::filter_links(links_to_remove, sub);

        let item = sub.get_mut(&triggering_item_id).unwrap();

        item.set_triggering(&to_add, &to_remove);

        Ok((add_results, remove_results))
    }

    pub(super) fn delete_monitored_items(
        &mut self,
        subscription_id: u32,
        items: &[u32],
    ) -> Result<Vec<(StatusCode, MonitoredItemRef)>, StatusCode> {
        let Some(sub) = self.subscriptions.get_mut(&subscription_id) else {
            return Err(StatusCode::BadSubscriptionIdInvalid);
        };
        let mut results = Vec::with_capacity(items.len());
        for id in items {
            let handle = MonitoredItemHandle {
                subscription_id,
                monitored_item_id: *id,
            };
            if let Some(item) = sub.remove(id) {
                results.push((
                    StatusCode::Good,
                    MonitoredItemRef::new(
                        handle,
                        item.item_to_monitor().node_id.clone(),
                        item.item_to_monitor().attribute_id,
                    ),
                ));
            } else {
                results.push((
                    StatusCode::BadMonitoredItemIdInvalid,
                    MonitoredItemRef::new(handle, NodeId::null(), AttributeId::NodeId),
                ))
            }
        }
        Ok(results)
    }

    pub(super) fn delete_subscriptions(
        &mut self,
        ids: &[u32],
    ) -> Vec<(StatusCode, Vec<MonitoredItemRef>)> {
        let mut result = Vec::with_capacity(ids.len());
        for id in ids {
            let Some(mut sub) = self.subscriptions.remove(id) else {
                result.push((StatusCode::BadSubscriptionIdInvalid, Vec::new()));
                continue;
            };

            let items = sub
                .drain()
                .map(|item| {
                    MonitoredItemRef::new(
                        MonitoredItemHandle {
                            subscription_id: *id,
                            monitored_item_id: item.1.id(),
                        },
                        item.1.item_to_monitor().node_id.clone(),
                        item.1.item_to_monitor().attribute_id,
                    )
                })
                .collect();

            result.push((StatusCode::Good, items))
        }

        for id in ids {
            let removed = self.retransmission_queue.remove_subscription(*id);
            for notification in removed {
                Self::reclaim_non_acked_publish(
                    &mut self.data_change_notification_pool,
                    notification,
                );
            }
        }

        result
    }

    /// This function takes the requested values passed in a create / modify and returns revised
    /// values that conform to the server's limits. For simplicity the return type is a tuple
    fn revise_subscription_values(
        info: &ServerInfo,
        requested_publishing_interval: f64,
        requested_max_keep_alive_count: u32,
        requested_lifetime_count: u32,
    ) -> (f64, u32, u32) {
        let revised_publishing_interval = f64::max(
            requested_publishing_interval,
            info.config.limits.subscriptions.min_publishing_interval_ms,
        );
        let revised_max_keep_alive_count = if requested_max_keep_alive_count
            > info.config.limits.subscriptions.max_keep_alive_count
        {
            info.config.limits.subscriptions.max_keep_alive_count
        } else if requested_max_keep_alive_count == 0 {
            info.config.limits.subscriptions.default_keep_alive_count
        } else {
            requested_max_keep_alive_count
        };
        // Lifetime count must exceed keep alive count by at least a multiple of
        let min_lifetime_count = revised_max_keep_alive_count * 3;
        let revised_lifetime_count = if requested_lifetime_count < min_lifetime_count {
            min_lifetime_count
        } else if requested_lifetime_count > info.config.limits.subscriptions.max_lifetime_count {
            info.config.limits.subscriptions.max_lifetime_count
        } else {
            requested_lifetime_count
        };
        (
            revised_publishing_interval,
            revised_max_keep_alive_count,
            revised_lifetime_count,
        )
    }

    fn revise_max_notifications_per_publish(&self, inp: u32) -> u64 {
        if self.limits.max_notifications_per_publish == 0 {
            inp as u64
        } else if inp == 0 || inp as u64 > self.limits.max_notifications_per_publish {
            self.limits.max_notifications_per_publish
        } else {
            inp as u64
        }
    }

    fn enqueue_retransmission_notification(
        retransmission_queue: &mut RetransmissionQueue,
        data_change_notification_pool: &mut DataChangeNotificationVecPool,
        max_retransmission_queue_len: usize,
        subscription_id: u32,
        notification: Arc<NotificationMessage>,
    ) {
        retransmission_queue.enqueue(
            data_change_notification_pool,
            max_retransmission_queue_len,
            subscription_id,
            notification,
        );
    }

    fn reclaim_non_acked_publish(
        data_change_notification_pool: &mut DataChangeNotificationVecPool,
        notification: NonAckedPublish,
    ) {
        let Some(message) = Arc::into_inner(notification.message) else {
            return;
        };
        reclaim_data_change_notification_vecs(message, data_change_notification_pool);
    }

    pub(crate) fn enqueue_publish_request(
        &mut self,
        now: &DateTimeUtc,
        now_instant: Instant,
        mut request: PendingPublish,
    ) {
        let mut buffer = NotificationBuffer::new();
        if self.publish_request_queue.len() >= self.max_publish_requests() {
            // Tick to trigger publish, maybe remove a request to make space for new one
            let _ = self.tick(
                now,
                now_instant,
                TickReason::ReceivePublishRequest,
                &mut buffer,
            );
        }

        if self.publish_request_queue.len() >= self.max_publish_requests() {
            // Pop the oldest publish request from the queue and return it with an error
            let req = self.publish_request_queue.pop_front().unwrap();
            // Ignore the result of this, if it fails it just means that the
            // channel is disconnected.
            let _ = req.response.send(
                ServiceFault::new(
                    &req.request.request_header,
                    StatusCode::BadTooManyPublishRequests,
                )
                .into(),
            );
        }

        request.ack_results = self.process_subscription_acks(&request.request);
        self.publish_request_queue.push_back(request);
        self.tick(
            now,
            now_instant,
            TickReason::ReceivePublishRequest,
            &mut buffer,
        );
    }

    pub(super) fn has_more_notifications(&self) -> bool {
        self.subscriptions
            .values()
            .any(|subscription| subscription.more_notifications())
    }

    pub(super) fn next_tick_deadline(&self) -> Option<Instant> {
        self.subscriptions
            .values()
            .map(|subscription| subscription.next_publish_deadline())
            .min()
    }

    pub(super) fn has_queued_publish_request(&self) -> bool {
        !self.publish_request_queue.is_empty()
    }

    /// Queue a StatusChangeNotification to be delivered to this session on the next
    /// available publish request. Used when a subscription is transferred away
    /// (Part 4 §5.14.7.1).
    pub(super) fn queue_status_change(
        &mut self,
        subscription_id: u32,
        sequence_number: u32,
        publish_time: DateTime,
        status: StatusCode,
    ) {
        self.pending_status_changes.push_back((
            subscription_id,
            Arc::new(NotificationMessage::status_change(
                sequence_number,
                publish_time,
                status,
            )),
        ));
    }

    /// Deliver queued transfer status-change notifications, one per available publish
    /// request. Runs before the no-subscriptions early-out so the old session still
    /// receives Good_SubscriptionTransferred after its last subscription has moved.
    fn deliver_pending_status_changes(&mut self, now: &DateTimeUtc) {
        while !self.pending_status_changes.is_empty() {
            let Some(publish_request) = self.publish_request_queue.pop_front() else {
                break;
            };
            let (subscription_id, notification) = self.pending_status_changes.pop_front().unwrap();
            let _ = publish_request.response.send(
                PublishResponseShared {
                    response_header: ResponseHeader::new_timestamped_service_result(
                        DateTime::from(*now),
                        &publish_request.request.request_header,
                        StatusCode::Good,
                    ),
                    subscription_id,
                    available_sequence_numbers: None,
                    more_notifications: false,
                    notification_message: notification,
                    results: publish_request.ack_results,
                    diagnostic_infos: None,
                }
                .into(),
            );
        }
    }

    pub(super) fn tick(
        &mut self,
        now: &DateTimeUtc,
        now_instant: Instant,
        tick_reason: TickReason,
        buffer: &mut NotificationBuffer,
    ) -> Vec<RemovedSubscription> {
        self.deliver_pending_status_changes(now);

        if self.subscriptions.is_empty() || self.subscriptions.len() == self.transferring.len() {
            self.reject_publish_requests_without_subscriptions();
            return Vec::new();
        }

        self.remove_expired_publish_requests(now_instant);

        if self.publish_request_queue.is_empty() {
            return self.tick_subscriptions_without_publish_requests(
                now,
                now_instant,
                tick_reason,
                buffer,
            );
        }

        let (removed_subscriptions, responses, more_notifications) =
            self.tick_subscriptions_with_publish_requests(now, now_instant, tick_reason, buffer);
        self.send_publish_responses(now, responses, more_notifications);

        removed_subscriptions
    }

    fn reject_publish_requests_without_subscriptions(&mut self) {
        for pb in self.publish_request_queue.drain(..) {
            let _ = pb.response.send(
                ServiceFault::new(&pb.request.request_header, StatusCode::BadNoSubscription).into(),
            );
        }
    }

    fn tick_subscriptions_without_publish_requests(
        &mut self,
        now: &DateTimeUtc,
        now_instant: Instant,
        tick_reason: TickReason,
        buffer: &mut NotificationBuffer,
    ) -> Vec<RemovedSubscription> {
        let mut removed_subscriptions = Vec::new();
        let mut to_remove = Vec::new();

        for (sub_id, subscription) in &mut self.subscriptions {
            if self.transferring.contains(sub_id) {
                continue;
            }
            buffer.reset();
            let monitored_items = subscription.monitored_item_refs();
            let res = subscription.tick(
                now,
                now_instant,
                tick_reason,
                false,
                &mut *buffer,
                &mut self.data_change_notification_pool,
            );
            if matches!(res, TickResult::Expired) {
                removed_subscriptions.push(RemovedSubscription {
                    id: *sub_id,
                    monitored_items,
                });
            }

            if subscription.ready_to_remove() {
                to_remove.push(*sub_id);
            }
        }

        self.remove_ready_subscriptions(to_remove);
        removed_subscriptions
    }

    fn tick_subscriptions_with_publish_requests(
        &mut self,
        now: &DateTimeUtc,
        now_instant: Instant,
        tick_reason: TickReason,
        buffer: &mut NotificationBuffer,
    ) -> (Vec<RemovedSubscription>, Vec<PendingPublishResponse>, bool) {
        let mut removed_subscriptions = Vec::new();
        let mut responses = Vec::new();
        let mut more_notifications = false;

        for sub_id in self.subscription_ids_by_priority() {
            if self.transferring.contains(&sub_id) {
                continue;
            }
            let (removed_subscription, subscription_has_more_notifications) = self
                .tick_subscription_with_publish_requests(
                    sub_id,
                    now,
                    now_instant,
                    tick_reason,
                    buffer,
                    &mut responses,
                );
            more_notifications |= subscription_has_more_notifications;
            if let Some(removed_subscription) = removed_subscription {
                removed_subscriptions.push(removed_subscription);
            }
        }

        (removed_subscriptions, responses, more_notifications)
    }

    fn tick_subscription_with_publish_requests(
        &mut self,
        sub_id: u32,
        now: &DateTimeUtc,
        now_instant: Instant,
        tick_reason: TickReason,
        buffer: &mut NotificationBuffer,
        responses: &mut Vec<PendingPublishResponse>,
    ) -> (Option<RemovedSubscription>, bool) {
        let subscription = self.subscriptions.get_mut(&sub_id).unwrap();
        buffer.reset();
        let monitored_items = subscription.monitored_item_refs();
        let res = subscription.tick(
            now,
            now_instant,
            tick_reason,
            !self.publish_request_queue.is_empty(),
            &mut *buffer,
            &mut self.data_change_notification_pool,
        );

        while !self.publish_request_queue.is_empty() {
            let Some(notification_message) = subscription.take_notification() else {
                break;
            };
            tracing::trace!("Sending notification message {:?}", notification_message);
            let publish_request = self.publish_request_queue.pop_front().unwrap();
            responses.push((publish_request, Arc::new(notification_message), sub_id));
        }

        let more_notifications = subscription.more_notifications();
        let ready_to_remove = subscription.ready_to_remove();
        let removed_subscription =
            matches!(res, TickResult::Expired).then_some(RemovedSubscription {
                id: sub_id,
                monitored_items,
            });

        if ready_to_remove {
            self.subscriptions.remove(&sub_id);
            let removed = self.retransmission_queue.remove_subscription(sub_id);
            for notification in removed {
                Self::reclaim_non_acked_publish(
                    &mut self.data_change_notification_pool,
                    notification,
                );
            }
        }

        (removed_subscription, more_notifications)
    }

    fn subscription_ids_by_priority(&self) -> Vec<u32> {
        let mut subscription_priority: Vec<(u32, u8)> = self
            .subscriptions
            .values()
            .map(|v| (v.id(), v.priority()))
            .collect();
        subscription_priority.sort_by_key(|s1| std::cmp::Reverse(s1.1));
        subscription_priority.into_iter().map(|s| s.0).collect()
    }

    fn remove_ready_subscriptions(&mut self, to_remove: Vec<u32>) {
        for sub_id in to_remove {
            self.transferring.remove(&sub_id);
            self.subscriptions.remove(&sub_id);
            let removed = self.retransmission_queue.remove_subscription(sub_id);
            for notification in removed {
                Self::reclaim_non_acked_publish(
                    &mut self.data_change_notification_pool,
                    notification,
                );
            }
        }
    }

    fn send_publish_responses(
        &mut self,
        now: &DateTimeUtc,
        responses: Vec<PendingPublishResponse>,
        more_notifications: bool,
    ) {
        let num_responses = responses.len();
        for (idx, (publish_request, notification, subscription_id)) in
            responses.into_iter().enumerate()
        {
            let is_last = idx == num_responses - 1;
            let max_retransmission_queue_len = self.max_publish_requests() * 2;

            Self::enqueue_retransmission_notification(
                &mut self.retransmission_queue,
                &mut self.data_change_notification_pool,
                max_retransmission_queue_len,
                subscription_id,
                Arc::clone(&notification),
            );

            // Take note of the available sequence numbers after we have added the NonAckedPublish
            // to the list. This makes sure that the available sequence numbers list is not empty and contains
            // the NonAckedPublish we just added.
            let available_sequence_numbers = self.available_sequence_numbers(subscription_id);
            let _ = publish_request.response.send(
                PublishResponseShared {
                    response_header: ResponseHeader::new_timestamped_service_result(
                        DateTime::from(*now),
                        &publish_request.request.request_header,
                        StatusCode::Good,
                    ),
                    subscription_id,
                    available_sequence_numbers,
                    // Only set more_notifications on the last publish response.
                    more_notifications: is_last && more_notifications,
                    notification_message: Arc::clone(&notification),
                    results: publish_request.ack_results,
                    diagnostic_infos: None,
                }
                .into(),
            );
        }
    }

    fn find_notification_message(
        &self,
        subscription_id: u32,
        sequence_number: u32,
    ) -> Result<Arc<NotificationMessage>, StatusCode> {
        if !self.subscriptions.contains_key(&subscription_id) {
            return Err(StatusCode::BadSubscriptionIdInvalid);
        }
        let Some(notification) = self
            .retransmission_queue
            .get_message(subscription_id, sequence_number)
        else {
            return Err(StatusCode::BadMessageNotAvailable);
        };
        Ok(notification)
    }

    fn remove_expired_publish_requests(&mut self, now: Instant) {
        let queue = std::mem::take(&mut self.publish_request_queue);
        let mut kept = VecDeque::with_capacity(queue.len());
        for req in queue {
            if req.deadline < now {
                let _ = req.response.send(
                    ServiceFault::new(&req.request.request_header, StatusCode::BadTimeout).into(),
                );
            } else {
                kept.push_back(req);
            }
        }
        self.publish_request_queue = kept;
    }

    fn process_subscription_acks(&mut self, request: &PublishRequest) -> Option<Vec<StatusCode>> {
        let acks = request.subscription_acknowledgements.as_ref()?;
        if acks.is_empty() {
            return None;
        }

        Some(
            acks.iter()
                .map(|ack| {
                    if !self.subscriptions.contains_key(&ack.subscription_id) {
                        StatusCode::BadSubscriptionIdInvalid
                    } else if let Some(notification) = self
                        .retransmission_queue
                        .ack(ack.subscription_id, ack.sequence_number)
                    {
                        Self::reclaim_non_acked_publish(
                            &mut self.data_change_notification_pool,
                            notification,
                        );
                        StatusCode::Good
                    } else {
                        StatusCode::BadSequenceNumberUnknown
                    }
                })
                .collect(),
        )
    }

    /// Returns the array of available sequence numbers in the retransmission queue for the specified subscription
    pub(super) fn available_sequence_numbers(&self, subscription_id: u32) -> Option<Vec<u32>> {
        self.retransmission_queue
            .available_sequence_numbers(subscription_id)
    }

    pub(super) fn drain_ring_chunk(
        &mut self,
        ring: &ArrayQueue<NotificationWorkItem>,
        type_tree: &dyn TypeTree,
        event_chunk: usize,
        pending_refresh: &mut Option<PendingRefreshDrain>,
    ) -> usize {
        let mut processed = 0;
        let now = DateTime::now();
        while processed < event_chunk {
            if pending_refresh.is_some() {
                processed +=
                    self.drain_pending_refresh(type_tree, event_chunk - processed, pending_refresh);
                break;
            }

            let Some(item) = ring.pop() else {
                break;
            };

            match item {
                NotificationWorkItem::Data { handle, value } => {
                    let Some(sub) = self.subscriptions.get_mut(&handle.subscription_id) else {
                        processed += 1;
                        continue;
                    };
                    sub.notify_data_value(&handle.monitored_item_id, value, &now);
                }
                NotificationWorkItem::Event { handle, event } => {
                    if !self.event_receive_allowed(&*event) {
                        processed += 1;
                        continue;
                    }
                    let Some(sub) = self.subscriptions.get_mut(&handle.subscription_id) else {
                        processed += 1;
                        continue;
                    };
                    sub.notify_event(&handle.monitored_item_id, &*event, type_tree);
                }
                NotificationWorkItem::Refresh {
                    subscription_id,
                    monitored_item,
                    events,
                } => {
                    *pending_refresh = Some(PendingRefreshDrain::new(
                        subscription_id,
                        monitored_item,
                        events,
                    ));
                    processed += self.drain_pending_refresh(
                        type_tree,
                        event_chunk - processed,
                        pending_refresh,
                    );
                    continue;
                }
            }

            processed += 1;
        }

        processed
    }

    fn drain_pending_refresh(
        &mut self,
        type_tree: &dyn TypeTree,
        event_limit: usize,
        pending_refresh: &mut Option<PendingRefreshDrain>,
    ) -> usize {
        let Some(refresh) = pending_refresh.as_mut() else {
            return 0;
        };

        let deliver_count = refresh.remaining().min(event_limit);
        if deliver_count == 0 {
            return 0;
        }

        let start = refresh.next_event;
        let end = start + deliver_count;
        let events = refresh.events[start..end]
            .iter()
            .filter_map(|event| {
                let event = event.as_ref() as &dyn Event;
                self.event_receive_allowed(event).then_some(event)
            })
            .collect::<Vec<_>>();
        if let Some(sub) = self.subscriptions.get_mut(&refresh.subscription_id) {
            if !events.is_empty() {
                let _ = sub.refresh_events(refresh.monitored_item, &events, type_tree);
            }
        }
        refresh.next_event = end;

        deliver_count
    }

    fn event_receive_allowed(&self, event: &dyn Event) -> bool {
        let Some(source_node_id) = event_source_node(event) else {
            return true;
        };

        let source_role_permissions = self.source_role_permissions(&source_node_id);
        let user_roles = self.session.read().roles();

        rbac::decision::event_receive_allowed_with_enforcement(
            &user_roles,
            source_role_permissions.as_deref(),
            self.enforce_role_based_access,
        )
    }

    fn source_role_permissions(&self, source_node_id: &NodeId) -> Option<Vec<RolePermissionType>> {
        self.node_managers
            .iter()
            .find(|manager| manager.owns_node(source_node_id))
            .and_then(|manager| manager.role_permissions(source_node_id))
    }

    pub(super) fn user_token(&self) -> &PersistentSessionKey {
        &self.user_token
    }

    pub(super) fn type_tree_for_user(&self) -> Arc<dyn TypeTreeForUserStatic> {
        Arc::clone(&self.type_tree_for_user)
    }

    pub(super) fn get_monitored_item_count(&self, subscription_id: u32) -> Option<usize> {
        self.subscriptions.get(&subscription_id).map(|s| s.len())
    }

    /// Get a reference to the session this subscription collection is owned by.
    pub fn session(&self) -> &Arc<RwLock<Session>> {
        &self.session
    }
}

fn event_source_node(event: &dyn Event) -> Option<NodeId> {
    let source = event.get_field(
        &NodeId::from(ObjectTypeId::BaseEventType),
        AttributeId::Value,
        &opcua_types::NumericRange::None,
        &[QualifiedName::new(0, "SourceNode")],
    );

    match source {
        Variant::NodeId(source_node_id) if !source_node_id.is_null() => Some(*source_node_id),
        Variant::ExpandedNodeId(source_node_id)
            if source_node_id.server_index == 0 && !source_node_id.node_id.is_null() =>
        {
            Some(source_node_id.node_id)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashSet, VecDeque},
        sync::Arc,
        time::{Duration, Instant},
    };

    use chrono::Utc;
    use hashbrown::HashMap;
    use opcua_core::{sync::RwLock, ResponseMessage};
    use opcua_crypto::SecurityPolicy;
    use opcua_types::{
        ApplicationDescription, ByteString, DataValue, DateTime, MessageSecurityMode,
        MonitoredItemNotification, NodeId, NotificationMessage, PublishRequest, RequestHeader,
        StatusCode, SubscriptionAcknowledgement, UAString,
    };

    use super::super::pool::NotificationBuffer;
    use super::super::retransmission_queue::RetransmissionQueue;
    use super::super::subscription::TickReason;
    use super::super::{PendingPublish, PersistentSessionKey, Subscription};
    use super::{DataChangeNotificationVecPool, SessionSubscriptions};
    use crate::{
        authenticator::UserToken,
        identity_token::{IdentityToken, POLICY_ID_ANONYMOUS},
        node_manager::NodeManagersRef,
        session::instance::Session,
        ServerBuilder,
    };

    fn data_change_msg(seq: u32) -> Arc<NotificationMessage> {
        Arc::new(NotificationMessage::data_change(
            seq,
            DateTime::now(),
            vec![MonitoredItemNotification {
                client_handle: seq,
                value: DataValue::new_now(seq as i32),
            }],
            Vec::new(),
        ))
    }

    fn pending_publish(
        request_handle: u32,
        deadline: Instant,
    ) -> (
        PendingPublish,
        tokio::sync::oneshot::Receiver<ResponseMessage>,
    ) {
        let (response, recv) = tokio::sync::oneshot::channel();
        let request = PublishRequest {
            request_header: RequestHeader {
                request_handle,
                ..Default::default()
            },
            subscription_acknowledgements: None,
        };

        (
            PendingPublish {
                response,
                request: Box::new(request),
                ack_results: None,
                deadline,
            },
            recv,
        )
    }

    async fn assert_publish_response(
        recv: tokio::sync::oneshot::Receiver<ResponseMessage>,
        request_handle: u32,
        status: StatusCode,
    ) {
        let response = recv.await.expect("publish response should be sent");
        let header = response.response_header();
        assert_eq!(header.request_handle, request_handle);
        assert_eq!(header.service_result, status);
    }

    fn test_session_subscriptions(subscription_id: u32) -> SessionSubscriptions {
        let (_server, handle) = ServerBuilder::new_anonymous("session subscriptions unit test")
            .without_node_managers()
            .build()
            .expect("test server should build");
        let info = handle.info();
        let user_token = UserToken(POLICY_ID_ANONYMOUS.to_string());
        let session = Session::create(
            info,
            NodeId::new(1, "session-subscriptions-test-token"),
            1,
            60_000,
            0,
            0,
            UAString::from(info.base_endpoint()),
            SecurityPolicy::None.to_uri().to_string(),
            IdentityToken::None,
            None,
            ByteString::null(),
            UAString::from("session-subscriptions-unit-test"),
            ApplicationDescription::default(),
            MessageSecurityMode::None,
        );

        let mut subscriptions = HashMap::new();
        subscriptions.insert(
            subscription_id,
            Subscription::new(
                subscription_id,
                true,
                Duration::from_millis(100),
                100,
                20,
                0,
                20,
                1000,
            ),
        );

        SessionSubscriptions {
            user_token: PersistentSessionKey::new(
                &user_token,
                MessageSecurityMode::None,
                "session-subscriptions-unit-test",
            ),
            subscriptions,
            publish_request_queue: VecDeque::new(),
            pending_status_changes: VecDeque::new(),
            transferring: HashSet::new(),
            retransmission_queue: RetransmissionQueue::new(),
            data_change_notification_pool: DataChangeNotificationVecPool::default(),
            limits: info.config.limits.subscriptions,
            session: Arc::new(RwLock::new(session)),
            type_tree_for_user: info.type_tree.clone(),
            node_managers: NodeManagersRef::new_empty(),
            enforce_role_based_access: false,
        }
    }

    #[test]
    fn keep_alive_messages_are_not_queued_for_retransmission() {
        let mut retransmission_queue = RetransmissionQueue::new();
        let mut data_change_notification_pool = DataChangeNotificationVecPool::default();

        SessionSubscriptions::enqueue_retransmission_notification(
            &mut retransmission_queue,
            &mut data_change_notification_pool,
            2,
            1,
            Arc::new(NotificationMessage::keep_alive(7, DateTime::now())),
        );

        assert!(retransmission_queue.is_empty());
    }

    #[test]
    fn status_change_messages_are_queued_for_retransmission() {
        let mut retransmission_queue = RetransmissionQueue::new();
        let mut data_change_notification_pool = DataChangeNotificationVecPool::default();

        SessionSubscriptions::enqueue_retransmission_notification(
            &mut retransmission_queue,
            &mut data_change_notification_pool,
            2,
            1,
            Arc::new(NotificationMessage::status_change(
                7,
                DateTime::now(),
                StatusCode::BadTimeout,
            )),
        );

        assert_eq!(retransmission_queue.len(), 1);
        assert_eq!(
            retransmission_queue.available_sequence_numbers(1),
            Some(vec![7])
        );
        assert!(retransmission_queue.get_message(1, 7).is_some());
    }

    #[tokio::test]
    async fn publish_queue_overflow_rejects_oldest_and_preserves_newer_requests() {
        // Feature 029 T008, grounded in Part 4 §5.14.5.1/§5.14.5.3: when the
        // queued Publish request limit is exceeded, the oldest Publish request is
        // de-queued with Bad_TooManyPublishRequests and later queued requests remain serviceable.
        let sub_id = 1;
        let mut subs = test_session_subscriptions(sub_id);
        subs.limits.max_pending_publish_requests = 2;
        subs.limits.max_publish_requests_per_subscription = 2;
        let now = Utc::now();
        let now_instant = Instant::now();
        let deadline = now_instant + Duration::from_secs(30);

        let (publish_1, response_1) = pending_publish(1, deadline);
        let (publish_2, response_2) = pending_publish(2, deadline);
        let (publish_3, response_3) = pending_publish(3, deadline);

        subs.enqueue_publish_request(&now, now_instant, publish_1);
        subs.enqueue_publish_request(&now, now_instant, publish_2);
        assert_eq!(subs.publish_request_queue.len(), 2);

        subs.enqueue_publish_request(&now, now_instant, publish_3);
        assert_publish_response(response_1, 1, StatusCode::BadTooManyPublishRequests).await;
        assert_eq!(subs.publish_request_queue.len(), 2);

        subs.queue_status_change(
            sub_id,
            1,
            DateTime::from(now),
            StatusCode::GoodSubscriptionTransferred,
        );
        subs.queue_status_change(
            sub_id,
            2,
            DateTime::from(now),
            StatusCode::GoodSubscriptionTransferred,
        );
        let mut buffer = NotificationBuffer::new();
        subs.tick(
            &now,
            now_instant,
            TickReason::ReceivePublishRequest,
            &mut buffer,
        );

        assert_publish_response(response_2, 2, StatusCode::Good).await;
        assert_publish_response(response_3, 3, StatusCode::Good).await;
        assert!(subs.publish_request_queue.is_empty());
    }

    #[tokio::test]
    async fn republish_evicted_sequence_returns_message_not_available() {
        // Feature 029 T005, grounded in Part 4 §5.14.6.3: Republish of a message no
        // longer available in the retransmission queue returns Bad_MessageNotAvailable.
        let sub_id = 1;
        let mut subs = test_session_subscriptions(sub_id);

        SessionSubscriptions::enqueue_retransmission_notification(
            &mut subs.retransmission_queue,
            &mut subs.data_change_notification_pool,
            2,
            sub_id,
            data_change_msg(1),
        );
        SessionSubscriptions::enqueue_retransmission_notification(
            &mut subs.retransmission_queue,
            &mut subs.data_change_notification_pool,
            2,
            sub_id,
            data_change_msg(2),
        );
        SessionSubscriptions::enqueue_retransmission_notification(
            &mut subs.retransmission_queue,
            &mut subs.data_change_notification_pool,
            2,
            sub_id,
            data_change_msg(3),
        );

        assert_eq!(subs.available_sequence_numbers(sub_id), Some(vec![2, 3]));
        assert_eq!(
            subs.find_notification_message(sub_id, 1).unwrap_err(),
            StatusCode::BadMessageNotAvailable
        );
        assert_eq!(
            subs.find_notification_message(sub_id, 3)
                .expect("held sequence should be available")
                .sequence_number,
            3
        );
    }

    #[tokio::test]
    async fn publish_ack_results_follow_request_order_and_status_codes() {
        // Feature 029 T005, grounded in Part 4 §5.14.5.2/§5.14.5.4: ack result
        // order mirrors the request and distinguishes Good, unknown sequence, and invalid subscription.
        let sub_id = 1;
        let mut subs = test_session_subscriptions(sub_id);
        SessionSubscriptions::enqueue_retransmission_notification(
            &mut subs.retransmission_queue,
            &mut subs.data_change_notification_pool,
            4,
            sub_id,
            data_change_msg(10),
        );

        let request = PublishRequest {
            request_header: RequestHeader::default(),
            subscription_acknowledgements: Some(vec![
                SubscriptionAcknowledgement {
                    subscription_id: sub_id,
                    sequence_number: 10,
                },
                SubscriptionAcknowledgement {
                    subscription_id: sub_id,
                    sequence_number: 999,
                },
                SubscriptionAcknowledgement {
                    subscription_id: sub_id + 1,
                    sequence_number: 10,
                },
            ]),
        };

        assert_eq!(
            subs.process_subscription_acks(&request),
            Some(vec![
                StatusCode::Good,
                StatusCode::BadSequenceNumberUnknown,
                StatusCode::BadSubscriptionIdInvalid,
            ])
        );
        assert_eq!(
            subs.process_subscription_acks(&request),
            Some(vec![
                StatusCode::BadSequenceNumberUnknown,
                StatusCode::BadSequenceNumberUnknown,
                StatusCode::BadSubscriptionIdInvalid,
            ]),
            "the first successful ack removes the message from the retransmission queue"
        );
    }
}
