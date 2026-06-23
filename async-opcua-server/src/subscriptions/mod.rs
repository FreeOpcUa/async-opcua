mod monitored_item;
mod notify;
pub(crate) mod pool;
mod retransmission_queue;
mod session_subscriptions;
mod subscription;

use std::{hash::Hash, sync::Arc, time::Instant};

use chrono::Utc;
use hashbrown::{Equivalent, HashMap};
pub use monitored_item::{CreateMonitoredItem, MonitoredItem};
use opcua_core::{trace_read_lock, trace_write_lock, RepublishResponseShared, ResponseMessage};
use opcua_nodes::{Event, TypeTree};
use session_subscriptions::RemovedSubscription;
pub use session_subscriptions::SessionSubscriptions;
use subscription::TickReason;
pub use subscription::{MonitoredItemHandle, Subscription, SubscriptionState};
use tracing::error;

pub use notify::{
    SubscriptionDataNotifier, SubscriptionDataNotifierBatch, SubscriptionEventNotifier,
    SubscriptionEventNotifierBatch,
};

use opcua_core::sync::{Mutex, RwLock};

use opcua_types::{
    node_id::{IdentifierRef, NodeIdRef},
    AttributeId, CreateSubscriptionRequest, CreateSubscriptionResponse, DataEncoding, DataValue,
    DateTime, DateTimeUtc, MessageSecurityMode, ModifySubscriptionRequest,
    ModifySubscriptionResponse, MonitoredItemCreateResult, MonitoredItemModifyRequest,
    MonitoringMode, NodeId, NotificationMessage, NumericRange, PublishRequest, RepublishRequest,
    ResponseHeader, SetPublishingModeRequest, SetPublishingModeResponse, StatusCode,
    TimestampsToReturn, TransferResult, TransferSubscriptionsRequest,
    TransferSubscriptionsResponse,
};

use crate::node_manager::RequestContextInner;

use super::{
    authenticator::UserToken,
    info::ServerInfo,
    node_manager::{MonitoredItemRef, MonitoredItemUpdateRef, RequestContext, ServerContext},
    session::instance::Session,
    SubscriptionLimits,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MonitoredItemKey {
    id: NodeId,
    attribute_id: AttributeId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MonitoredItemKeyRef<T: IdentifierRef> {
    id: NodeIdRef<T>,
    attribute_id: AttributeId,
}

impl<T> Hash for MonitoredItemKeyRef<T>
where
    T: IdentifierRef,
{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.attribute_id.hash(state);
    }
}

impl<T: IdentifierRef> Equivalent<MonitoredItemKey> for MonitoredItemKeyRef<T> {
    fn equivalent(&self, key: &MonitoredItemKey) -> bool {
        self.id == key.id && self.attribute_id == key.attribute_id
    }
}

/// A basic description of the monitoring parameters for a monitored item, used
/// for conditional sampling.
pub struct MonitoredItemEntry {
    /// Whether the monitored item is currently active.
    pub enabled: bool,
    /// The data encoding of the monitored item.
    pub data_encoding: DataEncoding,
    /// The index range of the monitored item.
    pub index_range: NumericRange,
}

struct SubscriptionCacheInner {
    /// Map from session ID to subscription cache
    session_subscriptions: HashMap<u32, Arc<Mutex<SessionSubscriptions>>>,
    /// Map from subscription ID to session ID.
    subscription_to_session: HashMap<u32, u32>,
    /// Map from notifier node ID to monitored item handles.
    monitored_items: HashMap<MonitoredItemKey, HashMap<MonitoredItemHandle, MonitoredItemEntry>>,
}

/// Structure storing all subscriptions and monitored items on the server.
/// Used to notify users of changes.
///
/// Subscriptions can outlive sessions, and sessions can outlive connections,
/// so neither can be owned by the connection. This provides convenient methods for
/// manipulating subscriptions.
pub struct SubscriptionCache {
    inner: RwLock<SubscriptionCacheInner>,
    /// Configured limits on subscriptions.
    limits: SubscriptionLimits,
}

impl SubscriptionCache {
    pub(crate) fn new(limits: SubscriptionLimits) -> Self {
        Self {
            inner: RwLock::new(SubscriptionCacheInner {
                session_subscriptions: HashMap::new(),
                subscription_to_session: HashMap::new(),
                monitored_items: HashMap::new(),
            }),
            limits,
        }
    }

    /// Get the `SessionSubscriptions` object for a single session by its numeric ID.
    pub fn get_session_subscriptions(
        &self,
        session_id: u32,
    ) -> Option<Arc<Mutex<SessionSubscriptions>>> {
        let inner = trace_read_lock!(self.inner);
        inner.session_subscriptions.get(&session_id).cloned()
    }

    pub(crate) fn update_session_user(&self, session_id: u32, context: &RequestContext) {
        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions.get(&session_id).cloned()
        }) else {
            return;
        };

        let key = Self::get_key(&context.session);
        let type_tree_for_user = context.info.type_tree_getter.get_type_tree_static(context);
        cache.lock().update_owner(key, type_tree_for_user);
    }

    pub(crate) fn get_session_monitored_items(&self, session_id: u32) -> Vec<MonitoredItemRef> {
        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions.get(&session_id).cloned()
        }) else {
            return Vec::new();
        };

        let cache_lck = cache.lock();
        cache_lck.monitored_item_refs()
    }

    pub(crate) fn apply_revalidated_values(
        &self,
        session_id: u32,
        values: Vec<(MonitoredItemRef, DataValue)>,
    ) {
        if values.is_empty() {
            return;
        }

        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions.get(&session_id).cloned()
        }) else {
            return;
        };

        cache.lock().apply_revalidated_values(values);
    }

    pub(crate) fn delete_monitored_item_refs(
        &self,
        session_id: u32,
        items: &[MonitoredItemRef],
    ) -> Result<Vec<(StatusCode, MonitoredItemRef)>, StatusCode> {
        let mut ids_by_subscription: HashMap<u32, Vec<u32>> = HashMap::new();
        for item in items {
            let handle = item.handle();
            ids_by_subscription
                .entry(handle.subscription_id)
                .or_default()
                .push(handle.monitored_item_id);
        }

        let mut lck = trace_write_lock!(self.inner);
        let Some(cache) = lck.session_subscriptions.get(&session_id).cloned() else {
            return Err(StatusCode::BadNoSubscription);
        };

        let mut cache_lck = cache.lock();
        let mut results = Vec::with_capacity(items.len());
        for (subscription_id, item_ids) in ids_by_subscription {
            let deleted = cache_lck.delete_monitored_items(subscription_id, &item_ids)?;
            for (status, rf) in &deleted {
                if status.is_good() {
                    let key = MonitoredItemKeyRef {
                        id: rf.node_id().into(),
                        attribute_id: rf.attribute(),
                    };
                    if let Some(it) = lck.monitored_items.get_mut(&key) {
                        it.remove(&rf.handle());
                    }
                }
            }
            results.extend(deleted);
        }

        Ok(results)
    }

    /// This is the periodic subscription tick where we check for
    /// triggered subscriptions.
    ///
    pub(crate) async fn periodic_tick(&self, context: &ServerContext) {
        // TODO: Look into replacing this with a smarter system, in theory it should be possible to
        // always just sleep for the exact time until the next expired publish request, which could
        // be more efficient, and would be more responsive.
        let mut to_delete = Vec::new();
        let mut expired_subscriptions = Vec::new();
        {
            let now = Utc::now();
            let now_instant = Instant::now();
            let mut buffer = pool::NotificationBuffer::new();
            let session_subscriptions = {
                let lck = trace_read_lock!(self.inner);
                lck.session_subscriptions
                    .iter()
                    .map(|(session_id, sub)| (*session_id, Arc::clone(sub)))
                    .collect::<Vec<_>>()
            };
            for (session_id, sub) in session_subscriptions {
                let mut sub_lck = sub.lock();
                let removed_subscriptions =
                    sub_lck.tick(&now, now_instant, TickReason::TickTimerFired, &mut buffer);
                if !removed_subscriptions.is_empty() {
                    expired_subscriptions.push((sub_lck.session().clone(), removed_subscriptions));
                }
                if sub_lck.is_ready_to_delete() {
                    to_delete.push(session_id);
                }
            }
        }
        if !to_delete.is_empty() || !expired_subscriptions.is_empty() {
            let mut lck = trace_write_lock!(self.inner);
            for (_, removed_subscriptions) in &expired_subscriptions {
                Self::cleanup_removed_subscriptions(&mut lck, removed_subscriptions);
            }
            for id in to_delete {
                lck.session_subscriptions.remove(&id);
            }
            context
                .info
                .diagnostics
                .set_current_subscription_count(lck.subscription_to_session.len() as u32);
        }
        if !expired_subscriptions.is_empty() {
            Self::delete_expired_monitored_items(context, expired_subscriptions).await;
        }
    }

    async fn delete_expired_monitored_items(
        context: &ServerContext,
        expired_subscriptions: Vec<(Arc<RwLock<Session>>, Vec<RemovedSubscription>)>,
    ) {
        for (session, removed_subscriptions) in expired_subscriptions {
            // Create a local request context, since we need to call delete monitored items.

            let (id, token) = {
                let lck = session.read();
                let Some(token) = lck.user_token() else {
                    error!("Active session missing user token, this should be impossible");
                    continue;
                };

                (lck.session_id_numeric(), token.clone())
            };
            let ctx = RequestContext {
                current_node_manager_index: 0,
                inner: Arc::new(RequestContextInner {
                    session,
                    session_id: id,
                    authenticator: context.authenticator.clone(),
                    token,
                    type_tree: context.type_tree.clone(),
                    subscriptions: context.subscriptions.clone(),
                    info: context.info.clone(),
                    type_tree_getter: context.type_tree_getter.clone(),
                }),
            };

            for mgr in context.node_managers.iter() {
                let owned: Vec<&MonitoredItemRef> = removed_subscriptions
                    .iter()
                    .flat_map(|removed| removed.monitored_items.iter())
                    .filter(|n| mgr.owns_node(n.node_id()))
                    .collect();

                if owned.is_empty() {
                    continue;
                }

                mgr.delete_monitored_items(&ctx, &owned).await;
            }
        }
    }

    fn cleanup_removed_subscriptions(
        inner: &mut SubscriptionCacheInner,
        removed_subscriptions: &[RemovedSubscription],
    ) {
        for removed in removed_subscriptions {
            inner.subscription_to_session.remove(&removed.id);
            Self::cleanup_monitored_item_refs(inner, &removed.monitored_items);
        }
    }

    fn cleanup_monitored_item_refs(inner: &mut SubscriptionCacheInner, items: &[MonitoredItemRef]) {
        for item in items {
            let key = MonitoredItemKeyRef {
                id: item.node_id().into(),
                attribute_id: item.attribute(),
            };
            let remove_key = if let Some(handles) = inner.monitored_items.get_mut(&key) {
                handles.remove(&item.handle());
                handles.is_empty()
            } else {
                false
            };
            if remove_key {
                inner.monitored_items.remove(&key);
            }
        }
    }

    pub(crate) fn get_monitored_item_count(
        &self,
        session_id: u32,
        subscription_id: u32,
    ) -> Option<usize> {
        let cache = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions.get(&session_id).cloned()
        })?;
        let cache_lck = cache.lock();
        cache_lck.get_monitored_item_count(subscription_id)
    }

    pub(crate) fn create_subscription(
        &self,
        session_id: u32,
        request: &CreateSubscriptionRequest,
        context: &RequestContext,
    ) -> Result<CreateSubscriptionResponse, StatusCode> {
        let mut lck = trace_write_lock!(self.inner);
        let cache = lck
            .session_subscriptions
            .entry(session_id)
            .or_insert_with(|| {
                Arc::new(Mutex::new(SessionSubscriptions::new(
                    self.limits,
                    Self::get_key(&context.session),
                    context.session.clone(),
                    context.info.type_tree_getter.get_type_tree_static(context),
                )))
            })
            .clone();
        let mut cache_lck = cache.lock();
        let res = cache_lck.create_subscription(request, &context.info)?;
        lck.subscription_to_session
            .insert(res.subscription_id, session_id);
        context
            .info
            .diagnostics
            .set_current_subscription_count(lck.subscription_to_session.len() as u32);
        context.info.diagnostics.inc_subscription_count();
        Ok(res)
    }

    pub(crate) fn modify_subscription(
        &self,
        session_id: u32,
        request: &ModifySubscriptionRequest,
        info: &ServerInfo,
    ) -> Result<ModifySubscriptionResponse, StatusCode> {
        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions.get(&session_id).cloned()
        }) else {
            return Err(StatusCode::BadNoSubscription);
        };
        let mut cache_lck = cache.lock();
        cache_lck.modify_subscription(request, info)
    }

    pub(crate) fn set_publishing_mode(
        &self,
        session_id: u32,
        request: &SetPublishingModeRequest,
    ) -> Result<SetPublishingModeResponse, StatusCode> {
        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions.get(&session_id).cloned()
        }) else {
            return Err(StatusCode::BadNoSubscription);
        };
        let mut cache_lck = cache.lock();
        cache_lck.set_publishing_mode(request)
    }

    pub(crate) fn republish(
        &self,
        session_id: u32,
        request: &RepublishRequest,
    ) -> Result<RepublishResponseShared, StatusCode> {
        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions.get(&session_id).cloned()
        }) else {
            return Err(StatusCode::BadNoSubscription);
        };
        let mut cache_lck = cache.lock();
        cache_lck.republish(request)
    }

    pub(crate) fn enqueue_publish_request(
        &self,
        session_id: u32,
        now: &DateTimeUtc,
        now_instant: Instant,
        request: PendingPublish,
    ) -> Result<(), StatusCode> {
        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions.get(&session_id).cloned()
        }) else {
            return Err(StatusCode::BadNoSubscription);
        };

        let mut cache_lck = cache.lock();
        cache_lck.enqueue_publish_request(now, now_instant, request);
        Ok(())
    }

    /// Return a notifier for notifying the server of a batch of changes.
    ///
    /// Note: This contains a lock, and should _not_ be kept around for long periods of time,
    /// or held over await points.
    ///
    /// The notifier submits notifications only once dropped.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut notifier = cache.data_notifier();
    /// for (node_id, data_value) in my_changes {
    ///     notifier.notify(node_id, AttributeId::Value, value);
    /// }
    /// ```
    pub fn data_notifier(&self) -> SubscriptionDataNotifier<'_> {
        SubscriptionDataNotifier::new(trace_read_lock!(self.inner))
    }

    /// Return a notifier for notifying the server of a batch of events.
    ///
    /// Note: This contains a lock, and should _not_ be kept around for long periods of time,
    /// or held over await points.
    ///
    /// The notifier submits notifications only once dropped.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut notifier = cache.event_notifier();
    /// for evt in my_evts {
    ///     notifier.notify(emitter_id, evt);
    /// }
    /// ```
    pub fn event_notifier<'b>(&self) -> SubscriptionEventNotifier<'_, 'b> {
        SubscriptionEventNotifier::new(trace_read_lock!(self.inner))
    }

    /// Notify any listening clients about a list of data changes.
    /// This can be called any time anything changes on the server, or only for values with
    /// an existing monitored item. Either way this method will deal with distributing the values
    /// to the appropriate monitored items.
    pub fn notify_data_change<'a>(
        &self,
        items: impl Iterator<Item = (DataValue, &'a NodeId, AttributeId)>,
    ) {
        let mut notif = self.data_notifier();
        for (dv, node_id, attribute_id) in items {
            notif.notify(node_id, attribute_id, dv);
        }
    }

    /// Notify with a dynamic sampler, to avoid getting values for nodes that
    /// may not have monitored items.
    /// This is potentially much more efficient than simply notifying blindly, but is
    /// also somewhat harder to use.
    pub fn maybe_notify<'a>(
        &self,
        items: impl Iterator<Item = (&'a NodeId, AttributeId)>,
        sample: impl Fn(&NodeId, AttributeId, &NumericRange, &DataEncoding) -> Option<DataValue>,
    ) {
        let mut notif = self.data_notifier();
        for (id, attribute_id) in items {
            if let Some(mut batch) = notif.notify_for(id, attribute_id) {
                for (handle, entry) in batch.entries() {
                    if let Some(value) =
                        sample(id, attribute_id, &entry.index_range, &entry.data_encoding)
                    {
                        batch.data_value_to_item(value, handle);
                    }
                }
            }
        }
    }

    /// Notify listening clients to events. Without a custom node manager implementing
    /// event history, this is the only way to report events in the server.
    pub fn notify_events<'a>(&self, items: impl Iterator<Item = (&'a dyn Event, &'a NodeId)>) {
        let mut notif = self.event_notifier();
        for (evt, id) in items {
            notif.notify(id, evt);
        }
    }

    pub(crate) fn create_monitored_items(
        &self,
        session_id: u32,
        subscription_id: u32,
        requests: &[CreateMonitoredItem],
    ) -> Result<Vec<MonitoredItemCreateResult>, StatusCode> {
        let mut lck = trace_write_lock!(self.inner);
        let Some(cache) = lck.session_subscriptions.get(&session_id).cloned() else {
            return Err(StatusCode::BadNoSubscription);
        };

        let mut cache_lck = cache.lock();
        let result = cache_lck.create_monitored_items(subscription_id, requests);
        if let Ok(res) = &result {
            for (create, res) in requests.iter().zip(res.iter()) {
                if res.status_code.is_good() {
                    let key = MonitoredItemKey {
                        id: create.item_to_monitor().node_id.clone(),
                        attribute_id: create.item_to_monitor().attribute_id,
                    };

                    let index_range = create.item_to_monitor().index_range.clone();

                    lck.monitored_items.entry(key).or_default().insert(
                        create.handle(),
                        MonitoredItemEntry {
                            enabled: !matches!(create.monitoring_mode(), MonitoringMode::Disabled),
                            index_range,
                            data_encoding: create.item_to_monitor().data_encoding.clone(),
                        },
                    );
                }
            }
        }

        result
    }

    pub(crate) fn modify_monitored_items(
        &self,
        session_id: u32,
        subscription_id: u32,
        info: &ServerInfo,
        timestamps_to_return: TimestampsToReturn,
        requests: Vec<MonitoredItemModifyRequest>,
        type_tree: &dyn TypeTree,
    ) -> Result<Vec<MonitoredItemUpdateRef>, StatusCode> {
        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions.get(&session_id).cloned()
        }) else {
            return Err(StatusCode::BadNoSubscription);
        };

        let mut cache_lck = cache.lock();
        cache_lck.modify_monitored_items(
            subscription_id,
            info,
            timestamps_to_return,
            requests,
            type_tree,
        )
    }

    fn get_key(session: &RwLock<Session>) -> PersistentSessionKey {
        let lck = trace_read_lock!(session);
        PersistentSessionKey::new(
            lck.user_token().unwrap(),
            lck.message_security_mode(),
            lck.application_description().application_uri.as_ref(),
        )
    }

    pub(crate) fn set_monitoring_mode(
        &self,
        session_id: u32,
        subscription_id: u32,
        monitoring_mode: MonitoringMode,
        items: Vec<u32>,
    ) -> Result<Vec<(StatusCode, MonitoredItemRef)>, StatusCode> {
        let mut lck = trace_write_lock!(self.inner);
        let Some(cache) = lck.session_subscriptions.get(&session_id).cloned() else {
            return Err(StatusCode::BadNoSubscription);
        };

        let mut cache_lck = cache.lock();
        let result = cache_lck.set_monitoring_mode(subscription_id, monitoring_mode, items);

        if let Ok(res) = &result {
            for (status, rf) in res {
                if status.is_good() {
                    let key = MonitoredItemKeyRef {
                        id: rf.node_id().into(),
                        attribute_id: rf.attribute(),
                    };
                    if let Some(it) = lck
                        .monitored_items
                        .get_mut(&key)
                        .and_then(|it| it.get_mut(&rf.handle()))
                    {
                        it.enabled = !matches!(monitoring_mode, MonitoringMode::Disabled);
                    }
                }
            }
        }
        result
    }

    pub(crate) fn set_triggering(
        &self,
        session_id: u32,
        subscription_id: u32,
        triggering_item_id: u32,
        links_to_add: Vec<u32>,
        links_to_remove: Vec<u32>,
    ) -> Result<(Vec<StatusCode>, Vec<StatusCode>), StatusCode> {
        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions.get(&session_id).cloned()
        }) else {
            return Err(StatusCode::BadNoSubscription);
        };

        let mut cache_lck = cache.lock();
        cache_lck.set_triggering(
            subscription_id,
            triggering_item_id,
            links_to_add,
            links_to_remove,
        )
    }

    pub(crate) fn delete_monitored_items(
        &self,
        session_id: u32,
        subscription_id: u32,
        items: &[u32],
    ) -> Result<Vec<(StatusCode, MonitoredItemRef)>, StatusCode> {
        let mut lck = trace_write_lock!(self.inner);
        let Some(cache) = lck.session_subscriptions.get(&session_id).cloned() else {
            return Err(StatusCode::BadNoSubscription);
        };

        let mut cache_lck = cache.lock();
        let result = cache_lck.delete_monitored_items(subscription_id, items);
        if let Ok(res) = &result {
            for (status, rf) in res {
                if status.is_good() {
                    let key = MonitoredItemKeyRef {
                        id: rf.node_id().into(),
                        attribute_id: rf.attribute(),
                    };
                    if let Some(it) = lck.monitored_items.get_mut(&key) {
                        it.remove(&rf.handle());
                    }
                }
            }
        }
        result
    }

    pub(crate) fn delete_subscriptions(
        &self,
        session_id: u32,
        ids: &[u32],
        info: &ServerInfo,
    ) -> Result<Vec<(StatusCode, Vec<MonitoredItemRef>)>, StatusCode> {
        let mut lck = trace_write_lock!(self.inner);
        let Some(cache) = lck.session_subscriptions.get(&session_id).cloned() else {
            return Err(StatusCode::BadNoSubscription);
        };
        let mut cache_lck = cache.lock();
        let result = cache_lck.delete_subscriptions(ids);
        let removed_subscriptions = result
            .iter()
            .zip(ids.iter())
            .filter(|((status, _), _)| status.is_good())
            .map(|((_, monitored_items), id)| RemovedSubscription {
                id: *id,
                monitored_items: monitored_items.clone(),
            })
            .collect::<Vec<_>>();
        Self::cleanup_removed_subscriptions(&mut lck, &removed_subscriptions);
        info.diagnostics
            .set_current_subscription_count(lck.subscription_to_session.len() as u32);

        Ok(result)
    }

    pub(crate) fn get_session_subscription_ids(&self, session_id: u32) -> Vec<u32> {
        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions.get(&session_id).cloned()
        }) else {
            return Vec::new();
        };

        let cache_lck = cache.lock();
        cache_lck.subscription_ids()
    }

    #[cfg(test)]
    fn reverse_index_size_for_test(&self) -> usize {
        let lck = trace_read_lock!(self.inner);
        lck.monitored_items.values().map(|items| items.len()).sum()
    }

    #[cfg(test)]
    fn subscription_to_session_size_for_test(&self) -> usize {
        let lck = trace_read_lock!(self.inner);
        lck.subscription_to_session.len()
    }

    pub(crate) fn transfer(
        &self,
        req: &TransferSubscriptionsRequest,
        context: &RequestContext,
    ) -> TransferSubscriptionsResponse {
        let mut results: Vec<_> = req
            .subscription_ids
            .iter()
            .flatten()
            .map(|id| {
                (
                    *id,
                    TransferResult {
                        status_code: StatusCode::BadSubscriptionIdInvalid,
                        available_sequence_numbers: None,
                    },
                )
            })
            .collect();

        let key = Self::get_key(&context.session);
        {
            let mut lck = trace_write_lock!(self.inner);
            let session_subs = lck
                .session_subscriptions
                .entry(context.session_id)
                .or_insert_with(|| {
                    Arc::new(Mutex::new(SessionSubscriptions::new(
                        self.limits,
                        key.clone(),
                        context.session.clone(),
                        context.info.type_tree_getter.get_type_tree_static(context),
                    )))
                })
                .clone();
            let mut session_subs_lck = session_subs.lock();

            for (sub_id, res) in &mut results {
                let Some(current_owner_session_id) = lck.subscription_to_session.get(sub_id) else {
                    continue;
                };
                if context.session_id == *current_owner_session_id {
                    res.status_code = StatusCode::Good;
                    res.available_sequence_numbers =
                        session_subs_lck.available_sequence_numbers(*sub_id);
                    continue;
                }

                let Some(session_cache) = lck
                    .session_subscriptions
                    .get(current_owner_session_id)
                    .cloned()
                else {
                    // Should be impossible.
                    continue;
                };

                let mut session_lck = session_cache.lock();

                if !session_lck.user_token().is_equivalent_for_transfer(&key) {
                    res.status_code = StatusCode::BadUserAccessDenied;
                    continue;
                }

                if let (Some(sub), notifs) = session_lck.remove(*sub_id) {
                    tracing::debug!(
                        "Transfer subscription {} to session {}",
                        sub.id(),
                        context.session_id
                    );
                    res.status_code = StatusCode::Good;
                    res.available_sequence_numbers =
                        Some(notifs.iter().map(|n| n.message.sequence_number).collect());

                    // Capture the next sequence number before the subscription moves out, to
                    // label the final status-change delivered to the old session.
                    let next_seq = sub.peek_next_sequence_number();

                    if let Err((e, sub, notifs)) = session_subs_lck.insert(sub, notifs) {
                        res.status_code = e;
                        let _ = session_lck.insert(sub, notifs);
                    } else {
                        if req.send_initial_values {
                            if let Some(sub) = session_subs_lck.get_mut(*sub_id) {
                                sub.set_resend_data();
                            }
                        }
                        lck.subscription_to_session
                            .insert(*sub_id, context.session_id);
                        // Part 4 §5.14.7.1: the old session shall receive a
                        // Good_SubscriptionTransferred StatusChangeNotification.
                        session_lck.queue_status_change(
                            *sub_id,
                            next_seq,
                            DateTime::now(),
                            StatusCode::GoodSubscriptionTransferred,
                        );
                    }
                }
            }
        }

        TransferSubscriptionsResponse {
            response_header: ResponseHeader::new_good(&req.request_header),
            results: Some(results.into_iter().map(|r| r.1).collect()),
            diagnostic_infos: None,
        }
    }
}

pub(crate) struct PendingPublish {
    pub response: tokio::sync::oneshot::Sender<ResponseMessage>,
    pub request: Box<PublishRequest>,
    pub ack_results: Option<Vec<StatusCode>>,
    pub deadline: Instant,
}

struct NonAckedPublish {
    message: Arc<NotificationMessage>,
    subscription_id: u32,
}

#[derive(Debug, Clone)]
struct PersistentSessionKey {
    token: UserToken,
    security_mode: MessageSecurityMode,
    application_uri: String,
}

impl PersistentSessionKey {
    fn new(token: &UserToken, security_mode: MessageSecurityMode, application_uri: &str) -> Self {
        Self {
            token: token.clone(),
            security_mode,
            application_uri: application_uri.to_owned(),
        }
    }

    fn is_equivalent_for_transfer(&self, other: &PersistentSessionKey) -> bool {
        if self.token.is_anonymous() {
            other.token.is_anonymous()
                && matches!(
                    other.security_mode,
                    MessageSecurityMode::Sign | MessageSecurityMode::SignAndEncrypt
                )
                && self.application_uri == other.application_uri
        } else {
            other.token == self.token
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use opcua_core::sync::RwLock;
    use opcua_crypto::{random, SecurityPolicy};
    use opcua_types::{
        ApplicationDescription, AttributeId, BuildInfo, ByteString, CreateSubscriptionRequest,
        ExtensionObject, MessageSecurityMode, MonitoredItemCreateRequest, MonitoringMode,
        MonitoringParameters, NodeId, ReadValueId, StatusCode, TimestampsToReturn, UAString,
    };

    use crate::{
        authenticator::UserToken,
        identity_token::{IdentityToken, POLICY_ID_ANONYMOUS},
        node_manager::{RequestContext, RequestContextInner, ServerContext},
        session::instance::Session,
        ServerBuilder, ServerStatusWrapper, SubscriptionCache,
    };

    use super::CreateMonitoredItem;

    #[tokio::test]
    async fn delete_subscriptions_returns_data_change_reverse_indexes_to_baseline() {
        const CHURN_CYCLES: usize = 4;
        const ITEMS_PER_SUBSCRIPTION: usize = 3;

        let fixture = SubscriptionFixture::new();
        let baseline_monitored_items = fixture.cache.reverse_index_size_for_test();
        let baseline_subscription_to_session =
            fixture.cache.subscription_to_session_size_for_test();

        for cycle in 0..CHURN_CYCLES {
            let subscription_id = fixture
                .cache
                .create_subscription(
                    fixture.context.session_id,
                    &CreateSubscriptionRequest {
                        requested_publishing_interval: 100.0,
                        requested_lifetime_count: 30,
                        requested_max_keep_alive_count: 10,
                        publishing_enabled: true,
                        ..Default::default()
                    },
                    &fixture.context,
                )
                .expect("subscription should be created")
                .subscription_id;

            let requests = (0..ITEMS_PER_SUBSCRIPTION)
                .map(|idx| {
                    let request = MonitoredItemCreateRequest::new(
                        ReadValueId::new(
                            NodeId::new(2, format!("cycle-{cycle}-value-{idx}")),
                            AttributeId::Value,
                        ),
                        MonitoringMode::Reporting,
                        MonitoringParameters {
                            client_handle: idx as u32 + 1,
                            sampling_interval: 0.0,
                            filter: ExtensionObject::null(),
                            queue_size: 1,
                            discard_oldest: true,
                        },
                    );
                    let type_tree = fixture.info.type_tree.read();
                    let mut item = CreateMonitoredItem::new(
                        request,
                        fixture.info.monitored_item_id_handle.next(),
                        subscription_id,
                        &fixture.info,
                        TimestampsToReturn::Both,
                        &*type_tree,
                        None,
                    );
                    item.set_status(StatusCode::Good);
                    item
                })
                .collect::<Vec<_>>();

            let results = fixture
                .cache
                .create_monitored_items(fixture.context.session_id, subscription_id, &requests)
                .expect("monitored items should be created");
            assert!(results.iter().all(|r| r.status_code.is_good()));

            let delete_results = fixture
                .cache
                .delete_subscriptions(
                    fixture.context.session_id,
                    &[subscription_id],
                    &fixture.info,
                )
                .expect("subscription delete should complete");
            assert_eq!(delete_results.len(), 1);
            assert!(delete_results[0].0.is_good());
        }

        assert_eq!(
            fixture.cache.subscription_to_session_size_for_test(),
            baseline_subscription_to_session,
            "subscription_to_session should return to baseline after delete churn"
        );
        assert_eq!(
            fixture.cache.reverse_index_size_for_test(),
            baseline_monitored_items,
            "monitored_items reverse index should return to baseline after delete churn"
        );
    }

    #[tokio::test]
    async fn expired_subscriptions_return_reverse_indexes_to_baseline() {
        const ITEMS_PER_SUBSCRIPTION: usize = 3;

        let fixture = SubscriptionFixture::new();
        let baseline_monitored_items = fixture.cache.reverse_index_size_for_test();
        let baseline_subscription_to_session =
            fixture.cache.subscription_to_session_size_for_test();

        let subscription_id = fixture
            .cache
            .create_subscription(
                fixture.context.session_id,
                &CreateSubscriptionRequest {
                    requested_publishing_interval: 100.0,
                    requested_lifetime_count: 3,
                    requested_max_keep_alive_count: 1,
                    publishing_enabled: true,
                    ..Default::default()
                },
                &fixture.context,
            )
            .expect("subscription should be created")
            .subscription_id;

        let requests = (0..ITEMS_PER_SUBSCRIPTION)
            .map(|idx| {
                let request = MonitoredItemCreateRequest::new(
                    ReadValueId::new(
                        NodeId::new(2, format!("expiry-value-{idx}")),
                        AttributeId::Value,
                    ),
                    MonitoringMode::Reporting,
                    MonitoringParameters {
                        client_handle: idx as u32 + 1,
                        sampling_interval: 0.0,
                        filter: ExtensionObject::null(),
                        queue_size: 1,
                        discard_oldest: true,
                    },
                );
                let type_tree = fixture.info.type_tree.read();
                let mut item = CreateMonitoredItem::new(
                    request,
                    fixture.info.monitored_item_id_handle.next(),
                    subscription_id,
                    &fixture.info,
                    TimestampsToReturn::Both,
                    &*type_tree,
                    None,
                );
                item.set_status(StatusCode::Good);
                item
            })
            .collect::<Vec<_>>();

        let results = fixture
            .cache
            .create_monitored_items(fixture.context.session_id, subscription_id, &requests)
            .expect("monitored items should be created");
        assert!(results.iter().all(|r| r.status_code.is_good()));

        for _ in 0..6 {
            fixture.cache.periodic_tick(&fixture.server_context).await;
            tokio::time::sleep(Duration::from_millis(110)).await;
        }

        assert_eq!(
            fixture.cache.subscription_to_session_size_for_test(),
            baseline_subscription_to_session,
            "subscription_to_session should return to baseline after expiry"
        );
        assert_eq!(
            fixture.cache.reverse_index_size_for_test(),
            baseline_monitored_items,
            "monitored_items reverse index should return to baseline after expiry"
        );
    }

    struct SubscriptionFixture {
        info: Arc<crate::ServerInfo>,
        cache: Arc<SubscriptionCache>,
        context: RequestContext,
        server_context: ServerContext,
    }

    impl SubscriptionFixture {
        fn new() -> Self {
            let (_server, handle) = ServerBuilder::new_anonymous("subscription index leak test")
                .without_node_managers()
                .build()
                .expect("test server should build");
            let info = Arc::clone(handle.info());
            let cache = Arc::new(SubscriptionCache::new(info.config.limits.subscriptions));
            let session = Arc::new(RwLock::new(Session::create(
                &info,
                NodeId::new(1, "subscription-index-leak-token"),
                1,
                60_000,
                0,
                0,
                UAString::from(info.base_endpoint()),
                SecurityPolicy::None.to_uri().to_string(),
                IdentityToken::None,
                None,
                random::byte_string(info.config.session_nonce_length),
                UAString::from("subscription-index-leak-test"),
                ApplicationDescription::default(),
                MessageSecurityMode::None,
            )));
            session.write().activate(
                1,
                ByteString::null(),
                IdentityToken::None,
                None,
                UserToken(POLICY_ID_ANONYMOUS.to_string()),
                None,
            );
            let session_id = session.read().session_id_numeric();
            let context = RequestContext::new_test(Arc::new(RequestContextInner {
                session,
                session_id,
                authenticator: info.authenticator.clone(),
                token: UserToken(POLICY_ID_ANONYMOUS.to_string()),
                type_tree: info.type_tree.clone(),
                type_tree_getter: info.type_tree_getter.clone(),
                subscriptions: Arc::clone(&cache),
                info: Arc::clone(&info),
            }));
            let server_context = ServerContext {
                node_managers: handle.node_managers().as_weak(),
                subscriptions: Arc::clone(&cache),
                info: Arc::clone(&info),
                authenticator: info.authenticator.clone(),
                type_tree: info.type_tree.clone(),
                type_tree_getter: info.type_tree_getter.clone(),
                status: Arc::new(ServerStatusWrapper::new(
                    BuildInfo::default(),
                    Arc::clone(&cache),
                )),
            };

            Self {
                info,
                cache,
                context,
                server_context,
            }
        }
    }
}
