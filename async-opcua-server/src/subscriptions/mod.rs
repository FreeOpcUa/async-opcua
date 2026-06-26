mod actor;
mod monitored_item;
mod notify;
pub(crate) mod pool;
mod retransmission_queue;
mod ring;
mod session_subscriptions;
mod subscription;

use std::{hash::Hash, sync::Arc, time::Instant};

use hashbrown::{Equivalent, HashMap};
pub use monitored_item::{CreateMonitoredItem, MonitoredItem};
use opcua_core::{trace_read_lock, trace_write_lock, RepublishResponseShared, ResponseMessage};
use opcua_nodes::Event;
use ring::NotificationWorkItem;
use session_subscriptions::RemovedSubscription;
pub use session_subscriptions::SessionSubscriptions;
pub use subscription::{MonitoredItemHandle, Subscription, SubscriptionState};
use tokio::sync::mpsc;
use tracing::error;

use actor::SubscriptionActorHandle;
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
    node_manager::{
        MonitoredItemRef, MonitoredItemUpdateRef, RequestContext, ServerContext,
        TypeTreeForUserStatic,
    },
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

const NOTIFICATION_RING_CAPACITY: usize = 8192;
const RING_DRAIN_EVENT_CHUNK: usize = 128;
const RING_DRAIN_BUDGET: usize = 4096;

#[derive(Clone)]
#[allow(dead_code)]
struct SessionEntry {
    handle: SubscriptionActorHandle,
}

impl SessionEntry {
    fn new(
        session_id: u32,
        limits: SubscriptionLimits,
        key: PersistentSessionKey,
        session: Arc<RwLock<Session>>,
        type_tree: Arc<dyn TypeTreeForUserStatic>,
        cleanup_tx: mpsc::UnboundedSender<SubscriptionCleanup>,
    ) -> Self {
        let subs = SessionSubscriptions::new(limits, key, session, Arc::clone(&type_tree));
        Self {
            handle: actor::spawn(session_id, subs, type_tree, cleanup_tx),
        }
    }

    fn handle(&self) -> SubscriptionActorHandle {
        self.handle.clone()
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

pub(crate) struct SubscriptionCleanup {
    session_id: u32,
    session: Option<Arc<RwLock<Session>>>,
    removed_subscriptions: Vec<RemovedSubscription>,
    ready_to_delete: bool,
}

struct SubscriptionCacheInner {
    /// Map from session ID to subscription cache
    session_subscriptions: HashMap<u32, SessionEntry>,
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
    cleanup_tx: mpsc::UnboundedSender<SubscriptionCleanup>,
    cleanup_rx: Mutex<Option<mpsc::UnboundedReceiver<SubscriptionCleanup>>>,
}

impl SubscriptionCache {
    pub(crate) fn new(limits: SubscriptionLimits) -> Self {
        let (cleanup_tx, cleanup_rx) = mpsc::unbounded_channel();
        Self {
            inner: RwLock::new(SubscriptionCacheInner {
                session_subscriptions: HashMap::new(),
                subscription_to_session: HashMap::new(),
                monitored_items: HashMap::new(),
            }),
            limits,
            cleanup_tx,
            cleanup_rx: Mutex::new(Some(cleanup_rx)),
        }
    }

    pub(crate) fn take_cleanup_receiver(
        &self,
    ) -> Option<mpsc::UnboundedReceiver<SubscriptionCleanup>> {
        self.cleanup_rx.lock().take()
    }

    /// Get the `SessionSubscriptions` object for a single session by its numeric ID.
    #[cfg_attr(not(feature = "generated-address-space"), allow(dead_code))]
    pub(crate) fn get_session_subscriptions(
        &self,
        session_id: u32,
    ) -> Option<SubscriptionActorHandle> {
        let inner = trace_read_lock!(self.inner);
        inner
            .session_subscriptions
            .get(&session_id)
            .map(SessionEntry::handle)
    }

    /// Run `f` against the owned `SessionSubscriptions` for `session_id` inside its actor and return
    /// the result. Returns `None` if there is no such session. Primarily for tests/introspection.
    pub async fn with_session_subscriptions<R: Send + 'static>(
        &self,
        session_id: u32,
        f: impl FnOnce(&SessionSubscriptions) -> R + Send + 'static,
    ) -> Option<R> {
        let cache = {
            let inner = trace_read_lock!(self.inner);
            inner
                .session_subscriptions
                .get(&session_id)
                .map(SessionEntry::handle)
        }?;

        cache.legacy(move |subs| f(subs)).await.ok()
    }

    #[allow(dead_code)]
    pub(crate) fn push_work(&self, session_id: u32, item: NotificationWorkItem) {
        let inner = trace_read_lock!(self.inner);
        let Some(entry) = inner.session_subscriptions.get(&session_id) else {
            return;
        };

        entry.handle.push_notification(item);
    }

    pub(crate) async fn update_session_user(&self, session_id: u32, context: &RequestContext) {
        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions
                .get(&session_id)
                .map(SessionEntry::handle)
        }) else {
            return;
        };

        let key = Self::get_key(&context.session);
        let type_tree_for_user = context.info.type_tree_getter.get_type_tree_static(context);
        let _ = cache
            .legacy(move |subs| subs.update_owner(key, type_tree_for_user))
            .await;
    }

    pub(crate) async fn get_session_monitored_items(
        &self,
        session_id: u32,
    ) -> Vec<MonitoredItemRef> {
        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions
                .get(&session_id)
                .map(SessionEntry::handle)
        }) else {
            return Vec::new();
        };

        cache
            .legacy(|subs| subs.monitored_item_refs())
            .await
            .unwrap_or_default()
    }

    pub(crate) async fn apply_revalidated_values(
        &self,
        session_id: u32,
        values: Vec<(MonitoredItemRef, DataValue)>,
    ) {
        if values.is_empty() {
            return;
        }

        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions
                .get(&session_id)
                .map(SessionEntry::handle)
        }) else {
            return;
        };

        let _ = cache
            .legacy(move |subs| subs.apply_revalidated_values(values))
            .await;
    }

    pub(crate) async fn delete_monitored_item_refs(
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

        let cache = {
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions
                .get(&session_id)
                .map(SessionEntry::handle)
        }
        .ok_or(StatusCode::BadNoSubscription)?;

        let mut results = Vec::with_capacity(items.len());
        for (subscription_id, item_ids) in ids_by_subscription {
            let deleted = cache
                .legacy(move |subs| subs.delete_monitored_items(subscription_id, &item_ids))
                .await
                .map_err(|_| StatusCode::BadNoSubscription)??;
            for (status, rf) in &deleted {
                if status.is_good() {
                    let key = MonitoredItemKeyRef {
                        id: rf.node_id().into(),
                        attribute_id: rf.attribute(),
                    };
                    let mut lck = trace_write_lock!(self.inner);
                    if let Some(it) = lck.monitored_items.get_mut(&key) {
                        it.remove(&rf.handle());
                    }
                }
            }
            results.extend(deleted);
        }

        Ok(results)
    }

    async fn delete_expired_monitored_items(
        context: &ServerContext,
        expired_subscriptions: Vec<(Arc<RwLock<Session>>, Vec<RemovedSubscription>)>,
    ) {
        for (session, removed_subscriptions) in expired_subscriptions {
            // Create a local request context, since we need to call delete monitored items.

            let (id, token, user_roles) = {
                let lck = session.read();
                let Some(token) = lck.user_token() else {
                    error!("Active session missing user token, this should be impossible");
                    continue;
                };

                (lck.session_id_numeric(), token.clone(), lck.roles())
            };
            let ctx = RequestContext {
                current_node_manager_index: 0,
                inner: Arc::new(RequestContextInner {
                    session,
                    session_id: id,
                    authenticator: context.authenticator.clone(),
                    token,
                    user_roles,
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

    pub(crate) async fn run_cleanup(
        &self,
        context: &ServerContext,
        mut rx: mpsc::UnboundedReceiver<SubscriptionCleanup>,
    ) {
        while let Some(c) = rx.recv().await {
            let should_delete_expired_monitored_items =
                c.session.is_some() && !c.removed_subscriptions.is_empty();
            {
                let mut lck = trace_write_lock!(self.inner);
                if !c.removed_subscriptions.is_empty() {
                    Self::cleanup_removed_subscriptions(&mut lck, &c.removed_subscriptions);
                }
                if c.ready_to_delete {
                    if let Some(entry) = lck.session_subscriptions.remove(&c.session_id) {
                        entry.handle.stop();
                    }
                }
                context
                    .info
                    .diagnostics
                    .set_current_subscription_count(lck.subscription_to_session.len() as u32);
            }
            if should_delete_expired_monitored_items {
                if let Some(session) = c.session {
                    Self::delete_expired_monitored_items(
                        context,
                        vec![(session, c.removed_subscriptions)],
                    )
                    .await;
                }
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

    pub(crate) async fn get_monitored_item_count(
        &self,
        session_id: u32,
        subscription_id: u32,
    ) -> Option<usize> {
        let cache = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions
                .get(&session_id)
                .map(SessionEntry::handle)
        })?;
        cache
            .legacy(move |subs| subs.get_monitored_item_count(subscription_id))
            .await
            .ok()
            .flatten()
    }

    pub(crate) async fn create_subscription(
        &self,
        session_id: u32,
        request: &CreateSubscriptionRequest,
        context: &RequestContext,
    ) -> Result<CreateSubscriptionResponse, StatusCode> {
        let cache = {
            let mut lck = trace_write_lock!(self.inner);
            lck.session_subscriptions
                .entry(session_id)
                .or_insert_with(|| {
                    let cleanup_tx = self.cleanup_tx.clone();
                    SessionEntry::new(
                        session_id,
                        self.limits,
                        Self::get_key(&context.session),
                        context.session.clone(),
                        context.info.type_tree_getter.get_type_tree_static(context),
                        cleanup_tx,
                    )
                })
                .handle()
        };
        let request = request.clone();
        let info = context.info.clone();
        let res = cache
            .legacy(move |subs| subs.create_subscription(&request, &info))
            .await
            .map_err(|_| StatusCode::BadNoSubscription)??;
        let mut lck = trace_write_lock!(self.inner);
        lck.subscription_to_session
            .insert(res.subscription_id, session_id);
        context
            .info
            .diagnostics
            .set_current_subscription_count(lck.subscription_to_session.len() as u32);
        context.info.diagnostics.inc_subscription_count();
        Ok(res)
    }

    fn ensure_session_entry(
        &self,
        session_id: u32,
        key: PersistentSessionKey,
        context: &RequestContext,
    ) -> SubscriptionActorHandle {
        let mut lck = trace_write_lock!(self.inner);
        let cleanup_tx = self.cleanup_tx.clone();
        lck.session_subscriptions
            .entry(session_id)
            .or_insert_with(|| {
                SessionEntry::new(
                    session_id,
                    self.limits,
                    key,
                    context.session.clone(),
                    context.info.type_tree_getter.get_type_tree_static(context),
                    cleanup_tx,
                )
            })
            .handle()
    }

    pub(crate) async fn modify_subscription(
        &self,
        session_id: u32,
        request: &ModifySubscriptionRequest,
        info: Arc<ServerInfo>,
    ) -> Result<ModifySubscriptionResponse, StatusCode> {
        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions
                .get(&session_id)
                .map(SessionEntry::handle)
        }) else {
            return Err(StatusCode::BadNoSubscription);
        };
        let request = request.clone();
        cache
            .legacy(move |subs| subs.modify_subscription(&request, &info))
            .await
            .map_err(|_| StatusCode::BadNoSubscription)?
    }

    pub(crate) async fn set_publishing_mode(
        &self,
        session_id: u32,
        request: &SetPublishingModeRequest,
    ) -> Result<SetPublishingModeResponse, StatusCode> {
        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions
                .get(&session_id)
                .map(SessionEntry::handle)
        }) else {
            return Err(StatusCode::BadNoSubscription);
        };
        let request = request.clone();
        cache
            .legacy(move |subs| subs.set_publishing_mode(&request))
            .await
            .map_err(|_| StatusCode::BadNoSubscription)?
    }

    pub(crate) async fn republish(
        &self,
        session_id: u32,
        request: &RepublishRequest,
    ) -> Result<RepublishResponseShared, StatusCode> {
        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions
                .get(&session_id)
                .map(SessionEntry::handle)
        }) else {
            return Err(StatusCode::BadNoSubscription);
        };
        let request = request.clone();
        cache
            .legacy(move |subs| subs.republish(&request))
            .await
            .map_err(|_| StatusCode::BadNoSubscription)?
    }

    pub(crate) async fn enqueue_publish_request(
        &self,
        session_id: u32,
        now: DateTimeUtc,
        now_instant: Instant,
        request: PendingPublish,
    ) -> Result<(), StatusCode> {
        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions
                .get(&session_id)
                .map(SessionEntry::handle)
        }) else {
            return Err(StatusCode::BadNoSubscription);
        };

        cache
            .enqueue_publish_request(now, now_instant, request)
            .await
            .map_err(|_| StatusCode::BadNoSubscription)
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

    #[allow(dead_code)]
    pub(crate) fn refresh_subscription_events(
        &self,
        session_id: u32,
        subscription_id: u32,
        monitored_item: Option<MonitoredItemHandle>,
        events: Vec<Box<dyn Event + Send>>,
    ) -> Result<(), StatusCode> {
        if let Some(handle) = monitored_item {
            if handle.subscription_id != subscription_id {
                return Err(StatusCode::BadMonitoredItemIdInvalid);
            }
        }

        let lck = trace_read_lock!(self.inner);
        let Some(owner_session_id) = lck.subscription_to_session.get(&subscription_id) else {
            return Err(StatusCode::BadSubscriptionIdInvalid);
        };
        if *owner_session_id != session_id {
            return Err(StatusCode::BadSubscriptionIdInvalid);
        }

        let Some(entry) = lck.session_subscriptions.get(&session_id) else {
            return Err(StatusCode::BadSubscriptionIdInvalid);
        };

        let item = NotificationWorkItem::Refresh {
            subscription_id,
            monitored_item,
            events,
        };
        entry.handle.push_notification(item);

        Ok(())
    }

    pub(crate) async fn create_monitored_items(
        &self,
        session_id: u32,
        subscription_id: u32,
        requests: Vec<CreateMonitoredItem>,
    ) -> Result<Vec<MonitoredItemCreateResult>, StatusCode> {
        let cache = {
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions
                .get(&session_id)
                .map(SessionEntry::handle)
        }
        .ok_or(StatusCode::BadNoSubscription)?;

        let requests_for_index = requests.clone();
        let result = cache
            .legacy(move |subs| subs.create_monitored_items(subscription_id, &requests))
            .await
            .map_err(|_| StatusCode::BadNoSubscription)?;
        if let Ok(res) = &result {
            let mut lck = trace_write_lock!(self.inner);
            for (create, res) in requests_for_index.iter().zip(res.iter()) {
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

    pub(crate) async fn modify_monitored_items(
        &self,
        session_id: u32,
        subscription_id: u32,
        info: Arc<ServerInfo>,
        timestamps_to_return: TimestampsToReturn,
        requests: Vec<MonitoredItemModifyRequest>,
    ) -> Result<Vec<MonitoredItemUpdateRef>, StatusCode> {
        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions
                .get(&session_id)
                .map(SessionEntry::handle)
        }) else {
            return Err(StatusCode::BadNoSubscription);
        };

        cache
            .legacy(move |subs| {
                let type_tree_for_user = subs.type_tree_for_user();
                let type_tree = type_tree_for_user.get_type_tree();
                subs.modify_monitored_items(
                    subscription_id,
                    &info,
                    timestamps_to_return,
                    requests,
                    type_tree.get(),
                )
            })
            .await
            .map_err(|_| StatusCode::BadNoSubscription)?
    }

    fn get_key(session: &RwLock<Session>) -> PersistentSessionKey {
        let lck = trace_read_lock!(session);
        PersistentSessionKey::new(
            lck.user_token().unwrap(),
            lck.message_security_mode(),
            lck.application_description().application_uri.as_ref(),
        )
    }

    pub(crate) async fn set_monitoring_mode(
        &self,
        session_id: u32,
        subscription_id: u32,
        monitoring_mode: MonitoringMode,
        items: Vec<u32>,
    ) -> Result<Vec<(StatusCode, MonitoredItemRef)>, StatusCode> {
        let cache = {
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions
                .get(&session_id)
                .map(SessionEntry::handle)
        }
        .ok_or(StatusCode::BadNoSubscription)?;

        let result = cache
            .legacy(move |subs| subs.set_monitoring_mode(subscription_id, monitoring_mode, items))
            .await
            .map_err(|_| StatusCode::BadNoSubscription)?;

        if let Ok(res) = &result {
            let mut lck = trace_write_lock!(self.inner);
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

    pub(crate) async fn set_triggering(
        &self,
        session_id: u32,
        subscription_id: u32,
        triggering_item_id: u32,
        links_to_add: Vec<u32>,
        links_to_remove: Vec<u32>,
    ) -> Result<(Vec<StatusCode>, Vec<StatusCode>), StatusCode> {
        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions
                .get(&session_id)
                .map(SessionEntry::handle)
        }) else {
            return Err(StatusCode::BadNoSubscription);
        };

        cache
            .legacy(move |subs| {
                subs.set_triggering(
                    subscription_id,
                    triggering_item_id,
                    links_to_add,
                    links_to_remove,
                )
            })
            .await
            .map_err(|_| StatusCode::BadNoSubscription)?
    }

    pub(crate) async fn delete_monitored_items(
        &self,
        session_id: u32,
        subscription_id: u32,
        items: &[u32],
    ) -> Result<Vec<(StatusCode, MonitoredItemRef)>, StatusCode> {
        let cache = {
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions
                .get(&session_id)
                .map(SessionEntry::handle)
        }
        .ok_or(StatusCode::BadNoSubscription)?;

        let items = items.to_vec();
        let result = cache
            .legacy(move |subs| subs.delete_monitored_items(subscription_id, &items))
            .await
            .map_err(|_| StatusCode::BadNoSubscription)?;
        if let Ok(res) = &result {
            let mut lck = trace_write_lock!(self.inner);
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

    pub(crate) async fn delete_subscriptions(
        &self,
        session_id: u32,
        ids: &[u32],
        info: Arc<ServerInfo>,
    ) -> Result<Vec<(StatusCode, Vec<MonitoredItemRef>)>, StatusCode> {
        let cache = {
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions
                .get(&session_id)
                .map(SessionEntry::handle)
        }
        .ok_or(StatusCode::BadNoSubscription)?;
        let ids = ids.to_vec();
        let ids_for_cleanup = ids.clone();
        let result = cache
            .legacy(move |subs| subs.delete_subscriptions(&ids))
            .await
            .map_err(|_| StatusCode::BadNoSubscription)?;
        let removed_subscriptions = result
            .iter()
            .zip(ids_for_cleanup.iter())
            .filter(|((status, _), _)| status.is_good())
            .map(|((_, monitored_items), id)| RemovedSubscription {
                id: *id,
                monitored_items: monitored_items.clone(),
            })
            .collect::<Vec<_>>();
        let mut lck = trace_write_lock!(self.inner);
        Self::cleanup_removed_subscriptions(&mut lck, &removed_subscriptions);
        info.diagnostics
            .set_current_subscription_count(lck.subscription_to_session.len() as u32);

        Ok(result)
    }

    pub(crate) async fn get_session_subscription_ids(&self, session_id: u32) -> Vec<u32> {
        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions
                .get(&session_id)
                .map(SessionEntry::handle)
        }) else {
            return Vec::new();
        };

        cache
            .legacy(|subs| subs.subscription_ids())
            .await
            .unwrap_or_default()
    }

    pub(crate) async fn teardown_session(&self, session_id: u32, info: &ServerInfo) {
        let entry = {
            let mut lck = trace_write_lock!(self.inner);
            lck.session_subscriptions.remove(&session_id)
        };
        let Some(entry) = entry else {
            return;
        };

        let (subscription_ids, monitored_items) = entry
            .handle
            .legacy(|subs| (subs.subscription_ids(), subs.monitored_item_refs()))
            .await
            .unwrap_or_default();

        {
            let mut lck = trace_write_lock!(self.inner);
            for id in subscription_ids {
                lck.subscription_to_session.remove(&id);
            }
            Self::cleanup_monitored_item_refs(&mut lck, &monitored_items);
            info.diagnostics
                .set_current_subscription_count(lck.subscription_to_session.len() as u32);
        }

        entry.handle.stop();
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

    pub(crate) async fn transfer(
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
        let dest_handle = self.ensure_session_entry(context.session_id, key.clone(), context);

        for (sub_id, res) in &mut results {
            let Some((current_owner_session_id, source_handle)) = ({
                let lck = trace_read_lock!(self.inner);
                let owner = lck.subscription_to_session.get(sub_id).copied();
                owner.and_then(|owner_session_id| {
                    lck.session_subscriptions
                        .get(&owner_session_id)
                        .map(|entry| (owner_session_id, entry.handle()))
                })
            }) else {
                continue;
            };

            if context.session_id == current_owner_session_id {
                res.status_code = StatusCode::Good;
                res.available_sequence_numbers = dest_handle
                    .legacy({
                        let sub_id = *sub_id;
                        move |subs| subs.available_sequence_numbers(sub_id)
                    })
                    .await
                    .ok()
                    .flatten();
                continue;
            }

            let user_matches = source_handle
                .legacy({
                    let key = key.clone();
                    move |subs| subs.user_token().is_equivalent_for_transfer(&key)
                })
                .await
                .unwrap_or(false);
            if !user_matches {
                res.status_code = StatusCode::BadUserAccessDenied;
                continue;
            }

            let staged = source_handle
                .legacy({
                    let sub_id = *sub_id;
                    move |subs| subs.clone_for_transfer(sub_id)
                })
                .await;
            let Ok(Some((sub, notifs))) = staged else {
                continue;
            };

            tracing::debug!(
                "Transfer subscription {} to session {}",
                sub.id(),
                context.session_id
            );
            let next_seq = sub.peek_next_sequence_number();
            let available_sequence_numbers = Some(
                notifs
                    .iter()
                    .map(|n| n.message.sequence_number)
                    .collect::<Vec<_>>(),
            );

            let inserted = dest_handle
                .legacy({
                    let send_initial_values = req.send_initial_values;
                    let sub_id = *sub_id;
                    move |subs| {
                        if let Err((e, _, _)) = subs.insert(sub, notifs) {
                            return Err(e);
                        }
                        if send_initial_values {
                            if let Some(sub) = subs.get_mut(sub_id) {
                                sub.set_resend_data();
                            }
                        }
                        Ok::<(), StatusCode>(())
                    }
                })
                .await;

            match inserted {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    res.status_code = e;
                    continue;
                }
                Err(()) => {
                    res.status_code = StatusCode::BadNoSubscription;
                    continue;
                }
            }

            if source_handle
                .legacy({
                    let sub_id = *sub_id;
                    move |subs| subs.mark_transferring(sub_id)
                })
                .await
                .map_err(|_| StatusCode::BadNoSubscription)
                .and_then(|r| r)
                .is_err()
            {
                res.status_code = StatusCode::BadSubscriptionIdInvalid;
                continue;
            }

            {
                let mut lck = trace_write_lock!(self.inner);
                lck.subscription_to_session
                    .insert(*sub_id, context.session_id);
            }

            let _ = source_handle
                .legacy({
                    let sub_id = *sub_id;
                    move |subs| {
                        let _ = subs.remove(sub_id);
                        subs.queue_status_change(
                            sub_id,
                            next_seq,
                            DateTime::now(),
                            StatusCode::GoodSubscriptionTransferred,
                        );
                    }
                })
                .await;

            res.status_code = StatusCode::Good;
            res.available_sequence_numbers = available_sequence_numbers;
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

#[derive(Clone)]
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
    use std::sync::Arc;

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
                .await
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
                .create_monitored_items(fixture.context.session_id, subscription_id, requests)
                .await
                .expect("monitored items should be created");
            assert!(results.iter().all(|r| r.status_code.is_good()));

            let delete_results = fixture
                .cache
                .delete_subscriptions(
                    fixture.context.session_id,
                    &[subscription_id],
                    fixture.info.clone(),
                )
                .await
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
            .await
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
            .create_monitored_items(fixture.context.session_id, subscription_id, requests)
            .await
            .expect("monitored items should be created");
        assert!(results.iter().all(|r| r.status_code.is_good()));

        // No publish requests are ever sent, so the subscription's lifetime expires.
        // The per-session actor self-ticks on its own deadline timer (no central scan)
        // and reports the removed subscription on the cleanup channel; the reaper
        // (run as the server runs it) performs the index cleanup. Wait for the indexes
        // to return to baseline rather than driving ticks manually.
        let cleanup_rx = fixture
            .cache
            .take_cleanup_receiver()
            .expect("cleanup receiver should be available");
        {
            let cache = Arc::clone(&fixture.cache);
            let ctx = fixture.server_context.clone();
            tokio::spawn(async move { cache.run_cleanup(&ctx, cleanup_rx).await });
        }

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let at_baseline = fixture.cache.subscription_to_session_size_for_test()
                == baseline_subscription_to_session
                && fixture.cache.reverse_index_size_for_test() == baseline_monitored_items;
            if at_baseline {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "subscription did not self-tick to expiry and clean up within 10s"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
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
                Arc::new(Vec::new()),
            );
            let session_id = session.read().session_id_numeric();
            let user_roles = session.read().roles();
            let context = RequestContext::new_test(Arc::new(RequestContextInner {
                session,
                session_id,
                authenticator: info.authenticator.clone(),
                token: UserToken(POLICY_ID_ANONYMOUS.to_string()),
                user_roles,
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
