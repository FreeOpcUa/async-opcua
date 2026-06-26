#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::{sync::Arc, time::Instant};

use chrono::Utc;
use opcua_core::{Message, RequestMessage, ResponseMessage};
use parking_lot::RwLock;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tracing::{debug, debug_span, warn};
use tracing_futures::Instrument;

use crate::{
    authenticator::UserToken,
    info::ServerInfo,
    node_manager::{
        get_namespaces_for_user, MonitoredItemRef, NodeManagers, ReadNode, RequestContext,
        RequestContextInner,
    },
    session::{
        audit::{self, AuditEventContext},
        services,
    },
    subscriptions::{PendingPublish, SubscriptionCache},
};
use opcua_types::{
    AttributeId, CancelResponse, DataValue, DiagnosticBits, DiagnosticInfo, NamespaceMap, NodeId,
    PublishRequest, ReadRequest, ReadResponse, ReadValueId, ResponseHeader, ServiceFault,
    SetTriggeringRequest, SetTriggeringResponse, StatusCode, TimestampsToReturn, UAString,
    WriteRequest, WriteResponse,
};

use super::{actor::SessionMessage, controller::Response, instance::Session};

/// Type that takes care of incoming requests that have passed
/// the initial validation stage, meaning that they have a session and a valid
/// secure channel.
pub(crate) struct MessageHandler {
    node_managers: NodeManagers,
    info: Arc<ServerInfo>,
    subscriptions: Arc<SubscriptionCache>,
}

/// Result of a message. All messages should be able to yield a response, but
/// depending on the message this may take different forms.
pub(crate) enum HandleMessageResult {
    /// A request spawned as a tokio task, all messages that go to
    /// node managers return this response type.
    AsyncMessage(JoinHandle<Response>),
    /// A message that was resolved synchronously and returns a response immediately.
    SyncMessage(Response),
}

pub(crate) struct PendingPublishRequest {
    request_id: u32,
    request_handle: u32,
    recv: tokio::sync::oneshot::Receiver<ResponseMessage>,
}

impl PendingPublishRequest {
    /// Receive a publish request response.
    /// This may take a long time, since publish requests can be open for
    /// arbitrarily long waiting for new data to be produced.
    pub(super) async fn recv(self) -> Result<Response, String> {
        match self.recv.await {
            Ok(msg) => Ok(Response {
                message: msg,
                request_id: self.request_id,
            }),
            Err(_) => {
                // This shouldn't be possible at all.
                warn!("Failed to receive response to publish request, sender dropped.");
                Ok(Response {
                    message: ServiceFault::new(self.request_handle, StatusCode::BadInternalError)
                        .into(),
                    request_id: self.request_id,
                })
            }
        }
    }
}

/// Wrapper around information necessary for executing a request.
pub(super) struct Request<T> {
    pub request: Box<T>,
    pub request_id: u32,
    pub request_handle: u32,
    pub info: Arc<ServerInfo>,
    pub session: Arc<RwLock<Session>>,
    pub token: UserToken,
    pub subscriptions: Arc<SubscriptionCache>,
    pub session_id: u32,
}

/// Convenient macro for creating a response containing a service fault.
macro_rules! service_fault {
    ($req:ident, $status:expr) => {
        Response {
            message: opcua_types::ServiceFault::new($req.request_handle, $status).into(),
            request_id: $req.request_id,
        }
    };
}

impl<T> Request<T> {
    /// Create a new request.
    #[allow(clippy::too_many_arguments)]
    fn new(
        request: Box<T>,
        info: Arc<ServerInfo>,
        request_id: u32,
        request_handle: u32,
        session: Arc<RwLock<Session>>,
        token: UserToken,
        subscriptions: Arc<SubscriptionCache>,
        session_id: u32,
    ) -> Self {
        Self {
            request,
            request_id,
            request_handle,
            info,
            session,
            token,
            subscriptions,
            session_id,
        }
    }

    /// Get a request context object from this request.
    pub(super) fn context(&self) -> RequestContext {
        let user_roles = self.session.read().roles();
        RequestContext {
            current_node_manager_index: 0,
            inner: Arc::new(RequestContextInner {
                session: self.session.clone(),
                authenticator: self.info.authenticator.clone(),
                token: self.token.clone(),
                user_roles,
                type_tree: self.info.type_tree.clone(),
                type_tree_getter: self.info.type_tree_getter.clone(),
                subscriptions: self.subscriptions.clone(),
                session_id: self.session_id,
                info: self.info.clone(),
            }),
        }
    }
}

/// Macro for calling a service asynchronously.
macro_rules! async_service_call {
    ($m:path, $slf:ident, $req:ident, $r:ident) => {
        HandleMessageResult::AsyncMessage(tokio::task::spawn($m(
            $slf.node_managers.clone(),
            Request::new(
                $req,
                $slf.info.clone(),
                $r.request_id,
                $r.request_handle,
                $r.session,
                $r.token,
                $slf.subscriptions.clone(),
                $r.session_id,
            ),
        )))
    };
}

struct RequestData {
    request_id: u32,
    request_handle: u32,
    session: Arc<RwLock<Session>>,
    token: UserToken,
    session_id: u32,
    actor_sender: Option<mpsc::Sender<SessionMessage>>,
}

impl MessageHandler {
    /// Create a new message handler.
    pub(super) fn new(
        info: Arc<ServerInfo>,
        node_managers: NodeManagers,
        subscriptions: Arc<SubscriptionCache>,
    ) -> Self {
        Self {
            node_managers,
            info,
            subscriptions,
        }
    }

    /// The subscription cache used to dispatch server events (e.g. audit events).
    pub(crate) fn subscriptions(&self) -> &Arc<SubscriptionCache> {
        &self.subscriptions
    }

    /// Handle an incoming message and return a result object.
    /// This method returns synchronously, but the returned result object
    /// may take longer to resolve.
    /// Once this returns the request will either be resolved or will have been started.
    pub(super) fn handle_message(
        &mut self,
        message: RequestMessage,
        session_id: u32,
        session: Arc<RwLock<Session>>,
        token: UserToken,
        request_id: u32,
        actor_sender: Option<mpsc::Sender<SessionMessage>>,
    ) -> HandleMessageResult {
        let data = RequestData {
            request_id,
            request_handle: message.request_handle(),
            session,
            token,
            session_id,
            actor_sender,
        };
        // Session management requests are not handled here.
        match message {
            RequestMessage::Read(request) => self.read(request, data),

            RequestMessage::Browse(request) => {
                async_service_call!(services::browse, self, request, data)
            }

            RequestMessage::BrowseNext(request) => {
                async_service_call!(services::browse_next, self, request, data)
            }

            RequestMessage::TranslateBrowsePathsToNodeIds(request) => {
                async_service_call!(services::translate_browse_paths, self, request, data)
            }

            RequestMessage::RegisterNodes(request) => {
                async_service_call!(services::register_nodes, self, request, data)
            }

            RequestMessage::UnregisterNodes(request) => {
                async_service_call!(services::unregister_nodes, self, request, data)
            }

            RequestMessage::CreateMonitoredItems(request) => {
                async_service_call!(services::create_monitored_items, self, request, data)
            }

            RequestMessage::ModifyMonitoredItems(request) => {
                async_service_call!(services::modify_monitored_items, self, request, data)
            }

            RequestMessage::SetMonitoringMode(request) => {
                async_service_call!(services::set_monitoring_mode, self, request, data)
            }

            RequestMessage::DeleteMonitoredItems(request) => {
                async_service_call!(services::delete_monitored_items, self, request, data)
            }

            RequestMessage::SetTriggering(request) => self.set_triggering(*request, data),

            RequestMessage::Publish(request) => self.publish(request, data),

            RequestMessage::Republish(request) => {
                let subscriptions = self.subscriptions.clone();
                HandleMessageResult::AsyncMessage(tokio::task::spawn(async move {
                    let result = subscriptions.republish(data.session_id, &request).await;
                    Response::from_result(result, data.request_handle, data.request_id)
                }))
            }

            RequestMessage::CreateSubscription(request) => {
                let request = self.get_request(data, *request);
                HandleMessageResult::AsyncMessage(tokio::task::spawn(async move {
                    let context = request.context();
                    let result = request
                        .subscriptions
                        .create_subscription(request.session_id, &request.request, &context)
                        .await;
                    Response::from_result(result, request.request_handle, request.request_id)
                }))
            }

            RequestMessage::ModifySubscription(request) => {
                let subscriptions = self.subscriptions.clone();
                let info = self.info.clone();
                HandleMessageResult::AsyncMessage(tokio::task::spawn(async move {
                    let result = subscriptions
                        .modify_subscription(data.session_id, &request, info)
                        .await;
                    Response::from_result(result, data.request_handle, data.request_id)
                }))
            }

            RequestMessage::SetPublishingMode(request) => {
                let subscriptions = self.subscriptions.clone();
                HandleMessageResult::AsyncMessage(tokio::task::spawn(async move {
                    let result = subscriptions
                        .set_publishing_mode(data.session_id, &request)
                        .await;
                    Response::from_result(result, data.request_handle, data.request_id)
                }))
            }

            RequestMessage::TransferSubscriptions(request) => {
                let request = self.get_request(data, *request);
                HandleMessageResult::AsyncMessage(tokio::task::spawn(async move {
                    let context = request.context();
                    Response {
                        message: request
                            .subscriptions
                            .transfer(&request.request, &context)
                            .await
                            .into(),
                        request_id: request.request_id,
                    }
                }))
            }

            RequestMessage::DeleteSubscriptions(request) => {
                async_service_call!(services::delete_subscriptions, self, request, data)
            }

            RequestMessage::HistoryRead(request) => {
                async_service_call!(services::history_read, self, request, data)
            }

            RequestMessage::HistoryUpdate(request) => {
                async_service_call!(services::history_update, self, request, data)
            }

            RequestMessage::Write(request) => self.write(request, data),

            RequestMessage::QueryFirst(request) => {
                async_service_call!(services::query_first, self, request, data)
            }

            RequestMessage::QueryNext(request) => {
                async_service_call!(services::query_next, self, request, data)
            }

            RequestMessage::Call(request) => {
                async_service_call!(services::call, self, request, data)
            }

            RequestMessage::AddNodes(request) => {
                async_service_call!(services::add_nodes, self, request, data)
            }

            RequestMessage::AddReferences(request) => {
                async_service_call!(services::add_references, self, request, data)
            }

            RequestMessage::DeleteNodes(request) => {
                async_service_call!(services::delete_nodes, self, request, data)
            }

            RequestMessage::DeleteReferences(request) => {
                async_service_call!(services::delete_references, self, request, data)
            }

            RequestMessage::Cancel(request) => {
                // Part 4 §5.7.5: Cancel cancels outstanding requests for the Session and returns the
                // number cancelled. This server processes requests without a cancellable queue, so
                // there is nothing outstanding to cancel; respond Good with cancelCount = 0.
                let session_id = Some(data.session.read().session_id().clone());
                audit::dispatch_cancel(
                    &self.subscriptions,
                    &self.info,
                    &request.request_header,
                    session_id,
                    request.request_handle,
                    StatusCode::Good,
                );
                HandleMessageResult::SyncMessage(Response {
                    message: CancelResponse {
                        response_header: ResponseHeader::new_good(&request.request_header),
                        cancel_count: 0,
                    }
                    .into(),
                    request_id,
                })
            }

            message => {
                debug!(
                    "Message handler does not handle this kind of message {:?}",
                    message
                );
                HandleMessageResult::SyncMessage(Response {
                    message: ServiceFault::new(
                        message.request_header(),
                        StatusCode::BadServiceUnsupported,
                    )
                    .into(),
                    request_id,
                })
            }
        }
    }

    /// Delete the subscriptions from a session.
    pub(super) async fn delete_session_subscriptions(
        &mut self,
        session_id: u32,
        session: Arc<RwLock<Session>>,
        token: UserToken,
    ) {
        let ids = self
            .subscriptions
            .get_session_subscription_ids(session_id)
            .await;
        if ids.is_empty() {
            self.subscriptions
                .teardown_session(session_id, &self.info)
                .await;
            return;
        }

        let user_roles = session.read().roles();
        let mut context = RequestContext {
            current_node_manager_index: 0,
            inner: Arc::new(RequestContextInner {
                session,
                session_id,
                authenticator: self.info.authenticator.clone(),
                token,
                user_roles,
                type_tree: self.info.type_tree.clone(),
                subscriptions: self.subscriptions.clone(),
                info: self.info.clone(),
                type_tree_getter: self.info.type_tree_getter.clone(),
            }),
        };

        // Ignore the result
        if let Err(e) = services::delete_subscriptions_inner(
            self.node_managers.clone(),
            ids,
            &self.subscriptions,
            &mut context,
        )
        .await
        {
            warn!("Cleaning up session subscriptions failed: {e}");
        }
        self.subscriptions
            .teardown_session(session_id, &self.info)
            .await;
    }

    pub(super) async fn revalidate_monitored_items_for_user(
        &mut self,
        session: Arc<RwLock<Session>>,
        session_id: u32,
        token: UserToken,
    ) {
        let user_roles = session.read().roles();
        let context = RequestContext {
            current_node_manager_index: 0,
            inner: Arc::new(RequestContextInner {
                session,
                session_id,
                authenticator: self.info.authenticator.clone(),
                token,
                user_roles,
                type_tree: self.info.type_tree.clone(),
                subscriptions: self.subscriptions.clone(),
                info: self.info.clone(),
                type_tree_getter: self.info.type_tree_getter.clone(),
            }),
        };

        self.subscriptions
            .update_session_user(session_id, &context)
            .await;

        struct RevalidationItem {
            item: MonitoredItemRef,
            read: ReadNode,
        }

        let mut items = self
            .subscriptions
            .get_session_monitored_items(session_id)
            .await
            .into_iter()
            .map(|item| {
                let read = ReadNode::new(
                    ReadValueId {
                        node_id: item.node_id().clone(),
                        attribute_id: item.attribute() as u32,
                        ..Default::default()
                    },
                    Default::default(),
                );
                RevalidationItem { item, read }
            })
            .collect::<Vec<_>>();

        if items.is_empty() {
            return;
        }

        for (idx, node_manager) in self.node_managers.iter().enumerate() {
            let mut owned = items
                .iter_mut()
                .filter(|item| {
                    item.read.status() == StatusCode::BadNodeIdUnknown
                        && node_manager.owns_node(item.item.node_id())
                })
                .map(|item| &mut item.read)
                .collect::<Vec<_>>();

            if owned.is_empty() {
                continue;
            }

            let mut read_context = context.clone();
            read_context.current_node_manager_index = idx;
            if let Err(e) = node_manager
                .read(&read_context, 0.0, TimestampsToReturn::Neither, &mut owned)
                .instrument(debug_span!(
                    "RevalidateMonitoredItems",
                    node_manager = %node_manager.name()
                ))
                .await
            {
                for item in owned {
                    item.set_error(e);
                }
            }
        }

        let mut denied = Vec::new();
        let mut refreshed_values = Vec::new();
        for item in items {
            let status = item.read.status();
            if matches!(
                status,
                StatusCode::BadUserAccessDenied | StatusCode::BadNotReadable
            ) {
                denied.push(item.item);
            } else if status.is_good() && item.item.attribute() != AttributeId::EventNotifier {
                refreshed_values.push((item.item, item.read.result));
            }
        }

        self.subscriptions
            .apply_revalidated_values(session_id, refreshed_values)
            .await;

        if denied.is_empty() {
            return;
        }

        let deleted = match self
            .subscriptions
            .delete_monitored_item_refs(session_id, &denied)
            .await
        {
            Ok(deleted) => deleted,
            Err(e) => {
                warn!("Revalidating monitored items failed to delete inaccessible items: {e}");
                return;
            }
        };

        let deleted = deleted
            .into_iter()
            .filter_map(|(status, item)| status.is_good().then_some(item))
            .collect::<Vec<_>>();

        for (idx, node_manager) in self.node_managers.iter().enumerate() {
            let owned = deleted
                .iter()
                .filter(|item| node_manager.owns_node(item.node_id()))
                .collect::<Vec<_>>();

            if owned.is_empty() {
                continue;
            }

            let mut delete_context = context.clone();
            delete_context.current_node_manager_index = idx;
            node_manager
                .delete_monitored_items(&delete_context, &owned)
                .instrument(debug_span!(
                    "DeleteRevalidatedMonitoredItems",
                    node_manager = %node_manager.name()
                ))
                .await;
        }
    }

    pub(super) fn get_namespaces_for_user(
        &mut self,
        session: Arc<RwLock<Session>>,
        session_id: u32,
        token: UserToken,
    ) -> NamespaceMap {
        let user_roles = session.read().roles();
        let ctx = RequestContext {
            current_node_manager_index: 0,
            inner: Arc::new(RequestContextInner {
                session,
                session_id,
                authenticator: self.info.authenticator.clone(),
                token,
                user_roles,
                type_tree: self.info.type_tree.clone(),
                subscriptions: self.subscriptions.clone(),
                info: self.info.clone(),
                type_tree_getter: self.info.type_tree_getter.clone(),
            }),
        };
        get_namespaces_for_user(&ctx, &self.node_managers)
    }

    fn set_triggering(
        &self,
        request: SetTriggeringRequest,
        data: RequestData,
    ) -> HandleMessageResult {
        let subscriptions = self.subscriptions.clone();
        HandleMessageResult::AsyncMessage(tokio::task::spawn(async move {
            let result = subscriptions
                .set_triggering(
                    data.session_id,
                    request.subscription_id,
                    request.triggering_item_id,
                    request.links_to_add.unwrap_or_default(),
                    request.links_to_remove.unwrap_or_default(),
                )
                .await
                .map(|(add_res, remove_res)| SetTriggeringResponse {
                    response_header: ResponseHeader::new_good(&request.request_header),
                    add_results: Some(add_res),
                    add_diagnostic_infos: None,
                    remove_results: Some(remove_res),
                    remove_diagnostic_infos: None,
                });

            Response::from_result(result, data.request_handle, data.request_id)
        }))
    }

    fn get_request<T>(&self, dt: RequestData, request: T) -> Request<T> {
        Request::new(
            Box::new(request),
            self.info.clone(),
            dt.request_id,
            dt.request_handle,
            dt.session,
            dt.token,
            self.subscriptions.clone(),
            dt.session_id,
        )
    }

    fn read(&self, request: Box<ReadRequest>, data: RequestData) -> HandleMessageResult {
        let info = self.info.clone();
        HandleMessageResult::AsyncMessage(tokio::task::spawn(async move {
            Self::read_via_actor(request, data, info).await
        }))
    }

    async fn read_via_actor(
        request: Box<ReadRequest>,
        data: RequestData,
        info: Arc<ServerInfo>,
    ) -> Response {
        let request = *request;
        if request.max_age < 0.0 {
            return Self::service_fault(&data, StatusCode::BadMaxAgeInvalid);
        }
        if request.timestamps_to_return == TimestampsToReturn::Invalid {
            return Self::service_fault(&data, StatusCode::BadTimestampsToReturnInvalid);
        }

        let Some(nodes_to_read) = request.nodes_to_read else {
            return Self::service_fault(&data, StatusCode::BadNothingToDo);
        };
        if nodes_to_read.is_empty() {
            return Self::service_fault(&data, StatusCode::BadNothingToDo);
        }
        if nodes_to_read.len() > info.operational_limits.max_nodes_per_read {
            return Self::service_fault(&data, StatusCode::BadTooManyOperations);
        }

        let Some(actor_sender) = data.actor_sender.clone() else {
            return Self::service_fault(&data, StatusCode::BadSessionClosed);
        };
        let include_diagnostics = !request.request_header.return_diagnostics.is_empty();

        // The whole batch is one actor round-trip; node managers run
        // concurrently within it.
        let batch = match Self::actor_read(
            &actor_sender,
            nodes_to_read,
            request.max_age,
            request.timestamps_to_return,
            request.request_header.return_diagnostics,
        )
        .await
        {
            Ok(r) => r,
            // The actor faulted (node manager panic) or the session is
            // gone; fail the whole service call like the pre-actor path.
            Err(status) => return Self::service_fault(&data, status),
        };

        let mut results = Vec::with_capacity(batch.len());
        let mut diagnostics = include_diagnostics.then(|| Vec::with_capacity(batch.len()));
        for (result, diagnostic) in batch {
            results.push(result);
            if let Some(diagnostics) = &mut diagnostics {
                diagnostics.push(diagnostic.unwrap_or_default());
            }
        }

        Response {
            message: ReadResponse {
                response_header: ResponseHeader::new_good(data.request_handle),
                results: Some(results),
                diagnostic_infos: diagnostics,
            }
            .into(),
            request_id: data.request_id,
        }
    }

    async fn actor_read(
        actor_sender: &mpsc::Sender<SessionMessage>,
        nodes: Vec<ReadValueId>,
        max_age: f64,
        timestamps_to_return: TimestampsToReturn,
        return_diagnostics: DiagnosticBits,
    ) -> Result<Vec<(DataValue, Option<DiagnosticInfo>)>, StatusCode> {
        let (response, recv) = oneshot::channel();
        if actor_sender
            .send(SessionMessage::Read {
                nodes,
                max_age,
                timestamps_to_return,
                return_diagnostics,
                response,
            })
            .await
            .is_err()
        {
            return Err(StatusCode::BadSessionClosed);
        }

        recv.await.unwrap_or(Err(StatusCode::BadSessionClosed))
    }

    fn write(&self, request: Box<WriteRequest>, data: RequestData) -> HandleMessageResult {
        let info = self.info.clone();
        let subscriptions = self.subscriptions.clone();
        HandleMessageResult::AsyncMessage(tokio::task::spawn(async move {
            Self::write_via_actor(request, data, info, subscriptions).await
        }))
    }

    async fn write_via_actor(
        request: Box<WriteRequest>,
        data: RequestData,
        info: Arc<ServerInfo>,
        subscriptions: Arc<SubscriptionCache>,
    ) -> Response {
        let request = *request;
        let Some(nodes_to_write) = request.nodes_to_write else {
            return Self::service_fault(&data, StatusCode::BadNothingToDo);
        };
        if nodes_to_write.is_empty() {
            return Self::service_fault(&data, StatusCode::BadNothingToDo);
        }
        if nodes_to_write.len() > info.operational_limits.max_nodes_per_write {
            return Self::service_fault(&data, StatusCode::BadTooManyOperations);
        }

        let Some(actor_sender) = data.actor_sender.clone() else {
            return Self::service_fault(&data, StatusCode::BadSessionClosed);
        };
        let include_diagnostics = !request.request_header.return_diagnostics.is_empty();
        let write_targets: Vec<(NodeId, u32)> = nodes_to_write
            .iter()
            .map(|write| (write.node_id.clone(), write.attribute_id))
            .collect();

        // The whole batch is one actor round-trip; node managers run
        // concurrently within it.
        let batch = match Self::actor_write(
            &actor_sender,
            nodes_to_write,
            request.request_header.return_diagnostics,
        )
        .await
        {
            Ok(r) => r,
            // The actor faulted (node manager panic) or the session is
            // gone; fail the whole service call like the pre-actor path.
            Err(status) => return Self::service_fault(&data, status),
        };

        let mut results = Vec::with_capacity(batch.len());
        let mut diagnostics = include_diagnostics.then(|| Vec::with_capacity(batch.len()));
        for (status, diagnostic) in batch {
            results.push(status);
            if let Some(diagnostics) = &mut diagnostics {
                diagnostics.push(diagnostic.unwrap_or_default());
            }
        }

        let audit_context = {
            let session = data.session.read();
            AuditEventContext::new(
                "Write",
                &request.request_header,
                session
                    .user_token()
                    .map(|user_token| UAString::from(user_token.0.as_str())),
                Some(session.session_id().clone()),
            )
        };
        for (target, status) in write_targets.iter().zip(&results) {
            audit::dispatch_write_audit(
                &subscriptions,
                &info,
                &audit_context,
                &target.0,
                target.1,
                *status,
            );
        }

        Response {
            message: WriteResponse {
                response_header: ResponseHeader::new_good(data.request_handle),
                results: Some(results),
                diagnostic_infos: diagnostics,
            }
            .into(),
            request_id: data.request_id,
        }
    }

    async fn actor_write(
        actor_sender: &mpsc::Sender<SessionMessage>,
        values: Vec<opcua_types::WriteValue>,
        return_diagnostics: DiagnosticBits,
    ) -> Result<Vec<(StatusCode, Option<DiagnosticInfo>)>, StatusCode> {
        let (response, recv) = oneshot::channel();
        if actor_sender
            .send(SessionMessage::Write {
                values,
                return_diagnostics,
                response,
            })
            .await
            .is_err()
        {
            return Err(StatusCode::BadSessionClosed);
        }

        recv.await.unwrap_or(Err(StatusCode::BadSessionClosed))
    }

    fn service_fault(data: &RequestData, status: StatusCode) -> Response {
        Response {
            message: ServiceFault::new(data.request_handle, status).into(),
            request_id: data.request_id,
        }
    }

    fn publish(&self, request: Box<PublishRequest>, data: RequestData) -> HandleMessageResult {
        let now = Utc::now();
        let now_instant = Instant::now();
        let (send, recv) = tokio::sync::oneshot::channel();
        let timeout = request.request_header.timeout_hint;
        let timeout = if timeout == 0 {
            self.info.config.publish_timeout_default_ms
        } else {
            timeout.into()
        };

        let req = PendingPublish {
            response: send,
            request,
            ack_results: None,
            deadline: now_instant + std::time::Duration::from_millis(timeout),
        };
        let subscriptions = self.subscriptions.clone();
        HandleMessageResult::AsyncMessage(tokio::task::spawn(async move {
            match subscriptions
                .enqueue_publish_request(data.session_id, now, now_instant, req)
                .await
            {
                Ok(_) => PendingPublishRequest {
                    request_id: data.request_id,
                    request_handle: data.request_handle,
                    recv,
                }
                .recv()
                .await
                .unwrap_or_else(|_| Response {
                    message: ServiceFault::new(data.request_handle, StatusCode::BadInternalError)
                        .into(),
                    request_id: data.request_id,
                }),
                Err(e) => Response {
                    message: ServiceFault::new(data.request_handle, e).into(),
                    request_id: data.request_id,
                },
            }
        }))
    }
}
