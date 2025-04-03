mod client;
mod connect;
mod connection;
mod event_loop;
mod request_builder;
mod retry;
mod services;

/// Information about the server endpoint, security policy, security mode and user identity that the session will
/// will use to establish a connection.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// The endpoint
    pub endpoint: EndpointDescription,
    /// User identity token
    pub user_identity_token: IdentityToken,
    /// Preferred language locales
    pub preferred_locales: Vec<String>,
}

impl From<EndpointDescription> for SessionInfo {
    fn from(value: EndpointDescription) -> Self {
        Self {
            endpoint: value,
            user_identity_token: IdentityToken::Anonymous,
            preferred_locales: Vec::new(),
        }
    }
}

impl From<(EndpointDescription, IdentityToken)> for SessionInfo {
    fn from(value: (EndpointDescription, IdentityToken)) -> Self {
        Self {
            endpoint: value.0,
            user_identity_token: value.1,
            preferred_locales: Vec::new(),
        }
    }
}

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
pub use client::Client;
pub use connect::SessionConnectMode;
pub use connection::SessionBuilder;
pub use event_loop::{SessionActivity, SessionEventLoop, SessionPollResult};
use opcua_core::handle::AtomicHandle;
use opcua_core::sync::{Mutex, RwLock};
use opcua_crypto::CertificateStore;
pub use request_builder::UARequest;
pub use retry::{DefaultRetryPolicy, RequestRetryPolicy};
pub use services::attributes::{
    HistoryRead, HistoryReadAction, HistoryUpdate, HistoryUpdateAction, Read, Write,
};
pub use services::method::Call;
pub use services::node_management::{AddNodes, AddReferences, DeleteNodes, DeleteReferences};
pub use services::session::{ActivateSession, Cancel, CloseSession, CreateSession};
use services::subscriptions::state::SubscriptionState;
use services::subscriptions::PublishLimits;
pub use services::subscriptions::{
    CreateMonitoredItems, CreateSubscription, DataChangeCallback, DeleteMonitoredItems,
    DeleteSubscriptions, EventCallback, ModifyMonitoredItems, ModifySubscription, MonitoredItem,
    OnSubscriptionNotification, SetMonitoringMode, SetPublishingMode, SetTriggering, Subscription,
    SubscriptionActivity, SubscriptionCallbacks, TransferSubscriptions,
};
pub use services::view::{
    Browse, BrowseNext, RegisterNodes, TranslateBrowsePaths, UnregisterNodes,
};
use tracing::{error, info};

#[allow(unused)]
macro_rules! session_warn {
    ($session: expr, $($arg:tt)*) =>  {
        tracing::warn!("session:{} {}", $session.session_id(), format!($($arg)*));
    }
}
#[allow(unused)]
pub(crate) use session_warn;

#[allow(unused)]
macro_rules! session_error {
    ($session: expr, $($arg:tt)*) =>  {
        tracing::error!("session:{} {}", $session.session_id(), format!($($arg)*));
    }
}
#[allow(unused)]
pub(crate) use session_error;

#[allow(unused)]
macro_rules! session_debug {
    ($session: expr, $($arg:tt)*) =>  {
        tracing::debug!("session:{} {}", $session.session_id(), format!($($arg)*));
    }
}
#[allow(unused)]
pub(crate) use session_debug;

#[allow(unused)]
macro_rules! session_trace {
    ($session: expr, $($arg:tt)*) =>  {
        tracing::trace!("session:{} {}", $session.session_id(), format!($($arg)*));
    }
}
#[allow(unused)]
pub(crate) use session_trace;

use opcua_core::ResponseMessage;
use opcua_types::{
    ApplicationDescription, ContextOwned, DecodingOptions, EndpointDescription, Error, IntegerId,
    NamespaceMap, NodeId, ReadValueId, RequestHeader, ResponseHeader, StatusCode,
    TimestampsToReturn, TypeLoader, UAString, VariableId, Variant,
};

use crate::browser::Browser;
use crate::transport::tcp::TransportConfiguration;
use crate::transport::Connector;
use crate::{AsyncSecureChannel, ClientConfig, ExponentialBackoff, SessionRetryPolicy};

use super::IdentityToken;

/// Process the service result, i.e. where the request "succeeded" but the response
/// contains a failure status code.
pub(crate) fn process_service_result(response_header: &ResponseHeader) -> Result<(), StatusCode> {
    if response_header.service_result.is_bad() {
        info!(
            "Received a bad service result {} from the request",
            response_header.service_result
        );
        Err(response_header.service_result)
    } else {
        Ok(())
    }
}

pub(crate) fn process_unexpected_response(response: ResponseMessage) -> StatusCode {
    match response {
        ResponseMessage::ServiceFault(service_fault) => {
            error!(
                "Received a service fault of {} for the request",
                service_fault.response_header.service_result
            );
            service_fault.response_header.service_result
        }
        _ => {
            error!("Received an unexpected response to the request");
            StatusCode::BadUnknownResponse
        }
    }
}

#[derive(Clone, Copy)]
pub enum SessionState {
    Disconnected,
    Connected,
    Connecting,
}

static NEXT_SESSION_ID: AtomicU32 = AtomicU32::new(1);

/// An OPC-UA session. This session provides methods for all supported services that require an open session.
///
/// Note that not all servers may support all service requests and calling an unsupported API
/// may cause the connection to be dropped. Your client is expected to know the capabilities of
/// the server it is calling to avoid this.
///
pub struct Session {
    pub(super) channel: AsyncSecureChannel,
    pub(super) state_watch_rx: tokio::sync::watch::Receiver<SessionState>,
    pub(super) state_watch_tx: tokio::sync::watch::Sender<SessionState>,
    pub(super) certificate_store: Arc<RwLock<CertificateStore>>,
    pub(super) session_id: Arc<ArcSwap<NodeId>>,
    pub(super) auth_token: Arc<ArcSwap<NodeId>>,
    pub(super) internal_session_id: AtomicU32,
    pub(super) session_info: SessionInfo,
    pub(super) session_name: UAString,
    pub(super) application_description: ApplicationDescription,
    pub(super) request_timeout: Duration,
    pub(super) publish_timeout: Duration,
    pub(super) recreate_monitored_items_chunk: usize,
    pub(super) recreate_subscriptions: bool,
    pub(super) should_reconnect: AtomicBool,
    pub(super) session_timeout: f64,
    /// Reference to the subscription cache for the client.
    pub subscription_state: Mutex<SubscriptionState>,
    pub(super) publish_limits_watch_rx: tokio::sync::watch::Receiver<PublishLimits>,
    pub(super) publish_limits_watch_tx: tokio::sync::watch::Sender<PublishLimits>,
    pub(super) monitored_item_handle: AtomicHandle,
    pub(super) trigger_publish_tx: tokio::sync::watch::Sender<Instant>,
    decoding_options: DecodingOptions,
    pub(super) encoding_context: Arc<RwLock<ContextOwned>>,
}

impl Session {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        certificate_store: Arc<RwLock<CertificateStore>>,
        session_info: SessionInfo,
        session_name: UAString,
        application_description: ApplicationDescription,
        session_retry_policy: SessionRetryPolicy,
        decoding_options: DecodingOptions,
        config: &ClientConfig,
        session_id: Option<NodeId>,
        connector: Box<dyn Connector>,
        extra_type_loaders: Vec<Arc<dyn TypeLoader>>,
    ) -> (Arc<Self>, SessionEventLoop) {
        let auth_token: Arc<ArcSwap<NodeId>> = Arc::default();
        let (publish_limits_watch_tx, publish_limits_watch_rx) =
            tokio::sync::watch::channel(PublishLimits::new());
        let (state_watch_tx, state_watch_rx) =
            tokio::sync::watch::channel(SessionState::Disconnected);
        let (trigger_publish_tx, trigger_publish_rx) = tokio::sync::watch::channel(Instant::now());

        let mut encoding_context =
            ContextOwned::new_default(NamespaceMap::new(), decoding_options.clone());

        for loader in extra_type_loaders {
            encoding_context.loaders_mut().add(loader);
        }

        let encoding_context = Arc::new(RwLock::new(encoding_context));

        let session = Arc::new(Session {
            channel: AsyncSecureChannel::new(
                certificate_store.clone(),
                session_info.clone(),
                session_retry_policy.clone(),
                config.performance.ignore_clock_skew,
                auth_token.clone(),
                TransportConfiguration {
                    max_pending_incoming: 5,
                    send_buffer_size: config.decoding_options.max_chunk_size,
                    recv_buffer_size: config.decoding_options.max_incoming_chunk_size,
                    max_message_size: config.decoding_options.max_message_size,
                    max_chunk_count: config.decoding_options.max_chunk_count,
                },
                connector,
                config.channel_lifetime,
                encoding_context.clone(),
            ),
            internal_session_id: AtomicU32::new(NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed)),
            state_watch_rx,
            state_watch_tx,
            session_id: Arc::new(ArcSwap::new(Arc::new(session_id.unwrap_or_default()))),
            session_info,
            auth_token,
            session_name,
            application_description,
            certificate_store,
            request_timeout: config.request_timeout,
            session_timeout: config.session_timeout as f64,
            publish_timeout: config.publish_timeout,
            recreate_monitored_items_chunk: config.performance.recreate_monitored_items_chunk,
            recreate_subscriptions: config.recreate_subscriptions,
            should_reconnect: AtomicBool::new(true),
            subscription_state: Mutex::new(SubscriptionState::new(
                config.min_publish_interval,
                publish_limits_watch_tx.clone(),
            )),
            monitored_item_handle: AtomicHandle::new(1000),
            publish_limits_watch_rx,
            publish_limits_watch_tx,
            trigger_publish_tx,
            decoding_options,
            encoding_context,
        });

        (
            session.clone(),
            SessionEventLoop::new(
                session,
                session_retry_policy,
                trigger_publish_rx,
                config.keep_alive_interval,
                config.max_failed_keep_alive_count,
            ),
        )
    }

    /// Create a request header with the default timeout.
    pub(super) fn make_request_header(&self) -> RequestHeader {
        self.channel.make_request_header(self.request_timeout)
    }

    /// Reset the session after a hard disconnect, clearing the session ID and incrementing the internal
    /// session counter.
    pub(crate) fn reset(&self) {
        self.session_id.store(Arc::new(NodeId::null()));
        self.internal_session_id.store(
            NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed),
            Ordering::Relaxed,
        );
    }

    /// Wait for the session to be in either a connected or disconnected state.
    async fn wait_for_state(&self, connected: bool) -> bool {
        let mut rx = self.state_watch_rx.clone();

        let res = rx
            .wait_for(|s| {
                connected && matches!(*s, SessionState::Connected)
                    || !connected && matches!(*s, SessionState::Disconnected)
            })
            .await
            .is_ok();

        // Compiler limitation
        #[allow(clippy::let_and_return)]
        res
    }

    /// The internal ID of the session, used to keep track of multiple sessions in the same program.
    pub fn session_id(&self) -> u32 {
        self.internal_session_id.load(Ordering::Relaxed)
    }

    /// Get the current session ID. This is different from `session_id`, which is the client-side ID
    /// to keep track of multiple sessions. This is the session ID the server uses to identify this session.
    pub fn server_session_id(&self) -> NodeId {
        (**(*self.session_id).load()).clone()
    }

    /// Convenience method to wait for a connection to the server.
    ///
    /// You should also monitor the session event loop. If it ends, this method will never return.
    pub async fn wait_for_connection(&self) -> bool {
        self.wait_for_state(true).await
    }

    /// Disable automatic reconnects.
    /// This will make the event loop quit the next time
    /// it disconnects for whatever reason.
    pub fn disable_reconnects(&self) {
        self.should_reconnect.store(false, Ordering::Relaxed);
    }

    /// Enable automatic reconnects.
    /// Automatically reconnecting is enabled by default.
    pub fn enable_reconnects(&self) {
        self.should_reconnect.store(true, Ordering::Relaxed);
    }

    /// Inner method for disconnect. [`Session::disconnect`] and [`Session::disconnect_without_delete_subscriptions`]
    /// are shortands for this with `delete_subscriptions` set to `false` and `true` respectively, and
    /// `disable_reconnect` set to `true`.
    pub async fn disconnect_inner(
        &self,
        delete_subscriptions: bool,
        disable_reconnect: bool,
    ) -> Result<(), StatusCode> {
        if disable_reconnect {
            self.should_reconnect.store(false, Ordering::Relaxed);
        }
        let mut res = Ok(());
        if let Err(e) = self.close_session(delete_subscriptions).await {
            res = Err(e);
            session_warn!(
                self,
                "Failed to close session, channel will be closed anyway: {e}"
            );
        }
        self.channel.close_channel().await;

        self.wait_for_state(false).await;

        res
    }

    /// Disconnect from the server and wait until disconnected.
    /// This will set the `should_reconnect` flag to false on the session, indicating
    /// that it should not attempt to reconnect to the server. You may clear this flag
    /// yourself to
    pub async fn disconnect(&self) -> Result<(), StatusCode> {
        self.disconnect_inner(true, true).await
    }

    /// Disconnect the server without deleting subscriptions, then wait until disconnected.
    pub async fn disconnect_without_delete_subscriptions(&self) -> Result<(), StatusCode> {
        self.disconnect_inner(false, true).await
    }

    /// Get the decoding options used by the session.
    pub fn decoding_options(&self) -> &DecodingOptions {
        &self.decoding_options
    }

    /// Get a reference to the inner secure channel.
    pub fn channel(&self) -> &AsyncSecureChannel {
        &self.channel
    }

    /// Get the next request handle.
    pub fn request_handle(&self) -> IntegerId {
        self.channel.request_handle()
    }

    /// Set the namespace array on the session.
    /// Make sure that this namespace array contains the base namespace,
    /// or the session may behave unexpectedly.
    pub fn set_namespaces(&self, namespaces: NamespaceMap) {
        *self.encoding_context.write().namespaces_mut() = namespaces;
    }

    /// Add a type loader to the encoding context.
    /// Note that there is no mechanism to ensure uniqueness,
    /// you should avoid adding the same type loader more than once, it will
    /// work, but there will be a small performance overhead.
    pub fn add_type_loader(&self, type_loader: Arc<dyn TypeLoader>) {
        self.encoding_context.write().loaders_mut().add(type_loader);
    }

    /// Get a reference to the encoding
    pub fn context(&self) -> Arc<RwLock<ContextOwned>> {
        self.channel.secure_channel.read().context_arc()
    }

    /// Create a browser, used to recursively browse the node hierarchy.
    ///
    /// You must call `handler` on the returned browser and set a browse policy
    /// before it can be used. You can, for example, use [BrowseFilter](crate::browser::BrowseFilter)
    pub fn browser(&self) -> Browser<'_, (), DefaultRetryPolicy> {
        Browser::new(
            self,
            (),
            DefaultRetryPolicy::new(ExponentialBackoff::new(
                Duration::from_secs(30),
                Some(5),
                Duration::from_millis(500),
            )),
        )
    }

    /// Return namespace array from server and store in namespace cache
    pub async fn read_namespace_array(&self) -> Result<NamespaceMap, Error> {
        let nodeid: NodeId = VariableId::Server_NamespaceArray.into();
        let result = self
            .read(
                &[ReadValueId::from(nodeid)],
                TimestampsToReturn::Neither,
                0.0,
            )
            .await
            .map_err(|status_code| {
                Error::new(status_code, "Reading Server namespace array failed")
            })?;
        if let Some(Variant::Array(array)) = &result[0].value {
            let map = NamespaceMap::new_from_variant_array(&array.values)
                .map_err(|e| Error::new(StatusCode::Bad, e))?;
            let map_clone = map.clone();
            self.set_namespaces(map);
            Ok(map_clone)
        } else {
            Err(Error::new(
                StatusCode::BadNoValue,
                format!(
                    "Server namespace array is None. The server has an issue {:?}",
                    result
                ),
            ))
        }
    }

    /// Return index of supplied namespace url from cache
    pub fn get_namespace_index_from_cache(&self, url: &str) -> Option<u16> {
        self.encoding_context.read().namespaces().get_index(url)
    }

    /// Return index of supplied namespace url
    /// by first looking at namespace cache and querying server if necessary
    pub async fn get_namespace_index(&self, url: &str) -> Result<u16, Error> {
        if let Some(idx) = self.get_namespace_index_from_cache(url) {
            return Ok(idx);
        };
        let map = self.read_namespace_array().await?;
        let idx = map.get_index(url).ok_or_else(|| {
            Error::new(
                StatusCode::BadNoMatch,
                format!(
                    "Url {} not found in namespace array. Namspace array is {:?}",
                    url, &map
                ),
            )
        })?;
        Ok(idx)
    }
}
