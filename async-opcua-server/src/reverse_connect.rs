use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use hashbrown::HashMap;
use opcua_core::{
    sync::{Mutex, RwLock},
    trace_lock, trace_read_lock, trace_write_lock,
};
use opcua_types::StatusCode;
use tokio::sync::Notify;

#[derive(Clone)]
/// Configuration for a reverse connect target.
pub struct ReverseConnectTargetConfig {
    /// The client address the server should connect to.
    pub address: SocketAddr,
    /// The endpoint URL in the reverse hello message, informing the client
    /// of which endpoint this is.
    pub endpoint_url: String,
    /// Unique ID for this reverse connect target.
    pub id: String,
}

enum ReverseConnectStateType {
    /// Failed at time, will retry at time.
    Failed(Instant),
    /// Successfully connected at time.
    Connected,
    /// Currently trying to connect.
    Connecting,
    /// Not currently trying to connect, waiting to connect.
    Waiting,
}

struct ReverseConnectTarget {
    config: ReverseConnectTargetConfig,
    state: Arc<Mutex<ReverseConnectState>>,
}

struct ReverseConnectState {
    state: ReverseConnectStateType,
}

pub(crate) struct ReverseConnectionInstanceHandle {
    state: Arc<Mutex<ReverseConnectState>>,
    notify: Arc<Notify>,
}

impl ReverseConnectionInstanceHandle {
    fn new(state: Arc<Mutex<ReverseConnectState>>, notify: Arc<Notify>) -> Self {
        trace_lock!(state).state = ReverseConnectStateType::Connecting;
        Self { state, notify }
    }

    pub(crate) fn set_result(&self, status: StatusCode) {
        let mut state = trace_lock!(self.state);
        state.state = if status.is_good() {
            ReverseConnectStateType::Connected
        } else {
            ReverseConnectStateType::Failed(Instant::now())
        };
        self.notify.notify_waiters();
    }
}

impl Drop for ReverseConnectionInstanceHandle {
    fn drop(&mut self) {
        let mut state = trace_lock!(self.state);
        // Once the handle is dropped we're no longer connected.
        state.state = ReverseConnectStateType::Waiting;
        self.notify.notify_waiters();
    }
}

pub(crate) struct ReverseConnectionManager {
    active_targets: Arc<RwLock<HashMap<String, ReverseConnectTarget>>>,
    notify: Arc<tokio::sync::Notify>,
    failure_retry: Duration,
}

#[derive(Clone)]
pub(crate) struct ReverseConnectHandle {
    active_targets: Arc<RwLock<HashMap<String, ReverseConnectTarget>>>,
    notify: Arc<tokio::sync::Notify>,
}

impl ReverseConnectHandle {
    pub(crate) fn add_target(&self, target: ReverseConnectTargetConfig) {
        let mut targets = trace_write_lock!(self.active_targets);
        targets
            .entry(target.id.clone())
            .or_insert_with(|| ReverseConnectTarget {
                config: target,
                state: Arc::new(Mutex::new(ReverseConnectState {
                    state: ReverseConnectStateType::Waiting,
                })),
            });
        self.notify.notify_waiters();
    }

    pub(crate) fn remove_target(&self, id: &str) {
        let mut targets = trace_write_lock!(self.active_targets);
        targets.remove(id);
    }
}

pub(crate) struct PendingReverseConnection {
    pub target: ReverseConnectTargetConfig,
    pub handle: ReverseConnectionInstanceHandle,
}

impl PendingReverseConnection {
    fn new(target: ReverseConnectTargetConfig, handle: ReverseConnectionInstanceHandle) -> Self {
        Self { target, handle }
    }
}

impl ReverseConnectionManager {
    pub(crate) fn new(failure_retry: Duration) -> (Self, ReverseConnectHandle) {
        let active_targets = Arc::new(RwLock::new(HashMap::new()));
        let notify = Arc::new(tokio::sync::Notify::new());
        (
            Self {
                active_targets: active_targets.clone(),
                notify: notify.clone(),
                failure_retry,
            },
            ReverseConnectHandle {
                active_targets,
                notify,
            },
        )
    }

    pub(crate) async fn wait_for_connection(&self) -> PendingReverseConnection {
        loop {
            let mut next_wait_for = None;
            let notified = self.notify.notified();
            {
                let targets = trace_read_lock!(self.active_targets);
                for target in targets.values() {
                    {
                        let state = trace_lock!(target.state);
                        // Check if we should connect, and store the next time we should wake up if we have any rejected connections.
                        match &state.state {
                            ReverseConnectStateType::Failed(time) => {
                                let next_time = *time + self.failure_retry;
                                if Instant::now() < next_time {
                                    match next_wait_for {
                                        Some(next) if next < next_time => {}
                                        _ => {
                                            next_wait_for = Some(next_time);
                                        }
                                    }
                                    continue;
                                }
                            }
                            ReverseConnectStateType::Connecting
                            | ReverseConnectStateType::Connected => {
                                continue;
                            }
                            ReverseConnectStateType::Waiting => {}
                        }
                    }
                    return PendingReverseConnection::new(
                        target.config.clone(),
                        ReverseConnectionInstanceHandle::new(
                            target.state.clone(),
                            self.notify.clone(),
                        ),
                    );
                }
            }

            let next_fut = match next_wait_for {
                Some(time) => futures::future::Either::Left(tokio::time::sleep_until(time.into())),
                None => futures::future::Either::Right(futures::future::pending()),
            };
            tokio::select! {
                _ = notified => {}
                _ = next_fut => {}
            }
        }
    }
}
