#![allow(dead_code)]

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use crossbeam_queue::ArrayQueue;
use tokio::sync::{mpsc, oneshot, Notify};

use crate::node_manager::TypeTreeForUserStatic;

use super::{
    pool::NotificationBuffer, ring::NotificationWorkItem,
    session_subscriptions::PendingRefreshDrain, PendingPublish, SessionSubscriptions,
    SubscriptionCleanup, NOTIFICATION_RING_CAPACITY, RING_DRAIN_BUDGET, RING_DRAIN_EVENT_CHUNK,
};
use crate::subscriptions::subscription::TickReason;
use opcua_types::DateTimeUtc;
use std::time::{Duration, Instant};

/// Commands accepted by the per-session subscription actor.
pub(crate) enum SubscriptionCommand {
    /// Run a closure against the actor-owned [`SessionSubscriptions`].
    ///
    /// Typed results are returned by having the closure capture its own
    /// [`oneshot::Sender<R>`] and send the result before returning. The command
    /// itself intentionally remains non-generic so it can live in one channel.
    LegacyCall(Box<dyn FnOnce(&mut SessionSubscriptions) + Send>),
    EnqueuePublish {
        now: DateTimeUtc,
        now_instant: Instant,
        request: PendingPublish,
        response: oneshot::Sender<()>,
    },
    /// Stop the actor after all earlier commands have been handled.
    Stop,
}

#[derive(Clone)]
pub(crate) struct SubscriptionActorHandle {
    ring: Arc<ArrayQueue<NotificationWorkItem>>,
    notify: Arc<Notify>,
    commands: mpsc::UnboundedSender<SubscriptionCommand>,
    dropped: Arc<AtomicU64>,
}

impl SubscriptionActorHandle {
    pub(crate) fn push_notification(&self, item: NotificationWorkItem) {
        if self.ring.push(item).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        self.notify.notify_one();
    }

    pub(crate) async fn legacy<R: Send + 'static>(
        &self,
        f: impl FnOnce(&mut SessionSubscriptions) -> R + Send + 'static,
    ) -> Result<R, ()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(SubscriptionCommand::LegacyCall(Box::new(move |subs| {
                let _ = reply_tx.send(f(subs));
            })))
            .map_err(|_| ())?;

        reply_rx.await.map_err(|_| ())
    }

    pub(super) async fn enqueue_publish_request(
        &self,
        now: DateTimeUtc,
        now_instant: Instant,
        request: PendingPublish,
    ) -> Result<(), ()> {
        let (response, recv) = oneshot::channel();
        self.commands
            .send(SubscriptionCommand::EnqueuePublish {
                now,
                now_instant,
                request,
                response,
            })
            .map_err(|_| ())?;

        recv.await.map_err(|_| ())
    }

    pub(crate) fn stop(&self) {
        let _ = self.commands.send(SubscriptionCommand::Stop);
    }
}

pub(crate) struct SubscriptionActor {
    session_id: u32,
    subs: SessionSubscriptions,
    ring: Arc<ArrayQueue<NotificationWorkItem>>,
    notify: Arc<Notify>,
    commands_rx: mpsc::UnboundedReceiver<SubscriptionCommand>,
    cleanup_tx: mpsc::UnboundedSender<SubscriptionCleanup>,
    type_tree: Arc<dyn TypeTreeForUserStatic>,
    pending_refresh: Option<PendingRefreshDrain>,
}

impl SubscriptionActor {
    pub(crate) async fn run(mut self) {
        let sleep = tokio::time::sleep_until(Self::next_sleep_deadline(&self.subs));
        tokio::pin!(sleep);

        loop {
            sleep.as_mut().reset(Self::next_sleep_deadline(&self.subs));

            tokio::select! {
                command = self.commands_rx.recv() => {
                    match command {
                        Some(SubscriptionCommand::LegacyCall(f)) => {
                            self.drain_ring().await;
                            f(&mut self.subs);
                        }
                        Some(SubscriptionCommand::EnqueuePublish { now, now_instant, request, response }) => {
                            self.drain_ring().await;
                            let mut buffer = NotificationBuffer::new();
                            self.subs.enqueue_publish_request(&now, now_instant, request);
                            loop {
                                let more_notifications = self.subs.has_more_notifications()
                                    && self.subs.has_queued_publish_request();
                                if !more_notifications {
                                    break;
                                }
                                let _ = self.subs.tick(
                                    &now,
                                    now_instant,
                                    TickReason::ReceivePublishRequest,
                                    &mut buffer,
                                );
                            }
                            let _ = response.send(());
                        }
                        Some(SubscriptionCommand::Stop) | None => break,
                    }
                }
                _ = self.notify.notified() => {
                    self.drain_ring().await;
                }
                _ = &mut sleep => {
                    self.drain_ring().await;
                    let now = DateTimeUtc::from(chrono::Utc::now());
                    let now_instant = std::time::Instant::now();
                    let mut buffer = NotificationBuffer::new();
                    let removed = self.subs.tick(
                        &now,
                        now_instant,
                        TickReason::TickTimerFired,
                        &mut buffer,
                    );
                    let ready = self.subs.is_ready_to_delete();
                    if !removed.is_empty() || ready {
                        let session = (!removed.is_empty()).then(|| self.subs.session().clone());
                        let _ = self.cleanup_tx.send(SubscriptionCleanup {
                            session_id: self.session_id,
                            session,
                            removed_subscriptions: removed,
                            ready_to_delete: ready,
                        });
                    }
                }
            }
        }
    }

    fn next_sleep_deadline(subs: &SessionSubscriptions) -> tokio::time::Instant {
        subs.next_tick_deadline()
            .map(tokio::time::Instant::from_std)
            .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(3600))
    }

    async fn drain_ring(&mut self) {
        let mut processed = 0;
        loop {
            if processed >= RING_DRAIN_BUDGET {
                tokio::task::yield_now().await;
                processed = 0;
            }

            let drained = {
                let type_tree = self.type_tree.get_type_tree();
                self.subs.drain_ring_chunk(
                    self.ring.as_ref(),
                    type_tree.get(),
                    RING_DRAIN_EVENT_CHUNK,
                    &mut self.pending_refresh,
                )
            };

            let completed_refresh = self
                .pending_refresh
                .as_ref()
                .is_some_and(PendingRefreshDrain::is_complete);
            if completed_refresh {
                self.pending_refresh = None;
            }

            if drained == 0 {
                break;
            }

            processed += drained;
            tokio::task::yield_now().await;
        }
    }
}

pub(crate) fn spawn(
    session_id: u32,
    subs: SessionSubscriptions,
    type_tree: Arc<dyn TypeTreeForUserStatic>,
    cleanup_tx: mpsc::UnboundedSender<SubscriptionCleanup>,
) -> SubscriptionActorHandle {
    assert_actor_send_bounds();

    let ring = Arc::new(ArrayQueue::new(NOTIFICATION_RING_CAPACITY));
    let notify = Arc::new(Notify::new());
    let dropped = Arc::new(AtomicU64::new(0));
    let (commands, commands_rx) = mpsc::unbounded_channel();

    tokio::spawn(
        SubscriptionActor {
            session_id,
            subs,
            ring: Arc::clone(&ring),
            notify: Arc::clone(&notify),
            commands_rx,
            cleanup_tx,
            type_tree,
            pending_refresh: None,
        }
        .run(),
    );

    SubscriptionActorHandle {
        ring,
        notify,
        commands,
        dropped,
    }
}

fn assert_actor_send_bounds() {
    fn assert_send<T: Send>() {}

    assert_send::<SessionSubscriptions>();
}
